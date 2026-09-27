"""
companion_integrity.py — Firmware Attacks Module, Phase 3 (Companion-Side Integrity).

Verifies firmware images / update files on the COMPANION computer (RPi / Jetson)
against a signed trusted manifest, watches protected directories for tampering,
and gates update activity to an allowed window. Hashing runs OFF the hot path
in a bounded background worker; the hot path is a non-blocking O(1) cache read.

============================================================================
MANIFEST FORMAT (documented contract — see firmware_manifest_format.md)
============================================================================
Trusted manifest = two files next to each other:

  firmware_manifest.json      the manifest itself (UTF-8 JSON, <= 1 MiB):
      {
        "manifest_version": 1,
        "generated_utc": "2026-09-24T00:00:00Z",
        "algorithm": "sha256",
        "entries": [
          {"path": "firmware/ardupilot.apj", "sha256": "<64 hex>", "size": 12345}
        ]
      }
      * `path` is POSIX-style, RELATIVE to the watch root. No leading "/",
        no "..". Duplicate paths are rejected. Empty entries list is rejected.

  firmware_manifest.json.sig  HMAC-SHA256 signature over the CANONICAL JSON
                              encoding of the manifest (sorted keys, compact
                              separators, UTF-8). Single line, 64 hex chars.

  firmware_manifest.json.key  hex-encoded HMAC key (single line). Loaded only
                              if present; if `require_signature` is set and the
                              key/sig is missing, loading FAILS LOUDLY.

HMAC (not asymmetric) keeps stdlib-only and SWaP-C small; it protects against
OFF-PLATFORM tampering of the update payload, NOT against full companion
compromise (attacker with root can read the key). Documented limitation —
hardware-rooted trust (secure boot / TPM) is REQUIRED for the FC-side guarantee
and is explicitly out of scope (see firmware_attacks_threat_model.md F-011/F-012).

============================================================================
BOUNDEDNESS (hot path + worker)
============================================================================
* Hot path (`quick_check`) = dict lookup + optional non-blocking queue put.
  No file I/O, no hashing, no allocation beyond the job tuple.
* Worker queue is bounded (default 64 jobs). Full queue => submit returns
  False and the job is counted in stats (no unbounded memory growth).
* Hashing is chunked and capped (`max_hash_bytes`) so a hostile huge file
  cannot pin the worker.
* Manifest reads are capped at 1 MiB.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .command_injection_detector import AlertRateLimiter, IDSAlert, _MITRE_MAP
from .ids_config import get_fail_mode, load_config

logger = logging.getLogger("ids.firmware_integrity")

MAX_MANIFEST_BYTES = 1_048_576          # 1 MiB manifest read bound
DEFAULT_MAX_HASH_BYTES = 33_554_432     # 32 MiB per-file hashing cap
MANIFEST_REQUIRED_KEYS = ("manifest_version", "algorithm", "entries")


class ManifestError(ValueError):
    """Raised when a manifest is missing, malformed, oversized, or badly signed."""


# ---------------------------------------------------------------------------
# Alert helper — reuses IDSAlert + _MITRE_MAP from the existing schema.
# ---------------------------------------------------------------------------
def make_fw_alert(
    severity: str,
    reason: str,
    rule_id: Optional[str] = None,
    detail: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
    sysid: Optional[int] = None,
    compid: Optional[int] = None,
    confidence: Optional[float] = None,
    command: Optional[str] = None,
) -> IDSAlert:
    """Build a firmware-attack IDSAlert (MITRE tag reused from shared map)."""
    return IDSAlert(
        timestamp=time.time(),
        severity=severity,
        reason=reason,
        rule_id=rule_id,
        mitre_attack=_MITRE_MAP.get(reason),
        detail=detail,
        evidence=evidence or {},
        sysid=sysid,
        compid=compid,
        confidence=confidence,
        command=command,
    )


# ---------------------------------------------------------------------------
# Manifest canonicalization / signing (HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------
def canonical_bytes(manifest: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding used for the signature (stable across runs)."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any], key: bytes) -> str:
    """Return the HMAC-SHA256 hex signature for a manifest dict."""
    return hmac.new(key, canonical_bytes(manifest), hashlib.sha256).hexdigest()


def verify_manifest_signature(
    manifest: Dict[str, Any], key: bytes, signature_hex: str
) -> bool:
    """Constant-time signature comparison."""
    try:
        expected = sign_manifest(manifest, key)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature_hex.strip().lower())


def _validate_manifest_structure(manifest: Dict[str, Any]) -> None:
    """Structural checks. Raises ManifestError loudly on any violation."""
    for key in MANIFEST_REQUIRED_KEYS:
        if key not in manifest:
            raise ManifestError(f"manifest missing required key {key!r}")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise ManifestError("manifest 'entries' must be a non-empty list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError("manifest entry is not an object")
        path = str(entry.get("path", ""))
        sha = str(entry.get("sha256", ""))
        size = entry.get("size")
        if not path or sha is None or size is None:
            raise ManifestError(f"manifest entry missing path/sha256/size: {entry!r}")
        norm = _norm_rel(path)
        if norm.startswith("/") or ".." in norm.split("/") or not norm:
            raise ManifestError(f"unsafe manifest path {path!r} (relative only)")
        if norm in seen:
            raise ManifestError(f"duplicate manifest path {path!r}")
        if not isinstance(size, int) or size < 0:
            raise ManifestError(f"manifest entry {norm!r} has invalid size")
        seen.add(norm)


def _norm_rel(path: str) -> str:
    """Normalize a manifest/watch path to posix-style relative form."""
    return str(path).replace("\\", "/").strip("/")


def load_manifest(
    path: str,
    *,
    key: Optional[bytes] = None,
    require_signature: bool = False,
    max_bytes: int = MAX_MANIFEST_BYTES,
) -> Dict[str, Any]:
    """
    Load + validate a manifest, optionally verifying its HMAC signature.

    Args:
        path: path to the manifest JSON file.
        key: HMAC key bytes (if None, tries ``path + ".key"``).
        require_signature: when True, a valid signature is REQUIRED.
        max_bytes: read bound; larger manifests raise ManifestError.

    Returns:
        The validated manifest dict.

    Raises:
        ManifestError: missing/oversized/invalid JSON/invalid structure/
            missing or invalid signature. Always fails loudly.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ManifestError(f"manifest not readable: {path} ({exc})") from exc
    if size > max_bytes:
        raise ManifestError(f"manifest too large: {size} > {max_bytes} bytes")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest unreadable/invalid JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ManifestError("manifest root must be a JSON object")
    _validate_manifest_structure(manifest)

    sig_path = path + ".sig"
    have_sig = os.path.exists(sig_path)
    if require_signature and not have_sig:
        raise ManifestError(f"signature required but missing: {sig_path}")
    if have_sig:
        if key is None:
            key_path = path + ".key"
            if not os.path.exists(key_path):
                if require_signature:
                    raise ManifestError(f"key file missing: {key_path}")
                key = None
            else:
                with open(key_path, "r", encoding="utf-8") as fh:
                    key = bytes.fromhex(fh.read().strip())
        if key is not None:
            with open(sig_path, "r", encoding="utf-8") as fh:
                sig = fh.read().strip()
            if not verify_manifest_signature(manifest, key, sig):
                raise ManifestError("manifest signature INVALID (tampering?)")
    return manifest


# ---------------------------------------------------------------------------
# File hashing (bounded)
# ---------------------------------------------------------------------------
def hash_file(
    path: str, algorithm: str = "sha256", max_bytes: int = DEFAULT_MAX_HASH_BYTES
) -> Tuple[Optional[str], int]:
    """
    Hash a file in chunks, capped at ``max_bytes``.

    Returns:
        (hexdigest or None, bytes_hashed). hexdigest is None when the file
        could not be read or exceeded the cap (bytes_hashed == -1 signals cap).
    """
    h = hashlib.new(algorithm)
    hashed = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                hashed += len(chunk)
                if hashed > max_bytes:
                    return None, -1          # capped — treat as untrusted
                h.update(chunk)
    except OSError:
        return None, hashed
    return h.hexdigest(), hashed


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class VerifyResult:
    """Outcome of one file verification against the manifest."""
    path: str
    ok: bool
    reason: Optional[str]            # None when ok; else e.g. 'hash_mismatch'
    expected_size: Optional[int] = None
    actual_size: Optional[int] = None
    expected_sha: Optional[str] = None
    actual_sha: Optional[str] = None
    in_manifest: bool = True
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "ok": self.ok, "reason": self.reason,
            "expected_size": self.expected_size, "actual_size": self.actual_size,
            "in_manifest": self.in_manifest, "timestamp": self.timestamp,
        }


def _manifest_index(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build {normalized_rel_path: entry} index for O(1) lookups."""
    idx: Dict[str, Dict[str, Any]] = {}
    for entry in manifest.get("entries", []):
        idx[_norm_rel(str(entry.get("path", "")))] = entry
    return idx


def _resolve_rel(path: str, index: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """
    Map an absolute (or relative) file path onto a manifest entry key.

    Tries the full normalized path first, then progressively trims leading
    path components ("C:/tmp/x/fw/firmware/app.apj" -> "fw/firmware/app.apj"
    -> "firmware/app.apj"). Watch roots differ per machine; manifest entries
    are relative, so suffix alignment is the portable join.
    """
    rel = _norm_rel(path)
    if rel in index:
        return rel
    parts = rel.split("/")
    for i in range(len(parts)):
        candidate = "/".join(parts[i:])
        if candidate in index:
            return candidate
    return None


def verify_file(manifest: Dict[str, Any], path: str,
                algorithm: str = "sha256") -> VerifyResult:
    """
    Synchronous one-shot verification (worker uses this off the hot path).

    ``path`` may be absolute (watcher) or relative (manifest-style); it is
    aligned to manifest entries by suffix. Classifies:
    ok | hash_mismatch | size_mismatch | missing | not_in_manifest.
    """
    index = _manifest_index(manifest)
    key = _resolve_rel(path, index)
    if key is None:
        return VerifyResult(_norm_rel(path), ok=False, reason="not_in_manifest",
                            in_manifest=False, timestamp=time.time())
    expected = index[key]

    if not os.path.exists(path):
        return VerifyResult(key, ok=False, reason="missing",
                            expected_size=expected["size"],
                            expected_sha=expected["sha256"], timestamp=time.time())

    actual_size = os.path.getsize(path)
    if actual_size != expected["size"]:
        return VerifyResult(key, ok=False, reason="size_mismatch",
                            expected_size=expected["size"],
                            actual_size=actual_size, timestamp=time.time())

    digest, hashed = hash_file(path, algorithm)
    if digest is None:
        return VerifyResult(key, ok=False, reason="hash_capped_or_unreadable",
                            expected_size=expected["size"],
                            actual_size=actual_size, timestamp=time.time())
    if not hmac.compare_digest(digest, str(expected["sha256"]).lower()):
        return VerifyResult(key, ok=False, reason="hash_mismatch",
                            expected_size=expected["size"], actual_size=actual_size,
                            expected_sha=expected["sha256"], actual_sha=digest,
                            timestamp=time.time())
    return VerifyResult(key, ok=True, reason=None,
                        expected_size=expected["size"],
                        actual_size=actual_size, expected_sha=expected["sha256"],
                        actual_sha=digest, timestamp=time.time())


# ---------------------------------------------------------------------------
# Background worker — bounded queue, bounded CPU, thread-safe cache
# ---------------------------------------------------------------------------
class IntegrityWorker:
    """
    Off-hot-path verification worker.

    * ``submit(path)``  — non-blocking enqueue (False when queue full).
    * ``process_pending(n)`` — synchronous bounded drain (tests call this
      directly; the background thread calls it in a loop with a sleep).
    * ``quick_check(path)`` — HOT PATH: cached result or None; enqueues if
      unknown. Never blocks, never touches the filesystem.
    """

    CACHE_MAX = 4096   # bounded result cache (evict-oldest)

    def __init__(
        self,
        manifest: Dict[str, Any],
        algorithm: str = "sha256",
        queue_size: int = 64,
        max_files_per_cycle: int = 8,
        poll_interval_s: float = 1.0,
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
    ) -> None:
        self._manifest = manifest
        self._algorithm = algorithm
        self._max_files = max(1, max_files_per_cycle)
        self._poll_s = max(0.05, poll_interval_s)
        self._max_hash_bytes = max_hash_bytes
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=max(1, queue_size))
        self._results: "OrderedDict[str, VerifyResult]" = __import__(
            "collections").OrderedDict()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats: Dict[str, int] = {
            "submitted": 0, "processed": 0, "dropped_queue_full": 0,
            "failed": 0, "cycles": 0,
        }

    # -- hot path ----------------------------------------------------------
    def quick_check(self, path: str) -> Optional[VerifyResult]:
        """Cached verdict or None (and enqueue for verification). Non-blocking."""
        rel = _norm_rel(path)
        with self._lock:
            res = self._results.get(rel)
        if res is not None:
            return res
        self.submit(rel)
        return None

    def submit(self, path: str) -> bool:
        """Non-blocking enqueue. False when the bounded queue is full."""
        try:
            self._q.put_nowait(_norm_rel(path))
            self.stats["submitted"] += 1
            return True
        except queue.Full:
            self.stats["dropped_queue_full"] += 1
            return False

    # -- worker side -------------------------------------------------------
    def process_pending(self, max_items: Optional[int] = None) -> int:
        """Drain up to ``max_items`` jobs synchronously. Returns count done."""
        n = self._max_files if max_items is None else max_items
        done = 0
        while done < n:
            try:
                rel = self._q.get_nowait()
            except queue.Empty:
                break
            res = verify_file(self._manifest, rel, self._algorithm)
            with self._lock:
                self._results[rel] = res
                while len(self._results) > self.CACHE_MAX:
                    self._results.popitem(last=False)
            self.stats["processed"] += 1
            if not res.ok and res.reason != "not_in_manifest":
                self.stats["failed"] += 1
            done += 1
        self.stats["cycles"] += 1
        return done

    def result(self, path: str) -> Optional[VerifyResult]:
        with self._lock:
            return self._results.get(_norm_rel(path))

    # -- background thread ---------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.is_set():
                self.process_pending()
                self._stop.wait(self._poll_s)   # bounded CPU: sleep between cycles

        self._thread = threading.Thread(target=_loop, name="ids-fw-integrity",
                                        daemon=True)
        self._thread.start()
        logger.info("IntegrityWorker started (poll=%.2fs, batch=%d)",
                    self._poll_s, self._max_files)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None


# ---------------------------------------------------------------------------
# File-integrity watcher — bounded polling over watch dirs
# ---------------------------------------------------------------------------
class FileIntegrityWatcher:
    """
    Poll-based watcher (no external deps). One ``scan_once()`` pass:
      * files present but NOT in manifest  -> 'companion_file_unexpected'
      * manifest files with bad verdict    -> 'companion_file_hash_mismatch' /
                                              'companion_file_missing'
      * clean pass                         -> no alerts (FPR-negative)
    Bounded: at most ``max_files_per_scan`` paths examined per pass; hashing
    is delegated to the worker (this pass only lists dirs + reads cache).
    """

    MAX_DIR_ENTRIES = 512

    def __init__(
        self,
        worker: IntegrityWorker,
        watch_dirs: List[str],
        policy: Optional[Dict[str, Any]] = None,
        max_files_per_scan: int = 64,
    ) -> None:
        self._worker = worker
        self._watch_dirs = list(watch_dirs or [])
        self._max_files = max(1, max_files_per_scan)
        pol = policy or {}
        al = pol.get("alerting", {})
        self._limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0),
        )
        self._fail_mode = get_fail_mode(pol) if pol else "alert_and_pass"
        self.scans_done = 0
        # Cheap per-file stat signatures (mtime_ns, size) -> detect changes
        # without hashing on the hot path. Bounded, evict-oldest.
        self._stats: "OrderedDict[str, Tuple[int, int]]" = OrderedDict()

    def _emit(self, alert: IDSAlert) -> Optional[IDSAlert]:
        """Dedupe/rate-limit then apply fail mode (never silent-drop default)."""
        key = f"{alert.reason}:{(alert.evidence or {}).get('path', '')}"
        if not self._limiter.allow(key, int(alert.sysid or 0), "integrity",
                                   time.time()):
            return None
        if self._fail_mode == "alert_and_block":
            alert.evidence["drop"] = True   # IDSAlert is slots; marker in evidence
        return alert

    def scan_once(self) -> List[IDSAlert]:
        """Run one bounded pass. Returns list of alerts (may be empty)."""
        alerts: List[IDSAlert] = []
        examined = 0
        seen_dirs: List[str] = []

        # 1) Files on disk under watch dirs (bounded recursive walk)
        for root in self._watch_dirs:
            if examined >= self._max_files:
                break
            if not os.path.isdir(root):
                continue
            seen_dirs.append(root)
            for dirpath, dirnames, filenames in os.walk(root):
                if examined >= self._max_files:
                    break
                for name in filenames[: self.MAX_DIR_ENTRIES]:
                    if examined >= self._max_files:
                        break
                    full = os.path.join(dirpath, name)
                    examined += 1
                    rel = _norm_rel(full)
                    # Cheap change detection: stat signature (mtime, size).
                    # Changed/new files are re-verified by the worker; the
                    # cached verdict is returned but may be one scan stale.
                    try:
                        st = os.stat(full)
                        sig = (st.st_mtime_ns, st.st_size)
                    except OSError:
                        continue
                    prev = self._stats.get(rel)
                    if prev != sig:
                        self._stats[rel] = sig
                        if len(self._stats) > 4096:
                            self._stats.popitem(last=False)
                        self._worker.submit(rel)      # re-verify off hot path
                    res = self._worker.quick_check(rel)
                    if res is None:
                        continue                          # not yet verified
                    if res.reason == "not_in_manifest":
                        a = make_fw_alert(
                            severity="high", reason="companion_file_unexpected",
                            rule_id="FW-005", detail=f"unexpected file {rel}",
                            evidence={"path": rel})
                        em = self._emit(a)
                        if em:
                            alerts.append(em)
                    elif not res.ok:
                        a = make_fw_alert(
                            severity="high",
                            reason=("companion_file_missing" if res.reason == "missing"
                                    else "companion_file_hash_mismatch"),
                            rule_id="FW-005", detail=f"{rel}: {res.reason}",
                            evidence={"path": rel, "reason": res.reason,
                                      "expected_size": res.expected_size,
                                      "actual_size": res.actual_size})
                        em = self._emit(a)
                        if em:
                            alerts.append(em)

        # 2) Manifest entries ABSENT from disk under watched roots.
        #    quick_check enqueues a cheap 'missing' verification for never-
        #    seen entries; previously-seen-then-deleted files already carry
        #    a cached 'missing' verdict and alert on this pass.
        for root in seen_dirs:
            for entry in self._worker._manifest.get("entries", []):
                rel_entry = _norm_rel(str(entry.get("path", "")))
                full = os.path.join(root, *rel_entry.split("/"))
                if os.path.exists(full):
                    continue
                res = self._worker.quick_check(_norm_rel(full))
                if res is not None and not res.ok and res.reason == "missing":
                    a = make_fw_alert(
                        severity="high", reason="companion_file_missing",
                        rule_id="FW-005", detail=f"missing {rel_entry}",
                        evidence={"path": rel_entry})
                    em = self._emit(a)
                    if em:
                        alerts.append(em)

        self.scans_done += 1
        return alerts


# ---------------------------------------------------------------------------
# Update-workflow guard
# ---------------------------------------------------------------------------
class UpdateGuard:
    """
    Flags update activity outside the allowed window or without a valid
    manifest. Called by stream-level detectors on UPDATE_AUTOPILOT / FTP
    writes to firmware paths, and by the update tooling pre-flight.
    """

    def __init__(self, policy: Dict[str, Any],
                 state_getter: Optional[Callable[[], str]] = None) -> None:
        self._policy = policy
        fw = policy.get("firmware", {})
        self._window = fw.get("update_window", {})
        self._state_getter = state_getter or (lambda: "DISARMED")
        al = policy.get("alerting", {})
        self._limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0))
        self._fail_mode = get_fail_mode(policy)

    def _emit(self, alert: IDSAlert) -> Optional[IDSAlert]:
        if not self._limiter.allow(alert.reason, int(alert.sysid or 0),
                                   "update", time.time()):
            return None
        if self._fail_mode == "alert_and_block":
            alert.evidence["drop"] = True   # IDSAlert is slots; marker in evidence
        return alert

    def check(self, *, source_sysid: int = 255, command: str = "UPDATE",
              has_valid_manifest: bool = True, now: Optional[float] = None
              ) -> Optional[IDSAlert]:
        """Return an alert when the update is NOT allowed right now."""
        del now  # reserved for clock-window policies
        state = self._state_getter()
        allowed_states = self._window.get("allowed_states", ["DISARMED"])

        if state not in allowed_states:
            a = make_fw_alert(
                severity="high", reason="update_outside_allowed_window",
                rule_id="FW-009", command=command, sysid=source_sysid,
                evidence={"state": state, "allowed_states": allowed_states})
            return self._emit(a)
        if not has_valid_manifest:
            a = make_fw_alert(
                severity="high", reason="update_without_valid_manifest",
                rule_id="FW-009", command=command, sysid=source_sysid,
                evidence={"state": state})
            return self._emit(a)
        return None


# ---------------------------------------------------------------------------
# Facade — wires manifest + worker + watcher + update guard
# ---------------------------------------------------------------------------
class CompanionIntegrityModule:
    """Single entry point for the firmware-attacks companion-side layer."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None,
        manifest_path: Optional[str] = None,
        manifest_key_path: Optional[str] = None,
        state_getter: Optional[Callable[[], str]] = None,
        start_worker: bool = False,
    ) -> None:
        if config_path is not None and policy is not None:
            raise ValueError("supply either config_path or policy, not both")
        if policy is not None:
            self._policy = policy
        elif config_path is not None:
            self._policy = load_config(config_path)
        else:
            from .ids_config import default_policy
            self._policy = default_policy()

        ci = self._policy.get("companion_integrity", {})
        self._fail_mode = get_fail_mode(self._policy)
        self.manifest_path = manifest_path or ci.get("manifest_path", "")
        self.key_path = manifest_key_path or (self.manifest_path + ".key")

        key: Optional[bytes] = None
        if os.path.exists(self.key_path):
            with open(self.key_path, "r", encoding="utf-8") as fh:
                key = bytes.fromhex(fh.read().strip())

        # Manifest may legitimately be absent (companion without update pkg):
        # the module still runs file-watching + update gating.
        self.manifest: Optional[Dict[str, Any]] = None
        self.manifest_error: Optional[str] = None
        if self.manifest_path and os.path.exists(self.manifest_path):
            try:
                self.manifest = load_manifest(
                    self.manifest_path, key=key,
                    require_signature=ci.get("require_signature", False))
            except ManifestError as exc:
                self.manifest_error = str(exc)
                logger.error("manifest load failed: %s", exc)
        elif self.manifest_path and key is None and not os.path.exists(self.key_path):
            logger.info("no manifest at %s (companion integrity degraded)",
                        self.manifest_path)

        alg = ci.get("hash_algorithm", "sha256")
        self.worker = IntegrityWorker(
            self.manifest or {"entries": []}, algorithm=alg,
            poll_interval_s=1.0)
        self.watcher = FileIntegrityWatcher(
            self.worker, ci.get("watch_dirs", []), self._policy)
        self.update_guard = UpdateGuard(self._policy, state_getter)
        if start_worker:
            self.worker.start()

    # -- hot path ------------------------------------------------------------
    def quick_check(self, path: str) -> Optional[VerifyResult]:
        """Non-blocking cached verification (returns None until verified)."""
        return self.worker.quick_check(path)

    # -- synchronous conveniences ---------------------------------------------
    def scan_once(self) -> List[IDSAlert]:
        """One bounded watcher pass (alerts, may be empty)."""
        out: List[IDSAlert] = list(self.watcher.scan_once())
        if self.manifest_error:
            em = self._rate(self._watcher_limiter,
                            make_fw_alert(
                                severity="high", reason="manifest_load_error",
                                rule_id="FW-009", detail=self.manifest_error,
                                evidence={"manifest": self.manifest_path}),
                            "manifest")
            if em:
                out.append(em)
        return out

    def check_update(self, *, source_sysid: int = 255, command: str = "UPDATE",
                     has_valid_manifest: Optional[bool] = None) -> Optional[IDSAlert]:
        """Update-workflow gate (uses manifest presence when not overridden)."""
        if has_valid_manifest is None:
            has_valid_manifest = self.manifest is not None
        return self.update_guard.check(source_sysid=source_sysid,
                                       command=command,
                                       has_valid_manifest=has_valid_manifest)

    # -- shared limiter plumbing -----------------------------------------------
    @property
    def _watcher_limiter(self) -> AlertRateLimiter:
        return self.watcher._limiter

    def _rate(self, limiter: AlertRateLimiter, alert: IDSAlert,
              channel: str) -> Optional[IDSAlert]:
        if not limiter.allow(alert.reason, int(alert.sysid or 0), channel,
                             time.time()):
            return None
        if self._fail_mode == "alert_and_block":
            alert.evidence["drop"] = True   # IDSAlert is slots; marker in evidence
        return alert

    # -- stats ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        return {
            "worker": dict(self.worker.stats),
            "watcher_scans": self.watcher.scans_done,
            "manifest_loaded": self.manifest is not None,
            "manifest_error": self.manifest_error,
            "fail_mode": self._fail_mode,
        }

    def reset(self) -> None:
        """Clear cached verdicts and scan counters (does not stop the worker)."""
        with self.worker._lock:
            self.worker._results.clear()
        self.watcher.scans_done = 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    print("=" * 70)
    print("COMPANION INTEGRITY — SELF TEST (temp dirs, no hardware needed)")
    print("=" * 70)
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "fw")
        os.makedirs(root, exist_ok=True)
        fw = os.path.join(root, "firmware")
        os.makedirs(fw, exist_ok=True)

        # build a file + manifest + key + sig
        img = os.path.join(fw, "ardupilot.apj")
        with open(img, "wb") as fh:
            fh.write(b"ARDOI-IMAGE-BYTES")
        digest, size = hash_file(img)
        manifest = {"manifest_version": 1, "generated_utc": "2026-09-24T00:00:00Z",
                    "algorithm": "sha256",
                    "entries": [{"path": "firmware/ardupilot.apj",
                                 "sha256": digest, "size": size}]}
        key = os.urandom(32)
        mpath = os.path.join(tmp, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        with open(mpath + ".sig", "w", encoding="utf-8") as fh:
            fh.write(sign_manifest(manifest, key))
        with open(mpath + ".key", "w", encoding="utf-8") as fh:
            fh.write(key.hex())

        pol = {"fail_mode": "alert_and_pass", "alerting": {},
               "companion_integrity": {"watch_dirs": [root]},
               "firmware": {"update_window": {"allowed_states": ["DISARMED"]}}}

        mod = CompanionIntegrityModule(policy=pol, manifest_path=mpath)
        print(f"[1] manifest signed + loaded: {'PASS' if mod.manifest else 'FAIL'}")
        ok &= mod.manifest is not None

        res = verify_file(manifest, img)
        print(f"[2] clean image verifies: {'PASS' if res.ok else 'FAIL'}")
        ok &= res.ok

        # tamper (same size, different bytes -> pure hash mismatch)
        with open(img, "r+b") as fh:
            data = bytearray(fh.read())
            data[0] ^= 0xFF
            fh.seek(0)
            fh.write(data)
        res2 = verify_file(manifest, img)
        print(f"[3] tampered image flagged ({res2.reason}): "
              f"{'PASS' if (not res2.ok and res2.reason == 'hash_mismatch') else 'FAIL'}")
        ok &= (not res2.ok and res2.reason == "hash_mismatch")

        # worker path
        w = IntegrityWorker(manifest)
        w.submit(img)
        w.process_pending()
        r3 = w.result(img)
        print(f"[4] worker flags tamper: {'PASS' if r3 and not r3.ok else 'FAIL'}")
        ok &= bool(r3 and not r3.ok)

        # update guard
        g = UpdateGuard(pol, state_getter=lambda: "FLYING")
        a = g.check()
        print(f"[5] update while FLYING flagged: {'PASS' if a else 'FAIL'}")
        ok &= a is not None
        g2 = UpdateGuard(pol, state_getter=lambda: "DISARMED")
        b = g2.check(has_valid_manifest=True)
        print(f"[6] legal DISARMED update silent: {'PASS' if b is None else 'FAIL'}")
        ok &= b is None

    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    print("=" * 70)
    raise SystemExit(0 if ok else 1)
