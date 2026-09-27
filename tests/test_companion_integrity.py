"""
Phase 3 tests — companion-side integrity (manifest, worker, watcher, guard).

Every rule has a positive (detected) and negative (benign -> silent) case.
Run:  python -m pytest test_companion_integrity.py -v
"""

import json
import os
import sys
import time


import pytest

from ids.companion_integrity import (
    IntegrityWorker,
    ManifestError,
    UpdateGuard,
    canonical_bytes,
    hash_file,
    load_manifest,
    make_fw_alert,
    sign_manifest,
    verify_file,
    verify_manifest_signature,
    CompanionIntegrityModule,
    FileIntegrityWatcher,
)


# ---------------------------------------------------------------------------
# Fixtures — a signed manifest describing one good file + one extra file
# ---------------------------------------------------------------------------
@pytest.fixture()
def fw_env(tmp_path):
    """Directory tree + signed manifest + key. Returns dict of paths/state."""
    root = tmp_path / "fw"
    fwdir = root / "firmware"
    fwdir.mkdir(parents=True)

    good = fwdir / "ardupilot.apj"
    good.write_bytes(b"GOOD-FIRMWARE-IMAGE-BYTES")

    digest, size = hash_file(str(good))
    manifest = {
        "manifest_version": 1,
        "generated_utc": "2026-09-24T00:00:00Z",
        "algorithm": "sha256",
        "entries": [{"path": "firmware/ardupilot.apj",
                     "sha256": digest, "size": size}],
    }
    key = os.urandom(32)
    mpath = tmp_path / "manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "manifest.json.sig").write_text(sign_manifest(manifest, key),
                                                encoding="utf-8")
    (tmp_path / "manifest.json.key").write_text(key.hex(), encoding="utf-8")

    return {
        "root": str(root), "fwdir": str(fwdir), "good": str(good),
        "manifest": manifest, "manifest_path": str(mpath),
        "key": key, "tmp": str(tmp_path),
    }


def make_policy(watch_dirs):
    return {
        "fail_mode": "alert_and_pass",
        "alerting": {"rate_limit_per_sec": 100, "dedupe_window_s": 1.0},
        "companion_integrity": {"watch_dirs": watch_dirs},
        "firmware": {"update_window": {"allowed_states": ["DISARMED"]}},
    }


# ---------------------------------------------------------------------------
# Manifest loading / signing (FW-009 preconditions)
# ---------------------------------------------------------------------------
class TestManifest:
    def test_load_valid_signed_manifest(self, fw_env):
        m = load_manifest(fw_env["manifest_path"], key=fw_env["key"],
                          require_signature=True)
        assert m["entries"][0]["path"] == "firmware/ardupilot.apj"

    def test_load_missing_manifest_raises(self, tmp_path):
        with pytest.raises(ManifestError):
            load_manifest(str(tmp_path / "nope.json"))

    def test_load_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(str(p))

    def test_load_oversized_manifest_raises(self, tmp_path):
        p = tmp_path / "big.json"
        p.write_text("x" * (MAX := 1_048_577), encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(str(p))

    def test_structure_missing_entries_raises(self):
        from ids.companion_integrity import _validate_manifest_structure
        bad = {"manifest_version": 1, "algorithm": "sha256", "entries": []}
        with pytest.raises(ManifestError):
            _validate_manifest_structure(bad)

    def test_structure_unsafe_path_raises(self):
        from ids.companion_integrity import _validate_manifest_structure
        bad = {"manifest_version": 1, "algorithm": "sha256",
               "entries": [{"path": "../etc/passwd", "sha256": "a" * 64,
                            "size": 1}]}
        with pytest.raises(ManifestError):
            _validate_manifest_structure(bad)

    def test_signature_valid_and_tampered(self, fw_env):
        m = fw_env["manifest"]
        sig = sign_manifest(m, fw_env["key"])
        assert verify_manifest_signature(m, fw_env["key"], sig)      # positive
        bad = dict(m)
        bad["entries"] = [dict(m["entries"][0], size=999)]           # tampered
        assert not verify_manifest_signature(bad, fw_env["key"], sig)  # negative

    def test_tampered_manifest_rejected_on_load(self, fw_env):
        # rewrite manifest content but keep old signature -> must fail loudly
        tampered = dict(fw_env["manifest"])
        tampered["entries"] = [dict(fw_env["manifest"]["entries"][0], size=1)]
        (fw_env["tmp"] + "/manifest.json") and None
        p = fw_env["manifest_path"]
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh)
        with pytest.raises(ManifestError):
            load_manifest(p, key=fw_env["key"], require_signature=True)


# ---------------------------------------------------------------------------
# File verification (FW-005)
# ---------------------------------------------------------------------------
class TestVerifyFile:
    def test_clean_file_ok(self, fw_env):
        res = verify_file(fw_env["manifest"], fw_env["good"])
        assert res.ok and res.reason is None                          # positive

    def test_tampered_content_hash_mismatch(self, fw_env):
        with open(fw_env["good"], "r+b") as fh:
            data = bytearray(fh.read())
            data[0] ^= 0xFF
            fh.seek(0)
            fh.write(data)
        res = verify_file(fw_env["manifest"], fw_env["good"])
        assert not res.ok and res.reason == "hash_mismatch"           # negative

    def test_truncated_file_size_mismatch(self, fw_env):
        with open(fw_env["good"], "wb") as fh:
            fh.write(b"SHORT")
        res = verify_file(fw_env["manifest"], fw_env["good"])
        assert not res.ok and res.reason == "size_mismatch"

    def test_missing_file_flagged(self, fw_env):
        os.unlink(fw_env["good"])
        res = verify_file(fw_env["manifest"], fw_env["good"])
        assert not res.ok and res.reason == "missing"

    def test_unlisted_file_not_in_manifest(self, fw_env):
        extra = os.path.join(fw_env["fwdir"], "evil.py")
        with open(extra, "w", encoding="utf-8") as fh:
            fh.write("print('pwn')")
        res = verify_file(fw_env["manifest"], extra)
        assert not res.ok and res.reason == "not_in_manifest"
        assert res.in_manifest is False

    def test_absolute_path_resolves_to_manifest_entry(self, fw_env):
        # absolute watch-root path must align to the relative manifest key
        res = verify_file(fw_env["manifest"], fw_env["good"])
        assert res.ok and res.path == "firmware/ardupilot.apj"


# ---------------------------------------------------------------------------
# Background worker (bounded queue / hot path)
# ---------------------------------------------------------------------------
class TestWorker:
    def test_submit_process_result(self, fw_env):
        w = IntegrityWorker(fw_env["manifest"])
        assert w.submit(fw_env["good"]) is True
        assert w.process_pending() == 1
        res = w.result(fw_env["good"])
        assert res is not None and res.ok                             # positive

    def test_tamper_processed_as_failed(self, fw_env):
        with open(fw_env["good"], "r+b") as fh:
            data = bytearray(fh.read())
            data[-1] ^= 0x5A
            fh.seek(0)
            fh.write(data)
        w = IntegrityWorker(fw_env["manifest"])
        w.submit(fw_env["good"])
        w.process_pending()
        res = w.result(fw_env["good"])
        assert res is not None and not res.ok                         # negative
        assert w.stats["failed"] == 1

    def test_queue_is_bounded(self, fw_env):
        w = IntegrityWorker(fw_env["manifest"], queue_size=2)
        sent = sum(w.submit(f"/nonexistent/{i}.bin") for i in range(10))
        assert sent == 2                       # rest dropped, queue never grows
        assert w.stats["dropped_queue_full"] == 8
        assert w._q.qsize() <= 2

    def test_quick_check_cached_then_hot(self, fw_env):
        w = IntegrityWorker(fw_env["manifest"])
        assert w.quick_check(fw_env["good"]) is None   # unknown yet -> None
        w.process_pending()
        res = w.quick_check(fw_env["good"])
        assert res is not None and res.ok              # cached O(1) verdict


# ---------------------------------------------------------------------------
# Watcher (FW-005)
# ---------------------------------------------------------------------------
class TestWatcher:
    """Two-pass pattern: scan#1 enqueues, worker processes, scan#2 alerts."""

    def _watcher(self, fw_env):
        w = IntegrityWorker(fw_env["manifest"])
        pol = make_policy([fw_env["root"]])
        return w, FileIntegrityWatcher(w, [fw_env["root"]], pol)

    def _two_pass(self, w, watcher):
        watcher.scan_once()          # pass 1: discover + enqueue
        w.process_pending()          # worker hashes everything queued
        return watcher.scan_once()   # pass 2: cached verdicts -> alerts

    def test_clean_pass_no_alerts(self, fw_env):
        w, watcher = self._watcher(fw_env)
        assert self._two_pass(w, watcher) == []                        # negative

    def test_unexpected_new_file_detected(self, fw_env):
        extra = os.path.join(fw_env["fwdir"], "payload.lua")
        with open(extra, "w", encoding="utf-8") as fh:
            fh.write("malicious")
        w, watcher = self._watcher(fw_env)
        alerts = self._two_pass(w, watcher)
        assert any(a.reason == "companion_file_unexpected" for a in alerts)

    def test_missing_file_detected(self, fw_env):
        w, watcher = self._watcher(fw_env)
        os.unlink(fw_env["good"])
        alerts = self._two_pass(w, watcher)
        assert any(a.reason == "companion_file_missing" for a in alerts)

    def test_modified_file_detected(self, fw_env):
        w, watcher = self._watcher(fw_env)
        with open(fw_env["good"], "r+b") as fh:
            data = bytearray(fh.read())
            data[2] ^= 0x01
            fh.seek(0)
            fh.write(data)
        alerts = self._two_pass(w, watcher)
        assert any(a.reason == "companion_file_hash_mismatch" for a in alerts)


# ---------------------------------------------------------------------------
# Update-workflow guard (FW-009)
# ---------------------------------------------------------------------------
class TestUpdateGuard:
    def _guard(self, state: str):
        pol = make_policy([])
        return UpdateGuard(pol, state_getter=lambda: state)

    def test_update_while_flying_flagged(self):
        alert = self._guard("FLYING").check()
        assert alert is not None                                       # positive
        assert alert.reason == "update_outside_allowed_window"
        assert alert.rule_id == "FW-009"

    def test_update_disarmed_with_manifest_silent(self):
        alert = self._guard("DISARMED").check(has_valid_manifest=True)
        assert alert is None                                           # negative

    def test_update_disarmed_without_manifest_flagged(self):
        alert = self._guard("DISARMED").check(has_valid_manifest=False)
        assert alert is not None
        assert alert.reason == "update_without_valid_manifest"

    def test_fail_mode_block_marks_evidence(self):
        pol = make_policy([])
        pol["fail_mode"] = "alert_and_block"
        g = UpdateGuard(pol, state_getter=lambda: "FLYING")
        alert = g.check()
        assert alert is not None
        assert alert.evidence.get("drop") is True


# ---------------------------------------------------------------------------
# Facade end-to-end
# ---------------------------------------------------------------------------
class TestFacade:
    def test_tamper_to_alert_end_to_end(self, fw_env):
        pol = make_policy([fw_env["root"]])
        mod = CompanionIntegrityModule(policy=pol,
                                       manifest_path=fw_env["manifest_path"])

        def two_pass():
            mod.scan_once()                       # discover + enqueue
            mod.worker.process_pending()          # hash everything queued
            return mod.scan_once()                # cached verdicts -> alerts

        # clean baseline -> silent (FPR negative)
        assert two_pass() == []

        # tamper, re-verify via worker, scan -> alert
        with open(fw_env["good"], "r+b") as fh:
            data = bytearray(fh.read())
            data[1] ^= 0x7F
            fh.seek(0)
            fh.write(data)
        alerts = two_pass()
        assert any(a.reason == "companion_file_hash_mismatch" for a in alerts)

    def test_manifest_error_surfaces(self, fw_env):
        pol = make_policy([fw_env["root"]])
        # corrupt manifest -> module still constructs, error recorded
        with open(fw_env["manifest_path"], "w", encoding="utf-8") as fh:
            fh.write("{broken")
        mod = CompanionIntegrityModule(policy=pol,
                                       manifest_path=fw_env["manifest_path"])
        assert mod.manifest is None
        assert mod.manifest_error is not None
        alerts = mod.scan_once()
        assert any(a.reason == "manifest_load_error" for a in alerts)


# ---------------------------------------------------------------------------
# Alert schema sanity
# ---------------------------------------------------------------------------
def test_fw_alert_has_mitre_and_rule():
    a = make_fw_alert("high", "companion_file_hash_mismatch", rule_id="FW-005",
                      evidence={"path": "x"})
    assert a.mitre_attack == "T0856"
    assert a.rule_id == "FW-005"
    assert a.severity == "high"