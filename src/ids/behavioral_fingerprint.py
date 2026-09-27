"""
behavioral_fingerprint.py — Firmware Attacks Module, Phase 4.

Cyber-physical behavioral fingerprint: learns a benign baseline of flight
dynamics from benign SITL/flight logs, then flags DRIFT in those features
after a tamper-relevant event (reboot / version change / upload event).

DESIGN (deliberately simple, explainable, tunable, cheap — see mentor
synthesis: fused cyber-physical detection matters, but on a companion
computer we trade heavy ML for transparent statistics):
  * Per-feature Welford running stats (mean/variance, O(1) per sample) form
    the baseline during `collecting` mode.
  * After `min_samples` the baseline FREEZES; monitoring compares a fixed
    rolling window (bounded deque) of recent values against it with a
    z-score (Shewhart-style — same family as the RF-jamming layer).
  * Alerts are EVENT-GATED: drift is reported only within
    `event_window_s` of register_event("reboot"|"version_change"|"upload")
    unless `alert_without_tamper_event` is set in policy. This matches the
    Phase-0 model (F-010: post-tamper behavioral drift).
  * `retrain_on_version_change`: a version_change event returns the module
    to collecting mode (legitimate upgrade invalidates the old baseline).

FEATURES (all computable from standard MAVLink telemetry, no extra deps):
  attitude_vs_command   mean |target roll/pitch − measured roll/pitch| (deg),
                        from ATTITUDE_TARGET vs last ATTITUDE (GUIDED/AUTO).
  motor_vs_throttle     motor-output dispersion (max−min across servo1..8 of
                        SERVO_OUTPUT_RAW, µs): proxy for mixer/tuning tamper.
  telemetry_rate_jitter mean |Δt_heartbeat − expected_interval| (s).
  pid_response          measured attitude response rate (|Δattitude|/Δt,
                        deg/s) from consecutive ATTITUDE: PID-response proxy.

HONEST LIMITS (documented, per Phase-0):
  * A drift alert INDICATES suspected tampering; it is NOT proof. Legitimate
    payload/config changes, wind, and degraded sensors can also drift.
  * Baseline must be trained on BENIGN data for the same airframe; a stolen
    baseline file is meaningless without attestation (hardware root of trust
    is out of scope here — F-011/F-012).
  * ML upgrade path (LightGBM + SMOTE + PCA + SHAP per mentor research) is a
    Phase-6+ evaluation concern; this module stays stdlib-only and bounded.

HOT PATH: ingest() is O(1) fixed work (deque append + Welford update);
evaluation runs every `evaluate_every` ingests and is O(#features). Memory:
one fixed deque + 3 floats per enabled feature. No unbounded growth.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from .command_injection_detector import AlertRateLimiter, IDSAlert, _MITRE_MAP
from .ids_config import get_fail_mode, load_config

logger = logging.getLogger("ids.firmware_behavior")

# Features this implementation can compute (policy lists are filtered to these)
VALID_FEATURES = (
    "attitude_vs_command",
    "motor_vs_throttle",
    "telemetry_rate_jitter",
    "pid_response",
)

_EVENT_KINDS = ("reboot", "version_change", "upload")
_MAX_TARGET_AGE_S = 0.5        # ATTITUDE_TARGET vs last ATTITUDE pairing window
_MAX_DT_S = 2.0                # skip absurd deltas (gap/reorder)
_BASELINE_FILE_VERSION = 1


# ---------------------------------------------------------------------------
# Welford running statistics (numerically stable, O(1) per sample)
# ---------------------------------------------------------------------------
class _Welford:
    __slots__ = ("count", "mean", "m2")

    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, x: float) -> None:
        self.count += 1
        d = x - self.mean
        self.mean += d / self.count
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    def to_dict(self) -> Dict[str, float]:
        return {"count": self.count, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: Dict[str, float]) -> "_Welford":
        w = cls()
        w.count = int(d.get("count", 0))
        w.mean = float(d.get("mean", 0.0))
        w.m2 = float(d.get("m2", 0.0))
        return w


# ---------------------------------------------------------------------------
# Alert helper (reuses shared IDSAlert + MITRE map)
# ---------------------------------------------------------------------------
def _make_alert(reason: str, rule_id: str, severity: str,
                evidence: Dict[str, Any],
                confidence: Optional[float] = None) -> IDSAlert:
    return IDSAlert(
        timestamp=time.time(), severity=severity, reason=reason,
        rule_id=rule_id, mitre_attack=_MITRE_MAP.get(reason),
        evidence=evidence, confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Behavioral fingerprint
# ---------------------------------------------------------------------------
class BehavioralFingerprint:
    """
    Learn-then-monitor behavioral baseline. See module docstring for design
    and limits. Unit: all attitude values in degrees, time in seconds.
    """

    def __init__(self, policy: Optional[Dict[str, Any]] = None,
                 state_getter: Optional[Any] = None) -> None:
        del state_getter  # reserved: arm-state gating for future features
        if policy is None:
            from .ids_config import default_policy
            policy = default_policy()
        self._policy = policy
        bb = policy.get("behavioral_baseline", {})
        self.enabled = bool(bb.get("enabled", False))
        self.min_samples = max(1, int(bb.get("min_samples", 1000)))
        self.threshold = max(1.0, float(bb.get("drift_threshold_std", 5.0)))
        self.window_size = max(4, int(bb.get("window_size", 64)))
        self.evaluate_every = max(1, int(bb.get("evaluate_every", 16)))
        self.event_window_s = max(0.0, float(bb.get("event_window_s", 300.0)))
        self.alert_without_event = bool(bb.get("alert_without_tamper_event", False))
        self.expected_hb_s = max(0.05, float(
            bb.get("expected_heartbeat_interval_s", 1.0)))
        self.epsilon = float(bb.get("epsilon_std", 1e-6))
        self.retrain_on_version_change = bool(
            bb.get("retrain_on_version_change", True))
        self.baseline_path = str(bb.get("baseline_path", "") or "")

        requested = list(bb.get("features", VALID_FEATURES))
        self.features = [f for f in requested if f in VALID_FEATURES]
        dropped = [f for f in requested if f not in VALID_FEATURES]
        if dropped:
            logger.warning("ignoring unknown baseline features: %s", dropped)

        # Per-feature state
        self._baseline: Dict[str, _Welford] = {f: _Welford() for f in self.features}
        self._window: Dict[str, deque] = {
            f: deque(maxlen=self.window_size) for f in self.features}
        self._mode = "collecting"          # collecting | monitoring
        self._since_event_ts: Optional[float] = None
        self._last_event_kind: Optional[str] = None

        # Cross-message pairing state (bounded: scalars only)
        self._last_att: Optional[Tuple[float, float, float]] = None  # roll,pitch,ts
        self._last_hb_ts: Optional[float] = None

        al = policy.get("alerting", {})
        self._limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0))
        self._fail_mode = get_fail_mode(policy)

        self._ingest_count = 0
        self.stats: Dict[str, Any] = {"ingested": 0, "evaluations": 0,
                                      "alerts": 0, "events": 0,
                                      "suppressed_no_event": 0}
        if self.baseline_path and os.path.exists(self.baseline_path):
            try:
                self.load(self.baseline_path)
            except Exception as exc:                       # fail loud-ish
                logger.error("baseline load failed from %s: %s",
                             self.baseline_path, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def register_event(self, kind: str, ts: Optional[float] = None) -> None:
        """
        Record a tamper-relevant event. Opens the drift-reporting window and,
        for version_change (if retrain_on_version_change), restarts training.
        """
        if kind not in _EVENT_KINDS:
            raise ValueError(f"unknown event kind {kind!r}")
        ts = time.time() if ts is None else ts
        self.stats["events"] += 1
        if kind == "version_change" and self.retrain_on_version_change:
            self._mode = "collecting"
            self._baseline = {f: _Welford() for f in self.features}
            self._window = {f: deque(maxlen=self.window_size)
                            for f in self.features}
            logger.info("version_change: baseline retrain started")
        elif kind in ("reboot", "upload"):
            # Reboot/upload events do NOT retrain; they only open the
            # drift-reporting window. Baseline stays frozen.
            pass
        self._since_event_ts = ts
        self._last_event_kind = kind

    def ingest(self, msg: Dict[str, Any], ts: Optional[float] = None
               ) -> Optional[IDSAlert]:
        """
        Hot path: update feature windows from one telemetry dict.
        Evaluates drift on the configured cadence; returns an alert or None.
        """
        if not self.enabled:
            return None
        self._ingest_count += 1
        self.stats["ingested"] += 1
        now = time.time() if ts is None else ts

        mt = msg.get("msg_type")
        if mt == "ATTITUDE":
            self._on_attitude(msg, now)
        elif mt == "ATTITUDE_TARGET":
            self._on_attitude_target(msg, now)
        elif mt == "SERVO_OUTPUT_RAW":
            self._on_servo(msg)
        elif mt == "HEARTBEAT":
            self._on_heartbeat(now)

        if self._mode == "collecting":
            self._maybe_freeze()
        elif (self._ingest_count % self.evaluate_every) == 0:
            return self.evaluate(now)
        return None

    def train_from_messages(self, msgs: List[Dict[str, Any]],
                            ts: Optional[float] = None) -> None:
        """Bulk-train from benign messages (SITL/flight log replay helper)."""
        base_ts = time.time() if ts is None else ts
        for i, m in enumerate(msgs):
            self.ingest(m, ts=base_ts + i * 0.01)

    def freeze_baseline(self) -> bool:
        """Manually freeze. True when enough data existed."""
        if self._mode == "monitoring":
            return True
        ready = [f for f in self.features
                 if self._baseline[f].count >= self.min_samples]
        if len(ready) < len(self.features):
            logger.info("freeze requested but features not ready: %s",
                        {f: self._baseline[f].count for f in self.features})
            return False
        self._mode = "monitoring"
        logger.info("behavioral baseline frozen (%d features)", len(ready))
        return True

    def evaluate(self, now: Optional[float] = None) -> Optional[IDSAlert]:
        """One drift evaluation over all windowed features (bounded)."""
        if self._mode != "monitoring":
            return None
        self.stats["evaluations"] += 1
        drifted: List[Dict[str, Any]] = []
        for f in self.features:
            w = self._window[f]
            b = self._baseline[f]
            if len(w) < w.maxlen or b.count < self.min_samples:
                continue
            bstd = b.std
            if bstd <= self.epsilon:
                continue                       # constant feature: not informative
            wmean = sum(w) / len(w)
            z = (wmean - b.mean) / bstd
            if abs(z) > self.threshold:
                drifted.append({
                    "feature": f,
                    "window_mean": round(wmean, 6),
                    "baseline_mean": round(b.mean, 6),
                    "baseline_std": round(bstd, 6),
                    "z_score": round(z, 3),
                    "samples": len(w),
                })
        if not drifted:
            return None

        # Event gate: report drift only near a tamper-relevant event
        now = time.time() if now is None else now
        in_window = (self._since_event_ts is not None
                     and (now - self._since_event_ts) <= self.event_window_s)
        if not in_window and not self.alert_without_event:
            self.stats["suppressed_no_event"] += 1
            logger.debug("drift suppressed (no recent tamper event): %s", drifted)
            return None

        max_z = max(abs(d["z_score"]) for d in drifted)
        confidence = round(min(1.0, max_z / (2.0 * self.threshold)), 2)
        alert = _make_alert(
            reason="behavioral_baseline_drift",
            rule_id="FW-010",
            severity="high" if len(drifted) > 1 else "medium",
            evidence={
                "drifted_features": drifted,
                "threshold_std": self.threshold,
                "last_event": self._last_event_kind,
                "event_age_s": (round(now - self._since_event_ts, 1)
                                if self._since_event_ts is not None else None),
                "note": "indicates suspected tampering, not proof",
            },
            confidence=confidence,
        )
        if not self._limiter.allow(alert.reason, 0, "behavior", now):
            return None
        if self._fail_mode == "alert_and_block":
            alert.evidence["drop"] = True
        self.stats["alerts"] += 1
        return alert

    def save(self, path: str) -> None:
        """Persist the frozen baseline (JSON). Windows are not saved."""
        data = {
            "version": _BASELINE_FILE_VERSION,
            "mode": self._mode,
            "min_samples": self.min_samples,
            "threshold_std": self.threshold,
            "features": {f: self._baseline[f].to_dict() for f in self.features},
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)

    def load(self, path: str) -> None:
        """Load a baseline (e.g. trained offline from SITL logs)."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if int(data.get("version", 0)) != _BASELINE_FILE_VERSION:
            raise ValueError(f"unsupported baseline version: {data.get('version')}")
        feats = data.get("features", {})
        for f in self.features:
            if f in feats:
                self._baseline[f] = _Welford.from_dict(feats[f])
        self._mode = str(data.get("mode", "monitoring"))
        if self._mode not in ("collecting", "monitoring"):
            self._mode = "monitoring"

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "mode": self._mode,
            "features": {f: self._baseline[f].count for f in self.features},
            "window_len": {f: len(self._window[f]) for f in self.features},
        }

    def reset(self, keep_baseline: bool = False) -> None:
        """Reset windows/event state; optionally keep the frozen baseline."""
        self._window = {f: deque(maxlen=self.window_size) for f in self.features}
        self._since_event_ts = None
        self._last_event_kind = None
        self._last_att = None
        self._last_hb_ts = None
        if not keep_baseline:
            self._baseline = {f: _Welford() for f in self.features}
            self._mode = "collecting"

    # ------------------------------------------------------------------
    # Feature extractors (each O(1), bounded)
    # ------------------------------------------------------------------
    def _add(self, feature: str, value: float) -> None:
        if self._mode == "collecting":
            self._baseline[feature].add(value)
        self._window[feature].append(value)

    def _on_attitude(self, msg: Dict[str, Any], now: float) -> None:
        try:
            roll = math.degrees(float(msg.get("roll", 0.0)))
            pitch = math.degrees(float(msg.get("pitch", 0.0)))
        except (TypeError, ValueError):
            return
        if self._last_att is not None:
            lroll, lpitch, lts = self._last_att
            dt = now - lts
            if 0.0 < dt <= _MAX_DT_S:
                if "pid_response" in self.features:
                    rate = (abs(roll - lroll) + abs(pitch - lpitch)) / dt
                    self._add("pid_response", rate)
        self._last_att = (roll, pitch, now)

    def _on_attitude_target(self, msg: Dict[str, Any], now: float) -> None:
        if "attitude_vs_command" not in self.features:
            return
        q = msg.get("attitude_quaternion") or msg.get("q")
        if not q or len(q) < 4:
            return
        try:
            w_, x, y, z = (float(q[0]), float(q[1]), float(q[2]), float(q[3]))
        except (TypeError, ValueError):
            return
        n = math.sqrt(w_ * w_ + x * x + y * y + z * z) or 1.0
        w_, x, y, z = w_ / n, x / n, y / n, z / n
        t_roll = math.degrees(math.atan2(2 * (w_ * x + y * z),
                                         1 - 2 * (x * x + y * y)))
        sin_p = max(-1.0, min(1.0, 2 * (w_ * y - z * x)))
        t_pitch = math.degrees(math.asin(sin_p))
        if self._last_att is None:
            return
        lroll, lpitch, lts = self._last_att
        if (now - lts) > _MAX_TARGET_AGE_S:
            return
        residual = abs(t_roll - lroll) + abs(t_pitch - lpitch)
        self._add("attitude_vs_command", residual)

    def _on_servo(self, msg: Dict[str, Any]) -> None:
        if "motor_vs_throttle" not in self.features:
            return
        vals = []
        for i in range(1, 9):                       # servo1_raw..servo8_raw
            v = msg.get(f"servo{i}_raw")
            if isinstance(v, (int, float)) and v > 0:
                vals.append(float(v))
        if len(vals) >= 2:
            self._add("motor_vs_throttle", max(vals) - min(vals))

    def _on_heartbeat(self, now: float) -> None:
        if "telemetry_rate_jitter" not in self.features:
            return
        if self._last_hb_ts is not None:
            dt = now - self._last_hb_ts
            if 0.0 < dt <= _MAX_DT_S:
                self._add("telemetry_rate_jitter", abs(dt - self.expected_hb_s))
        self._last_hb_ts = now

    def _maybe_freeze(self) -> None:
        if all(self._baseline[f].count >= self.min_samples
               for f in self.features):
            self._mode = "monitoring"
            logger.info("behavioral baseline auto-frozen (%d samples/feature)",
                        self.min_samples)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("BEHAVIORAL FINGERPRINT — SELF TEST (synthetic, no hardware)")
    print("=" * 70)
    ok = True

    def pol():
        return {
            "fail_mode": "alert_and_pass",
            "alerting": {"rate_limit_per_sec": 100, "dedupe_window_s": 0.0},
            "behavioral_baseline": {
                "enabled": True, "min_samples": 40, "drift_threshold_std": 5.0,
                "window_size": 8, "evaluate_every": 4, "event_window_s": 300.0,
                "features": list(VALID_FEATURES),
            },
        }

    fp = BehavioralFingerprint(pol())

    # benign training stream: alternating values -> mean/std well-defined
    ts = 1000.0
    for i in range(60):
        ts += 0.5
        r = (1.0 if i % 2 else 3.0)          # deg residual, mean 2, std ~1
        fp.ingest({"msg_type": "ATTITUDE_TARGET",
                   "attitude_quaternion": [1.0, 0.02, 0.0, 0.0]}, ts=ts)
        fp.ingest({"msg_type": "ATTITUDE", "roll": 0.02 * (1 if i % 2 else -1),
                   "pitch": 0.0}, ts=ts)
        fp.ingest({"msg_type": "SERVO_OUTPUT_RAW",
                   "servo1_raw": 1500 + (20 if i % 2 else -20),
                   "servo2_raw": 1500 - (20 if i % 2 else -20)}, ts=ts)
        fp.ingest({"msg_type": "HEARTBEAT"}, ts=ts)
    st = fp.get_stats()
    print(f"[1] auto-frozen: mode={st['mode']} (expect monitoring) -> "
          f"{'PASS' if st['mode'] == 'monitoring' else 'FAIL'}")
    ok &= st["mode"] == "monitoring"

    # benign continuation -> no alert (FPR negative)
    a = fp.evaluate(ts)
    print(f"[2] benign drift-free silent -> {'PASS' if a is None else 'FAIL'}")
    ok &= a is None

    # drift suppressed without tamper event (negative)
    for i in range(16):
        ts += 0.5
        fp.ingest({"msg_type": "ATTITUDE_TARGET",
                   "attitude_quaternion": [1.0, 0.18, 0.0, 0.0]}, ts=ts)
        fp.ingest({"msg_type": "ATTITUDE", "roll": 0.01, "pitch": 0.0}, ts=ts)
    a = fp.evaluate(ts)
    print(f"[3] drift w/o event suppressed -> {'PASS' if a is None else 'FAIL'}")
    ok &= a is None

    # register reboot event -> drift now reported (positive)
    fp.register_event("reboot", ts=ts)
    a = fp.evaluate(ts)
    print(f"[4] drift after reboot flagged -> {'PASS' if a is not None else 'FAIL'}")
    ok &= a is not None
    if a:
        feats = [d["feature"] for d in a.evidence["drifted_features"]]
        print(f"    drifted: {feats}  mitre={a.mitre_attack} "
              f"rule={a.rule_id} conf={a.confidence}")
        ok &= a.rule_id == "FW-010"

    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    print("=" * 70)
    raise SystemExit(0 if ok else 1)
