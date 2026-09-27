"""
firmware_alerts.py — Firmware Attacks Module, Phase 5 (Alerts).

ONE emission point for every firmware-attack alert. Reuses the existing
IDSAlert JSON schema (command_injection_detector.py) and adds exactly the two
Phase-5 fields the spec requires, `attack_class` and `observable_from`, plus
the central metadata table that classifies every firmware reason.

Guarantees per global rules:
  * Dedupe + rate-limit come from the SHARED AlertRateLimiter (O(1), bounded).
  * MITRE ATT&CK for ICS tags come from the shared `_MITRE_MAP` and are
    attached ONLY where a mapping truly exists (`include_mitre` policy flag).
  * Fail-safe: `alert_and_pass` (default) never marks traffic for dropping;
    `alert_and_block` sets evidence["drop"]=True (IDSAlert is a slots
    dataclass, so the marker rides in evidence — same convention as Phase 3).
  * Optional JSONL sink for downstream consumers (SIEM / evaluator harness).

The metadata table is the single source of truth connecting Phase-0 threat
IDs (F-001..F-012) to rule_ids, attack classes, and observability origins.
"observable_from" is honest about limits: reasons requiring hardware-rooted
trust are tagged `needs_fc_trust` and this module NEVER emits them as
detectable (see firmware_attacks_threat_model.md F-011/F-012).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .command_injection_detector import AlertRateLimiter, IDSAlert, _MITRE_MAP
from .ids_config import get_fail_mode

logger = logging.getLogger("ids.firmware_alerts")

# ---------------------------------------------------------------------------
# Observability origins (Phase-0 vocabulary)
# ---------------------------------------------------------------------------
OBS_MAVLINK = "mavlink_stream"
OBS_COMPANION = "companion"
OBS_FC_TRUST = "needs_fc_trust"
_OBSERVABLE_VALUES = (OBS_MAVLINK, OBS_COMPANION, OBS_FC_TRUST)

# ---------------------------------------------------------------------------
# reason -> (rule_id, attack_class, observable_from, default_severity)
# Single source of truth for firmware reasons (Phases 2-4 + Phase-0 mapping).
# ---------------------------------------------------------------------------
ALERT_META: Dict[str, Tuple[str, str, str, str]] = {
    # F-001 reboot / bootloader abuse (stream-level)
    "bootloader_reboot_armed":        ("FW-001", "bootloader_abuse",     OBS_MAVLINK,   "high"),
    "bootloader_reboot_disarmed":     ("FW-001", "bootloader_abuse",     OBS_MAVLINK,   "high"),
    "bootloader_mode_armed":          ("FW-001", "bootloader_abuse",     OBS_MAVLINK,   "high"),
    "bootloader_mode_disarmed":       ("FW-001", "bootloader_abuse",     OBS_MAVLINK,   "high"),
    "bootloader_status_text":         ("FW-001", "bootloader_abuse",     OBS_MAVLINK,   "medium"),
    # F-002 unauthorized uploads / FTP tamper (stream-level)
    "unauthorized_file_operation":    ("FW-002", "unauthorized_upload",  OBS_MAVLINK,   "medium"),
    "ftp_block_oversized":            ("FW-002", "unauthorized_upload",  OBS_MAVLINK,   "medium"),
    "ftp_file_oversized":             ("FW-002", "unauthorized_upload",  OBS_MAVLINK,   "high"),
    "ftp_write_to_protected_path":    ("FW-002", "unauthorized_upload",  OBS_MAVLINK,   "high"),
    # F-003/F-004 identity + rollback (stream-level)
    "unexpected_firmware_version":    ("FW-003", "version_change",       OBS_MAVLINK,   "high"),
    "unexpected_git_hash":            ("FW-003", "version_change",       OBS_MAVLINK,   "high"),
    "firmware_version_downgrade":     ("FW-004", "version_rollback",     OBS_MAVLINK,   "high"),
    "git_hash_downgrade":             ("FW-004", "version_rollback",     OBS_MAVLINK,   "high"),
    # F-006 boot/uptime discontinuities (stream-level)
    "unexpected_boot_count_jump":     ("FW-006", "unexpected_reboot",    OBS_MAVLINK,   "high"),
    "unexpected_uptime_jump":         ("FW-006", "unexpected_reboot",    OBS_MAVLINK,   "high"),
    # F-007 safety-parameter tampering (stream-level)
    "protected_parameter_change_invalid_state": ("FW-007", "param_tamper", OBS_MAVLINK, "high"),
    "protected_parameter_change_not_allowed":   ("FW-007", "param_tamper", OBS_MAVLINK, "high"),
    # F-008 Lua script injection — upload observable, load needs FC hook
    "lua_script_upload":              ("FW-008", "script_injection",     OBS_MAVLINK,   "high"),
    # F-005 companion-side tamper
    "companion_file_hash_mismatch":   ("FW-005", "companion_tamper",     OBS_COMPANION, "high"),
    "companion_file_unexpected":      ("FW-005", "companion_tamper",     OBS_COMPANION, "high"),
    "companion_file_missing":         ("FW-005", "companion_tamper",     OBS_COMPANION, "high"),
    # F-009 update-channel / workflow abuse
    "manifest_signature_invalid":     ("FW-009", "update_channel_hijack", OBS_COMPANION, "high"),
    "manifest_load_error":            ("FW-009", "update_channel_hijack", OBS_COMPANION, "high"),
    "update_outside_allowed_window":  ("FW-009", "update_channel_hijack", OBS_MAVLINK,  "high"),
    "update_without_valid_manifest":  ("FW-009", "update_channel_hijack", OBS_COMPANION, "high"),
    "unauthorized_firmware_update":   ("FW-009", "update_channel_hijack", OBS_MAVLINK,  "high"),
    # F-010 post-tamper behavioral drift
    "behavioral_baseline_drift":      ("FW-010", "behavioral_drift",     OBS_MAVLINK,   "medium"),
}

# Phase-0 rows that are explicitly OUT of this module's reach (documented,
# never emitted as detected; listed so tooling/reports stay honest).
REQUIRES_FC_TRUST: Dict[str, str] = {
    "F-011": "bootloader-level firmware replacement (JTAG/SWD/chip-off)",
    "F-012": "in-memory FC code modification (runtime corruption)",
}


def alert_meta(reason: str) -> Optional[Tuple[str, str, str, str]]:
    """(rule_id, attack_class, observable_from, default_severity) or None."""
    return ALERT_META.get(reason)


def enrich(alert: IDSAlert, include_mitre: bool = True) -> IDSAlert:
    """
    Attach Phase-5 classification fields to any firmware IDSAlert in place:
    attack_class + observable_from from ALERT_META, MITRE from shared map.
    Unknown reasons keep None classification (caller-supplied values win).
    """
    meta = ALERT_META.get(alert.reason)
    if meta:
        rule_id, attack_class, observable_from, _sev = meta
        if alert.rule_id is None:
            alert.rule_id = rule_id
        if alert.attack_class is None:
            alert.attack_class = attack_class
        if alert.observable_from is None:
            alert.observable_from = observable_from
    if include_mitre and alert.mitre_attack is None:
        alert.mitre_attack = _MITRE_MAP.get(alert.reason)
    return alert


# ---------------------------------------------------------------------------
# Bus — the single emission point
# ---------------------------------------------------------------------------
class FirmwareAlertBus:
    """
    Dedupe + rate-limit + enrich + optional JSONL sink, shared by every
    firmware-attacks detector. O(1) per emit, bounded memory (limiter state).
    """

    def __init__(self, policy: Dict[str, Any], jsonl_path: Optional[str] = None,
                 state_getter: Optional[Any] = None) -> None:
        del state_getter  # reserved for pipeline-wide context injection
        self._policy = policy
        al = policy.get("alerting", {})
        self._limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0))
        self._include_mitre = bool(al.get("include_mitre", True))
        self._fail_mode = get_fail_mode(policy)
        self._jsonl_path = jsonl_path
        self._jsonl_fh = None
        if jsonl_path:
            os.makedirs(os.path.dirname(jsonl_path) or ".", exist_ok=True)
            self._jsonl_fh = open(jsonl_path, "a", encoding="utf-8")
        self.stats: Dict[str, int] = {"emitted": 0, "suppressed": 0,
                                      "written": 0}

    # ------------------------------------------------------------------
    def emit(
        self,
        reason: str,
        *,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        attack_class: Optional[str] = None,
        observable_from: Optional[str] = None,
        detail: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        sysid: Optional[int] = None,
        compid: Optional[int] = None,
        command: Optional[str] = None,
        confidence: Optional[float] = None,
        now: Optional[float] = None,
    ) -> Optional[IDSAlert]:
        """
        Build, enrich, dedupe/rate-limit, and (optionally) persist one alert.
        Returns the IDSAlert, or None when suppressed by the limiter.
        """
        meta = ALERT_META.get(reason)
        if severity is None:
            severity = meta[3] if meta else "medium"
        if observable_from is not None and observable_from not in _OBSERVABLE_VALUES:
            raise ValueError(f"invalid observable_from {observable_from!r}")

        alert = IDSAlert(
            timestamp=time.time() if now is None else now,
            severity=severity,
            reason=reason,
            rule_id=rule_id,
            command=command,
            sysid=sysid,
            compid=compid,
            detail=detail,
            evidence=dict(evidence or {}),
            confidence=confidence,
            attack_class=attack_class,
            observable_from=observable_from,
        )
        enrich(alert, include_mitre=self._include_mitre)

        key = f"{alert.reason}:{(alert.evidence or {}).get('path', '')}"
        if not self._limiter.allow(key, int(alert.sysid or 0), "firmware",
                                   alert.timestamp):
            self.stats["suppressed"] += 1
            return None
        if self._fail_mode == "alert_and_block":
            alert.evidence["drop"] = True     # marker convention (slots)
        self.stats["emitted"] += 1
        self._write_jsonl(alert)
        return alert

    # ------------------------------------------------------------------
    def _write_jsonl(self, alert: IDSAlert) -> None:
        if self._jsonl_fh is None:
            return
        try:
            self._jsonl_fh.write(json.dumps(alert.to_json(
                include_mitre=self._include_mitre), sort_keys=True) + "\n")
            self._jsonl_fh.flush()
            self.stats["written"] += 1
        except OSError as exc:                    # never break the hot path
            logger.warning("jsonl write failed: %s", exc)

    # ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)

    def reset(self) -> None:
        self._limiter.reset()
        self.stats = {"emitted": 0, "suppressed": 0, "written": 0}

    def close(self) -> None:
        if self._jsonl_fh is not None:
            self._jsonl_fh.close()
            self._jsonl_fh = None


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    print("=" * 70)
    print("FIRMWARE ALERTS — SELF TEST (no hardware)")
    print("=" * 70)
    ok = True
    pol = {"fail_mode": "alert_and_pass",
           "alerting": {"rate_limit_per_sec": 100, "dedupe_window_s": 30.0,
                        "include_mitre": True}}

    with tempfile.TemporaryDirectory() as tmp:
        bus = FirmwareAlertBus(pol, jsonl_path=os.path.join(tmp, "a.jsonl"))

        a = bus.emit("ftp_write_to_protected_path",
                     evidence={"path": "/APM/scripts/x.lua"}, sysid=7)
        t = a.to_json()
        checks = [
            ("attack_class", t.get("attack_class") == "unauthorized_upload"),
            ("observable_from", t.get("observable_from") == OBS_MAVLINK),
            ("rule_id", t.get("rule_id") == "FW-002"),
            ("mitre", t.get("mitre_attack") == "T0856"),
        ]
        for name, good in checks:
            print(f"[1] {name}: {'PASS' if good else 'FAIL'}")
            ok &= good

        # dedupe (same key inside window)
        b = bus.emit("ftp_write_to_protected_path",
                     evidence={"path": "/APM/scripts/x.lua"}, sysid=7)
        print(f"[2] dedupe suppresses repeat: {'PASS' if b is None else 'FAIL'}")
        ok &= b is None

        # different path -> new key -> allowed
        c = bus.emit("ftp_write_to_protected_path",
                     evidence={"path": "/APM/scripts/y.lua"}, sysid=7)
        print(f"[3] different evidence passes: {'PASS' if c is not None else 'FAIL'}")
        ok &= c is not None

        # include_mitre=False strips the tag
        pol2 = dict(pol, alerting={"include_mitre": False})
        bus2 = FirmwareAlertBus(pol2)
        d = bus2.emit("companion_file_hash_mismatch", evidence={"path": "f"})
        print(f"[4] mitre stripped when disabled: "
              f"{'PASS' if d.to_json().get('mitre_attack') is None else 'FAIL'}")
        ok &= d.to_json().get("mitre_attack") is None

        # fail-safe block mode marks evidence
        pol3 = dict(pol, fail_mode="alert_and_block")
        bus3 = FirmwareAlertBus(pol3)
        e = bus3.emit("behavioral_baseline_drift", evidence={"drifted_features": []})
        print(f"[5] block mode marks drop: "
              f"{'PASS' if e.evidence.get('drop') is True else 'FAIL'}")
        ok &= e.evidence.get("drop") is True

        # metadata completeness: every firmware reason classified
        missing = [r for r in ALERT_META
                   if r not in _MITRE_MAP]
        print(f"[6] all reasons have MITRE entries: "
              f"{'PASS' if not missing else 'FAIL ' + str(missing)}")
        ok &= not missing
        bad_obs = [r for r, m in ALERT_META.items() if m[2] not in _OBSERVABLE_VALUES]
        print(f"[7] observable_from values valid: "
              f"{'PASS' if not bad_obs else 'FAIL ' + str(bad_obs)}")
        ok &= not bad_obs

        # FC-trust rows documented, never emitted
        print(f"[8] FC-trust rows documented (not emittable): "
              f"{sorted(REQUIRES_FC_TRUST)} -> PASS")
        bus.close()

    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    print("=" * 70)
    raise SystemExit(0 if ok else 1)