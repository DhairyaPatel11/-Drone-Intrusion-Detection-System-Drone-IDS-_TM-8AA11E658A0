"""
Phase 5 tests — firmware alert schema + bus (dedupe / rate-limit / JSONL).

Every behavior has a positive and a negative case, plus a consistency sweep
that keeps ALERT_META, _MITRE_MAP, and the Phase-0 threat model aligned.

Run:  python -m pytest test_firmware_alerts.py -v
"""

import json
import os
import sys


import pytest

from ids.command_injection_detector import IDSAlert, _MITRE_MAP
from ids.firmware_alerts import (
    ALERT_META,
    OBS_COMPANION,
    OBS_FC_TRUST,
    OBS_MAVLINK,
    REQUIRES_FC_TRUST,
    FirmwareAlertBus,
    alert_meta,
    enrich,
)
from ids.ids_config import default_policy


def make_bus(**alerting) -> FirmwareAlertBus:
    pol = default_policy()
    pol["alerting"] = {"rate_limit_per_sec": 100, "dedupe_window_s": 30.0,
                       "include_mitre": True, **alerting}
    return FirmwareAlertBus(pol)


# ---------------------------------------------------------------------------
# Enrichment (positive + negative)
# ---------------------------------------------------------------------------
class TestEnrichment:
    def test_known_reason_gets_full_classification(self):
        bus = make_bus()
        a = bus.emit("ftp_write_to_protected_path",
                     evidence={"path": "/APM/scripts/x.lua"}, sysid=7)
        assert a is not None
        t = a.to_json()
        assert t["attack_class"] == "unauthorized_upload"      # positive
        assert t["observable_from"] == OBS_MAVLINK
        assert t["rule_id"] == "FW-002"
        assert t["mitre_attack"] == "T0856"
        assert t["severity"] == "high"                          # table default

    def test_unknown_reason_has_no_fabricated_metadata(self):
        bus = make_bus()
        a = bus.emit("totally_unknown_reason")
        t = a.to_json()
        assert t.get("attack_class") is None                    # negative
        assert t.get("observable_from") is None
        assert t.get("mitre_attack") is None                    # no invented tag

    def test_caller_supplied_values_win(self):
        bus = make_bus()
        a = bus.emit("companion_file_hash_mismatch",
                     attack_class="custom_class",
                     observable_from=OBS_COMPANION,
                     rule_id="CUSTOM-1")
        t = a.to_json()
        assert t["attack_class"] == "custom_class"
        assert t["observable_from"] == OBS_COMPANION
        assert t["rule_id"] == "CUSTOM-1"

    def test_invalid_observable_from_rejected(self):
        bus = make_bus()
        with pytest.raises(ValueError):
            bus.emit("companion_file_missing", observable_from="telepathy")

    def test_severity_override(self):
        bus = make_bus()
        a = bus.emit("bootloader_status_text", severity="high")
        assert a.severity == "high"                             # override wins
        assert alert_meta("bootloader_status_text")[3] == "medium"  # default

    def test_enrich_works_on_prebuilt_alerts(self):
        raw = IDSAlert(timestamp=1.0, severity="medium", reason="unexpected_uptime_jump")
        enrich(raw)
        assert raw.attack_class == "unexpected_reboot"
        assert raw.rule_id == "FW-006"
        assert raw.mitre_attack == "T0856"


# ---------------------------------------------------------------------------
# Dedupe / rate limiting (positive + negative)
# ---------------------------------------------------------------------------
class TestLimiting:
    def test_same_key_deduped_within_window(self):
        bus = make_bus()
        first = bus.emit("companion_file_hash_mismatch", evidence={"path": "f"})
        second = bus.emit("companion_file_hash_mismatch", evidence={"path": "f"})
        assert first is not None and second is None             # neg after pos

    def test_different_evidence_not_deduped(self):
        bus = make_bus()
        a = bus.emit("companion_file_hash_mismatch", evidence={"path": "f1"})
        b = bus.emit("companion_file_hash_mismatch", evidence={"path": "f2"})
        assert a is not None and b is not None

    def test_rate_limit_flood(self):
        bus = make_bus(rate_limit_per_sec=3)
        got = sum(bus.emit("bootloader_status_text",
                           evidence={"path": f"/var/{i}"}) is not None
                  for i in range(10))
        assert got == 3                                          # only 3 pass

    def test_suppression_counted(self):
        bus = make_bus(rate_limit_per_sec=1)
        bus.emit("bootloader_status_text", evidence={"i": "0"})
        bus.emit("bootloader_status_text", evidence={"i": "1"})
        s = bus.get_stats()
        assert s["emitted"] == 1 and s["suppressed"] == 1


# ---------------------------------------------------------------------------
# Fail-safe modes
# ---------------------------------------------------------------------------
class TestFailSafe:
    def test_alert_and_pass_never_marks_drop(self):
        bus = make_bus()
        a = bus.emit("update_outside_allowed_window", sysid=255)
        assert a is not None
        assert "drop" not in a.evidence                          # default safe

    def test_alert_and_block_marks_drop_in_evidence(self):
        pol = default_policy()
        pol["fail_mode"] = "alert_and_block"
        pol["alerting"] = {"rate_limit_per_sec": 100, "dedupe_window_s": 30.0}
        bus = FirmwareAlertBus(pol)
        a = bus.emit("update_outside_allowed_window", sysid=255)
        assert a is not None
        assert a.evidence.get("drop") is True


# ---------------------------------------------------------------------------
# JSONL sink
# ---------------------------------------------------------------------------
class TestJsonl:
    def test_jsonl_lines_are_valid_schema(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        bus = make_bus()
        bus._jsonl_path = str(path)
        bus._jsonl_fh = open(path, "a", encoding="utf-8")
        a = bus.emit("unexpected_firmware_version",
                     evidence={"current_version": "4.3.0"})
        bus._write_jsonl(a)
        bus.close()
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert line["reason"] == "unexpected_firmware_version"
        assert line["attack_class"] == "version_change"
        assert line["observable_from"] == OBS_MAVLINK
        assert "mitre_attack" in line

    def test_write_failure_never_breaks_hot_path(self, tmp_path):
        bus = make_bus()
        bus._jsonl_path = str(tmp_path / "no_dir" / "x.jsonl")
        bus._jsonl_fh = None          # simulate unwritable sink
        a = bus.emit("companion_file_unexpected", evidence={"path": "p"})
        assert a is not None        # emission unaffected by sink problems


# ---------------------------------------------------------------------------
# Metadata consistency sweep (drift guard between phases)
# ---------------------------------------------------------------------------
class TestConsistency:
    def test_every_meta_reason_has_mitre_entry(self):
        missing = [r for r in ALERT_META if r not in _MITRE_MAP]
        assert missing == []

    def test_observable_values_are_from_the_enum(self):
        bad = [r for r, m in ALERT_META.items() if m[2] not in
               (OBS_MAVLINK, OBS_COMPANION, OBS_FC_TRUST)]
        assert bad == []

    def test_no_reason_claims_fc_trust(self):
        # Nothing in this module may claim detectability of FC-internal rows.
        fc = [r for r, m in ALERT_META.items() if m[2] == OBS_FC_TRUST]
        assert fc == []

    def test_rule_ids_match_phase0_table(self):
        expected = {"FW-001", "FW-002", "FW-003", "FW-004", "FW-005",
                    "FW-006", "FW-007", "FW-008", "FW-009", "FW-010"}
        assert {m[0] for m in ALERT_META.values()} == expected

    def test_threat_model_documents_fc_trust_rows(self):
        assert set(REQUIRES_FC_TRUST) == {"F-011", "F-012"}


# ---------------------------------------------------------------------------
# Backward compatibility — existing constructors unaffected
# ---------------------------------------------------------------------------
def test_idsalert_backwards_compatible():
    # Old positional/keyword construction still works; new fields default None.
    a = IDSAlert(timestamp=1.0, severity="low", reason="x")
    assert a.attack_class is None and a.observable_from is None
    t = a.to_json()
    assert "attack_class" not in t          # None fields dropped, schema stable
    assert "observable_from" not in t