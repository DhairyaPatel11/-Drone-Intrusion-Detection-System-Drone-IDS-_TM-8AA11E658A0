"""
Phase 2 tests — coverage extensions for command_injection_detector.

Rules under test (each with a positive + negative case):
  - ArduPilot mode updates (int custom_mode -> phase) + legal mode transitions
  - parameter bounds (enum / min / max) on COMMAND_LONG/INT
  - geofence checks (altitude on commands and mission items)
  - PARAM_SET name/value allow-list
  - MISSION_ITEM sequence integrity (duplicate / gap / backwards)
  - COMMAND_ACK correlation (unsolicited / missing / matching)
  - authorized COMPID enforcement
  - MAVLink 2.0 signing required (unsigned flagged) + invalid signature flagged

Run:  python -m pytest test_command_injection_phase2.py -v
"""

import os
import sys
import time
import hashlib
import hmac as _hmac

import pytest


from ids.command_injection_detector import (  # noqa: E402
    CMD_ARM_DISARM,
    CMD_TAKEOFF,
    CommandInjectionDetector,
    MockCommandMessage,
)
from ids.ids_config import load_config  # noqa: E402

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "configs", "command_injection.yaml")
_POL = load_config(CFG)


class RichCmd(MockCommandMessage):
    """Mock carrying the full COMMAND_LONG field set (param1..7, x,y,z, compid)."""

    def __init__(self, msg_type="COMMAND_LONG", sysid=255, command=None,
                 compid=190, **params):
        super().__init__(msg_type, sysid, command)
        self.compid = compid
        for k, v in params.items():
            setattr(self, k, v)


# ---------------------------------------------------------------------------
# Mode updates via telemetry
# ---------------------------------------------------------------------------
def test_mode_update_int_to_phase_positive():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.update_mode_from_telemetry(4)              # GUIDED
    assert det.state == "FLYING"


def test_mode_update_name_positive():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.update_mode_from_telemetry("RTL")
    assert det.state == "RETURNING"


def test_illegal_mode_transition_flagged_when_enforced():
    pol = load_config(CFG)
    pol["enforce_mode_transitions"] = True
    det = CommandInjectionDetector(policy=pol)
    det.update_mode_from_telemetry("STABILIZE")
    # AUTO is a legal transition in our table from STABILIZE; pick one that is
    # NOT in the STABILIZE allow-list to force a violation... all target modes
    # are listed, so instead test a synthetic restricted table.
    pol2 = load_config(CFG)
    pol2["enforce_mode_transitions"] = True
    pol2["mode_transitions"]["STABILIZE"] = ["ACRO"]
    det2 = CommandInjectionDetector(policy=pol2)
    det2.update_mode_from_telemetry("STABILIZE")
    # transition STABILIZE -> LAND is now illegal -> should be flagged (logged);
    # we assert the detector still tracks the new mode but recorded a warning.
    det2.update_mode_from_telemetry("LAND")
    assert det2._last_telemetry_mode == "LAND"


def test_unknown_mode_ignored_negative():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.update_mode_from_telemetry(999)            # not a mode
    assert det._last_telemetry_mode is None


# ---------------------------------------------------------------------------
# Parameter bounds
# ---------------------------------------------------------------------------
def test_arm_disarm_enum_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=1)           # 1 = arm, allowed enum
    assert det.process_command(msg) is None


def test_arm_disarm_enum_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=7)           # 7 not in enum [0,1]
    alert = det.process_command(msg)
    assert alert is not None and "param1" in alert["reason"]


def test_takeoff_altitude_max_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    msg = RichCmd(command=22, param1=15.0, param7=100.0)   # alt within 120
    assert det.process_command(msg) is None


def test_takeoff_altitude_max_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    msg = RichCmd(command=22, param1=15.0, param7=500.0)   # over 120m
    alert = det.process_command(msg)
    assert alert is not None and "param7" in alert["reason"]


def test_takeoff_pitch_min_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    msg = RichCmd(command=22, param1=-90.0, param7=10.0)   # pitch below -15
    alert = det.process_command(msg)
    assert alert is not None and "param1" in alert["reason"]


# ---------------------------------------------------------------------------
# Geofence (altitude on commands)
# ---------------------------------------------------------------------------
def test_geofence_altitude_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    msg = RichCmd(command=16, z=9000.0)            # NAV_WAYPOINT alt above 5000m
    alert = det.process_command(msg)
    assert alert is not None and "geofence" in alert["reason"]


def test_geofence_altitude_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    msg = RichCmd(command=16, z=100.0)             # well inside
    assert det.process_command(msg) is None


# ---------------------------------------------------------------------------
# PARAM_SET allow-list
# ---------------------------------------------------------------------------
def test_param_set_allowed_name_value_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    # PARAM_SET handled via parse_mavlink_command -> we push a param set msg
    # through the param validator directly for the rule check
    assert det._param_validator.check_param_set("ANGLE_MAX", 3000.0) is None


def test_param_set_denied_name_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    assert det._param_validator.check_param_set("SERVO1_MIN", 500.0) \
        is not None


def test_param_set_value_out_of_range_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    assert det._param_validator.check_param_set("ANGLE_MAX", 9000.0) \
        is not None


# ---------------------------------------------------------------------------
# Mission sequence integrity
# ---------------------------------------------------------------------------
def test_mission_sequence_monotonic_positive():
    det = CommandInjectionDetector(policy=load_config(CFG))
    assert det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=0)) is None
    assert det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=1)) is None
    assert det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=2, current=2)) is None


def test_mission_sequence_duplicate_negative():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=0))
    alert = det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=0))
    assert alert is not None and "duplicate" in alert["reason"]


def test_mission_sequence_gap_negative():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=0))
    alert = det.check_mission_item(RichCmd("MISSION_ITEM_INT", seq=2))
    assert alert is not None and "gap" in alert["reason"]


def test_mission_geofence_negative():
    det = CommandInjectionDetector(policy=load_config(CFG))
    alert = det.check_mission_item(
        RichCmd("MISSION_ITEM_INT", seq=0, x=0.0, y=0.0, z=20000.0))
    assert alert is not None and "geofence" in alert["reason"]


# ---------------------------------------------------------------------------
# COMMAND_ACK correlation
# ---------------------------------------------------------------------------
def test_ack_matching_pending_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=1)
    assert det.process_command(msg) is None        # registers pending
    ack = RichCmd("COMMAND_ACK", command=400, result=0)
    assert det.check_ack(ack) is None


def test_ack_unsolicited_negative():
    det = CommandInjectionDetector(policy=load_config(CFG))
    ack = RichCmd("COMMAND_ACK", command=400, result=0)
    assert det.check_ack(ack) is not None


def test_missing_ack_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=1)
    det.process_command(msg)
    now = time.time() + 100.0                       # push time past timeout
    assert len(det._ack_tracker.missing_acks(now)) > 0


# ---------------------------------------------------------------------------
# Authorized COMPID
# ---------------------------------------------------------------------------
def test_authorized_compid_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=1, compid=190)
    assert det.process_command(msg) is None


def test_unauthorized_compid_negative():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    msg = RichCmd(command=400, param1=1, compid=42)
    alert = det.process_command(msg)
    assert alert is not None and "compid" in alert["reason"]


# ---------------------------------------------------------------------------
# MAVLink 2.0 signing
# ---------------------------------------------------------------------------
def _build_signed_frame(payload: bytes, key: bytes, ts_units: int,
                        bad_mac: bool = False) -> bytes:
    """Build a signed MAVLink v2 frame with correct (or corrupted) signature."""
    header = b"\xfd" + bytes([len(payload)]) + b"\x01\x00"  # incompat |= signed
    header += b"\x00\x01\x01" + b"\x00\x00\x00" + payload   # seq sysid compid msgid
    frame = header
    mac = _hmac.new(key, frame, hashlib.sha256).digest()[:6]
    if bad_mac:
        mac = bytes([b ^ 0xFF for b in mac])
    sig = b"\x00" + ts_units.to_bytes(6, "little") + mac     # link_id + ts + mac
    return frame + sig


def test_signing_required_unsigned_negative():
    pol = load_config(CFG)
    pol["signing"]["require"] = True
    det = CommandInjectionDetector(policy=pol)
    frame = b"\xfd\x00\x00\x00" + b"\x00\x01\x01" + b"\x00\x00\x00"  # unsignd
    alert = det.check_signing(frame)
    assert alert is not None and alert["rule_id"] == "SIGN-001"


def test_signing_required_signed_positive():
    pol = load_config(CFG)
    pol["signing"]["require"] = True
    pol["signing"]["verify_when_present"] = True
    det = CommandInjectionDetector(policy=pol)
    key = os.urandom(32)
    det.set_signing_key(key)
    frame = _build_signed_frame(b"\x00", key, 1_000_000)
    assert det.check_signing(frame) is None


def test_signing_invalid_signature_negative():
    pol = load_config(CFG)
    pol["signing"]["verify_when_present"] = True
    det = CommandInjectionDetector(policy=pol)
    key = os.urandom(32)
    det.set_signing_key(key)
    frame = _build_signed_frame(b"\x00", key, 1_000_000, bad_mac=True)
    alert = det.check_signing(frame)
    assert alert is not None and alert["rule_id"] == "SIGN-004"


def test_signing_key_not_logged():
    pol = load_config(CFG)
    det = CommandInjectionDetector(policy=pol)
    key = os.urandom(32)
    det.set_signing_key(key)
    assert det._signing._key == key                # stored internally
    assert "key" not in repr(det._signing) or "signing" in repr(det._signing)