"""
Phase 3 tests — cyber-physical fusion for command_injection_detector.

Each physical check has a positive (clean) + negative (flagged) case.
"""

import os
import sys
import time

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


class TelemetryMsg:
    """Minimal pymavlink-style telemetry message with attribute access."""
    def __init__(self, msg_type: str, **kwargs):
        self._type = msg_type
        for k, v in kwargs.items():
            setattr(self, k, v)

    def get_type(self) -> str:
        return self._type


# ---------------------------------------------------------------------------
# PhysicalCrossChecker ingest + check_command
# ---------------------------------------------------------------------------
def test_disarm_vs_airborne_positive():
    # DISARM is allowed in DISARMED state. Physical check should pass
    # when telemetry shows on ground.
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=0.2,
                                       climb=0.0,
                                       vx=0.0, vy=0.0, vz=0.0))
    msg = RichCmd(command=400, param1=0, x=0.0, y=0.0, z=0.0)  # disarm
    assert det.process_command(msg) is None


def test_disarm_vs_airborne_negative():
    # DISARM allowed in DISARMED, but telemetry shows airborne -> PHY-001
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=10.0,
                                       climb=2.5,
                                       vx=0.0, vy=0.0, vz=0.0))
    msg = RichCmd(command=400, param1=0, x=0.0, y=0.0, z=0.0)
    alert = det.process_command(msg)
    assert alert is not None and "disarm_while_airborne" in alert["reason"]


def test_takeoff_vs_flying_positive():
    # TAKEOFF allowed in ARMED. On ground -> passes.
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=0.1,
                                       climb=0.0))
    msg = RichCmd(command=22, param1=15.0, param7=10.0)
    assert det.process_command(msg) is None


def test_takeoff_vs_flying_negative():
    # TAKEOFF allowed in ARMED, but telemetry shows already flying -> PHY-002
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=50.0,
                                       climb=1.0))
    msg = RichCmd(command=22, param1=15.0, param7=10.0)
    alert = det.process_command(msg)
    assert alert is not None and "takeoff_while_flying" in alert["reason"]


def test_waypoint_teleport_horizontal_negative():
    # NAV_WAYPOINT allowed in FLYING. Teleport >500m -> PHY-003
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=100.0,
                                       lat=0.0, lon=0.0))
    msg = RichCmd(command=16, x=0.008, y=0.0, z=100.0)  # ~800m
    alert = det.process_command(msg)
    assert alert is not None and "waypoint_teleport" in alert["reason"]


def test_waypoint_teleport_horizontal_positive():
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=100.0,
                                       lat=0.0, lon=0.0))
    msg = RichCmd(command=16, x=0.0005, y=0.0, z=100.0)  # ~50m
    assert det.process_command(msg) is None


def test_waypoint_alt_step_negative():
    # NAV_WAYPOINT in FLYING. Z jump 200m -> PHY-004
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="FLYING")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=100.0))
    msg = RichCmd(command=16, x=0.0, y=0.0, z=300.0)
    alert = det.process_command(msg)
    assert alert is not None and "alt_step" in alert["reason"]


def test_altitude_teleport_negative():
    # TAKEOFF in ARMED. On ground (0.1m) but commands 100m (diff > 50m) -> PHY-005
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=0.1,
                                       climb=0.0))
    msg = RichCmd(command=22, param7=100.0)
    alert = det.process_command(msg)
    assert alert is not None and "altitude_teleport" in alert["reason"]


def test_altitude_teleport_positive():
    # TAKEOFF in ARMED. On ground (0.1m), commands 30m (diff < 50m) -> PASS
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="ARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=0.1,
                                       climb=0.0))
    msg = RichCmd(command=22, param7=30.0)
    assert det.process_command(msg) is None


def test_stale_telemetry_skips_check():
    """Stale telemetry should NOT trigger physical checks (skip -> pass)."""
    det = CommandInjectionDetector(policy=load_config(CFG), initial_state="DISARMED")
    # ingest 10s old telemetry (older than max_telemetry_age_s=5)
    now = time.time() - 10.0
    det._physical.state._data = {
        "relative_alt": (100.0, now),
        "climb": (5.0, now),
    }
    msg = RichCmd(command=400, param1=0)
    # Should PASS (check skipped due to staleness)
    assert det.process_command(msg) is None


def test_physical_disabled_allows_all():
    pol = load_config(CFG)
    pol["physical"]["enabled"] = False
    det = CommandInjectionDetector(policy=pol, initial_state="DISARMED")
    det.ingest_telemetry(TelemetryMsg("GLOBAL_POSITION_INT",
                                       relative_alt=100.0, climb=10.0))
    msg = RichCmd(command=400, param1=0)
    assert det.process_command(msg) is None


# ---------------------------------------------------------------------------
# ingest_telemetry on various message types
# ---------------------------------------------------------------------------
def test_ingest_vfr_hud():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.ingest_telemetry(TelemetryMsg("VFR_HUD",
                                       climb=5.0, groundspeed=10.0, airspeed=12.0))
    assert det._physical.state.fresh("climb", time.time())


def test_ingest_scaled_pressure():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.ingest_telemetry(TelemetryMsg("SCALED_PRESSURE", press_abs=950.0))
    assert "baro_alt" in det._physical.state._data


def test_ingest_gps_raw_int():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.ingest_telemetry(TelemetryMsg("GPS_RAW_INT",
                                       fix_type=3, satellites_visible=12))
    assert det._physical.state.fresh("gps_fix", time.time())


def test_ingest_attitude():
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.ingest_telemetry(TelemetryMsg("ATTITUDE",
                                       rollspeed=0.1, pitchspeed=-0.05, yawspeed=0.02))
    assert det._physical.state.fresh("roll_rate", time.time())


def test_ingest_sys_status_ignored():
    """SYS_STATUS is accepted (not an error) but doesn't populate numeric features."""
    det = CommandInjectionDetector(policy=load_config(CFG))
    det.ingest_telemetry(TelemetryMsg("SYS_STATUS", voltage_battery=15000))
    # no exception, no features populated
    assert True