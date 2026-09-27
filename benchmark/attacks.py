"""Deterministic benign + attack frame generators for the benchmark harness.

Every generator returns real :class:`~ids_pipeline.IDSMessage` frames built
with ``make_frame`` (valid MAVLink v2 + correct X25 CRC), so the exact same
code path exercised by the live pipeline is benchmarked offline.

Attack classes and their ground-truth alert spec (layer + reason/type):

Communication-Attacks (Phases 1-4):
    unauthorized    -> {"layer": "command_injection", "reason": "unauthorized_command_source"}
    replay          -> {"layer": "replay",            "reason": "replay_detected"}
    crc             -> {"layer": "anomaly",           "reason": "crc_mismatch"}
    state_violation -> {"layer": "command_injection", "reason": "command_not_allowed_in_state"}
    rf_jam          -> {"layer": "rf_jamming",        "type": "rf_jamming_suspected", "confidence": "high"}

Control-System-Attacks (Phases 1-4):
    gps_spoofing          -> {"layer": "control_system", "reason": "fused_gps_spoofing", "attack_class": "gps_spoofing"}
    baro_spoofing         -> {"layer": "control_system", "reason": "fused_sensor_spoofing", "attack_class": "sensor_spoofing"}
    optical_flow_anomaly  -> {"layer": "control_system", "reason": "fused_sensor_spoofing", "attack_class": "sensor_spoofing"}
    ekf_innovation_error  -> {"layer": "control_system", "reason": "fused_estimator_manipulation", "attack_class": "estimator_manipulation"}
    attitude_tracking_err -> {"layer": "control_system", "reason": "fused_control_loop_manipulation", "attack_class": "control_loop_manipulation"}
    actuator_asymmetry    -> {"layer": "control_system", "reason": "fused_actuator_manipulation", "attack_class": "actuator_manipulation"}
    geofence_violation    -> {"layer": "control_system", "reason": "fused_geofence_violation", "attack_class": "geofence_violation"}
    rtl_no_gps_lock       -> {"layer": "control_system", "reason": "fused_failsafe_abuse", "attack_class": "failsafe_abuse"}

All sequences are freshly allocated per call so windows never bleed between
attack classes.
"""

from typing import Dict, List, Tuple

import ids.ids_pipeline as _p
from ids.ids_pipeline import IDSMessage, make_frame

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

AlertSpec = Dict[str, object]
FramesAndSpec = Tuple[List[IDSMessage], AlertSpec]


def _msg(
    msg_type: str,
    seq: int,
    field_: Dict[str, object] | None = None,
    sysid: int = 255,
    corrupt: bool = False,
) -> IDSMessage:
    """Build one IDSMessage with a valid (or intentionally corrupt) frame."""
    raw = make_frame(seq % 256)          # wire seq is one byte; IDS keeps full seq
    if corrupt:
        raw = raw[:-1] + bytes([raw[-1] ^ 0xFF])
    return IDSMessage(
        msg_type=msg_type,
        seq=seq,
        sysid=sysid,
        compid=1,
        arrival_time=_p.time.time(),
        msg_timestamp=0.0,
        raw_frame=raw,
        field=field_ or {},
    )


def _telemetry_msg(
    msg_type: str,
    seq: int,
    field_: Dict[str, object] | None = None,
    sysid: int = 1,
) -> IDSMessage:
    """Build a telemetry message (from FC, sysid=1)."""
    raw = make_frame(seq % 256)
    return IDSMessage(
        msg_type=msg_type,
        seq=seq,
        sysid=sysid,
        compid=1,
        arrival_time=_p.time.time(),
        msg_timestamp=0.0,
        raw_frame=raw,
        field=field_ or {},
    )


def heartbeat(seq: int, mode: str = "FLYING", custom_mode: int = 4) -> IDSMessage:
    """A HEARTBEAT that moves the state machine to ``mode`` (telemetry)."""
    return _telemetry_msg("HEARTBEAT", seq, field_={"mode": mode, "custom_mode": custom_mode})


def command(seq: int, cmd: str, sysid: int = 255) -> IDSMessage:
    """A COMMAND_LONG with a named MAV_CMD (as pulled from the wire)."""
    return _msg("COMMAND_LONG", seq, field_={"command": cmd}, sysid=sysid)


def radio_status(seq: int, rssi: float, noise: float, rxerrors: int) -> IDSMessage:
    """One RADIO_STATUS sample for the RF-jamming layer."""
    return _telemetry_msg(
        "RADIO_STATUS", seq,
        field_={"rssi": float(rssi), "noise": float(noise), "rxerrors": int(rxerrors)},
    )


# ---------------------------------------------------------------------------
# Control System telemetry message builders
# ---------------------------------------------------------------------------

def gps_raw_int(seq: int, lat: float = 0.0, lon: float = 0.0, alt: float = 100.0,
                vx: float = 0.0, vy: float = 0.0, vz: float = 0.0,
                fix: int = 3, sats: int = 8) -> IDSMessage:
    """GPS_RAW_INT telemetry message."""
    return _telemetry_msg("GPS_RAW_INT", seq, field_={
        "gps_lat": int(lat * 1e7), "gps_lon": int(lon * 1e7), "gps_alt": int(alt * 1000),
        "gps_vx": int(vx * 100), "gps_vy": int(vy * 100), "gps_vz": int(vz * 100),
        "gps_fix": fix, "gps_satellites_visible": sats,
    })


def scaled_pressure(seq: int, press_abs: float = 1013.25, press_diff: float = 0.0) -> IDSMessage:
    """SCALED_PRESSURE telemetry message (barometer)."""
    return _telemetry_msg("SCALED_PRESSURE", seq, field_={
        "press_abs": press_abs, "press_diff": press_diff,
    })


def attitude(seq: int, roll: float = 0.0, pitch: float = 0.0, yaw: float = 0.0,
             rollspeed: float = 0.0, pitchspeed: float = 0.0, yawspeed: float = 0.0) -> IDSMessage:
    """ATTITUDE telemetry message."""
    return _telemetry_msg("ATTITUDE", seq, field_={
        "roll": roll, "pitch": pitch, "yaw": yaw,
        "rollspeed": rollspeed, "pitchspeed": pitchspeed, "yawspeed": yawspeed,
    })


def highres_imu(seq: int, xacc: float = 0.0, yacc: float = 0.0, zacc: float = -9.81,
                xgyro: float = 0.0, ygyro: float = 0.0, zgyro: float = 0.0,
                xmag: float = 100.0, ymag: float = 0.0, zmag: float = 0.0) -> IDSMessage:
    """HIGHRES_IMU telemetry message."""
    return _telemetry_msg("HIGHRES_IMU", seq, field_={
        "xacc": xacc, "yacc": yacc, "zacc": zacc,
        "xgyro": xgyro, "ygyro": ygyro, "zgyro": zgyro,
        "xmag": xmag, "ymag": ymag, "zmag": zmag,
    })


def optical_flow(seq: int, quality: int = 200, flow_x: float = 1.0, flow_y: float = 0.0) -> IDSMessage:
    """OPTICAL_FLOW telemetry message."""
    return _telemetry_msg("OPTICAL_FLOW", seq, field_={
        "flow_quality": quality, "flow_comp_m_x": flow_x, "flow_comp_m_y": flow_y,
    })


def vfr_hud(seq: int, groundspeed: float = 5.0, airspeed: float = 5.0, climb: float = 0.0) -> IDSMessage:
    """VFR_HUD telemetry message."""
    return _telemetry_msg("VFR_HUD", seq, field_={
        "groundspeed": groundspeed, "airspeed": airspeed, "climb": climb,
    })


def estimator_status(seq: int, pos_horiz: float = 0, pos_vert: float = 0,
                     vel_horiz: float = 0, vel_vert: float = 0) -> IDSMessage:
    """ESTIMATOR_STATUS telemetry message (EKF health)."""
    return _telemetry_msg("ESTIMATOR_STATUS", seq, field_={
        "est_pos_horiz_abs_status": pos_horiz,
        "est_pos_vert_abs_status": pos_vert,
        "est_vel_horiz_abs_status": vel_horiz,
        "est_vel_vert_abs_status": vel_vert,
    })


def nav_controller_output(seq: int, nav_roll: float = 0.0, nav_pitch: float = 0.0, nav_bearing: float = 0.0) -> IDSMessage:
    """NAV_CONTROLLER_OUTPUT telemetry message."""
    return _telemetry_msg("NAV_CONTROLLER_OUTPUT", seq, field_={
        "nav_roll": nav_roll, "nav_pitch": nav_pitch, "nav_bearing": nav_bearing,
    })


def servo_output_raw(seq: int, servos: List[int] | None = None) -> IDSMessage:
    """SERVO_OUTPUT_RAW telemetry message."""
    if servos is None:
        servos = [1500] * 8
    field = {f"servo{i+1}_raw": servos[i] for i in range(min(8, len(servos)))}
    return _telemetry_msg("SERVO_OUTPUT_RAW", seq, field_=field)


def global_position_int(seq: int, lat: float = 0.0, lon: float = 0.0,
                         relative_alt: float = 100.0) -> IDSMessage:
    """GLOBAL_POSITION_INT telemetry message."""
    return _telemetry_msg("GLOBAL_POSITION_INT", seq, field_={
        "lat": int(lat * 1e7), "lon": int(lon * 1e7), "relative_alt": int(relative_alt * 1000),
    })


# ---------------------------------------------------------------------------
# Benign traffic
# ---------------------------------------------------------------------------

def benign_stream(n: int, mode: str = "FLYING") -> List[IDSMessage]:
    """``n`` clean frames: alternating HEARTBEAT / GLOBAL_POSITION_INT.

    Monotonic link sequence, valid CRC, no commands -> the pipeline must emit
    zero alerts (this is the FPR measurement stream).
    """
    frames: List[IDSMessage] = []
    for i in range(n):
        if i % 2 == 0:
            frames.append(heartbeat(i, mode=mode))
        else:
            frames.append(_msg("GLOBAL_POSITION_INT", i))
    return frames


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

def unauthorized_attack() -> FramesAndSpec:
    """Armed command from an unauthorized GCS sysid (attacker on the link)."""
    frames = [heartbeat(200), command(201, "COMPONENT_ARM_DISARM", sysid=7)]
    return frames, {"layer": "command_injection", "reason": "unauthorized_command_source"}


def replay_attack() -> FramesAndSpec:
    """Exact duplicate of an already-seen frame (RFC-4303 window reject)."""
    frames = [heartbeat(300), heartbeat(300)]
    return frames, {"layer": "replay", "reason": "replay_detected"}


def crc_attack() -> FramesAndSpec:
    """Frame whose X25 CRC was flipped in transit."""
    frames = [_msg("HEARTBEAT", 400, field_={"mode": "FLYING"}, corrupt=True)]
    return frames, {"layer": "anomaly", "reason": "crc_mismatch"}


def state_violation_attack() -> FramesAndSpec:
    """Authorized GCS issues NAV_TAKEOFF while already airborne (FLYING)."""
    frames = [heartbeat(500, mode="FLYING"), command(501, "NAV_TAKEOFF")]
    return frames, {"layer": "command_injection", "reason": "command_not_allowed_in_state"}


def rf_jam_attack() -> FramesAndSpec:
    """Noise surge + climbing rxerror counter on RADIO_STATUS (high confidence)."""
    frames: List[IDSMessage] = []
    rxerr = 0
    for i in range(30):
        if i < 10:
            rssi, noise = 190, 30
        else:
            rssi = max(190 - 2 * (i - 10), 120)
            noise = min(30 + 15 * (i - 10), 200)
            rxerr += 50 * (i - 10)
        frames.append(radio_status(600 + i, rssi, noise, rxerr))
    return frames, {"layer": "rf_jamming", "type": "rf_jamming_suspected", "confidence": "high"}


# ---------------------------------------------------------------------------
# Control System Attacks
# ---------------------------------------------------------------------------

def gps_spoofing_attack() -> FramesAndSpec:
    """GPS position jump - sudden position change without corresponding IMU motion."""
    frames: List[IDSMessage] = []
    # Establish baseline
    frames.append(heartbeat(1000, "FLYING"))
    frames.append(gps_raw_int(1001, lat=0.0, lon=0.0, alt=100.0))
    frames.append(highres_imu(1002, xacc=0.0, yacc=0.0, zacc=-9.81))
    frames.append(scaled_pressure(1003))
    # Sudden position jump (spoofed) - large enough to exceed 5m threshold
    # 0.0001 deg * 111320 = ~11m jump
    frames.append(gps_raw_int(1004, lat=0.0001, lon=0.0, alt=100.0))
    frames.append(highres_imu(1005, xacc=0.0, yacc=0.0, zacc=-9.81))
    frames.append(scaled_pressure(1006))
    # Expected: control_system (fused_gps_spoofing) + navigation (baro_spoofing, coordinated_gnss_baro)
    return frames, [
        {"layer": "control_system", "reason": "fused_gps_spoofing", "attack_class": "gps_spoofing"},
        {"layer": "navigation", "reason": "baro_spoofing", "attack_class": "baro_spoofing"},
        {"layer": "navigation", "reason": "coordinated_gnss_baro", "attack_class": "coordinated_gnss_baro"},
    ]


def baro_spoofing_attack() -> FramesAndSpec:
    """Barometer vs GPS altitude mismatch."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(2000, "FLYING"))
    frames.append(gps_raw_int(2001, alt=100.0))
    frames.append(highres_imu(2002))
    frames.append(scaled_pressure(2003, press_abs=900.0))  # ~1000m baro altitude
    # Need more context for detector
    frames.append(gps_raw_int(2004, alt=100.0))
    frames.append(highres_imu(2005))
    frames.append(scaled_pressure(2006, press_abs=900.0))
    # Expected: control_system (fused_sensor_spoofing) + navigation (baro_spoofing)
    return frames, [
        {"layer": "control_system", "reason": "fused_sensor_spoofing", "attack_class": "sensor_spoofing"},
        {"layer": "navigation", "reason": "baro_spoofing", "attack_class": "baro_spoofing"},
    ]


def optical_flow_anomaly_attack() -> FramesAndSpec:
    """Optical flow quality drops while moving fast."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(3000, "FLYING", 4))  # FLYING mode, custom_mode=4 (GUIDED)
    frames.append(gps_raw_int(3001, alt=100.0))  # GPS for context
    frames.append(highres_imu(3002))  # IMU for context
    frames.append(optical_flow(3003, quality=10, flow_x=0.0, flow_y=0.0))
    frames.append(vfr_hud(3004, groundspeed=5.0))
    frames.append(highres_imu(3005))
    # Add more context
    frames.append(optical_flow(3006, quality=10, flow_x=0.0, flow_y=0.0))
    frames.append(vfr_hud(3007, groundspeed=5.0))
    frames.append(highres_imu(3008))
    return frames, {"layer": "control_system", "reason": "fused_sensor_spoofing", "attack_class": "sensor_spoofing"}


def ekf_innovation_error_attack() -> FramesAndSpec:
    """EKF innovation error flags."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(4000, "FLYING"))
    frames.append(estimator_status(4001, pos_horiz=2, pos_vert=0, vel_horiz=0, vel_vert=0))  # ERROR
    frames.append(gps_raw_int(4002))
    frames.append(highres_imu(4003))
    return frames, {"layer": "control_system", "reason": "fused_estimator_manipulation", "attack_class": "estimator_manipulation"}


def attitude_tracking_error_attack() -> FramesAndSpec:
    """Attitude tracking error - commanded vs actual mismatch."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(5000, "FLYING"))
    frames.append(nav_controller_output(5001, nav_roll=0.0, nav_pitch=0.0))  # Commanded level
    frames.append(attitude(5002, roll=20.0, pitch=0.0))  # Actual 20deg roll
    frames.append(highres_imu(5003))
    frames.append(servo_output_raw(5004))
    return frames, {"layer": "control_system", "reason": "fused_control_loop_manipulation", "attack_class": "control_loop_manipulation"}


def actuator_asymmetry_attack() -> FramesAndSpec:
    """Actuator left/right asymmetry."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(6000, "FLYING"))
    # Build history with asymmetry
    for i in range(20):
        frames.append(servo_output_raw(6001 + i, [1200, 1200, 1800, 1800, 1500, 1500, 1500, 1500]))
    frames.append(vfr_hud(6021, groundspeed=5.0))
    return frames, {"layer": "control_system", "reason": "fused_actuator_manipulation", "attack_class": "actuator_manipulation"}


def geofence_violation_attack() -> FramesAndSpec:
    """GPS position outside geofence."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(7000, "FLYING"))
    frames.append(global_position_int(7001, lat=95.0, lon=0.0))  # Outside lat range
    frames.append(gps_raw_int(7002, lat=95.0, lon=0.0))
    frames.append(scaled_pressure(7003))
    # Expected: control_system (fused_geofence_violation) + navigation (baro_spoofing)
    return frames, [
        {"layer": "control_system", "reason": "fused_geofence_violation", "attack_class": "geofence_violation"},
        {"layer": "navigation", "reason": "baro_spoofing", "attack_class": "baro_spoofing"},
    ]


def rtl_no_gps_lock_attack() -> FramesAndSpec:
    """RTL mode activated without 3D GPS fix."""
    frames: List[IDSMessage] = []
    # RTL mode = custom_mode 6, with baro altitude matching GPS (100m = ~1001 hPa)
    frames.append(heartbeat(8000, "RTL", 6))  # RTL mode = custom_mode 6
    frames.append(gps_raw_int(8001, alt=100.0, fix=2))  # Only 2D fix, alt=100m
    frames.append(scaled_pressure(8002, press_abs=1001.0))  # Baro ~100m to match GPS
    return frames, {"layer": "control_system", "reason": "fused_failsafe_abuse", "attack_class": "failsafe_abuse"}


# ---------------------------------------------------------------------------
# Navigation Attacks (Phase 6)
# ---------------------------------------------------------------------------

def gps_spoofing_jump_attack() -> FramesAndSpec:
    """GPS position jump - sudden position change without corresponding IMU motion."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(9000, "FLYING"))
    frames.append(gps_raw_int(9001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(9002, xacc=0.0, yacc=0.0, zacc=-9.81))
    frames.append(scaled_pressure(9003))
    frames.append(ekf_status(9004))
    # Sudden position jump (spoofed) - large enough to exceed 10m threshold
    frames.append(gps_raw_int(9005, lat=0.0001, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(9006, xacc=0.0, yacc=0.0, zacc=-9.81))
    frames.append(scaled_pressure(9007))
    frames.append(ekf_status(9008))
    return frames, {"layer": "navigation", "reason": "gps_spoofing_jump", "attack_class": "gps_spoofing_jump"}


def gps_spoofing_drift_attack() -> FramesAndSpec:
    """GPS slow drift - gradual position offset over time."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(10000, "FLYING"))
    # Establish baseline
    for i in range(5):
        frames.append(gps_raw_int(10001 + i, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
        frames.append(highres_imu(10006 + i, xacc=0.0, yacc=0.0, zacc=-9.81))
        frames.append(scaled_pressure(10011 + i))
        frames.append(ekf_status(10016 + i, pos_horiz=1.5))  # High innovation
    return frames, {"layer": "navigation", "reason": "gps_spoofing_drift", "attack_class": "gps_spoofing_drift"}


def gnss_jamming_attack() -> FramesAndSpec:
    """GNSS jamming - satellite count drops, fix type degrades."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(11000, "FLYING"))
    frames.append(gps_raw_int(11001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(11002))
    frames.append(scaled_pressure(11003))
    # Jamming: satellites drop below threshold
    frames.append(gps_raw_int(11004, lat=0.0, lon=0.0, alt=100.0, sats=2, fix=1))
    frames.append(highres_imu(11005))
    frames.append(scaled_pressure(11006))
    return frames, {"layer": "navigation", "reason": "gnss_jamming", "attack_class": "gnss_jamming"}


def gps_spoofing_seamless_attack() -> FramesAndSpec:
    """Seamless GPS takeover - GNSS looks healthy but INS disagrees."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(12000, "FLYING"))
    # GNSS looks perfect (8 sats, 3D fix)
    frames.append(gps_raw_int(12001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    # But INS innovations are high
    frames.append(highres_imu(12002))
    frames.append(ekf_status(12003, pos_horiz=2.0, pos_vert=2.0))
    frames.append(scaled_pressure(12004))
    return frames, {"layer": "navigation", "reason": "gps_spoofing_seamless", "attack_class": "gps_spoofing_seamless"}


def gps_time_spoofing_attack() -> FramesAndSpec:
    """GPS time spoofing - clock jump detected."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(13000, "FLYING"))
    frames.append(gps_raw_int(13001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(13002))
    frames.append(scaled_pressure(13003))
    # Time jump - large time_usec delta
    frames.append(gps_raw_int(13004, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3, time_usec=int(time.time() * 1e6) + 10_000_000))
    return frames, {"layer": "navigation", "reason": "gps_time_spoofing", "attack_class": "gps_time_spoofing"}


def gnss_jamming_ramp_attack() -> FramesAndSpec:
    """Swept-frequency jamming - gradual SNR degradation."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(14000, "FLYING"))
    # Gradually increasing eph/epv (proxy for SNR degradation)
    for i in range(5):
        eph = 150 + i * 50  # Increasing HDOP proxy
        epv = 200 + i * 80  # Increasing VDOP proxy
        frames.append(gps_raw_int(14001 + i, lat=0.0, lon=0.0, alt=100.0, sats=8 - i, fix=3, eph=eph, epv=epv))
        frames.append(highres_imu(14006 + i))
    return frames, {"layer": "navigation", "reason": "gnss_jamming_ramp", "attack_class": "gnss_jamming_ramp"}


def baro_spoofing_iemi_attack() -> FramesAndSpec:
    """Barometer IEMI spoofing - acoustic/EM interference on pressure sensor."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(15000, "FLYING"))
    frames.append(gps_raw_int(15001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(15002))
    # Baro pressure offset (900 hPa ≈ 1000m vs GPS 100m)
    frames.append(scaled_pressure(15003, press_abs=900.0))
    # Additional context
    frames.append(gps_raw_int(15004, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(15005))
    frames.append(scaled_pressure(15006, press_abs=900.0))
    return frames, {"layer": "navigation", "reason": "baro_spoofing", "attack_class": "baro_spoofing"}


def mag_spoofing_coil_attack() -> FramesAndSpec:
    """Magnetometer spoofing - active coil/EMI."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(16000, "FLYING"))
    frames.append(gps_raw_int(16001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3, vn=300, ve=400))
    frames.append(highres_imu(16002, xmag=100.0, ymag=0.0, zmag=0.0))
    frames.append(attitude(16003, roll=0.0, pitch=0.0, yaw=0.0))
    # Mag heading offset (xmag=-100 gives 180 deg vs gyro 0 deg)
    frames.append(highres_imu(16004, xmag=-100.0, ymag=0.0, zmag=0.0))
    frames.append(attitude(16005, roll=0.0, pitch=0.0, yaw=0.0))
    return frames, {"layer": "navigation", "reason": "mag_spoofing", "attack_class": "mag_spoofing"}


def optical_flow_spoofing_attack() -> FramesAndSpec:
    """Optical flow spoofing - zero flow while moving."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(17000, "FLYING"))
    frames.append(gps_raw_int(17001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3, vn=300, ve=400))
    frames.append(highres_imu(17002))
    frames.append(vfr_hud(17003, groundspeed=5.0))
    # Zero optical flow while GPS shows 5 m/s groundspeed
    frames.append(optical_flow(17004, quality=100, flow_x=0.0, flow_y=0.0))
    frames.append(highres_imu(17005))
    frames.append(vfr_hud(17006, groundspeed=5.0))
    return frames, {"layer": "navigation", "reason": "optical_flow_spoofing", "attack_class": "optical_flow_spoofing"}


def rangefinder_spoofing_attack() -> FramesAndSpec:
    """Rangefinder spoofing - distance sensor vs baro/GNSS alt mismatch."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(18000, "FLYING"))
    frames.append(gps_raw_int(18001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(18002))
    frames.append(scaled_pressure(18003, press_abs=1001.0))  # 100m
    # Rangefinder says 50m while GPS/Baro say 100m
    frames.append(distance_sensor(18004, distance=50.0))
    return frames, {"layer": "navigation", "reason": "rangefinder_spoofing", "attack_class": "rangefinder_spoofing"}


def rtcorrection_injection_attack() -> FramesAndSpec:
    """RTK correction stream injection - base station coordinate shift."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(19000, "FLYING"))
    frames.append(gps_raw_int(19001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=6))  # RTK Fixed
    frames.append(highres_imu(19002))
    frames.append(scaled_pressure(19003))
    # No base station coordinates available for verification
    return frames, {"layer": "navigation", "reason": "rtk_correction_injection", "attack_class": "rtcorrection_injection"}


def coordinated_gnss_baro_attack() -> FramesAndSpec:
    """Coordinated GNSS + Barometer spoofing."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(20000, "FLYING"))
    frames.append(gps_raw_int(20001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(20002))
    frames.append(scaled_pressure(20003, press_abs=900.0))  # Baro mismatch
    # GPS position jump
    frames.append(gps_raw_int(20004, lat=0.0001, lon=0.0, alt=100.0, sats=8, fix=3))
    frames.append(highres_imu(20005))
    frames.append(scaled_pressure(20006, press_abs=900.0))
    return frames, {"layer": "navigation", "reason": "coordinated_gnss_baro", "attack_class": "coordinated_gnss_baro"}


def mag_bias_drift_attack() -> FramesAndSpec:
    """Magnetometer bias drift - slow heading offset."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(21000, "FLYING"))
    frames.append(gps_raw_int(21001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3, vn=300, ve=400))
    frames.append(highres_imu(21002, xmag=100.0, ymag=0.0))
    frames.append(attitude(21003, yaw=0.0))
    # Gradual mag heading drift
    for i in range(5):
        drift = (i + 1) * 5.0  # 5, 10, 15, 20, 25 deg
        frames.append(highres_imu(21004 + i, xmag=100.0, ymag=drift))
        frames.append(attitude(21009 + i, yaw=0.0))
    return frames, {"layer": "navigation", "reason": "mag_bias_drift", "attack_class": "mag_bias_drift"}


def optical_flow_bias_attack() -> FramesAndSpec:
    """Optical flow constant velocity bias."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(22000, "FLYING"))
    frames.append(gps_raw_int(22001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3, vn=300, ve=400))
    frames.append(highres_imu(22002))
    frames.append(vfr_hud(22003, groundspeed=5.0))
    # Constant optflow bias (flow_x=1.0 m/s offset)
    for i in range(5):
        frames.append(optical_flow(22004 + i, quality=100, flow_x=1.0, flow_y=0.0))
        frames.append(highres_imu(22009 + i))
        frames.append(vfr_hud(22014 + i, groundspeed=5.0))
    return frames, {"layer": "navigation", "reason": "optical_flow_bias", "attack_class": "optical_flow_bias"}


def rtcorrection_fault_attack() -> FramesAndSpec:
    """RTK correction fault - RTK Fixed degrades to 3D without sat loss."""
    frames: List[IDSMessage] = []
    frames.append(heartbeat(23000, "FLYING"))
    # RTK Fixed initially
    frames.append(gps_raw_int(23001, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=6))
    frames.append(highres_imu(23002))
    frames.append(scaled_pressure(23003))
    frames.append(ekf_status(23004, pos_horiz=1.2))  # High innovation during RTK Fixed
    # Degrades to 3D fix (no sat loss)
    frames.append(gps_raw_int(23005, lat=0.0, lon=0.0, alt=100.0, sats=8, fix=3))
    return frames, {"layer": "navigation", "reason": "rtk_correction_fault", "attack_class": "rtcorrection_fault"}


# ---------------------------------------------------------------------------
# Combined attack registry
# ---------------------------------------------------------------------------

ATTACK_CLASSES: Dict[str, object] = {
    # Communication-Attacks (original)
    "unauthorized": unauthorized_attack,
    "replay": replay_attack,
    "crc": crc_attack,
    "state_violation": state_violation_attack,
    "rf_jam": rf_jam_attack,
    # Control-System-Attacks (new)
    "gps_spoofing": gps_spoofing_attack,
    "baro_spoofing": baro_spoofing_attack,
    "optical_flow_anomaly": optical_flow_anomaly_attack,
    "ekf_innovation_error": ekf_innovation_error_attack,
    "attitude_tracking_error": attitude_tracking_error_attack,
    "actuator_asymmetry": actuator_asymmetry_attack,
    "geofence_violation": geofence_violation_attack,
    "rtl_no_gps_lock": rtl_no_gps_lock_attack,
}