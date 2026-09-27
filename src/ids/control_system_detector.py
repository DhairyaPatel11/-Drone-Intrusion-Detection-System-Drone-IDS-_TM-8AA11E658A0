"""
control_system_detector.py — Control System Attacks Detector (Phases 1-2).

Implements telemetry ingestion and detectors for control-loop attacks:
- Sensor cross-consistency checks (GPS vs IMU, baro vs GPS, etc.)
- Estimator health (EKF innovation/variance monitoring)
- Control invariant/dynamics model validation
- Actuator anomaly detection
- Controller/parameter tampering detection
- Failsafe/geofence/mode logic abuse detection

Uses the existing config system (ids_config.py) and alert schema (IDSAlert).
"""

from __future__ import annotations

import collections
import math
import time
from typing import Any, Dict, List, Optional, Tuple

from .command_injection_detector import IDSAlert
from .ids_config import load_config, default_policy


# ---------------------------------------------------------------------------
# Telemetry ingestion — time-aligned buffers
# ---------------------------------------------------------------------------
class ControlSystemTelemetry:
    """
    Bounded store of latest telemetry values for control-system attack detection.
    Maintains time-aligned snapshots for cross-sensor consistency checks.
    """

    # Feature name -> (value, received_at)
    _FEATURES: Tuple[str, ...] = (
        # GPS_RAW_INT
        "gps_lat", "gps_lon", "gps_alt", "gps_vx", "gps_vy", "gps_vz",
        "gps_fix", "gps_satellites_visible",
        # GLOBAL_POSITION_INT / VFR_HUD
        "lat", "lon", "relative_alt", "groundspeed", "airspeed", "climb",
        # SCALED_PRESSURE (barometer)
        "press_abs", "press_diff",
        # ATTITUDE
        "roll", "pitch", "yaw", "rollspeed", "pitchspeed", "yawspeed",
        # HIGHRES_IMU
        "xacc", "yacc", "zacc", "xgyro", "ygyro", "zgyro",
        "xmag", "ymag", "zmag",
        # OPTICAL_FLOW
        "flow_quality", "flow_comp_m_x", "flow_comp_m_y",
        # DISTANCE_SENSOR
        "current_distance",
        # SERVO_OUTPUT_RAW (actuator commands)
        "servo1_raw", "servo2_raw", "servo3_raw", "servo4_raw",
        "servo5_raw", "servo6_raw", "servo7_raw", "servo8_raw",
        # ESTIMATOR_STATUS (EKF health)
        "est_pos_horiz_abs_status", "est_pos_vert_abs_status",
        "est_vel_horiz_abs_status", "est_vel_vert_abs_status",
        # PARAM_VALUE (for tampering detection)
        "param_value",
        # HEARTBEAT (for mode/logic)
        "custom_mode", "base_mode", "system_status",
        # NAV_CONTROLLER_OUTPUT (for control invariant)
        "nav_roll", "nav_pitch", "nav_bearing",
        # VIBRATION (for gyro resonance)
        "vibration_x", "vibration_y", "vibration_z",
    )

    def __init__(self, max_age_s: float = 2.0) -> None:
        self.max_age_s = max_age_s
        self._data: Dict[str, tuple] = {}   # feature -> (value, ts)
        self._history: Dict[str, collections.deque] = {}  # feature -> deque of (value, ts)
        self._history_size = 100  # Keep last N samples for trend analysis

    def ingest(self, msg_type: str, ts: float, **fields) -> None:
        """Merge one telemetry message's fields into the state (drop stale)."""
        if not fields:
            return
        for k, v in fields.items():
            if k in self._FEATURES and v is not None:
                self._data[k] = (v, ts)
                # Maintain history for trend analysis
                if k not in self._history:
                    self._history[k] = collections.deque(maxlen=self._history_size)
                self._history[k].append((v, ts))

    def get(self, feature: str, default: Any = None, now: float = 0.0) -> Any:
        """Latest value of a feature, or default if missing/stale."""
        ent = self._data.get(feature)
        if ent is None:
            return default
        val, ts = ent
        if now and now - ts > self.max_age_s:
            return default
        return val

    def fresh(self, feature: str, now: float) -> bool:
        """Check if feature is fresh (not stale)."""
        ent = self._data.get(feature)
        return ent is not None and now - ent[1] <= self.max_age_s

    def get_history(self, feature: str, count: Optional[int] = None) -> List[Tuple[Any, float]]:
        """Get historical values for a feature."""
        if feature not in self._history:
            return []
        hist = list(self._history[feature])
        if count is not None:
            return hist[-count:]
        return hist

    def clear(self) -> None:
        """Clear all telemetry data."""
        self._data.clear()
        self._history.clear()


# ---------------------------------------------------------------------------
# Detector base class
# ---------------------------------------------------------------------------
class ControlSystemDetector:
    """Base class for all control-system attack detectors."""

    def __init__(self, policy: Dict[str, Any]) -> None:
        self.policy = policy
        self.enabled = self._get_enabled()
        self.stats = {"checks": 0, "alerts": 0}

    def _get_enabled(self) -> bool:
        """Check if this detector is enabled in policy."""
        # Override in subclasses
        return True

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        """Perform detection check. Return alert if attack detected."""
        # Override in subclasses
        self.stats["checks"] += 1
        return None

    def _create_alert(self, reason: str, severity: str, detail: str,
                      evidence: Dict[str, Any], attack_class: str,
                      observable_from: str, rule_id: str) -> IDSAlert:
        """Create a standardized IDSAlert for control system attacks."""
        return IDSAlert(
            timestamp=time.time(),
            severity=severity,
            reason=reason,
            rule_id=rule_id,
            attack_class=attack_class,
            observable_from=observable_from,
            detail=detail,
            evidence=evidence,
            confidence=0.8,  # Default confidence, can be overridden
        )


# ---------------------------------------------------------------------------
# Sensor cross-consistency detectors
# ---------------------------------------------------------------------------
class SensorConsistencyDetector(ControlSystemDetector):
    """Detects inconsistencies between different sensor modalities."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("sensor_consistency", {}).get("enabled", True)

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("sensor_consistency", {})
        if not cfg.get("enabled", True):
            return None

        max_age = cfg.get("max_age_s", 2.0)
        gps_cfg = cfg.get("gps_vs_imu", {})
        baro_cfg = cfg.get("baro_vs_gps_alt", {})
        optflow_cfg = cfg.get("optflow_vs_imu", {})
        mag_cfg = cfg.get("mag_vs_cog", {})
        dist_cfg = cfg.get("dist_sensor_vs_alt", {})

        # GPS vs IMU dead-reckoning (position and velocity)
        if gps_cfg.get("enabled", True) and telemetry.fresh("gps_lat", now) and telemetry.fresh("xacc", now):
            alert = self._check_gps_vs_imu(telemetry, now, gps_cfg)
            if alert:
                return alert

        # Baro vs GPS altitude
        if baro_cfg.get("enabled", True) and telemetry.fresh("gps_alt", now) and telemetry.fresh("press_abs", now):
            baro_alt = self._baro_to_altitude(telemetry.get("press_abs"))
            gps_alt = telemetry.get("gps_alt")
            if baro_alt is not None and gps_alt is not None:
                alt_diff = abs(baro_alt - gps_alt)
                max_diff = baro_cfg.get("max_diff_m", 10.0)
                if alt_diff > max_diff:
                    return self._create_alert(
                        reason="baro_gps_altitude_mismatch",
                        severity="medium",
                        detail=f"Baro altitude {baro_alt:.1f}m differs from GPS {gps_alt:.1f}m by {alt_diff:.1f}m",
                        evidence={
                            "baro_altitude": baro_alt,
                            "gps_altitude": gps_alt,
                            "difference": alt_diff,
                            "threshold": max_diff
                        },
                        attack_class="sensor_spoofing",
                        observable_from="mavlink_stream",
                        rule_id="CSI-001"
                    )

        # Optical flow vs IMU velocity
        if optflow_cfg.get("enabled", True) and telemetry.fresh("flow_quality", now) and telemetry.fresh("groundspeed", now):
            flow_quality = telemetry.get("flow_quality")
            flow_x = telemetry.get("flow_comp_m_x")
            flow_y = telemetry.get("flow_comp_m_y")
            if flow_quality is not None and flow_x is not None and flow_y is not None:
                min_quality = optflow_cfg.get("min_quality", 50)
                if flow_quality < min_quality:
                    groundspeed = telemetry.get("groundspeed")
                    if groundspeed is not None and groundspeed > 1.0:
                        flow_magnitude = math.sqrt(flow_x**2 + flow_y**2)
                        if flow_magnitude < 0.1:
                            return self._create_alert(
                                reason="optical_flow_anomaly",
                                severity="medium",
                                detail=f"Optical flow quality {flow_quality} low despite ground speed {groundspeed:.1f}m/s",
                                evidence={
                                    "flow_quality": flow_quality,
                                    "groundspeed": groundspeed,
                                    "flow_vector": [flow_x, flow_y],
                                    "min_quality_threshold": min_quality
                                },
                                attack_class="sensor_spoofing",
                                observable_from="mavlink_stream",
                                rule_id="CSI-002"
                            )

        # Magnetometer vs GPS course-over-ground
        if mag_cfg.get("enabled", True) and telemetry.fresh("xmag", now) and telemetry.fresh("gps_vx", now):
            mag_x = telemetry.get("xmag")
            mag_y = telemetry.get("ymag")
            gps_speed = math.sqrt(telemetry.get("gps_vx", 0)**2 + telemetry.get("gps_vy", 0)**2)
            if None not in (mag_x, mag_y) and gps_speed > mag_cfg.get("min_gps_speed_ms", 2.0):
                mag_heading = math.degrees(math.atan2(mag_y, mag_x))
                # GPS course over ground from velocity components
                gps_cog = math.degrees(math.atan2(telemetry.get("gps_vy", 0), telemetry.get("gps_vx", 0)))
                heading_diff = abs(mag_heading - gps_cog)
                if heading_diff > 180:
                    heading_diff = 360 - heading_diff
                max_diff = mag_cfg.get("max_yaw_diff_deg", 30.0)
                if heading_diff > max_diff:
                    return self._create_alert(
                        reason="mag_gps_heading_mismatch",
                        severity="medium",
                        detail=f"Mag heading {mag_heading:.1f}° vs GPS COG {gps_cog:.1f}° diff={heading_diff:.1f}°",
                        evidence={
                            "mag_heading_deg": mag_heading,
                            "gps_cog_deg": gps_cog,
                            "difference_deg": heading_diff,
                            "threshold_deg": max_diff
                        },
                        attack_class="sensor_spoofing",
                        observable_from="mavlink_stream",
                        rule_id="CSI-003"
                    )

        # Distance sensor vs baro/GPS altitude
        if dist_cfg.get("enabled", True) and telemetry.fresh("current_distance", now):
            dist = telemetry.get("current_distance")
            baro_alt = self._baro_to_altitude(telemetry.get("press_abs"))
            gps_alt = telemetry.get("gps_alt")
            if dist is not None:
                ref_alt = baro_alt if baro_alt is not None else gps_alt
                if ref_alt is not None:
                    diff = abs(dist - ref_alt)
                    max_diff = dist_cfg.get("max_diff_m", 2.0)
                    if diff > max_diff:
                        return self._create_alert(
                            reason="distance_sensor_altitude_mismatch",
                            severity="medium",
                            detail=f"Distance sensor {dist:.1f}m vs ref altitude {ref_alt:.1f}m diff={diff:.1f}m",
                            evidence={
                                "distance_sensor_m": dist,
                                "reference_altitude_m": ref_alt,
                                "difference_m": diff,
                                "threshold_m": max_diff
                            },
                            attack_class="sensor_spoofing",
                            observable_from="mavlink_stream",
                            rule_id="CSI-004"
                        )

        return None

    def _check_gps_vs_imu(self, telemetry: ControlSystemTelemetry, now: float, gps_cfg: Dict) -> Optional[IDSAlert]:
        """Check GPS vs IMU dead-reckoning consistency with jump/drift detection."""
        # Get current GPS position and velocity
        gps_lat = telemetry.get("gps_lat")
        gps_lon = telemetry.get("gps_lon")
        gps_alt = telemetry.get("gps_alt")
        gps_vx = telemetry.get("gps_vx")
        gps_vy = telemetry.get("gps_vy")
        gps_vz = telemetry.get("gps_vz")

        # Get IMU data for dead-reckoning
        xacc = telemetry.get("xacc")
        yacc = telemetry.get("yacc")
        zacc = telemetry.get("zacc")

        if None in (gps_lat, gps_lon, gps_alt, gps_vx, gps_vy, gps_vz, xacc, yacc, zacc):
            return None

        # Get previous GPS position from history for jump detection
        gps_lat_hist = telemetry.get_history("gps_lat", count=2)
        gps_lon_hist = telemetry.get_history("gps_lon", count=2)
        gps_alt_hist = telemetry.get_history("gps_alt", count=2)

        # Check for sudden position jumps (spoofing indicator)
        if len(gps_lat_hist) >= 2:
            prev_lat = gps_lat_hist[-2][0]
            prev_lon = gps_lon_hist[-2][0]
            prev_alt = gps_alt_hist[-2][0] if len(gps_alt_hist) >= 2 else gps_alt

            # Convert to meters (approximate)
            lat_diff_m = (gps_lat - prev_lat) * 111320.0  # 1 deg lat ≈ 111km
            lon_diff_m = (gps_lon - prev_lon) * 111320.0 * math.cos(math.radians(gps_lat))
            alt_diff_m = gps_alt - prev_alt

            # Position jump thresholds
            max_pos_jump = gps_cfg.get("max_pos_drift_m", 5.0)
            max_alt_jump = gps_cfg.get("max_vel_drift_ms", 1.0) * 10  # Allow larger alt jumps

            horiz_jump = math.sqrt(lat_diff_m**2 + lon_diff_m**2)
            if horiz_jump > max_pos_jump:
                return self._create_alert(
                    reason="gps_position_jump",
                    severity="high",
                    detail=f"GPS horizontal position jump {horiz_jump:.1f}m exceeds threshold {max_pos_jump}m",
                    evidence={
                        "horizontal_jump_m": horiz_jump,
                        "altitude_jump_m": alt_diff_m,
                        "threshold_m": max_pos_jump,
                        "prev_lat": prev_lat,
                        "curr_lat": gps_lat,
                        "prev_lon": prev_lon,
                        "curr_lon": gps_lon
                    },
                    attack_class="gps_spoofing",
                    observable_from="mavlink_stream",
                    rule_id="CSI-005"
                )

        # Check velocity consistency (GPS vs IMU-derived)
        # IMU velocity estimate from accelerometer integration (simplified)
        # In practice, would use proper IMU integration with attitude compensation
        imu_vx = telemetry.get_history("xacc", count=10)
        imu_vy = telemetry.get_history("yacc", count=10)
        if len(imu_vx) >= 2 and len(imu_vy) >= 2:
            # Simple integration: v = sum(a * dt), assuming ~10Hz
            dt = 0.1
            imu_vx_est = sum(v for v, _ in imu_vx) * dt
            imu_vy_est = sum(v for v, _ in imu_vy) * dt
            gps_speed = math.sqrt(gps_vx**2 + gps_vy**2)
            imu_speed = math.sqrt(imu_vx_est**2 + imu_vy_est**2)
            if gps_speed > 0.5:  # Only check when moving
                vel_diff = abs(gps_speed - imu_speed)
                max_vel_diff = gps_cfg.get("max_vel_drift_ms", 1.0)
                if vel_diff > max_vel_diff:
                    return self._create_alert(
                        reason="gps_imu_velocity_mismatch",
                        severity="medium",
                        detail=f"GPS speed {gps_speed:.2f}m/s vs IMU estimate {imu_speed:.2f}m/s diff={vel_diff:.2f}m/s",
                        evidence={
                            "gps_speed_ms": gps_speed,
                            "imu_estimated_speed_ms": imu_speed,
                            "difference_ms": vel_diff,
                            "threshold_ms": max_vel_diff
                        },
                        attack_class="gps_spoofing",
                        observable_from="mavlink_stream",
                        rule_id="CSI-006"
                    )

        # Check yaw consistency (GPS course vs IMU yaw rate integration)
        gps_cog = math.degrees(math.atan2(gps_vy, gps_vx)) if (gps_vx != 0 or gps_vy != 0) else 0
        yaw_hist = telemetry.get_history("yaw", count=2)
        if len(yaw_hist) >= 2 and gps_speed > 1.0:
            imu_yaw = math.degrees(yaw_hist[-1][0])
            yaw_diff = abs(gps_cog - imu_yaw)
            if yaw_diff > 180:
                yaw_diff = 360 - yaw_diff
            max_yaw_diff = gps_cfg.get("max_yaw_drift_deg", 10.0)
            if yaw_diff > max_yaw_diff:
                return self._create_alert(
                    reason="gps_imu_yaw_mismatch",
                    severity="medium",
                    detail=f"GPS COG {gps_cog:.1f}° vs IMU yaw {imu_yaw:.1f}° diff={yaw_diff:.1f}°",
                    evidence={
                        "gps_cog_deg": gps_cog,
                        "imu_yaw_deg": imu_yaw,
                        "difference_deg": yaw_diff,
                        "threshold_deg": max_yaw_diff
                    },
                    attack_class="gps_spoofing",
                    observable_from="mavlink_stream",
                    rule_id="CSI-007"
                )

        return None

    def _baro_to_altitude(self, pressure: Optional[float]) -> Optional[float]:
        """Convert barometric pressure (hPa) to altitude (meters) using ISA formula."""
        if pressure is None or pressure <= 0:
            return None
        return 44330.0 * (1.0 - (pressure / 1013.25) ** 0.190284)


# ---------------------------------------------------------------------------
# Estimator health detectors (EKF innovation/variance)
# ---------------------------------------------------------------------------
class EstimatorHealthDetector(ControlSystemDetector):
    """Monitors EKF innovation and variance for signs of manipulation."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("estimator_health", {}).get("enabled", True)

    def __init__(self, policy: Dict[str, Any]) -> None:
        super().__init__(policy)
        # CUSUM state for innovation monitoring
        self._cusum_pos_horiz = 0.0
        self._cusum_pos_vert = 0.0
        self._cusum_vel_horiz = 0.0
        self._cusum_vel_vert = 0.0

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("estimator_health", {})
        if not cfg.get("enabled", True):
            return None

        max_age = cfg.get("max_age_s", 1.0)
        innov_cfg = cfg.get("innovation", {})
        var_cfg = cfg.get("variance", {})

        # Check EKF innovation flags from ESTIMATOR_STATUS
        pos_horiz_status = telemetry.get("est_pos_horiz_abs_status")
        pos_vert_status = telemetry.get("est_pos_vert_abs_status")
        vel_horiz_status = telemetry.get("est_vel_horiz_abs_status")
        vel_vert_status = telemetry.get("est_vel_vert_abs_status")

        # Status flags: 0=OK, 1=WARNING, 2=ERROR
        if innov_cfg.get("enabled", True):
            if pos_horiz_status == 2 or pos_vert_status == 2:
                return self._create_alert(
                    reason="ekf_position_innovation_error",
                    severity="high",
                    detail=f"EKF position innovation error: horiz={pos_horiz_status}, vert={pos_vert_status}",
                    evidence={
                        "pos_horiz_status": pos_horiz_status,
                        "pos_vert_status": pos_vert_status,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-001"
                )
            if vel_horiz_status == 2 or vel_vert_status == 2:
                return self._create_alert(
                    reason="ekf_velocity_innovation_error",
                    severity="high",
                    detail=f"EKF velocity innovation error: horiz={vel_horiz_status}, vert={vel_vert_status}",
                    evidence={
                        "vel_horiz_status": vel_horiz_status,
                        "vel_vert_status": vel_vert_status,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-002"
                )

            # CUSUM test on innovation residuals (approximated from status flags)
            # In real implementation, we'd use actual innovation values from EKF
            # Here we use status as proxy: 0=OK, 1=WARNING, 2=ERROR
            cusum_threshold = innov_cfg.get("cusum_threshold", 5.0)
            window_size = innov_cfg.get("window_size", 50)

            # Update CUSUM for position horizontal
            pos_horiz_val = float(pos_horiz_status) if pos_horiz_status is not None else 0.0
            self._cusum_pos_horiz = max(0.0, self._cusum_pos_horiz + pos_horiz_val - 0.5)  # Expected mean ~0.5
            if self._cusum_pos_horiz > cusum_threshold:
                self._cusum_pos_horiz = 0.0  # Reset after alert
                return self._create_alert(
                    reason="ekf_cusum_position_horiz",
                    severity="medium",
                    detail=f"EKF position horizontal CUSUM {self._cusum_pos_horiz:.2f} exceeds threshold {cusum_threshold}",
                    evidence={
                        "cusum_value": self._cusum_pos_horiz,
                        "threshold": cusum_threshold,
                        "status": pos_horiz_status,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-003"
                )

            # Update CUSUM for position vertical
            pos_vert_val = float(pos_vert_status) if pos_vert_status is not None else 0.0
            self._cusum_pos_vert = max(0.0, self._cusum_pos_vert + pos_vert_val - 0.5)
            if self._cusum_pos_vert > cusum_threshold:
                self._cusum_pos_vert = 0.0
                return self._create_alert(
                    reason="ekf_cusum_position_vert",
                    severity="medium",
                    detail=f"EKF position vertical CUSUM {self._cusum_pos_vert:.2f} exceeds threshold {cusum_threshold}",
                    evidence={
                        "cusum_value": self._cusum_pos_vert,
                        "threshold": cusum_threshold,
                        "status": pos_vert_status,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-004"
                )

        # Check variance flags
        if var_cfg.get("enabled", True):
            max_pos_horiz = var_cfg.get("max_pos_horiz_var", 25.0)
            max_pos_vert = var_cfg.get("max_pos_vert_var", 10.0)
            max_vel = var_cfg.get("max_vel_var", 4.0)

            if pos_horiz_status is not None and pos_horiz_status > max_pos_horiz:
                return self._create_alert(
                    reason="ekf_position_variance_high",
                    severity="medium",
                    detail=f"EKF horizontal position variance {pos_horiz_status} exceeds threshold",
                    evidence={
                        "pos_horiz_variance": pos_horiz_status,
                        "threshold": max_pos_horiz,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-005"
                )
            if pos_vert_status is not None and pos_vert_status > max_pos_vert:
                return self._create_alert(
                    reason="ekf_position_vert_variance_high",
                    severity="medium",
                    detail=f"EKF vertical position variance {pos_vert_status} exceeds threshold",
                    evidence={
                        "pos_vert_variance": pos_vert_status,
                        "threshold": max_pos_vert,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-006"
                )
            if vel_horiz_status is not None and vel_horiz_status > max_vel:
                return self._create_alert(
                    reason="ekf_velocity_variance_high",
                    severity="medium",
                    detail=f"EKF velocity variance {vel_horiz_status} exceeds threshold",
                    evidence={
                        "vel_horiz_variance": vel_horiz_status,
                        "threshold": max_vel,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-007"
                )

        # Chi-square test on innovation (simplified - using status as proxy)
        if innov_cfg.get("enabled", True):
            chi2_threshold = innov_cfg.get("chi2_threshold", 100.0)
            # Sum of squared status values as proxy for chi-square
            chi2_stat = 0.0
            for status in [pos_horiz_status, pos_vert_status, vel_horiz_status, vel_vert_status]:
                if status is not None:
                    chi2_stat += float(status) ** 2
            if chi2_stat > chi2_threshold:
                return self._create_alert(
                    reason="ekf_innovation_chi2_high",
                    severity="high",
                    detail=f"EKF innovation chi-square {chi2_stat:.1f} exceeds threshold {chi2_threshold}",
                    evidence={
                        "chi2_statistic": chi2_stat,
                        "threshold": chi2_threshold,
                        "pos_horiz": pos_horiz_status,
                        "pos_vert": pos_vert_status,
                        "vel_horiz": vel_horiz_status,
                        "vel_vert": vel_vert_status,
                    },
                    attack_class="estimator_manipulation",
                    observable_from="mavlink_stream",
                    rule_id="EHI-008"
                )

        return None


# ---------------------------------------------------------------------------
# Control invariant / dynamics model
# ---------------------------------------------------------------------------
class ControlInvariantDetector(ControlSystemDetector):
    """Validates that control outputs produce expected physical responses."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("control_invariant", {}).get("enabled", True)

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("control_invariant", {})
        if not cfg.get("enabled", True):
            return None

        max_age = cfg.get("max_age_s", 1.0)

        # Check attitude vs commanded attitude
        att_cfg = cfg.get("attitude", {})
        if att_cfg.get("enabled", True):
            nav_roll = telemetry.get("nav_roll")
            nav_pitch = telemetry.get("nav_pitch")
            nav_yaw = telemetry.get("nav_bearing")
            actual_roll = telemetry.get("roll")
            actual_pitch = telemetry.get("pitch")
            actual_yaw = telemetry.get("yaw")

            if None not in (nav_roll, nav_pitch, actual_roll, actual_pitch):
                roll_err = abs(nav_roll - actual_roll)
                pitch_err = abs(nav_pitch - actual_pitch)
                max_roll_err = att_cfg.get("max_roll_err_deg", 10.0)
                max_pitch_err = att_cfg.get("max_pitch_err_deg", 10.0)
                max_yaw_err = att_cfg.get("max_yaw_err_deg", 15.0)

                yaw_err = 0.0
                if nav_yaw is not None and actual_yaw is not None:
                    yaw_err = abs(nav_yaw - actual_yaw)
                    if yaw_err > 180:
                        yaw_err = 360 - yaw_err

                if roll_err > max_roll_err or pitch_err > max_pitch_err or yaw_err > max_yaw_err:
                    return self._create_alert(
                        reason="control_attitude_tracking_error",
                        severity="medium",
                        detail=f"Attitude tracking error: roll_err={roll_err:.1f}°, pitch_err={pitch_err:.1f}°, yaw_err={yaw_err:.1f}°",
                        evidence={
                            "nav_roll": nav_roll,
                            "nav_pitch": nav_pitch,
                            "nav_yaw": nav_yaw,
                            "actual_roll": actual_roll,
                            "actual_pitch": actual_pitch,
                            "actual_yaw": actual_yaw,
                            "roll_error": roll_err,
                            "pitch_error": pitch_err,
                            "yaw_error": yaw_err,
                            "max_roll_err": max_roll_err,
                            "max_pitch_err": max_pitch_err,
                            "max_yaw_err": max_yaw_err,
                        },
                        attack_class="control_loop_manipulation",
                        observable_from="mavlink_stream",
                        rule_id="CI-001"
                    )

        # Check position/velocity tracking (GPS vs dead-reckoned)
        pos_cfg = cfg.get("position", {})
        if pos_cfg.get("enabled", True):
            # Compare GPS position with IMU-dead-reckoned position
            # This is a simplified check - real implementation would use proper integration
            gps_lat = telemetry.get("gps_lat")
            gps_lon = telemetry.get("gps_lon")
            gps_alt = telemetry.get("gps_alt")
            gps_vx = telemetry.get("gps_vx")
            gps_vy = telemetry.get("gps_vy")
            gps_vz = telemetry.get("gps_vz")
            xacc = telemetry.get("xacc")
            yacc = telemetry.get("yacc")
            zacc = telemetry.get("zacc")

            if None not in (gps_lat, gps_lon, gps_alt, gps_vx, gps_vy, gps_vz, xacc, yacc, zacc):
                # Get previous position from history
                lat_hist = telemetry.get_history("gps_lat", count=2)
                lon_hist = telemetry.get_history("gps_lon", count=2)
                alt_hist = telemetry.get_history("gps_alt", count=2)

                if len(lat_hist) >= 2 and len(lon_hist) >= 2:
                    prev_lat = lat_hist[-2][0]
                    prev_lon = lon_hist[-2][0]
                    prev_alt = alt_hist[-2][0] if len(alt_hist) >= 2 else gps_alt

                    # Time delta
                    dt = now - lat_hist[-2][1]
                    if dt > 0:
                        # Expected position from velocity integration
                        exp_lat = prev_lat + (gps_vy / 100.0) * dt / 111320.0  # m to deg
                        exp_lon = prev_lon + (gps_vx / 100.0) * dt / (111320.0 * math.cos(math.radians(gps_lat)))
                        exp_alt = prev_alt + (gps_vz / 100.0) * dt

                        # Position error
                        lat_err_m = (gps_lat - exp_lat) * 111320.0
                        lon_err_m = (gps_lon - exp_lon) * 111320.0 * math.cos(math.radians(gps_lat))
                        alt_err_m = gps_alt - exp_alt
                        pos_err = math.sqrt(lat_err_m**2 + lon_err_m**2)

                        max_pos_err = pos_cfg.get("max_pos_err_m", 5.0)
                        max_vel_err = pos_cfg.get("max_vel_err_ms", 1.0)

                        if pos_err > max_pos_err or abs(alt_err_m) > max_vel_err * 5:  # Allow larger alt error
                            return self._create_alert(
                                reason="control_position_tracking_error",
                                severity="medium",
                                detail=f"Position tracking error: horiz_err={pos_err:.1f}m, alt_err={alt_err_m:.1f}m",
                                evidence={
                                    "gps_lat": gps_lat,
                                    "gps_lon": gps_lon,
                                    "gps_alt": gps_alt,
                                    "expected_lat": exp_lat,
                                    "expected_lon": exp_lon,
                                    "expected_alt": exp_alt,
                                    "horizontal_error_m": pos_err,
                                    "vertical_error_m": alt_err_m,
                                    "max_pos_err_m": max_pos_err,
                                    "max_vel_err_ms": max_vel_err,
                                },
                                attack_class="control_loop_manipulation",
                                observable_from="mavlink_stream",
                                rule_id="CI-003"
                            )

        # Check actuator response
        act_cfg = cfg.get("actuator", {})
        if act_cfg.get("enabled", True):
            # Check if servo outputs are saturated when they shouldn't be
            servo_vals = [
                telemetry.get(f"servo{i}_raw") for i in range(1, 9)
                if telemetry.get(f"servo{i}_raw") is not None
            ]
            if servo_vals:
                # Servo PWM typically ranges from 1000-2000μs
                # Saturation is near the ends (e.g., <1100 or >1900)
                saturated_count = sum(1 for v in servo_vals if v < 1100 or v > 1900)
                total_servos = len(servo_vals)
                if total_servos > 0 and saturated_count / total_servos > 0.5:  # More than half saturated
                    # Only alert if we're not commanding extreme maneuvers
                    climb = telemetry.get("climb", 0)
                    airspeed = telemetry.get("airspeed", 0)
                    if abs(climb) < 2.0 and airspeed < 5.0:  # Gentle flight
                        return self._create_alert(
                            reason="actuator_saturation_anomaly",
                            severity="medium",
                            detail=f"{saturated_count}/{total_servos} servos saturated during gentle flight",
                            evidence={
                                "servo_values": servo_vals,
                                "saturated_count": saturated_count,
                                "total_servos": total_servos,
                                "climb": climb,
                                "airspeed": airspeed,
                            },
                            attack_class="actuator_manipulation",
                            observable_from="mavlink_stream",
                            rule_id="CI-002"
                        )

            # Check PWM residual (difference between commanded and expected)
            max_pwm_residual = act_cfg.get("max_pwm_residual_us", 200)
            # In real implementation, compare NAV_CONTROLLER_OUTPUT with SERVO_OUTPUT_RAW
            # Simplified: check if servos are responding to attitude changes
            rollspeed = telemetry.get("rollspeed")
            pitchspeed = telemetry.get("pitchspeed")
            if rollspeed is not None and pitchspeed is not None:
                # If high angular rates but servos near trim, possible actuator failure
                servo_trim = sum(servo_vals) / len(servo_vals)
                if abs(rollspeed) > 0.5 or abs(pitchspeed) > 0.5:
                    deviation_from_trim = sum(abs(v - 1500) for v in servo_vals) / len(servo_vals)
                    if deviation_from_trim < 50:  # Servos near trim despite rotation
                        return self._create_alert(
                            reason="actuator_not_responding",
                            severity="high",
                            detail=f"High angular rates (roll={rollspeed:.2f}, pitch={pitchspeed:.2f}) but servos near trim",
                            evidence={
                                "rollspeed": rollspeed,
                                "pitchspeed": pitchspeed,
                                "servo_trim": servo_trim,
                                "deviation_from_trim": deviation_from_trim,
                                "threshold": 50,
                            },
                            attack_class="actuator_manipulation",
                            observable_from="mavlink_stream",
                            rule_id="CI-004"
                        )

        return None


# ---------------------------------------------------------------------------
# Actuator anomaly detector
# ---------------------------------------------------------------------------
class ActuatorAnomalyDetector(ControlSystemDetector):
    """Detects anomalies in actuator outputs (asymmetry, oscillation, resonance)."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("actuator_anomaly", {}).get("enabled", True)

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("actuator_anomaly", {})
        if not cfg.get("enabled", True):
            return None

        max_age = cfg.get("max_age_s", 1.0)

        # Get recent servo history for analysis
        servo_histories = {}
        for i in range(1, 9):
            hist = telemetry.get_history(f"servo{i}_raw", count=50)
            if len(hist) >= 10:  # Need minimum samples
                servo_histories[i] = [v for v, _ in hist]

        if not servo_histories:
            return None

        # Check for asymmetry (left-right imbalance)
        asym_cfg = cfg.get("asymmetry", {})
        if asym_cfg.get("enabled", True):
            # Group servos by left/right (simplified assignment)
            left_servos = [1, 2]  # Front-left, rear-left (example)
            right_servos = [3, 4]  # Front-right, rear-right (example)

            left_vals = []
            right_vals = []
            for servo in left_servos:
                if servo in servo_histories:
                    left_vals.extend(servo_histories[servo])
            for servo in right_servos:
                if servo in servo_histories:
                    right_vals.extend(servo_histories[servo])

            if left_vals and right_vals:
                left_avg = sum(left_vals) / len(left_vals)
                right_avg = sum(right_vals) / len(right_vals)
                avg_pwm = (left_avg + right_avg) / 2
                if avg_pwm > 0:
                    asymmetry_ratio = abs(left_avg - right_avg) / avg_pwm
                    max_asymmetry = asym_cfg.get("max_asymmetry_ratio", 0.3)
                    if asymmetry_ratio > max_asymmetry:
                        return self._create_alert(
                            reason="actuator_asymmetry",
                            severity="medium",
                            detail=f"Actuator asymmetry ratio {asymmetry_ratio:.2f} exceeds threshold {max_asymmetry}",
                            evidence={
                                "left_avg_pwm": left_avg,
                                "right_avg_pwm": right_avg,
                                "asymmetry_ratio": asymmetry_ratio,
                                "threshold": max_asymmetry,
                            },
                            attack_class="actuator_manipulation",
                            observable_from="mavlink_stream",
                            rule_id="AA-001"
                        )

        # Check for oscillation using FFT
        osc_cfg = cfg.get("oscillation", {})
        if osc_cfg.get("enabled", True):
            for servo_num, hist in servo_histories.items():
                if len(hist) >= osc_cfg.get("window_size", 50):
                    # Detrend
                    mean_val = sum(hist) / len(hist)
                    detrended = [h - mean_val for h in hist]
                    
                    # Apply window function (Hanning)
                    n = len(detrended)
                    windowed = [detrended[i] * 0.5 * (1 - math.cos(2 * math.pi * i / (n - 1))) for i in range(n)]
                    
                    # Simple FFT to find dominant frequency (using numpy if available, else manual)
                    # For now, use zero-crossing method with better frequency estimation
                    zero_crossings = sum(1 for i in range(1, n) if detrended[i] * detrended[i-1] < 0)
                    # Estimate sampling rate from timestamps (assuming ~10Hz)
                    # In real implementation, would use actual timestamps
                    est_freq = zero_crossings * (10.0 / n)  # Rough estimate
                    max_freq = osc_cfg.get("max_freq_hz", 20.0)
                    min_amp = osc_cfg.get("min_amplitude_us", 50)
                    amplitude = (max(detrended) - min(detrended)) / 2
                    if est_freq > max_freq and amplitude > min_amp:
                        return self._create_alert(
                            reason="actuator_oscillation",
                            severity="medium",
                            detail=f"Servo {servo_num} oscillating at {est_freq:.1f}Hz with amplitude {amplitude:.0f}μs",
                            evidence={
                                "servo_number": servo_num,
                                "frequency_hz": est_freq,
                                "amplitude_us": amplitude,
                                "max_freq_threshold": max_freq,
                                "min_amplitude_threshold": min_amp,
                            },
                            attack_class="actuator_manipulation",
                            observable_from="mavlink_stream",
                            rule_id="AA-002"
                        )

        # Check for gyro resonance signature in vibration data using FFT
        gyro_cfg = cfg.get("gyro_resonance", {})
        if gyro_cfg.get("enabled", True):
            vib_x = telemetry.get_history("vibration_x", count=gyro_cfg.get("window_size", 200))
            vib_y = telemetry.get_history("vibration_y", count=gyro_cfg.get("window_size", 200))
            vib_z = telemetry.get_history("vibration_z", count=gyro_cfg.get("window_size", 200))

            if len(vib_x) >= 50:  # Minimum for frequency analysis
                # Extract values
                vib_x_vals = [v for v, _ in vib_x]
                vib_y_vals = [v for v, _ in vib_y]
                vib_z_vals = [v for v, _ in vib_z]

                # Compute power spectral density using simple periodogram
                peak_freq = gyro_cfg.get("peak_freq_hz", 400.0)
                freq_tol = gyro_cfg.get("freq_tolerance_hz", 50.0)
                min_power_db = gyro_cfg.get("min_power_db", -10.0)

                # Check each axis for resonance at the configured frequency
                for axis_name, axis_vals in [("x", vib_x_vals), ("y", vib_y_vals), ("z", vib_z_vals)]:
                    if len(axis_vals) >= 50:
                        power_db = self._compute_power_at_freq(axis_vals, peak_freq, freq_tol)
                        if power_db > min_power_db:
                            return self._create_alert(
                                reason="gyro_resonance_detected",
                                severity="high",
                                detail=f"Gyro resonance detected on {axis_name}-axis: {power_db:.1f}dB at {peak_freq}Hz",
                                evidence={
                                    "axis": axis_name,
                                    "power_db": power_db,
                                    "suspected_peak_freq_hz": peak_freq,
                                    "frequency_tolerance_hz": freq_tol,
                                    "min_power_threshold_db": min_power_db,
                                },
                                attack_class="sensor_spoofing",
                                observable_from="mavlink_stream",
                                rule_id="AA-003"
                            )

        return None

    def _compute_power_at_freq(self, signal: List[float], target_freq: float, tolerance: float) -> float:
        """Compute power at target frequency using simple Goertzel algorithm."""
        n = len(signal)
        if n < 2:
            return -100.0

        # Estimate sampling rate from typical MAVLink vibration message rate (~10-20Hz)
        fs = 10.0  # Hz, approximate

        # Goertzel algorithm for single frequency
        k = int(0.5 + n * target_freq / fs)
        if k == 0 or k >= n:
            return -100.0

        omega = 2.0 * math.pi * k / n
        coeff = 2.0 * math.cos(omega)

        s_prev = 0.0
        s_prev2 = 0.0
        for sample in signal:
            s = sample + coeff * s_prev - s_prev2
            s_prev2 = s_prev
            s_prev = s

        power = s_prev2**2 + s_prev**2 - coeff * s_prev * s_prev2
        if power <= 0:
            return -100.0

        # Convert to dB relative to signal RMS
        rms = math.sqrt(sum(s**2 for s in signal) / n)
        if rms <= 0:
            return -100.0

        power_db = 10.0 * math.log10(power / (rms**2 * n))
        return power_db


# ---------------------------------------------------------------------------
# Controller/parameter tampering detector
# ---------------------------------------------------------------------------
class ParameterTamperingDetector(ControlSystemDetector):
    """Detects unauthorized changes to flight-critical parameters."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("param_tampering", {}).get("enabled", True)

    def __init__(self, policy: Dict[str, Any]) -> None:
        super().__init__(policy)
        self._param_history: Dict[str, Tuple[float, float]] = {}  # param -> (value, timestamp)

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("param_tampering", {})
        if not cfg.get("enabled", True):
            return None

        critical_params = cfg.get("critical_params", [])
        allow_in_flight = cfg.get("allow_in_flight", False)
        value_bounds = cfg.get("value_bounds", {})

        # Check if we're in flight (armed)
        armed = telemetry.get("base_mode", 0) & 0x80  # MAV_MODE_FLAG_SAFETY_ARMED

        # Look for PARAM_VALUE messages in history
        # In real implementation, this would come from PARAM_VALUE message handler
        # For now, check if any critical params have changed in telemetry
        for param_name in critical_params:
            # Check if param value is in telemetry (from PARAM_VALUE messages)
            param_val = telemetry.get("param_value")
            if param_val is not None:
                # In real implementation, param_value would contain the param name and value
                # This is a placeholder - would need proper PARAM_VALUE message parsing
                pass

        # Check value bounds for any known parameters
        for param_name, bounds in value_bounds.items():
            min_val = bounds.get("min", float('-inf'))
            max_val = bounds.get("max", float('inf'))
            # In real implementation, would check actual parameter values
            pass

        # Note: Full implementation requires parsing PARAM_VALUE messages
        # which carry param_id (string) and param_value (float)
        # This would be integrated with the MAVLink message handler

        return None


# ---------------------------------------------------------------------------
# Failsafe/geofence/mode logic abuse detector
# ---------------------------------------------------------------------------
class FailsafeLogicDetector(ControlSystemDetector):
    """Detects abuse of failsafe, geofence, and mode logic."""

    def _get_enabled(self) -> bool:
        return self.policy.get("control_system", {}).get("failsafe_logic", {}).get("enabled", True)

    def __init__(self, policy: Dict[str, Any]) -> None:
        super().__init__(policy)
        self._prev_mode = None
        self._prev_armed = None

    def check(self, telemetry: ControlSystemTelemetry, now: float) -> Optional[IDSAlert]:
        self.stats["checks"] += 1
        cfg = self.policy.get("control_system", {}).get("failsafe_logic", {})
        if not cfg.get("enabled", True):
            return None

        max_age = cfg.get("max_age_s", 2.0)
        parachute_min_alt = cfg.get("parachute_min_alt_m", 50.0)
        engine_kill_requires_armed = cfg.get("engine_kill_requires_armed", True)
        geofence_action = cfg.get("geofence_action", "rtl")

        # Get current state
        custom_mode = telemetry.get("custom_mode")
        base_mode = telemetry.get("base_mode")
        relative_alt = telemetry.get("relative_alt")
        lat = telemetry.get("lat")
        lon = telemetry.get("lon")
        gps_alt = telemetry.get("gps_alt")

        armed = (base_mode & 0x80) != 0 if base_mode is not None else False

        # Check for unsafe parachute deployment (MAV_CMD_DO_PARACHUTE = 176)
        # In real implementation, would monitor COMMAND_LONG for this command
        # For now, check if mode indicates parachute and altitude is too low
        if custom_mode is not None and relative_alt is not None:
            # ArduPilot parachute mode is typically custom_mode value
            # This is a simplified check - real implementation would parse COMMAND_ACK
            if relative_alt < parachute_min_alt:
                # If we detect parachute deployment at low altitude
                # This would be triggered by a COMMAND_LONG message
                pass  # Placeholder - requires COMMAND_LONG monitoring

        # Check for unsafe engine kill (MAV_CMD_DO_SET_MODE to MANUAL with throttle=0)
        # or MAV_CMD_COMPONENT_ARM_DISARM with param1=0
        if engine_kill_requires_armed and self._prev_armed is not None and armed:
            if not self._prev_armed:
                # Just armed - check for immediate disarm command
                pass
            # In real implementation, would monitor COMMAND_LONG for disarm

        # Check for illegal mode transitions (PGFUZZ-style)
        if self._prev_mode is not None and custom_mode is not None:
            if custom_mode != self._prev_mode:
                # Check if transition is allowed
                # In real implementation, would check against mode_transitions in config
                # For now, flag unexpected transitions to dangerous modes
                dangerous_modes = [0, 9]  # STABILIZE, LAND in some contexts
                if custom_mode in dangerous_modes and armed:
                    # Transitioning to manual mode while armed at altitude
                    if relative_alt is not None and relative_alt > 10.0:
                        return self._create_alert(
                            reason="unsafe_mode_transition",
                            severity="high",
                            detail=f"Transition to mode {custom_mode} while armed at {relative_alt:.1f}m altitude",
                            evidence={
                                "previous_mode": self._prev_mode,
                                "new_mode": custom_mode,
                                "armed": armed,
                                "relative_alt_m": relative_alt,
                            },
                            attack_class="failsafe_abuse",
                            observable_from="mavlink_stream",
                            rule_id="FL-001"
                        )

        # Check for geofence violations
        if lat is not None and lon is not None:
            # Get geofence from config (simplified - would be polygon)
            geofence = self.policy.get("geofence", {})
            if geofence:
                lat_min = geofence.get("lat_min", -90.0)
                lat_max = geofence.get("lat_max", 90.0)
                lon_min = geofence.get("lon_min", -180.0)
                lon_max = geofence.get("lon_max", 180.0)
                alt_min = geofence.get("alt_min", -50.0)
                alt_max = geofence.get("alt_max", 5000.0)

                if lat < lat_min or lat > lat_max or lon < lon_min or lon > lon_max:
                    return self._create_alert(
                        reason="geofence_violation",
                        severity="high",
                        detail=f"Geofence violation: lat={lat:.6f}, lon={lon:.6f}",
                        evidence={
                            "latitude": lat,
                            "longitude": lon,
                            "lat_min": lat_min,
                            "lat_max": lat_max,
                            "lon_min": lon_min,
                            "lon_max": lon_max,
                            "geofence_action": geofence_action,
                        },
                        attack_class="geofence_violation",
                        observable_from="mavlink_stream",
                        rule_id="FL-002"
                    )

                if gps_alt is not None and (gps_alt < alt_min or gps_alt > alt_max):
                    return self._create_alert(
                        reason="geofence_altitude_violation",
                        severity="high",
                        detail=f"Geofence altitude violation: alt={gps_alt:.1f}m",
                        evidence={
                            "altitude": gps_alt,
                            "alt_min": alt_min,
                            "alt_max": alt_max,
                            "geofence_action": geofence_action,
                        },
                        attack_class="geofence_violation",
                        observable_from="mavlink_stream",
                        rule_id="FL-003"
                    )

        # Check for failsafe activation without proper conditions
        # e.g., RTL triggered without GPS lock
        if custom_mode is not None:
            # RTL mode is typically 6 in ArduPilot
            if custom_mode == 6:  # RTL
                gps_fix = telemetry.get("gps_fix")
                if gps_fix is not None and gps_fix < 3:
                    return self._create_alert(
                        reason="rtl_without_gps_lock",
                        severity="high",
                        detail=f"RTL mode activated with GPS fix type {gps_fix} (< 3D fix)",
                        evidence={
                            "mode": custom_mode,
                            "gps_fix": gps_fix,
                            "required_fix": 3,
                        },
                        attack_class="failsafe_abuse",
                        observable_from="mavlink_stream",
                        rule_id="FL-004"
                    )

        # Update state
        self._prev_mode = custom_mode
        self._prev_armed = armed

        return None


# ---------------------------------------------------------------------------
# Control System Detector Facade
# ---------------------------------------------------------------------------
class ControlSystemDetectorFacade:
    """
    Main facade for control-system attack detection.
    Combines all detectors and handles alert fusion/rate limiting.
    """

    def __init__(self, policy: Optional[Dict[str, Any]] = None,
                 config_path: Optional[str] = None,
                 profile: Optional[str] = None) -> None:
        if config_path is not None and policy is not None:
            raise ValueError("supply either config_path or policy, not both")

        if policy is not None:
            self._policy = policy
        elif config_path is not None:
            self._policy = load_config(config_path, profile=profile)
        else:
            # Back-compat: module-level default when no config given.
            self._policy = default_policy()

        # Initialize detectors
        self.telemetry = ControlSystemTelemetry(
            max_age_s=self._policy.get("control_system", {}).get("sensor_consistency", {}).get("max_age_s", 2.0)
        )
        self.sensor_consistency = SensorConsistencyDetector(self._policy)
        self.estimator_health = EstimatorHealthDetector(self._policy)
        self.control_invariant = ControlInvariantDetector(self._policy)
        self.actuator_anomaly = ActuatorAnomalyDetector(self._policy)
        self.param_tampering = ParameterTamperingDetector(self._policy)
        self.failsafe_logic = FailsafeLogicDetector(self._policy)

        # Alert rate limiting (reuse from command_injection_detector)
        from .command_injection_detector import AlertRateLimiter
        al = self._policy.get("alerting", {})
        self._alert_limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0),
        )
        self._include_mitre = al.get("include_mitre", True)
        self._fail_mode = self._get_fail_mode()

        # Stats
        self.stats = {
            "checks": 0,
            "alerts": 0,
            "suppressed": 0,
        }

    def _get_fail_mode(self) -> str:
        """Get fail-safe mode from policy."""
        from .ids_config import get_fail_mode
        return get_fail_mode(self._policy)

    def ingest_telemetry(self, msg_type: str, ts: float, **fields) -> None:
        """Ingest one telemetry message."""
        self.telemetry.ingest(msg_type, ts, **fields)

    def check(self, now: Optional[float] = None) -> Optional[IDSAlert]:
        """
        Run all enabled detectors and return the fused alert.
        Returns None if no attack detected or if alert is rate-limited.
        """
        if now is None:
            now = time.time()

        self.stats["checks"] += 1

        # Get fusion weights from config
        fusion_cfg = self._policy.get("control_system", {}).get("fusion", {})
        weights = {
            "sensor_consistency": fusion_cfg.get("sensor_consistency_weight", 0.3),
            "estimator_health": fusion_cfg.get("estimator_health_weight", 0.2),
            "control_invariant": fusion_cfg.get("control_invariant_weight", 0.25),
            "actuator_anomaly": fusion_cfg.get("actuator_anomaly_weight", 0.15),
            "param_tampering": fusion_cfg.get("param_tampering_weight", 0.05),
            "failsafe_logic": fusion_cfg.get("failsafe_logic_weight", 0.05),
        }
        alert_threshold = fusion_cfg.get("alert_threshold", 0.5)

        # Run all detectors
        detector_map = {
            "sensor_consistency": self.sensor_consistency,
            "estimator_health": self.estimator_health,
            "control_invariant": self.control_invariant,
            "actuator_anomaly": self.actuator_anomaly,
            "param_tampering": self.param_tampering,
            "failsafe_logic": self.failsafe_logic,
        }

        alerts_by_class: Dict[str, List[Dict]] = {}
        for det_name, detector in detector_map.items():
            if not detector.enabled:
                continue
            alert = detector.check(self.telemetry, now)
            if alert is not None:
                attack_class = alert.attack_class
                if attack_class not in alerts_by_class:
                    alerts_by_class[attack_class] = []
                alerts_by_class[attack_class].append({
                    "alert": alert,
                    "detector": det_name,
                    "weight": weights.get(det_name, 0.0),
                })

        if not alerts_by_class:
            return None

        # Fuse alerts by attack class using weighted confidence
        fused_alerts = []
        for attack_class, class_alerts in alerts_by_class.items():
            # Compute weighted confidence
            total_weight = 0.0
            weighted_confidence = 0.0
            combined_evidence = {}
            max_severity = "low"
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            first_alert = class_alerts[0]["alert"]

            for entry in class_alerts:
                alert = entry["alert"]
                weight = entry["weight"]
                confidence = getattr(alert, "confidence", 0.8)
                weighted_confidence += confidence * weight
                total_weight += weight

                # Combine evidence
                for k, v in (alert.evidence or {}).items():
                    if k not in combined_evidence:
                        combined_evidence[k] = v
                    elif isinstance(combined_evidence[k], list):
                        combined_evidence[k].append(v)
                    else:
                        combined_evidence[k] = [combined_evidence[k], v]

                # Track max severity
                if severity_order.get(alert.severity, 0) > severity_order.get(max_severity, 0):
                    max_severity = alert.severity

            avg_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0

            # Only emit if fused confidence exceeds threshold
            if avg_confidence >= alert_threshold:
                fused_alert = IDSAlert(
                    timestamp=now,
                    severity=max_severity,
                    reason=f"fused_{attack_class}",
                    rule_id=f"CS-FUSED-{hash(attack_class) % 1000:03d}",
                    attack_class=attack_class,
                    observable_from=first_alert.observable_from,
                    detail=f"Fused {len(class_alerts)} detector(s) for {attack_class} (confidence={avg_confidence:.2f})",
                    evidence=combined_evidence,
                    confidence=avg_confidence,
                )
                fused_alerts.append(fused_alert)

        if not fused_alerts:
            return None

        # Select highest severity fused alert
        fused_alerts.sort(key=lambda a: severity_order.get(a.severity, 0), reverse=True)
        selected_alert = fused_alerts[0]

        # Apply rate limiting and deduplication
        # Create a dedupe key based on reason and key evidence fields
        evidence = selected_alert.evidence or {}
        dedupe_key = f"{selected_alert.reason}:{evidence.get('baro_altitude', '')}:{evidence.get('gps_altitude', '')}:{evidence.get('flow_quality', '')}:{evidence.get('servo_values', '')}"

        if not self._alert_limiter.allow(dedupe_key, 0, "control_system", now):
            self.stats["suppressed"] += 1
            return None

        self.stats["alerts"] += 1

        # Apply fail-safe mode
        if self._fail_mode == "alert_and_block":
            selected_alert.evidence["drop"] = True

        return selected_alert

    def get_stats(self) -> Dict[str, int]:
        """Get detector statistics."""
        return dict(self.stats)

    def reset(self) -> None:
        """Reset detector statistics."""
        self.stats = {"checks": 0, "alerts": 0, "suppressed": 0}
        self._alert_limiter.reset()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("CONTROL SYSTEM DETECTOR — SELF TEST")
    print("=" * 70)

    # Test with default policy
    detector = ControlSystemDetectorFacade()
    tel = detector.telemetry
    now = time.time()

    # Ingest some nominal telemetry
    tel.ingest("GLOBAL_POSITION_INT", now, lat=0.0, lon=0.0, relative_alt=10.0)
    tel.ingest("GPS_RAW_INT", now, gps_lat=0.0, gps_lon=0.0, gps_alt=10.0,
               gps_vx=0.0, gps_vy=0.0, gps_vz=0.0, gps_fix=3, gps_satellites_visible=8)
    tel.ingest("ATTITUDE", now, roll=0.0, pitch=0.0, yaw=0.0,
               rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0)
    tel.ingest("SCALED_PRESSURE", now, press_abs=1013.25, press_diff=0.0)
    tel.ingest("SERVO_OUTPUT_RAW", now,
               servo1_raw=1500, servo2_raw=1500, servo3_raw=1500, servo4_raw=1500,
               servo5_raw=1500, servo6_raw=1500, servo7_raw=1500, servo8_raw=1500)

    # Should not alert on nominal data
    alert = detector.check(now)
    assert alert is None, f"Unexpected alert on nominal data: {alert}"
    print("[1] Nominal telemetry: PASS (no alert)")

    # Test baro/GPS altitude mismatch
    tel.ingest("SCALED_PRESSURE", now + 1, press_abs=900.0)  # Low pressure = high altitude
    tel.ingest("GPS_RAW_INT", now + 1, gps_lat=0.0, gps_lon=0.0, gps_alt=100.0,
               gps_vx=0.0, gps_vy=0.0, gps_vz=0.0, gps_fix=3, gps_satellites_visible=8)
    # Baro altitude from 900hPa is ~1000m, GPS says 100m -> large difference
    alert = detector.check(now + 1)
    if alert is not None and alert.reason == "baro_gps_altitude_mismatch":
        print("[2] Baro/GPS altitude mismatch: PASS (alert triggered)")
    else:
        print(f"[2] Baro/GPS altitude mismatch: FAIL (got {alert})")

    # Test optical flow anomaly (use time > max_age_s to clear old data)
    tel.clear()
    tel.ingest("OPTICAL_FLOW", now + 10, flow_quality=10, flow_comp_m_x=0.0, flow_comp_m_y=0.0)
    tel.ingest("VFR_HUD", now + 10, groundspeed=5.0)  # Moving fast but no flow
    alert = detector.check(now + 10)
    if alert is not None and alert.reason == "optical_flow_anomaly":
        print("[3] Optical flow anomaly: PASS (alert triggered)")
    else:
        print(f"[3] Optical flow anomaly: FAIL (got {alert})")

    # Test actuator saturation (use time > max_age_s to clear old data)
    tel.clear()
    tel.ingest("SERVO_OUTPUT_RAW", now + 20,
               servo1_raw=1050, servo2_raw=1050, servo3_raw=1950, servo4_raw=1950,
               servo5_raw=1050, servo6_raw=1500, servo7_raw=1500, servo8_raw=1500)
    tel.ingest("VFR_HUD", now + 20, groundspeed=1.0, climb=0.0)  # Gentle flight
    alert = detector.check(now + 20)
    if alert is not None and alert.reason == "actuator_saturation_anomaly":
        print("[4] Actuator saturation: PASS (alert triggered)")
    else:
        print(f"[4] Actuator saturation: FAIL (got {alert})")

    print("\nSENSOR CONSISTENCY DETECTOR STATS:", detector.sensor_consistency.stats)
    print("ESTIMATOR HEALTH DETECTOR STATS:", detector.estimator_health.stats)
    print("CONTROL INVARIANT DETECTOR STATS:", detector.control_invariant.stats)
    print("ACTUATOR ANOMALY DETECTOR STATS:", detector.actuator_anomaly.stats)
    print("PARAM TAMPERING DETECTOR STATS:", detector.param_tampering.stats)
    print("FAILSAFE LOGIC DETECTOR STATS:", detector.failsafe_logic.stats)
    print("FACADE STATS:", detector.get_stats())

    print("=" * 70)
    print("SELF-TEST COMPLETE")
    print("=" * 70)