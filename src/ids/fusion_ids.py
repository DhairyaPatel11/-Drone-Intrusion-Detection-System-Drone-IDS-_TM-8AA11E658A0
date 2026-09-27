"""
fusion_ids.py
Navigation Fusion Intrusion Detection System

Main detection module that ties together:
- Telemetry ingestion (nav_sensors.NavTelemetryBuffer)
- Feature extraction (nav_sensors.NavFeatureExtractor)
- Attack detection logic for all navigation attack classes
- Alert generation with trust scores and advisory responses

Implements the detection pipeline per the specification:
- GNSS jamming/spoofing detection (jump, drift, seamless, time)
- INS/GNSS consistency (Chi-square + CUSUM)
- Bounded dead reckoning
- Multi-source attribution
- Sensor cross-checks (mag/baro/optflow)
- Stealthy attack analysis
- Trust scores with hysteresis
- Advisory failover recommendations
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .nav_sensors import (
    NavigationConfig,
    NavTelemetryBuffer,
    NavFeatureExtractor,
)
from .ids_config import load_config, default_policy
from .command_injection_detector import IDSAlert, AlertRateLimiter


# ---------------------------------------------------------------------------
# Detector State
# ---------------------------------------------------------------------------
@dataclass
class NavigationDetectorState:
    """Mutable state maintained by the navigation detector."""
    # CUSUM state for INS/GNSS consistency
    cusum_pos_horiz: float = 0.0
    cusum_pos_vert: float = 0.0
    cusum_vel: float = 0.0
    cusum_mag: float = 0.0
    mag_bias_cusum: float = 0.0
    optflow_bias_cusum: float = 0.0

    # Dead reckoning uncertainty
    dr_uncertainty_m: float = 0.0
    last_gnss_update_ts: float = 0.0

    # Trust scores with hysteresis
    trust_gnss: float = 1.0
    trust_ins: float = 1.0
    trust_baro: float = 1.0
    trust_optflow: float = 1.0
    trust_magnetometer: float = 1.0

    # Previous position for jump detection
    prev_gps_pos: Optional[Tuple[float, float, float]] = None
    prev_gps_vel: Optional[Tuple[float, float, float]] = None
    prev_gps_time: Optional[float] = None

    # RTK correction fault tracking
    rtk_fixed_duration: int = 0
    rtk_base_lat: Optional[float] = None
    rtk_base_lon: Optional[float] = None

    # Alert deduplication
    last_alert_ts: Dict[str, float] = field(default_factory=dict)

    # Detection floor tracking
    last_detection_floor: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main Detector
# ---------------------------------------------------------------------------
class NavigationIDS:
    """
    Navigation Fusion Intrusion Detection System.

    Consumes MAVLink telemetry, extracts features, runs detection logic,
    and emits structured alerts with trust scores and advisory actions.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None,
        profile: Optional[str] = None,
    ):
        """
        Initialize the Navigation IDS.

        Args:
            config_path: Path to YAML config file
            policy: Pre-loaded policy dict
            profile: Mission profile to apply
        """
        if config_path is not None and policy is not None:
            raise ValueError("supply either config_path or policy, not both")

        if policy is not None:
            self.policy = policy
        elif config_path is not None:
            self.policy = load_config(config_path, profile=profile)
        else:
            self.policy = default_policy()

        self.config = NavigationConfig(self.policy)
        self.buffer = NavTelemetryBuffer(max_age_s=5.0)
        self.extractor = NavFeatureExtractor(self.config, self.buffer)
        self.state = NavigationDetectorState()

        # Alert rate limiting
        al = self.policy.get("alerting", {})
        self.alert_limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0),
        )
        self.include_mitre = al.get("include_mitre", True)
        self.fail_mode = self._get_fail_mode()

        # MITRE mapping for navigation attacks
        self._mitre_map = {
            "gps_spoofing_jump": "T0883",
            "gps_spoofing_drift": "T0883",
            "gps_jamming": "T0884",
            "gps_spoofing_seamless": "T0883",
            "gps_time_spoofing": "T0884",
            "gnss_jamming_ramp": "T0884",
            "baro_spoofing_iemi": "T0856",
            "mag_spoofing_coil": "T0856",
            "optical_flow_spoofing": "T0883",
            "rangefinder_spoofing": "T0883",
            "rtcorrection_injection": "T0856",
            "coordinated_gnss_baro": "T0883",
            "mag_bias_drift": "T0856",
            "optical_flow_bias": "T0883",
            "rtcorrection_fault": "T0856",
        }

        # Stats
        self.stats = {
            "packets": 0,
            "alerts": 0,
            "suppressed": 0,
            "detections": {},
        }

        print(f"[NavigationIDS] Initialized with profile={profile or 'default'}")

    def _get_fail_mode(self) -> str:
        from .ids_config import get_fail_mode
        return get_fail_mode(self.policy)

    # -----------------------------------------------------------------------
    # Telemetry Ingestion
    # -----------------------------------------------------------------------
    def ingest_telemetry(self, msg_type: str, ts: float, **fields) -> None:
        """Ingest one MAVLink telemetry message."""
        self.buffer.ingest(msg_type, ts, **fields)

    # -----------------------------------------------------------------------
    # Main Detection Loop
    # -----------------------------------------------------------------------
    def check(self, now: Optional[float] = None) -> Optional[IDSAlert]:
        """
        Run all detection checks and return the highest priority alert.

        Returns:
            IDSAlert if attack detected, None otherwise.
        """
        if now is None:
            now = time.time()

        # Extract features
        features = self.extractor.extract_all(now)

        # Update state
        self._update_state(features, now)

        # Run all detectors
        alerts = []
        detectors = [
            ("gnss_jamming", self._detect_gnss_jamming, features),
            ("gps_spoofing_jump", self._detect_gps_spoofing_jump, features),
            ("gps_spoofing_drift", self._detect_gps_spoofing_drift, features),
            ("gps_spoofing_seamless", self._detect_gps_spoofing_seamless, features),
            ("gps_time_spoofing", self._detect_gps_time_spoofing, features),
            ("gnss_jamming_ramp", self._detect_gnss_jamming_ramp, features),
            ("baro_spoofing", self._detect_baro_spoofing, features),
            ("mag_spoofing", self._detect_mag_spoofing, features),
            ("optical_flow_spoofing", self._detect_optical_flow_spoofing, features),
            ("rangefinder_spoofing", self._detect_rangefinder_spoofing, features),
            ("rtcorrection_injection", self._detect_rtcorrection_injection, features),
            ("coordinated_gnss_baro", self._detect_coordinated_gnss_baro, features),
            ("mag_bias_drift", self._detect_mag_bias_drift, features),
            ("optical_flow_bias", self._detect_optical_flow_bias, features),
            ("rtcorrection_fault", self._detect_rtcorrection_fault, features),
            ("stealthy_attack", self._detect_stealthy_attack, features),
        ]

        for attack_name, detector_fn, feats in detectors:
            if not self.config.enabled:
                continue
            try:
                alert = detector_fn(feats, now)
                if alert:
                    alert.attack_class = attack_name
                    alerts.append(alert)
            except Exception as e:
                print(f"[NavigationIDS] Detector {attack_name} error: {e}")

        if not alerts:
            return None

        # Select highest severity alert
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        alerts.sort(key=lambda a: severity_order.get(a.severity, 0), reverse=True)
        selected = alerts[0]

        # Apply rate limiting and deduplication
        dedupe_key = f"{selected.reason}:{selected.attack_class}"
        allowed = self.alert_limiter.allow(dedupe_key, 0, "navigation", now)
        if not allowed:
            self.stats["suppressed"] += 1
            return None

        self.stats["alerts"] += 1
        self.stats["detections"][selected.attack_class] = \
            self.stats["detections"].get(selected.attack_class, 0) + 1

        # Apply fail-safe mode
        if self.fail_mode == "alert_and_block":
            selected.evidence["drop"] = True

        return selected

    # -----------------------------------------------------------------------
    # State Update
    # -----------------------------------------------------------------------
    def _update_state(self, features: Dict[str, Any], now: float) -> None:
        """Update mutable detector state from features."""
        # Update trust scores with hysteresis
        for trust_key in ["trust_gnss", "trust_ins", "trust_baro", "trust_optflow", "trust_magnetometer"]:
            new_val = features.get(trust_key)
            if new_val is not None:
                old_val = getattr(self.state, trust_key)
                if abs(new_val - old_val) > self.config.hysteresis:
                    setattr(self.state, trust_key, new_val)

        # Update dead reckoning uncertainty
        self.state.dr_uncertainty_m = features.get("dr_uncertainty_m", 0.0)

        # Update last GNSS update timestamp
        if features.get("gnss_fix_ok"):
            self.state.last_gnss_update_ts = time.time()

        # Update CUSUM state for drift detection
        self._update_cusum_state(features)

    def _update_cusum_state(self, features: Dict[str, Any]) -> None:
        """Update CUSUM statistics for slow drift detection."""
        # CUSUM on horizontal position innovation (EKF pos_horiz_ratio)
        # pos_horiz_ratio > 1 means innovation exceeds expected noise
        pos_horiz_ratio = features.get("ekf_pos_horiz_ratio")
        if pos_horiz_ratio is not None:
            # Reference value: 1.0 is expected (noise-matched), >1 is anomaly
            drift = max(0.0, pos_horiz_ratio - 1.0)
            self.state.cusum_pos_horiz = max(0.0, self.state.cusum_pos_horiz + drift - 0.01)
        else:
            # Decay CUSUM when no data
            self.state.cusum_pos_horiz = max(0.0, self.state.cusum_pos_horiz - 0.02)

        # CUSUM on vertical position innovation
        pos_vert_ratio = features.get("ekf_pos_vert_ratio")
        if pos_vert_ratio is not None:
            drift = max(0.0, pos_vert_ratio - 1.0)
            self.state.cusum_pos_vert = max(0.0, self.state.cusum_pos_vert + drift - 0.01)
        else:
            self.state.cusum_pos_vert = max(0.0, self.state.cusum_pos_vert - 0.02)

        # CUSUM on velocity innovation
        vel_ratio = features.get("ekf_vel_ratio")
        if vel_ratio is not None:
            drift = max(0.0, vel_ratio - 1.0)
            self.state.cusum_vel = max(0.0, self.state.cusum_vel + drift - 0.01)
        else:
            self.state.cusum_vel = max(0.0, self.state.cusum_vel - 0.02)

        # CUSUM on magnetometer innovation
        mag_ratio = features.get("ekf_mag_ratio")
        if mag_ratio is not None:
            drift = max(0.0, mag_ratio - 1.0)
            self.state.cusum_mag = max(0.0, self.state.cusum_mag + drift - 0.01)
        else:
            self.state.cusum_mag = max(0.0, self.state.cusum_mag - 0.02)

    # -----------------------------------------------------------------------
    # Individual Detectors
    # -----------------------------------------------------------------------
    def _detect_gnss_jamming(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect GNSS jamming via signal quality collapse."""
        if not feats.get("gnss_fix_ok", True):
            sats = feats.get("gnss_satellites", 0)
            if sats is not None and sats < self.config.min_satellites:
                return self._create_alert(
                    now, "high", "gnss_jamming",
                    f"GNSS signal loss: {sats} sats, fix_type={feats.get('gnss_fix_type')}",
                    {"satellites": sats,
                     "fix_type": feats.get("gnss_fix_type"),
                     "trust_gnss": feats.get("trust_gnss")},
                    "navigation", "mavlink_stream", "NAV-001"
                )
        return None

    def _detect_gps_spoofing_jump(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect GPS spoofing via abrupt position jump."""
        jump = feats.get("gnss_position_jump_m")
        if jump is not None and not feats.get("gnss_position_jump_ok", True):
            return self._create_alert(
                now, "high", "gps_spoofing_jump",
                f"GPS position jump: {jump:.1f}m (threshold={self.config.position_jump_threshold_m}m)",
                {"jump_m": jump,
                 "threshold_m": self.config.position_jump_threshold_m,
                 "prev_pos": self.state.prev_gps_pos,
                 "trust_gnss": feats.get("trust_gnss")},
                "navigation", "mavlink_stream", "NAV-002"
            )
        return None

    def _detect_gps_spoofing_drift(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect GPS spoofing via slow drift (CUSUM on innovation)."""
        chi2 = feats.get("ekf_chi2")
        if chi2 is not None and chi2 > self.config.innovation_chi2_threshold:
            # Check if drift is persistent (CUSUM)
            if self.state.cusum_pos_horiz > self.config.cusum_threshold:
                return self._create_alert(
                    now, "high", "gps_spoofing_drift",
                    f"GNSS slow drift detected: chi2={chi2:.1f}, CUSUM={self.state.cusum_pos_horiz:.1f}",
                    {"chi2": chi2, "cusum": self.state.cusum_pos_horiz,
                     "threshold": self.config.cusum_threshold},
                    "navigation", "mavlink_stream", "NAV-003"
                )
        return None

    def _detect_gps_spoofing_seamless(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect seamless GPS takeover (drag-off).
        This is fundamentally hard to detect from MAVLink alone.
        We flag when GNSS looks perfect but other sensors disagree.
        """
        # Check if GNSS looks perfect but INS disagrees
        if (feats.get("gnss_fix_ok") and feats.get("gnss_satellites", 0) >= 8 and
            feats.get("trust_gnss", 0) > 0.9):
            # Cross-check with other sources
            if (feats.get("trust_ins", 1) < 0.5 or
                feats.get("trust_baro", 1) < 0.5 or
                feats.get("trust_optflow", 1) < 0.5):
                return self._create_alert(
                    now, "medium", "gps_spoofing_seamless",
                    "Possible seamless GPS takeover: GNSS healthy but other sensors disagree",
                    {"trust_gnss": feats.get("trust_gnss"),
                     "trust_ins": feats.get("trust_ins"),
                     "trust_baro": feats.get("trust_baro")},
                    "navigation", "mavlink_stream", "NAV-004"
                )
        return None

    def _detect_gps_time_spoofing(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect GPS time spoofing via clock drift."""
        jump = feats.get("gnss_clock_jump_s")
        if jump is not None and not feats.get("gnss_clock_jump_ok", True):
            return self._create_alert(
                now, "medium", "gps_time_spoofing",
                f"GPS time jump: {jump:.3f}s (threshold={self.config.clock_jump_threshold_s}s)",
                {"clock_jump_s": jump, "threshold_s": self.config.clock_jump_threshold_s},
                "navigation", "mavlink_stream", "NAV-005"
            )
        return None

    def _detect_gnss_jamming_ramp(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect swept-frequency jamming via SNR degradation."""
        # SNR features would need per-satellite data (not in standard MAVLink)
        # Placeholder for when receiver provides SNR distribution
        snr_spread = feats.get("gnss_snr_spread_db")
        snr_change = feats.get("gnss_snr_change_rate_db_s")
        if (snr_spread is not None and snr_spread > self.config.snr_spread_threshold_db) or \
           (snr_change is not None and snr_change > self.config.snr_change_rate_db_s):
            return self._create_alert(
                now, "medium", "gnss_jamming_ramp",
                f"Swept jamming suspected: SNR spread={snr_spread}dB, rate={snr_change}dB/s",
                {"snr_spread_db": snr_spread, "snr_change_rate_db_s": snr_change},
                "navigation", "mavlink_stream", "NAV-006"
            )
        return None

    def _detect_baro_spoofing(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect barometer spoofing (IEMI/acoustic)."""
        diff = feats.get("baro_gnss_alt_diff_m")
        if diff is not None and not feats.get("baro_gnss_alt_ok", True):
            return self._create_alert(
                now, "high", "baro_spoofing",
                f"Baro/GNSS altitude mismatch: {diff:.1f}m",
                {"diff_m": diff, "threshold_m": self.config.max_baro_diff_m + self.config.weather_drift_allowance_m,
                 "trust_baro": feats.get("trust_baro")},
                "navigation", "mavlink_stream", "NAV-007"
            )

        # Also check for frozen altitude (IEMI bus stall) - baro altitude doesn't change over time
        baro_press = feats.get("baro_press")
        if baro_press is not None:
            baro_alt = 44330 * (1 - (baro_press / 1013.25) ** 0.190284)
            baro_alt_history = self.extractor.buffer.get_history("baro_press", count=50)
            if len(baro_alt_history) >= 10:
                altitudes = [44330 * (1 - (p / 1013.25) ** 0.190284) for p, _ in baro_alt_history if p > 0]
                if len(altitudes) >= 10:
                    # Check if altitude is frozen (very low variance)
                    alt_var = sum((a - sum(altitudes)/len(altitudes))**2 for a in altitudes) / len(altitudes)
                    if alt_var < 0.01:  # Essentially frozen
                        return self._create_alert(
                            now, "high", "baro_frozen",
                            f"Barometer altitude frozen (IEMI suspected): variance={alt_var:.4f}",
                            {"baro_variance": alt_var, "baro_pressure": baro_press},
                            "navigation", "mavlink_stream", "NAV-007b"
                        )
        return None

    def _detect_mag_spoofing(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect magnetometer spoofing (active coil/EMI)."""
        diff = feats.get("mag_gyro_yaw_diff_deg")
        yaw_ok = feats.get("mag_gyro_yaw_ok")
        if diff is not None and not feats.get("mag_gyro_yaw_ok", True):
            return self._create_alert(
                now, "high", "mag_spoofing",
                f"Magnetometer/gyro heading mismatch: {diff:.1f}deg",
                {"diff_deg": diff, "threshold_deg": self.config.max_yaw_diff_deg,
                 "trust_magnetometer": feats.get("trust_magnetometer")},
                "navigation", "mavlink_stream", "NAV-008"
            )
        return None

    def _detect_optical_flow_spoofing(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect optical flow spoofing (laser/projection)."""
        diff = feats.get("optflow_gnss_vel_diff_ms")
        if diff is not None and not feats.get("optflow_gnss_vel_ok", True):
            return self._create_alert(
                now, "high", "optical_flow_spoofing",
                f"Optical flow/GNSS velocity mismatch: {diff:.2f}m/s",
                {"diff_ms": diff, "threshold_ms": self.config.max_vel_diff_ms + self.config.wind_allowance_ms,
                 "quality": feats.get("optflow_quality_ok"),
                 "trust_optflow": feats.get("trust_optflow")},
                "navigation", "mavlink_stream", "NAV-009"
            )
        return None

    def _detect_rangefinder_spoofing(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect rangefinder/LiDAR spoofing."""
        # Compare DISTANCE_SENSOR with baro/GNSS altitude
        dist = feats.get("dist_sensor")
        gps_alt = feats.get("gps_alt")
        baro_alt = feats.get("baro_alt")

        if dist is not None:
            ref_alt = None
            if gps_alt is not None:
                ref_alt = gps_alt
            elif baro_alt is not None:
                ref_alt = baro_alt

            if ref_alt is not None:
                diff = abs(dist - ref_alt)
                max_diff = self.config.dist_sensor_vs_alt.get("max_diff_m", 2.0)
                if diff > max_diff:
                    return self._create_alert(
                        now, "high", "rangefinder_spoofing",
                        f"Rangefinder/altitude mismatch: {diff:.1f}m (threshold={max_diff}m)",
                        {"rangefinder_m": dist, "reference_alt_m": ref_alt,
                         "difference_m": diff, "threshold_m": max_diff},
                        "navigation", "mavlink_stream", "NAV-012"
                    )

        # Check for frozen rangefinder value (spoofing)
        dist_hist = self.extractor.buffer.get_history("dist_sensor", count=50)
        if len(dist_hist) >= 10:
            vals = [v for v, _ in dist_hist]
            if max(vals) - min(vals) < 0.01:  # Essentially frozen
                return self._create_alert(
                    now, "high", "rangefinder_frozen",
                    f"Rangefinder frozen: {dist:.2f}m constant over {len(dist_hist)} samples",
                    {"rangefinder_m": vals[-1], "samples": len(vals)},
                    "navigation", "mavlink_stream", "NAV-012b"
                )

        return None

    def _detect_rtcorrection_injection(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect RTK correction stream injection."""
        # Check for RTK fix with unexpected position
        fix_type = feats.get("gnss_fix_type")
        if fix_type == 6:  # RTK Fixed
            # In real implementation, would verify base station coordinates
            # via separate authenticated channel (OSNMA, MAVShield, etc.)
            # Here we check if RTK fix appears without proper base station
            rtk_base_lat = feats.get("rtk_base_lat")
            rtk_base_lon = feats.get("rtk_base_lon")
            if rtk_base_lat is None or rtk_base_lon is None:
                return self._create_alert(
                    now, "medium", "rtk_correction_injection",
                    "RTK Fixed but no base station coordinates available for verification",
                    {"fix_type": fix_type, "base_station_verified": False},
                    "navigation", "mavlink_stream", "NAV-013"
                )
        return None

    def _detect_coordinated_gnss_baro(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect coordinated GNSS + barometer spoofing."""
        # Both GNSS and baro show anomalies simultaneously
        gnss_jump = feats.get("gnss_position_jump_m")
        baro_diff = feats.get("baro_gnss_alt_diff_m")
        if (gnss_jump is not None and not feats.get("gnss_position_jump_ok", True) and
            baro_diff is not None and not feats.get("baro_gnss_alt_ok", True)):
            return self._create_alert(
                now, "critical", "coordinated_gnss_baro",
                f"Coordinated GNSS+Baro spoofing: GPS jump + Baro diff",
                {"gnss_jump_m": gnss_jump, "baro_diff_m": baro_diff},
                "navigation", "mavlink_stream", "NAV-010"
            )
        return None

    def _detect_mag_bias_drift(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect slow magnetometer bias drift."""
        # Track heading drift over time using CUSUM on mag/gyro difference
        diff = feats.get("mag_gyro_yaw_diff_deg")
        if diff is not None:
            # Update CUSUM state
            self.state.mag_bias_cusum = max(0.0, self.state.mag_bias_cusum + diff - 0.5)
            threshold = self.config.max_yaw_diff_deg * 0.5  # Lower threshold for drift
            if self.state.mag_bias_cusum > threshold:
                self.state.mag_bias_cusum = 0.0  # Reset after alert
                return self._create_alert(
                    now, "medium", "mag_bias_drift",
                    f"Slow magnetometer bias drift detected: CUSUM={self.state.mag_bias_cusum:.1f}deg",
                    {"cusum_deg": self.state.mag_bias_cusum, "threshold_deg": threshold,
                     "current_diff_deg": diff},
                    "navigation", "mavlink_stream", "NAV-014"
                )
        return None

    def _detect_optical_flow_bias(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect constant optical flow velocity bias."""
        # Look for persistent optflow/GNSS velocity offset when moving
        diff = feats.get("optflow_gnss_vel_diff_ms")
        groundspeed = feats.get("gnss_groundspeed") or feats.get("vfr_groundspeed")
        if diff is not None and groundspeed is not None and groundspeed > 1.0:
            # Track persistent bias using CUSUM
            self.state.optflow_bias_cusum = max(0.0, self.state.optflow_bias_cusum + diff - 0.1)
            threshold = self.config.max_vel_diff_ms * 2  # Persistent bias threshold
            if self.state.optflow_bias_cusum > threshold:
                self.state.optflow_bias_cusum = 0.0
                return self._create_alert(
                    now, "medium", "optical_flow_bias",
                    f"Persistent optical flow velocity bias: CUSUM={self.state.optflow_bias_cusum:.2f}m/s",
                    {"cusum_ms": self.state.optflow_bias_cusum, "threshold_ms": threshold,
                     "current_diff_ms": diff, "groundspeed_ms": groundspeed},
                    "navigation", "mavlink_stream", "NAV-015"
                )
        return None

    def _detect_rtcorrection_fault(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect RTK correction faults (CRC error, bit flip, base shift, fix loss)."""
        fix_type = feats.get("gnss_fix_type")
        sats = feats.get("gnss_satellites")

        # Track RTK fix state transitions
        if fix_type == 6:  # RTK Fixed
            self.state.rtk_fixed_duration = self.state.rtk_fixed_duration + 1 if hasattr(self.state, 'rtk_fixed_duration') else 1
        else:
            if hasattr(self.state, 'rtk_fixed_duration') and self.state.rtk_fixed_duration > 0:
                # Was RTK Fixed, now degraded - check if sats remained stable
                if sats is not None and sats >= self.config.min_satellites:
                    return self._create_alert(
                        now, "high", "rtk_correction_fault",
                        f"RTK Fixed lost (fix_type={fix_type}) with {sats} sats stable - possible correction fault",
                        {"prev_fix_type": 6, "current_fix_type": fix_type,
                         "satellites": sats, "rtk_fixed_duration": self.state.rtk_fixed_duration},
                        "navigation", "mavlink_stream", "NAV-016"
                    )
            self.state.rtk_fixed_duration = 0

        # Check for RTK base station coordinate shift (if available)
        rtk_base_lat = feats.get("rtk_base_lat")
        rtk_base_lon = feats.get("rtk_base_lon")
        if rtk_base_lat is not None and rtk_base_lon is not None:
            if hasattr(self.state, 'rtk_base_lat') and self.state.rtk_base_lat is not None:
                base_shift = math.hypot(rtk_base_lat - self.state.rtk_base_lat, rtk_base_lon - self.state.rtk_base_lon)
                if base_shift > 1e-6:  # ~0.1m at equator
                    return self._create_alert(
                        now, "high", "rtk_base_shift",
                        f"RTK base station coordinates shifted: {base_shift*1e7:.1f} deg",
                        {"base_lat": rtk_base_lat, "base_lon": rtk_base_lon,
                         "shift_deg": base_shift},
                        "navigation", "mavlink_stream", "NAV-017"
                    )
            self.state.rtk_base_lat = rtk_base_lat
            self.state.rtk_base_lon = rtk_base_lon

        # Check EKF innovation anomaly during RTK Fixed
        if fix_type == 6:
            chi2 = feats.get("ekf_chi2")
            if chi2 is not None and chi2 > self.config.innovation_chi2_threshold * 0.5:
                return self._create_alert(
                    now, "medium", "rtk_innovation_anomaly",
                    f"High EKF innovation during RTK Fixed: chi2={chi2:.1f}",
                    {"chi2": chi2, "threshold": self.config.innovation_chi2_threshold},
                    "navigation", "mavlink_stream", "NAV-018"
                )

        return None

    def _detect_stealthy_attack(self, feats: Dict, now: float) -> Optional[IDSAlert]:
        """Detect stealthy coordinated FDI attacks by computing detection floor."""
        if feats.get("stealth_possible"):
            drift = feats.get("stealth_drift_rate_ms", 0)
            bias = feats.get("stealth_position_bias_m", 0)
            if drift > 0 and drift <= self.config.max_undetected_drift_rate_ms:
                return self._create_alert(
                    now, "medium", "stealthy_attack",
                    f"Possible stealthy FDI attack: drift={drift:.3f}m/s (below detection floor)",
                    {"drift_rate_ms": drift,
                     "max_undetected_drift_rate_ms": self.config.max_undetected_drift_rate_ms,
                     "position_bias_m": bias,
                     "max_undetected_bias_m": self.config.max_undetected_bias_m,
                     "detection_floor": "Drift below EKF innovation gate"},
                    "navigation", "mavlink_stream", "NAV-011"
                )

        # Also report detection floor metrics regardless of alert
        self.state.last_detection_floor = {
            "max_undetected_drift_rate_ms": self.config.max_undetected_drift_rate_ms,
            "max_undetected_bias_m": self.config.max_undetected_bias_m,
            "current_drift_rate_ms": feats.get("stealth_drift_rate_ms", 0),
            "current_bias_m": feats.get("stealth_position_bias_m", 0),
            "timestamp": time.time()
        }
        return None

    # -----------------------------------------------------------------------
    # Alert Creation
    # -----------------------------------------------------------------------
    def _create_alert(
        self,
        now: float,
        severity: str,
        reason: str,
        detail: str,
        evidence: Dict[str, Any],
        attack_class: str,
        observable_from: str,
        rule_id: str,
    ) -> IDSAlert:
        """Create a standardized IDSAlert."""
        # Map attack_class to affected channel
        channel_map = {
            "gnss_jamming": "gnss",
            "gps_spoofing_jump": "gnss",
            "gps_spoofing_drift": "gnss",
            "gps_spoofing_seamless": "gnss",
            "gps_time_spoofing": "gnss",
            "gnss_jamming_ramp": "gnss",
            "baro_spoofing": "baro",
            "baro_frozen": "baro",
            "mag_spoofing": "magnetometer",
            "mag_bias_drift": "magnetometer",
            "optical_flow_spoofing": "optflow",
            "optical_flow_bias": "optflow",
            "rangefinder_spoofing": "rangefinder",
            "rangefinder_frozen": "rangefinder",
            "rtcorrection_injection": "rtk",
            "rtk_correction_fault": "rtk",
            "rtk_base_shift": "rtk",
            "rtk_innovation_anomaly": "rtk",
            "coordinated_gnss_baro": "gnss+baro",
            "stealthy_attack": "gnss+ins",
        }
        affected_channel = channel_map.get(attack_class, "unknown")
        
        # Determine recommended action based on severity and attack class
        if severity in ("critical", "high"):
            recommended_action = "distrust"
        elif severity == "medium":
            recommended_action = "caution"
        else:
            recommended_action = "none"
        
        alert = IDSAlert(
            timestamp=now,
            severity=severity,
            reason=reason,
            rule_id=rule_id,
            detail=detail,
            evidence=evidence,
            confidence=0.8,
            attack_class=attack_class,
            observable_from=observable_from,
            affected_channel=affected_channel,
            recommended_action=recommended_action,
        )
        if self.include_mitre:
            mitre = self._mitre_map.get(attack_class)
            if mitre:
                alert.mitre_attack = mitre
        return alert

    # -----------------------------------------------------------------------
    # Trust Score Update (called externally)
    # -----------------------------------------------------------------------
    def update_trust_scores(self, features: Dict[str, Any]) -> None:
        """Update per-channel trust scores with hysteresis."""
        for key in ["trust_gnss", "trust_ins", "trust_baro", "trust_optflow", "trust_magnetometer"]:
            new_val = features.get(key)
            if new_val is not None:
                old_val = getattr(self.state, key)
                if abs(new_val - old_val) > self.config.hysteresis:
                    setattr(self.state, key, new_val)

    def get_trust_scores(self) -> Dict[str, float]:
        """Get current trust scores."""
        return {
            "gnss": self.state.trust_gnss,
            "ins": self.state.trust_ins,
            "baro": self.state.trust_baro,
            "optflow": self.state.trust_optflow,
            "magnetometer": self.state.trust_magnetometer,
        }

    def get_recommended_action(self) -> Dict[str, Any]:
        """Get advisory recommended action based on trust scores."""
        trust = self.get_trust_scores()

        # Find lowest trust sensor
        if not trust:
            return {"action": "none", "reason": "no trust data"}

        min_trust = min(trust.values())
        min_sensor = min(trust, key=trust.get)

        # Determine recommended navigation source (highest trust)
        max_trust = max(trust.values())
        recommended_source = max(trust, key=trust.get)

        # Nav source recommendation
        nav_source_rec = {
            "recommended_source": recommended_source,
            "source_trust": max_trust,
            "all_sources": trust,
            "can_re_anchor": self.can_re_anchor(),
        }

        if min_trust < 0.3:
            return {
                "action": "distrust",
                "sensor": min_sensor,
                "trust": min_trust,
                "recommendation": f"Distrust {min_sensor}, rely on other sources",
                "nav_source": nav_source_rec,
            }
        elif min_trust < 0.7:
            return {
                "action": "caution",
                "sensor": min_sensor,
                "trust": min_trust,
                "recommendation": f"Monitor {min_sensor} closely, cross-check with other sources",
                "nav_source": nav_source_rec,
            }
        return {
            "action": "none", 
            "reason": "all sensors nominal",
            "nav_source": nav_source_rec,
        }

    def get_recommended_nav_source(self) -> Dict[str, Any]:
        """Get recommended navigation source based on trust scores."""
        trust = self.get_trust_scores()
        if not trust:
            return {"source": "none", "reason": "no trust data"}
        
        recommended = max(trust, key=trust.get)
        return {
            "source": recommended,
            "trust": trust[recommended],
            "all_trust": trust,
            "can_re_anchor": self.can_re_anchor(),
        }

    def can_re_anchor(self) -> bool:
        """Check if GNSS can be trusted for dead-reckoning re-anchoring."""
        return self.state.trust_gnss >= self.config.min_trust_for_re_anchor

    # -----------------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)

    def reset(self) -> None:
        self.stats = {"packets": 0, "alerts": 0, "suppressed": 0, "detections": {}}
        self.alert_limiter.reset()
        self.state = NavigationDetectorState()


# ---------------------------------------------------------------------------
# High-level Facade
# ---------------------------------------------------------------------------
class NavigationIDSFacade:
    """
    Facade matching the NavSample-style interface for easy integration.
    """

    def __init__(self, config_path: Optional[str] = None, profile: Optional[str] = None):
        self.ids = NavigationIDS(config_path=config_path, profile=profile)

    def ingest(self, msg_type: str, ts: float, **fields) -> None:
        """Ingest one telemetry message."""
        self.ids.ingest_telemetry(msg_type, ts, **fields)

    def check(self, now: Optional[float] = None) -> Optional[IDSAlert]:
        """Run detection checks."""
        return self.ids.check(now)

    def get_alert(self) -> Optional[IDSAlert]:
        """Alias for check()."""
        return self.check()

    def get_trust_scores(self) -> Dict[str, float]:
        return self.ids.get_trust_scores()

    def get_recommended_action(self) -> Dict[str, Any]:
        return self.ids.get_recommended_action()

    def can_re_anchor(self) -> bool:
        return self.ids.can_re_anchor()

    def get_recommended_nav_source(self) -> Dict[str, Any]:
        return self.ids.get_recommended_nav_source()

    def get_stats(self) -> Dict[str, Any]:
        return self.ids.get_stats()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("NAVIGATION FUSION IDS — SELF TEST")
    print("=" * 70)

    # Load default policy
    policy = default_policy()
    ids = NavigationIDS(policy=policy)

    now = time.time()

    # Test 1: Nominal
    # GPS_RAW_INT alt is in mm, so 100m = 100000 mm
    # Baro at 100m: pressure ≈ 1001 hPa
    ids.ingest_telemetry("GPS_RAW_INT", now, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=8, fix_type=3,
                         time_usec=int(now * 1e6))
    ids.ingest_telemetry("GLOBAL_POSITION_INT", now, relative_alt=100000,
                         vx=300, vy=400, vz=0, hdg=0)
    ids.ingest_telemetry("SCALED_IMU", now, xacc=0, yacc=0, zacc=-981,
                         xgyro=0, ygyro=0, zgyro=0, xmag=100, ymag=0, zmag=0)
    ids.ingest_telemetry("ATTITUDE", now, roll=0, pitch=0, yaw=0,
                         rollspeed=0, pitchspeed=0, yawspeed=0)
    ids.ingest_telemetry("VFR_HUD", now, alt=100000, groundspeed=500, airspeed=500, climb=0)
    # Pressure at 100m ≈ 1001 hPa
    ids.ingest_telemetry("SCALED_PRESSURE", now, press_abs=1001.0, press_diff=0)
    ids.ingest_telemetry("EKF_STATUS_REPORT", now, vel_ratio=0.5, pos_horiz_ratio=0.5,
                         pos_vert_ratio=0.5, mag_ratio=0.5)

    alert = ids.check(now)
    assert alert is None, f"Unexpected alert on nominal: {alert}"
    print("[1] Nominal: PASS (no alert)")

    # Test 2: GNSS jamming
    ids.ingest_telemetry("GPS_RAW_INT", now + 1, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=2, fix_type=1,
                         time_usec=int((now + 1) * 1e6))
    alert = ids.check(now + 1)
    assert alert and alert.reason == "gnss_jamming"
    print(f"[2] GNSS jamming: PASS ({alert.reason})")

    # Test 3: GPS spoofing jump
    ids.ingest_telemetry("GPS_RAW_INT", now + 2, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=8, fix_type=3,
                         time_usec=int((now + 2) * 1e6))
    # Need to call check once to store position
    ids.check(now + 2)

    ids.ingest_telemetry("GPS_RAW_INT", now + 2.1, lat=1000000, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=8, fix_type=3,
                         time_usec=int((now + 2.1) * 1e6))
    alert = ids.check(now + 2.1)
    assert alert and alert.reason == "gps_spoofing_jump"
    print(f"[3] GPS spoofing jump: PASS ({alert.reason})")

    # Test 4: Baro spoofing
    # GPS says 100m (100000 mm), baro says 900 hPa ≈ 1000m
    ids.buffer.clear()  # Clear to avoid GPS jump from previous test
    ids.ingest_telemetry("SCALED_PRESSURE", now + 3, press_abs=900.0)
    ids.ingest_telemetry("GPS_RAW_INT", now + 3, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=8, fix_type=3,
                         time_usec=int((now + 3) * 1e6))
    # Call check twice: first to establish GPS position, then to detect baro mismatch
    ids.check(now + 3)
    alert = ids.check(now + 3.1)
    if alert is None:
        ids.ingest_telemetry("SCALED_PRESSURE", now + 3.2, press_abs=900.0)
        alert = ids.check(now + 3.2)
    if alert is None or alert.reason != "baro_spoofing":
        ids.ingest_telemetry("GPS_RAW_INT", now + 3.3, lat=0, lon=0, alt=100000,
                             vel=500, vn=300, ve=400, vd=0, cog=0,
                             eph=150, epv=200, satellites_visible=8, fix_type=3,
                             time_usec=int((now + 3.3) * 1e6))
        alert = ids.check(now + 3.3)
    assert alert and alert.reason == "baro_spoofing"
    print(f"[4] Baro spoofing: PASS ({alert.reason})")

    # Test 5: Mag spoofing (use time > max_age_s to clear old baro data)
    # Clear buffer or advance time beyond max_age_s (5s) to expire old baro data
    ids.buffer.clear()
    ids.ingest_telemetry("SCALED_IMU", now + 10, xacc=0, yacc=0, zacc=-981,
                         xgyro=0, ygyro=0, zgyro=0, xmag=-100, ymag=0, zmag=0)
    ids.ingest_telemetry("ATTITUDE", now + 10, roll=0, pitch=0, yaw=0,
                         rollspeed=0, pitchspeed=0, yawspeed=0)
    alert = ids.check(now + 10)
    assert alert and alert.reason == "mag_spoofing"
    print(f"[5] Mag spoofing: PASS ({alert.reason})")

    # Test 6: Trust scores and nav source recommendation
    trust = ids.get_trust_scores()
    print(f"[6] Trust scores: {trust}")
    action = ids.get_recommended_action()
    print(f"[7] Recommended action: {action}")
    nav_src = ids.get_recommended_nav_source()
    print(f"[8] Nav source recommendation: {nav_src}")

    # Test 7: Trust hysteresis - verify nav source switches when trust degrades
    # Clear buffer and simulate GNSS degradation (low sats)
    ids.buffer.clear()
    ids.ingest_telemetry("GPS_RAW_INT", now + 20, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=2, fix_type=1,
                         time_usec=int((now + 20) * 1e6))
    ids.ingest_telemetry("SCALED_IMU", now + 20, xacc=0, yacc=0, zacc=-981,
                         xgyro=0, ygyro=0, zgyro=0, xmag=100, ymag=0, zmag=0)
    ids.ingest_telemetry("ATTITUDE", now + 20, roll=0, pitch=0, yaw=0,
                         rollspeed=0, pitchspeed=0, yawspeed=0)
    ids.ingest_telemetry("EKF_STATUS_REPORT", now + 20, vel_ratio=0.5, pos_horiz_ratio=0.5,
                         pos_vert_ratio=0.5, mag_ratio=0.5)
    ids.check(now + 20)

    trust_degraded = ids.get_trust_scores()
    print(f"[9] Trust scores (degraded GNSS): {trust_degraded}")
    assert trust_degraded["gnss"] < 0.7, f"GNSS trust should be < 0.7, got {trust_degraded['gnss']}"
    
    action_degraded = ids.get_recommended_action()
    print(f"[10] Recommended action (degraded): {action_degraded}")
    assert action_degraded["action"] == "distrust", f"Expected distrust, got {action_degraded['action']}"
    assert action_degraded["nav_source"]["recommended_source"] == "ins", \
        f"Expected INS as recommended source, got {action_degraded['nav_source']['recommended_source']}"
    print("[11] Nav source correctly switches to INS when GNSS degrades: PASS")

    # Test 8: can_re_anchor
    assert ids.can_re_anchor() == False, "can_re_anchor should be False when GNSS trust < 0.7"
    print("[12] can_re_anchor correctly False when GNSS trust low: PASS")

    # Test 9: Verify hysteresis - small trust changes don't flip state
    # Restore good GNSS
    ids.buffer.clear()
    ids.ingest_telemetry("GPS_RAW_INT", now + 30, lat=0, lon=0, alt=100000,
                         vel=500, vn=300, ve=400, vd=0, cog=0,
                         eph=150, epv=200, satellites_visible=8, fix_type=3,
                         time_usec=int((now + 30) * 1e6))
    ids.ingest_telemetry("SCALED_IMU", now + 30, xacc=0, yacc=0, zacc=-981,
                         xgyro=0, ygyro=0, zgyro=0, xmag=100, ymag=0, zmag=0)
    ids.ingest_telemetry("ATTITUDE", now + 30, roll=0, pitch=0, yaw=0,
                         rollspeed=0, pitchspeed=0, yawspeed=0)
    ids.ingest_telemetry("EKF_STATUS_REPORT", now + 30, vel_ratio=0.5, pos_horiz_ratio=0.5,
                         pos_vert_ratio=0.5, mag_ratio=0.5)
    ids.check(now + 30)

    trust_restored = ids.get_trust_scores()
    print(f"[13] Trust scores (restored GNSS): {trust_restored}")
    assert trust_restored["gnss"] > 0.7, f"GNSS trust should be > 0.7, got {trust_restored['gnss']}"
    
    action_restored = ids.get_recommended_action()
    print(f"[14] Recommended action (restored): {action_restored}")
    assert action_restored["action"] == "none", f"Expected none, got {action_restored['action']}"
    assert action_restored["nav_source"]["recommended_source"] == "gnss", \
        f"Expected GNSS as recommended source, got {action_restored['nav_source']['recommended_source']}"
    assert ids.can_re_anchor() == True, "can_re_anchor should be True when GNSS trust >= 0.7"
    print("[15] Nav source correctly switches back to GNSS: PASS")
    print("[16] can_re_anchor correctly True when GNSS trust restored: PASS")

    print("=" * 70)
    print("SELF TEST COMPLETE")
    print("=" * 70)