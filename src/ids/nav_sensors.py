"""
nav_sensors.py
Navigation Sensor Telemetry Ingestion and Feature Extraction

Consumes MAVLink telemetry and extracts GNSS quality, INS/GNSS consistency,
dead reckoning uncertainty, multi-source attribution weights, and sensor
cross-check features for navigation attack detection.
"""

from __future__ import annotations

import collections
import math
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .ids_config import load_config, default_policy
from .command_injection_detector import IDSAlert


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class NavigationConfig:
    """Configuration holder for navigation detector."""
    policy: Dict[str, Any]

    def __post_init__(self):
        nav = self.policy.get("navigation", {})
        self.enabled = nav.get("enabled", True)

        # GNSS quality
        gnss = nav.get("gnss_quality", {})
        self.gnss_enabled = gnss.get("enabled", True)
        self.min_satellites = gnss.get("min_satellites", 5)
        self.max_hdop = gnss.get("max_hdop", 3.0)
        self.max_epv = gnss.get("max_epv", 5.0)
        self.snr_spread_threshold_db = gnss.get("snr_spread_threshold_db", 15.0)
        self.snr_change_rate_db_s = gnss.get("snr_change_rate_db_s", 10.0)
        self.fix_type_change_alert = gnss.get("fix_type_change_alert", True)
        self.position_jump_threshold_m = gnss.get("position_jump_threshold_m", 10.0)
        self.velocity_jump_threshold_ms = gnss.get("velocity_jump_threshold_ms", 5.0)
        self.clock_jump_threshold_s = gnss.get("clock_jump_threshold_s", 1.0)
        self.spoof_flag_weight = gnss.get("spoof_flag_weight", 1.0)
        self.jam_flag_weight = gnss.get("jam_flag_weight", 1.0)

        # INS/GNSS consistency
        ins = nav.get("ins_gnss_consistency", {})
        self.ins_enabled = ins.get("enabled", True)
        self.innovation_chi2_threshold = ins.get("innovation_chi2_threshold", 100.0)
        self.cusum_threshold = ins.get("cusum_threshold", 5.0)
        self.cusum_window = ins.get("cusum_window", 50)
        self.widen_during_maneuver = ins.get("widen_during_maneuver", True)
        self.yaw_rate_threshold_deg_s = ins.get("yaw_rate_threshold_deg_s", 30.0)
        self.accel_threshold_ms2 = ins.get("accel_threshold_ms2", 3.0)
        self.drift_allowance = ins.get("drift_allowance", 0.5)

        # Dead reckoning
        dr = nav.get("dead_reckoning", {})
        self.dr_enabled = dr.get("enabled", True)
        self.max_uncertainty_m = dr.get("max_uncertainty_m", 50.0)
        self.uncertainty_growth_ms = dr.get("uncertainty_growth_ms", 0.5)
        self.re_anchor_trust_threshold = dr.get("re_anchor_trust_threshold", 0.7)

        # Multi-source attribution
        ms = nav.get("multi_source_attribution", {})
        self.ms_enabled = ms.get("enabled", True)
        self.min_sources_for_attribution = ms.get("min_sources_for_attribution", 3)
        self.source_weights = ms.get("source_weights", {
            "gnss": 1.0, "ins": 0.9, "baro": 0.8,
            "optflow": 0.7, "magnetometer": 0.7, "wind_airspeed": 0.6
        })

        # Sensor cross-checks
        sc = nav.get("sensor_cross_checks", {})
        self.sc_enabled = sc.get("enabled", True)
        mag = sc.get("mag_vs_gyro_heading", {})
        self.mag_heading_enabled = mag.get("enabled", True)
        self.max_yaw_diff_deg = mag.get("max_yaw_diff_deg", 30.0)
        self.min_gps_speed_ms = mag.get("min_gps_speed_ms", 2.0)
        baro = sc.get("baro_vs_gnss_alt", {})
        self.baro_alt_enabled = baro.get("enabled", True)
        self.max_baro_diff_m = baro.get("max_diff_m", 10.0)
        self.weather_drift_allowance_m = baro.get("weather_drift_allowance_m", 2.0)
        opt = sc.get("optflow_vs_gnss_vel", {})
        self.optflow_vel_enabled = opt.get("enabled", True)
        self.max_vel_diff_ms = opt.get("max_vel_diff_ms", 1.0)
        self.wind_allowance_ms = opt.get("wind_allowance_ms", 2.0)
        self.min_quality = opt.get("min_quality", 50)

        # Stealthy analysis
        stealth = nav.get("stealthy_analysis", {})
        self.stealth_enabled = stealth.get("enabled", True)
        df = stealth.get("detection_floor", {})
        self.max_undetected_drift_rate_ms = df.get("max_undetected_drift_rate_ms", 0.1)
        self.max_undetected_bias_m = df.get("max_undetected_bias_m", 5.0)

        # Trust
        trust = nav.get("trust", {})
        self.trust_enabled = trust.get("enabled", True)
        self.hysteresis = trust.get("hysteresis", 0.1)
        self.initial_trust = trust.get("initial_trust", 1.0)
        self.min_trust_for_re_anchor = trust.get("min_trust_for_re_anchor", 0.7)


# ---------------------------------------------------------------------------
# Time-aligned Telemetry Buffer
# ---------------------------------------------------------------------------
class NavTelemetryBuffer:
    """
    Bounded, time-aligned buffer for navigation-relevant MAVLink messages.
    Handles jitter, loss, reordering, and missing fields.
    """

    def __init__(self, max_age_s: float = 5.0, history_size: int = 200):
        self.max_age_s = max_age_s
        self.history_size = history_size
        self._data: Dict[str, Tuple[Any, float]] = {}  # feature -> (value, ts)
        self._history: Dict[str, Deque[Tuple[Any, float]]] = {}
        self._msg_timestamps: Dict[str, float] = {}

    def ingest(self, msg_type: str, ts: float, **fields) -> None:
        """Ingest a MAVLink message, extracting navigation-relevant fields."""
        if not fields:
            return

        # Message-type-specific field mappings
        if msg_type == "GPS_RAW_INT":
            mapping = {
                "lat": "gps_lat",
                "lon": "gps_lon",
                "alt": "gps_alt",
                "vel": "gps_vel",
                "vn": "gps_vn",
                "ve": "gps_ve",
                "vd": "gps_vd",
                "cog": "gps_cog",
                "eph": "gps_eph",
                "epv": "gps_epv",
                "satellites_visible": "gps_sats",
                "fix_type": "gps_fix_type",
                "time_usec": "gps_time_usec",
                # Also accept internal field names (with gps_ prefix) for compatibility
                "gps_lat": "gps_lat",
                "gps_lon": "gps_lon",
                "gps_alt": "gps_alt",
                "gps_vel": "gps_vel",
                "gps_vn": "gps_vn",
                "gps_ve": "gps_ve",
                "gps_vd": "gps_vd",
                "gps_cog": "gps_cog",
                "gps_eph": "gps_eph",
                "gps_epv": "gps_epv",
                "gps_satellites_visible": "gps_sats",
                "gps_fix": "gps_fix_type",
                "gps_time_usec": "gps_time_usec",
            }
        elif msg_type == "GLOBAL_POSITION_INT":
            mapping = {
                "relative_alt": "rel_alt",
                "vx": "vel_n",
                "vy": "vel_e",
                "vz": "vel_d",
                "hdg": "hdg",
            }
        elif msg_type in ("SCALED_IMU", "HIGHRES_IMU"):
            mapping = {
                "xacc": "imu_xacc",
                "yacc": "imu_yacc",
                "zacc": "imu_zacc",
                "xgyro": "imu_xgyro",
                "ygyro": "imu_ygyro",
                "zgyro": "imu_zgyro",
                "xmag": "imu_xmag",
                "ymag": "imu_ymag",
                "zmag": "imu_zmag",
            }
        elif msg_type == "ATTITUDE":
            mapping = {
                "roll": "att_roll",
                "pitch": "att_pitch",
                "yaw": "att_yaw",
                "rollspeed": "att_rollspeed",
                "pitchspeed": "att_pitchspeed",
                "yawspeed": "att_yawspeed",
            }
        elif msg_type == "VFR_HUD":
            mapping = {
                "alt": "vfr_alt",
                "groundspeed": "vfr_groundspeed",
                "airspeed": "vfr_airspeed",
                "climb": "vfr_climb",
            }
        elif msg_type == "SCALED_PRESSURE":
            mapping = {
                "press_abs": "baro_press",
                "press_diff": "baro_press_diff",
            }
        elif msg_type in ("OPTICAL_FLOW", "OPTICAL_FLOW_RAD"):
            mapping = {
                "flow_x": "optflow_x",
                "flow_y": "optflow_y",
                "flow_comp_m_x": "optflow_comp_x",
                "flow_comp_m_y": "optflow_comp_y",
                "quality": "optflow_quality",
                "ground_distance": "optflow_ground_dist",
            }
        elif msg_type == "DISTANCE_SENSOR":
            mapping = {
                "current_distance": "dist_sensor",
            }
        elif msg_type == "EKF_STATUS_REPORT":
            mapping = {
                "vel_ratio": "ekf_vel_ratio",
                "pos_horiz_ratio": "ekf_pos_horiz_ratio",
                "pos_vert_ratio": "ekf_pos_vert_ratio",
                "mag_ratio": "ekf_mag_ratio",
                "hagl_ratio": "ekf_hagl_ratio",
                "tas_ratio": "ekf_tas_ratio",
                "flags": "ekf_flags",
            }
        elif msg_type == "WIND":
            mapping = {
                "wind_speed": "wind_speed",
                "wind_dir": "wind_dir",
            }
        elif msg_type == "GPS2_RAW":
            mapping = {
                "lat": "gps2_lat",
                "lon": "gps2_lon",
                "alt": "gps2_alt",
                "vel": "gps2_vel",
                "vn": "gps2_vn",
                "ve": "gps2_ve",
                "vd": "gps2_vd",
                "cog": "gps2_cog",
                "eph": "gps2_eph",
                "epv": "gps2_epv",
                "satellites_visible": "gps2_sats",
                "fix_type": "gps2_fix_type",
                "time_usec": "gps2_time_usec",
                "sats_cn0": "gnss_sats_cn0",  # Per-satellite CN0 array
            }
        elif msg_type == "GPS_RTCM_DATA":
            mapping = {
                "flags": "rtcm_flags",
                "len": "rtcm_len",
                "data": "rtcm_data",
            }
        else:
            mapping = {}

        for k, v in fields.items():
            if k in mapping and v is not None:
                fname = mapping[k]
                self._data[fname] = (v, ts)
                if fname not in self._history:
                    self._history[fname] = collections.deque(maxlen=self.history_size)
                self._history[fname].append((v, ts))

        self._msg_timestamps[msg_type] = ts

    def get(self, feature: str, default: Any = None, now: float = 0.0) -> Any:
        """Get latest value of a feature, or default if missing/stale."""
        ent = self._data.get(feature)
        if ent is None:
            return default
        val, ts = ent
        if now and now - ts > self.max_age_s:
            return default
        return val

    def get_history(self, feature: str, count: Optional[int] = None) -> List[Tuple[Any, float]]:
        """Get historical values for a feature."""
        if feature not in self._history:
            return []
        hist = list(self._history[feature])
        if count is not None:
            return hist[-count:]
        return hist

    def fresh(self, feature: str, now: float) -> bool:
        """Check if feature is fresh."""
        ent = self._data.get(feature)
        return ent is not None and now - ent[1] <= self.max_age_s

    def clear(self) -> None:
        self._data.clear()
        self._history.clear()
        self._msg_timestamps.clear()


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------
class NavFeatureExtractor:
    """
    Extracts navigation attack detection features from the telemetry buffer.
    """

    def __init__(self, config: NavigationConfig, buffer: NavTelemetryBuffer):
        self.config = config
        self.buffer = buffer
        self._prev_gps_pos: Optional[Tuple[float, float, float]] = None
        self._prev_gps_vel: Optional[Tuple[float, float, float]] = None
        self._prev_gps_time: Optional[float] = None
        self._prev_imu_vel: Optional[Tuple[float, float, float]] = None

    def extract_all(self, now: float) -> Dict[str, Any]:
        """Extract all navigation features at current time."""
        features = {}

        # GNSS quality features
        if self.config.gnss_enabled:
            features.update(self._extract_gnss_quality(now))

        # INS/GNSS consistency
        if self.config.ins_enabled:
            features.update(self._extract_ins_gnss_consistency(now))

        # Dead reckoning uncertainty
        if self.config.dr_enabled:
            features.update(self._extract_dead_reckoning(now))

        # Multi-source attribution weights
        if self.config.ms_enabled:
            features.update(self._extract_source_weights(now))

        # Sensor cross-checks
        if self.config.sc_enabled:
            features.update(self._extract_sensor_cross_checks(now))

        # Stealthy analysis
        if self.config.stealth_enabled:
            features.update(self._extract_stealth_features(now))

        # Trust scores
        if self.config.trust_enabled:
            features.update(self._extract_trust_scores(now))

        return features

    def _extract_gnss_quality(self, now: float) -> Dict[str, Any]:
        """Extract GNSS signal quality features."""
        feats = {}

        sats = self.buffer.get("gps_sats", now=now)
        feats["gnss_satellites"] = sats
        feats["gnss_satellites_ok"] = (sats is not None and sats >= self.config.min_satellites)

        fix_type = self.buffer.get("gps_fix_type", now=now)
        feats["gnss_fix_type"] = fix_type
        feats["gnss_fix_ok"] = (fix_type is not None and fix_type >= 3)

        eph = self.buffer.get("gps_eph", now=now)
        feats["gnss_eph"] = eph
        feats["gnss_eph_ok"] = (eph is not None and eph <= self.config.max_hdop * 100)  # eph in cm

        epv = self.buffer.get("gps_epv", now=now)
        feats["gnss_epv"] = epv
        feats["gnss_epv_ok"] = (epv is not None and epv <= self.config.max_epv * 100)

        # SNR spread and change rate (proxy features since GPS_RAW_INT lacks per-sat SNR)
        # Use eph/epv and satellite count as proxies for signal quality
        # Higher eph/epv and dropping sats = effective SNR degradation
        sats = feats.get("gnss_satellites")
        eph = feats.get("gnss_eph")
        epv = feats.get("gnss_epv")

        # SNR spread proxy: based on satellite geometry dilution (PDOP proxy from eph/epv)
        # and satellite count. Fewer satellites with high DOP = larger SNR spread.
        if sats is not None and sats > 0:
            # Empirical model: SNR spread increases as sats decrease and DOP increases
            # Good: 8+ sats, eph<150cm -> spread ~2-3 dB
            # Poor: 4 sats, eph>300cm -> spread ~10-15 dB
            eph_factor = 1.0
            if eph is not None:
                eph_factor = max(1.0, eph / 150.0)  # Normalized to 150cm baseline
            sat_factor = max(1.0, 8.0 / max(sats, 1))
            # Spread in dB: ~2 * log10(sat_factor * eph_factor)
            snr_spread_proxy = max(0.0, 2.0 * math.log10(sat_factor * eph_factor) * 10.0)
            feats["gnss_snr_spread_db"] = snr_spread_proxy
        else:
            feats["gnss_snr_spread_db"] = None

        # SNR change rate: true rate of change using history
        # Track eph/epv history to compute d/dt
        if eph is not None and epv is not None:
            # Get recent history (last 10 samples over ~5 seconds)
            eph_hist = self.buffer.get_history("gps_eph", count=10)
            epv_hist = self.buffer.get_history("gps_epv", count=10)
            
            if len(eph_hist) >= 3 and len(epv_hist) >= 3:
                # Compute rate of change (cm/s) using linear regression on recent samples
                eph_vals = [v for v, _ in eph_hist]
                epv_vals = [v for v, _ in epv_hist]
                eph_times = [t for _, t in eph_hist]
                epv_times = [t for _, t in epv_hist]
                
                # Simple rate: (last - first) / time_delta
                eph_dt = eph_times[-1] - eph_times[0]
                epv_dt = epv_times[-1] - epv_times[0]
                
                if eph_dt > 0.5 and epv_dt > 0.5:  # Need at least 0.5s of data
                    eph_rate = (eph_vals[-1] - eph_vals[0]) / eph_dt  # cm/s
                    epv_rate = (epv_vals[-1] - epv_vals[0]) / epv_dt  # cm/s
                    
                    # Convert to dB/s proxy: rate relative to baseline
                    # eph/epv degradation rate of 100 cm/s ≈ 5 dB/s
                    eph_rate_db = max(0.0, abs(eph_rate) / 100.0 * 5.0)
                    epv_rate_db = max(0.0, abs(epv_rate) / 150.0 * 5.0)
                    feats["gnss_snr_change_rate_db_s"] = max(eph_rate_db, epv_rate_db)
                else:
                    feats["gnss_snr_change_rate_db_s"] = None
            else:
                # Not enough history yet - use static proxy
                baseline_eph = 100.0  # cm, typical good value
                baseline_epv = 150.0  # cm, typical good value
                eph_degradation = max(0.0, (eph - baseline_eph) / baseline_eph) * 5.0  # dB scale
                epv_degradation = max(0.0, (epv - baseline_epv) / baseline_epv) * 5.0
                feats["gnss_snr_change_rate_db_s"] = max(eph_degradation, epv_degradation)
        else:
            feats["gnss_snr_change_rate_db_s"] = None

        # Also check for GPS_RTCM_DATA or GPS2_RAW which may have per-sat CN0
        # This would be populated if those message types are ingested
        gnss_snr_mean = self.buffer.get("gnss_snr_mean_db", now=now)
        gnss_snr_std = self.buffer.get("gnss_snr_std_db", now=now)
        if gnss_snr_mean is not None:
            feats["gnss_snr_mean_db"] = gnss_snr_mean
        if gnss_snr_std is not None:
            feats["gnss_snr_spread_db"] = gnss_snr_std  # Override proxy with real data

        # Process per-satellite CN0 from GPS2_RAW if available
        sats_cn0 = self.buffer.get("gnss_sats_cn0", now=now)
        if sats_cn0 is not None and isinstance(sats_cn0, (list, tuple)) and len(sats_cn0) > 0:
            # Filter valid CN0 values (typically 0-60 dB-Hz)
            valid_cn0 = [c for c in sats_cn0 if isinstance(c, (int, float)) and 0 < c < 60]
            if len(valid_cn0) >= 3:
                mean_cn0 = sum(valid_cn0) / len(valid_cn0)
                # Population std dev
                variance = sum((c - mean_cn0) ** 2 for c in valid_cn0) / len(valid_cn0)
                std_cn0 = math.sqrt(variance)
                feats["gnss_snr_mean_db"] = mean_cn0
                feats["gnss_snr_spread_db"] = std_cn0  # Real spread from CN0
                feats["gnss_snr_sat_count"] = len(valid_cn0)
                feats["gnss_snr_min_db"] = min(valid_cn0)
                feats["gnss_snr_max_db"] = max(valid_cn0)

        # Position jump detection
        lat = self.buffer.get("gps_lat", now=now)
        lon = self.buffer.get("gps_lon", now=now)
        alt_mm = self.buffer.get("gps_alt", now=now)
        if None not in (lat, lon, alt_mm):
            cur_pos = (lat, lon, alt_mm / 1000.0)  # Convert mm to meters
            if self._prev_gps_pos is not None:
                dist = self._haversine(self._prev_gps_pos, cur_pos)
                feats["gnss_position_jump_m"] = dist
                feats["gnss_position_jump_ok"] = dist <= self.config.position_jump_threshold_m
            self._prev_gps_pos = cur_pos

        # Velocity jump detection
        vn = self.buffer.get("gps_vn", now=now)
        ve = self.buffer.get("gps_ve", now=now)
        vd = self.buffer.get("gps_vd", now=now)
        if None not in (vn, ve, vd):
            cur_vel = (vn, ve, vd)
            if self._prev_gps_vel is not None:
                dv = math.sqrt(sum((a - b)**2 for a, b in zip(cur_vel, self._prev_gps_vel)))
                feats["gnss_velocity_jump_ms"] = dv / 100.0  # cm/s to m/s
                feats["gnss_velocity_jump_ok"] = (dv / 100.0) <= self.config.velocity_jump_threshold_ms
            self._prev_gps_vel = cur_vel

        # Clock jump detection
        gps_time = self.buffer.get("gps_time_usec", now=now)
        if gps_time is not None and self._prev_gps_time is not None:
            dt = abs(gps_time - self._prev_gps_time) / 1e6
            feats["gnss_clock_jump_s"] = dt
            feats["gnss_clock_jump_ok"] = dt <= self.config.clock_jump_threshold_s
        self._prev_gps_time = gps_time

        # Fix type change
        if fix_type is not None:
            feats["gnss_fix_type_changed"] = False  # Would need previous state

        return feats

    def _extract_ins_gnss_consistency(self, now: float) -> Dict[str, Any]:
        """Extract INS/GNSS consistency features (innovation, CUSUM)."""
        feats = {}

        # EKF innovation ratios from EKF_STATUS_REPORT
        vel_ratio = self.buffer.get("ekf_vel_ratio", now=now)
        pos_horiz_ratio = self.buffer.get("ekf_pos_horiz_ratio", now=now)
        pos_vert_ratio = self.buffer.get("ekf_pos_vert_ratio", now=now)
        mag_ratio = self.buffer.get("ekf_mag_ratio", now=now)

        # Normalized Innovation Squared (NIS) approximation
        # Ratios > 1 indicate innovation exceeds expected noise
        nis_vel = vel_ratio ** 2 if vel_ratio is not None else None
        nis_pos_horiz = pos_horiz_ratio ** 2 if pos_horiz_ratio is not None else None
        nis_pos_vert = pos_vert_ratio ** 2 if pos_vert_ratio is not None else None
        nis_mag = mag_ratio ** 2 if mag_ratio is not None else None

        feats["ekf_nis_vel"] = nis_vel
        feats["ekf_nis_pos_horiz"] = nis_pos_horiz
        feats["ekf_nis_pos_vert"] = nis_pos_vert
        feats["ekf_nis_mag"] = nis_mag

        # Chi-square test (sum of NIS)
        nis_values = [v for v in [nis_vel, nis_pos_horiz, nis_pos_vert, nis_mag] if v is not None]
        if nis_values:
            chi2 = sum(nis_values)
            feats["ekf_chi2"] = chi2
            feats["ekf_chi2_ok"] = chi2 <= self.config.innovation_chi2_threshold
        else:
            feats["ekf_chi2"] = None
            feats["ekf_chi2_ok"] = None

        # CUSUM on position horizontal innovation
        if pos_horiz_ratio is not None:
            # Maintain CUSUM state externally or compute here
            # For now, just report current value
            feats["ekf_cusum_pos_horiz"] = pos_horiz_ratio

        # Widen thresholds during high maneuver
        if self.config.widen_during_maneuver:
            yaw_rate = self.buffer.get("att_yawspeed", now=now)
            accel_x = self.buffer.get("imu_xacc", now=now)
            accel_y = self.buffer.get("imu_yacc", now=now)
            accel_z = self.buffer.get("imu_zacc", now=now)

            high_yaw = abs(yaw_rate) > math.radians(self.config.yaw_rate_threshold_deg_s) if yaw_rate else False
            high_accel = False
            if None not in (accel_x, accel_y, accel_z):
                accel_mag = math.sqrt(accel_x**2 + accel_y**2 + accel_z**2)
                high_accel = accel_mag > self.config.accel_threshold_ms2

            feats["ekf_maneuver_active"] = high_yaw or high_accel

        return feats

    def _extract_dead_reckoning(self, now: float) -> Dict[str, Any]:
        """Track dead reckoning uncertainty growth."""
        feats = {}

        # Simple uncertainty model: grows with time since last GNSS update
        gps_fresh = self.buffer.fresh("gps_lat", now) and self.buffer.fresh("gps_lon", now)
        last_gps_ts = self.buffer._data.get("gps_lat", (None, 0))[1] if "gps_lat" in self.buffer._data else 0

        if gps_fresh:
            uncertainty = 0.0
        else:
            dt = now - last_gps_ts if last_gps_ts else 0
            uncertainty = dt * self.config.uncertainty_growth_ms

        feats["dr_uncertainty_m"] = uncertainty
        feats["dr_uncertainty_ok"] = uncertainty <= self.config.max_uncertainty_m
        feats["dr_can_re_anchor"] = uncertainty > 0  # Can re-anchor when GNSS returns

        return feats

    def _extract_source_weights(self, now: float) -> Dict[str, Any]:
        """Extract current source reliability weights."""
        feats = {}

        # Base weights from config
        weights = dict(self.config.source_weights)

        # Adjust based on current signal quality
        if not self.buffer.fresh("gps_lat", now):
            weights["gnss"] *= 0.1

        # Optical flow only valid at low altitude
        alt = self.buffer.get("rel_alt", now=now) or self.buffer.get("gps_alt", now=now)
        if alt is not None and alt > 50:  # meters
            weights["optflow"] *= 0.3

        # Magnetometer only valid with good GPS speed
        gps_speed = math.sqrt(
            (self.buffer.get("gps_vn", 0) or 0)**2 +
            (self.buffer.get("gps_ve", 0) or 0)**2
        ) / 100.0
        if gps_speed < self.config.min_gps_speed_ms:
            weights["magnetometer"] *= 0.3

        # Normalize
        total = sum(weights.values())
        if total > 0:
            weights = {k: v/total for k, v in weights.items()}

        feats["source_weights"] = weights
        feats["attribution_possible"] = sum(1 for v in weights.values() if v > 0.1) >= self.config.min_sources_for_attribution

        return feats

    def _extract_sensor_cross_checks(self, now: float) -> Dict[str, Any]:
        """Extract sensor-level cross-check features."""
        feats = {}

        # Mag vs gyro heading
        if self.config.mag_heading_enabled:
            xmag = self.buffer.get("imu_xmag", now=now)
            ymag = self.buffer.get("imu_ymag", now=now)
            att_yaw = self.buffer.get("att_yaw", now=now)

            if None not in (xmag, ymag, att_yaw):
                mag_heading = math.degrees(math.atan2(ymag, xmag))
                gyro_heading = math.degrees(att_yaw)
                diff = abs(mag_heading - gyro_heading)
                if diff > 180:
                    diff = 360 - diff
                feats["mag_gyro_yaw_diff_deg"] = diff
                feats["mag_gyro_yaw_ok"] = diff <= self.config.max_yaw_diff_deg

        # Baro vs GNSS altitude
        if self.config.baro_alt_enabled:
            baro_press = self.buffer.get("baro_press", now=now)
            gps_alt_mm = self.buffer.get("gps_alt", now=now)  # GPS alt in mm

            if baro_press is not None and gps_alt_mm is not None:
                # Convert pressure to altitude (ISA)
                baro_alt = 44330 * (1 - (baro_press / 1013.25) ** 0.190284)
                gps_alt = gps_alt_mm / 1000.0  # Convert mm to meters
                diff = abs(baro_alt - gps_alt)
                feats["baro_gnss_alt_diff_m"] = diff
                feats["baro_gnss_alt_ok"] = diff <= (self.config.max_baro_diff_m + self.config.weather_drift_allowance_m)

        # Optflow vs GNSS velocity
        if self.config.optflow_vel_enabled:
            opt_x = self.buffer.get("optflow_comp_x", now=now)
            opt_y = self.buffer.get("optflow_comp_y", now=now)
            opt_quality = self.buffer.get("optflow_quality", now=now)
            vn = self.buffer.get("gps_vn", now=now)
            ve = self.buffer.get("gps_ve", now=now)

            if None not in (opt_x, opt_y, opt_quality, vn, ve):
                opt_vel = math.sqrt(opt_x**2 + opt_y**2)
                gps_vel = math.sqrt(vn**2 + ve**2) / 100.0  # cm/s to m/s
                diff = abs(opt_vel - gps_vel)
                feats["optflow_gnss_vel_diff_ms"] = diff
                feats["optflow_gnss_vel_ok"] = diff <= (self.config.max_vel_diff_ms + self.config.wind_allowance_ms)
                feats["optflow_quality_ok"] = opt_quality >= self.config.min_quality

        return feats

    def _extract_stealth_features(self, now: float) -> Dict[str, Any]:
        """Extract features for stealthy attack detection floor estimation."""
        feats = {}

        # Track slow position drift
        lat = self.buffer.get("gps_lat", now=now)
        lon = self.buffer.get("gps_lon", now=now)
        alt = self.buffer.get("gps_alt", now=now)

        if None not in (lat, lon, alt):
            # Compare with IMU-derived velocity
            vn = self.buffer.get("gps_vn", now=now)
            ve = self.buffer.get("gps_ve", now=now)
            imu_xacc = self.buffer.get("imu_xacc", now=now)
            imu_yacc = self.buffer.get("imu_yacc", now=now)

            if None not in (vn, ve, imu_xacc, imu_yacc):
                gps_vel = math.sqrt(vn**2 + ve**2) / 100.0
                # Estimate IMU velocity (simplified)
                imu_vel = math.sqrt(imu_xacc**2 + imu_yacc**2) * 0.1  # rough integration
                drift = abs(gps_vel - imu_vel)
                feats["stealth_drift_rate_ms"] = drift

                # Detect if drift is below threshold but accumulating
                if drift <= self.config.max_undetected_drift_rate_ms:
                    feats["stealth_possible"] = True
                else:
                    feats["stealth_possible"] = False

        # Track position bias
        if self._prev_gps_pos is not None:
            lat = self.buffer.get("gps_lat", now=now)
            lon = self.buffer.get("gps_lon", now=now)
            alt_mm = self.buffer.get("gps_alt", now=now)
            if None not in (lat, lon, alt_mm):
                cur_pos = (lat, lon, alt_mm / 1000.0)  # Convert mm to meters
                dist = self._haversine(self._prev_gps_pos, cur_pos)
                feats["stealth_position_bias_m"] = dist
                feats["stealth_bias_ok"] = dist <= self.config.max_undetected_bias_m

        return feats

    def _extract_trust_scores(self, now: float) -> Dict[str, Any]:
        """Extract per-channel trust scores."""
        feats = {}

        # GNSS trust
        gnss_trust = 1.0
        fix_type = self.buffer.get("gps_fix_type", now=now)
        sats = self.buffer.get("gps_sats", now=now)
        eph = self.buffer.get("gps_eph", now=now)
        epv = self.buffer.get("gps_epv", now=now)

        if fix_type is not None and fix_type < 3:
            gnss_trust = 0.0
        elif sats is not None and sats < self.config.min_satellites:
            gnss_trust = max(0.0, gnss_trust - 0.3)
        if eph is not None and eph > self.config.max_hdop * 100:
            gnss_trust = max(0.0, gnss_trust - 0.2)
        if epv is not None and epv > self.config.max_epv * 100:
            gnss_trust = max(0.0, gnss_trust - 0.2)

        feats["trust_gnss"] = max(0.0, gnss_trust)

        # INS trust (degrades with high innovations)
        ins_trust = 1.0
        vel_ratio = self.buffer.get("ekf_vel_ratio", now=now)
        pos_horiz_ratio = self.buffer.get("ekf_pos_horiz_ratio", now=now)
        if vel_ratio is not None and vel_ratio > 1.5:
            ins_trust = max(0.0, ins_trust - 0.3)
        if pos_horiz_ratio is not None and pos_horiz_ratio > 1.5:
            ins_trust = max(0.0, ins_trust - 0.3)
        feats["trust_ins"] = ins_trust

        # Baro trust
        baro_press = self.buffer.get("baro_press", now=now)
        gps_alt_mm = self.buffer.get("gps_alt", now=now)
        baro_trust = 1.0
        if baro_press is not None and gps_alt_mm is not None:
            baro_alt = 44330 * (1 - (baro_press / 1013.25) ** 0.190284)
            gps_alt = gps_alt_mm / 1000.0  # Convert mm to meters
            diff = abs(baro_alt - gps_alt)
            if diff > 20:
                baro_trust = 0.0
            elif diff > 10:
                baro_trust = 0.5
        feats["trust_baro"] = baro_trust

        # Optflow trust
        opt_quality = self.buffer.get("optflow_quality", now=now)
        opt_trust = 1.0
        if opt_quality is not None and opt_quality < 50:
            opt_trust = 0.0
        feats["trust_optflow"] = opt_trust

        # Mag trust
        mag_trust = 1.0
        mag_ratio = self.buffer.get("ekf_mag_ratio", now=now)
        if mag_ratio is not None and mag_ratio > 1.5:
            mag_trust = 0.0
        feats["trust_magnetometer"] = mag_trust

        return feats

    def _haversine(self, pos1: Tuple[float, float, float],
                   pos2: Tuple[float, float, float]) -> float:
        """Calculate distance between two lat/lon/alt positions in meters."""
        lat1, lon1, alt1 = pos1
        lat2, lon2, alt2 = pos2

        R = 6371000  # Earth radius in meters
        phi1 = math.radians(lat1 / 1e7)
        phi2 = math.radians(lat2 / 1e7)
        dphi = math.radians((lat2 - lat1) / 1e7)
        dlambda = math.radians((lon2 - lon1) / 1e7)

        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
        horiz = 2 * R * math.atan2(math.sqrt(a), math.sqrt(1-a))
        vert = alt2 - alt1
        return math.sqrt(horiz**2 + vert**2)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("NAV SENSORS — SELF TEST")
    print("=" * 70)

    # Load default policy
    policy = default_policy()
    config = NavigationConfig(policy)
    buffer = NavTelemetryBuffer(max_age_s=5.0)
    extractor = NavFeatureExtractor(config, buffer)

    now = time.time()

    # Test 1: Nominal GNSS
    buffer.ingest("GPS_RAW_INT", now, lat=0, lon=0, alt=100000000,  # 100m
                  vel=500, vn=300, ve=400, vd=0, cog=0,
                  eph=150, epv=200, satellites_visible=8, fix_type=3,
                  time_usec=int(now * 1e6))
    buffer.ingest("GLOBAL_POSITION_INT", now, relative_alt=100000,
                  vx=300, vy=400, vz=0, hdg=0)
    buffer.ingest("SCALED_IMU", now, xacc=0, yacc=0, zacc=-981,
                  xgyro=0, ygyro=0, zgyro=0, xmag=100, ymag=0, zmag=0)
    buffer.ingest("ATTITUDE", now, roll=0, pitch=0, yaw=0,
                  rollspeed=0, pitchspeed=0, yawspeed=0)
    buffer.ingest("VFR_HUD", now, alt=100000, groundspeed=500, airspeed=500, climb=0)
    buffer.ingest("SCALED_PRESSURE", now, press_abs=1013.25, press_diff=0)
    buffer.ingest("EKF_STATUS_REPORT", now, vel_ratio=0.5, pos_horiz_ratio=0.5,
                  pos_vert_ratio=0.5, mag_ratio=0.5)

    feats = extractor.extract_all(now)
    print("[1] Nominal GNSS:")
    print(f"    sats: {feats.get('gnss_satellites')}, fix_ok: {feats.get('gnss_fix_ok')}")
    print(f"    trust_gnss: {feats.get('trust_gnss'):.2f}")
    print(f"    ekf_chi2: {feats.get('ekf_chi2')}, ok: {feats.get('ekf_chi2_ok')}")
    print(f"    dr_uncertainty: {feats.get('dr_uncertainty_m'):.2f}m")

    # Test 2: GNSS jamming (satellites drop)
    buffer.ingest("GPS_RAW_INT", now + 1, lat=0, lon=0, alt=100000000,
                  vel=500, vn=300, ve=400, vd=0, cog=0,
                  eph=150, epv=200, satellites_visible=2, fix_type=1,
                  time_usec=int((now + 1) * 1e6))

    feats = extractor.extract_all(now + 1)
    print("[2] GNSS jamming (satellites drop):")
    print(f"    sats: {feats.get('gnss_satellites')}, fix_ok: {feats.get('gnss_fix_ok')}")
    print(f"    trust_gnss: {feats.get('trust_gnss'):.2f}")

    # Test 3: GPS spoofing (position jump)
    # First ingest a position (MAVLink format: degrees * 1e7)
    buffer.ingest("GPS_RAW_INT", now + 2, lat=0, lon=0, alt=100000000,
                  vel=500, vn=300, ve=400, vd=0, cog=0,
                  eph=150, epv=200, satellites_visible=8, fix_type=3,
                  time_usec=int((now + 2) * 1e6))
    # Need to call extract once to store the position
    feats1 = extractor.extract_all(now + 2)

    # Now ingest a different position (spoofed) - 0.1 degrees = ~11km
    buffer.ingest("GPS_RAW_INT", now + 2.1, lat=1000000, lon=0, alt=100000000,  # ~11km jump
                  vel=500, vn=300, ve=400, vd=0, cog=0,
                  eph=150, epv=200, satellites_visible=8, fix_type=3,
                  time_usec=int((now + 2.1) * 1e6))

    feats = extractor.extract_all(now + 2.1)
    print("[3] GPS spoofing (position jump):")
    jump = feats.get('gnss_position_jump_m')
    print(f"    jump: {jump:.1f}m, ok: {feats.get('gnss_position_jump_ok')}")
    print(f"    trust_gnss: {feats.get('trust_gnss'):.2f}")

    print("=" * 70)
    print("SELF TEST COMPLETE")
    print("=" * 70)