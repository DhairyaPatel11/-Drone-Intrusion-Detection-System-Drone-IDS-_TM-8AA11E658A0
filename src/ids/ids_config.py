"""
ids_config.py

Phase 1 — Config & policy loader for the Command-Injection Detector.

Moves ALL hardcoded policy (flight states, allowed commands, rate limits,
thresholds, fail mode) out of the detector source into YAML, validates it
against a JSON Schema at load time, and supports per-mission-profile
overrides. Invalid config FAILS LOUDLY (raises ConfigError) — a detector
must never run with silently-ignored or half-applied policy.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

import yaml
from jsonschema import Draft7Validator, FormatChecker


class ConfigError(ValueError):
    """Raised when a config file is missing, invalid, or fails schema."""


# ---------------------------------------------------------------------------
# JSON Schema for the policy file (validated with jsonschema).
# Sections in `mission_profiles` deep-merge over the base policy.
# ---------------------------------------------------------------------------
POLICY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["fail_mode", "states", "rate_limit", "authorized_sysids"],
    "properties": {
        "fail_mode": {
            "type": "string",
            "enum": ["alert_and_pass", "alert_and_block"],
            "description": "alert_and_pass = never drop traffic, only alert "
                           "(default, fail-safe). alert_and_block = drop.",
        },
        "states": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "required": ["allowed_commands"],
                "properties": {
                    "allowed_commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 0,
                    },
                    "transitions_to": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "rate_limit": {
            "type": "object",
            "required": ["commands_per_sec"],
            "properties": {
                "commands_per_sec": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        "authorized_sysids": {
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 1,
        },
        "authorized_compids": {
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 1,
            "default": [190],
        },
        "modes": {
            "type": "object",
            "additionalProperties": {"type": "string"},
        },
        "mode_allowed_commands": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "mode_transitions": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "enforce_mode_transitions": {"type": "boolean", "default": False},
        "command_params": {
            "type": "object",
            "additionalProperties": {"type": "object"},
        },
        "geofence": {
            "type": "object",
            "properties": {
                "lat_min": {"type": "number"},
                "lat_max": {"type": "number"},
                "lon_min": {"type": "number"},
                "lon_max": {"type": "number"},
                "alt_min": {"type": "number"},
                "alt_max": {"type": "number"},
            },
        },
        "param_set_rules": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "min": {"type": "number"},
                    "max": {"type": "number"},
                    "allowed_types": {"type": "array", "items": {"type": "integer"}},
                },
            },
        },
        "mission": {
            "type": "object",
            "properties": {
                "max_items": {"type": "integer", "minimum": 1, "default": 32767},
                "min_waypoint_sep_m": {"type": "number", "minimum": 0, "default": 0.0},
            },
        },
        "ack": {
            "type": "object",
            "properties": {
                "timeout_s": {"type": "number", "minimum": 0.1, "default": 3.0},
            },
        },
        "signing": {
            "type": "object",
            "properties": {
                "require": {"type": "boolean", "default": False},
                "verify_when_present": {"type": "boolean", "default": False},
                "timestamp_tolerance_s": {"type": "number", "minimum": 0.0, "default": 30.0},
            },
        },
        "physical": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                "max_telemetry_age_s": {"type": "number", "minimum": 0.0, "default": 5.0},
                "checks": {
                    "type": "object",
                    "additionalProperties": {"type": "object"},
                },
            },
        },
        # Phase 4 — alerting
        "alerting": {
            "type": "object",
            "properties": {
                "rate_limit_per_sec": {"type": "integer", "minimum": 1, "default": 10},
                "dedupe_window_s": {"type": "number", "minimum": 0.0, "default": 30.0},
                "include_mitre": {"type": "boolean", "default": True},
            },
        },
        "command_ids": {
            "type": "object",
            "additionalProperties": {"type": "integer"},
        },
        "mission_profiles": {
            "type": "object",
            "additionalProperties": {"type": "object"},
        },
        # ==================== FIRMWARE ATTACKS (Phase 0-1) ====================
        "firmware": {
            "type": "object",
            "properties": {
                "approved_versions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of approved firmware version strings (e.g. 'Copter-4.5.0')"
                },
                "approved_git_hashes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of approved ArduPilot git commit hashes (full or prefix >= 7 chars)"
                },
                "reject_downgrade": {"type": "boolean", "default": True},
                "protected_param_prefixes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["ARMING_", "EKF2_", "EKF3_", "BATT_", "FS_", "GPS_", "INS_", "RTL_", "WPNAV_", "ANGLE_", "ATC_"],
                    "description": "Parameter prefixes considered safety-critical; mid-flight changes flagged"
                },
                "protected_ftp_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["/APM/scripts/", "/etc/", "/APM/params/", "/APM/firmware/"],
                    "description": "Directories where writes/creates/removes via FTP are flagged"
                },
                "allowed_ftp_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["/logs/", "/APM/logs/"],
                    "description": "Directories where FTP writes are allowed during flight"
                },
                "max_ftp_block_size": {"type": "integer", "minimum": 64, "default": 512},
                "max_ftp_file_size": {"type": "integer", "minimum": 1024, "default": 1048576},
                "update_window": {
                    "type": "object",
                    "properties": {
                        "require_disarmed": {"type": "boolean", "default": True},
                        "require_ground": {"type": "boolean", "default": True},
                        "allowed_states": {"type": "array", "items": {"type": "string"}, "default": ["DISARMED"]},
                    },
                },
                "reboot_rules": {
                    "type": "object",
                    "properties": {
                        "allow_bootloader_reboot_armed": {"type": "boolean", "default": False},
                        "allow_bootloader_reboot_disarmed": {"type": "boolean", "default": True},
                        "unexpected_bootcount_threshold": {"type": "integer", "minimum": 0, "default": 1},
                        "max_uptime_jump_s": {"type": "number", "minimum": 0, "default": 60.0},
                    },
                },
            },
            "additionalProperties": False,
        },
        "companion_integrity": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                "manifest_path": {"type": "string", "default": "/etc/drone-ids/firmware_manifest.json"},
                "watch_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["/opt/ardupilot/", "/etc/ardupilot/", "/home/pi/firmware/"],
                },
                "hash_algorithm": {"type": "string", "enum": ["sha256", "sha512"], "default": "sha256"},
                "max_worker_cpu_percent": {"type": "number", "minimum": 1, "maximum": 50, "default": 10},
                "verify_on_update_only": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
        "behavioral_baseline": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": False},
                "min_samples": {"type": "integer", "minimum": 100, "default": 1000},
                "drift_threshold_std": {"type": "number", "minimum": 1.0, "default": 5.0},
                "features": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["attitude_vs_command", "motor_vs_throttle", "telemetry_rate_jitter", "pid_response"],
                },
                "retrain_on_version_change": {"type": "boolean", "default": True},
                "note": "Indicates suspected tampering, NOT proof. Requires benign training data.",
            },
            "additionalProperties": False,
        },
        # ==================== CONTROL SYSTEM ATTACKS (Phase 1) ====================
        "control_system": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                # Sensor cross-consistency thresholds
                "sensor_consistency": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_age_s": {"type": "number", "minimum": 0.1, "default": 2.0},
                        # GPS vs IMU dead-reckoning
                        "gps_vs_imu": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_pos_drift_m": {"type": "number", "minimum": 0.5, "default": 5.0},
                                "max_vel_drift_ms": {"type": "number", "minimum": 0.1, "default": 1.0},
                                "max_yaw_drift_deg": {"type": "number", "minimum": 1.0, "default": 10.0},
                            },
                            "additionalProperties": False,
                        },
                        # Baro vs GPS altitude
                        "baro_vs_gps_alt": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_diff_m": {"type": "number", "minimum": 0.5, "default": 10.0},
                            },
                            "additionalProperties": False,
                        },
                        # Optical flow vs IMU velocity
                        "optflow_vs_imu": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_vel_diff_ms": {"type": "number", "minimum": 0.1, "default": 1.0},
                                "min_quality": {"type": "integer", "minimum": 0, "maximum": 255, "default": 50},
                            },
                            "additionalProperties": False,
                        },
                        # Magnetometer vs GPS course-over-ground
                        "mag_vs_cog": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_yaw_diff_deg": {"type": "number", "minimum": 1.0, "default": 30.0},
                                "min_gps_speed_ms": {"type": "number", "minimum": 0.5, "default": 2.0},
                            },
                            "additionalProperties": False,
                        },
                        # Distance sensor vs baro/GPS
                        "dist_sensor_vs_alt": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_diff_m": {"type": "number", "minimum": 0.2, "default": 2.0},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Estimator health (EKF innovation/variance)
                "estimator_health": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_age_s": {"type": "number", "minimum": 0.1, "default": 1.0},
                        "innovation": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "chi2_threshold": {"type": "number", "minimum": 1.0, "default": 100.0},
                                "cusum_threshold": {"type": "number", "minimum": 1.0, "default": 5.0},
                                "window_size": {"type": "integer", "minimum": 10, "default": 50},
                            },
                            "additionalProperties": False,
                        },
                        "variance": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_pos_horiz_var": {"type": "number", "minimum": 0.1, "default": 25.0},
                                "max_pos_vert_var": {"type": "number", "minimum": 0.1, "default": 10.0},
                                "max_vel_var": {"type": "number", "minimum": 0.1, "default": 4.0},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Control invariant / dynamics model
                "control_invariant": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_age_s": {"type": "number", "minimum": 0.1, "default": 1.0},
                        "attitude": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_roll_err_deg": {"type": "number", "minimum": 1.0, "default": 10.0},
                                "max_pitch_err_deg": {"type": "number", "minimum": 1.0, "default": 10.0},
                                "max_yaw_err_deg": {"type": "number", "minimum": 1.0, "default": 15.0},
                            },
                            "additionalProperties": False,
                        },
                        "position": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_pos_err_m": {"type": "number", "minimum": 0.5, "default": 5.0},
                                "max_vel_err_ms": {"type": "number", "minimum": 0.1, "default": 1.0},
                            },
                            "additionalProperties": False,
                        },
                        "actuator": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_pwm_residual_us": {"type": "integer", "minimum": 10, "default": 200},
                                "saturation_margin_us": {"type": "integer", "minimum": 0, "default": 100},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Actuator anomaly
                "actuator_anomaly": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_age_s": {"type": "number", "minimum": 0.1, "default": 1.0},
                        "asymmetry": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_asymmetry_ratio": {"type": "number", "minimum": 0.0, "default": 0.3},
                            },
                            "additionalProperties": False,
                        },
                        "oscillation": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_freq_hz": {"type": "number", "minimum": 1.0, "default": 20.0},
                                "min_amplitude_us": {"type": "integer", "minimum": 10, "default": 50},
                                "window_size": {"type": "integer", "minimum": 10, "default": 50},
                            },
                            "additionalProperties": False,
                        },
                        "gyro_resonance": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "peak_freq_hz": {"type": "number", "minimum": 100.0, "default": 400.0},
                                "freq_tolerance_hz": {"type": "number", "minimum": 10.0, "default": 50.0},
                                "min_power_db": {"type": "number", "minimum": -50.0, "default": -10.0},
                                "window_size": {"type": "integer", "minimum": 50, "default": 200},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Controller/parameter tampering
                "param_tampering": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "critical_params": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": ["ATC_RAT_RLL_P", "ATC_RAT_PIT_P", "ATC_RAT_YAW_P",
                                        "WPNAV_SPEED", "WPNAV_ACCEL", "RTL_ALT", "FS_GCS_ENABLE",
                                        "ARMING_CHECK", "BRD_SAFETYENABLE"],
                        },
                        "allow_in_flight": {"type": "boolean", "default": False},
                        "value_bounds": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "object",
                                "properties": {
                                    "min": {"type": "number"},
                                    "max": {"type": "number"},
                                },
                            },
                        },
                    },
                    "additionalProperties": False,
                },
                # Failsafe/geofence/mode logic abuse
                "failsafe_logic": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_age_s": {"type": "number", "minimum": 0.1, "default": 2.0},
                        "parachute_min_alt_m": {"type": "number", "minimum": 0.0, "default": 50.0},
                        "engine_kill_requires_armed": {"type": "boolean", "default": True},
                        "geofence_action": {"type": "string", "enum": ["rtl", "loiter", "land", "none"], "default": "rtl"},
                    },
                    "additionalProperties": False,
                },
                # Fusion weights for confidence scoring
                "fusion": {
                    "type": "object",
                    "properties": {
                        "sensor_consistency_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.3},
                        "estimator_health_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.2},
                        "control_invariant_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.25},
                        "actuator_anomaly_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.15},
                        "param_tampering_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.05},
                        "failsafe_logic_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.05},
                        "alert_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.5},
                    },
                    "additionalProperties": False,
                },
                # Advisory response
                "advisory": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": False},
                        "auto_failsafe": {"type": "boolean", "default": False},
                        "sensor_to_distrust": {"type": "array", "items": {"type": "string"}},
                        "recommended_mode": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        },
        # ==================== NAVIGATION ATTACKS (Phase 1) ====================
        "navigation": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                # GNSS quality features
                "gnss_quality": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "min_satellites": {"type": "integer", "minimum": 0, "default": 5},
                        "max_hdop": {"type": "number", "minimum": 0.5, "default": 3.0},
                        "max_epv": {"type": "number", "minimum": 0.5, "default": 5.0},
                        "snr_spread_threshold_db": {"type": "number", "minimum": 0.0, "default": 15.0},
                        "snr_change_rate_db_s": {"type": "number", "minimum": 0.0, "default": 10.0},
                        "fix_type_change_alert": {"type": "boolean", "default": True},
                        "position_jump_threshold_m": {"type": "number", "minimum": 1.0, "default": 10.0},
                        "velocity_jump_threshold_ms": {"type": "number", "minimum": 0.5, "default": 5.0},
                        "clock_jump_threshold_s": {"type": "number", "minimum": 0.1, "default": 1.0},
                        "spoof_flag_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 1.0},
                        "jam_flag_weight": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 1.0},
                    },
                    "additionalProperties": False,
                },
                # INS/GNSS consistency
                "ins_gnss_consistency": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "innovation_chi2_threshold": {"type": "number", "minimum": 1.0, "default": 100.0},
                        "cusum_threshold": {"type": "number", "minimum": 1.0, "default": 5.0},
                        "cusum_window": {"type": "integer", "minimum": 10, "default": 50},
                        "widen_during_maneuver": {"type": "boolean", "default": True},
                        "yaw_rate_threshold_deg_s": {"type": "number", "minimum": 5.0, "default": 30.0},
                        "accel_threshold_ms2": {"type": "number", "minimum": 1.0, "default": 3.0},
                        "drift_allowance": {"type": "number", "minimum": 0.0, "default": 0.5},
                    },
                    "additionalProperties": False,
                },
                # Bounded dead reckoning
                "dead_reckoning": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "max_uncertainty_m": {"type": "number", "minimum": 1.0, "default": 50.0},
                        "uncertainty_growth_ms": {"type": "number", "minimum": 0.01, "default": 0.5},
                        "re_anchor_trust_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.7},
                    },
                    "additionalProperties": False,
                },
                # Multi-source attribution
                "multi_source_attribution": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "min_sources_for_attribution": {"type": "integer", "minimum": 2, "maximum": 5, "default": 3},
                        "source_weights": {
                            "type": "object",
                            "additionalProperties": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "default": {
                                "gnss": 1.0,
                                "ins": 0.9,
                                "baro": 0.8,
                                "optflow": 0.7,
                                "magnetometer": 0.7,
                                "wind_airspeed": 0.6
                            },
                        },
                    },
                    "additionalProperties": False,
                },
                # Sensor-level cross-checks
                "sensor_cross_checks": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "mag_vs_gyro_heading": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_yaw_diff_deg": {"type": "number", "minimum": 1.0, "default": 30.0},
                                "min_gps_speed_ms": {"type": "number", "minimum": 0.5, "default": 2.0},
                            },
                            "additionalProperties": False,
                        },
                        "baro_vs_gnss_alt": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_diff_m": {"type": "number", "minimum": 0.5, "default": 10.0},
                                "weather_drift_allowance_m": {"type": "number", "minimum": 0.0, "default": 2.0},
                            },
                            "additionalProperties": False,
                        },
                        "optflow_vs_gnss_vel": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "max_vel_diff_ms": {"type": "number", "minimum": 0.1, "default": 1.0},
                                "wind_allowance_ms": {"type": "number", "minimum": 0.0, "default": 2.0},
                                "min_quality": {"type": "integer", "minimum": 0, "maximum": 255, "default": 50},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Stealthy attack analysis
                "stealthy_analysis": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "detection_floor": {
                            "type": "object",
                            "properties": {
                                "max_undetected_drift_rate_ms": {"type": "number", "minimum": 0.01, "default": 0.1},
                                "max_undetected_bias_m": {"type": "number", "minimum": 0.1, "default": 5.0},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                # Trust and advisory response
                "trust": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "hysteresis": {"type": "number", "minimum": 0.0, "default": 0.1},
                        "initial_trust": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 1.0},
                        "min_trust_for_re_anchor": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.7},
                    },
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}


def _deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    """Recursive dict merge; `over` wins on conflicts."""
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(
    path: Optional[str] = None,
    *,
    profile: Optional[str] = None,
    default_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Load, validate, and (optionally) profile-merge a YAML policy file.

    Args:
        path: Path to the YAML policy file. If None, `default_policy` is
            used (useful for tests / programmatic construction).
        profile: Name of the mission-profile section to apply as an
            override layer on top of the base policy.
        default_policy: In-memory policy dict (used when path is None).

    Returns:
        Validated, profile-merged policy dict.

    Raises:
        ConfigError: file missing/unparsable, schema-invalid, or the
            requested profile does not exist. Fail LOUD, never partially.
        jsonschema.ValidationError: propagated for invalid schema.
    """
    if path is not None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw: Dict[str, Any] = yaml.safe_load(fh) or {}
        except FileNotFoundError as exc:
            raise ConfigError(f"policy file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"policy file is not valid YAML: {path}") from exc
    elif default_policy is not None:
        raw = copy.deepcopy(default_policy)
    else:
        raise ConfigError("load_config requires either `path` or `default_policy`")

    _validate(raw)

    if profile is not None:
        if profile not in raw.get("mission_profiles", {}):
            raise ConfigError(
                f"profile {profile!r} not found; available: "
                f"{list(raw.get('mission_profiles', {}))}"
            )
        raw = _deep_merge(raw, raw["mission_profiles"][profile])

    return raw


def _validate(cfg: Dict[str, Any]) -> None:
    """Run JSON Schema + structural sanity checks. Raises ConfigError loudly."""
    errors = sorted(
        Draft7Validator(POLICY_SCHEMA, format_checker=FormatChecker())
        .iter_errors(cfg),
        key=lambda e: list(e.path),
    )
    if errors:
        first = errors[0]
        raise ConfigError(
            f"policy schema violation at {list(first.path) or '<root>'}: "
            f"{first.message}"
        )

    # Cross-reference: every state named in `transitions_to` must exist.
    states = cfg["states"]
    for state, body in states.items():
        for target in body.get("transitions_to", []):
            if target not in states:
                raise ConfigError(
                    f"state {state!r} transitions to unknown state {target!r}"
                )


def default_policy() -> Dict[str, Any]:
    """
    Return the in-memory default policy (mirrors the previous hardcoded
    constants), so existing tests / callers keep working without a file.
    """
    return {
        "fail_mode": "alert_and_pass",
        "states": {
            "DISARMED": {"allowed_commands": ["COMPONENT_ARM_DISARM"],
                         "transitions_to": ["ARMED"]},
            "ARMED": {"allowed_commands": ["NAV_TAKEOFF", "NAV_LOITER_UNLIM",
                                           "DO_SET_MODE"],
                      "transitions_to": ["TAKING_OFF", "DISARMED"]},
            "TAKING_OFF": {"allowed_commands": ["DO_SET_MODE"],
                           "transitions_to": ["FLYING", "LANDING"]},
            "FLYING": {"allowed_commands": ["NAV_LAND", "NAV_RETURN_TO_LAUNCH",
                                            "NAV_LOITER_UNLIM", "DO_SET_MODE",
                                            "NAV_WAYPOINT", "PARAM_SET"],
                       "transitions_to": ["LANDING", "RETURNING", "DISARMED"]},
            "LANDING": {"allowed_commands": ["DO_SET_MODE"],
                        "transitions_to": ["DISARMED", "ARMED"]},
            "RETURNING": {"allowed_commands": ["DO_SET_MODE"],
                          "transitions_to": ["LANDING", "FLYING", "DISARMED"]},
        },
        "rate_limit": {"commands_per_sec": 20},
        "authorized_sysids": [255],
        "authorized_compids": [190],
        # ArduPilot Copter mode table (custom_mode int -> canonical name)
        "modes": {
            0: "STABILIZE", 1: "ACRO", 2: "ALT_HOLD", 3: "AUTO",
            4: "GUIDED", 5: "LOITER", 6: "RTL", 7: "CIRCLE",
            8: "LAND", 9: "DRIFT", 10: "SPORT", 11: "FLIP",
            13: "POSHOLD", 14: "BRAKE", 15: "THROW", 16: "AVOID_ADSB",
            17: "GUIDED_NOGPS", 18: "SMART_RTL", 19: "FLOWHOLD",
            20: "FOLLOW", 21: "ZIGZAG", 22: "SYSTEMID", 23: "AUTOROTATE",
            24: "AUTO_RTL",
        },
        # Per-flight-mode command allowlists (in addition to phase tables)
        "mode_allowed_commands": {
            "STABILIZE": ["COMPONENT_ARM_DISARM", "DO_SET_MODE"],
            "ACRO": ["DO_SET_MODE"],
            "ALT_HOLD": ["DO_SET_MODE"],
            "AUTO": ["DO_SET_MODE"],
            "GUIDED": ["NAV_TAKEOFF", "NAV_LAND", "NAV_WAYPOINT",
                       "NAV_LOITER_UNLIM", "NAV_RETURN_TO_LAUNCH",
                       "DO_SET_MODE", "PARAM_SET"],
            "LOITER": ["NAV_WAYPOINT", "DO_SET_MODE"],
            "RTL": ["DO_SET_MODE"],
            "LAND": ["DO_SET_MODE"],
            "SMART_RTL": ["DO_SET_MODE"],
            "AUTO_RTL": ["DO_SET_MODE"],
        },
        # Legal ArduPilot mode-to-mode transitions (name -> allowed names)
        "mode_transitions": {
            "STABILIZE": ["ACRO", "ALT_HOLD", "AUTO", "GUIDED", "LOITER",
                          "RTL", "CIRCLE", "LAND", "DRIFT", "SPORT", "FLIP",
                          "POSHOLD", "BRAKE", "THROW", "AVOID_ADSB",
                          "GUIDED_NOGPS", "SMART_RTL", "FLOWHOLD", "FOLLOW",
                          "ZIGZAG", "SYSTEMID", "AUTOROTATE", "AUTO_RTL"],
            "ACRO": ["STABILIZE", "ALT_HOLD", "AUTO", "GUIDED", "LOITER", "RTL"],
            "ALT_HOLD": ["STABILIZE", "ACRO", "AUTO", "GUIDED", "LOITER", "RTL", "LAND"],
            "AUTO": ["STABILIZE", "GUIDED", "LOITER", "RTL", "LAND"],
            "GUIDED": ["STABILIZE", "ALT_HOLD", "AUTO", "LOITER", "RTL", "LAND"],
            "LOITER": ["STABILIZE", "ALT_HOLD", "AUTO", "GUIDED", "RTL", "LAND"],
            "RTL": ["STABILIZE", "ALT_HOLD", "AUTO", "GUIDED", "LOITER", "LAND"],
            "LAND": ["STABILIZE", "ALT_HOLD", "AUTO", "GUIDED", "LOITER", "RTL"],
            "SMART_RTL": ["STABILIZE", "GUIDED", "LOITER", "RTL"],
            "AUTO_RTL": ["AUTO", "GUIDED", "LAND"],
        },
        "enforce_mode_transitions": False,
        # Per-command parameter bounds (validate values, not just ids)
        "command_params": {
            "COMPONENT_ARM_DISARM": {"param1": {"enum": [0, 1]}},
            "NAV_TAKEOFF": {
                "param1": {"min": -15.0, "max": 45.0},      # pitch deg
                "param7": {"min": 0.5, "max": 120.0},        # alt m
            },
            "NAV_LAND": {"param7": {"min": 0.0, "max": 60.0}},
            "NAV_RETURN_TO_LAUNCH": {},
            "NAV_LOITER_UNLIM": {},
            "NAV_WAYPOINT": {
                "param1": {"min": 0.0, "max": 3600.0},       # hold s
                "param2": {"min": 0.0, "max": 100.0},        # accept radius m
            },
            "DO_SET_MODE": {"param1": {"mode": True}},        # must be valid mode
        },
        "geofence": {
            "lat_min": -90.0, "lat_max": 90.0,
            "lon_min": -180.0, "lon_max": 180.0,
            "alt_min": -50.0, "alt_max": 5000.0,
        },
        # PARAM_SET allow-list: name -> value/type bounds (empty = deny mid-flight)
        "param_set_rules": {
            "ANGLE_MAX": {"min": 100.0, "max": 4500.0},
            "ATC_RATE_RP_P": {"min": 0.001, "max": 1.0},
            "WPNAV_SPEED": {"min": 100.0, "max": 2000.0},
            "RTL_ALT": {"min": 0.0, "max": 1000.0},
        },
        "mission": {"max_items": 32767, "min_waypoint_sep_m": 0.0},
        "ack": {"timeout_s": 3.0},
        "signing": {
            "require": False,
            "verify_when_present": False,
            "timestamp_tolerance_s": 30.0,
        },
        # Phase 3 — cyber-physical fusion (each check is pluggable + thresholds)
        "physical": {
            "enabled": True,
            "max_telemetry_age_s": 5.0,
            "checks": {
                "disarm_vs_airborne": {
                    "enabled": True,
                    "max_disarm_alt_m": 0.5,      # disarm allowed only near ground
                    "max_disarm_climb_ms": 0.5,
                },
                "takeoff_vs_flying": {
                    "enabled": True,
                    "min_takeoff_alt_m": 1.0,     # TAKEOFF only from low altitude
                },
                "waypoint_teleport": {
                    "enabled": True,
                    "max_step_m": 500.0,          # per-command horizontal step
                    "max_alt_step_m": 50.0,
                },
                "altitude_teleport": {
                    "enabled": True,
                    "max_alt_step_m": 50.0,       # commanded-alt vs measured alt
                },
            },
        },
        "command_ids": {
            "COMPONENT_ARM_DISARM": 400,
            "NAV_TAKEOFF": 22,
            "NAV_LAND": 21,
            "NAV_RETURN_TO_LAUNCH": 20,
            "DO_SET_MODE": 183,
            "NAV_WAYPOINT": 16,
            "NAV_LOITER_UNLIM": 17,
        },
        "physical": {
            "enabled": True,
            "max_telemetry_age_s": 5.0,
            "checks": {
                "disarm_vs_airborne": {
                    "enabled": True,
                    "max_disarm_alt_m": 0.5,
                    "max_disarm_climb_ms": 0.5,
                },
                "takeoff_vs_flying": {
                    "enabled": True,
                    "min_takeoff_alt_m": 1.0,
                },
                "waypoint_teleport": {
                    "enabled": True,
                    "max_step_m": 500.0,
                    "max_alt_step_m": 50.0,
                },
                "altitude_teleport": {
                    "enabled": True,
                    "max_alt_step_m": 50.0,
                },
            },
        },
        "alerting": {
            "rate_limit_per_sec": 10,
            "dedupe_window_s": 30.0,
            "include_mitre": True,
        },
        "mission_profiles": {},
        # ==================== FIRMWARE ATTACKS (Phase 0-1) ====================
        "firmware": {
            "approved_versions": ["Copter-4.5.0", "Copter-4.4.4"],
            "approved_git_hashes": [],
            "reject_downgrade": True,
            "protected_param_prefixes": ["ARMING_", "EKF2_", "EKF3_", "BATT_", "FS_", "GPS_", "INS_", "RTL_", "WPNAV_", "ANGLE_", "ATC_"],
            "protected_ftp_paths": ["/APM/scripts/", "/etc/", "/APM/params/", "/APM/firmware/"],
            "allowed_ftp_paths": ["/logs/", "/APM/logs/"],
            "max_ftp_block_size": 512,
            "max_ftp_file_size": 1048576,
            "update_window": {
                "require_disarmed": True,
                "require_ground": True,
                "allowed_states": ["DISARMED"],
            },
            "reboot_rules": {
                "allow_bootloader_reboot_armed": False,
                "allow_bootloader_reboot_disarmed": True,
                "unexpected_bootcount_threshold": 1,
                "max_uptime_jump_s": 60.0,
            },
        },
        "companion_integrity": {
            "enabled": True,
            "manifest_path": "/etc/drone-ids/firmware_manifest.json",
            "watch_dirs": ["/opt/ardupilot/", "/etc/ardupilot/", "/home/pi/firmware/"],
            "hash_algorithm": "sha256",
            "max_worker_cpu_percent": 10,
            "verify_on_update_only": True,
        },
        "behavioral_baseline": {
            "enabled": False,
            "min_samples": 1000,
            "drift_threshold_std": 5.0,
            "features": ["attitude_vs_command", "motor_vs_throttle", "telemetry_rate_jitter", "pid_response"],
            "retrain_on_version_change": True,
        },
        # ==================== CONTROL SYSTEM ATTACKS (Phase 1) ====================
        "control_system": {
            "enabled": True,
            "sensor_consistency": {
                "enabled": True,
                "max_age_s": 2.0,
                "gps_vs_imu": {
                    "enabled": True,
                    "max_pos_drift_m": 5.0,
                    "max_vel_drift_ms": 1.0,
                    "max_yaw_drift_deg": 10.0,
                },
                "baro_vs_gps_alt": {
                    "enabled": True,
                    "max_diff_m": 10.0,
                },
                "optflow_vs_imu": {
                    "enabled": True,
                    "max_vel_diff_ms": 1.0,
                    "min_quality": 50,
                },
                "mag_vs_cog": {
                    "enabled": True,
                    "max_yaw_diff_deg": 30.0,
                    "min_gps_speed_ms": 2.0,
                },
                "dist_sensor_vs_alt": {
                    "enabled": True,
                    "max_diff_m": 2.0,
                },
            },
            "estimator_health": {
                "enabled": True,
                "max_age_s": 1.0,
                "innovation": {
                    "enabled": True,
                    "chi2_threshold": 100.0,
                    "cusum_threshold": 5.0,
                    "window_size": 50,
                },
                "variance": {
                    "enabled": True,
                    "max_pos_horiz_var": 25.0,
                    "max_pos_vert_var": 10.0,
                    "max_vel_var": 4.0,
                },
            },
            "control_invariant": {
                "enabled": True,
                "max_age_s": 1.0,
                "attitude": {
                    "enabled": True,
                    "max_roll_err_deg": 10.0,
                    "max_pitch_err_deg": 10.0,
                    "max_yaw_err_deg": 15.0,
                },
                "position": {
                    "enabled": True,
                    "max_pos_err_m": 5.0,
                    "max_vel_err_ms": 1.0,
                },
                "actuator": {
                    "enabled": True,
                    "max_pwm_residual_us": 200,
                    "saturation_margin_us": 100,
                },
            },
            "actuator_anomaly": {
                "enabled": True,
                "max_age_s": 1.0,
                "asymmetry": {
                    "enabled": True,
                    "max_asymmetry_ratio": 0.3,
                },
                "oscillation": {
                    "enabled": True,
                    "max_freq_hz": 20.0,
                    "min_amplitude_us": 50,
                    "window_size": 50,
                },
                "gyro_resonance": {
                    "enabled": True,
                    "peak_freq_hz": 400.0,
                    "freq_tolerance_hz": 50.0,
                    "min_power_db": -10.0,
                    "window_size": 200,
                },
            },
            "param_tampering": {
                "enabled": True,
                "critical_params": ["ATC_RAT_RLL_P", "ATC_RAT_PIT_P", "ATC_RAT_YAW_P",
                                    "WPNAV_SPEED", "WPNAV_ACCEL", "RTL_ALT", "FS_GCS_ENABLE",
                                    "ARMING_CHECK", "BRD_SAFETYENABLE"],
                "allow_in_flight": False,
                "value_bounds": {
                    "ATC_RAT_RLL_P": {"min": 0.001, "max": 1.0},
                    "ATC_RAT_PIT_P": {"min": 0.001, "max": 1.0},
                    "ATC_RAT_YAW_P": {"min": 0.001, "max": 1.0},
                    "WPNAV_SPEED": {"min": 100.0, "max": 2000.0},
                    "WPNAV_ACCEL": {"min": 50.0, "max": 500.0},
                    "RTL_ALT": {"min": 0.0, "max": 1000.0},
                    "FS_GCS_ENABLE": {"min": 0.0, "max": 2.0},
                    "ARMING_CHECK": {"min": 0.0, "max": 65535.0},
                    "BRD_SAFETYENABLE": {"min": 0.0, "max": 1.0},
                },
            },
            "failsafe_logic": {
                "enabled": True,
                "max_age_s": 2.0,
                "parachute_min_alt_m": 50.0,
                "engine_kill_requires_armed": True,
                "geofence_action": "rtl",
            },
            "fusion": {
                "sensor_consistency_weight": 0.3,
                "estimator_health_weight": 0.2,
                "control_invariant_weight": 0.25,
                "actuator_anomaly_weight": 0.15,
                "param_tampering_weight": 0.05,
                "failsafe_logic_weight": 0.05,
                "alert_threshold": 0.5,
            },
            "advisory": {
                "enabled": False,
                "auto_failsafe": False,
                "sensor_to_distrust": [],
                "recommended_mode": None,
            },
        },
        # ==================== NAVIGATION ATTACKS (Phase 1) ====================
        "navigation": {
            "enabled": True,
            # GNSS quality features
            "gnss_quality": {
                "enabled": True,
                "min_satellites": 5,
                "max_hdop": 3.0,
                "max_epv": 5.0,
                "snr_spread_threshold_db": 15.0,
                "snr_change_rate_db_s": 10.0,
                "fix_type_change_alert": True,
                "position_jump_threshold_m": 10.0,
                "velocity_jump_threshold_ms": 5.0,
                "clock_jump_threshold_s": 1.0,
                "spoof_flag_weight": 1.0,
                "jam_flag_weight": 1.0,
            },
            # INS/GNSS consistency
            "ins_gnss_consistency": {
                "enabled": True,
                "innovation_chi2_threshold": 100.0,
                "cusum_threshold": 5.0,
                "cusum_window": 50,
                "widen_during_maneuver": True,
                "yaw_rate_threshold_deg_s": 30.0,
                "accel_threshold_ms2": 3.0,
                "drift_allowance": 0.5,
            },
            # Bounded dead reckoning
            "dead_reckoning": {
                "enabled": True,
                "max_uncertainty_m": 50.0,
                "uncertainty_growth_ms": 0.5,
                "re_anchor_trust_threshold": 0.7,
            },
            # Multi-source attribution
            "multi_source_attribution": {
                "enabled": True,
                "min_sources_for_attribution": 3,
                "source_weights": {
                    "gnss": 1.0,
                    "ins": 0.9,
                    "baro": 0.8,
                    "optflow": 0.7,
                    "magnetometer": 0.7,
                    "wind_airspeed": 0.6
                },
            },
            # Sensor-level cross-checks
            "sensor_cross_checks": {
                "enabled": True,
                "mag_vs_gyro_heading": {
                    "enabled": True,
                    "max_yaw_diff_deg": 30.0,
                    "min_gps_speed_ms": 2.0,
                },
                "baro_vs_gnss_alt": {
                    "enabled": True,
                    "max_diff_m": 10.0,
                    "weather_drift_allowance_m": 2.0,
                },
                "optflow_vs_gnss_vel": {
                    "enabled": True,
                    "max_vel_diff_ms": 1.0,
                    "wind_allowance_ms": 2.0,
                    "min_quality": 50,
                },
            },
            # Stealthy attack analysis
            "stealthy_analysis": {
                "enabled": True,
                "detection_floor": {
                    "max_undetected_drift_rate_ms": 0.1,
                    "max_undetected_bias_m": 5.0,
                },
            },
            # Trust and advisory response
            "trust": {
                "enabled": True,
                "hysteresis": 0.1,
                "initial_trust": 1.0,
                "min_trust_for_re_anchor": 0.7,
            },
        },
    }


def get_fail_mode(cfg: Dict[str, Any]) -> str:
    """Return the validated fail mode ('alert_and_pass' default)."""
    return cfg.get("fail_mode", "alert_and_pass")


def get_authorized_sysids(cfg: Dict[str, Any]) -> list[int]:
    """Return the allowed GCS source system IDs from policy."""
    return list(cfg.get("authorized_sysids", [255]))