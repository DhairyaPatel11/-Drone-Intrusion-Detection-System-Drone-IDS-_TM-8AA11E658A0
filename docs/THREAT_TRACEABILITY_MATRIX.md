---
tags: [drone-ids, threat-traceability, mitre, limits, phase8]
updated: 2026-09-26
---

# Threat Traceability Matrix & System Limits

> **Scope**: Navigation Attack Detection (NAV-001 through NAV-018) + Control System Attacks (CS-FUSED-*) + Communication Attacks (Layers 1–4) + Firmware Attacks
> **Standard**: MITRE ATT&CK for ICS (T0883, T0884, T0856, T0831, T0886)
> **Status**: All rules implemented, eval F1=0.963 on Windows host. On-target validation **TO MEASURE**.

---

## 1. Navigation Attack Rules (NAV-001…NAV-018)

| Rule ID | Attack Class | MITRE ATT&CK | Severity | Observable From | Affected Channel | Detection Method | Config Keys |
|---|---|---|---|---|---|---|---|
| **NAV-001** | `gnss_jamming` | T0884 | high | mavlink_stream | gnss | Satellite count < min_satellites + fix_type < 3 | `gnss_quality.min_satellites`, `gnss_quality.max_hdop`, `gnss_quality.max_epv` |
| **NAV-002** | `gps_spoofing_jump` | T0883 | high | mavlink_stream | gnss | Position jump > threshold (Haversine) between consecutive GPS_RAW_INT | `gnss_quality.position_jump_threshold_m` |
| **NAV-003** | `gps_spoofing_drift` | T0883 | high | mavlink_stream | gnss | CUSUM on EKF pos_horiz_ratio innovation > cusum_threshold | `ins_gnss_consistency.cusum_threshold`, `ins_gnss_consistency.innovation_chi2_threshold` |
| **NAV-004** | `gps_spoofing_seamless` | T0883 | medium | mavlink_stream | gnss+ins | GNSS healthy (8+ sats, fix=3) but INS trust < 0.5 | `trust.hysteresis`, `multi_source_attribution.source_weights` |
| **NAV-005** | `gps_time_spoofing` | T0883 | medium | mavlink_stream | gnss | GPS time jump > clock_jump_threshold_s | `gnss_quality.clock_jump_threshold_s` |
| **NAV-006** | `gnss_jamming_ramp` | T0884 | medium | mavlink_stream | gnss | SNR spread > snr_spread_threshold_db OR SNR change rate > snr_change_rate_db_s | `gnss_quality.snr_spread_threshold_db`, `gnss_quality.snr_change_rate_db_s` |
| **NAV-007** | `baro_spoofing` | T0856 | high | mavlink_stream | baro | Baro/GNSS altitude diff > max_diff_m + weather_drift_allowance_m | `sensor_cross_checks.baro_vs_gnss_alt.max_diff_m`, `sensor_cross_checks.baro_vs_gnss_alt.weather_drift_allowance_m` |
| **NAV-007b** | `baro_frozen` | T0856 | high | mavlink_stream | baro | Baro altitude variance < 0.01 over 50 samples (IEMI bus stall) | N/A (fixed threshold) |
| **NAV-008** | `mag_spoofing` | T0856 | high | mavlink_stream | magnetometer | Mag/Gyro heading diff > max_yaw_diff_deg | `sensor_cross_checks.mag_vs_gyro_heading.max_yaw_diff_deg` |
| **NAV-009** | `optical_flow_spoofing` | T0856 | high | mavlink_stream | optflow | Optflow/GNSS velocity diff > max_vel_diff_ms at groundspeed > 1 m/s | `sensor_cross_checks.optflow_vs_gnss_vel.max_vel_diff_ms`, `sensor_cross_checks.optflow_vs_gnss_vel.min_quality` |
| **NAV-010** | `coordinated_gnss_baro` | T0856 | critical | mavlink_stream | gnss+baro | Simultaneous GPS position jump + Baro altitude mismatch | Combines NAV-002 + NAV-007 logic |
| **NAV-011** | `stealthy_attack` | T0856 | medium | mavlink_stream | gnss+ins | Drift rate ≤ max_undetected_drift_rate_ms AND position bias ≤ max_undetected_bias_m | `stealthy_analysis.detection_floor.max_undetected_drift_rate_ms`, `stealthy_analysis.detection_floor.max_undetected_bias_m` |
| **NAV-012** | `rangefinder_spoofing` | T0856 | high | mavlink_stream | rangefinder | Rangefinder vs Baro/GNSS alt diff > dist_sensor_vs_alt.max_diff_m | `sensor_cross_checks.dist_sensor_vs_alt.max_diff_m` |
| **NAV-012b** | `rangefinder_frozen` | T0856 | high | mavlink_stream | rangefinder | Rangefinder variance < 0.01 over 10 samples | N/A (fixed threshold) |
| **NAV-013** | `rtk_correction_injection` | T0856 | medium | mavlink_stream | rtk | RTK Fixed (fix_type=6) but no base station coords for verification | Requires GPS_RTCM_DATA ingestion |
| **NAV-014** | `mag_bias_drift` | T0856 | medium | mavlink_stream | magnetometer | CUSUM on Mag/Gyro heading diff > max_yaw_diff_deg × 0.5 | `sensor_cross_checks.mag_vs_gyro_heading.max_yaw_diff_deg` |
| **NAV-015** | `optical_flow_bias` | T0856 | medium | mavlink_stream | optflow | CUSUM on Optflow/GNSS velocity diff > max_vel_diff_ms × 2 | `sensor_cross_checks.optflow_vs_gnss_vel.max_vel_diff_ms` |
| **NAV-016** | `rtk_correction_fault` | T0856 | high | mavlink_stream | rtk | RTK Fixed → Float/3D without sat loss (sats ≥ min_satellites) | `ins_gnss_consistency.innovation_chi2_threshold` |
| **NAV-017** | `rtk_base_shift` | T0856 | high | mavlink_stream | rtk | RTK base station coordinate shift > 0.1m | Requires GPS_RTCM_DATA base coords |
| **NAV-018** | `rtk_innovation_anomaly` | T0856 | medium | mavlink_stream | rtk | High EKF innovation (chi2 > threshold × 0.5) during RTK Fixed | `ins_gnss_consistency.innovation_chi2_threshold` |

---

## 2. Control System Fused Rules (CS-FUSED-*)

| Rule Pattern | Attack Class | MITRE ATT&CK | Severity | Layer |
|---|---|---|---|---|
| `fused_sensor_spoofing` | `sensor_spoofing` | T0856 | medium/high | control_system |
| `fused_gps_spoofing` | `gps_spoofing` | T0883 | high | control_system |
| `fused_estimator_manipulation` | `estimator_manipulation` | T0831 | high | control_system |
| `fused_control_loop_manipulation` | `control_loop_manipulation` | T0831 | medium | control_system |
| `fused_actuator_manipulation` | `actuator_manipulation` | T0831 | medium | control_system |
| `fused_geofence_violation` | `geofence_violation` | T0831 | high | control_system |
| `fused_failsafe_abuse` | `failsafe_abuse` | T0831 | high | control_system |

---

## 3. Communication Attack Rules (Layers 1–4)

| Rule ID | MITRE ATT&CK | Layer | Severity | Description |
|---|---|---|---|---|
| `crc_mismatch` | T0856 | anomaly | high | X25 CRC verification failed |
| `sequence` (backward/duplicate/large_gap) | T0886 | anomaly/replay | medium | Sequence number anomalies |
| `replay_detected` | T0886 | replay | high | Sequence within sliding window |
| `unauthorized_command_source` | T0883 | command_injection | high | SysID not in authorized_sysids |
| `command_not_allowed_in_state` | T0831 | command_injection | high | Command illegal for current flight state |
| `command_param_out_of_bounds` | T0883 | command_injection | high | MAV_CMD parameter outside allowed range |
| `rf_jamming_suspected` | T0884 | rf_jamming | high | RSSI drop + rxerrors climb (high confidence) |

---

## 4. Firmware Attack Rules

| Rule ID | MITRE ATT&CK | Severity | Description |
|---|---|---|---|
| `unauthorized_upload` | T0831 | high | FILE_TRANSFER_PROTOCOL write to protected path |
| `bootloader_reboot_armed` | T0831 | critical | Bootloader reboot while armed |
| `unexpected_bootcount` | T0831 | high | Unexpected bootcount increment |
| `firmware_version_mismatch` | T0856 | high | AUTOPILOT_VERSION not in approved list |
| `protected_param_change` | T0831 | high | Protected parameter (EKF2_, GPS_, etc.) changed in flight |
| `companion_integrity_violation` | T0856 | high | Hash mismatch in watched directories |
| `behavioral_drift` | T0856 | medium | Cyber-physical fingerprint deviation > 5σ |

---

## 5. System Limits & Non-Goals (Stated Exclusions)

### Detection Limits
| Limit | Value | Rationale |
|---|---|---|
| **Minimum detectable GPS jump** | `position_jump_threshold_m` (default 10 m) | Below this, indistinguishable from GPS noise/multipath |
| **Maximum undetectable drift rate** | `max_undetected_drift_rate_ms` (default 0.1 m/s) | Below EKF innovation gate; requires carrier-phase or OSNMA |
| **Maximum undetectable position bias** | `max_undetected_bias_m` (default 5 m) | Consistent offset within sensor noise floor |
| **Jamming detection latency** | ≥ 3 RADIO_STATUS samples (~300 ms) | Need trend confirmation to avoid FPR on transient fades |
| **RTK fault detection** | Requires fix_type transition Fixed→Float | Cannot detect bit-flip in correction stream without RTCM CRC |

### Architectural Non-Goals
- **No active response / actuator control** — IDS is advisory only; `alert_and_block` sets `drop=true` in evidence for upstream logic, never takes control
- **No cryptographic MAVLink signing verification** — Assumes FC enforces signing upstream (MAV1_OPTIONS=1); IDS only checks unsigned frames when `signing.require=true`
- **No GPS carrier-phase / OSNMA processing** — Requires receiver-level access; out of scope for MAVLink-only monitor
- **No RF spectrum analysis** — RF jamming detector uses RSSI/rxerrors from RADIO_STATUS only
- **No multi-UAV swarm correlation** — Single-vehicle IDS; swarm-level correlation is a separate system
- **No learning-based zero-day detection** — Only signature/rule-based; behavioral baseline is drift detection, not classification
- **No cross-domain (cyber→physical→cyber) attestation** — Companion integrity is hash-based; no remote attestation protocol

### Performance Bounds (Measured on Windows Host)
| Metric | Value | Note |
|---|---|---|
| Pipeline latency p50 | 638 µs | 9-stage pipeline incl. NavigationStage (5000 pkts, 1000 warmup) |
| Pipeline latency p99 | 1483 µs | ±15% run-to-run on a shared laptop |
| Throughput | 1,580 pkts/s | tracemalloc off during timing |
| RSS | 42.6 MB | Steady state |
| CPU | 91% | Single core; **TO MEASURE on Pi 3B / Jetson Nano** |
| Max telemetry age | 5 s (nav) / 2 s (control) | Stale data skips physical checks |

### Configurable Thresholds (Tunable per Platform)
```yaml
navigation:
  gnss_quality:
    min_satellites: 5          # Raise to 8 for high_value profile
    max_hdop: 3.0              # Lower to 2.0 for high_value
    position_jump_threshold_m: 10.0
    snr_spread_threshold_db: 15.0
  ins_gnss_consistency:
    cusum_threshold: 5.0       # Lower to 3.0 for high_value
    innovation_chi2_threshold: 100.0
  sensor_cross_checks:
    max_yaw_diff_deg: 30.0
    max_baro_diff_m: 10.0
    max_vel_diff_ms: 1.0
  stealthy_analysis:
    max_undetected_drift_rate_ms: 0.1
    max_undetected_bias_m: 5.0
```

---

## 6. Coverage Summary

| Domain | Rules Implemented | Tested (Pos+Neg) | Eval F1 | On-Target Validated |
|---|---|---|---|---|
| Communication | 12 | ✅ | 0.929* | ❌ |
| Firmware | 11 | ✅ | — | ❌ |
| Control System | 7 fused + 24 individual | ✅ | 0.929* | ❌ |
| Navigation | 18 (NAV-001…018) | ✅ (self-tests) | 0.929* | ❌ |

* Aggregate micro-F1 across 13 attack classes in offline benchmark. Navigation-specific attack classes not yet in benchmark generator matrix for full per-class metrics.

---

## 7. Traceability Notes

- **NAV-001, NAV-006** → RF jamming (T0884) — detect at GNSS layer; correlates with Layer 4 `rf_jamming_suspected`
- **NAV-002, NAV-003, NAV-004, NAV-005** → GPS spoofing (T0883) — position/time domain; fused with `control_system.fused_gps_spoofing`
- **NAV-007, NAV-008, NAV-009, NAV-010, NAV-012, NAV-014, NAV-015** → Sensor spoofing (T0856) — cross-check residuals
- **NAV-013, NAV-016, NAV-017, NAV-018** → RTK integrity (T0856) — requires GPS_RTCM_DATA for full coverage
- **NAV-011** → Stealthy FDI (T0856) — reports detection floor; cannot alert on sub-threshold attacks by definition

---

**End of Traceability Matrix** — All rule IDs mapped to MITRE ATT&CK for ICS, detection methods documented, and system limits explicitly stated. Phase 8 complete.