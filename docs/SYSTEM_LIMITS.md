---
tags: [drone-ids, limits, non-goals, phase8]
updated: 2026-09-26
---

# System Limits & Non-Goals

> **Purpose**: Explicitly state what this IDS does NOT do, detection boundaries, and architectural boundaries. Required for PUSHPAK evaluation transparency.

---

## 1. Detection Boundaries (What We Cannot Detect)

| Category | Limitation | Impact |
|---|---|---|
| **Sub-threshold GPS spoofing** | Drift ≤ 0.1 m/s and bias ≤ 5 m (configurable) | Below EKF innovation gate; requires carrier-phase/OSNMA |
| **GNSS signal replay (aligned)** | Replayed signals time-synchronized to real | Indistinguishable without cryptographic authentication (OSNMA) |
| **Coordinated multi-sensor spoofing** | All sensors (GNSS, baro, mag, optflow) spoofed consistently | No ground truth reference; requires external anchor |
| **Firmware supply-chain implants** | Malicious code in signed firmware | Hash-based integrity only catches post-build modification |
| **Zero-day command sequences** | Novel MAV_CMD combinations not in policy | Rule-based only; behavioral baseline detects drift, not semantics |
| **Encrypted/covert channels** | Data exfil via MAVLink payload steganography | IDS inspects structure, not entropy/stego |

---

## 2. Architectural Non-Goals (Explicit Exclusions)

| Non-Goal | Reason |
|---|---|
| **Active response / actuator control** | Safety-critical; IDS is advisory only. `alert_and_block` sets evidence flag for upstream logic. |
| **MAVLink 2.0 signing verification** | FC enforces signing upstream (MAV1_OPTIONS=1). IDS only flags unsigned when `signing.require=true`. |
| **GPS carrier-phase / OSNMA processing** | Requires receiver-level access; out of scope for MAVLink monitor. |
| **RF spectrum analysis / direction finding** | Uses RSSI/rxerrors from RADIO_STATUS only. |
| **Multi-UAV swarm correlation** | Single-vehicle IDS; swarm-level is separate system. |
| **ML-based zero-day detection** | Rule/signature-based only; behavioral baseline is drift detection. |
| **Remote attestation / TPM integration** | Companion integrity is hash-based; no TPM/protocol. |
| **Cross-domain (cyber→physical→cyber) attestation** | Out of scope for this phase. |

---

## 3. Performance & Operational Limits

### Measured End-to-End Latency (Windows host, offline synthetic)

From `benchmark/results/perf_metrics.csv`, `python -m benchmark.benchmark_perf
--packets 5000 --warmup 1000`, `tracemalloc` **off** during timing:

| Metric | Value |
|---|---|
| p50 | 637.9 µs |
| p95 | 1225.17 µs |
| p99 | 1482.8 µs |
| Throughput | 1,580 pkts/s |
| RSS | 42.57 MB |
| CPU | 91.36% (one core) |

At the shallower 500-warmup / 1500-packet configuration the same code measures
p50 ≈ 467 µs and ≈ 2,440 pkts/s. Latency therefore **grows with history depth**
(the behavioural and navigation stages aggregate over rolling windows). Both
ends are quoted so the depth sensitivity is visible rather than hidden.

### Per-Stage Cost Breakdown (cProfile, indicative — NOT a measurement)

These are relative costs from a 1,500-packet profile, useful for prioritising
optimisation. They are *not* the source of the totals above and must not be
summed to reproduce them.

| Stage | Indicative cost | Notes |
|---|---|---|
| Companion integrity (dir scan) | ~14% | ~3 × `os.path.isdir` filesystem probes **per packet** — dominant single cost |
| Navigation (18 rules + trust) | ~32% | `fusion_ids.check` + `nav_sensors.extract_all` |
| Control system (6 detectors) | ~30% | Several `check()` passes per packet |
| Anomaly (CRC) | ~3% | O(1) per packet |
| Replay / command-inj / RF / firmware | ~small | Windowed stats, state machine, periodic hashes |
| Behavioural | ~small | Inference every N packets |

**Known optimisation, not yet implemented:** the companion-integrity module
re-probes its watched directories on every packet. Caching the scan behind a
short timer (e.g. 1 s) would remove the largest single per-packet cost without
weakening detection meaningfully. Listed as an open risk, not a claim.

**On-target (RPi 3B / Jetson Nano): TO MEASURE** — CPU is the likely bottleneck
on Pi 3B (already 91% of one core on an x86 laptop). Run the identical command
on the board and commit the CSV; see `benchmark/hil_guide.md`.

### Memory Bounds
- Telemetry buffer: 200 samples × ~20 fields × 8 bytes ≈ 32 KB
- History deques: max 200 entries per field
- No hot-path allocations (pre-allocated alert list, reused dataclasses)
- Python allocator peak: ~0 MB steady-state delta after warmup — i.e. no unbounded
  per-packet growth. Total footprint is the RSS figure (42.57 MB).

### False Positive Rate Targets
| Layer | Target FPR | Measured (500 benign) |
|---|---|---|
| Anomaly (CRC) | 0 | 0 |
| Replay | 0 | 0 |
| Command Injection | 0 | 0 |
| RF Jamming | < 1% | 0 |
| Control System | < 0.5% | 0 |
| Navigation | < 0.5% | 0 |

---

## 4. Configuration-Dependent Limits

### GPS Jump Detection
- **Minimum detectable**: `position_jump_threshold_m` (default 10 m)
- **Maximum position history age**: `max_age_s` (default 5 s) — older samples expired
- **Requires**: Two consecutive GPS_RAW_INT with `check()` between them

### CUSUM Drift Detection
- **Warmup**: ~10 samples before CUSUM stabilizes
- **Decay rate**: 0.01–0.02 per sample when no anomaly
- **Maneuver widening**: Yaw rate > 30°/s or accel > 3 m/s² doubles thresholds

### Trust Hysteresis
- **Threshold**: 0.1 (configurable) — trust only updates if change > hysteresis
- **Distrust threshold**: < 0.3 → `distrust` action
- **Caution threshold**: < 0.7 → `caution` action
- **Re-anchor threshold**: GNSS trust ≥ 0.7 → `can_re_anchor=true`

---

## 5. Hardware & Platform Assumptions

| Assumption | Detail |
|---|---|
| **Companion computer** | Raspberry Pi 3B+ / Jetson Nano / equivalent ARM64 |
| **Flight controller** | ArduPilot Copter 4.4+ / 4.5+ on Pixhawk 4 / Cube Orange |
| **MAVLink version** | 2.0 with signing (MAV1_OPTIONS=1) |
| **Telemetry rate** | 10–50 Hz HEARTBEAT, 5–10 Hz GPS_RAW_INT, 50–100 Hz IMU |
| **Radio telemetry** | SiK / RFD900 / ELRS with RADIO_STATUS support |
| **RTK support** | GPS_RTCM_DATA for base coords; GPS2_RAW for CN0 (optional) |

---

## 6. Evaluation Scope (What Was Measured)

| Metric | Value | Conditions |
|---|---|---|
| Eval F1 (13 classes) | 0.963 | Offline synthetic replay, 500 benign packets |
| Precision | 0.929 | |
| Recall | 1.000 | |
| Clean-path p50 latency | 121 µs | Windows 11, Python 3.13, AMD64 (`metrics.json` `latency_us.clean_path`) |
| Attack-path p50 latency | 85 µs | 13 attack classes (`latency_us.attack_path`) |
| End-to-end p50 / p99 | 638 / 1483 µs | 5000 packets, 1000 warmup, tracemalloc off |
| On-target (Pi/Jetson) | **TO MEASURE** | `benchmark/hil_guide.md` |

---

## 7. References

- MITRE ATT&CK for ICS: T0883 (Command Injection), T0884 (Jamming), T0856 (Integrity), T0831 (Manipulation), T0886 (DoS)
- ArduPilot MAVLink message definitions (GPS_RAW_INT, GPS2_RAW, GPS_RTCM_DATA, EKF_STATUS_REPORT, etc.)
- ICAO Annex 10 / RTCA DO-316 (GNSS threat models)
- PUSHPAK Grand Challenge 2026 evaluation rubric

---

**End of Limits Document** — All boundaries explicitly stated for transparent evaluation.