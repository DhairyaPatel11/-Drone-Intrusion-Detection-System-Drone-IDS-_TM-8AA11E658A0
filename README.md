# Drone IDS — Multi-Tier MAVLink Cyber-Physical Intrusion Detection System

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-212%20passing-brightgreen)]()

Production-credible Drone IDS for IIT Bombay PUSHPAK Grand Challenge 2026. Implements a **9-stage pipeline** processing MAVLink 2.0 telemetry and command streams in real time on a companion computer (Raspberry Pi 3B+ / Jetson Nano / equivalent ARM64).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Drone IDS Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│ Layer 0  | MavlinkAnomalyDetector   | CRC integrity             │
│ Layer 1  | ReplayDetector           | Sliding-window anti-replay│
│ Layer 2  | CommandInjectionDetector | State-machine validation  │
│ Layer 3  | RFJammingDetector        | RADIO_STATUS statistics   │
│ Layer 4  | FirmwareAttackDetector   | Manifest integrity + FTP  │
│ Layer 5  | BehavioralFingerprint    | Cyber-physical baseline   │
│ Layer 6  | CompanionIntegrityModule | File hash verification    │
│ Layer 7  | ControlSystemDetector    | 6-detector weighted fusion│
│ Layer 8  | NavigationIDS            | 18-detector sensor fusion │
└─────────────────────────────────────────────────────────────────┘
```

An interactive, self-contained version of the end-to-end data flow is in
[`docs/architecture.html`](docs/architecture.html) — open it directly in any browser
(no server, no network access required). Its source spec is
[`docs/architecture.spec.json`](docs/architecture.spec.json).

## Detection Capabilities

| Module | Rules | MITRE ATT&CK | Headline Metric |
|--------|-------|--------------|-----------------|
| **Communication** | 12 (CRC, replay, cmd injection, RF jam) | T0883, T0884, T0856, T0886 | 1.000 F1 (5 classes) |
| **Firmware** | 11 (FTP, bootloader, version, params, integrity) | T0831, T0856 | 97 tests passing |
| **Control System** | 7 fused + 24 individual | T0831, T0856 | 1.000/0.667 F1 (8 classes) |
| **Navigation** | 18 (NAV-001..018) | T0883, T0884, T0856 | 0.963 F1 (13 classes) |

**Aggregate (13 classes):** Precision 0.929, Recall 1.000, F1 0.963 (tp=13, fp=1, fn=0)

## Quickstart

```bash
# Clone and install
git clone <repo-url>
cd Drone-Intrusion-Detection-System
pip install -e .

# Run demo (synthetic data, no hardware needed)
python scripts/run_demo.py

# Run full test suite
python -m pytest tests/ -q

# Run evaluation benchmark
python -m benchmark.run_benchmark --benign-packets 500

# Run performance benchmark
python -m benchmark.benchmark_perf --packets 5000 --warmup 500
```

## Repository Structure

```
Drone-Intrusion-Detection-System/
├── src/ids/                    # Core package
│   ├── ids_pipeline.py         # 9-stage pipeline
│   ├── command_injection_detector.py
│   ├── fusion_ids.py           # Navigation IDS (NAV-001..018)
│   ├── control_system_detector.py
│   ├── firmware_attack_detector.py
│   ├── behavioral_fingerprint.py
│   ├── companion_integrity.py
│   ├── ids_config.py           # YAML config + JSON schema
│   └── ... (other detectors)
├── configs/                    # Default + per-scenario YAML policies
│   ├── command_injection.yaml
│   ├── firmware_attacks.yaml
│   └── navigation.yaml
├── benchmark/                  # Evaluation harness
│   ├── run_benchmark.py        # Accuracy / FPR evaluation
│   ├── benchmark_perf.py       # Latency / throughput benchmark
│   ├── attacks.py              # 13 comm/ctrl + 15 nav attack generators
│   ├── report_metrics.py       # CSV/JSON metric emission
│   ├── results/                # Real measured output (metrics, latency, perf)
│   └── hil_guide.md            # On-target (RPi / Jetson) measurement procedure
├── params/                     # ArduPilot parameter set used on target
├── docs/
│   ├── STAGE1_REPORT.md        # Stage 1 proposal (6-8 pages)
│   ├── architecture.html       # Interactive end-to-end data-flow diagram
│   ├── architecture.spec.json  # Diagram source spec
│   ├── THREAT_TRACEABILITY_MATRIX.md
│   ├── FIRMWARE_THREAT_MODEL.md
│   ├── firmware_manifest_format.md
│   └── SYSTEM_LIMITS.md
├── scripts/
│   └── run_demo.py
├── tests/                      # 212 unit tests
├── media/                      # Screenshots / media referenced by docs
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## Key Features

- **Advisory-only IDS**: Fail-safe default `alert_and_pass`; `alert_and_block` sets `drop=true` in evidence only
- **Multi-tier fusion**: Per-domain detectors + weighted fusion (control system) + trust hysteresis (navigation)
- **Structured alerts**: JSON with `attack_class`, `affected_channel`, `recommended_action`, MITRE tags
- **Rate limiting**: Shared `AlertRateLimiter` with dedup window
- **Synthetic simulator**: `NavSample`-style interface for offline testing
- **SITL adapter**: `benchmark/hil_guide.md` for live MAVLink integration

## Performance (Windows Host)

| Metric | Value |
|--------|-------|
| Pipeline p50/p95/p99 | 346 / 572 / 923 µs |
| Throughput | 2,924 pkts/s |
| RSS | 42 MB |
| CPU | 91% (single core) |

**On-target (RPi 3B / Jetson Nano): TO MEASURE**

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/STAGE1_REPORT.md`](docs/STAGE1_REPORT.md) | Full Stage 1 proposal (6-8 pages) |
| [`docs/architecture.html`](docs/architecture.html) | Interactive end-to-end data-flow diagram (self-contained HTML) |
| [`docs/THREAT_TRACEABILITY_MATRIX.md`](docs/THREAT_TRACEABILITY_MATRIX.md) | NAV-001..018 and comm/firmware attacks → MITRE mapping |
| [`docs/FIRMWARE_THREAT_MODEL.md`](docs/FIRMWARE_THREAT_MODEL.md) | Firmware/companion attack catalogue |
| [`docs/firmware_manifest_format.md`](docs/firmware_manifest_format.md) | Signed firmware manifest schema |
| [`docs/SYSTEM_LIMITS.md`](docs/SYSTEM_LIMITS.md) | Detection boundaries, known evasions, non-goals |
| [`benchmark/hil_guide.md`](benchmark/hil_guide.md) | On-target (RPi 3B / Jetson Nano) measurement procedure |
| [`benchmark/results/`](benchmark/results/) | Measured metrics, latency histogram, perf CSVs |

## Requirements

- Python 3.9+ (developed and measured on CPython 3.13, Windows x64)
- `numpy`, `scipy`, `psutil`, `pyyaml`, `jsonschema`, `pymavlink` — see `requirements.txt`
- **No SITL required.** The base repo runs fully offline against the built-in synthetic
  simulator; `scripts/run_demo.py` and `python -m pytest tests/ -q` work with no hardware
  and no ArduPilot install. Live MAVLink / SITL integration is optional — see
  `benchmark/hil_guide.md`.

## License

MIT — see [LICENSE](LICENSE)

## Acknowledgments

- IIT Bombay PUSHPAK Grand Challenge 2026
- Mentors: Arnab Maity (MAVShield), Faruk Kazi (hybrid cyber-physical IDS)