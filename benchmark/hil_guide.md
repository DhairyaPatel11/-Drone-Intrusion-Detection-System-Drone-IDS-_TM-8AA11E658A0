# HIL / On-Target Benchmark Run Guide (Phase 6)

Steps to reproduce the latency/CPU/RSS/throughput figures on real hardware.
All numbers must be captured **on the board** — figures below the board column
are left blank until then (TO MEASURE).

## 0. Prerequisites (per board)
- Raspberry Pi 3B (32-bit OS) **or** Jetson Nano **or** Pixhawk companion running
  ArduPilot SITL (`arducopter -f simple -I0`) or a live MAVLink link.
- Python 3.9+ with `pymavlink` (for real link capture) and `psutil` (for RSS).
- The repo copied to the board (clone or `scp -r`).

## 1. Install the harness on the board
```bash
cd ~/drone-ids
pip3 install --user psutil
python3 -c "import psutil, pymavlink; print('deps ok')"
```

## 2. Run the offline performance micro-benchmark (per board)
```bash
cd ~/drone-ids
python3 -m benchmark.benchmark_perf --packets 20000 --warmup 1000
cp benchmark/results/perf_metrics.csv perf_metrics_<BOARD>.csv
```
| Board | p50 µs | p95 µs | p99 µs | CPU % | RSS MB | pkts/s |
|-------|--------|--------|--------|-------|--------|--------|
| RPi 3B | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE |
| Jetson Nano | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE |
| Pixhawk companion | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE | TO MEASURE |

## 3. Run the offline evaluation harness (accuracy/FPR, per board)
```bash
cd ~/drone-ids
python3 -m benchmark.run_benchmark --benign-packets 500
```
Read `benchmark/results/metrics.json`.

## 4. Live-link soak (optional, needs SITL or drone)
```bash
# Terminal A — SITL (if not attached to a real controller)
./arducopter -f simple -I0 --defaults params/ids_copter.parm

# Terminal B — capture and replay real frames through the pipeline
python3 - <<'EOF'
import time
from ids_pipeline import IDSPipeline, message_from_pymavlink
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
pipe = IDSPipeline()
while True:
    msg = m.recv_match(blocking=True)
    pipe.ingest(message_from_pymavlink(msg))
EOF
```

## 5. System monitoring during a soak (record alongside CSV)
```bash
pidstat -r -u 1            # RSS + CPU per second
vmstat 1                   # memory / IO / context switches
```
Plot `p50/p95/p99` and mean CPU% from the CSV; record peak RSS from pidstat.

## 6. Reporting checklist per board
- [ ] `perf_metrics_<BOARD>.csv` saved (latency, CPU%, throughput)
- [ ] Peak RSS (pidstat) recorded in MB
- [ ] `metrics.json` from `run_benchmark` saved (FPR/accuracy)
- [ ] Board name, OS version, Python version noted in `versions-benchmark.txt`