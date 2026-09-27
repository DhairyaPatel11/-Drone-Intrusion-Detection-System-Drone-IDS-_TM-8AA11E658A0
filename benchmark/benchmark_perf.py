"""Phase 6 — Performance micro-benchmark for the IDS pipeline.

Measures on the *current host* (offline synthetic frames):

    * per-packet latency: p50 / p95 / p99 / mean (µs)
    * throughput (packets/second)
    * CPU utilization (%)   = process_time / wall_time
    * Python-allocator peak (MB, tracemalloc) — NOT full RSS; real RSS must be
      captured on-target with psutil/pidstat ("TO MEASURE" there).

Usage (from the repo root):
    python -m benchmark.benchmark_perf [--packets 20000] [--warmup 1000]

Artifacts:
    benchmark/results/perf_metrics.csv

Run the identical command on the Raspberry Pi / Jetson / Pixhawk companion
after capturing the CSV there (record host name first). Hardware figures are
"TO MEASURE" until such a run happens — see benchmark/hil_guide.md.
"""

import argparse
import os
import sys
import time
import tracemalloc
from typing import Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark import attacks
from benchmark.report_metrics import latency_summary_us, write_csv
from ids.ids_pipeline import IDSPipeline

_HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(_HERE, "results")


def _host_label() -> str:
    """Best-effort host identifier (platform + machine name)."""
    try:
        import platform
        return "%s/%s (%s)" % (platform.system(), platform.machine(),
                               platform.node() or "unknown")
    except Exception:                                    # pragma: no cover
        return "unknown"


def _rss_mb_if_available() -> float | None:
    """Return current RSS in MB via psutil if installed, else None."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024.0 * 1024.0)
    except Exception:
        return None


def run_micro(
    packets: int, warmup: int, frames: List[attacks.IDSMessage]
) -> Dict[str, object]:
    """Time per-packet ingestion through the real pipeline."""
    pipe = IDSPipeline()
    lat: List[float] = []

    # Warm-up: JIT/caches/scheduler settle before measurement.
    for i in range(min(warmup, len(frames))):
        pipe.ingest(frames[i])

    tracemalloc.start()
    t_wall0 = time.perf_counter()
    t_cpu0 = time.process_time()
    for i in range(warmup, warmup + packets):
        idx = i % len(frames)
        t0 = time.perf_counter()
        pipe.ingest(frames[idx])
        lat.append((time.perf_counter() - t0) * 1e6)
    wall = time.perf_counter() - t_wall0
    cpu = time.process_time() - t_cpu0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    summary = latency_summary_us(lat)
    summary["mean_us"] = round(summary["mean_us"], 2)
    return {
        "host": _host_label(),
        "packets": packets,
        "elapsed_s": round(wall, 4),
        "throughput_pkts_s": round(packets / wall, 1) if wall else 0.0,
        "cpu_percent": round(100.0 * cpu / wall, 2) if wall else 0.0,
        "py_allocator_peak_mb": round(peak / (1024.0 * 1024.0), 2),
        "rss_mb": _rss_mb_if_available(),       # None -> psutil absent
        **{k: summary[k] for k in ("p50_us", "p95_us", "p99_us", "mean_us")},
        "units": ("latency=µs/packet, cpu%%=process_cpu, "
                  "peak=RSS MB; hardware figures TO MEASURE on target"),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 6 — IDS pipeline performance micro-benchmark")
    parser.add_argument("--packets", type=int, default=20000,
                        help="measured packets (default 20000)")
    parser.add_argument("--warmup", type=int, default=1000,
                        help="warm-up packets before timing (default 1000)")
    args = parser.parse_args(argv)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    frames = attacks.benign_stream(max(args.warmup + args.packets, 1000))

    print("=" * 72)
    print("DRONE IDS — PHASE 6 PERFORMANCE (host: %s)" % _host_label())
    print("=" * 72)
    print("packets=%d warmup=%d" % (args.packets, args.warmup))

    m = run_micro(args.packets, args.warmup, frames)
    for k in ("p50_us", "p95_us", "p99_us", "mean_us", "throughput_pkts_s",
              "cpu_percent", "py_allocator_peak_mb", "rss_mb"):
        print("  %-22s %s" % (k, m[k]))

    out = os.path.join(RESULTS_DIR, "perf_metrics.csv")
    write_csv(out, [["metric", "value", "unit"]] + [
        ["host", m["host"], ""],
        ["packets", m["packets"], ""],
        ["elapsed_s", m["elapsed_s"], "s"],
        ["throughput_pkts_s", m["throughput_pkts_s"], "pkts/s"],
        ["p50_us", m["p50_us"], "us"],
        ["p95_us", m["p95_us"], "us"],
        ["p99_us", m["p99_us"], "us"],
        ["mean_us", m["mean_us"], "us"],
        ["cpu_percent", m["cpu_percent"], "%"],
        ["py_allocator_peak_mb", m["py_allocator_peak_mb"], "MB"],
        ["rss_mb", m["rss_mb"], "MB" if m["rss_mb"] is not None else "TO MEASURE"],
        ["board_hw", "TO MEASURE", ""],
    ])
    print("\nCSV written to benchmark/results/perf_metrics.csv")
    print("Run the same command on the Pi/Jetson and save the CSV per board.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())