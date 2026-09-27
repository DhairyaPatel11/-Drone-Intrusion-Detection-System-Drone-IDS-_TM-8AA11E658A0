"""Phase 5 — Offline evaluation harness for the Drone IDS pipeline.

Runs the REAL pipeline (:class:`ids_pipeline.IDSPipeline`) over deterministic
benign + attack frame streams and reports:

    * benign-only FPR  (alerts / packets on clean traffic)
    * per-class TP / FP / FN / precision / recall / F1
    * aggregate (micro-averaged) accuracy
    * clean-path and attack-path p50 / p95 / p99 latency (µs)

Usage (from the repo root):
    python -m benchmark.run_benchmark [--benign-packets 500]

Artifacts:
    benchmark/results/metrics.json      machine-readable report
    benchmark/results/metrics.csv       per-class table
    benchmark/results/latency_hist.csv  clean-path latency distribution
    benchmark/logs/pipeline_bench.log   every alert raised during the run

Scope note: numbers produced here are OFFLINE SYNTHETIC REPLAY measurements.
On-target (SITL / RPi / Jetson / Pixhawk) figures must be produced by running
this same module on the target; hardware figures are "TO MEASURE" by design.
"""

import argparse
import os
import sys
import time
from typing import Dict, List, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark import attacks
from benchmark.report_metrics import (
    aggregate_metrics,
    compute_confusion,
    latency_summary_us,
    rule_hit,
    summarize,
    write_csv,
    write_json,
)
from ids.ids_pipeline import IDSPipeline

# ---------------------------------------------------------------------------
# Where artifacts land
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(_HERE, "results")
LOGS_DIR = os.path.join(_HERE, "logs")


def _ensure_dirs() -> None:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def run_class(
    pipeline: IDSPipeline,
    frames: List[attacks.IDSMessage],
    spec: attacks.AlertSpec,
    latencies_us: List[float],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    """Feed one attack window; returns (alerts, per-packet latencies µs)."""
    alerts: List[Dict[str, object]] = []
    pipe = IDSPipeline(alert_callback=lambda a: alerts.append(a))
    for f in frames:
        t0 = time.perf_counter()
        pipe.ingest(f)
        latencies_us.append((time.perf_counter() - t0) * 1e6)
    pipe.reset(hard=True)
    return alerts, latencies_us


def benign_fpr_run(packets: int) -> Tuple[float, List[float]]:
    """Count alerts on clean traffic -> FPR = alerts / packets."""
    alerts: List[Dict[str, object]] = []
    pipe = IDSPipeline(alert_callback=lambda a: alerts.append(a))
    lat: List[float] = []
    for f in attacks.benign_stream(packets):
        t0 = time.perf_counter()
        pipe.ingest(f)
        lat.append((time.perf_counter() - t0) * 1e6)
    pipe.reset(hard=True)
    fpr = len(alerts) / float(packets) if packets else 0.0
    return fpr, lat


def build_report(
    benign_packets: int,
    benign_alerts: int,
    fpr: float,
    per_class: Dict[str, Dict[str, int]],
    clean_lat: List[float],
    attack_lat: List[float],
    pipeline_stats: Dict[str, object],
) -> Dict[str, object]:
    """Assemble the full machine-readable report dict."""
    rows = []
    for name, conf in per_class.items():
        rows.append({"class": name, **conf, **summarize(conf)})
    return {
        "scope": "offline_synthetic_replay",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "benign_only": {
            "packets": benign_packets,
            "alerts": benign_alerts,
            "fpr": round(fpr, 6),
            "note": "on-target (SITL/hardware) FPR: TO MEASURE",
        },
        "per_class": {r["class"]: r for r in rows},
        "aggregate": aggregate_metrics(per_class),
        "latency_us": {
            "clean_path": latency_summary_us(clean_lat),
            "attack_path": latency_summary_us(attack_lat),
            "note": "offline synthetic only; on-target hardware latency: TO MEASURE",
        },
        "pipeline_stats": pipeline_stats,
        "definition": {
            "tp": "attack fired and expected alert observed (binary per class)",
            "fp": "alerts in window not matching expected spec",
            "fn": "1 when expected alert never fired",
            "fpr": "benign alerts / benign packets",
        },
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Drone IDS offline evaluation harness (Phase 5).")
    parser.add_argument(
        "--benign-packets", type=int, default=500,
        help="frames in the benign-only FPR run (default 500)")
    args = parser.parse_args(argv)
    _ensure_dirs()

    print("=" * 72)
    print("DRONE IDS — PHASE 5 EVALUATION (offline synthetic replay)")
    print("=" * 72)

    # 1) Benign-only FPR -----------------------------------------------
    print("\n[1] Benign-only run (%d packets) -> measure FPR" % args.benign_packets)
    fpr, clean_lat = benign_fpr_run(args.benign_packets)
    benign_alerts = int(round(fpr * args.benign_packets))
    print("    alerts=%d  fpr=%.6f  p50=%.1fµs p95=%.1fµs p99=%.1fµs"
          % (benign_alerts, fpr, *[latency_summary_us(clean_lat)[k]
                                   for k in ("p50_us", "p95_us", "p99_us")]))

    # 2) Per-attack-class runs -----------------------------------------
    per_class: Dict[str, Dict[str, int]] = {}
    attack_lat: List[float] = []
    all_alerts: List[Dict[str, object]] = []
    pipeline_stats: Dict[str, object] = {}

    print("\n[2] Attack classes")
    for name, gen in attacks.ATTACK_CLASSES.items():
        frames, spec = gen()
        alerts, lat = run_class(IDSPipeline(), frames, spec, [])
        attack_lat.extend(lat)
        conf = compute_confusion(alerts, spec)
        per_class[name] = conf
        all_alerts += alerts
        hit = conf["tp"] == 1
        spec_str = str(spec) if isinstance(spec, list) else str(list(spec.values()))
        print("    %-16s frames=%-3d alerts=%-2d expected=%-40s -> %s"
              % (name, len(frames), len(alerts), spec_str, "DETECTED" if hit else "MISSED"))
        for a in alerts:
            print("        + %s" % (a,))

    # 3) Aggregate + latency -------------------------------------------
    agg = aggregate_metrics(per_class)
    clean_sum = latency_summary_us(clean_lat)
    print("\n[3] Aggregate (micro): precision=%.3f recall=%.3f f1=%.3f "
          "(tp=%d fp=%d fn=%d)" % (agg["precision"], agg["recall"], agg["f1"],
                                   agg["tp"], agg["fp"], agg["fn"]))
    print("    clean-path latency:  %s" % clean_sum)
    print("    attack-path latency: %s" % latency_summary_us(attack_lat))

    # 4) Capture pipeline stats from one mixed run ----------------------
    pipe = IDSPipeline()
    for f in attacks.benign_stream(200):
        pipe.ingest(f)
    pipeline_stats = pipe.get_stats()
    print("\n[4] Pipeline stats: %s" % pipeline_stats)

    # 5) Write artifacts ------------------------------------------------
    report = build_report(args.benign_packets, benign_alerts, fpr, per_class,
                          clean_lat, attack_lat, pipeline_stats)
    write_json(os.path.join(RESULTS_DIR, "metrics.json"), report)
    write_csv(os.path.join(RESULTS_DIR, "metrics.csv"),
              [["class", "tp", "fp", "fn", "precision", "recall", "f1"]]
              + [[c["class"], c["tp"], c["fp"], c["fn"],
                  c["precision"], c["recall"], c["f1"]]
                 for c in report["per_class"].values()])
    write_csv(os.path.join(RESULTS_DIR, "latency_hist.csv"),
              [["percentile", "us"]]
              + [[p, latency_summary_us(clean_lat)["%s_us" % label]] for p, label in
                 ((50, "p50"), (95, "p95"), (99, "p99"))])
    with open(os.path.join(LOGS_DIR, "pipeline_bench.log"), "w",
              encoding="utf-8") as fh:
        for a in all_alerts:
            fh.write(str(a) + "\n")

    print("\nArtifacts:")
    for p in ("metrics.json", "metrics.csv", "latency_hist.csv"):
        print("  benchmark/results/%s" % p)
    print("  benchmark/logs/pipeline_bench.log")
    print("\nNOTE: all numbers above are OFFLINE synthetic replay on this host.")
    print("On-target SITL/hardware figures: TO MEASURE (run this module there).")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())