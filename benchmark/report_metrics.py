"""Classification metrics + artifact writers for the benchmark harness.

Definitions (consistent with the evaluation rubric: detection accuracy, FPR):
    TP  per class: the attack fired AND an alert matching its ground-truth spec
                   appeared in its window (binary: one expected alert class).
    FP  per class: alerts inside the window that do NOT match the expected spec.
    FN  per class: 1 when the expected alert never fired.
    Precision = TP / (TP + FP)     Recall = TP / (TP + FN)     F1 = harmonic mean
    Benign-only FPR = alerts_on_benign_traffic / benign_packets
"""

import json
from typing import Any, Dict, List

from benchmark.attacks import AlertSpec


def rule_hit(alert: Dict[str, Any], spec: AlertSpec) -> bool:
    """True when ``alert`` satisfies every key/value pair in ``spec``.
    
    If spec is a list, returns True if alert matches ANY pattern in the list.
    """
    if isinstance(spec, list):
        return any(rule_hit(alert, s) for s in spec)
    return all(alert.get(k) == v for k, v in spec.items())


def compute_confusion(alerts: List[Dict[str, Any]], spec: AlertSpec) -> Dict[str, int]:
    """Return {'tp', 'fp', 'fn'} for one attack window.
    
    If spec is a list, any alert matching any pattern counts as TP.
    """
    if isinstance(spec, list):
        # Multiple acceptable alert patterns
        tp = 1 if any(any(rule_hit(a, s) for s in spec) for a in alerts) else 0
        fn = 1 - tp
        fp = sum(1 for a in alerts if not any(rule_hit(a, s) for s in spec))
    else:
        # Single expected alert pattern (legacy)
        tp = 1 if any(rule_hit(a, spec) for a in alerts) else 0
        fn = 1 - tp
        fp = sum(1 for a in alerts if not rule_hit(a, spec))
    return {"tp": tp, "fp": fp, "fn": fn}


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def summarize(conf: Dict[str, int]) -> Dict[str, float]:
    """Derive precision / recall / F1 from a confusion dict."""
    tp, fp, fn = conf["tp"], conf["fp"], conf["fn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def aggregate_metrics(per_class: Dict[str, Dict[str, int]]) -> Dict[str, float]:
    """Micro-averaged confusion across all classes -> single accuracy line."""
    tp = sum(c["tp"] for c in per_class.values())
    fp = sum(c["fp"] for c in per_class.values())
    fn = sum(c["fn"] for c in per_class.values())
    return {
        "tp": int(tp), "fp": int(fp), "fn": int(fn),
        **summarize({"tp": tp, "fp": fp, "fn": fn}),
    }


def percentile(sorted_values: List[float], p: float) -> float:
    """Linear-interpolated percentile on an ascending list (p in 0..100)."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * p / 100.0
    lo, hi = int(pos), min(int(pos) + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def latency_summary_us(latencies_us: List[float]) -> Dict[str, float]:
    """p50 / p95 / p99 / mean of per-packet latencies in µs."""
    if not latencies_us:
        return {"p50_us": 0.0, "p95_us": 0.0, "p99_us": 0.0, "mean_us": 0.0}
    s = sorted(latencies_us)
    return {
        "p50_us": round(percentile(s, 50), 2),
        "p95_us": round(percentile(s, 95), 2),
        "p99_us": round(percentile(s, 99), 2),
        "mean_us": round(sum(s) / len(s), 2),
    }


def write_json(path: str, data: Any) -> None:
    """Persist the metrics report as JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def write_csv(path: str, rows: List[List[Any]]) -> None:
    """Persist a simple table as CSV."""
    import csv
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)