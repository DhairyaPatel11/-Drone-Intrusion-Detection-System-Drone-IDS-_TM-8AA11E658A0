"""Unit + integration tests for the Phase 5/6 benchmark harness.

Every metric helper has positive AND negative cases; the integration tests
push real frames through the real :class:`ids_pipeline.IDSPipeline` and assert
the ground-truth alert spec fires (attack) or stays silent (benign FPR).

Run:  python -m pytest tests/test_benchmark.py -q
"""

import pytest  # noqa: F401  (pytest is required to run this file)

from benchmark import attacks
from benchmark.report_metrics import (
    aggregate_metrics,
    compute_confusion,
    latency_summary_us,
    percentile,
    rule_hit,
    summarize,
)
from ids.ids_pipeline import IDSPipeline


# ---------------------------------------------------------------------------
# metric helpers — positive + negative cases
# ---------------------------------------------------------------------------

def test_rule_hit_matches_exact_spec():
    spec = {"layer": "replay", "reason": "replay_detected"}
    assert rule_hit({"layer": "replay", "reason": "replay_detected", "seq": 12}, spec)
    assert not rule_hit({"layer": "anomaly", "reason": "crc_mismatch"}, spec)          # wrong layer
    assert not rule_hit({"layer": "replay", "reason": "crc_mismatch"}, spec)           # wrong reason
    assert not rule_hit({}, spec)                                                      # empty alert


def test_compute_confusion_tp_and_fp_cases():
    spec = {"reason": "crc_mismatch"}
    only_expected = [{"reason": "crc_mismatch"}]
    assert compute_confusion(only_expected, spec) == {"tp": 1, "fp": 0, "fn": 0}
    missed = [{"reason": "replay_detected"}]                                           # no TP -> FN
    assert compute_confusion(missed, spec) == {"tp": 0, "fp": 1, "fn": 1}
    mixed = [{"reason": "replay_detected"}, {"reason": "crc_mismatch"}]                # TP + 1 FP
    assert compute_confusion(mixed, spec) == {"tp": 1, "fp": 1, "fn": 0}
    assert compute_confusion([], spec) == {"tp": 0, "fp": 0, "fn": 1}                  # silent -> FN


def test_summarize_precision_recall_f1():
    perfect = summarize({"tp": 5, "fp": 0, "fn": 0})
    assert perfect == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    half = summarize({"tp": 5, "fp": 5, "fn": 5})                                      # p=r=0.5 -> f1=0.5
    assert half["precision"] == 0.5 and half["recall"] == 0.5 and half["f1"] == 0.5
    noop = summarize({"tp": 0, "fp": 0, "fn": 1})                                      # no TP -> 0.0, no div-by-zero
    assert noop == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_aggregate_metrics_micro_average():
    agg = aggregate_metrics({
        "a": {"tp": 1, "fp": 0, "fn": 0},
        "b": {"tp": 1, "fp": 1, "fn": 1},
    })
    assert agg["tp"] == 2 and agg["fp"] == 1 and agg["fn"] == 1
    assert agg["precision"] == pytest.approx(round(2 / 3, 4))   # report rounds to 4 dp
    assert agg["recall"] == pytest.approx(round(2 / 3, 4))


def test_percentile_extremes_and_interpolation():
    data = sorted([float(i) for i in range(0, 1001)])
    assert percentile(data, 0.0) == 0.0
    assert percentile(data, 100.0) == 1000.0
    assert percentile(data, 50.0) == 500.0
    assert percentile([], 50) == 0.0
    assert percentile([7.0], 50) == 7.0


def test_latency_summary_us():
    s = latency_summary_us([1.0, 2.0, 3.0, 4.0])
    assert s["p50_us"] == 2.5 and s["mean_us"] == 2.5          # interp p50 = 2.5
    assert s["p95_us"] > 3.0 and s["p99_us"] > 3.0
    empty = latency_summary_us([])
    assert empty["mean_us"] == 0.0


# ---------------------------------------------------------------------------
# integration — benign stream must be silent (FPR = 0)
# ---------------------------------------------------------------------------

def test_benign_stream_zero_alerts():
    alerts = []
    pipe = IDSPipeline(alert_callback=lambda a: alerts.append(a))
    for f in attacks.benign_stream(200):
        pipe.ingest(f)
    assert alerts == []          # negative case: clean traffic -> no FPs


# ---------------------------------------------------------------------------
# integration — every attack class must fire its expected alert (positive)
# ---------------------------------------------------------------------------

def _fire(frames):
    alerts = []
    pipe = IDSPipeline(alert_callback=lambda a: alerts.append(a))
    for f in frames:
        pipe.ingest(f)
    return alerts


@pytest.mark.parametrize("name", sorted(attacks.ATTACK_CLASSES))
def test_attack_class_fires_expected_alert(name):
    frames, spec = attacks.ATTACK_CLASSES[name]()
    alerts = _fire(frames)
    assert alerts, "attack '%s' produced no alerts" % name
    assert any(rule_hit(a, spec) for a in alerts), (
        "attack '%s' missed expected spec %s (got %s)" % (name, spec, alerts))