"""Consensus gate before auto-reporting."""

import pytest

from aisoc import consensus as c
from aisoc import metrics, pipeline


@pytest.fixture(scope="module")
def run():
    return pipeline.run("learning")


@pytest.fixture(scope="module")
def m(run):
    return c.evaluate(run)


def test_no_false_auto_reports(m):
    assert m["false_auto_reports"] == 0


def test_baseline_would_auto_report_false_alarms(m):
    assert m["baseline_false_auto_reports"] > 0


def test_gate_never_starts_containment(m):
    assert m["containment_started_by_gate"] == 0


def test_sweep_is_monotonic(m):
    counts = [int(m["sweep_min_agree"][k].split()[0]) for k in (1, 2, 3, 4)]
    assert counts == sorted(counts, reverse=True)


def test_four_votes_each(run):
    for case in run.cases()[:20]:
        d = c.decide(case)
        assert [v.check for v in d.votes] == ["rule", "behaviour", "intel", "peer"]


def test_strong_benign_vetoes(run):
    for case in run.cases():
        d = c.decide(case, min_agree=0)
        if any(v.vote == "benign" and v.strong for v in d.votes):
            assert not d.auto_report


def test_auto_reports_are_true_positives(run):
    for case in run.cases():
        if c.decide(case).auto_report:
            assert metrics.gold(case) == "true_positive"


def test_low_confidence_blocks(run):
    for case in run.cases():
        if case.incident.verdict != "true_positive":
            assert not c.decide(case, min_agree=0).auto_report
