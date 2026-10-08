"""Metrics are computed from runs; predictive risk is evaluated honestly; tenants stay isolated."""

import pytest

from aisoc import isolation, metrics, risk


def test_every_story_detected_within_an_hour(learning):
    st = metrics.stories(learning)
    assert len(st) == 9 and all(s.detected for s in st)
    assert all(0 < s.mttd_min <= 60 for s in st)


def test_every_story_contained_in_dry_run(learning):
    assert all(s.contained and s.mttr_min > 0 for s in metrics.stories(learning))


@pytest.mark.parametrize("mode", ["baseline", "learning"])
def test_no_attack_is_ever_auto_closed(request, mode):
    run = request.getfixturevalue(mode)
    assert metrics.triage_quality(run)["auto_closed_attacks"] == 0


def test_feedback_loop_improves_holdout(learning, baseline):
    b, l_ = metrics.triage_quality(baseline, "holdout"), metrics.triage_quality(learning, "holdout")
    assert l_["accuracy_3class_pct"] > b["accuracy_3class_pct"]
    assert l_["human_reviews"] < b["human_reviews"]
    assert l_["malicious_recall_pct"] == b["malicious_recall_pct"] == 100.0


def test_human_approval_stopped_wrong_plans_in_baseline(baseline):
    r = metrics.response_stats(baseline)
    assert r["plans_not_approved"] > 0 and r["actions_executed_live"] == 0


def test_coverage_numbers(learning):
    s = metrics.summary(learning)
    assert s["attack_priority_coverage"] == "11/21" and s["story_techniques_alerted"] == "11/12"


def test_override_rate_is_zero_without_reviews():
    assert metrics._pct(0, 0) == 0.0


def test_risk_flags_planted_precursors_and_misses_spray():
    r = risk.evaluate()
    by = {p["story"]: p["hit"] for p in r["per_story"]}
    assert r["stories_flagged_day_before"] == 7
    assert not by["brightwater-spray-d9"] and not by["pinecrest-spray-d17"]
    assert r["precision_at_5_pct"] > r["random_precision_pct"]


def test_canary_never_leaves_its_tenant():
    c = isolation.canary_check()
    assert c["planted_rows"] > 0
    assert c["seen"]["pinecrest"] > 0
    assert c["seen"]["brightwater"] == 0 and c["seen"]["orchidvalley"] == 0


def test_every_cross_tenant_attempt_is_denied():
    attempts = isolation.cross_tenant_attempts()
    assert len(attempts) == 8 and all(o.startswith("denied") for _, o in attempts)


def test_technique_mix_follows_the_route(learning):
    for c in learning.cases():
        mix = metrics.technique_mix(c)
        assert "logistic-score" in mix and set(mix) <= set(metrics.TECHNIQUES)
        if c.route.tier == 1:
            assert "tool-investigation" not in mix and "llm-narrative" not in mix
        else:
            assert {"tool-investigation", "llm-narrative", "human"} <= set(mix)


def test_technique_mix_varies_and_the_model_is_not_called_for_every_incident(learning):
    s = metrics.mix_summary(learning)
    assert len(s["combinations"]) >= 5
    llm = sum(s["usage"]["llm-narrative"].values())
    assert 0 < llm < s["incidents"] and s["usage"]["llm-narrative"][1] == 0
    assert sum(len(t) for _, t in s["combinations"]) == s["incidents"]


def test_case_notes_never_contribute_without_the_feedback_loop(baseline):
    assert sum(metrics.mix_summary(baseline)["usage"]["case-notes"].values()) == 0
