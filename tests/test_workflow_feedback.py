"""The MAF workflow (HITL pauses, QA sampling) and the feedback loop (case notes, priors, thresholds, gate)."""

import asyncio

import pytest

from aisoc import feedback
from aisoc.audit import AuditLog
from aisoc.detections import all_alerts
from aisoc.feedback import PRIOR_STRENGTH, Review, propose_thresholds
from aisoc.knowledge import CaseNote, KnowledgeBase
from aisoc.pipeline import replay_gate
from aisoc.store import load
from aisoc.triage import Learned, build_incidents, thresholds
from aisoc.workflow import AnalystDecision, Deps, build, run_case


def _deps(tenant="orchidvalley"):
    s = load(tenant)
    incs = build_incidents(s, all_alerts(s))
    return s, incs, Deps(s, KnowledgeBase(tenant), Learned(), AuditLog(tenant), incidents={i.id: i for i in incs})


def test_workflow_pauses_for_a_human_before_any_execution():
    _s, incs, deps = _deps()
    inc = next(i for i in incs if i.id == "INC-OR-032")
    from aisoc.workflow import Case

    c = Case(inc)
    deps.cases[inc.id] = c
    wf = build(deps)
    res = asyncio.run(wf.run(c))
    pending = res.get_request_info_events()
    assert len(pending) == 1 and pending[0].data.kind == "approval" and pending[0].data.tier == 3
    assert not deps.audit.events("containment.executed") and deps.audit.events("approval.requested")


def test_rejected_plan_is_not_executed():
    _s, incs, deps = _deps()
    inc = next(i for i in incs if i.id == "INC-OR-032")
    no = lambda req: AnalystDecision("analyst.okafor", "true_positive", [], req.requested_at)  # noqa: E731
    c = asyncio.run(run_case(deps, inc, no))
    assert c.approved is False and c.executions == [] and deps.audit.events("containment.skipped")


def test_every_tenth_auto_closure_is_sampled_for_qa(learning):
    every = thresholds()["qa_sample_every"]
    for tr in learning.tenants.values():
        closed = [c for c in tr.cases if c.route.tier == 1]
        sampled = [i for i, c in enumerate(closed, 1) if c.qa_sampled]
        assert sampled == [i for i in range(1, len(closed) + 1) if i % every == 0]


def test_trail_follows_the_graph(learning):
    for c in learning.cases():
        if c.route.tier == 1:
            assert c.trail[:3] == ["triage", "route", "close"]
        else:
            assert c.trail == ["triage", "route", "investigate", "summarize", "plan"]


def test_knowledge_base_only_accepts_analyst_decisions():
    kb = KnowledgeBase("brightwater")
    with pytest.raises(PermissionError):
        kb.add(CaseNote("brightwater", "s", "benign_positive", "agent:triage", "INC-1", ""))


def test_beta_prior_update(learning):
    tr = learning.tenants["brightwater"]
    src = "mass-download"
    mal, n = tr.loop.counts[src]
    base = Learned().prior(src)
    assert tr.loop.learned.priors[src] == round((base * PRIOR_STRENGTH + mal) / (PRIOR_STRENGTH + n), 4)


def _r(src, ai, gold, conf):
    return Review("t", "i", "train", 2, "review", (src,), ai, conf, gold, "analyst.rivera")


def test_thresholds_need_enough_reviews_and_respect_the_floor():
    th = thresholds()
    few = [_r("x", "false_positive", "false_positive", 0.8)] * (th["min_reviews_to_tune"] - 1)
    assert propose_thresholds(few) == {}
    many = [_r("x", "false_positive", "false_positive", 0.6)] * th["min_reviews_to_tune"]
    assert propose_thresholds(many) == {"x": th["threshold_floor"]}


def test_a_missed_attack_locks_the_detector():
    rs = [_r("x", "false_positive", "false_positive", 0.95)] * 4 + [_r("x", "false_positive", "true_positive", 0.95)]
    assert propose_thresholds(rs) == {"x": 0.99}


def test_promotion_gate_blocks_thresholds_that_would_close_attacks():
    s = load("pinecrest")
    incs = build_incidents(s, all_alerts(s))
    sources = {src for i in incs for src in i.sources}
    reckless = Learned(priors={src: 0.001 for src in sources}, auto_close={src: 0.01 for src in sources})  # a poisoned learning history
    assert replay_gate(s, incs, KnowledgeBase("pinecrest"), reckless)
    assert replay_gate(s, incs, KnowledgeBase("pinecrest"), Learned()) == []


def test_learning_is_frozen_for_the_holdout_window(learning):
    for tr in learning.tenants.values():
        noted = {n.incident_id for n in tr.loop.kb.notes}
        hold = {r.incident_id for r in tr.loop.reviews if r.window == "holdout"}
        assert hold and not (noted & hold)


def test_threshold_promotion_is_audited(learning):
    for tr in learning.tenants.values():
        assert tr.audit.events("thresholds.tuned")


def test_known_detectors_lists_rules():
    assert "password-spray" in feedback.known_detectors()
