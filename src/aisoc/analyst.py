"""Simulated analysts and approvers: the evaluation harness, not part of the product.

To measure the feedback loop without people, an analyst is simulated from the labelled ground truth:
the analyst's verdict is the gold verdict, a tier 3 case goes to the senior analyst, and customer
approvers approve containment only for real attacks. Review times come from config/thresholds.yaml
(analyst_minutes). This module is the only consumer of aisoc.labels outside metrics and tests."""

from __future__ import annotations

from datetime import timedelta

from aisoc import labels
from aisoc.response import Approval
from aisoc.store import TenantStore
from aisoc.triage import thresholds
from aisoc.workflow import AnalystDecision, ReviewRequest


def minutes_for(req: ReviewRequest) -> int:
    m = thresholds()["analyst_minutes"]
    return m["qa"] if req.kind == "qa" else m["tier3"] if req.tier == 3 else m["tier2"]


def decide(store: TenantStore, req: ReviewRequest) -> AnalystDecision:
    gold = labels.verdict_for_events(store.tenant.id, req.event_ids)
    analyst = "analyst.okafor" if req.tier == 3 else "analyst.rivera"
    at = req.requested_at + timedelta(minutes=minutes_for(req))
    approvals = []
    if req.kind == "approval" and req.actions and gold == labels.MALICIOUS:
        need = max(n for _, _, n in req.actions)
        approvals = [Approval(a, req.plan_digest, True, at) for a in store.tenant.approvers[:need]]
    note = f"{req.kind} review by {analyst}: {gold}"
    return AnalystDecision(analyst=analyst, verdict=gold, approvals=approvals, decided_at=at, note=note)
