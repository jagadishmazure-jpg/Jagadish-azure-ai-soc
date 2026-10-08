"""The per-incident Microsoft Agent Framework workflow.

    triage ──> route ──┬── tier 1 ──> close ──(every Nth: QA request_info)──┐
                       └── tier 2/3 ──> investigate ──> summarize ──> plan ──> approval gate (request_info)
                                                                                     │
                                       capture (knowledge + feedback) <──────────────┘

Each node is a MAF `Executor`. Routing uses conditional edges. The approval gate and the QA sample
pause the workflow with `ctx.request_info`; nothing with a side effect runs until a named person
answers through `Workflow.run(responses=...)`. Execution after approval is a dry run (aisoc.response)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agent_framework import Executor, WorkflowBuilder, WorkflowContext, handler, response_handler

from aisoc import guardrails, llm, response
from aisoc.audit import AuditLog
from aisoc.investigation import SETTLE, Investigation, investigate
from aisoc.knowledge import KnowledgeBase
from aisoc.routing import Route, route
from aisoc.store import TenantStore
from aisoc.triage import Incident, Learned, enrich_and_score, thresholds


@dataclass
class Case:
    incident: Incident
    route: Route | None = None
    investigation: Investigation | None = None
    narrative: llm.Narrative | None = None
    plan: response.ContainmentPlan | None = None
    approved: bool = False
    approval_problems: list[str] = field(default_factory=list)
    executions: list[response.ExecutionRecord] = field(default_factory=list)
    decision: AnalystDecision | None = None
    qa_sampled: bool = False
    machine_ms: float = 0.0
    trail: list[str] = field(default_factory=list)

    @property
    def final_verdict(self) -> str:
        return self.decision.verdict if self.decision else self.incident.verdict


@dataclass(frozen=True)
class ReviewRequest:
    kind: str  # "approval" or "qa"
    incident_id: str
    tenant: str
    tier: int
    verdict: str
    confidence: float
    headline: str
    event_ids: tuple[str, ...]
    plan_digest: str
    actions: tuple[tuple[str, str, int], ...]
    requested_at: datetime


@dataclass(frozen=True)
class AnalystDecision:
    analyst: str
    verdict: str
    approvals: list[response.Approval]
    decided_at: datetime
    note: str = ""


@dataclass
class Deps:
    store: TenantStore
    kb: KnowledgeBase
    learned: Learned
    audit: AuditLog
    guard: bool = True
    gullible: bool = False
    counters: dict[str, int] = field(default_factory=dict)
    incidents: dict[str, Incident] = field(default_factory=dict)
    on_capture: Any = None  # callable(case) supplied by the feedback loop
    cases: dict[str, Case] = field(default_factory=dict)


class Node(Executor):
    node = "node"

    def __init__(self, deps: Deps) -> None:
        super().__init__(id=self.node)
        self.deps = deps

    def timed(self, case: Case):
        case.trail.append(self.node)
        return _Timer(case)


class _Timer:
    def __init__(self, case: Case) -> None:
        self.case = case

    def __enter__(self):
        self.t0 = time.perf_counter()

    def __exit__(self, *exc):
        self.case.machine_ms += (time.perf_counter() - self.t0) * 1000


def _at(case: Case) -> datetime:
    return case.incident.end


class TriageNode(Node):
    node = "triage"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case]) -> None:
        d = self.deps
        with self.timed(case):
            inc = enrich_and_score(d.store, case.incident, d.kb, d.learned, d.guard)
            d.audit.append("agent:triage", "triage.scored", {"incident": inc.id, "verdict": inc.verdict, "p": inc.p_malicious,
                           "features": inc.features, "duplicates": inc.duplicates}, _at(case))
        await ctx.send_message(case)


class RouteNode(Node):
    node = "route"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case]) -> None:
        d = self.deps
        with self.timed(case):
            case.route = route(d.store, case.incident, d.learned)
            d.audit.append("agent:triage", "case.routed", {"incident": case.incident.id, "tier": case.route.tier, "reasons": list(case.route.reasons)}, _at(case))
        await ctx.send_message(case)


class CloseNode(Node):
    node = "close"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case, Case]) -> None:
        d = self.deps
        with self.timed(case):
            d.counters["closed"] = d.counters.get("closed", 0) + 1
            case.qa_sampled = d.counters["closed"] % thresholds()["qa_sample_every"] == 0
            d.audit.append("agent:triage", "case.auto_closed", {"incident": case.incident.id, "verdict": case.incident.verdict,
                           "confidence": case.incident.confidence, "qa_sampled": case.qa_sampled}, _at(case))
        if case.qa_sampled:
            await ctx.request_info(_request(case, "qa"), AnalystDecision)
            return
        await ctx.send_message(case)

    @response_handler
    async def qa(self, req: ReviewRequest, decision: AnalystDecision, ctx: WorkflowContext[Case, Case]) -> None:
        case = self.deps.cases[req.incident_id]
        case.decision = decision
        self.deps.audit.append(decision.analyst, "case.qa_reviewed", {"incident": req.incident_id, "verdict": decision.verdict,
                               "agrees": decision.verdict == req.verdict}, decision.decided_at)
        await ctx.send_message(case)


class InvestigateNode(Node):
    node = "investigate"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case]) -> None:
        d = self.deps
        with self.timed(case):
            case.investigation = investigate(d.store, case.incident, d.audit, d.incidents)
        await ctx.send_message(case)


class SummarizeNode(Node):
    node = "summarize"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case]) -> None:
        d = self.deps
        with self.timed(case):
            plan = response.plan(d.store, case.incident, case.investigation)
            pseudo = guardrails.Pseudonymizer(d.store.tenant.id, d.store.tenant.domain, set(d.store.assets()))
            case.narrative = await llm.write_narrative(case.incident, case.investigation, plan, pseudo, d.guard, d.gullible)
            case.plan = plan
        await ctx.send_message(case)


class PlanNode(Node):
    node = "plan"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case]) -> None:
        d = self.deps
        with self.timed(case):
            p = case.plan
            d.audit.append("agent:response", "containment.planned", {"incident": p.incident_id, "digest": p.digest,
                           "actions": [(a.action, a.target, a.approvals_required) for a in p.actions], "denied": p.denied}, _at(case))
        await ctx.send_message(case)


class ApprovalGate(Node):
    node = "approval_gate"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case, Case]) -> None:
        req = _request(case, "approval")
        self.deps.audit.append("agent:response", "approval.requested", {"incident": req.incident_id, "digest": req.plan_digest,
                               "tier": req.tier}, req.requested_at)
        await ctx.request_info(req, AnalystDecision)

    @response_handler
    async def decided(self, req: ReviewRequest, decision: AnalystDecision, ctx: WorkflowContext[Case, Case]) -> None:
        d = self.deps
        case = d.cases[req.incident_id]
        case.decision = decision
        ok, problems = response.validate_approvals(d.store, case.plan, decision.approvals, req.requested_at)
        case.approved, case.approval_problems = ok, problems
        for a in decision.approvals:
            d.audit.append(a.approver, "approval.decided", {"incident": req.incident_id, "digest": a.plan_digest, "approved": a.approved}, a.at)
        d.audit.append(decision.analyst, "case.reviewed", {"incident": req.incident_id, "verdict": decision.verdict, "ai_verdict": req.verdict,
                       "override": decision.verdict != req.verdict}, decision.decided_at)
        case.executions = response.execute(d.store, case.plan, ok, d.audit, decision.decided_at)
        await ctx.send_message(case)


class CaptureNode(Node):
    node = "capture"

    @handler
    async def run(self, case: Case, ctx: WorkflowContext[Case, Case]) -> None:
        if self.deps.on_capture:
            self.deps.on_capture(case)
        await ctx.yield_output(case)


def _request(case: Case, kind: str) -> ReviewRequest:
    inc = case.incident
    plan = case.plan
    return ReviewRequest(
        kind=kind,
        incident_id=inc.id,
        tenant=inc.tenant,
        tier=case.route.tier if case.route else 2,
        verdict=inc.verdict,
        confidence=inc.confidence,
        headline=case.narrative.summary.headline if case.narrative else f"{inc.id} auto-closed as {inc.verdict}",
        event_ids=tuple(inc.event_ids),
        plan_digest=plan.digest if plan else "",
        actions=tuple((a.action, a.target, a.approvals_required) for a in plan.actions) if plan else (),
        requested_at=inc.end + SETTLE,
    )


def build(deps: Deps):
    triage, rte, close = TriageNode(deps), RouteNode(deps), CloseNode(deps)
    inv, summ, plan, gate, cap = InvestigateNode(deps), SummarizeNode(deps), PlanNode(deps), ApprovalGate(deps), CaptureNode(deps)
    return (
        WorkflowBuilder(start_executor=triage, name="aisoc-incident", max_iterations=20)
        .add_edge(triage, rte)
        .add_edge(rte, close, condition=lambda c: c.route.tier == 1)
        .add_edge(rte, inv, condition=lambda c: c.route.tier != 1)
        .add_edge(close, cap)
        .add_edge(inv, summ)
        .add_edge(summ, plan)
        .add_edge(plan, gate)
        .add_edge(gate, cap)
        .build()
    )


async def run_case(deps: Deps, inc: Incident, answer) -> Case:
    """Run one incident through the workflow. `answer(request) -> AnalystDecision` plays the human."""
    case = Case(inc)
    deps.cases[inc.id] = case
    wf = build(deps)
    res = await wf.run(case)
    pending = res.get_request_info_events()
    while pending:
        ev = pending[0]
        res = await wf.run(responses={ev.request_id: answer(ev.data)})
        pending = res.get_request_info_events()
    outs = res.get_outputs()
    return outs[-1] if outs else case
