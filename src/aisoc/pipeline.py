"""End-to-end runs over all tenants, used by the CLI, the metrics and the docs.

`run(mode)`:
* `baseline`: no learning; every incident is triaged with the shipped priors and thresholds.
* `learning`: the feedback loop is on for the training window (days 0-13); at its end thresholds are
  proposed, gated by a replay of the training window, and the learned state is frozen for the holdout
  window (days 14-20), so holdout numbers measure what was learned, not what was peeked at."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field

from aisoc import analyst
from aisoc.audit import AuditLog
from aisoc.detections import all_alerts
from aisoc.feedback import FeedbackLoop, propose_thresholds
from aisoc.knowledge import KnowledgeBase
from aisoc.labels import verdict_for_events
from aisoc.routing import route
from aisoc.store import TenantStore, load
from aisoc.synth import TRAIN_DAYS, day_of
from aisoc.tenants import tenants
from aisoc.triage import Incident, Learned, build_incidents, enrich_and_score
from aisoc.workflow import Case, Deps, run_case


@dataclass
class TenantRun:
    tenant: str
    cases: list[Case]
    loop: FeedbackLoop
    audit: AuditLog
    promoted: dict[str, float] = field(default_factory=dict)
    rejected: dict[str, float] = field(default_factory=dict)
    gate_log: list[str] = field(default_factory=list)


@dataclass
class Run:
    mode: str
    guard: bool
    tenants: dict[str, TenantRun]

    def cases(self, window: str | None = None) -> list[Case]:
        out = [c for t in self.tenants.values() for c in t.cases]
        if window:
            out = [c for c in out if window_of(c.incident) == window]
        return out


def window_of(inc: Incident) -> str:
    return "train" if day_of(inc.start) < TRAIN_DAYS else "holdout"


def replay_gate(store: TenantStore, incidents: list[Incident], kb: KnowledgeBase, learned: Learned) -> list[str]:
    """Re-triage the training window with candidate thresholds; any real attack that would be auto-closed blocks promotion."""
    misses = []
    for inc in incidents:
        if window_of(inc) != "train":
            continue
        probe = copy.copy(inc)
        enrich_and_score(store, probe, kb, learned)
        if route(store, probe, learned).tier == 1 and verdict_for_events(store.tenant.id, inc.event_ids) == "true_positive":
            misses.append(inc.id)
    return misses


async def run_tenant(tenant_id: str, mode: str = "learning", guard: bool = True, gullible: bool = False, store: TenantStore | None = None) -> TenantRun:
    store = store or load(tenant_id)
    kb = KnowledgeBase(tenant_id)
    learned = Learned()
    audit = AuditLog(tenant_id)
    loop = FeedbackLoop(tenant_id, kb, learned, enabled=(mode == "learning"))
    incidents = build_incidents(store, all_alerts(store))
    deps = Deps(store, kb, learned, audit, guard=guard, gullible=gullible, incidents={i.id: i for i in incidents}, on_capture=loop.capture)
    tr = TenantRun(tenant_id, [], loop, audit)
    answer = lambda req: analyst.decide(store, req)  # noqa: E731
    tuned = False
    for inc in incidents:
        if mode == "learning" and not tuned and window_of(inc) == "holdout":
            tuned = True
            candidate = propose_thresholds(loop.reviews)
            trial = Learned(dict(learned.priors), {**learned.auto_close, **candidate})
            misses = replay_gate(store, incidents, kb, trial)
            if misses:
                tr.rejected = candidate
                tr.gate_log.append(f"rejected {len(candidate)} threshold change(s): replay would auto-close {misses}")
            else:
                learned.auto_close.update(candidate)
                tr.promoted = candidate
                tr.gate_log.append(f"promoted {len(candidate)} threshold change(s); replay auto-closed 0 real attacks")
            loop.enabled = False  # freeze learned state for the holdout window
            audit.append("svc:feedback", "thresholds.tuned", {"promoted": tr.promoted, "rejected": tr.rejected}, inc.start)
        tr.cases.append(await run_case(deps, inc, answer))
    return tr


async def run_async(mode: str = "learning", guard: bool = True, gullible: bool = False, stores: dict[str, TenantStore] | None = None) -> Run:
    out = {}
    for t in sorted(tenants()):
        out[t] = await run_tenant(t, mode, guard, gullible, (stores or {}).get(t))
    return Run(mode, guard, out)


_CACHE: dict[tuple, Run] = {}


def run(mode: str = "learning", guard: bool = True, gullible: bool = False) -> Run:
    key = (mode, guard, gullible)
    if key not in _CACHE:
        _CACHE[key] = asyncio.run(run_async(mode, guard, gullible))
    return _CACHE[key]
