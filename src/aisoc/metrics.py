"""SOC metrics computed from a pipeline run against the labelled ground truth.

Every number here is computed; nothing is typed in. Definitions:

* MTTD: first alert time minus the story's first malicious event, per attack story. Alert time includes
  the configured ingestion delay and the rule's schedule (aisoc.detections).
* MTTR (simulated): first alert to dry-run containment. Machine time is measured; analyst review and
  approval time comes from config/thresholds.yaml (analyst_minutes), so MTTR is a model, not a
  measurement, and is labelled that way everywhere.
* Verdict accuracy: AI verdict vs gold verdict per incident, 3-class (true positive / benign positive /
  false positive) and binary (malicious or not).
* Escalation noise: share of escalated (tier 2/3) incidents whose gold verdict is not malicious. This is
  the SOC's false-positive burden after AI triage.
* Auto-closed attacks: tier 1 closures whose gold verdict is malicious. The release gate requires 0.
* Override rate: share of human reviews where the analyst's verdict differs from the AI's.
* ATT&CK coverage: priority techniques with at least one detection (static), and story techniques that
  appeared on at least one alert (observed)."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from aisoc import attack, labels
from aisoc.detections import all_alerts
from aisoc.pipeline import Run, window_of
from aisoc.store import load
from aisoc.synth import rel
from aisoc.tenants import tenants
from aisoc.triage import thresholds
from aisoc.workflow import Case


def gold(case: Case) -> str:
    return labels.verdict_for_events(case.incident.tenant, case.incident.event_ids)


def _pct(a: int, b: int) -> float:
    return round(100 * a / b, 1) if b else 0.0


@dataclass
class StoryResult:
    tenant: str
    story: str
    kind: str
    window: str
    started: str
    detected: bool
    mttd_min: float | None
    incident: str | None
    tier: int | None
    ai_verdict: str | None
    contained: bool
    mttr_min: float | None
    techniques_expected: tuple[str, ...]
    techniques_alerted: tuple[str, ...]


def stories(run: Run) -> list[StoryResult]:
    out = []
    for t in sorted(tenants()):
        store = load(t)
        alerts = all_alerts(store)
        cases = run.tenants[t].cases
        for s in labels.stories(t):
            mine = [a for a in alerts if labels.story_for_events(t, a.event_ids) == s["id"]]
            first = min((a.time for a in mine), default=None)
            mttd = round((first - s["first_event"]).total_seconds() / 60, 1) if first else None
            case = next((c for c in cases if labels.story_for_events(t, c.incident.event_ids) == s["id"]), None)
            contained = bool(case and case.executions)
            mttr = None
            if contained and first:
                done = case.decision.decided_at + _machine(case)
                mttr = round((done - first).total_seconds() / 60, 1)
            alerted = sorted({x for a in mine for x in attack.map_alert(a)})
            out.append(
                StoryResult(
                    t,
                    s["id"],
                    s["kind"],
                    s["window"],
                    rel(s["first_event"]),
                    bool(mine),
                    mttd,
                    case.incident.id if case else None,
                    case.route.tier if case else None,
                    case.incident.verdict if case else None,
                    contained,
                    mttr,
                    tuple(s["techniques"]),
                    tuple(alerted),
                )
            )
    return out


def _machine(case: Case):
    from datetime import timedelta

    return timedelta(milliseconds=case.machine_ms)


def triage_quality(run: Run, window: str | None = None) -> dict:
    cs = run.cases(window)
    g = [gold(c) for c in cs]
    ai = [c.incident.verdict for c in cs]
    mal_g = [x == labels.MALICIOUS for x in g]
    mal_ai = [x == labels.MALICIOUS for x in ai]
    tp = sum(a and b for a, b in zip(mal_ai, mal_g, strict=True))
    tier = [c.route.tier for c in cs]
    esc = [i for i, t in enumerate(tier) if t > 1]
    reviews = [r for t in run.tenants.values() for r in t.loop.reviews if window is None or r.window == window]
    m = thresholds()["analyst_minutes"]
    minutes = sum(m["qa"] if r.kind == "qa" else m["tier3"] if r.tier == 3 else m["tier2"] for r in reviews)
    n_alerts = sum(len(c.incident.alerts) + c.incident.duplicates for c in cs)
    return {
        "alerts": n_alerts,
        "incidents": len(cs),
        "malicious_incidents": sum(mal_g),
        "accuracy_3class_pct": _pct(sum(a == b for a, b in zip(ai, g, strict=True)), len(cs)),
        "accuracy_binary_pct": _pct(sum(a == b for a, b in zip(mal_ai, mal_g, strict=True)), len(cs)),
        "malicious_precision_pct": _pct(tp, sum(mal_ai)),
        "malicious_recall_pct": _pct(tp, sum(mal_g)),
        "tier1": tier.count(1),
        "tier2": tier.count(2),
        "tier3": tier.count(3),
        "auto_closed_pct": _pct(tier.count(1), len(cs)),
        "auto_closed_attacks": sum(1 for i, t in enumerate(tier) if t == 1 and mal_g[i]),
        "escalation_noise_pct": _pct(sum(1 for i in esc if not mal_g[i]), len(esc)),
        "human_reviews": len(reviews),
        "qa_reviews": sum(r.kind == "qa" for r in reviews),
        "override_rate_pct": _pct(sum(r.override for r in reviews), len(reviews)),
        "binary_override_rate_pct": _pct(sum(r.binary_override for r in reviews), len(reviews)),
        "simulated_analyst_minutes": minutes,
    }


def investigation_stats(run: Run) -> dict:
    inv = [c.investigation for c in run.cases() if c.investigation]
    calls = [i.tool_calls for i in inv]
    ms = sorted(i.ms for i in inv)
    return {
        "investigated": len(inv),
        "tool_calls_total": sum(calls),
        "tool_calls_mean": round(statistics.mean(calls), 1) if calls else 0,
        "evidence_rows_mean": round(statistics.mean(len(i.evidence) for i in inv), 1) if inv else 0,
        "denied_calls": sum(i.denied_calls for i in inv),
        "ms_median": round(statistics.median(ms), 1) if ms else 0,
        "ms_p95": round(ms[int(0.95 * (len(ms) - 1))], 1) if ms else 0,
    }


def guardrail_stats(run: Run) -> dict:
    cs = [c for c in run.cases() if c.narrative]
    return {
        "narratives": len(cs),
        "fallbacks": sum(c.narrative.used_fallback for c in cs),
        "injection_obeyed": sum(c.narrative.injection_obeyed for c in cs),
        "injection_incidents": sum(bool(c.incident.injection) for c in run.cases()),
        "prompt_tokens": sum(c.narrative.prompt_tokens for c in cs),
        "output_tokens": sum(c.narrative.output_tokens for c in cs),
    }


def response_stats(run: Run) -> dict:
    cs = run.cases()
    planned = [c for c in cs if c.plan and c.plan.actions]
    return {
        "plans_with_actions": len(planned),
        "actions_planned": sum(len(c.plan.actions) for c in planned),
        "plans_approved": sum(c.approved for c in planned),
        "plans_not_approved": sum(not c.approved for c in planned),
        "actions_executed_dry_run": sum(len(c.executions) for c in cs),
        "actions_executed_live": sum(1 for c in cs for e in c.executions if e.mode != "dry-run"),
        "dual_approval_plans": sum(any(a.approvals_required == 2 for a in c.plan.actions) for c in planned),
        "policy_denials": sum(len(c.plan.denied) for c in cs if c.plan),
    }


def summary(run: Run) -> dict:
    st = stories(run)
    detected = [s for s in st if s.detected]
    mttd = [s.mttd_min for s in detected if s.mttd_min is not None]
    mttr = [s.mttr_min for s in st if s.mttr_min is not None]
    observed_expected = sorted({t for s in st for t in s.techniques_expected})
    observed_alerted = sorted({t for s in st for t in s.techniques_alerted if t in observed_expected})
    cov = attack.coverage()
    return {
        "stories": len(st),
        "stories_detected": len(detected),
        "mttd_median_min": statistics.median(mttd) if mttd else None,
        "mttd_max_min": max(mttd) if mttd else None,
        "mttr_simulated_median_min": statistics.median(mttr) if mttr else None,
        "stories_contained": sum(s.contained for s in st),
        "attack_priority_coverage": f"{len(cov['covered'])}/{len(cov['priority'])}",
        "story_techniques_alerted": f"{len(observed_alerted)}/{len(observed_expected)}",
    }


def window_label(case: Case) -> str:
    return window_of(case.incident)
