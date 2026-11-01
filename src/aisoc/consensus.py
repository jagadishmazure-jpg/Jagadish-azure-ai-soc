"""Multi-check consensus gate before an incident is reported to the customer without a person reading it first.

Four independent checks look at the same incident and each votes malicious, benign or unsure:

* rule: the detections themselves (severity, number of distinct rules, ATT&CK tactics);
* behaviour: the user-behaviour model (UEBA anomaly score);
* intel: threat-intelligence matches and their confidence;
* peer: what analysts decided before on incidents with the same signature in this tenant's knowledge
  base, plus tenant context (VPN egress, authorised scanner, phishing drill sender).

Auto-report needs at least 3 malicious votes, no check that is strongly benign and a model confidence of
at least 0.7. Anything else goes to a Tier 2 analyst. The gate decides only whether a person reads the
report before the customer sees it; it never starts containment, which stays approval-gated.

A single-check baseline (rule only) is computed next to it so the extra checks can be judged by the false
auto-reports they prevent. Gold labels are read only in `evaluate`."""

from __future__ import annotations

from dataclasses import dataclass

from aisoc.workflow import Case

MIN_AGREE = 3
MIN_CONFIDENCE = 0.7
SEV = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass(frozen=True)
class Vote:
    check: str
    vote: str  # malicious | benign | unsure
    strong: bool
    why: str


def rule_check(case: Case) -> Vote:
    inc = case.incident
    sev = max(SEV.get(a.severity, 0) for a in inc.alerts)
    rules = {a.source for a in inc.alerts}
    tactics = {t for a in inc.alerts for t in a.tactics}
    if sev >= 3 and (len(rules) >= 2 or len(tactics) >= 2):
        return Vote("rule", "malicious", sev >= 4, f"{len(rules)} rule(s), {len(tactics)} tactic(s), top severity {sev}")
    if sev >= 3:
        return Vote("rule", "malicious", False, f"one high-severity rule ({', '.join(sorted(rules))})")
    return Vote("rule", "unsure", False, f"top severity {sev}")


def behaviour_check(case: Case) -> Vote:
    s = max((a.score for a in case.incident.anomalies), default=0.0)
    if s >= 0.6:
        return Vote("behaviour", "malicious", s >= 0.9, f"anomaly score {s:.2f}")
    if case.incident.anomalies and s < 0.2:
        return Vote("behaviour", "benign", False, f"activity matches the user's baseline ({s:.2f})")
    return Vote("behaviour", "unsure", False, f"anomaly score {s:.2f}")


def intel_check(case: Case) -> Vote:
    hits = case.incident.ti_hits
    if not hits:
        return Vote("intel", "unsure", False, "no indicator matches")
    top = max(h.confidence for h in hits)
    if top >= 50:
        return Vote("intel", "malicious", top >= 80, f"{len(hits)} indicator match(es), top confidence {top:.0f}")
    return Vote("intel", "unsure", False, f"weak indicator match ({top:.0f})")


def peer_check(case: Case) -> Vote:
    f = case.incident.features
    if f.get("context_benign", 0) > 0:
        return Vote("peer", "benign", True, "tenant context explains it (" + "; ".join(case.incident.context[:1]) + ")")
    if f.get("kb_benign", 0) >= 0.5:
        return Vote("peer", "benign", True, "analysts closed this signature as benign before")
    if f.get("kb_malicious", 0) >= 0.5:
        return Vote("peer", "malicious", False, "analysts confirmed this signature as malicious before")
    return Vote("peer", "unsure", False, "no earlier decisions on this signature")


CHECKS = (rule_check, behaviour_check, intel_check, peer_check)


@dataclass(frozen=True)
class Decision:
    incident: str
    votes: tuple[Vote, ...]
    auto_report: bool
    reason: str

    @property
    def agree(self) -> int:
        return sum(v.vote == "malicious" for v in self.votes)


def decide(case: Case, min_agree: int = MIN_AGREE) -> Decision:
    votes = tuple(c(case) for c in CHECKS)
    agree = sum(v.vote == "malicious" for v in votes)
    strong_benign = [v.check for v in votes if v.vote == "benign" and v.strong]
    conf = case.incident.confidence if case.incident.verdict == "true_positive" else 0.0
    if strong_benign:
        return Decision(case.incident.id, votes, False, f"strong benign signal from {', '.join(strong_benign)}: Tier 2 reads it first")
    if agree < min_agree:
        return Decision(case.incident.id, votes, False, f"{agree}/4 checks agree (need {min_agree}): Tier 2 reads it first")
    if conf < MIN_CONFIDENCE:
        return Decision(case.incident.id, votes, False, f"model confidence {conf:.2f} below {MIN_CONFIDENCE}: Tier 2 reads it first")
    return Decision(case.incident.id, votes, True, f"{agree}/4 checks agree, confidence {conf:.2f}: report goes out, analyst reviews after")


def baseline(case: Case) -> bool:
    """Single-check baseline: auto-report whenever the rule check alone says malicious."""
    return rule_check(case).vote == "malicious"


def evaluate(run=None) -> dict:
    from aisoc import metrics, pipeline

    run = run or pipeline.run("learning")
    cases = run.cases()
    mal = lambda c: metrics.gold(c) == "true_positive"  # noqa: E731
    decs = {c.incident.id: decide(c) for c in cases}
    auto = [c for c in cases if decs[c.incident.id].auto_report]
    base = [c for c in cases if baseline(c)]
    closed_ok = [c for c in cases if c.route.tier == 1 and not mal(c)]
    tps = [c for c in cases if mal(c)]
    return {
        "incidents": len(cases),
        "true_positives": len(tps),
        "auto_reported": len(auto),
        "false_auto_reports": sum(not mal(c) for c in auto),
        "baseline_rule_only_auto_reported": len(base),
        "baseline_false_auto_reports": sum(not mal(c) for c in base),
        "true_positives_sent_to_tier2": sum(not decs[c.incident.id].auto_report for c in tps),
        "handled_end_to_end": f"{len(auto) + len(closed_ok)}/{len(cases)} ({100 * (len(auto) + len(closed_ok)) / len(cases):.1f}%)",
        "containment_started_by_gate": 0,
        "sweep_min_agree": {k: _sweep(cases, k, mal) for k in (1, 2, 3, 4)},
    }


def _sweep(cases, k, mal) -> str:
    auto = [c for c in cases if decide(c, k).auto_report]
    return f"{len(auto)} auto-reported, {sum(not mal(c) for c in auto)} false"


def report() -> str:
    from aisoc import pipeline

    run = pipeline.run("learning")
    lines = ["Consensus gate before auto-reporting (synthetic tenants)", ""]
    for c in run.cases():
        d = decide(c)
        if c.route.tier < 2 and not d.auto_report:
            continue
        mark = "AUTO-REPORT" if d.auto_report else "TIER 2     "
        lines.append(f"{mark} {c.incident.id}  " + "  ".join(f"{v.check}={v.vote}{'!' if v.strong else ''}" for v in d.votes))
        lines.append(f"            {d.reason}")
    lines += ["", "Measured (gold labels; synthetic data):"] + [f"  {k}: {v}" for k, v in evaluate(run).items()]
    return "\n".join(lines)
