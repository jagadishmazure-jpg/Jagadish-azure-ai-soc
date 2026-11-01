"""Incident timeline written only from the hash-chained audit log.

The timeline never reads telemetry or case objects: it first verifies the audit chain, then groups the
records for one incident into four sections a customer can read:

1. How they got in   (alert records at the initial-access or credential-access stage)
2. What they did     (later alert records)
3. What we checked   (triage, routing and the investigation's tool calls)
4. When they were evicted (approvals, dry-run executions and post-action verification)

Main-pipeline incidents carry no alert records in the audit log, so their timelines start at triage and
say so. The identity (ITDR) and endpoint packs write their alerts to the log through `record_itdr_case`,
which is why their timelines include sections 1 and 2. If the chain does not verify, no timeline is
produced."""

from __future__ import annotations

from datetime import datetime, timedelta

from aisoc import authority, itdr
from aisoc.audit import AuditLog
from aisoc.tenants import get

ENTRY_STAGES = {"initial-access", "credential-access"}


def _when(at: str | None, t0: datetime) -> str:
    if not at:
        return "--"
    ts = datetime.fromisoformat(at)
    return f"D{(ts - t0).days:02d} {ts:%H:%M}"


def records_for(audit: AuditLog, incident: str) -> list[dict]:
    mine = [r for r in audit.records if r["data"].get("incident") == incident]
    if not mine:
        return []
    lo, hi = mine[0]["seq"], mine[-1]["seq"]
    # tool calls carry no incident id; the agent works one incident at a time, so take those inside the range
    return [r for r in audit.records if r in mine or (r["event"].startswith("tool.") and lo <= r["seq"] <= hi)]


def _line(r: dict) -> str:
    d, e = r["data"], r["event"]
    if e == "alert.raised":
        return f"{d['rule']} ({d['technique']}): {d['what']}"
    if e == "triage.scored":
        return f"triage agent scored it {d['verdict'].replace('_', ' ')} (P {d['p']:.3f})"
    if e == "case.routed":
        return f"routed to tier {d['tier']}: {'; '.join(d.get('reasons', []))}"
    if e == "case.auto_closed":
        return "closed automatically as benign"
    if e == "tool.call":
        a = d["args"]
        what = a.get("template") or a.get("kind") or ""
        return f"checked {d['tool']}{' ' + what if what else ''} ({d['rows']} row(s))"
    if e == "tool.denied":
        return f"tool call refused: {d.get('tool')}"
    if e == "containment.planned":
        return "containment proposed: " + ", ".join(f"{x[0]} {x[1]}" for x in d["actions"])
    if e == "approval.requested":
        return f"approval requested (plan {d['digest']})"
    if e == "approval.decided":
        return f"{r['actor']} {'approved' if d['approved'] else 'rejected'} plan {d['digest']}"
    if e == "case.reviewed":
        return f"{r['actor']} reviewed: {d['verdict'].replace('_', ' ')}"
    if e == "containment.executed":
        return f"{d['action']} {d['target']} ({d['mode']})"
    if e == "containment.skipped":
        return f"{d.get('action', 'containment')} skipped: {d.get('reason', '')}"
    if e == "containment.verified":
        return f"verified at T+{d['minute']} min: {d['action']} {d['target']} {'holds' if d['ok'] else 'DID NOT HOLD (human case opened)'}"
    return e


def build(audit: AuditLog, incident: str, t0: datetime) -> dict:
    ok, msg = audit.verify()
    if not ok:
        raise ValueError(f"audit chain does not verify ({msg}); no timeline produced")
    recs = records_for(audit, incident)
    alerts = [r for r in recs if r["event"] == "alert.raised"]
    entry = [r for r in alerts if r["data"]["stage"] in ENTRY_STAGES][:1] or alerts[:1]
    sections = {
        "How they got in": entry,
        "What they did": [r for r in alerts if r not in entry],
        "What we checked": [
            r for r in recs if r["event"] in ("triage.scored", "case.routed", "case.auto_closed", "tool.call", "tool.denied", "case.reviewed")
        ],
        "When they were evicted": [r for r in recs if r["event"].startswith(("containment.", "approval."))],
    }
    return {
        "incident": incident,
        "chain": msg,
        "records": len(recs),
        "sections": {
            k: [(_when(r["at"], t0), r["seq"], _line(r)) for r in sorted(v, key=lambda r: (r["at"] or "", r["seq"]))] for k, v in sections.items()
        },
    }


def render(tl: dict) -> str:
    lines = [f"Timeline for {tl['incident']} (from {tl['records']} audit records; chain: {tl['chain']})"]
    for name, rows in tl["sections"].items():
        lines.append(f"\n{name}:")
        if not rows:
            lines.append(
                "  (no audit records: the main pipeline logs from triage onward)" if name in ("How they got in", "What they did") else "  (none)"
            )
        lines += [f"  {when}  #{seq:<4} {text}" for when, seq, text in rows]
    return "\n".join(lines)


# --------------------------------------------------------------------------- pack cases -> audit log
def record_itdr_case(audit: AuditLog, case: itdr.Case, data: itdr.PackData) -> None:
    """Write an identity-pack case to the audit log as the agents would: alerts, plan, approval, dry run, checks."""
    ten = get(itdr.TENANT)
    for a in case.alerts:
        ev = itdr.event(data, a.event_ids[0])
        audit.append("svc:detections", "alert.raised", {"incident": case.id, "rule": a.rule, "stage": a.stage, "technique": a.technique,
                     "what": itdr.describe(*ev) if ev else a.rule}, a.at)  # fmt: skip
    audit.append("agent:triage", "triage.scored", {"incident": case.id, "verdict": "true_positive", "p": 0.95}, case.end)
    steps = [s for s in itdr.plan_actions(case, data) if s[0] in authority.actions()]
    plan = authority.Plan(itdr.TENANT, case.id, steps, {"account_entity", "true_positive_verdict"}, 3, 0.95)
    audit.append(
        "agent:response", "containment.planned", {"incident": case.id, "digest": plan.digest, "actions": [(a, t, 1) for a, t in steps]}, case.end
    )
    at = case.end + timedelta(minutes=25)
    audit.append(ten.approvers[0], "approval.decided", {"incident": case.id, "digest": plan.digest, "approved": True}, at)
    state: dict = {}
    res = authority.execute(plan, [authority.Approval(ten.approvers[0], plan.digest)], state)
    for o in res:
        audit.append(
            "svc:containment-executor", "containment.executed", {"incident": case.id, "action": o.action, "target": o.target, "mode": "dry-run"}, at
        )
    authority.verify(res, state)
    for o in res:
        for m, ok, _ in o.checks:
            audit.append("svc:verifier", "containment.verified", {"incident": case.id, "action": o.action, "target": o.target, "minute": m, "ok": ok},
                         at + timedelta(minutes=m))  # fmt: skip


def itdr_audit() -> AuditLog:
    data = itdr.generate()
    audit = AuditLog(itdr.TENANT)
    for c in itdr.cases(itdr.detect(data)):
        if any(not a.rule.startswith("hosting-or-vpn") for a in c.alerts):
            record_itdr_case(audit, c, data)
    return audit


def report(incident: str = "ITDR-001") -> str:
    if incident.startswith("ITDR-"):
        return render(build(itdr_audit(), incident, itdr.T0))
    from aisoc import pipeline, synth

    run = pipeline.run("learning")
    for tr in run.tenants.values():
        if any(r["data"].get("incident") == incident for r in tr.audit.records):
            return render(build(tr.audit, incident, synth.T0))
    raise KeyError(f"no audit records for {incident}")
