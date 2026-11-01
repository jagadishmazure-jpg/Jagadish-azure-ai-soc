"""Authority registry, post-action verification and undo plans for containment (all simulated).

* `config/authority.yaml` gives every action a stage (1-4), an owner, the number of approvals, the
  evidence it needs, the consensus and confidence it needs, its blast radius, its effect on tenant state,
  when to verify it and how to undo it. Nothing is at stage 4 and `promote` refuses to apply stage 4.
* `execute` runs an approved plan against a simulated tenant state (a dict), never against a real API.
  It checks approvals (enough distinct tenant approvers, bound to the plan digest), evidence and the
  consensus gate before each action.
* `verify` re-reads the state at each `verify_after` minute. A drift (directory sync re-enables a user,
  an OAuth app re-creates an inbox rule) fails verification and opens a human case.
* `undo` replays the saved before-values and must restore the state digest exactly.
* `quarantine_ai_agent` takes a misbehaving AI agent offline (identity disabled, tool connections cut,
  credential revoked) after two approvals; `agent_scenario` walks one synthetic case end to end."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from functools import cache

import yaml

from aisoc import CONFIG
from aisoc.tenants import get


@cache
def registry() -> dict:
    return yaml.safe_load((CONFIG / "authority.yaml").read_text())


def actions() -> dict:
    return registry()["actions"]


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


@dataclass
class Plan:
    tenant: str
    incident: str
    steps: list[tuple[str, str]]  # (action, target)
    evidence: set[str]
    agree: int
    confidence: float

    @property
    def digest(self) -> str:
        return digest([self.tenant, self.incident, self.steps])


@dataclass
class Approval:
    by: str
    digest: str


@dataclass
class Outcome:
    action: str
    target: str
    status: str  # executed | refused
    reason: str
    before: object = None
    checks: list[tuple[int, bool, str]] = field(default_factory=list)


class Drift:
    """Simulated things that undo a fix behind your back, applied at a minute offset after execution."""

    def __init__(self, rules: list[tuple[str, int, object, str | None]] | None = None) -> None:
        # (state key, minute, value it is set back to, key that must be False/absent to stop it or None)
        self.rules = rules or []

    def apply(self, state: dict, minute: int) -> None:
        for key, at, value, unless in self.rules:
            if minute >= at and key in state and not (unless and state.get(unless) is False):
                state[key] = value


def check_plan(plan: Plan, approvals: list[Approval]) -> list[str]:
    problems = []
    ten = get(plan.tenant)
    good = {a.by for a in approvals if a.digest == plan.digest and a.by in ten.approvers}
    stale = [a.by for a in approvals if a.digest != plan.digest]
    if stale:
        problems.append(f"approval(s) from {', '.join(stale)} were for a different plan")
    for act, target in plan.steps:
        spec = actions().get(act)
        if spec is None:
            problems.append(f"{act}: not in the authority registry")
            continue
        if spec["stage"] >= 4 or spec["stage"] > registry()["max_stage"]:
            problems.append(f"{act}: stage {spec['stage']} is above the allowed maximum")
        if len(good) < spec["approvals"]:
            problems.append(f"{act} on {target}: needs {spec['approvals']} approval(s) from tenant approvers, has {len(good)}")
        missing = set(spec["evidence"]) - plan.evidence
        if missing:
            problems.append(f"{act} on {target}: missing evidence {sorted(missing)}")
        if plan.agree < spec["min_agree"] or plan.confidence < spec["min_confidence"]:
            problems.append(
                f"{act} on {target}: consensus {plan.agree}/4 at {plan.confidence:.2f} is below {spec['min_agree']}/4 at {spec['min_confidence']}"
            )
        if target in ten.break_glass:
            problems.append(f"{act} on {target}: break-glass accounts are never contained automatically")
    return problems


def effects(act: str, target: str) -> list[tuple[str, object]]:
    e = actions()[act]["effect"]
    return [(x["key"].format(target=target), x["value"]) for x in (e if isinstance(e, list) else [e])]


def execute(plan: Plan, approvals: list[Approval], state: dict) -> list[Outcome]:
    problems = check_plan(plan, approvals)
    if problems:
        return [Outcome(a, t, "refused", "; ".join(problems)) for a, t in plan.steps]
    out = []
    for act, target in plan.steps:
        before = {}
        for k, v in effects(act, target):
            before[k] = state.get(k)
            state[k] = v
        out.append(Outcome(act, target, "executed", "dry-run against simulated state", before))
    return out


def verify(outcomes: list[Outcome], state: dict, drift: Drift | None = None) -> list[str]:
    """Re-check each executed action at its verify_after minutes; returns human cases opened for failures."""
    drift = drift or Drift()
    opened = []
    minutes = sorted({m for o in outcomes if o.status == "executed" for m in actions()[o.action]["verify_after"]})
    for m in minutes:
        drift.apply(state, m)
        for o in outcomes:
            if o.status != "executed" or m not in actions()[o.action]["verify_after"]:
                continue
            for k, v in effects(o.action, o.target):
                ok = state.get(k) == v
                o.checks.append((m, ok, f"{k} = {state.get(k)}"))
                if not ok and not any(o.action in c and o.target in c for c in opened):
                    opened.append(f"verification failed at T+{m} min: {o.action} on {o.target} ({k} is {state.get(k)}): human case opened")
    return opened


def undo_plan(outcomes: list[Outcome]) -> list[tuple[str, object, str]]:
    return [(k, b, actions()[o.action]["undo"]) for o in reversed(outcomes) if o.status == "executed" for k, b in o.before.items()]


def undo(outcomes: list[Outcome], state: dict) -> None:
    for k, before, _ in undo_plan(outcomes):
        if before is None:
            state.pop(k, None)
        else:
            state[k] = before


def promote(action: str, verified_runs: int, failed: int, apply: bool = False) -> str:
    spec, rule = actions()[action], registry()["promotion"]
    nxt = spec["stage"] + 1
    if verified_runs < rule["min_verified_runs"] or failed > rule["max_failed_verifications"]:
        return f"{action}: stays at stage {spec['stage']} ({verified_runs} verified run(s), {failed} failed)"
    if nxt >= 4:
        if apply:
            raise PermissionError(f"{action}: stage 4 (no approval) can be proposed for a person to decide, never applied by code")
        return f"{action}: stage 4 proposed for a person to decide (not applied; containment stays approval-gated)"
    return f"{action}: stage {nxt} proposed for a person to decide"


# --------------------------------------------------------------------------- scenarios
def _state(tenant: str) -> dict:
    return {"user:dana.ruiz@orchidvalley.example:enabled": True, "user:dana.ruiz@orchidvalley.example:sessions": 3,
            "mailbox:gus.moreau@orchidvalley.example:hiding_rule": True, "grant:gus.moreau@orchidvalley.example:active": True,
            "agent:ap-invoice-assistant:identity_enabled": True, "agent:ap-invoice-assistant:tool_connections": 3,
            "agent:ap-invoice-assistant:credential_valid": True}  # fmt: skip


def scenarios() -> list[dict]:
    t = "orchidvalley"
    ap = get(t).approvers
    out = []
    # 1 account takeover: disable + revoke; directory sync re-enables the account at T+30, so T+60 fails
    plan = Plan(t, "ITDR-001", [("revoke_sessions", "dana.ruiz@orchidvalley.example"), ("disable_user", "dana.ruiz@orchidvalley.example")],
                {"account_entity", "true_positive_verdict"}, 3, 0.95)  # fmt: skip
    state = _state(t)
    start = digest(state)
    res = execute(plan, [Approval(ap[0], plan.digest)], state)
    cases = verify(res, state, Drift([("user:dana.ruiz@orchidvalley.example:enabled", 30, True, None)]))
    undo(res, state)
    out.append(
        {
            "name": "account takeover; directory sync re-enables the user",
            "plan": plan,
            "outcomes": res,
            "cases": cases,
            "undo_restores": digest(state) == start,
        }
    )
    # 2 inbox rule removed but OAuth app still holds a grant and re-creates it; with the grant revoked it stays gone
    for with_grant in (False, True):
        steps = [("remove_inbox_rule", "gus.moreau@orchidvalley.example")] + (
            [("revoke_oauth_grant", "gus.moreau@orchidvalley.example")] if with_grant else []
        )
        plan = Plan(t, "ITDR-002", steps, {"account_entity"}, 3, 0.9)
        state = _state(t)
        start = digest(state)
        res = execute(plan, [Approval(ap[0], plan.digest)], state)
        cases = verify(
            res, state, Drift([("mailbox:gus.moreau@orchidvalley.example:hiding_rule", 20, True, "grant:gus.moreau@orchidvalley.example:active")])
        )
        undo(res, state)
        name = "inbox rule removed and app grant revoked" if with_grant else "inbox rule removed, app grant left in place"
        out.append({"name": name, "plan": plan, "outcomes": res, "cases": cases, "undo_restores": digest(state) == start})
    # 3 refused plans: no approval; approval bound to another plan
    plan = Plan(t, "ITDR-003", [("disable_user", "kai.lund@orchidvalley.example")], {"account_entity", "true_positive_verdict"}, 3, 0.9)
    out.append({"name": "no approval", "plan": plan, "outcomes": execute(plan, [], _state(t)), "cases": [], "undo_restores": True})
    out.append(
        {
            "name": "approval for a different plan",
            "plan": plan,
            "outcomes": execute(plan, [Approval(ap[0], "0" * 16)], _state(t)),
            "cases": [],
            "undo_restores": True,
        }
    )
    out.append(agent_scenario())
    return out


def agent_scenario() -> dict:
    """A synthetic Microsoft Foundry agent follows an injected instruction and tries to send invoices to an outside address."""
    t = "orchidvalley"
    ap = get(t).approvers
    signals = ["guardrail blocked 4 tool calls to send_email with an external recipient in 10 minutes",
               "prompt shield flagged an instruction hidden in an uploaded invoice", "agent asked for a tool outside its allow-list (export_all_invoices)"]  # fmt: skip
    plan = Plan(t, "AGENT-001", [("quarantine_ai_agent", "ap-invoice-assistant")], {"agent_entity", "guardrail_violation"}, 3, 0.92)
    state = _state(t)
    start = digest(state)
    one = execute(plan, [Approval(ap[0], plan.digest)], copy.deepcopy(state))  # one approval is not enough for this action
    res = execute(plan, [Approval(ap[0], plan.digest), Approval(ap[1], plan.digest)], state)
    cases = verify(res, state)
    undo(res, state)
    return {"name": "AI agent quarantine (Microsoft Foundry agent, two approvals)", "plan": plan, "outcomes": res, "cases": cases,
            "undo_restores": digest(state) == start, "signals": signals, "one_approval": one}  # fmt: skip


def evaluate() -> dict:
    sc = scenarios()
    outs = [o for s in sc for o in s["outcomes"]]
    return {
        "actions_in_registry": len(actions()),
        "actions_at_stage_4": sum(a["stage"] >= 4 for a in actions().values()),
        "scenarios": len(sc),
        "actions_executed_dry_run": sum(o.status == "executed" for o in outs),
        "actions_refused": sum(o.status == "refused" for o in outs),
        "verification_failures_caught": sum(len(s["cases"]) for s in sc),
        "undo_restores_exact_state": f"{sum(s['undo_restores'] for s in sc)}/{len(sc)}",
        "agent_quarantine_with_one_approval": sc[-1]["one_approval"][0].status,
    }


def report() -> str:
    lines = ["Authority registry (config/authority.yaml)", ""]
    lines.append(f"  {'action':<28}{'stage':<7}{'owner':<19}{'approvals':<11}blast radius")
    for name, a in actions().items():
        lines.append(f"  {name:<28}{a['stage']:<7}{a['owner']:<19}{a['approvals']:<11}{a['blast_radius']}")
    lines += ["", "Scenarios (simulated tenant state, dry run):"]
    for s in scenarios():
        lines.append(f"- {s['name']}  [plan {s['plan'].digest}]")
        for sig in s.get("signals", []):
            lines.append(f"    signal: {sig}")
        if "one_approval" in s:
            lines.append(f"    with one approval: {s['one_approval'][0].status} ({s['one_approval'][0].reason})")
        for o in s["outcomes"]:
            lines.append(f"    {o.status}: {o.action} on {o.target}" + (f" ({o.reason})" if o.status == "refused" else ""))
            for m, ok, what in o.checks:
                lines.append(f"      verify T+{m}: {'ok' if ok else 'FAILED'} ({what})")
        lines += [f"    {c}" for c in s["cases"]]
        if any(o.status == "executed" for o in s["outcomes"]):
            lines.append(f"    undo plan restores the starting state exactly: {s['undo_restores']}")
    lines += [
        "",
        "Promotion check:",
        "  " + promote("revoke_sessions", 6, 0),
        "  " + promote("reset_password", 6, 0),
        "  " + promote("disable_user", 6, 1),
    ]
    lines += ["", "Measured (simulated):"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
