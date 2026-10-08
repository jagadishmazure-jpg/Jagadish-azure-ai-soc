"""Response agent: containment planning, approval and execution.

The planner proposes actions from the catalogue in config/actions.yaml. Nothing runs until people approve:

* every action needs an approver from the tenant's approver list; agents can never approve;
* an action on a privileged account or a crown-jewel host needs two different approvers (dual control);
* an approval is bound to the plan digest, so a plan changed after approval is not approved;
* approvals expire after APPROVAL_TTL;
* break-glass accounts can never be disabled, and a target must belong to the incident's tenant;
* the executor identity holds exactly one permission per action (least privilege), checked per call;
* execution is a dry run by default: the Graph or Defender request is recorded, not sent. AISOC_EXECUTE=live
  reaches `LiveExecutor`, which is intentionally not implemented in this repository.

Every step is written to the tenant's audit chain."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from functools import cache

import yaml

from aisoc import CONFIG
from aisoc.audit import AuditLog
from aisoc.investigation import Investigation
from aisoc.store import TenantStore
from aisoc.triage import Incident

APPROVAL_TTL = timedelta(minutes=60)
EXECUTOR_PERMISSIONS = {  # the containment executor's identity: one permission per catalogue action, nothing else
    "disable_user": {"User.EnableDisableAccount.All"},
    "revoke_sessions": {"User.RevokeSessions.All"},
    "isolate_host": {"Machine.Isolate"},
    "block_ip": {"Ti.ReadWrite.All"},
}


@cache
def catalogue() -> dict[str, dict]:
    return yaml.safe_load((CONFIG / "actions.yaml").read_text())["actions"]


class PolicyViolation(PermissionError):
    pass


@dataclass(frozen=True)
class PlannedAction:
    action: str
    target: str
    reason: str
    evidence: tuple[str, ...]
    approvals_required: int
    permission: str
    request: str


@dataclass
class ContainmentPlan:
    incident_id: str
    tenant: str
    actions: list[PlannedAction]
    denied: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        body = json.dumps([asdict(a) for a in self.actions], sort_keys=True)
        return hashlib.sha256(f"{self.tenant}|{self.incident_id}|{body}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Approval:
    approver: str
    plan_digest: str
    approved: bool
    at: datetime
    reason: str = ""


@dataclass(frozen=True)
class ExecutionRecord:
    action: str
    target: str
    mode: str
    status: str
    request: str


def _owns(store: TenantStore, kind: str, target: str) -> bool:
    t = store.tenant
    if kind == "account":
        return target.lower().endswith("@" + t.domain)
    if kind == "host":
        return target.upper().startswith(t.prefix + "-")
    return True


def check_policy(store: TenantStore, action: str, target: str) -> None:
    cat = catalogue()
    if action not in cat:
        raise PolicyViolation(f"{action} is not in the action catalogue")
    kind = cat[action]["target"]
    if kind in ("account", "host") and not _owns(store, kind, target):
        raise PolicyViolation(f"{target} does not belong to tenant {store.tenant.id}")
    if action == "disable_user" and target in store.tenant.break_glass:
        raise PolicyViolation(f"{target} is a break-glass account and is never disabled")


def plan(store: TenantStore, inc: Incident, inv: Investigation) -> ContainmentPlan:
    """Propose containment for a malicious incident. Benign incidents get an empty plan."""
    p = ContainmentPlan(inc.id, inc.tenant, [])
    if inc.verdict != "true_positive":
        return p
    users = store.users()
    t = store.tenant
    cat = catalogue()
    wanted: list[tuple[str, str, str]] = []
    for acct in inv.scope["accounts"]:
        wanted.append(("revoke_sessions", acct, "account active during the incident"))
        wanted.append(("disable_user", acct, "account compromised or misused"))
    for host in inv.scope["hosts"]:
        wanted.append(("isolate_host", host, "host ran the malicious chain"))
    for ip in inv.scope["external_ips"]:
        if ip not in t.authorized_scanners and ip not in t.vpn_ips:
            wanted.append(("block_ip", ip, "attacker infrastructure"))
    for action, target, reason in wanted:
        try:
            check_policy(store, action, target)
        except PolicyViolation as exc:
            p.denied.append(str(exc))
            continue
        sensitive = users.get(target, {}).get("IsPrivileged") or target in t.crown_jewels
        ev = tuple(e.id for e in inv.evidence if target.lower() in e.summary.lower())[:5]
        p.actions.append(
            PlannedAction(
                action, target, reason, ev, 2 if sensitive else 1, cat[action]["permission"], cat[action]["request"].replace("{target}", target)
            )
        )
    return p


def validate_approvals(store: TenantStore, p: ContainmentPlan, approvals: list[Approval], requested_at: datetime) -> tuple[bool, list[str]]:
    """True when every action has enough valid approvals. Problems are returned, never raised."""
    problems = []
    valid = []
    for a in approvals:
        if a.approver.startswith("agent:"):
            problems.append(f"{a.approver}: agents cannot approve containment")
        elif a.approver not in store.tenant.approvers:
            problems.append(f"{a.approver}: not an approver for {store.tenant.id}")
        elif a.plan_digest != p.digest:
            problems.append(f"{a.approver}: approval is for plan {a.plan_digest}, current plan is {p.digest}")
        elif a.at - requested_at > APPROVAL_TTL:
            problems.append(f"{a.approver}: approval expired")
        elif not a.approved:
            problems.append(f"{a.approver}: rejected ({a.reason})")
        else:
            valid.append(a.approver)
    distinct = len(set(valid))
    need = max((x.approvals_required for x in p.actions), default=0)
    if p.actions and distinct < need:
        problems.append(f"{distinct} valid approval(s); this plan needs {need}")
    return (bool(p.actions) and distinct >= need and not any("rejected" in x for x in problems)), problems


class LiveExecutor:
    def run(self, action: PlannedAction) -> ExecutionRecord:
        raise NotImplementedError("live containment is intentionally not implemented; this repository records requests only")


def execute(
    store: TenantStore, p: ContainmentPlan, approved: bool, audit: AuditLog, at: datetime, identity: str = "svc:containment-executor"
) -> list[ExecutionRecord]:
    mode = os.environ.get("AISOC_EXECUTE", "dry-run")
    out = []
    if not approved:
        audit.append(identity, "containment.skipped", {"incident": p.incident_id, "digest": p.digest, "reason": "not approved"}, at)
        return out
    for a in p.actions:
        check_policy(store, a.action, a.target)
        if a.permission not in EXECUTOR_PERMISSIONS.get(a.action, set()):
            raise PolicyViolation(f"executor lacks {a.permission} for {a.action}")
        if mode == "live":
            rec = LiveExecutor().run(a)
        else:
            rec = ExecutionRecord(a.action, a.target, "dry-run", "recorded", a.request)
        audit.append(identity, "containment.executed", {"incident": p.incident_id, "digest": p.digest, **asdict(rec)}, at)
        out.append(rec)
    return out
