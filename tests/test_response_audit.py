"""Containment: human approval, least privilege, dry run by default, and a tamper-evident audit trail."""

import copy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import case

from aisoc import response
from aisoc.audit import AuditLog
from aisoc.response import EXECUTOR_PERMISSIONS, Approval, LiveExecutor, PolicyViolation, catalogue
from aisoc.store import load

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def ov_plan(learning):
    c = case(learning, "orchidvalley", "INC-OR-032")
    return load("orchidvalley"), c.plan, c.incident.end


def test_benign_incidents_get_no_plan(learning):
    for c in learning.cases():
        if c.plan and c.incident.verdict != "true_positive":
            assert not c.plan.actions


def test_only_catalogue_actions_are_planned(learning):
    for c in learning.cases():
        if c.plan:
            assert {a.action for a in c.plan.actions} <= set(catalogue())


@pytest.mark.parametrize(
    "approver,digest,delay,ok",
    [
        ("ciso@orchidvalley.example", None, 10, True),
        ("agent:response", None, 10, False),
        ("soc.lead@brightwater.example", None, 10, False),
        ("ciso@orchidvalley.example", "0" * 16, 10, False),
        ("ciso@orchidvalley.example", None, 61, False),
    ],
)
def test_approval_rules(ov_plan, approver, digest, delay, ok):
    store, plan, at = ov_plan
    got, _ = response.validate_approvals(store, plan, [Approval(approver, digest or plan.digest, True, at + timedelta(minutes=delay))], at)
    assert got is ok


def test_dual_control_needs_two_distinct_approvers(ov_plan):
    store, plan, at = ov_plan
    dual = replace(plan, actions=[replace(a, approvals_required=2) for a in plan.actions])
    one = Approval("ciso@orchidvalley.example", dual.digest, True, at)
    assert not response.validate_approvals(store, dual, [one, one], at)[0]
    two = [Approval(a, dual.digest, True, at) for a in store.tenant.approvers[:2]]
    assert response.validate_approvals(store, dual, two, at)[0]


def test_a_rejection_blocks_the_plan(ov_plan):
    store, plan, at = ov_plan
    apps = [
        Approval("ciso@orchidvalley.example", plan.digest, True, at),
        Approval("it.manager@orchidvalley.example", plan.digest, False, at, "wrong host"),
    ]
    assert not response.validate_approvals(store, plan, apps, at)[0]


def test_changed_plan_invalidates_approval(ov_plan):
    store, plan, at = ov_plan
    approval = Approval("ciso@orchidvalley.example", plan.digest, True, at)
    changed = replace(plan, actions=plan.actions[:-1])
    assert changed.digest != plan.digest and not response.validate_approvals(store, changed, [approval], at)[0]


@pytest.mark.parametrize(
    "action,target",
    [
        ("disable_user", "breakglass01@brightwater.example"),
        ("disable_user", "ciso@orchidvalley.example"),
        ("isolate_host", "PCU-DC01"),
        ("delete_mailbox", "a@brightwater.example"),
    ],
)
def test_policy_refusals(action, target):
    with pytest.raises(PolicyViolation):
        response.check_policy(load("brightwater"), action, target)


def test_execution_is_a_dry_run_by_default(ov_plan):
    store, plan, at = ov_plan
    log = AuditLog("orchidvalley")
    recs = response.execute(store, plan, True, log, at)
    assert recs and all(r.mode == "dry-run" and r.status == "recorded" for r in recs)
    assert len(log.events("containment.executed")) == len(plan.actions)


def test_unapproved_plan_executes_nothing(ov_plan):
    store, plan, at = ov_plan
    log = AuditLog("orchidvalley")
    assert response.execute(store, plan, False, log, at) == [] and log.events("containment.skipped")


def test_live_mode_is_not_implemented(ov_plan, monkeypatch):
    store, plan, at = ov_plan
    monkeypatch.setenv("AISOC_EXECUTE", "live")
    with pytest.raises(NotImplementedError):
        response.execute(store, plan, True, AuditLog("orchidvalley"), at)
    with pytest.raises(NotImplementedError):
        LiveExecutor().run(plan.actions[0])


def test_executor_holds_exactly_one_permission_per_action():
    assert set(EXECUTOR_PERMISSIONS) == set(catalogue())
    for name, spec in catalogue().items():
        assert EXECUTOR_PERMISSIONS[name] == {spec["permission"]}


def test_infrastructure_never_grants_containment_permissions():
    text = "\n".join(p.read_text() for p in (ROOT / "infra").rglob("*") if p.is_file() and p.suffix in (".tf", ".bicep", ".hcl", ".tfvars"))
    for spec in catalogue().values():
        assert spec["permission"] not in text


def test_runs_record_human_approval_before_every_execution(learning):
    for tr in learning.tenants.values():
        seen_approval = set()
        for r in tr.audit.records:
            if r["event"] == "approval.decided" and r["data"]["approved"]:
                seen_approval.add(r["data"]["incident"])
            if r["event"] == "containment.executed":
                assert r["data"]["incident"] in seen_approval


def test_audit_chain_detects_edit_delete_and_reorder(learning):
    log = learning.tenants["pinecrest"].audit
    assert log.verify()[0]
    edited = copy.deepcopy(log)
    edited.records[5]["data"]["tool"] = "something_else"
    assert not edited.verify()[0]
    deleted = copy.deepcopy(log)
    del deleted.records[3]
    assert not deleted.verify()[0]
    swapped = copy.deepcopy(log)
    swapped.records[2], swapped.records[3] = swapped.records[3], swapped.records[2]
    assert not swapped.verify()[0]


def test_audit_chain_rejects_foreign_tenant_records():
    log = AuditLog("brightwater")
    log.append("x", "e", {})
    forged = copy.deepcopy(log)
    forged.tenant = "pinecrest"
    assert not forged.verify()[0]
