"""Authority registry, verification after action, undo plans and AI agent quarantine."""

import pytest

from aisoc import authority as au
from aisoc.tenants import get


def plan(steps, evidence=("account_entity", "true_positive_verdict"), agree=3, conf=0.95):
    return au.Plan("orchidvalley", "T-1", steps, set(evidence), agree, conf)


AP = get("orchidvalley").approvers


def test_no_action_at_stage_four():
    assert all(a["stage"] < 4 for a in au.actions().values())


def test_registry_covers_main_catalogue():
    from aisoc.response import catalogue

    assert set(catalogue()) <= set(au.actions())


@pytest.mark.parametrize("name", list(au.actions()))
def test_every_action_has_governance_fields(name):
    a = au.actions()[name]
    for k in ("stage", "owner", "approvals", "evidence", "blast_radius", "effect", "verify_after", "undo"):
        assert k in a


def test_promotion_to_stage_four_is_never_applied():
    with pytest.raises(PermissionError):
        au.promote("revoke_sessions", 10, 0, apply=True)
    assert "not applied" in au.promote("revoke_sessions", 10, 0)


def test_promotion_needs_clean_record():
    assert "stays" in au.promote("disable_user", 10, 1)
    assert "stays" in au.promote("disable_user", 2, 0)


def test_refused_without_approval():
    p = plan([("disable_user", "kai.lund@orchidvalley.example")])
    assert au.execute(p, [], {})[0].status == "refused"


def test_refused_with_approval_for_other_plan():
    p = plan([("disable_user", "kai.lund@orchidvalley.example")])
    assert au.execute(p, [au.Approval(AP[0], "f" * 16)], {})[0].status == "refused"


def test_refused_when_approver_not_from_tenant():
    p = plan([("disable_user", "kai.lund@orchidvalley.example")])
    assert au.execute(p, [au.Approval("soc.lead@brightwater.example", p.digest)], {})[0].status == "refused"


def test_refused_without_evidence():
    p = plan([("disable_user", "kai.lund@orchidvalley.example")], evidence=("account_entity",))
    assert "missing evidence" in au.execute(p, [au.Approval(AP[0], p.digest)], {})[0].reason


def test_refused_below_consensus():
    p = plan([("disable_user", "kai.lund@orchidvalley.example")], agree=1)
    assert au.execute(p, [au.Approval(AP[0], p.digest)], {})[0].status == "refused"


def test_break_glass_never_contained():
    p = plan([("disable_user", "breakglass01@orchidvalley.example")])
    assert "break-glass" in au.execute(p, [au.Approval(AP[0], p.digest)], {})[0].reason


def test_unknown_action_refused():
    p = plan([("wipe_device", "OVC-WS008")])
    assert au.execute(p, [au.Approval(AP[0], p.digest)], {})[0].status == "refused"


def test_execute_and_undo_restore_state():
    p = plan([("revoke_sessions", "a@orchidvalley.example"), ("disable_user", "a@orchidvalley.example")])
    state = {"user:a@orchidvalley.example:enabled": True, "user:a@orchidvalley.example:sessions": 2}
    start = dict(state)
    res = au.execute(p, [au.Approval(AP[0], p.digest)], state)
    assert state["user:a@orchidvalley.example:enabled"] is False
    au.undo(res, state)
    assert state == start


def test_drift_fails_verification_and_opens_case():
    p = plan([("disable_user", "a@orchidvalley.example")])
    state = {"user:a@orchidvalley.example:enabled": True}
    res = au.execute(p, [au.Approval(AP[0], p.digest)], state)
    cases = au.verify(res, state, au.Drift([("user:a@orchidvalley.example:enabled", 30, True, None)]))
    assert len(cases) == 1 and "T+60" in cases[0]
    assert [ok for _, ok, _ in res[0].checks] == [True, False]


def test_drift_stopped_by_companion_action():
    sc = {s["name"]: s for s in au.scenarios()}
    assert sc["inbox rule removed, app grant left in place"]["cases"]
    assert not sc["inbox rule removed and app grant revoked"]["cases"]


def test_agent_quarantine_needs_two_approvals():
    s = au.agent_scenario()
    assert s["one_approval"][0].status == "refused"
    assert s["outcomes"][0].status == "executed" and s["undo_restores"]


def test_agent_quarantine_cuts_identity_tools_and_credential():
    keys = {k for k, _ in au.effects("quarantine_ai_agent", "x")}
    assert keys == {"agent:x:identity_enabled", "agent:x:tool_connections", "agent:x:credential_valid"}


def test_agent_quarantine_needs_guardrail_evidence():
    p = au.Plan("orchidvalley", "A", [("quarantine_ai_agent", "x")], {"agent_entity"}, 3, 0.9)
    assert au.execute(p, [au.Approval(AP[0], p.digest), au.Approval(AP[1], p.digest)], {})[0].status == "refused"


def test_same_approver_twice_counts_once():
    p = au.Plan("orchidvalley", "A", [("quarantine_ai_agent", "x")], {"agent_entity", "guardrail_violation"}, 3, 0.9)
    assert au.execute(p, [au.Approval(AP[0], p.digest), au.Approval(AP[0], p.digest)], {})[0].status == "refused"


def test_evaluate():
    m = au.evaluate()
    assert m["undo_restores_exact_state"] == "6/6" and m["verification_failures_caught"] == 2 and m["actions_at_stage_4"] == 0
