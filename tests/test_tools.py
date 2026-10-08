"""The Sentinel-shaped tool gateway: entitlement, template-only KQL for agents, caps and auditing."""

from datetime import timedelta

import pytest

from aisoc import tools as tools_mod
from aisoc.audit import AuditLog
from aisoc.store import load
from aisoc.tools import MAX_ROWS, SentinelTools, ToolDenied, render_template, templates

UPN = "hollis.lockwood@brightwater.example"


def gw(identity="agent:investigation", tenant="brightwater"):
    s = load(tenant)
    return SentinelTools(s, identity, AuditLog(tenant), s.now - timedelta(hours=1))


@pytest.mark.parametrize(
    "param,value",
    [
        ("upn", UPN + '" | take 1000 //'),
        ("upn", "someone@gmail.test"),
        ("lookback", "48h; drop"),
        ("lookback", "99999h"),
        ("until", "-1h"),
    ],
)
def test_template_parameters_are_pattern_checked(param, value):
    params = {"upn": UPN, "lookback": "48h", "until": "0h", param: value}
    with pytest.raises(ToolDenied):
        render_template("user_signins", params)


def test_unknown_template_and_extra_parameters_are_refused():
    with pytest.raises(ToolDenied):
        render_template("drop_tables", {})
    with pytest.raises(ToolDenied):
        render_template("user_signins", {"upn": UPN, "lookback": "1h", "until": "0h", "extra": "x"})


@pytest.mark.parametrize("name", sorted(templates()["templates"]))
def test_every_template_compiles_and_runs(name):
    t = templates()["templates"][name]
    sample = {"account": {"upn": UPN}, "host": {"host": "BWL-DC01"}, "ip": {"ip": "203.0.113.77"}, "domain": {"domain": "login-verify.example"}}[
        t["entity"]
    ]
    rows = gw().query_lake(name, {**sample, "lookback": "504h", "until": "0h"})
    assert isinstance(rows, list)


def test_agents_cannot_run_raw_kql_but_analysts_can():
    with pytest.raises(ToolDenied):
        gw().query_lake(kql_text="SigninLogs | take 5")
    assert len(gw("analyst.rivera").query_lake(kql_text="SigninLogs | take 5")) == 5


def test_row_cap(monkeypatch):
    monkeypatch.setattr(tools_mod, "MAX_ROWS", 3)
    assert len(gw("analyst.rivera").query_lake(kql_text="SigninLogs | take 50")) == 3
    assert MAX_ROWS == 200


def test_tool_allow_list_per_identity():
    with pytest.raises(ToolDenied):
        gw("agent:triage").query_lake("user_signins", {"upn": UPN, "lookback": "1h", "until": "0h"})
    with pytest.raises(ToolDenied):
        gw("customer.brightwater.viewer").analyze_user_entity(UPN)


def test_every_call_is_audited_including_denials():
    g = gw()
    g.list_sentinel_workspaces()
    with pytest.raises(ToolDenied):
        g.query_lake("user_signins", {"upn": UPN, "lookback": "1h", "until": "0h"}, workspace="law-soc-pinecrest")
    events = [r["event"] for r in g.audit.records]
    assert events == ["tool.call", "tool.denied"] and g.audit.verify()[0]


def test_gateway_cannot_see_the_future():
    g = gw()
    assert all(r["TimeGenerated"] <= g.as_of for r in g.query_lake("user_signins", {"upn": UPN, "lookback": "504h", "until": "0h"}))


def test_entity_tools_return_context():
    g = gw()
    assert g.analyze_host_entity("BWL-DC01")["crown_jewel"] is True
    assert g.analyze_url_entity("https://login-verify.example/reset")["indicators"]
    assert g.analyze_user_entity(UPN)["known"] is True
    assert [t["table"] for t in g.search_tables("RemoteIP")] == ["DeviceNetworkEvents"]
