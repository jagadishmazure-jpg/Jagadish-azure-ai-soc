"""Incident timeline from the audit log, and plain-English search that shows KQL before running."""

import copy

import pytest

from aisoc import itdr, nlsearch, pipeline, timeline
from aisoc.audit import AuditLog
from aisoc.store import load
from aisoc.tools import SentinelTools, ToolDenied


@pytest.fixture(scope="module")
def audit():
    return timeline.itdr_audit()


def test_timeline_has_four_sections(audit):
    tl = timeline.build(audit, "ITDR-001", itdr.T0)
    assert list(tl["sections"]) == ["How they got in", "What they did", "What we checked", "When they were evicted"]


def test_entry_is_first_alert(audit):
    tl = timeline.build(audit, "ITDR-001", itdr.T0)
    assert len(tl["sections"]["How they got in"]) == 1
    assert "hosting-or-vpn-signin" in tl["sections"]["How they got in"][0][2]


def test_sections_sorted_by_time(audit):
    for rows in timeline.build(audit, "ITDR-001", itdr.T0)["sections"].values():
        assert [r[0] for r in rows] == sorted(r[0] for r in rows)


def test_eviction_shows_approval_before_action(audit):
    ev = [r[2] for r in timeline.build(audit, "ITDR-001", itdr.T0)["sections"]["When they were evicted"]]
    assert any("approved plan" in e for e in ev)
    assert ev.index(next(e for e in ev if "approved plan" in e)) < ev.index(next(e for e in ev if "(dry-run)" in e))


def test_tampered_log_produces_no_timeline(audit):
    bad = copy.deepcopy(audit)
    bad.records[2]["data"]["stage"] = "edited"
    with pytest.raises(ValueError):
        timeline.build(bad, "ITDR-001", itdr.T0)


def test_records_scoped_to_one_incident(audit):
    a = timeline.records_for(audit, "ITDR-001")
    b = timeline.records_for(audit, "ITDR-002")
    assert a and b and not ({r["seq"] for r in a} & {r["seq"] for r in b})


def test_main_pipeline_timeline_is_honest_about_gaps():
    run = pipeline.run("learning")
    inc = run.cases()[0].incident.id
    out = timeline.report(inc)
    assert "no audit records" in out and "verified" in out


def test_unknown_incident_raises():
    with pytest.raises(KeyError):
        timeline.report("INC-DOES-NOT-EXIST")


# ----------------------------------------------------------------------- search


def test_regression_set_all_correct():
    m = nlsearch.evaluate()
    assert m["wrong"] == [] and m["queries_run_without_confirm"] == 0


def test_kql_shown_with_values_filled():
    t = nlsearch.translate("what did tom.baker@brightwater.example sign in from in the last 2 days?")
    assert t.template == "user_signins" and "tom.baker@brightwater.example" in t.kql and "ago(48h)" in t.kql


def test_this_week_is_168h():
    assert nlsearch.translate("did jordan.yardley@brightwater.example click any link this week").params.get("lookback") == "168h"


def test_email_domain_not_taken_as_sender_domain():
    t = nlsearch.translate("which emails did hollis.lockwood@brightwater.example get?")
    assert t.template == "user_email" and "domain" not in t.params


@pytest.mark.parametrize(
    "q",
    [
        "SigninLogs | where 1 == 1",
        "union * | take 10",
        "delete all alerts",
        'show logins for "x" or 1==1',
        "what is the weather",
        "sign ins for everyone",
    ],
)
def test_refuses_raw_kql_and_unclear(q):
    assert nlsearch.translate(q).refused


def test_no_run_without_confirm():
    store = load("brightwater")
    tools = SentinelTools(store, "analyst.rivera", AuditLog("brightwater"), store.now)
    t = nlsearch.translate("show logins for tom.baker@brightwater.example last 72 hours")
    assert nlsearch.run(t, tools) is None
    assert isinstance(nlsearch.run(t, tools, confirm=True), list)


def test_refused_translation_never_runs():
    t = nlsearch.translate("union * | take 10")
    with pytest.raises(ToolDenied):
        nlsearch.run(t, None, confirm=True)
