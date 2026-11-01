"""Identity threat pack: token replay, consent phishing, device code, legacy auth and hidden inbox rules."""

import ipaddress

import pytest

from aisoc import itdr


@pytest.fixture(scope="module")
def m():
    return itdr.evaluate()


@pytest.fixture(scope="module")
def data():
    return itdr.generate()


def test_every_story_detected(m):
    assert m["stories_detected"] == "4/4"


def test_known_false_positive_is_reported_not_hidden(m):
    assert m["false_positive_alerts"] == 1
    assert m["lookalike_kinds_alerting"] == ["traveller-commercial-vpn"]


def test_precision_is_measured(m):
    assert m["precision"] == pytest.approx(10 / 11, abs=1e-3)


def test_ten_lookalike_kinds(m):
    assert m["lookalike_kinds"] == 10


@pytest.mark.parametrize(
    "rule",
    ["token-replay", "oauth-consent-risky", "device-code-signin", "legacy-auth-signin", "hosting-or-vpn-signin", "inbox-rule-hides-security-mail"],
)
def test_every_rule_has_a_query_file(rule):
    r = next(x for x in itdr.rules() if x["id"] == rule)
    assert (itdr.RULES_DIR / r["file"]).exists()


def test_generation_is_deterministic():
    a, b = itdr.generate(), itdr.generate()
    assert a is b or a.tables == b.tables


def test_cases_group_by_account(data):
    cs = itdr.cases(itdr.detect(data))
    assert len(cs) == 5
    for c in cs:
        assert {a.entity for a in c.alerts} == {c.entity}


def test_token_replay_case_has_three_stages(data):
    c = itdr.cases(itdr.detect(data))[0]
    assert {a.rule for a in c.alerts} >= {"token-replay", "inbox-rule-hides-security-mail"}


def test_allow_listed_meeting_room_device_code_does_not_alert(data):
    alerts = itdr.detect(data)
    assert not any(a.entity.startswith("room-") for a in alerts)


def test_listed_printer_smtp_does_not_alert(data):
    assert not any(a.entity.startswith("scan-to-email") for a in itdr.detect(data))


def test_addresses_are_documentation_or_private(data):
    for r in data.tables["SigninLogs"]:
        ip = ipaddress.ip_address(r["IPAddress"])
        assert ip.is_private or any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def test_plans_contain_only_registered_actions(data):
    from aisoc import authority

    for c in itdr.cases(itdr.detect(data)):
        for act, _ in itdr.plan_actions(c, data):
            assert act in authority.actions()


def test_report_mentions_no_execution():
    out = itdr.report()
    assert "approval" in out.lower()
