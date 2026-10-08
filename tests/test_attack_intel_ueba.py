"""ATT&CK mapping and coverage, threat-intel decay, and behaviour baselines."""

from datetime import timedelta

import pytest

from aisoc import attack, intel, ueba
from aisoc.detections import Alert, rules
from aisoc.store import load
from aisoc.synth import T0


def _alert(**fields):
    return Alert("x", "brightwater", "test", "test", "Low", T0, [], [], [], [], fields)


@pytest.mark.parametrize(
    "fields,tech",
    [
        ({"ProcessCommandLine": "powershell -enc AAAA"}, "T1059.001"),
        ({"ProcessCommandLine": "rundll32 comsvcs.dll, MiniDump 624"}, "T1003.001"),
        ({"ProcessCommandLine": "vssadmin delete shadows /all"}, "T1490"),
        ({"InitiatingProcessFileName": "winword.exe"}, "T1204.002"),
        ({"Destination": "collect@mailbox-drop.example"}, "T1114.003"),
        ({"Description": "A message was removed after delivery."}, "T1566.002"),
    ],
)
def test_mapper_infers_techniques_from_content(fields, tech):
    assert tech in attack.map_alert(_alert(**fields))


def test_parent_dropped_when_sub_technique_present():
    a = Alert("x", "t", "s", "n", "Low", T0, ["T1059", "T1059.001"], [], [], [], {})
    assert attack.map_alert(a) == ["T1059.001"]


def test_every_rule_technique_is_in_the_catalogue():
    cat = attack.catalogue()
    for r in rules():
        for t in r["techniques"]:
            assert t in cat or t.split(".")[0] in cat, (r["id"], t)


def test_coverage_is_computed_not_claimed():
    cov = attack.coverage()
    assert len(cov["priority"]) == 21
    assert len(cov["covered"]) + len(cov["missing"]) == 21
    assert "T1486" in cov["missing"]  # encryption impact has no detection here: an honest gap


def test_navigator_layer_shape():
    layer = attack.navigator_layer()
    assert layer["domain"] == "enterprise-attack" and len(layer["techniques"]) == 21
    assert {t["score"] for t in layer["techniques"]} <= {0, 1}


def test_ti_confidence_decays_and_expires():
    ind = next(i for i in intel.indicators() if i["id"] == "ind-0007")
    assert intel.effective_confidence(ind, 0) > intel.effective_confidence(ind, 6) > 0
    assert intel.effective_confidence(ind, 8) == 0


@pytest.mark.parametrize("kind,value", [("url", "https://login-verify.example/reset"), ("mailbox", "x@mailbox-drop.example"), ("ip", "203.0.113.140")])
def test_ti_lookup_matches_on_domain_or_value(kind, value):
    assert intel.lookup(kind, value, 10)


def test_ti_lookup_misses_unknown_and_corporate():
    assert not intel.lookup("ip", "198.51.100.101", 10)
    assert not intel.lookup("url", "https://intranet.brightwater.example/", 10)


def test_ti_table_has_sentinel_columns():
    row = intel.table(10)[0]
    for col in ("IndicatorId", "NetworkIP", "DomainName", "ConfidenceScore", "Active", "ExpirationDateTime"):
        assert col in row


def test_insider_burst_is_anomalous():
    s = load("brightwater")
    day = T0 + timedelta(days=19)
    a = ueba.score_user(s, "jordan.yardley@brightwater.example", day, day + timedelta(days=1))
    assert a.score >= 0.5 and a.external_uploads == 6 and any("external uploads" in r for r in a.reasons)


def test_data_engineer_is_normal_once_baselined():
    s = load("brightwater")
    day = T0 + timedelta(days=17)
    a = ueba.score_user(s, "parker.draycott@brightwater.example", day, day + timedelta(days=1))
    assert a.score < 0.3, a.reasons


def test_new_country_is_flagged():
    s = load("pinecrest")
    day = T0 + timedelta(days=20)
    a = ueba.score_user(s, "bellamy.hartwell@pinecrest.example", day, day + timedelta(days=1))
    assert a.new_country == "VN"
