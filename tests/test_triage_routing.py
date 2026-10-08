"""Triage: de-duplication, correlation, explainable scoring and verdicts; routing to tiers."""

from aisoc.detections import all_alerts
from aisoc.knowledge import CaseNote, KnowledgeBase
from aisoc.routing import route
from aisoc.store import load
from aisoc.triage import WEIGHTS, Learned, build_incidents, enrich_and_score, signature


def incidents(tenant):
    s = load(tenant)
    return s, build_incidents(s, all_alerts(s))


def test_product_and_rule_alerts_on_same_event_are_merged():
    _s, incs = incidents("orchidvalley")
    rw = next(i for i in incs if "ti-c2-connection" in i.sources)
    assert rw.duplicates >= 2  # Defender alerts duplicated our encoded-powershell and lsass rules
    assert {"Suspicious PowerShell command line", "Possible LSASS memory access"} <= set(rw.sources)


def test_alert_volume_is_reduced_by_grouping():
    for t in ("brightwater", "orchidvalley", "pinecrest"):
        s, incs = incidents(t)
        assert len(incs) < len(all_alerts(s))


def test_corporate_egress_never_correlates_unrelated_users():
    _s, incs = incidents("brightwater")
    for i in incs:
        assert "198.51.100.101" not in {v for a in i.alerts for v in a.entity_values("ip")} or len(i.entities("account")) <= 1


def test_spray_and_success_correlate_into_one_incident():
    _s, incs = incidents("brightwater")
    i = next(i for i in incs if "success-after-spray" in i.sources)
    assert "password-spray" in i.sources


def test_score_is_explained_term_by_term():
    s, incs = incidents("orchidvalley")
    i = next(i for i in incs if "ti-c2-connection" in i.sources)
    enrich_and_score(s, i, KnowledgeBase("orchidvalley"), Learned())
    assert i.verdict == "true_positive" and i.p_malicious > 0.9
    assert i.explanation[0].startswith("prior") and any(e.startswith("ti ") for e in i.explanation)
    assert set(i.features) >= set(WEIGHTS)


def test_vpn_context_needs_to_explain_every_alert():
    s, incs = incidents("pinecrest")
    i = next(i for i in incs if any(a.entity_values("ip") == ["203.0.113.200"] for a in i.alerts))
    enrich_and_score(s, i, KnowledgeBase("pinecrest"), Learned())
    assert i.features["context_benign"] == 0 and i.verdict == "true_positive"


def test_scanner_spray_is_benign_by_context():
    s, incs = incidents("brightwater")
    i = next(i for i in incs if i.sources == ["password-spray"] and "198.51.100.50" in i.entities("ip"))
    enrich_and_score(s, i, KnowledgeBase("brightwater"), Learned())
    assert i.verdict == "benign_positive" and route(s, i, Learned()).tier == 1


def test_analyst_case_notes_move_the_verdict():
    s, incs = incidents("brightwater")
    i = next(i for i in incs if i.sources == ["shadow-copy-delete"])
    kb = KnowledgeBase("brightwater")
    enrich_and_score(s, i, kb, Learned())
    before = i.p_malicious
    for n in range(2):
        kb.add(CaseNote("brightwater", signature(i.alerts[0]), "benign_positive", "analyst.rivera", f"INC-{n}", "backup job"))
    enrich_and_score(s, i, kb, Learned())
    assert i.p_malicious < before and i.verdict == "benign_positive"


def test_injection_attempt_routes_malicious_case_to_tier_3():
    s, incs = incidents("brightwater")
    i = next(i for i in incs if "inbox-forward-external" in i.sources)
    enrich_and_score(s, i, KnowledgeBase("brightwater"), Learned())
    r = route(s, i, Learned())
    assert i.injection and r.tier == 3 and any("injection" in x for x in r.reasons)


def test_privileged_account_is_never_auto_closed():
    s, incs = incidents("brightwater")
    i = next(i for i in incs if i.sources == ["encoded-powershell"])
    enrich_and_score(s, i, KnowledgeBase("brightwater"), Learned(auto_close={"encoded-powershell": 0.5}))
    assert route(s, i, Learned(auto_close={"encoded-powershell": 0.5})).tier == 2


def test_crown_jewel_malicious_goes_to_tier_3(monkeypatch):
    s, incs = incidents("orchidvalley")
    i = next(i for i in incs if "ti-c2-connection" in i.sources)
    enrich_and_score(s, i, KnowledgeBase("orchidvalley"), Learned())
    i.alerts[0].entities.append({"type": "host", "value": "OVC-DC01"})
    assert route(s, i, Learned()).tier == 3
    i.alerts[0].entities.pop()
