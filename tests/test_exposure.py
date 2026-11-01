"""Exposure context: criticality with overrides, known-exploited findings, attack paths and choke points."""

import pytest

from aisoc import exposure as x
from aisoc import pipeline


@pytest.fixture(scope="module")
def run():
    return pipeline.run("learning")


def test_crown_jewel_is_ten():
    assert x.context("brightwater", "host", "BWL-DC01").criticality == 10


def test_override_wins_and_is_attributed():
    c = x.context("brightwater", "host", "BWL-SRV02")
    assert c.criticality == 2 and "override by it.director@brightwater.example" in c.criticality_source


def test_override_can_raise():
    assert x.context("orchidvalley", "host", "OVC-WS008").criticality == 7


def test_kev_findings_listed():
    assert x.context("brightwater", "host", "BWL-SRV03").kev_open == ("SYN-SMB-0907",)


def test_non_kev_finding_not_counted():
    assert x.context("brightwater", "host", "BWL-ERP01").kev_open == ()


def test_attack_path_found():
    c = x.context("brightwater", "host", "BWL-WS07")
    assert c.on_attack_path and c.path == ("BWL-WS07", "BWL-SRV03", "BWL-ADM01", "BWL-DC01")


def test_no_path_for_isolated_host():
    assert not x.context("brightwater", "host", "BWL-SRV02").on_attack_path


@pytest.mark.parametrize(
    "acct,crit",
    [
        ("soc.lead@brightwater.example", 9),
        ("breakglass01@brightwater.example", 9),
        ("svc.backup@brightwater.example", 7),
        ("tom.baker@brightwater.example", 3),
    ],
)
def test_account_criticality(acct, crit):
    assert x.context("brightwater", "account", acct).criticality == crit


def test_boost_is_bounded():
    for h in x.config()["tenants"]["brightwater"]["hosts"]:
        assert 0 <= x.context("brightwater", "host", h).boost <= x.MAX_BOOST


def test_choke_points_ranked():
    cp = x.choke_points("brightwater")
    assert cp[0] == ("BWL-BKP01", 2)
    assert [n for _, n in cp] == sorted([n for _, n in cp], reverse=True)


def test_crown_jewels_never_choke_points():
    for t in ("brightwater", "orchidvalley", "pinecrest"):
        assert not any(h.endswith(("DC01", "ERP01", "EHR01", "CORE01")) for h, _ in x.choke_points(t))


def test_context_never_changes_verdict_or_tier(run):
    ev = x.evaluate(run)
    assert ev["verdicts_or_tiers_changed"] == 0
    assert ev["true_positives_in_top_slots_after"] == ev["true_positives_in_top_slots_before"]


def test_queue_contains_only_escalated(run):
    q = x.queue(run, "pinecrest")
    assert all(r["case"].route.tier >= 2 for r in q)
    assert sorted(r["rank_after"] for r in q) == list(range(1, len(q) + 1))
