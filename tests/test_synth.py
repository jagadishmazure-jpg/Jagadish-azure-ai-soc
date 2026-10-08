"""Synthetic data: deterministic, fictional, and carrying every planted story and look-alike."""

import ipaddress
import re

import pytest

from aisoc import labels, synth
from aisoc.store import load
from aisoc.tenants import tenants

TENANTS = sorted(tenants())


@pytest.mark.parametrize("tenant", TENANTS)
def test_generation_is_deterministic(tenant):
    assert synth.fingerprint(synth.generate(tenant)) == synth.fingerprint(synth.generate(tenant))


def test_seed_changes_the_data():
    assert synth.fingerprint(synth.generate("brightwater", 1)) != synth.fingerprint(synth.generate("brightwater", 2))


@pytest.mark.parametrize("tenant", TENANTS)
def test_identities_are_fictional(tenant):
    s = load(tenant)
    for u in s.users():
        assert u.endswith(".example")
    allowed = [ipaddress.ip_network(n) for n in ("198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24", "10.0.0.0/8")]
    for r in s.tables["SigninLogs"]:
        ip = ipaddress.ip_address(r["IPAddress"])
        assert any(ip in n for n in allowed), r["IPAddress"]
    for r in s.tables["EmailEvents"]:
        assert r["SenderFromAddress"].endswith(".example")


def test_nine_stories_split_across_windows():
    st = [s for t in TENANTS for s in labels.stories(t)]
    assert len(st) == 9
    assert sum(s["window"] == "holdout" for s in st) == 5
    assert {s["kind"] for s in st} == {"phish", "spray", "ransomware", "insider", "travel"}


@pytest.mark.parametrize("tenant", TENANTS)
def test_story_clock_starts_on_story_day(tenant):
    for s in labels.stories(tenant):
        assert synth.day_of(s["first_event"]) == s["day"]


@pytest.mark.parametrize("kind", ["scanner", "admin_script", "backup", "phish_sim", "vpn_travel", "data_engineer"])
def test_every_tenant_has_each_lookalike(kind):
    for t in TENANTS:
        assert kind in set(labels.truth(t).labels.values()), (t, kind)


def test_planted_injection_and_pii_exist():
    bw = load("brightwater")
    assert any(synth.INJECTION_SUBJECT == r["Subject"] for r in bw.tables["EmailEvents"])
    ov = load("orchidvalley")
    assert any(synth.INJECTION_CMDLINE in (r.get("ProcessCommandLine") or "") for r in ov.tables["DeviceProcessEvents"])
    assert any(synth.PII_FILE == r.get("ObjectName") for r in bw.tables["CloudAppEvents"])


def test_no_real_guids_in_data():
    guid = re.compile(r"\b(?!00000000-)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    for t in TENANTS:
        for rows in load(t).tables.values():
            for r in rows[:200]:
                assert not guid.search(str(r))
