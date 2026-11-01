"""Log-filter cost simulation, service tiers with SLAs, monthly client reports and the new CLI commands."""

import subprocess
import sys

import pytest

from aisoc import monthly, pipeline, smartfilter, tiers

TENANTS = ("pinecrest", "brightwater", "orchidvalley")


@pytest.fixture(scope="module")
def sf():
    return smartfilter.evaluate()


def test_filter_that_hides_a_canary_is_rejected(sf):
    assert set(sf["rejected"]) == {"internal-mail-no-url-no-threat", "browser-https"}


def test_accepted_filters_lose_no_alerts(sf):
    assert sf["accepted"] == ["office-apps-from-explorer"] and sf["alerts_lost_with_accepted_filters"] == 0


def test_savings_are_modelled_and_bounded(sf):
    for v in sf["modelled_saving_pct"].values():
        assert 0 < v < 100


def test_prices_are_labelled_assumptions():
    assert "assum" in str(smartfilter.config()).lower()


def test_replay_of_no_filters_loses_nothing():
    assert all(v == [] for v in smartfilter.replay([]).values())


def test_three_tiers_one_per_tenant():
    names = {tiers.tier_of(t)["name"] for t in ("pinecrest", "brightwater", "orchidvalley")}
    assert names == {"Essentials", "Standard", "Plus"}


def test_higher_tier_has_tighter_slas():
    c = tiers.config()["tiers"]
    order = sorted(c.values(), key=lambda t: t["sla_min"]["mttd"], reverse=True)
    assert [t["name"] for t in order] == ["Essentials", "Standard", "Plus"]
    for k in ("ack", "mttr"):
        assert [t["sla_min"][k] for t in order] == sorted([t["sla_min"][k] for t in order], reverse=True)


def test_breaches_reported_not_hidden():
    run = pipeline.run("learning")
    total = sum(len(tiers.sla(run, t)["breaches"]) for t in ("pinecrest", "brightwater", "orchidvalley"))
    assert total > 0


@pytest.mark.parametrize("tenant", ["pinecrest", "brightwater", "orchidvalley"])
def test_monthly_report_formats(tenant, tmp_path):
    paths = monthly.write(tenant, tmp_path)
    assert sorted(p.suffix for p in paths) == [".csv", ".html", ".md"]
    md = (tmp_path / f"{tenant}.md").read_text()
    assert "preview" in md.lower() and "synthetic" in md.lower()


@pytest.mark.parametrize("tenant", ["pinecrest", "brightwater", "orchidvalley"])
def test_monthly_report_isolated_to_one_tenant(tenant):
    others = [t for t in TENANTS if t != tenant]
    text = monthly.to_markdown(monthly.build(tenant)) + monthly.to_csv(monthly.build(tenant))
    for o in others:
        assert f"@{o}.example" not in text


def test_monthly_html_escapes():
    r = monthly.build("pinecrest")
    r = {**r, "customer": "<script>x</script>"}
    assert "<script>" not in monthly.to_html(r)


def test_monthly_has_no_send_path():
    assert not any(n for n in dir(monthly) if "send" in n.lower() or "mail" in n.lower())


@pytest.mark.parametrize(
    "args",
    [
        ["itdr"],
        ["endpoint"],
        ["consensus"],
        ["smart-filter"],
        ["tiers"],
        ["authority"],
        ["exposure"],
        ["timeline"],
        ["search", "show logins for tom.baker@brightwater.example last 72 hours"],
        ["monthly-report", "--tenant", "pinecrest"],
        ["gate"],
    ],
)
def test_cli_commands_exit_zero(args):
    r = subprocess.run([sys.executable, "-m", "aisoc.cli", *args], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr


def test_gate_includes_pack_checks():
    r = subprocess.run([sys.executable, "-m", "aisoc.cli", "gate"], capture_output=True, text=True, timeout=300)
    assert "PASS (18/18)" in r.stdout
