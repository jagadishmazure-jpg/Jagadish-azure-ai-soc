"""PHP2Shell case study: detection quality, look-alikes, inventory classifier, verdicts and the approval gate."""

import ipaddress
import re
from pathlib import Path

import pytest

from aisoc import php2shell as p

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/case-studies/php2shell.md"


@pytest.fixture(scope="module")
def m():
    return p.evaluate()


def test_detection_precision_and_recall(m):
    assert m["precision"] == 1.0
    assert m["story_recall"] == 1.0
    assert m["event_recall"] >= 0.95  # the shell-with-wget step is a known miss (documented)


def test_no_false_positives_on_any_lookalike(m):
    assert m["lookalike_kinds"] == 8
    assert m["false_positive_alerts"] == 0 and m["lookalike_kinds_alerting"] == []


def test_every_rule_fires_and_blocklists_are_not_empty():
    fired = {a.rule for a in p.detect(p.generate())}
    assert fired == {r["id"] for r in p.rules()}
    for f in ("multipart-upload-progress-probe.kql", "web-worker-runs-from-tmp.kql", "web-worker-drops-executable.kql"):
        lists = re.findall(r"dynamic\(\[([^\]]*)\]\)", (p.RULES_DIR / f).read_text())
        assert lists and all(x.strip() for x in lists)


@pytest.mark.parametrize(("version", "want"), p.INVENTORY_CASES)
def test_inventory_classifier(version, want):
    assert p.classify_version(version) == want


def test_inventory_fixed_boundaries_are_exact():
    for (major, minor), fixed in p.FIXED.items():
        assert p.classify_version(f"{major}.{minor}.{fixed - 1}") == "vulnerable"
        assert p.classify_version(f"{major}.{minor}.{fixed}") == "fixed"


def test_failed_attempt_is_not_called_a_compromise(m):
    cases = {c.id: c for c in p.triage(p.detect(p.generate()), p.generate())}
    verdicts = sorted(c.verdict for c in cases.values())
    assert verdicts.count("confirmed_compromise") == 2 and verdicts.count("failed_attempt") == 3 and verdicts.count("recon") == 1
    assert m["verdicts_correct"] == m["cases"] == 6
    for c in cases.values():
        if c.verdict == "failed_attempt":
            assert "isolate_host" not in {a.action for a in p.plan(c, p.generate()).actions}


def test_severity_follows_patch_status():
    d = p.generate()
    by_host = {h: c for c in p.triage(p.detect(d), d) for h in c.hosts}
    assert by_host["PCU-WEB01"].severity == "High"  # vulnerable 8.4.26
    assert by_host["PCU-WEB02"].severity == "Medium"  # fixed 8.4.27
    assert by_host["PCU-WEB03"].severity == "Critical"


def test_zero_containment_without_human_approval(m):
    assert m["actions_planned"] > 0
    assert m["executed_without_approval"] == 0
    assert m["executed_with_agent_self_approval"] == 0
    assert m["executed_with_stale_digest"] == 0
    assert m["executed_with_human_approval"] == m["actions_planned"]


def test_declined_approval_runs_nothing():
    d = p.generate()
    c = next(c for c in p.triage(p.detect(d), d) if c.verdict == "confirmed_compromise")
    pl = p.plan(c, d)
    assert all(r["status"] == "awaiting_approval" for r in p.execute(pl, [p.Approval(p.get(p.TENANT).approvers[0], pl.digest, False)]))


def test_decision_record_paths():
    d = p.generate()
    assert p.decide("PCU-WEB07", d, False) == "take_offline_until_migrated"  # end of life, internet-facing
    assert p.decide("PCU-WEB10", d, False) == "restrict_and_migrate"
    assert p.decide("PCU-WEB02", d, False) == "keep_online_monitor"
    assert p.decide("PCU-WEB08", d, False) == "verify_backport_then_patch"
    assert p.decide("PCU-WEB01", d, True) == "isolate_host"


def test_only_documentation_or_private_addresses():
    nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.0.0.0/8")]
    d = p.generate()
    text = repr(d.tables) + (ROOT / "detections/php2shell").joinpath("rules.yaml").read_text() + DOC.read_text()
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and not ip.startswith(("0.", "8.", "7.", "5.")):
            assert any(ipaddress.ip_address(ip) in n for n in nets), ip


def test_deterministic():
    assert p.report() == p.report()


def test_case_study_real_output_is_current():
    block = DOC.read_text().split("<!-- php2shell-output -->")[1].split("```")[1]
    assert block.strip().removeprefix("text").strip() == p.report().strip()
