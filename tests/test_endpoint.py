"""Endpoint pack: detections, look-alikes, process tree, persistence checks and the triage agent."""

import pytest

from aisoc import endpoint as ep


@pytest.fixture(scope="module")
def data():
    return ep.generate()


@pytest.fixture(scope="module")
def m():
    return ep.evaluate()


@pytest.fixture(scope="module")
def tri(data):
    return {t.host: t for t in ep.triage_all(data)}


def test_every_story_detected(m):
    assert m["stories_detected"] == "3/3"


def test_one_rule_level_false_positive_is_cleared_by_triage(m, tri):
    assert m["false_positive_alerts"] == 1 and m["lookalike_kinds_alerting"] == ["signed-driver-service"]
    assert tri["BWL-SRV02"].verdict == "benign" and tri["BWL-SRV02"].plan == []


def test_triage_verdicts_all_correct(m):
    assert m["triage_verdicts_correct"] == "4/4" and m["attacks_cleared_as_benign"] == 0


def test_macos_hosts_present(m):
    assert m["macos_hosts"] == 4 and m["hosts"] == 15


@pytest.mark.parametrize("rule", ["autostart-persistence", "service-from-temp-path", "rmm-tool-abuse", "ransomware-canary-touched"])
def test_four_detections_each_fire_on_an_attack(data, rule):
    lab = data.labels
    hits = [a for a in ep.detect(data) if a.rule == rule]
    assert any(lab[e].startswith("attack:") for a in hits for e in a.event_ids)


def test_autostart_spans_windows_and_macos(data):
    hosts = {a.host for a in ep.detect(data) if a.rule == "autostart-persistence"}
    assert hosts == {"BWL-WS07", "BWL-MAC04"}


def test_rule_files_exist():
    for r in ep.rules():
        for f in r["files"]:
            assert (ep.RULES_DIR / f).exists()


@pytest.mark.parametrize("kind", ["approved-rmm", "signed-per-user-app", "signed-updater-task", "signed-vpn-launchdaemon", "backup-reads-canary"])
def test_silent_lookalikes(data, kind):
    lab = data.labels
    for a in ep.detect(data):
        assert not any(lab[e] == f"benign:{kind}" for e in a.event_ids)


def test_process_tree_shows_rmm_lineage(tri):
    tree = "\n".join(tri["BWL-WS07"].tree)
    assert "msedge.exe" in tree and "ScreenConnect.ClientSetup.exe" in tree and "svc32.exe" in tree
    assert tree.index("msedge.exe") < tree.index("ScreenConnect.ClientSetup.exe") < tree.index("svc32.exe")


def test_process_tree_hides_clean_branches(tri):
    assert not any(line.startswith("Finder") for line in tri["BWL-MAC04"].tree)


def test_persistence_lists_run_key_and_launch_agent(tri):
    assert any("run_key: SvcHost32" in p for p in tri["BWL-WS07"].persistence)
    assert any("launch_item" in p and "[unsigned]" in p for p in tri["BWL-MAC04"].persistence)


def test_signed_service_not_flagged_unsigned(tri):
    assert all("[unsigned]" not in p for p in tri["BWL-SRV02"].persistence)


def test_credential_dump_raises_score(tri):
    assert any("credential theft" in r for r in tri["BWL-SRV03"].reasons)


def test_plans_start_with_isolation_and_use_registered_actions(tri):
    from aisoc import authority

    for t in tri.values():
        if t.plan:
            assert t.plan[0][0] == "isolate_host"
            assert all(a in authority.actions() for a, _, _ in t.plan)


def test_signed_processes_never_killed(tri, data):
    signed = {r["FileName"] for r in data.tables["DeviceProcessEvents"] if r["Trusted"]}
    for t in tri.values():
        for a, target, _ in t.plan:
            if a == "kill_process":
                assert target.split(":")[1] not in signed


def test_remediation_text_requires_approval(tri):
    assert "needs your approval" in ep.remediation_text(tri["BWL-WS07"])
    assert "no action" in ep.remediation_text(tri["BWL-SRV02"])


def test_nothing_executed(m):
    assert m["actions_executed_without_approval"] == 0
