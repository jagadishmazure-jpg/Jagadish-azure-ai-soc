"""Infrastructure and workflow structure, checked offline (no Terraform or Bicep binaries needed)."""

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows"
TF = ROOT / "infra/terraform"
BICEP = ROOT / "infra/bicep"
SHA_PIN = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b")
# Built-in role definition IDs (public and identical in every Azure tenant).
SENTINEL_RESPONDER = "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
SENTINEL_READER = "8d289c81-5878-46d4-8554-54e1e3d8b5cb"


def tf_text() -> str:
    return "\n".join(p.read_text() for p in sorted(TF.glob("*.tf")))


def bicep_text() -> str:
    return "\n".join(p.read_text() for p in sorted(BICEP.rglob("*.bicep")))


def wf(name):
    return yaml.safe_load((WF / name).read_text())


# ---------------------------------------------------------------- rules: one source of truth


def test_rules_json_matches_the_kql_files():
    rules = json.loads((ROOT / "detections/rules.json").read_text())["rules"]
    kql = {p.stem: p.read_text() for p in (ROOT / "detections").glob("*.kql")}
    assert {r["id"] for r in rules} == set(kql)
    for r in rules:
        assert r["query"].strip() == kql[r["id"]].strip(), r["id"]
        assert r["tactics"] and r["techniques"] and r["entities"]


def test_both_stacks_load_rules_json():
    assert "detections/rules.json" in (TF / "locals.tf").read_text()
    assert "loadJsonContent('../../../detections/rules.json')" in (BICEP / "modules/workspace.bicep").read_text()


def test_rules_are_opt_in_and_created_disabled():
    variables = (TF / "variables.tf").read_text()
    for var in ("deploy_analytics_rules", "analytics_rules_enabled", "enable_automation_rule", "private_networking"):
        assert re.search(rf'variable "{var}"[\s\S]*?default\s*=\s*false', variables), var
    main = (BICEP / "main.bicep").read_text()
    for p in ("deployAnalyticsRules", "analyticsRulesEnabled", "enableAutomationRule", "privateNetworking"):
        assert f"param {p} bool = false" in main, p
    assert "enabled                    = var.analytics_rules_enabled" in tf_text()
    assert "enabled: analyticsRulesEnabled" in (BICEP / "modules/workspace.bicep").read_text()


# ---------------------------------------------------------------- least privilege


def test_only_sentinel_responder_and_reader_roles():
    roles = re.findall(r'role_definition_name\s*=\s*"([^"]+)"', tf_text())
    assert sorted(roles) == ["Microsoft Sentinel Reader", "Microsoft Sentinel Responder"]
    guids = set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", bicep_text()))
    assert guids == {SENTINEL_RESPONDER, SENTINEL_READER}


def test_role_assignments_are_scoped_to_the_workspace():
    assert tf_text().count("scope                = azurerm_log_analytics_workspace.this.id") == 2
    assert (BICEP / "modules/identity.bicep").read_text().count("scope: law") == 2


def test_infra_never_grants_or_performs_containment():
    text = tf_text() + bicep_text()
    for word in ("User.EnableDisableAccount", "Machine.Isolate", "User.RevokeSessions", "Ti.ReadWrite", "Owner", '"Contributor"'):
        assert word not in text, word
    playbook = (TF / "main.tf").read_text().split('resource "azurerm_logic_app_workflow"')[1]
    playbook += (BICEP / "modules/playbook.bicep").read_text()
    code = "\n".join(line for line in playbook.splitlines() if not line.strip().startswith(("#", "//")))
    for verb in ("disable", "isolate", "revokeSignInSessions", "block"):
        assert verb not in code.lower(), verb


def test_playbook_authenticates_with_managed_identity_only():
    for text in ((TF / "main.tf").read_text(), (BICEP / "modules/playbook.bicep").read_text()):
        assert "ManagedServiceIdentity" in text
        assert "parameterValueType" in text and "Alternative" in text


def test_agent_endpoint_must_be_https():
    assert 'startswith(var.agent_endpoint, "https://")' in (TF / "variables.tf").read_text()


# ---------------------------------------------------------------- workspace hardening


def test_workspace_disables_local_auth_in_both_stacks():
    assert re.search(r"local_authentication_enabled\s*=\s*false", tf_text())
    assert "disableLocalAuth: true" in (BICEP / "modules/workspace.bicep").read_text()


def test_private_networking_is_private_only_in_both_stacks():
    t = (TF / "network.tf").read_text()
    assert 'ingestion_access_mode = "PrivateOnly"' in t and 'query_access_mode     = "PrivateOnly"' in t
    assert "azurerm_network_security_group" in t
    assert "ingestionAccessMode: 'PrivateOnly', queryAccessMode: 'PrivateOnly'" in (BICEP / "modules/network.bicep").read_text()


def test_diagnostic_settings_in_both_stacks():
    t = tf_text()
    assert 'category_group = "audit"' in t and 'category = "WorkflowRuntime"' in t
    b = bicep_text()
    assert "categoryGroup: 'audit'" in b and "category: 'WorkflowRuntime'" in b


def test_prod_is_private_and_rules_still_disabled():
    prod = (TF / "envs/prod.tfvars").read_text()
    assert re.search(r"private_networking\s*=\s*true", prod)
    assert re.search(r"analytics_rules_enabled\s*=\s*false", prod)
    params = json.loads((BICEP / "main.parameters.json").read_text())["parameters"]
    assert params["deployAnalyticsRules"]["value"] is False


def test_checkov_has_no_skips():
    assert "skip-check" not in (ROOT / ".checkov.yaml").read_text()


def test_terraform_tests_cover_the_key_paths():
    t = (TF / "tests/plan.tftest.hcl").read_text()
    for run in ("dev_defaults", "analytics_rules", "private_networking_and_agent_endpoint", "rejects_plain_http_endpoint"):
        assert f'run "{run}"' in t
    assert 'mock_provider "azurerm"' in t and 'mock_provider "azapi"' in t


# ---------------------------------------------------------------- workflows


@pytest.mark.parametrize("name", sorted(p.name for p in WF.glob("*.yml")))
def test_workflow_hardening(name):
    d = wf(name)
    assert d["permissions"] == {"contents": "read"}, "top-level permissions must be read-only"
    text = (WF / name).read_text()
    for line in text.splitlines():
        if "uses:" in line and not line.strip().startswith("#"):
            assert SHA_PIN.search(line), f"{name}: action not pinned to a commit SHA: {line.strip()}"
    assert "client-secret" not in text and "AZURE_CLIENT_SECRET" not in text


def test_ci_runs_tests_gate_and_drift_checks():
    text = (WF / "ci.yml").read_text()
    for step in ("pytest -q", "aisoc gate", "rules-json --check", "render_docs.py --check", "gitleaks", "sbom-action", "bicep build"):
        assert step in text, step


def test_deploy_is_gated_and_uses_oidc():
    jobs = wf("deploy.yml")["jobs"]
    for name in ("deploy-dev", "deploy-prod"):
        assert "vars.DEPLOY_ENABLED == 'true'" in jobs[name]["if"]
        assert jobs[name]["permissions"]["id-token"] == "write"
        assert any("azure/login" in s.get("uses", "") for s in jobs[name]["steps"])
    assert jobs["deploy-dev"]["environment"] == "dev" and jobs["deploy-prod"]["environment"] == "prod"
    assert "deploy-dev" in jobs["deploy-prod"]["needs"]


def test_teardown_needs_gate_and_confirmation():
    job = wf("teardown.yml")["jobs"]["teardown"]
    assert "vars.DEPLOY_ENABLED == 'true'" in job["if"] and "inputs.confirm == inputs.environment" in job["if"]


def test_codeql_scans_python_and_actions():
    text = (WF / "codeql.yml").read_text()
    assert "python" in text and "actions" in text and "security-events: write" in text


def test_dependabot_covers_every_ecosystem():
    d = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert {u["package-ecosystem"] for u in d["updates"]} >= {"pip", "github-actions", "terraform"}


def test_deploy_script_has_every_subcommand():
    text = (ROOT / ".github/scripts/deploy.sh").read_text()
    for fn in ("provision()", "smoke()", "destroy()"):
        assert fn in text
