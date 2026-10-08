"""The doc renderer: output blocks and code excerpts."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_docs", ROOT / "scripts/render_docs.py")
rd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rd)


def test_output_block_is_filled_from_the_cli():
    out = rd.render("<!-- output: tenants -->\nstale\n<!-- /output -->\n")
    assert "Pinecrest Credit Union" in out and "stale" not in out


def test_python_excerpt_is_the_current_function():
    lang, body = rd.excerpt("src/aisoc/response.py::check_policy")
    assert lang == "python" and body.startswith("def check_policy")


def test_constant_excerpt():
    _, body = rd.excerpt("src/aisoc/triage.py::WEIGHTS")
    assert body.startswith("WEIGHTS")


def test_hcl_block_excerpt_balances_braces():
    lang, body = rd.excerpt('infra/terraform/main.tf::resource "azurerm_role_assignment" "agent_reader"')
    assert lang == "hcl" and body.count("{") == body.count("}")


def test_bicep_block_excerpt():
    lang, body = rd.excerpt("infra/bicep/modules/identity.bicep::resource agentReader")
    assert lang == "bicep" and body.rstrip().endswith("}")


def test_kql_file_excerpt():
    lang, body = rd.excerpt("detections/password-spray.kql")
    assert lang == "kusto" and "SigninLogs" in body


def test_unknown_name_fails():
    with pytest.raises(SystemExit):
        rd.excerpt("src/aisoc/triage.py::nope")


def test_failing_command_fails_the_render():
    with pytest.raises(SystemExit):
        rd.run("kql --tenant pinecrest --query 'NoSuchTable | take 1'")
