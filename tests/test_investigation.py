"""Investigation: evidence, timeline, graph, scope; and the static rule that product code never reads ground truth."""

import ast
from pathlib import Path

import pytest

from conftest import case

SRC = Path(__file__).resolve().parents[1] / "src" / "aisoc"
PRODUCT = ["triage", "routing", "investigation", "response", "tools", "llm", "workflow", "knowledge", "guardrails", "ueba", "intel", "detections", "store", "mcp_server"]


@pytest.mark.parametrize("module", PRODUCT)
def test_product_code_never_imports_ground_truth(module):
    tree = ast.parse((SRC / f"{module}.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module == "aisoc.labels" or (node.module == "aisoc" and any(a.name in ("labels", "analyst", "metrics") for a in node.names))), module
        if isinstance(node, ast.Import):
            assert not any(a.name in ("aisoc.labels", "aisoc.analyst") for a in node.names), module


def test_ransomware_scope_and_graph(learning):
    inv = case(learning, "orchidvalley", "INC-OR-032").investigation
    assert inv.scope["hosts"] == ["OVC-WS008"] and "203.0.113.140" in inv.scope["external_ips"]
    assert any(b == "203.0.113.140" for _, b, _ in inv.edges)
    assert inv.mermaid().startswith("graph LR")


def test_evidence_is_numbered_in_time_order(learning):
    inv = case(learning, "brightwater", "INC-BR-027").investigation
    tl = inv.timeline()
    assert [e.id for e in tl] == [f"EV-{n:03d}" for n in range(1, len(tl) + 1)]
    assert [e.time for e in tl] == sorted(e.time for e in tl)


def test_phishing_simulation_never_enters_scope(learning):
    inv = case(learning, "brightwater", "INC-BR-027").investigation
    assert not any("phishdrill" in d for d in inv.scope["destinations"])
    assert inv.scope["accounts"] == ["hollis.lockwood@brightwater.example"]


def test_spray_scope_is_the_compromised_account_only(learning):
    inv = case(learning, "brightwater", "INC-BR-015").investigation
    assert inv.scope["accounts"] == ["logan.easton@brightwater.example"]


def test_runbook_is_attached(learning):
    assert case(learning, "orchidvalley", "INC-OR-032").investigation.runbook.file == "ransomware-precursor.md"
    assert case(learning, "brightwater", "INC-BR-036").investigation.runbook.file == "insider-data-theft.md"


def test_investigation_reads_no_rows_after_its_as_of(learning):
    for c in learning.cases():
        if c.investigation:
            assert all(e.time <= c.investigation.as_of for e in c.investigation.evidence)
