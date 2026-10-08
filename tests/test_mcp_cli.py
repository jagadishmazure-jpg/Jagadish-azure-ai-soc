"""MCP server and CLI."""

import asyncio
import contextlib
import io

import pytest

from aisoc import cli, mcp_server


def test_mcp_demo():
    lines = asyncio.run(mcp_server.demo())
    assert lines[0] == "tools: " + ", ".join(sorted(mcp_server.TOOL_NAMES))
    assert "all read-only: True" in lines
    assert "injected parameter: is_error=True" in lines
    assert lines[-1].endswith("denied calls 1")


def test_mcp_exposes_no_containment_tool():
    assert not {"disable_user", "isolate_host", "block_ip", "revoke_sessions"} & set(mcp_server.TOOL_NAMES)


def _run(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(args)
    return rc, buf.getvalue()


@pytest.mark.parametrize(
    "args",
    [
        ["tenants"], ["data", "--tenant", "pinecrest"], ["detect"], ["attack"], ["triage", "--tenant", "brightwater"],
        ["investigate", "--tenant", "orchidvalley", "--incident", "INC-OR-032"], ["metrics"], ["stories"], ["compare"], ["feedback"],
        ["risk"], ["injection"], ["approvals"], ["audit", "--tenant", "brightwater", "--tamper"], ["rules-json", "--check"],
        ["kql", "--tenant", "brightwater", "--file", "detections/password-spray.kql"],
    ],
)  # fmt: skip
def test_cli_commands_run(args):
    rc, out = _run(args)
    assert rc == 0 and out.strip()


def test_gate_passes():
    rc, out = _run(["gate"])
    assert rc == 0 and "gate: PASS" in out and "FAIL" not in out


def test_tamper_is_detected_in_cli():
    _rc, out = _run(["audit", "--tenant", "pinecrest", "--tamper"])
    assert "(False, 'record" in out
