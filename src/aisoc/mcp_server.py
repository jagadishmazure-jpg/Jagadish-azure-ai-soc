"""MCP server exposing the Sentinel-shaped tool gateway (aisoc.tools) for one tenant.

Tool names follow the Microsoft Sentinel MCP server's data-exploration collection, so an agent written
against Microsoft's hosted server can be pointed at this one offline, and the other way round. Every
tool is read-only (`readOnlyHint`); there is no containment tool. Containment only happens through
the approval gate in the workflow, never from an MCP client.

    aisoc mcp --tenant brightwater     # stdio transport
    aisoc mcp-demo                     # scripted in-memory session
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from aisoc.audit import AuditLog
from aisoc.store import load
from aisoc.tools import SentinelTools

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
TOOL_NAMES = [
    "list_sentinel_workspaces",
    "search_tables",
    "query_lake",
    "analyze_user_entity",
    "analyze_url_entity",
    "analyze_host_entity",
    "lookup_indicator",
]


def build_server(tenant: str = "brightwater", identity: str = "agent:investigation", audit: AuditLog | None = None) -> MCPServer:
    store = load(tenant)
    gw = SentinelTools(store, identity, audit or AuditLog(tenant), store.now)
    server = MCPServer(f"aisoc-sentinel-{tenant}")

    @server.tool(annotations=RO)
    def list_sentinel_workspaces() -> list[dict[str, Any]]:
        """Workspaces this caller can reach (exactly one: the bound tenant's)."""
        return gw.list_sentinel_workspaces()

    @server.tool(annotations=RO)
    def search_tables(keyword: str) -> list[dict[str, Any]]:
        """Tables whose name or columns contain the keyword, with their columns."""
        return gw.search_tables(keyword)

    @server.tool(annotations=RO)
    def query_lake(template: str, params: dict[str, str]) -> list[dict[str, Any]]:
        """Run an allow-listed KQL template (config/kql-templates.yaml) with checked parameters; at most 200 rows."""
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()} for r in gw.query_lake(template, params)]

    @server.tool(annotations=RO)
    def analyze_user_entity(upn: str) -> dict[str, Any]:
        """Department, privilege and behaviour anomalies for one account."""
        return gw.analyze_user_entity(upn)

    @server.tool(annotations=RO)
    def analyze_url_entity(url: str) -> dict[str, Any]:
        """Threat-intel matches and click history for a URL or domain."""
        return gw.analyze_url_entity(url)

    @server.tool(annotations=RO)
    def analyze_host_entity(host: str) -> dict[str, Any]:
        """Role, criticality, exposure and open critical vulnerabilities for one device."""
        return gw.analyze_host_entity(host)

    @server.tool(annotations=RO)
    def lookup_indicator(kind: str, value: str) -> list[dict[str, Any]]:
        """Active indicators for an ip, domain, url, mailbox or filehash, with decayed confidence."""
        return gw.lookup_indicator(kind, value)

    server.gateway = gw  # type: ignore[attr-defined]
    return server


async def demo() -> list[str]:
    """Scripted session used by `aisoc mcp-demo`: what an investigation agent would ask."""
    from mcp import Client

    lines = []
    audit = AuditLog("brightwater")
    async with Client(build_server("brightwater", audit=audit)) as client:
        tools = await client.list_tools()
        lines.append("tools: " + ", ".join(sorted(t.name for t in tools.tools)))
        lines.append(f"all read-only: {all(t.annotations and t.annotations.read_only_hint for t in tools.tools)}")
        ws = (await client.call_tool("list_sentinel_workspaces", {})).structured_content["result"]
        lines.append(f"workspaces: {[w['name'] for w in ws]}")
        ind = (await client.call_tool("lookup_indicator", {"kind": "ip", "value": "203.0.113.77"})).structured_content["result"]
        lines.append(f"203.0.113.77: {[(i['indicator_id'], i['labels'], round(i['confidence'], 1)) for i in ind]}")
        rows = (
            await client.call_tool("query_lake", {"template": "ip_signins", "params": {"ip": "203.0.113.77", "lookback": "504h", "until": "0h"}})
        ).structured_content["result"]
        lines.append(f"ip_signins 203.0.113.77: attempts {rows[0]['Attempts']}, failures {rows[0]['Failures']}, accounts {rows[0]['Accounts']}")
        bad = await client.call_tool(
            "query_lake", {"template": "ip_signins", "params": {"ip": '203.0.113.77" | take 1000', "lookback": "24h", "until": "0h"}}
        )
        lines.append(f"injected parameter: is_error={bad.is_error}")
        host = (await client.call_tool("analyze_host_entity", {"host": "BWL-DC01"})).structured_content
        lines.append(f"BWL-DC01: role {host['role']}, criticality {host['criticality']}, crown jewel {host['crown_jewel']}")
    _ok, msg = audit.verify()
    lines.append(f"audit: {msg}; denied calls {len(audit.events('tool.denied'))}")
    return lines
