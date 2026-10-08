"""Sentinel-shaped tool gateway: the only door from an agent to tenant data.

The tool names and shapes follow the Microsoft Sentinel MCP server's data-exploration collection
(list_sentinel_workspaces, search_tables, query_lake, analyze_user_entity, analyze_url_entity), plus
three tools of our own (analyze_host_entity, lookup_indicator, get_incident). The same functions are
exposed over MCP by aisoc.mcp_server, so in production the agents could point at Microsoft's hosted
server or at this one; this repository's agents sit behind the interface, they do not replace
Security Copilot or Microsoft's server.

Controls enforced on every call:
* the gateway is bound to one tenant store; a call naming another workspace is denied;
* the caller identity must be entitled to the tenant and the tool (config/identities.yaml);
* agents may run only allow-listed KQL templates with regex-checked parameters; raw KQL is for humans;
* results are capped at MAX_ROWS rows;
* every call, allowed or denied, is appended to the tenant's audit chain."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache
from typing import Any

import yaml

from aisoc import CONFIG, intel, kql, ueba
from aisoc.audit import AuditLog
from aisoc.store import CONTEXT_TABLES, SECURITY_TABLES, TenantStore
from aisoc.synth import day_of
from aisoc.tenants import tenants

MAX_ROWS = 200


class ToolDenied(PermissionError):
    pass


@cache
def templates() -> dict:
    return yaml.safe_load((CONFIG / "kql-templates.yaml").read_text())


@cache
def identities() -> dict:
    return yaml.safe_load((CONFIG / "identities.yaml").read_text())["identities"]


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    rows: int
    ms: float
    allowed: bool


@dataclass
class SentinelTools:
    store: TenantStore
    identity: str
    audit: AuditLog
    as_of: datetime
    incidents: dict[str, Any] = field(default_factory=dict)
    calls: list[ToolCall] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.audit.tenant != self.store.tenant.id:
            raise ToolDenied("audit chain and store belong to different tenants")
        self._view = self.store.slice(self.as_of)

    # ---- access control -------------------------------------------------------------------------
    def _authorize(self, tool: str, args: dict[str, Any]) -> dict:
        ident = identities().get(self.identity)
        reason = None
        if ident is None:
            reason = f"unknown identity {self.identity}"
        elif "*" not in ident["tenants"] and self.store.tenant.id not in ident["tenants"]:
            reason = f"{self.identity} is not entitled to tenant {self.store.tenant.id}"
        elif "*" not in ident["tools"] and tool not in ident["tools"]:
            reason = f"{self.identity} may not call {tool}"
        ws = args.get("workspace")
        if reason is None and ws and ws != self.store.tenant.workspace:
            reason = f"workspace {ws} is outside this tenant ({self.store.tenant.workspace})"
        if reason:
            self.audit.append(self.identity, "tool.denied", {"tool": tool, "args": args, "reason": reason}, self.as_of)
            self.calls.append(ToolCall(tool, args, 0, 0.0, False))
            raise ToolDenied(reason)
        return ident

    def _call(self, tool: str, args: dict[str, Any], fn) -> Any:
        self._authorize(tool, args)
        t0 = time.perf_counter()
        result = fn()
        ms = (time.perf_counter() - t0) * 1000
        n = len(result) if isinstance(result, list) else 1
        self.calls.append(ToolCall(tool, args, n, ms, True))
        self.audit.append(self.identity, "tool.call", {"tool": tool, "args": args, "rows": n}, self.as_of)
        return result

    # ---- Sentinel MCP data-exploration shapes -----------------------------------------------------
    def list_sentinel_workspaces(self) -> list[dict]:
        t = self.store.tenant
        n = sorted(tenants()).index(t.id) + 1
        return self._call(
            "list_sentinel_workspaces", {}, lambda: [{"name": t.workspace, "tenant": t.name, "id": f"00000000-0000-0000-0000-{n:012d}"}]
        )

    def search_tables(self, keyword: str, workspace: str | None = None) -> list[dict]:
        def run():
            schema = self._view.schema()
            kw = keyword.lower()
            out = []
            for name in SECURITY_TABLES + CONTEXT_TABLES:
                cols = schema.get(name, [])
                if kw in name.lower() or any(kw in c.lower() for c in cols):
                    out.append({"table": name, "columns": cols})
            return out

        return self._call("search_tables", {"keyword": keyword, "workspace": workspace}, run)

    def query_lake(
        self, template: str | None = None, params: dict[str, str] | None = None, kql_text: str | None = None, workspace: str | None = None
    ) -> list[dict]:
        args = {"template": template, "params": params or {}, "raw": bool(kql_text), "workspace": workspace}
        ident = self._authorize("query_lake", args)
        if kql_text is not None:
            if not ident.get("raw_kql"):
                self.audit.append(self.identity, "tool.denied", {"tool": "query_lake", "reason": "raw KQL not allowed for this identity"}, self.as_of)
                raise ToolDenied(f"{self.identity} may only run allow-listed templates")
            text = kql_text
        else:
            try:
                text = render_template(template or "", params or {})
            except ToolDenied as exc:
                self.audit.append(self.identity, "tool.denied", {"tool": "query_lake", "args": args, "reason": str(exc)}, self.as_of)
                self.calls.append(ToolCall("query_lake", args, 0, 0.0, False))
                raise
        t0 = time.perf_counter()
        rows = kql.run(text, self._view.tables, self.as_of)[:MAX_ROWS]
        ms = (time.perf_counter() - t0) * 1000
        self.calls.append(ToolCall("query_lake", args, len(rows), ms, True))
        self.audit.append(self.identity, "tool.call", {"tool": "query_lake", "args": args, "rows": len(rows)}, self.as_of)
        return rows

    def analyze_user_entity(self, upn: str) -> dict:
        def run():
            users = self._view.users()
            if upn not in users:
                return {"upn": upn, "known": False}
            u = users[upn]
            day0 = self.as_of.replace(hour=0, minute=0, second=0, microsecond=0)
            a = ueba.score_user(self._view, upn, day0, day0 + timedelta(days=1))
            return {
                "upn": upn,
                "known": True,
                "department": u.get("Department"),
                "privileged": bool(u.get("IsPrivileged")),
                "anomaly_score": a.score,
                "anomalies": list(a.reasons),
            }

        return self._call("analyze_user_entity", {"upn": upn}, run)

    def analyze_url_entity(self, url: str) -> dict:
        def run():
            host = re.sub(r"^[a-z]+://", "", url).split("/")[0].lower()
            hits = intel.lookup("domain", host, day_of(self.as_of))
            clicks = [r for r in self._view.tables.get("UrlClickEvents", []) if host in str(r.get("Url", "")).lower()]
            return {
                "url": url,
                "domain": host,
                "indicators": [h.__dict__ for h in hits],
                "clicks": len(clicks),
                "clicked_by": sorted({c["AccountUpn"] for c in clicks}),
            }

        return self._call("analyze_url_entity", {"url": url}, run)

    # ---- our own tools ----------------------------------------------------------------------------
    def analyze_host_entity(self, host: str) -> dict:
        def run():
            a = self._view.assets().get(host)
            if a is None:
                return {"host": host, "known": False}
            return {
                "host": host,
                "known": True,
                "role": a.get("Role"),
                "criticality": a.get("Criticality"),
                "internet_facing": a.get("InternetFacing"),
                "open_critical_cves": a.get("OpenCriticalCves"),
                "crown_jewel": host in self.store.tenant.crown_jewels,
            }

        return self._call("analyze_host_entity", {"host": host}, run)

    def lookup_indicator(self, kind: str, value: str) -> list[dict]:
        return self._call(
            "lookup_indicator", {"kind": kind, "value": value}, lambda: [h.__dict__ for h in intel.lookup(kind, value, day_of(self.as_of))]
        )

    def get_incident(self, incident_id: str) -> dict:
        def run():
            inc = self.incidents.get(incident_id)
            if inc is None or inc.tenant != self.store.tenant.id:
                return {"id": incident_id, "found": False}
            return {
                "id": inc.id,
                "found": True,
                "alerts": [
                    {"id": a.id, "name": a.name, "source": a.source, "severity": a.severity, "entities": a.entities, "event_ids": a.event_ids}
                    for a in inc.alerts
                ],
            }

        return self._call("get_incident", {"incident_id": incident_id}, run)


def render_template(name: str, params: dict[str, str]) -> str:
    doc = templates()
    if name not in doc["templates"]:
        raise ToolDenied(f"unknown template {name!r}")
    text = doc["templates"][name]["kql"]
    needed = set(re.findall(r"\{(\w+)\}", text))
    if set(params) - needed:
        raise ToolDenied(f"unexpected parameters {sorted(set(params) - needed)}")
    for p in needed:
        v = params.get(p)
        if v is None:
            raise ToolDenied(f"missing parameter {p}")
        if not re.fullmatch(doc["params"][p], v):
            raise ToolDenied(f"parameter {p}={v!r} rejected by its pattern")
        text = text.replace("{" + p + "}", v)
    return text
