"""Multi-tenant isolation checks for the MSSP model.

`canary_check` plants a unique marker in one tenant's telemetry (a file name in pinecrest's insider
story, so it reaches that tenant's evidence, prompts and audit chain), runs the full pipeline for every
tenant, and searches every artefact of the other tenants for it: prompts, narratives, evidence,
knowledge-base notes and audit records. `cross_tenant_attempts` then tries the ways one tenant's
agent could reach another tenant and records that each is refused."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

from aisoc import response
from aisoc.audit import AuditLog
from aisoc.knowledge import CaseNote, KnowledgeBase
from aisoc.pipeline import Run, run_async
from aisoc.store import fresh, load
from aisoc.tools import SentinelTools, ToolDenied

CANARY = "CANARY-PCU-QX7"
CANARY_TENANT = "pinecrest"


def plant(store, marker: str = CANARY) -> int:
    n = 0
    for r in store.tables["CloudAppEvents"]:
        if r["ActionType"] == "FileDownloaded" and str(r.get("ObjectName", "")).startswith("/sites/finance/archive"):
            r["ObjectName"] = f"/sites/finance/{marker}-{n:03d}.xlsx"
            n += 1
    return n


def artefacts(run: Run, tenant: str) -> str:
    tr = run.tenants[tenant]
    parts = [json.dumps(tr.audit.records, default=str)]
    parts += [json.dumps(n.__dict__) for n in tr.loop.kb.notes]
    for c in tr.cases:
        if c.narrative:
            parts += [c.narrative.prompt, c.narrative.summary.model_dump_json()]
        if c.investigation:
            parts += [e.summary for e in c.investigation.evidence]
    return "\n".join(parts)


def canary_check() -> dict:
    store = fresh(CANARY_TENANT)
    planted = plant(store)
    run = asyncio.run(run_async("learning", stores={CANARY_TENANT: store}))
    seen = {t: artefacts(run, t).count(CANARY) for t in run.tenants}
    return {"planted_rows": planted, "seen": seen}


def cross_tenant_attempts() -> list[tuple[str, str]]:
    """Each attempt returns (attempt, outcome). Every outcome should start with 'denied'."""
    bw = load("brightwater")
    out = []
    audit = AuditLog("brightwater")
    tools = SentinelTools(bw, "agent:investigation", audit, bw.now - timedelta(hours=1))
    try:
        tools.query_lake("user_signins", {"upn": "ciso@orchidvalley.example", "lookback": "24h", "until": "0h"}, workspace="law-soc-orchidvalley")
        out.append(("query another tenant's workspace", "ALLOWED"))
    except ToolDenied as e:
        out.append(("query another tenant's workspace", f"denied: {e}"))
    rows = tools.query_lake("user_signins", {"upn": "ciso@orchidvalley.example", "lookback": "500h", "until": "0h"})
    out.append(("query another tenant's user through own workspace", "denied: 0 rows (the gateway's store holds only brightwater data)" if not rows else f"ALLOWED: {len(rows)} rows"))
    try:
        SentinelTools(bw, "customer.pinecrest.viewer", audit, bw.now).list_sentinel_workspaces()
        out.append(("unknown identity", "ALLOWED"))
    except ToolDenied as e:
        out.append(("unknown identity", f"denied: {e}"))
    try:
        SentinelTools(load("pinecrest"), "customer.brightwater.viewer", AuditLog("pinecrest"), bw.now).list_sentinel_workspaces()
        out.append(("brightwater customer viewer on pinecrest", "ALLOWED"))
    except ToolDenied as e:
        out.append(("brightwater customer viewer on pinecrest", f"denied: {e}"))
    try:
        SentinelTools(bw, "agent:investigation", AuditLog("pinecrest"), bw.now)
        out.append(("write brightwater activity to pinecrest's audit chain", "ALLOWED"))
    except ToolDenied as e:
        out.append(("write brightwater activity to pinecrest's audit chain", f"denied: {e}"))
    try:
        KnowledgeBase("brightwater").add(CaseNote("pinecrest", "sig", "benign_positive", "analyst.rivera", "INC-PI-001", ""))
        out.append(("store a pinecrest case note in brightwater's knowledge base", "ALLOWED"))
    except PermissionError as e:
        out.append(("store a pinecrest case note in brightwater's knowledge base", f"denied: {e}"))
    for action, target in (("disable_user", "ciso@orchidvalley.example"), ("isolate_host", "PCU-DC01")):
        try:
            response.check_policy(bw, action, target)
            out.append((f"{action} {target} from a brightwater incident", "ALLOWED"))
        except response.PolicyViolation as e:
            out.append((f"{action} {target} from a brightwater incident", f"denied: {e}"))
    return out
