"""Investigation agent logic: plan tool calls, collect evidence, build a timeline and an entity graph,
and work out scope and blast radius.

The investigator sees the tenant only through the tool gateway (aisoc.tools), as of one hour after the
incident's last alert, so it cannot read the future or another tenant. It never imports ground truth;
a static test enforces that.

Evidence selection is rule based: a row becomes evidence when it is one of the incident's own events,
touches a known-bad indicator or attacker address, or matches an ATT&CK behaviour pattern. Routine rows
are counted, not listed, so the analyst sees the signal and the size of the haystack."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from aisoc import attack, intel
from aisoc.audit import AuditLog
from aisoc.knowledge import Runbook, runbook_for
from aisoc.store import TenantStore
from aisoc.synth import CORP_EGRESS, rel
from aisoc.tools import SentinelTools
from aisoc.triage import Incident

LOOKBACK = timedelta(hours=48)
SETTLE = timedelta(hours=1)
ACCOUNT_STEPS = ("user_signins", "user_cloud_activity", "user_email", "user_url_clicks")
HOST_STEPS = ("host_processes", "host_network")
IP_STEPS = ("ip_signins", "ip_connections")


@dataclass(frozen=True)
class Evidence:
    id: str
    time: datetime
    kind: str
    summary: str
    event_id: str
    why: str


@dataclass
class Investigation:
    incident_id: str
    tenant: str
    as_of: datetime
    plan: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    routine: dict[str, int] = field(default_factory=dict)
    nodes: dict[str, str] = field(default_factory=dict)  # entity -> type
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    scope: dict[str, list[str]] = field(default_factory=dict)
    blast_radius: dict[str, object] = field(default_factory=dict)
    entity_context: dict[str, dict] = field(default_factory=dict)
    runbook: Runbook | None = None
    tool_calls: int = 0
    denied_calls: int = 0
    ms: float = 0.0

    def timeline(self) -> list[Evidence]:
        return sorted(self.evidence, key=lambda e: (e.time, e.id))

    def mermaid(self) -> str:
        ids = {n: f"n{i}" for i, n in enumerate(sorted(self.nodes))}
        lines = ["graph LR"]
        for n, kind in sorted(self.nodes.items()):
            lines.append(f'  {ids[n]}["{kind}: {n}"]')
        for a, b, label in sorted(set(self.edges)):
            lines.append(f"  {ids[a]} -- {label} --> {ids[b]}")
        return "\n".join(lines)


def _summ(table: str, r: dict) -> str:
    if table == "SigninLogs":
        res = "success" if str(r.get("ResultType")) == "0" else f"failure {r.get('ResultType')}"
        return f"sign-in {res} for {r.get('UserPrincipalName')} from {r.get('IPAddress')} ({r.get('Country')})"
    if table == "CloudAppEvents":
        dest = f" to {r['Destination']}" if r.get("Destination") else ""
        return f"{r.get('ActionType')} by {r.get('AccountUpn')}: {r.get('ObjectName') or ''}{dest}".strip()
    if table == "EmailEvents":
        return f"email from {r.get('SenderFromAddress')} to {r.get('RecipientEmailAddress')}, subject {r.get('Subject')!r}, threats {r.get('ThreatTypes') or 'none'}"
    if table == "UrlClickEvents":
        return f"{r.get('AccountUpn')} clicked {r.get('Url')}"
    if table == "DeviceProcessEvents":
        return f"{r.get('InitiatingProcessFileName')} started {r.get('FileName')} on {r.get('DeviceName')}: {r.get('ProcessCommandLine')}"
    if table == "DeviceNetworkEvents":
        return f"{r.get('DeviceName')} ({r.get('InitiatingProcessFileName')}) connected to {r.get('RemoteIP')}:{r.get('RemotePort')}"
    return str(r)


TEMPLATE_TABLE = {"user_signins": "SigninLogs", "user_cloud_activity": "CloudAppEvents", "user_email": "EmailEvents", "user_url_clicks": "UrlClickEvents",
                  "host_processes": "DeviceProcessEvents", "host_network": "DeviceNetworkEvents"}


def investigate(store: TenantStore, inc: Incident, audit: AuditLog, incidents: dict | None = None) -> Investigation:
    t0 = time.perf_counter()
    as_of = inc.end + SETTLE
    tools = SentinelTools(store, "agent:investigation", audit, as_of, incidents=incidents or {inc.id: inc})
    inv = Investigation(inc.id, inc.tenant, as_of)
    inv.runbook = runbook_for(inc.sources, inc.techniques)
    tenant = store.tenant
    benign_ips = {CORP_EGRESS.get(tenant.id), *tenant.vpn_ips}
    hours = math.ceil((as_of - (inc.start - LOOKBACK)).total_seconds() / 3600)
    window = {"lookback": f"{hours}h", "until": "0h"}
    own_events = set(inc.event_ids)
    bad_ips = {h.value for h in inc.ti_hits if h.entity_type == "ip"} | {ip for ip in inc.entities("ip") if ip not in benign_ips and ip not in tenant.authorized_scanners}
    bad_domains = {intel.domain_of(h.value) for h in inc.ti_hits if h.entity_type in ("url", "domain", "mailbox")}
    seen: set[str] = set()
    tools.get_incident(inc.id)

    def node(name: str, kind: str) -> None:
        inv.nodes.setdefault(name, kind)

    def add(table: str, r: dict, why: str) -> None:
        eid = r.get("EventId")
        if not eid or eid in seen:
            return
        seen.add(eid)
        inv.evidence.append(Evidence(f"EV-{len(inv.evidence) + 1:03d}", r["TimeGenerated"], table, _summ(table, r), eid, why))

    sim_domain = tenant.phish_sim_sender.split("@")[-1]

    def consider(table: str, rows: list[dict]) -> None:
        routine = 0
        for r in rows:
            if sim_domain in " ".join(str(r.get(c, "")) for c in ("SenderFromAddress", "Url")):
                inv.routine["phishing simulation"] = inv.routine.get("phishing simulation", 0) + 1
                continue
            ip = r.get("IPAddress") or r.get("RemoteIP")
            text = " ".join(str(r.get(c, "")) for c in ("ProcessCommandLine", "ObjectName", "Destination", "Url", "RemoteUrl"))
            if r.get("EventId") in own_events:
                add(table, r, "alert event")
            elif ip in bad_ips:
                add(table, r, f"attacker address {ip}")
            elif any(d in text for d in bad_domains):
                add(table, r, "known-bad domain")
            elif table == "DeviceProcessEvents" and attack.infer_text(text):
                add(table, r, "matches " + ", ".join(attack.infer_text(text)))
            elif table == "CloudAppEvents" and r.get("IsExternal"):
                add(table, r, "external destination")
            elif table == "EmailEvents" and r.get("ThreatTypes"):
                add(table, r, f"email flagged {r['ThreatTypes']}")
            else:
                routine += 1
                continue
            acct = r.get("UserPrincipalName") or r.get("AccountUpn") or r.get("RecipientEmailAddress")
            host = r.get("DeviceName")
            if acct:
                node(acct, "account")
            if host:
                node(host, "host")
            if acct and host:
                inv.edges.append((acct, host, "used"))
            if ip and ip not in benign_ips:
                node(ip, "ip")
                inv.edges.append((acct or host, ip, "connected" if host else "signed in from"))
            if r.get("Destination"):
                node(str(r["Destination"]), "destination")
                inv.edges.append((acct, str(r["Destination"]), "sent data to"))
            if r.get("Url"):
                d = str(r["Url"]).split("/")[2] if "://" in str(r["Url"]) else str(r["Url"])
                node(d, "domain")
                inv.edges.append((acct, d, "clicked"))
        if routine:
            inv.routine[table] = inv.routine.get(table, 0) + routine

    accounts = [a for a in inc.entities("account") if a.lower().endswith("@" + tenant.domain)]
    hosts = inc.entities("host")
    for acct in accounts:
        node(acct, "account")
        for step in ACCOUNT_STEPS:
            inv.plan.append(f"{step}({acct})")
            consider(TEMPLATE_TABLE[step], tools.query_lake(step, {"upn": acct, **window}))
        inv.plan.append(f"analyze_user_entity({acct})")
        inv.entity_context[acct] = tools.analyze_user_entity(acct)
    for host in hosts:
        node(host, "host")
        for step in HOST_STEPS:
            inv.plan.append(f"{step}({host})")
            consider(TEMPLATE_TABLE[step], tools.query_lake(step, {"host": host, **window}))
        inv.plan.append(f"analyze_host_entity({host})")
        inv.entity_context[host] = tools.analyze_host_entity(host)
    # pivot: every attacker address, including ones discovered above, to find other victims
    for ip in sorted(bad_ips | {n for n, k in inv.nodes.items() if k == "ip" and n not in benign_ips and n not in tenant.authorized_scanners}):
        node(ip, "ip")
        inv.plan.append(f"lookup_indicator(ip, {ip})")
        inv.entity_context[ip] = {"indicators": tools.lookup_indicator("ip", ip)}
        inv.plan.append(f"ip_signins({ip})")
        for row in tools.query_lake("ip_signins", {"ip": ip, **window}):
            inv.entity_context[ip]["signins"] = {k: row[k] for k in ("Attempts", "Failures", "Accounts")}
        inv.plan.append(f"ip_connections({ip})")
        for row in tools.query_lake("ip_connections", {"ip": ip, **window}):
            node(row["DeviceName"], "host")
            inv.edges.append((row["DeviceName"], ip, "connected"))
    for d in sorted(bad_domains):
        inv.plan.append(f"analyze_url_entity({d})")
        info = tools.analyze_url_entity(d)
        inv.entity_context[d] = info
        for who in info["clicked_by"]:
            node(who, "account")
            inv.edges.append((who, d, "clicked"))

    # scope: tenant accounts and hosts that took part in suspicious activity; attacker addresses
    involved_accounts = {n for n, k in inv.nodes.items() if k == "account" and n.lower().endswith("@" + tenant.domain)}
    if inc.sources == ["password-spray"] or set(inc.sources) <= {"password-spray", "Password spray", "success-after-spray"}:
        # spray targets that only failed are victims of noise, not compromised accounts
        succeeded = {e.summary.split(" for ")[1].split(" from ")[0] for e in inv.evidence if e.summary.startswith("sign-in success")}
        involved_accounts &= succeeded | set(accounts if "success-after-spray" in inc.sources else [])
    inv.scope = {
        "accounts": sorted(involved_accounts),
        "hosts": sorted(n for n, k in inv.nodes.items() if k == "host" and n.upper().startswith(tenant.prefix + "-")),
        "external_ips": sorted(n for n, k in inv.nodes.items() if k == "ip" and n not in benign_ips),
        "destinations": sorted(n for n, k in inv.nodes.items() if k in ("destination", "domain")),
    }
    # number evidence in time order so EV-001 is the earliest event
    order = sorted(inv.evidence, key=lambda e: (e.time, e.event_id))
    inv.evidence = [replace(e, id=f"EV-{n:03d}") for n, e in enumerate(order, 1)]
    users = store.users()
    inv.blast_radius = {
        "privileged_accounts": [a for a in inv.scope["accounts"] if users.get(a, {}).get("IsPrivileged")],
        "crown_jewels": [h for h in inv.scope["hosts"] if h in tenant.crown_jewels],
        "external_destinations": inv.scope["destinations"],
        "evidence_rows": len(inv.evidence),
        "routine_rows": sum(inv.routine.values()),
    }
    inv.tool_calls = sum(1 for c in tools.calls if c.allowed)
    inv.denied_calls = sum(1 for c in tools.calls if not c.allowed)
    inv.ms = round((time.perf_counter() - t0) * 1000, 2)
    return inv


def describe(inv: Investigation, limit: int = 12) -> list[str]:
    return [f"{e.id} {rel(e.time)} {e.summary} [{e.why}]" for e in inv.timeline()[:limit]]
