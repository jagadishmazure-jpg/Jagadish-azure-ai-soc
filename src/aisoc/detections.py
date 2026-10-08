"""Scheduled analytics rules, simulated locally.

Each rule's KQL runs once over the tenant's whole timeline through the pure-Python engine; every result
row becomes an alert. The alert time is what Sentinel would see: the moment the contributing events
crossed the rule's condition (first event, n-th event, or n-th distinct value), plus the assumed
ingestion delay, rounded up to the rule's next scheduled run. Product alerts already present in the
SecurityAlert table (Defender for Endpoint, Defender for Office 365, Entra ID Protection) join the stream
as they are."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache
from typing import Any

import yaml

from aisoc import CONFIG, DETECTIONS, kql
from aisoc.store import TenantStore

ISO = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?")


@dataclass
class Alert:
    id: str
    tenant: str
    source: str  # analytics rule id, or the product alert name
    name: str
    severity: str
    time: datetime
    techniques: list[str]
    tactics: list[str]
    entities: list[dict]  # {"type": account|host|ip|url|mailbox, "value": ...}
    event_ids: list[str]
    fields: dict[str, Any] = field(default_factory=dict)
    product: bool = False

    def entity_values(self, kind: str) -> list[str]:
        return [e["value"] for e in self.entities if e["type"] == kind]


def iso_duration(s: str) -> timedelta:
    m = ISO.fullmatch(s)
    if not m:
        raise ValueError(s)
    d, h, mi = (int(x) if x else 0 for x in m.groups())
    return timedelta(days=d, hours=h, minutes=mi)


@cache
def rules() -> list[dict]:
    doc = yaml.safe_load((DETECTIONS / "rules.yaml").read_text())
    for r in doc["rules"]:
        r["query"] = (DETECTIONS / r["file"]).read_text()
    return doc["rules"]


def rule(rule_id: str) -> dict:
    return next(r for r in rules() if r["id"] == rule_id)


@cache
def ingestion_delay() -> timedelta:
    return timedelta(minutes=yaml.safe_load((CONFIG / "thresholds.yaml").read_text())["ingestion_delay_minutes"])


def _ceil(ts: datetime, step: timedelta) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=ts.tzinfo)
    secs = (ts - epoch).total_seconds()
    s = step.total_seconds()
    return epoch + timedelta(seconds=math.ceil(secs / s) * s)


def _crossing(store: TenantStore, spec: dict, row: dict, ids: list[str]) -> datetime:
    times = sorted((store.event_time(e), e) for e in ids if store.event_time(e))
    if "nth" in spec:
        return times[min(spec["nth"], len(times)) - 1][0]
    if "distinct" in spec:
        seen: set[Any] = set()
        for ts, e in times:
            seen.add(store.event(e)[1].get(spec["distinct"]))
            if len(seen) >= spec["n"]:
                return ts
        return times[-1][0]
    return row.get("TimeGenerated") or times[0][0]


def _row_ids(row: dict) -> list[str]:
    if "EventIds" in row:
        return list(row["EventIds"])
    return [row["EventId"]] if row.get("EventId") else []


def run_rule(store: TenantStore, r: dict) -> list[Alert]:
    out = []
    for i, row in enumerate(kql.run(r["query"], store.tables, store.now)):
        ids = _row_ids(row)
        crossed = _crossing(store, r["crossing"], row, ids)
        when = _ceil(crossed + ingestion_delay(), iso_duration(r["frequency"]))
        ents = [{"type": t, "value": row[c]} for c, t in r["entities"].items() if row.get(c)]
        fields = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items() if k not in ("EventIds", "EventId")}
        out.append(
            Alert(
                id=f"{store.tenant.id[:2]}-{r['id']}-{i:03d}",
                tenant=store.tenant.id,
                source=r["id"],
                name=r["name"],
                severity=r["severity"],
                time=when,
                techniques=list(r["techniques"]),
                tactics=list(r["tactics"]),
                entities=ents,
                event_ids=ids,
                fields=fields,
            )
        )
    return out


def product_alerts(store: TenantStore) -> list[Alert]:
    out = []
    for row in store.tables.get("SecurityAlert", []):
        ents = []
        for e in row["Entities"] if isinstance(row["Entities"], list) else json.loads(row["Entities"]):
            t = e["Type"]
            val = e.get("Name") or e.get("HostName") or e.get("Address") or e.get("Url")
            ents.append({"type": {"mailbox": "account"}.get(t, t), "value": val})
        out.append(
            Alert(
                id=row["SystemAlertId"],
                tenant=store.tenant.id,
                source=row["AlertName"],
                name=row["AlertName"],
                severity=row["AlertSeverity"],
                time=row["TimeGenerated"],
                techniques=list(row["Techniques"]),
                tactics=list(row["Tactics"]),
                entities=ents,
                event_ids=list(row["EventIds"]),
                fields={"Description": row["Description"], "ProductName": row["ProductName"]},
                product=True,
            )
        )
    return out


def all_alerts(store: TenantStore) -> list[Alert]:
    alerts = [a for r in rules() for a in run_rule(store, r)] + product_alerts(store)
    return sorted(alerts, key=lambda a: (a.time, a.id))


def rules_json() -> dict:
    """detections/rules.json: rules with their query text embedded, for Terraform and Bicep."""
    keep = ("id", "name", "severity", "tactics", "techniques", "frequency", "period", "entities")
    return {
        "generated_by": "scripts/build_rules.py from detections/rules.yaml and the .kql files; do not edit",
        "rules": [
            {**{k: r[k] for k in keep}, "parent_techniques": sorted({t.split(".")[0] for t in r["techniques"]}), "query": r["query"]} for r in rules()
        ],
    }
