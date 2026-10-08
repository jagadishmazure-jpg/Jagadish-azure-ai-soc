"""Per-tenant data store: the only way agents and tools reach telemetry.

`TenantStore` holds one tenant's tables plus the shared threat-intel table. It never exposes ground
truth (labels live in `aisoc.labels`), and there is no API that returns another tenant's rows, so a
tool bound to one store cannot reach a second tenant even with a hand-written query."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache

from aisoc import intel, synth
from aisoc.tenants import Tenant, get

SECURITY_TABLES = ("SigninLogs", "DeviceProcessEvents", "DeviceNetworkEvents", "EmailEvents", "UrlClickEvents", "CloudAppEvents", "SecurityAlert")
CONTEXT_TABLES = ("IdentityInfo", "DeviceInfo", "ThreatIntelligenceIndicator")


@dataclass
class TenantStore:
    tenant: Tenant
    tables: dict[str, list[dict]]
    now: datetime
    _events: dict[str, tuple[str, dict]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name, rows in self.tables.items():
            for r in rows:
                if "EventId" in r:
                    self._events[r["EventId"]] = (name, r)

    def event(self, event_id: str) -> tuple[str, dict] | None:
        return self._events.get(event_id)

    def event_time(self, event_id: str) -> datetime | None:
        e = self._events.get(event_id)
        return e[1]["TimeGenerated"] if e else None

    def users(self) -> dict[str, dict]:
        return {u["AccountUpn"]: u for u in self.tables["IdentityInfo"]}

    def assets(self) -> dict[str, dict]:
        return {a["DeviceName"]: a for a in self.tables["DeviceInfo"]}

    def schema(self) -> dict[str, list[str]]:
        out = {}
        for name, rows in self.tables.items():
            cols: list[str] = []
            for r in rows[:50]:
                for k in r:
                    if k not in cols:
                        cols.append(k)
            out[name] = cols
        return out

    def slice(self, end: datetime) -> TenantStore:
        """A view of the store as it looked at `end` (rows after it removed)."""
        tables = {k: [r for r in v if r["TimeGenerated"] <= end] for k, v in self.tables.items()}
        return TenantStore(self.tenant, tables, end)


def fresh(tenant_id: str, seed: int = synth.SEED) -> TenantStore:
    """An uncached, private copy of a tenant's store (tests mutate it to plant canaries)."""
    ds = synth.generate(tenant_id, seed)
    now = synth.T0 + timedelta(days=synth.DAYS)
    tables = {k: [dict(r) for r in v] for k, v in ds.tables.items()}
    tables["ThreatIntelligenceIndicator"] = intel.table(synth.DAYS)
    return TenantStore(get(tenant_id), tables, now)


@cache
def load(tenant_id: str, seed: int = synth.SEED) -> TenantStore:
    """The shared, cached store for a tenant. Treat it as read-only."""
    return fresh(tenant_id, seed)
