"""The fictional MSSP and its tenants (config/tenants.yaml). A `Tenant` is the isolation boundary:
data, knowledge, learned thresholds, pseudonym maps and the audit chain are all keyed by tenant id."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache

import yaml

from aisoc import CONFIG


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str
    industry: str
    domain: str
    workspace: str
    home_country: str
    users: int
    hosts: int
    vpn_egress: tuple[dict, ...]
    authorized_scanners: tuple[str, ...]
    phish_sim_sender: str
    approvers: tuple[str, ...]
    break_glass: tuple[str, ...]
    crown_jewels: tuple[str, ...]
    prefix: str = field(default="")

    @property
    def vpn_ips(self) -> set[str]:
        return {v["ip"] for v in self.vpn_egress}


PREFIX = {"brightwater": "BWL", "orchidvalley": "OVC", "pinecrest": "PCU"}


@cache
def mssp() -> dict:
    return yaml.safe_load((CONFIG / "tenants.yaml").read_text())["mssp"]


@cache
def tenants() -> dict[str, Tenant]:
    doc = yaml.safe_load((CONFIG / "tenants.yaml").read_text())
    out = {}
    for t in doc["tenants"]:
        out[t["id"]] = Tenant(
            id=t["id"],
            name=t["name"],
            industry=t["industry"],
            domain=t["domain"],
            workspace=t["workspace"],
            home_country=t["home_country"],
            users=t["users"],
            hosts=t["hosts"],
            vpn_egress=tuple(t["vpn_egress"]),
            authorized_scanners=tuple(t["authorized_scanners"]),
            phish_sim_sender=t["phish_sim_sender"],
            approvers=tuple(t["approvers"]),
            break_glass=tuple(t["break_glass"]),
            crown_jewels=tuple(t["crown_jewels"]),
            prefix=PREFIX.get(t["id"], t["id"][:3].upper()),
        )
    return out


def get(tenant_id: str) -> Tenant:
    try:
        return tenants()[tenant_id]
    except KeyError:
        raise KeyError(f"unknown tenant {tenant_id!r}; known: {sorted(tenants())}") from None
