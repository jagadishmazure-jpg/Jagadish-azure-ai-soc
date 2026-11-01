"""Exposure context for triage: is the asset behind this alert critical, exposed and on a route to a crown jewel?

For every host or account on an incident, the triage view shows three facts from config/exposure.yaml
(synthetic):

* asset criticality 1-10: crown jewels are 10, otherwise a base value by role; a human override always
  wins and is shown with who set it and why;
* open known-exploited findings (the `kev` flag on a synthetic finding);
* on attack path: the host can reach a crown jewel through the "can reach" edges.

The context adds a bounded boost to queue priority. It never changes the verdict, the tier or the
containment plan, so it cannot auto-close or auto-contain anything. `choke_points` ranks the hosts whose
removal cuts the most entry-to-crown-jewel paths."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

import yaml

from aisoc import CONFIG
from aisoc.tenants import get

MAX_BOOST = 0.3


@cache
def config() -> dict:
    return yaml.safe_load((CONFIG / "exposure.yaml").read_text())


@dataclass(frozen=True)
class Context:
    asset: str
    kind: str  # host | account
    criticality: int
    criticality_source: str
    kev_open: tuple[str, ...]
    on_attack_path: bool
    path: tuple[str, ...]

    @property
    def boost(self) -> float:
        b = 0.015 * self.criticality + 0.06 * min(len(self.kev_open), 2) + (0.09 if self.on_attack_path else 0.0)
        return round(min(MAX_BOOST, b), 3)

    def line(self) -> str:
        parts = [f"criticality {self.criticality}/10 ({self.criticality_source})"]
        parts.append(f"{len(self.kev_open)} open known-exploited finding(s)" + (f" {', '.join(self.kev_open)}" if self.kev_open else ""))
        parts.append(f"on attack path {' -> '.join(self.path)}" if self.on_attack_path else "not on an attack path to a crown jewel")
        return f"{self.asset}: " + "; ".join(parts)


def _tenant(tenant: str) -> dict:
    return config()["tenants"].get(tenant, {"hosts": {}, "edges": [], "overrides": {}})


def paths_to_jewels(tenant: str, start: str) -> list[tuple[str, ...]]:
    t = _tenant(tenant)
    jewels = set(get(tenant).crown_jewels)
    adj: dict[str, list[str]] = {}
    for a, b in t["edges"]:
        adj.setdefault(a, []).append(b)
    out: list[tuple[str, ...]] = []

    def walk(node: str, seen: tuple[str, ...]) -> None:
        if node in jewels and len(seen) > 1:
            out.append(seen)
            return
        for nxt in adj.get(node, []):
            if nxt not in seen:
                walk(nxt, (*seen, nxt))

    walk(start, (start,))
    return sorted(out, key=len)


def context(tenant: str, kind: str, asset: str) -> Context:
    cfg, t = config(), _tenant(tenant)
    ten = get(tenant)
    override = (t.get("overrides") or {}).get(asset)
    if kind == "host":
        h = t["hosts"].get(asset, {"role": "workstation"})
        crit = 10 if asset in ten.crown_jewels else cfg["roles"][h["role"]]
        src = "crown jewel" if asset in ten.crown_jewels else f"role {h['role']}"
        kev = tuple(f["id"] for f in h.get("findings", []) if f["kev"])
        paths = paths_to_jewels(tenant, asset)
    else:
        a = cfg["accounts"]
        if asset in ten.approvers or asset in ten.break_glass:
            crit, src = 9, "approver or break-glass account"
        elif asset.startswith(a["service_account_prefix"]):
            crit, src = a["service_account"], "service account"
        else:
            crit, src = a["default"], "standard user"
        kev, paths = (), []
    if override:
        crit, src = int(override["criticality"]), f"override by {override['by']}: {override['why']}"
    return Context(asset, kind, crit, src, kev, bool(paths), paths[0] if paths else ())


def for_entities(tenant: str, entities: list[tuple[str, str]]) -> list[Context]:
    return [context(tenant, k, v) for k, v in sorted(set(entities)) if k in ("host", "account")]


def boost(contexts: list[Context]) -> float:
    return max((c.boost for c in contexts), default=0.0)


def choke_points(tenant: str) -> list[tuple[str, int]]:
    """Hosts ranked by how many entry-to-crown-jewel paths pass through them (entries = hosts with no inbound edge)."""
    t = _tenant(tenant)
    jewels = set(get(tenant).crown_jewels)
    inbound = {b for _, b in t["edges"]}
    entries = sorted({a for a, _ in t["edges"]} - inbound)
    counts: dict[str, int] = {}
    for e in entries:
        for p in paths_to_jewels(tenant, e):
            for node in p:
                if node not in jewels:
                    counts[node] = counts.get(node, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def incident_entities(case) -> list[tuple[str, str]]:
    return [(e["type"], e["value"]) for a in case.incident.alerts for e in a.entities]


def queue(run, tenant: str) -> list[dict]:
    """Escalated queue (tier 2 and 3) ordered by P(malicious) alone and with the exposure boost."""
    rows = []
    for c in run.tenants[tenant].cases:
        if c.route.tier < 2:
            continue
        ctx = for_entities(tenant, incident_entities(c))
        rows.append({"incident": c.incident.id, "p": round(c.incident.p_malicious, 3), "boost": boost(ctx), "context": ctx, "case": c})
    base = sorted(rows, key=lambda r: (-r["p"], r["incident"]))
    withx = sorted(rows, key=lambda r: (-(r["p"] + r["boost"]), r["incident"]))
    for i, r in enumerate(base, 1):
        r["rank_before"] = i
    for i, r in enumerate(withx, 1):
        r["rank_after"] = i
    return withx


def evaluate(run=None) -> dict:
    """Effect on the escalated queues, measured against the labels (reads gold verdicts)."""
    from aisoc import metrics, pipeline
    from aisoc.tenants import tenants

    run = run or pipeline.run("learning")
    moved = top_before = top_after = tps = 0
    for t in sorted(tenants()):
        q = queue(run, t)
        n_tp = sum(metrics.gold(r["case"]) == "true_positive" for r in q)
        tps += n_tp
        for r in q:
            moved += r["rank_before"] != r["rank_after"]
            if metrics.gold(r["case"]) == "true_positive":
                top_before += r["rank_before"] <= n_tp
                top_after += r["rank_after"] <= n_tp
    return {
        "escalated_incidents": sum(1 for c in run.cases() if c.route.tier >= 2),
        "true_positives_escalated": tps,
        "rank_changes": moved,
        "true_positives_in_top_slots_before": f"{top_before}/{tps}",
        "true_positives_in_top_slots_after": f"{top_after}/{tps}",
        "verdicts_or_tiers_changed": 0,
    }


def report(tenant: str = "brightwater") -> str:
    from aisoc import endpoint, pipeline

    run = pipeline.run("learning")
    lines = [f"Exposure context in triage ({get(tenant).name}, synthetic)", "", "Escalated queue (P = model probability, +X = exposure boost):"]
    for r in queue(run, tenant):
        lines.append(f"  #{r['rank_after']:<2} (was #{r['rank_before']:<2}) {r['incident']}  P {r['p']:.3f} +{r['boost']:.3f}")
        for c in r["context"]:
            if c.kind == "host" or c.criticality >= 7:
                lines.append(f"       {c.line()}")
    if tenant == endpoint.TENANT:
        lines += ["", "Endpoint pack hosts:"] + [f"  {context(tenant, 'host', t.host).line()}" for t in endpoint.triage_all()]
    lines += ["", "Choke points (fix one, cut the most paths to a crown jewel):"]
    lines += [f"  fixing {h} closes {n} path(s)" for h, n in choke_points(tenant)] or ["  none"]
    lines += ["", "Measured across all tenants (synthetic labels):"] + [f"  {k}: {v}" for k, v in evaluate(run).items()]
    return "\n".join(lines)
