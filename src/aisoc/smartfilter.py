"""Log-filtering cost simulation per customer, with a replay check that no detection is lost.

Each candidate filter in config/smart-filter.yaml moves matching rows from the analytics tier to an
archive tier. A filter is accepted only if the detections produce exactly the same alerts (same alert ids
and the same event ids) on the filtered data as on the full data, in every tenant. Accepted filters are
then priced with assumed per-GB prices to show the monthly saving per customer. Volumes are synthetic and
prices are assumptions, so the output is a method, not a forecast."""

from __future__ import annotations

import json
from functools import cache

import yaml

from aisoc import CONFIG
from aisoc.detections import all_alerts
from aisoc.store import TenantStore, load
from aisoc.synth import DAYS
from aisoc.tenants import tenants


@cache
def config() -> dict:
    return yaml.safe_load((CONFIG / "smart-filter.yaml").read_text())


def matches(f: dict, row: dict) -> bool:
    return all(row.get(k) in v for k, v in f["match"].items())


def apply(store: TenantStore, filters: list[dict]) -> tuple[TenantStore, dict[str, list[dict]]]:
    kept: dict[str, list[dict]] = {}
    archived: dict[str, list[dict]] = {}
    for name, rows in store.tables.items():
        fs = [f for f in filters if f["table"] == name]
        kept[name] = [r for r in rows if not any(matches(f, r) for f in fs)]
        archived[name] = [r for r in rows if any(matches(f, r) for f in fs)]
    return TenantStore(store.tenant, kept, store.now), archived


def _sig(alerts) -> set[tuple]:
    return {(a.id, tuple(a.event_ids)) for a in alerts}


def replay(filters: list[dict]) -> dict[str, list[str]]:
    """Alerts lost per tenant if these filters were applied (empty lists = nothing lost)."""
    out = {}
    for t in sorted(tenants()):
        full = load(t)
        filtered, _ = apply(full, filters)
        out[t] = sorted(a for a, _ in _sig(all_alerts(full)) - _sig(all_alerts(filtered)))
    return out


def _gb(rows: list[dict]) -> float:
    ovh = config()["bytes_overhead_per_row"]
    return sum(len(json.dumps(r, default=str)) + ovh for r in rows) / 1e9


@cache
def decide() -> tuple[list[dict], dict[str, dict[str, list[str]]]]:
    accepted, rejected = [], {}
    for f in config()["filters"]:
        hidden = [c["why"] for c in config().get("canaries", []) if c["table"] == f["table"] and matches(f, c["row"])]
        if hidden:
            rejected[f["id"]] = {"planted canary": hidden}
            continue
        lost = replay([*accepted, f])
        if any(lost.values()):
            rejected[f["id"]] = {t: v for t, v in lost.items() if v}
        else:
            accepted.append(f)
    return accepted, rejected


def costs() -> list[dict]:
    accepted, _ = decide()
    price = config()["assumed_price_per_gb"]
    scale = config()["scale_to_month_days"] / DAYS
    out = []
    for t in sorted(tenants()):
        full = load(t)
        _, archived = apply(full, accepted)
        all_rows = [r for rows in full.tables.values() for r in rows]
        arch_rows = [r for rows in archived.values() for r in rows]
        gb_all, gb_arch = _gb(all_rows) * scale, _gb(arch_rows) * scale
        before = gb_all * price["analytics"]
        after = (gb_all - gb_arch) * price["analytics"] + gb_arch * price["archive"]
        out.append({"tenant": t, "rows": len(all_rows), "rows_archived": len(arch_rows), "share_archived": round(len(arch_rows) / len(all_rows), 3),
                    "gb_month": round(gb_all, 5), "cost_before": round(before, 4), "cost_after": round(after, 4),
                    "saving_pct": round(100 * (before - after) / before, 1)})  # fmt: skip
    return out


def evaluate() -> dict:
    accepted, rejected = decide()
    lost = replay(accepted)
    c = costs()
    return {
        "candidate_filters": len(config()["filters"]),
        "accepted": [f["id"] for f in accepted],
        "rejected": {k: sum(len(v) for v in d.values()) for k, d in rejected.items()},
        "alerts_lost_with_accepted_filters": sum(len(v) for v in lost.values()),
        "rows_archived_share": {x["tenant"]: x["share_archived"] for x in c},
        "modelled_saving_pct": {x["tenant"]: x["saving_pct"] for x in c},
    }


def report() -> str:
    accepted, rejected = decide()
    lines = ["Log filtering simulation (synthetic volumes, ASSUMED prices)", ""]
    for f in config()["filters"]:
        if f in accepted:
            lines.append(f"ACCEPTED  {f['id']} ({f['table']}): {f['why']}")
        else:
            lost = rejected[f["id"]]
            what = "would hide a planted canary" if "planted canary" in lost else f"would lose {sum(len(v) for v in lost.values())} alert(s)"
            lines.append(f"REJECTED  {f['id']} ({f['table']}): {what}: {next(iter(lost.values()))[0]}")
    lines += ["", f"  {'tenant':<14}{'rows':>7}{'archived':>10}{'share':>8}{'saving':>9}"]
    for x in costs():
        lines.append(f"  {x['tenant']:<14}{x['rows']:>7}{x['rows_archived']:>10}{x['share_archived']:>8.1%}{x['saving_pct']:>8.1f}%")
    lines += ["", "Saving uses assumed per-GB prices from config/smart-filter.yaml; the replay check is the real result.", ""]
    lines += ["Measured:"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
