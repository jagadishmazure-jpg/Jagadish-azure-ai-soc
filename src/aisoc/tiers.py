"""Service tiers with SLAs, checked against the synthetic run.

config/service-tiers.yaml defines three fictional packages (Essentials, Standard, Plus) and maps each
customer to one. `sla(run, tenant)` measures, per customer:

* MTTD per attack story (aisoc.metrics.stories, measured);
* time to human acknowledgement: first alert to the analyst's decision, for escalated incidents (measured
  on the simulated analyst clock);
* MTTR per contained story (simulated, see aisoc.metrics).

Every breach is listed; nothing is rounded in the customer's favour."""

from __future__ import annotations

import statistics
from functools import cache

import yaml

from aisoc import CONFIG
from aisoc.tenants import get


@cache
def config() -> dict:
    return yaml.safe_load((CONFIG / "service-tiers.yaml").read_text())


def tier_of(tenant: str) -> dict:
    key = config()["customers"][tenant]
    return {"key": key, **config()["tiers"][key]}


def sla(run, tenant: str) -> dict:
    from aisoc import metrics

    t = tier_of(tenant)
    target = t["sla_min"]
    stories = [s for s in metrics.stories(run) if s.tenant == tenant]
    acks = [
        round((c.decision.decided_at - c.incident.start).total_seconds() / 60, 1)
        for c in run.tenants[tenant].cases
        if c.route.tier >= 2 and c.decision
    ]
    breaches = []
    for s in stories:
        if s.mttd_min is None:
            breaches.append(f"{s.story}: not detected")
        elif s.mttd_min > target["mttd"]:
            breaches.append(f"{s.story}: MTTD {s.mttd_min} min > {target['mttd']}")
        if s.mttr_min is not None and s.mttr_min > target["mttr"]:
            breaches.append(f"{s.story}: simulated MTTR {s.mttr_min} min > {target['mttr']}")
    late_acks = [a for a in acks if a > target["ack"]]
    if late_acks:
        breaches.append(f"{len(late_acks)} escalated incident(s) acknowledged after {target['ack']} min (worst {max(late_acks)})")
    return {
        "tenant": tenant,
        "customer": get(tenant).name,
        "tier": t["name"],
        "targets": target,
        "stories": len(stories),
        "mttd_max": max((s.mttd_min for s in stories if s.mttd_min is not None), default=None),
        "ack_median": statistics.median(acks) if acks else None,
        "ack_max": max(acks) if acks else None,
        "mttr_max_simulated": max((s.mttr_min for s in stories if s.mttr_min is not None), default=None),
        "breaches": breaches,
    }


def evaluate(run=None) -> dict:
    from aisoc import pipeline
    from aisoc.tenants import tenants

    run = run or pipeline.run("learning")
    rows = [sla(run, t) for t in sorted(tenants())]
    return {r["tenant"]: f"{r['tier']}: {len(r['breaches'])} breach(es)" for r in rows}


def report() -> str:
    from aisoc import pipeline
    from aisoc.tenants import tenants

    run = pipeline.run("learning")
    lines = ["Service tiers (fictional packaging; SLAs in minutes)", ""]
    for t in config()["tiers"].values():
        lines.append(f"{t['name']:<11} MTTD {t['sla_min']['mttd']:>3}  ack {t['sla_min']['ack']:>3}  MTTR {t['sla_min']['mttr']:>3}  {t['hours']}")
        lines.append(f"            for {t['for']}; covers {', '.join(t['coverage'])}")
    lines.append("")
    for t in sorted(tenants()):
        r = sla(run, t)
        lines.append(f"{r['customer']} ({r['tier']}): {r['stories']} attack stories, worst MTTD {r['mttd_max']} min, "
                     f"ack median {r['ack_median']} / worst {r['ack_max']} min, worst simulated MTTR {r['mttr_max_simulated']} min")  # fmt: skip
        lines += [f"    BREACH {b}" for b in r["breaches"]] or ["    all targets met"]
    return "\n".join(lines)
