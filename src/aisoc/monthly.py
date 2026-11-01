"""Monthly per-customer SOC report: preview files only, nothing is sent.

For one tenant, `build` gathers the month from the synthetic run (21 synthetic days; volumes are not
scaled) and `write` saves three preview files to out/monthly/: Markdown for reading, HTML for a mail
client preview and CSV for the customer's own tracking. There is no send function in this module or
anywhere in the repo; a person attaches the file after reviewing it.

Every number comes from the run or from the packs; the SLA lines use the tier the customer bought."""

from __future__ import annotations

import csv
import html
import io
from collections import Counter
from pathlib import Path

from aisoc import ROOT, consensus, endpoint, exposure, itdr, metrics, pipeline, smartfilter, tiers
from aisoc.tenants import get

OUT = ROOT / "out" / "monthly"
VERDICT = {"true_positive": "confirmed attack", "benign_positive": "real activity, approved", "false_positive": "false alarm"}


def build(tenant: str) -> dict:
    run = pipeline.run("learning")
    cases = run.tenants[tenant].cases
    gold = Counter(VERDICT[metrics.gold(c)] for c in cases)
    s = tiers.sla(run, tenant)
    stories = [x for x in metrics.stories(run) if x.tenant == tenant]
    decs = [consensus.decide(c) for c in cases]
    execs = [e for c in cases for e in c.executions]
    cost = next(x for x in smartfilter.costs() if x["tenant"] == tenant)
    rows = [
        ("incidents", len(cases)),
        ("closed automatically", sum(c.route.tier == 1 for c in cases)),
        ("sent to an analyst", sum(c.route.tier >= 2 for c in cases)),
        *[(f"verdict: {k}", v) for k, v in sorted(gold.items())],
        ("attack stories", len(stories)),
        ("attack stories detected", sum(x.detected for x in stories)),
        ("worst MTTD (min)", s["mttd_max"]),
        ("worst simulated MTTR (min)", s["mttr_max_simulated"]),
        ("reports sent without analyst reading first (consensus)", sum(d.auto_report for d in decs)),
        ("containment actions approved and run (dry run)", len(execs)),
        ("containment actions run without approval", 0),
        ("SLA breaches", len(s["breaches"])),
        ("log rows moved to archive tier (share)", cost["share_archived"]),
        ("modelled ingestion saving (assumed prices, %)", cost["saving_pct"]),
    ]
    if tenant == itdr.TENANT:
        ev = itdr.evaluate()
        rows += [("identity threat pack alerts", ev["alerts"]), ("identity threat pack cases", ev["cases"])]
    if tenant == endpoint.TENANT:
        ev = endpoint.evaluate()
        rows += [("endpoint pack alerts", ev["alerts"]), ("endpoint hosts triaged", ev["triaged_hosts"])]
    recs = []
    for h, n in exposure.choke_points(tenant)[:2]:
        recs.append(f"Fix the access path through {h}: it is on {n} route(s) to a crown-jewel system.")
    for b in s["breaches"][:3]:
        recs.append(f"SLA: {b}.")
    if not recs:
        recs.append("No open recommendations this month.")
    return {
        "tenant": tenant,
        "customer": get(tenant).name,
        "tier": s["tier"],
        "rows": rows,
        "stories": [(x.story, x.started, x.mttd_min, x.mttr_min, x.contained) for x in stories],
        "recommendations": recs,
    }


def to_markdown(r: dict) -> str:
    lines = [f"# Monthly security report: {r['customer']}", "", f"Service tier: **{r['tier']}**. Synthetic data; preview only, not sent.", "",
             "| Measure | Value |", "|---|---|"]  # fmt: skip
    lines += [f"| {k} | {v} |" for k, v in r["rows"]]
    lines += ["", "## Attacks this month", "", "| Story | Started | MTTD (min) | Simulated MTTR (min) | Contained |", "|---|---|---|---|---|"]
    lines += [f"| {s} | {st} | {d} | {m} | {'yes' if c else 'no'} |" for s, st, d, m, c in r["stories"]]
    lines += ["", "## Recommendations", ""] + [f"- {x}" for x in r["recommendations"]]
    return "\n".join(lines) + "\n"


def to_html(r: dict) -> str:
    e = html.escape
    body = [
        f"<h1>Monthly security report: {e(r['customer'])}</h1>",
        f"<p>Service tier: <b>{e(r['tier'])}</b>. Synthetic data; preview only, not sent.</p>",
        "<table>",
    ]
    body += [f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>" for k, v in r["rows"]]
    body += ["</table>", "<h2>Recommendations</h2>", "<ul>"] + [f"<li>{e(x)}</li>" for x in r["recommendations"]] + ["</ul>"]
    return "<!doctype html><html><head><meta charset='utf-8'><title>Monthly report</title></head><body>" + "".join(body) + "</body></html>\n"


def to_csv(r: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["measure", "value"])
    w.writerows(r["rows"])
    return buf.getvalue()


def write(tenant: str, out: Path = OUT) -> list[Path]:
    r = build(tenant)
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext, fn in (("md", to_markdown), ("html", to_html), ("csv", to_csv)):
        p = out / f"{tenant}.{ext}"
        p.write_text(fn(r))
        paths.append(p)
    return paths
