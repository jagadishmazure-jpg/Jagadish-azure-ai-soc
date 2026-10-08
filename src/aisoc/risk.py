"""Predictive risk: which accounts and hosts should the SOC watch tomorrow?

At midnight each day the model ranks a tenant's accounts and hosts from signals seen so far:
* download drift: the last four days against the account's earlier baseline (insider build-up);
* failed sign-ins from an address on the threat-intel feed in the last three days (credential probing);
* email from a domain on the threat-intel feed in the last three days (lures);
* privileged accounts get a small weight;
* hosts: open critical vulnerabilities weighted by asset criticality, plus internet exposure.

Evaluation (`evaluate`): for every attack story, was the targeted entity in the tenant's top five at the
midnight before the attack? Plus precision over all daily top-five lists.

Honesty note: the synthetic generator planted these precursors on purpose (aisoc.synth), so a high hit
rate shows the model reads the signals it was built for, not that it predicts real attacks. Stories
with no precursor (password spray) are expected misses and are reported as such."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from aisoc import intel, labels
from aisoc.store import TenantStore, load
from aisoc.synth import DAYS, T0, day_of
from aisoc.tenants import tenants

TOP_K = 5


@dataclass(frozen=True)
class Risk:
    entity: str
    kind: str
    score: float
    reasons: tuple[str, ...]


def rank(store: TenantStore, as_of: datetime) -> list[Risk]:
    day = day_of(as_of)
    recent = as_of - timedelta(days=3)
    users = store.users()
    out: dict[str, list] = {u: [0.0, []] for u in users}
    downloads: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for r in store.tables["CloudAppEvents"]:
        if r["TimeGenerated"] < as_of and r["ActionType"] == "FileDownloaded":
            downloads[r["AccountUpn"]][day_of(r["TimeGenerated"])] += 1
    for u, by_day in downloads.items():
        if u not in out:
            continue
        last = [by_day.get(d, 0) for d in range(day - 4, day)]
        base = [by_day.get(d, 0) for d in range(max(0, day - 18), day - 4)]
        base_mean = sum(base) / max(1, len(base))
        if sum(last) >= 20 and last == sorted(last) and last[-1] > 1.5 * max(base_mean, 1):
            out[u][0] += 0.4
            out[u][1].append(f"downloads rising {last} vs baseline {base_mean:.1f}/day")
    for r in store.tables["SigninLogs"]:
        t = r["TimeGenerated"]
        if recent <= t < as_of and str(r["ResultType"]) != "0" and intel.lookup("ip", r["IPAddress"], day_of(t)):
            u = r["UserPrincipalName"]
            if u in out and not any("probing" in x for x in out[u][1]):
                out[u][0] += 0.4
                out[u][1].append(f"credential probing: failed sign-ins from threat-intel address {r['IPAddress']}")
    for r in store.tables["EmailEvents"]:
        t = r["TimeGenerated"]
        if recent <= t < as_of:
            hits = intel.lookup("url", r.get("Url") or "", day_of(t)) + intel.lookup("mailbox", r["SenderFromAddress"], day_of(t))
            u = r["RecipientEmailAddress"]
            if hits and u in out and not any("lure" in x for x in out[u][1]):
                out[u][0] += 0.3
                out[u][1].append("received a lure linking to a threat-intel domain")
    for u, info in users.items():
        if info.get("IsPrivileged") and out[u][0] > 0:
            out[u][0] += 0.1
            out[u][1].append("privileged")
    risks = [Risk(u, "account", round(s, 2), tuple(r)) for u, (s, r) in out.items() if s > 0]
    for h, a in store.assets().items():
        s, why = 0.0, []
        cves = a.get("OpenCriticalCves") or 0
        if cves:
            s += min(0.4, 0.1 * cves * (a.get("Criticality", 1) / 5))
            why.append(f"{cves} open critical CVEs, criticality {a.get('Criticality')}")
        if a.get("InternetFacing"):
            s += 0.1
            why.append("internet facing")
        if s:
            risks.append(Risk(h, "host", round(s, 2), tuple(why)))
    return sorted(risks, key=lambda x: (-x.score, x.entity))


def evaluate(horizon_days: int = 3) -> dict:
    per_story = []
    slots = hits = 0
    base_num = base_den = 0
    for t in sorted(tenants()):
        store = load(t)
        st = labels.stories(t)
        for s in st:
            midnight = T0 + timedelta(days=s["day"])
            top = rank(store, midnight)[:TOP_K]
            targets = set(s["entities"]["accounts"]) | set(s["entities"]["hosts"])
            found = [r for r in top if r.entity in targets]
            per_story.append({"tenant": t, "story": s["id"], "hit": bool(found), "reasons": list(found[0].reasons) if found else []})
        everyone = set(store.users()) | set(store.assets())
        for d in range(1, DAYS):
            soon = {e for s in st if 0 <= s["day"] - d < horizon_days for e in s["entities"]["accounts"] + s["entities"]["hosts"]}
            base_num += len(soon & everyone)
            base_den += len(everyone)
            top = rank(store, T0 + timedelta(days=d))[:TOP_K]
            for r in top:
                slots += 1
                hits += any(r.entity in (set(s["entities"]["accounts"]) | set(s["entities"]["hosts"])) and 0 <= s["day"] - d < horizon_days for s in st)
    n_entities = sum(len(load(t).users()) + len(load(t).assets()) for t in tenants())
    per_tenant = n_entities / len(tenants())
    return {
        "stories": len(per_story),
        "stories_flagged_day_before": sum(p["hit"] for p in per_story),
        "precision_at_5_pct": round(100 * hits / slots, 1) if slots else 0.0,
        "random_story_hit_pct": round(100 * TOP_K / per_tenant, 1),
        "random_precision_pct": round(100 * base_num / base_den, 1) if base_den else 0.0,
        "per_story": per_story,
    }
