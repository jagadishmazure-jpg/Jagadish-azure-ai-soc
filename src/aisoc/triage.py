"""Triage agent logic: de-duplicate alerts, correlate them into incidents, enrich, score and give a verdict
with a confidence.

De-duplication merges alerts that share underlying events (a Defender product alert and an analytics
rule firing on the same process) or repeat the same rule on the same entity within the dedupe window.
Correlation joins alert groups that share an account, host, external address or URL within the
correlation window, measured from the incident's first alert.

Scoring is a transparent logistic model over named features, so every verdict can be explained term
by term. The model writes no part of the verdict; it only narrates it (aisoc.llm)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cache

import yaml

from aisoc import CONFIG, attack, guardrails, intel, ueba
from aisoc.detections import Alert, rule, rules
from aisoc.knowledge import KnowledgeBase
from aisoc.store import TenantStore
from aisoc.synth import CORP_EGRESS, day_of

PRODUCT_PRIORS = {
    "Atypical travel": 0.40,
    "Password spray": 0.55,
    "Suspicious PowerShell command line": 0.55,
    "Possible LSASS memory access": 0.75,
    "Email messages containing malicious URL removed after delivery": 0.55,
}
WEIGHTS = {
    "ti": 2.2,
    "ueba": 3.0,
    "two_tactics": 1.0,
    "three_tactics": 1.0,
    "injection": 1.5,
    "high_severity": 0.4,
    "context_benign": -4.0,
    "kb_benign": -3.0,
    "kb_malicious": 3.0,
}
VERDICTS = ("true_positive", "benign_positive", "false_positive")


@cache
def thresholds() -> dict:
    return yaml.safe_load((CONFIG / "thresholds.yaml").read_text())


@dataclass
class Learned:
    """Tenant-specific values learned by the feedback loop (aisoc.feedback); defaults until then."""

    priors: dict[str, float] = field(default_factory=dict)
    auto_close: dict[str, float] = field(default_factory=dict)

    def prior(self, source: str) -> float:
        if source in self.priors:
            return self.priors[source]
        try:
            return rule(source)["prior"]
        except StopIteration:
            return PRODUCT_PRIORS.get(source, 0.5)

    def threshold(self, source: str) -> float:
        return self.auto_close.get(source, thresholds()["auto_close_confidence"])


@dataclass
class Incident:
    id: str
    tenant: str
    alerts: list[Alert]
    duplicates: int = 0
    features: dict[str, float] = field(default_factory=dict)
    explanation: list[str] = field(default_factory=list)
    p_malicious: float = 0.0
    verdict: str = ""
    confidence: float = 0.0
    techniques: list[str] = field(default_factory=list)
    ti_hits: list[intel.Hit] = field(default_factory=list)
    anomalies: list[ueba.Anomaly] = field(default_factory=list)
    injection: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)

    @property
    def start(self):
        return min(a.time for a in self.alerts)

    @property
    def end(self):
        return max(a.time for a in self.alerts)

    @property
    def sources(self) -> list[str]:
        return sorted({a.source for a in self.alerts})

    @property
    def primary_source(self) -> str:
        return max(self.alerts, key=lambda a: (not a.product, a.time.timestamp() * -1)).source

    def entities(self, kind: str) -> list[str]:
        return sorted({v for a in self.alerts for v in a.entity_values(kind)})

    @property
    def event_ids(self) -> list[str]:
        return sorted({e for a in self.alerts for e in a.event_ids})

    @property
    def tactics(self) -> list[str]:
        return sorted({attack.tactic(t) for t in self.techniques})


def _common_ip(store: TenantStore, ip: str) -> bool:
    t = store.tenant
    return ip == CORP_EGRESS.get(t.id) or ip in t.vpn_ips


def _keys(store: TenantStore, a: Alert) -> set[tuple[str, str]]:
    keys = set()
    for e in a.entities:
        if e["type"] == "ip" and _common_ip(store, e["value"]):
            continue
        keys.add((e["type"], str(e["value"]).lower()))
    return keys


def signature(a: Alert) -> str:
    f = a.fields
    if a.source in ("encoded-powershell", "shadow-copy-delete", "lsass-dump", "office-spawns-script"):
        key = f"{f.get('DeviceName')}|{f.get('InitiatingProcessFileName')}"
    elif a.source in ("password-spray",):
        key = str(f.get("IPAddress"))
    elif a.source in ("mass-download", "exfil-personal-cloud"):
        key = str(f.get("AccountUpn"))
    elif a.source == "phish-click":
        key = str(f.get("SenderFromAddress"))
    elif a.product:
        ips = a.entity_values("ip")
        key = ips[0] if ips else (a.entity_values("account") + a.entity_values("host") + [""])[0]
    else:
        key = "|".join(sorted(str(e["value"]) for e in a.entities))
    return f"{a.source}|{key}"


def build_incidents(store: TenantStore, alerts: list[Alert]) -> list[Incident]:
    th = thresholds()
    dedupe = timedelta(minutes=th["dedupe_window_minutes"])
    window = timedelta(hours=th["correlation_window_hours"])
    groups: list[list[Alert]] = []
    for a in sorted(alerts, key=lambda x: (x.time, x.id)):
        placed = False
        for g in groups:
            lead = g[0]
            shared_events = set(a.event_ids) & {e for x in g for e in x.event_ids}
            same_rule = a.source == lead.source and _keys(store, a) == _keys(store, lead) and a.time - lead.time <= dedupe
            if shared_events or same_rule:
                g.append(a)
                placed = True
                break
        if not placed:
            groups.append([a])
    incidents: list[list[list[Alert]]] = []
    for g in groups:
        keys = set().union(*(_keys(store, a) for a in g))
        start = min(a.time for a in g)
        home = None
        for inc in incidents:
            inc_start = min(a.time for grp in inc for a in grp)
            inc_keys = set().union(*(_keys(store, a) for grp in inc for a in grp))
            if keys & inc_keys and abs(start - inc_start) < window:
                home = inc
                break
        if home is None:
            incidents.append([g])
        else:
            home.append(g)
    out = []
    for i, inc in enumerate(sorted(incidents, key=lambda x: min(a.time for g in x for a in g))):
        uniq = [g[0] for g in inc]
        dups = sum(len(g) - 1 for g in inc)
        merged = []
        for g in inc:
            lead = g[0]
            extra = [e for x in g[1:] for e in x.event_ids if e not in lead.event_ids]
            ents = list(lead.entities) + [e for x in g[1:] for e in x.entities if e not in lead.entities]
            techs = sorted(set(lead.techniques) | {t for x in g[1:] for t in x.techniques})
            merged.append(Alert(**{**lead.__dict__, "event_ids": lead.event_ids + extra, "entities": ents, "techniques": techs}))
        del uniq
        out.append(Incident(id=f"INC-{store.tenant.id[:2].upper()}-{i + 1:03d}", tenant=store.tenant.id, alerts=merged, duplicates=dups))
    return out


def _alert_context(store: TenantStore, a: Alert) -> tuple[str, str] | None:
    """Tenant context that explains one alert away, as (reason, verdict), or None."""
    t = store.tenant
    for ip in a.entity_values("ip"):
        if ip in t.authorized_scanners:
            return (f"{ip} is an authorised vulnerability scanner", "benign_positive")
        if ip in t.vpn_ips and a.name == "Atypical travel":
            return (f"{ip} is the tenant's VPN egress", "false_positive")
    if a.fields.get("SenderFromAddress") == t.phish_sim_sender:
        return ("sender is the tenant's phishing-simulation vendor", "benign_positive")
    return None


def _context(store: TenantStore, inc: Incident) -> list[tuple[str, str]]:
    """Context counts only when it explains every alert in the incident; one unexplained alert keeps it open."""
    found = [_alert_context(store, a) for a in inc.alerts]
    if all(found):
        return sorted(set(found))  # type: ignore[arg-type]
    return []


def enrich_and_score(store: TenantStore, inc: Incident, kb: KnowledgeBase, learned: Learned, guard: bool = True) -> Incident:
    day = day_of(inc.start) + inc.start.hour / 24
    inc.techniques = sorted({t for a in inc.alerts for t in attack.map_alert(a)})
    hits: list[intel.Hit] = []
    for kind in ("ip", "url", "account"):
        for v in inc.entities(kind):
            hits += intel.lookup("mailbox" if kind == "account" else kind, v, day)
    for a in inc.alerts:
        if a.fields.get("Destination"):
            hits += intel.lookup("domain", str(a.fields["Destination"]).split("@")[-1], day)
    inc.ti_hits = [h for h in hits if "consumer-cloud-storage" not in h.labels]
    start = inc.start.replace(hour=0, minute=0, second=0, microsecond=0)
    end = inc.end.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    inc.anomalies = [ueba.score_user(store, u, start, end) for u in inc.entities("account") if u in store.users()]
    for a in inc.alerts:
        for col in ("Subject", "ProcessCommandLine", "Description", "ObjectName"):
            s = guardrails.screen(a.fields.get(col))
            if s.flagged:
                inc.injection.append(f"{a.id}.{col}")
    ctx = _context(store, inc)
    inc.context = [c[0] for c in ctx]
    inc.signatures = sorted({signature(a) for a in inc.alerts})
    kb_counts: dict[str, int] = {v: 0 for v in VERDICTS}
    for sig in inc.signatures:
        for verdict, n in kb.prior(sig).items():
            kb_counts[verdict] += n
    kb_benign = kb_counts["benign_positive"] + kb_counts["false_positive"]
    prior = max(learned.prior(s) for s in inc.sources)
    f = {
        "prior": prior,
        "ti": max((h.confidence for h in inc.ti_hits), default=0) / 100,
        "ueba": max((x.score for x in inc.anomalies), default=0.0),
        "two_tactics": 1.0 if len(inc.tactics) >= 2 else 0.0,
        "three_tactics": 1.0 if len(inc.tactics) >= 3 else 0.0,
        "injection": 1.0 if (inc.injection and guard) else 0.0,
        "high_severity": 1.0 if any(a.severity == "High" for a in inc.alerts) else 0.0,
        "context_benign": 1.0 if ctx else 0.0,
        "kb_benign": 1.0 if kb_benign > kb_counts["true_positive"] else 0.0,
        "kb_malicious": 1.0 if kb_counts["true_positive"] > kb_benign else 0.0,
    }
    logit = math.log(prior / (1 - prior))
    expl = [f"prior {prior:.2f} ({', '.join(inc.sources)})"]
    for k, w in WEIGHTS.items():
        if f[k]:
            logit += w * f[k]
            expl.append(f"{k} {f[k]:.2f} x {w:+.1f}")
    inc.features = f
    inc.explanation = expl
    inc.p_malicious = round(1 / (1 + math.exp(-logit)), 4)
    if inc.p_malicious >= thresholds()["malicious_probability"]:
        inc.verdict = "true_positive"
    elif ctx:
        inc.verdict = ctx[0][1]
    elif f["kb_benign"]:
        inc.verdict = max(("benign_positive", "false_positive"), key=lambda v: kb_counts[v])
    else:
        inc.verdict = "false_positive"
    inc.confidence = round(max(inc.p_malicious, 1 - inc.p_malicious), 4)
    return inc


def rule_ids() -> list[str]:
    return [r["id"] for r in rules()]
