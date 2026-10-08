"""Tier 1 / 2 / 3 routing.

Tier 1: the AI closes it. Only a non-malicious verdict at or above the (learned) auto-close confidence,
        with no crown-jewel asset, no privileged account and no prompt-injection attempt. Every Nth
        closure is sampled for analyst quality review.
Tier 2: AI investigation, analyst decides. Everything that is neither tier 1 nor tier 3.
Tier 3: human-led, AI assists. A malicious verdict that touches a crown jewel or privileged account,
        spans three or more ATT&CK tactics, carries a prompt-injection attempt, or maps to no known
        technique (novel)."""

from __future__ import annotations

from dataclasses import dataclass

from aisoc.store import TenantStore
from aisoc.triage import Incident, Learned


@dataclass(frozen=True)
class Route:
    tier: int
    reasons: tuple[str, ...]


def route(store: TenantStore, inc: Incident, learned: Learned) -> Route:
    t = store.tenant
    users = store.users()
    crown = [h for h in inc.entities("host") if h in t.crown_jewels]
    privileged = [u for u in inc.entities("account") if users.get(u, {}).get("IsPrivileged")]
    threshold = min(learned.threshold(s) for s in inc.sources)
    if inc.verdict == "true_positive":
        why = []
        if crown:
            why.append(f"crown-jewel host {crown[0]}")
        if privileged:
            why.append("privileged account")
        if len(inc.tactics) >= 3:
            why.append(f"{len(inc.tactics)} ATT&CK tactics")
        if inc.injection:
            why.append("prompt-injection attempt in alert fields")
        if not inc.techniques:
            why.append("no mapped technique (novel)")
        if why:
            return Route(3, tuple(why))
        return Route(2, ("malicious verdict",))
    if inc.injection:
        return Route(2, ("prompt-injection attempt in alert fields",))
    if crown or privileged:
        return Route(2, ("crown-jewel host" if crown else "privileged account",))
    if inc.confidence >= threshold:
        return Route(1, (f"{inc.verdict} at confidence {inc.confidence:.2f} >= {threshold:.2f}",))
    return Route(2, (f"confidence {inc.confidence:.2f} below auto-close {threshold:.2f}",))
