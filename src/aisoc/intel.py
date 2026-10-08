"""Threat-intelligence enrichment from the MSSP's local IOC feed (data/ti/ioc-feed.json).

The feed is shared across tenants (it is MSSP knowledge); sightings are not: a match is recorded only in
the tenant whose telemetry produced it. An indicator is active from `first_seen_day` for `valid_days`,
and its confidence decays linearly to half by the end of that window, so stale intel counts for less."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from functools import cache
from urllib.parse import urlsplit

from aisoc import DATA
from aisoc.synth import T0

TYPE_TO_ENTITY = {"ipv4-addr": "ip", "domain-name": "domain", "file-sha256": "filehash"}


@dataclass(frozen=True)
class Hit:
    indicator_id: str
    entity_type: str
    value: str
    confidence: float  # 0-100 after decay
    labels: tuple[str, ...]
    actor: str
    techniques: tuple[str, ...]


@cache
def feed() -> dict:
    return json.loads((DATA / "ti" / "ioc-feed.json").read_text())


def indicators() -> list[dict]:
    return feed()["indicators"]


def effective_confidence(ind: dict, day: float) -> float:
    age = day - ind["first_seen_day"]
    if age < 0 or age > ind["valid_days"]:
        return 0.0
    return round(ind["confidence"] * (1 - 0.5 * age / ind["valid_days"]), 1)


def table(now_day: float) -> list[dict]:
    """The feed as Sentinel's ThreatIntelligenceIndicator table (the subset of columns the rules use)."""
    rows = []
    for ind in indicators():
        exp = T0 + timedelta(days=ind["first_seen_day"] + ind["valid_days"])
        rows.append(
            {
                "TimeGenerated": T0 + timedelta(days=ind["first_seen_day"]),
                "IndicatorId": ind["id"],
                "NetworkIP": ind["value"] if ind["type"] == "ipv4-addr" else "",
                "DomainName": ind["value"] if ind["type"] == "domain-name" else "",
                "FileHashValue": ind["value"] if ind["type"] == "file-sha256" else "",
                "ConfidenceScore": ind["confidence"],
                "Active": True,
                "ExpirationDateTime": exp,
                "ThreatType": ",".join(ind["labels"]),
                "Description": ind["actor"],
            }
        )
    return rows


def domain_of(value: str) -> str:
    if "://" in value:
        return urlsplit(value).hostname or ""
    return value.split("@")[-1] if "@" in value else value


def lookup(entity_type: str, value: str, day: float) -> list[Hit]:
    """Active indicators matching one entity. URLs and mailboxes match on their domain."""
    if not value:
        return []
    want = {"ip": ("ipv4-addr", value), "url": ("domain-name", domain_of(value)), "domain": ("domain-name", domain_of(value)),
            "mailbox": ("domain-name", domain_of(value)), "filehash": ("file-sha256", value.lower())}.get(entity_type)  # fmt: skip
    if not want:
        return []
    hits = []
    for ind in indicators():
        if ind["type"] == want[0] and ind["value"].lower() == want[1].lower():
            conf = effective_confidence(ind, day)
            if conf > 0:
                hits.append(Hit(ind["id"], entity_type, value, conf, tuple(ind["labels"]), ind["actor"], tuple(ind["techniques"])))
    return hits
