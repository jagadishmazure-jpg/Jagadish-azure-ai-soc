"""User and entity behaviour analytics: per-user baselines over the 14 days before a point in time,
compared with the activity under review. Peer groups (department) back up users with thin history.

Signals: download volume z-score against the user's own history, new sign-in country, external
uploads, and a drift slope (the last four days trending above the baseline)."""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from aisoc.store import TenantStore

HISTORY_DAYS = 14


@dataclass(frozen=True)
class UserBaseline:
    user: str
    department: str
    mean_downloads: float
    std_downloads: float
    peer_mean_downloads: float
    countries: frozenset[str]
    external_uploads: int


@dataclass(frozen=True)
class Anomaly:
    user: str
    score: float  # 0..1
    download_z: float
    downloads: int
    new_country: str | None
    external_uploads: int
    drift: float
    reasons: tuple[str, ...]


def _day_counts(store: TenantStore, start: datetime, end: datetime) -> dict[str, list[int]]:
    days = (end - start).days
    counts: dict[str, list[int]] = defaultdict(lambda: [0] * days)
    for r in store.tables["CloudAppEvents"]:
        if r["ActionType"] == "FileDownloaded" and start <= r["TimeGenerated"] < end:
            counts[r["AccountUpn"]][(r["TimeGenerated"] - start).days] += 1
    return counts


_CACHE: dict[tuple[int, datetime], dict[str, UserBaseline]] = {}


def _baselines(store: TenantStore, as_of: datetime) -> dict[str, UserBaseline]:
    key = (id(store), as_of)
    if key in _CACHE:
        return _CACHE[key]
    start = as_of - timedelta(days=HISTORY_DAYS)
    counts = _day_counts(store, start, as_of)
    users = store.users()
    by_dept: dict[str, list[float]] = defaultdict(list)
    for u, info in users.items():
        by_dept[info["Department"]].append(statistics.fmean(counts.get(u, [0])))
    countries: dict[str, set[str]] = defaultdict(set)
    uploads: dict[str, int] = defaultdict(int)
    for r in store.tables["SigninLogs"]:
        if start <= r["TimeGenerated"] < as_of and r["ResultType"] == "0":
            countries[r["UserPrincipalName"]].add(r["Location"])
    for r in store.tables["CloudAppEvents"]:
        if start <= r["TimeGenerated"] < as_of and r["ActionType"] == "FileUploaded" and r["IsExternal"]:
            uploads[r["AccountUpn"]] += 1
    out = {}
    for u, info in users.items():
        c = counts.get(u, [0] * HISTORY_DAYS)
        out[u] = UserBaseline(
            user=u,
            department=info["Department"],
            mean_downloads=statistics.fmean(c),
            std_downloads=statistics.pstdev(c),
            peer_mean_downloads=statistics.fmean(by_dept[info["Department"]]),
            countries=frozenset(countries.get(u, set())),
            external_uploads=uploads.get(u, 0),
        )
    _CACHE[key] = out
    return out


def baselines(store: TenantStore, as_of: datetime) -> dict[str, UserBaseline]:
    day = as_of.replace(hour=0, minute=0, second=0, microsecond=0)
    return _baselines(store, day)


def score_user(store: TenantStore, user: str, start: datetime, end: datetime) -> Anomaly:
    """Anomaly of `user` in [start, end) against the baseline ending at the start of that day."""
    base = baselines(store, start).get(user)
    downloads = sum(1 for r in store.tables["CloudAppEvents"] if r.get("AccountUpn") == user and r["ActionType"] == "FileDownloaded" and start <= r["TimeGenerated"] < end)
    uploads = sum(
        1 for r in store.tables["CloudAppEvents"] if r.get("AccountUpn") == user and r["ActionType"] == "FileUploaded" and r["IsExternal"] and start <= r["TimeGenerated"] < end
    )
    countries = {r["Location"] for r in store.tables["SigninLogs"] if r["UserPrincipalName"] == user and r["ResultType"] == "0" and start <= r["TimeGenerated"] < end}
    reasons = []
    if base is None:
        return Anomaly(user, 0.0, 0.0, downloads, None, uploads, 0.0, ("no baseline",))
    days = max((end - start).total_seconds() / 86400, 1 / 24)
    expected = max(base.mean_downloads, 0.5) * days
    spread = max(base.std_downloads * days, 0.25 * max(base.peer_mean_downloads, 1) * days, 2.0)
    z = (downloads - expected) / spread
    new_country = next((c for c in sorted(countries) if base.countries and c not in base.countries), None)
    midnight = start.replace(hour=0, minute=0, second=0, microsecond=0)
    recent = _day_counts(store, midnight - timedelta(days=4), midnight)
    last4 = recent.get(user, [0])
    drift = (statistics.fmean(last4) - base.mean_downloads) / max(base.std_downloads, 1.0) if last4 else 0.0
    score = 0.0
    if z > 3:
        score += min(0.5, 0.1 * z)
        reasons.append(f"downloads {downloads} vs expected {expected:.1f} (z={z:.1f})")
    if new_country:
        score += 0.3
        reasons.append(f"first sign-in from {new_country} in {HISTORY_DAYS} days")
    if uploads and base.external_uploads == 0:
        score += 0.25
        reasons.append(f"{uploads} external uploads with none in the baseline")
    if drift > 1.5:
        score += 0.1
        reasons.append(f"download trend rising before the alert (drift={drift:.1f})")
    return Anomaly(user, round(min(score, 1.0), 3), round(z, 2), downloads, new_country, uploads, round(drift, 2), tuple(reasons))
