"""Analytics rules: every rule fires, alert timing is realistic, and the IaC copy of the rules is current."""

import json

import pytest

from aisoc import DETECTIONS, labels
from aisoc.detections import all_alerts, ingestion_delay, iso_duration, rule, rules, rules_json
from aisoc.store import load
from aisoc.tenants import tenants

ALERTS = {t: all_alerts(load(t)) for t in sorted(tenants())}
RULE_IDS = [r["id"] for r in rules()]


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_fires_somewhere(rule_id):
    assert any(a.source == rule_id for alerts in ALERTS.values() for a in alerts)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_metadata_is_complete(rule_id):
    r = rule(rule_id)
    assert (DETECTIONS / r["file"]).exists()
    assert r["severity"] in ("Low", "Medium", "High") and r["techniques"] and r["tactics"]
    assert 0 < r["prior"] < 1 and iso_duration(r["frequency"]).total_seconds() > 0 and r["entities"]


def test_alert_never_precedes_its_events_plus_ingestion_delay():
    for t, alerts in ALERTS.items():
        s = load(t)
        for a in alerts:
            if a.product:
                continue
            first = min(s.event_time(e) for e in a.event_ids)
            assert a.time >= first + ingestion_delay(), a.id


def test_every_story_raises_at_least_one_alert():
    for t, alerts in ALERTS.items():
        hit = {labels.story_for_events(t, a.event_ids) for a in alerts}
        for s in labels.stories(t):
            assert s["id"] in hit, s["id"]


def test_alert_entities_are_typed():
    for alerts in ALERTS.values():
        for a in alerts:
            assert a.entities and all(e["type"] in ("account", "host", "ip", "url") for e in a.entities), a.id


def test_rules_json_is_current_and_carries_queries():
    on_disk = json.loads((DETECTIONS / "rules.json").read_text())
    assert on_disk == rules_json()
    assert all(r["query"].strip() and r["parent_techniques"] for r in on_disk["rules"])
    assert all("." not in t for r in on_disk["rules"] for t in r["parent_techniques"])
