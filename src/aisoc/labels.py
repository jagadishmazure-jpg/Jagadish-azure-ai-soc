"""Ground truth for the synthetic data. Only metrics, the simulated analyst and the evaluation gate
import this module; a test fails if triage, investigation, response or tool code ever does."""

from __future__ import annotations

from functools import cache

from aisoc import synth

MALICIOUS = "true_positive"


@cache
def truth(tenant_id: str, seed: int = synth.SEED) -> synth.Dataset:
    return synth.generate(tenant_id, seed)


def event_label(tenant_id: str, event_id: str) -> str:
    return truth(tenant_id).labels.get(event_id, "noise")


def verdict_for_events(tenant_id: str, event_ids: list[str]) -> str:
    """Expert verdict for a set of events: any story event -> true positive; else the benign kind decides."""
    labels = [event_label(tenant_id, e) for e in event_ids]
    if any(lab.startswith(f"{tenant_id}-") for lab in labels):
        return MALICIOUS
    kinds = {synth.BENIGN_KINDS[lab] for lab in labels if lab in synth.BENIGN_KINDS}
    if "benign_positive" in kinds:
        return "benign_positive"
    return "false_positive"


def story_for_events(tenant_id: str, event_ids: list[str]) -> str | None:
    for e in event_ids:
        lab = event_label(tenant_id, e)
        if lab.startswith(f"{tenant_id}-"):
            return lab
    return None


def stories(tenant_id: str) -> list[dict]:
    return truth(tenant_id).stories
