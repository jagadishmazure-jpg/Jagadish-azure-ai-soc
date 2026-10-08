"""The analyst feedback loop: every human decision makes the next triage better, under guard rails.

What a review changes:
* a case note per alert signature in the tenant's knowledge base (aisoc.knowledge);
* the per-detector prior, by a Beta update with the shipped prior worth PRIOR_STRENGTH pseudo-reviews
  (single-detector incidents only, so a noisy rule is not credited with an attack it merely joined);
* at the end of the training window, per-detector auto-close thresholds, tuned only when a detector has
  at least `min_reviews_to_tune` reviews, never below `threshold_floor`, and only promoted if replaying
  the training window with them auto-closes zero real attacks.

Overrides (analyst verdict differs from the AI verdict) are counted for the override-rate metric and
are what drives the knowledge base; the AI never writes to it."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from aisoc.knowledge import CaseNote, KnowledgeBase
from aisoc.synth import TRAIN_DAYS, day_of
from aisoc.triage import Learned, rule_ids, thresholds
from aisoc.workflow import Case

PRIOR_STRENGTH = 4


@dataclass(frozen=True)
class Review:
    tenant: str
    incident_id: str
    window: str
    tier: int
    kind: str
    sources: tuple[str, ...]
    ai_verdict: str
    ai_confidence: float
    analyst_verdict: str
    analyst: str

    @property
    def override(self) -> bool:
        return self.ai_verdict != self.analyst_verdict

    @property
    def binary_override(self) -> bool:
        return (self.ai_verdict == "true_positive") != (self.analyst_verdict == "true_positive")


@dataclass
class FeedbackLoop:
    tenant: str
    kb: KnowledgeBase
    learned: Learned
    enabled: bool = True
    reviews: list[Review] = field(default_factory=list)
    counts: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))  # source -> [malicious, total]
    tuning_log: list[str] = field(default_factory=list)

    def capture(self, case: Case) -> None:
        d = case.decision
        if d is None:
            return
        inc = case.incident
        r = Review(inc.tenant, inc.id, "train" if day_of(inc.start) < TRAIN_DAYS else "holdout", case.route.tier if case.route else 0,
                   "qa" if case.qa_sampled else "review", tuple(inc.sources), inc.verdict, inc.confidence, d.verdict, d.analyst)
        self.reviews.append(r)
        if not self.enabled:
            return
        for sig in inc.signatures:
            self.kb.add(CaseNote(inc.tenant, sig, d.verdict, d.analyst, inc.id, d.note))
        if len(inc.sources) == 1:
            src = inc.sources[0]
            c = self.counts[src]
            c[0] += d.verdict == "true_positive"
            c[1] += 1
            base = Learned().prior(src)
            self.learned.priors[src] = round((base * PRIOR_STRENGTH + c[0]) / (PRIOR_STRENGTH + c[1]), 4)


def propose_thresholds(reviews: list[Review]) -> dict[str, float]:
    th = thresholds()
    by_src: dict[str, list[Review]] = defaultdict(list)
    for r in reviews:
        if len(r.sources) == 1:
            by_src[r.sources[0]].append(r)
    out = {}
    for src, rs in by_src.items():
        if len(rs) < th["min_reviews_to_tune"]:
            continue
        if any(r.analyst_verdict == "true_positive" and r.ai_verdict != "true_positive" for r in rs):
            out[src] = 0.99  # the AI called a real attack benign on this detector: effectively never auto-close
            continue
        benign_right = [r.ai_confidence for r in rs if r.ai_verdict != "true_positive" and r.analyst_verdict != "true_positive"]
        if len(benign_right) >= th["min_reviews_to_tune"]:
            out[src] = round(max(th["threshold_floor"], min(benign_right) - th["threshold_margin"]), 2)
    return out


def known_detectors() -> list[str]:
    return rule_ids()
