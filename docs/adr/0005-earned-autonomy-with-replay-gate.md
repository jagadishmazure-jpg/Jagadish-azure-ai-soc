# ADR 0005: Autonomy earned per detector and tenant, behind a replay gate

**Status:** Accepted

## Context

A global auto-close threshold either closes too little or risks closing attacks. Feedback loops can poison
themselves if the AI's own verdicts become training signal.

## Decision

Only analyst decisions become case notes. Detector priors update by a Beta rule on single-source incidents.
Thresholds move only after four reviews, never below 0.70, lock at 0.99 after a missed attack, and are
promoted only if replaying the training window closes zero real attacks. Learning is frozen for the holdout.

## Consequences

* Tier 1 grows where evidence supports it, per customer.
* Tuning happens once per window here; production would schedule it with the same gate.
