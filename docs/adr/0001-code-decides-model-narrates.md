# ADR 0001: Code decides, the model narrates

**Status:** Accepted

## Context

A SOC verdict drives closure and containment. Language models are persuadable by the very text they read,
and alert fields are attacker-controlled.

## Decision

Verdicts, evidence selection, routing and containment plans are computed by code with explainable terms.
The MAF agent only writes the summary, with structured output, and `validate_summary` rejects any summary
that changes the verdict, cites unknown evidence or recommends actions outside the plan. A template replaces
rejected summaries.

## Consequences

* Injection cannot change a verdict or a tier; the worst case is a template summary.
* Scoring weights are hand-set and must be reviewed; the model's reasoning ability is not used for decisions.
