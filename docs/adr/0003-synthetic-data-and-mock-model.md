# ADR 0003: Synthetic tenants, labels kept apart, and a deterministic mock model

**Status:** Accepted

## Context

The repository must run offline in CI, use no real customer data and report numbers that are reproducible.

## Decision

Generate three fictional tenants deterministically, keep ground truth in a separate structure that only
evaluation code may import (enforced by an AST test), and run the MAF agent on `MockSocChatClient`, a real
MAF chat client with deterministic output and a deliberate gullible switch for injection tests. The Foundry
client is selected by `AISOC_LLM=foundry`.

## Consequences

* Every number is reproducible and drift-checked.
* Results are easier than real life: look-alikes repeat, analysts are simulated, and the model is not a real
  model. Docs say so wherever numbers appear.
