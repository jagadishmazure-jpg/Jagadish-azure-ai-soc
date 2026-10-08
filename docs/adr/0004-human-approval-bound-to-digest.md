# ADR 0004: Human approval bound to the plan digest, dry run by default

**Status:** Accepted

## Context

Disabling accounts or isolating hosts can stop a business. An approval for one plan must not authorise a
different one, and an agent must never approve its own work.

## Decision

Containment plans come from a fixed catalogue. Approvals name a tenant approver, the plan digest and a time;
they expire after 60 minutes; privileged accounts and crown jewels need two distinct approvers; break-glass
accounts can never be disabled. The executor holds one permission per action and records requests as a dry
run unless `AISOC_EXECUTE=live`, whose executor is deliberately not implemented. The IaC grants no
containment permission.

## Consequences

* Unreviewed or stale actions cannot run; every step is in the audit chain.
* Real containment requires a separate, reviewed implementation and identity.
