# ADR 0006: Terraform and Bicep from one rules file, deployment gated off

**Status:** Accepted

## Context

Teams differ in IaC preference, and the deployed rules must be the tested rules. This repository has not
been deployed and must not pretend otherwise.

## Decision

Both stacks read `detections/rules.json`, generated from the `.kql` files and drift-checked. Rules are
opt-in and created disabled because the schema is simplified. The deploy workflow uses OIDC, dev then prod
with reviewers, and runs only when `DEPLOY_ENABLED` is true; it is not set.

## Consequences

* Two stacks to maintain, kept in parity by tests.
* The IaC is validated with mocks, linters and checkov, not by a real deployment.
