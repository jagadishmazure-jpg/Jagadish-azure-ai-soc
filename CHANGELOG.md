# Changelog

All notable changes to this project are documented here.

## Unreleased

- Repository settings: Dependabot alerts and security updates, private vulnerability reporting and a
  `main` ruleset; Dependabot updates are grouped per ecosystem.
- Synthetic Sentinel and Defender XDR telemetry for a fictional MSSP and three tenants, with look-alikes and
  nine attack stories; ground truth isolated from agent code.
- Pure-Python KQL subset; twelve analytics rules as code with realistic alert timing; ATT&CK coverage and a
  Navigator layer.
- Triage (dedupe, correlation, TI, UEBA, explainable scoring) and tier 1 / 2 / 3 routing.
- Sentinel-MCP-shaped read-only tool gateway and local MCP server; investigation agent with cited timeline,
  scope and blast radius.
- Microsoft Agent Framework workflow per incident with QA and approval checkpoints; narrative agent with
  structured output, prompt guardrails and output validation; Foundry adapter path.
- Containment planning with digest-bound approvals, dual control, dry-run executor and per-tenant
  hash-chained audit.
- Feedback loop with analyst-only case notes, Beta-updated priors and replay-gated thresholds.
- Predictive risk watch list; tenant isolation canary and crossing checks; metrics and an eleven-check
  release gate.
- Terraform and Bicep for the workspace, rules, least-privilege identities, managed-identity playbook and
  private networking; CI, CodeQL, infra, gated deploy and teardown workflows.
- Documentation for engineers, reviewers and adopters with rendered outputs and code excerpts.
