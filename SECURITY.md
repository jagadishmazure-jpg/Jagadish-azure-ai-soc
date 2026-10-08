# Security policy

## Scope

This repository contains offline code, synthetic security telemetry and infrastructure templates for a
fictional MSSP and its fictional customers. It holds no credentials, subscription or tenant identifiers,
model keys, real indicators of compromise or real customer data, and its tests enforce that. The only GUIDs
outside `00000000-` mocks are two public Azure built-in role definition IDs, allow-listed by a test.

## Reporting a vulnerability

1. Open a private security advisory on GitHub (Security tab, "Report a vulnerability"). Include the file,
   the problem and how to reproduce it.
2. If that button is not shown (private reporting is not switched on for this repo yet), open an issue
   titled `Security contact request` with no technical details, and I will reply with a private channel.

I aim to acknowledge a report within 5 working days. This is a personal portfolio maintained by one person,
so there is no formal SLA or bug bounty.

## Design choices that matter for security

- **No secrets anywhere.** GitHub Actions log in to Azure with OIDC federated credentials; the workspace has
  local (shared key) auth disabled; the playbook uses managed identity for its connector and its call out.
- **Agents are read-only.** All data access goes through a gateway with identity entitlements, template-only
  KQL, regex-checked parameters, a row cap and an audit record per call. The MCP server has no write tool.
- **Containment needs people.** Plans come from a fixed catalogue; approvals are bound to the plan digest,
  expire, need two approvers for privileged accounts and crown jewels, and can never come from an agent.
  Execution is a dry run; the live executor is not implemented; the IaC grants no containment permission.
- **Untrusted text is handled as data.** Alert and evidence text is screened, redacted, pseudonymised and
  quoted before reaching the model; the model's output is validated against code-computed facts.
- **Tenants are isolated** and tested with a canary and eight crossing attempts in the release gate.
- **Supply chain:** SHA-pinned actions, Dependabot, CodeQL, gitleaks over full history, an SPDX SBOM,
  pinned Python dependencies, checkov (no skips) and tflint on Terraform.
- **Deployment gated off** until `DEPLOY_ENABLED` is set; prod needs environment reviewers.

See [docs/threat-model.md](docs/threat-model.md).

## Supported versions

Only the `main` branch is maintained.
