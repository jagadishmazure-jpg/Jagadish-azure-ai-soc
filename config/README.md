# config

Configuration read by the code. Nothing here is written by code.

| File | What it does |
|---|---|
| `tenants.yaml` | MSSP, tenants, domains, crown jewels, approvers, break-glass accounts |
| `identities.yaml` | Agent and human identities, tenant and tool entitlements |
| `kql-templates.yaml` | Allow-listed investigation templates and parameter patterns |
| `actions.yaml` | Containment action catalogue with requests, permissions and reversal |
| `thresholds.yaml` | Triage, routing, QA, windows and simulated analyst minutes |
| `attack-techniques.yaml` | Priority ATT&CK techniques for coverage |
| `authority.yaml` | Authority registry: stage, owner, approvals, evidence, blast radius, effect, verification and undo per action |
| `exposure.yaml` | Asset criticality by role with attributed overrides, synthetic open findings (known-exploited flag) and reachability |
| `smart-filter.yaml` | Candidate ingest filters, planted canaries and assumed per-GB prices for the cost simulation |
| `service-tiers.yaml` | Three fictional service tiers with SLA targets in minutes and the tenant-to-tier map |
