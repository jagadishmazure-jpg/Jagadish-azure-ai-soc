# aisoc

The `aisoc` package. Product modules never import `labels`, `analyst` or `metrics` (AST test).

| File | What it does |
|---|---|
| `__init__.py` | Package paths (config, detections, data, runbooks, out) |
| `synth.py` | Deterministic synthetic telemetry, stories and look-alikes |
| `tenants.py` | Fictional MSSP and tenant model |
| `store.py` | Per-tenant data store (the only path to telemetry) |
| `labels.py` | Ground truth (evaluation only) |
| `kql.py` | KQL subset interpreter |
| `detections.py` | Scheduled-rule simulation, product alerts, rules.json export |
| `attack.py` | ATT&CK catalogue, mapping, coverage, Navigator layer |
| `intel.py` | Threat-intel feed, decay and lookup |
| `ueba.py` | Behaviour baselines and anomaly scoring |
| `triage.py` | Dedupe, correlation, enrichment, scoring, verdict |
| `routing.py` | Tier 1 / 2 / 3 routing |
| `tools.py` | Sentinel-shaped tool gateway |
| `mcp_server.py` | MCP server over the gateway |
| `investigation.py` | Investigation agent logic |
| `knowledge.py` | Runbooks, case notes, per-tenant knowledge base |
| `guardrails.py` | Injection screen, redaction, pseudonyms, Prompt Shields adapter path |
| `llm.py` | MAF narrative agent, mock and Foundry clients, validator |
| `response.py` | Containment planning, approvals, executor |
| `audit.py` | Hash-chained audit log per tenant |
| `workflow.py` | MAF workflow with human checkpoints |
| `analyst.py` | Simulated analysts and approvers (evaluation only) |
| `feedback.py` | Feedback loop: notes, priors, thresholds |
| `pipeline.py` | End-to-end runs, replay gate, holdout freeze |
| `metrics.py` | Metric computation against ground truth; per-incident technique mix (`aisoc mix`) |
| `risk.py` | Predictive risk ranking and evaluation |
| `isolation.py` | Canary and cross-tenant checks |
| `iac.py` | Read-only summaries of the IaC and workflows |
| `cli.py` | The `aisoc` command line and release gate |
