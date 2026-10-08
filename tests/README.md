# tests

Offline tests: synthetic data, mock model, no Azure.

| File | What it does |
|---|---|
| `conftest.py` | Session fixtures for the learning and baseline runs |
| `test_synth.py` | Determinism, fictional identities, stories, ground-truth separation |
| `test_kql.py` | KQL operators, functions, joins and errors |
| `test_detections.py` | Rule firing, alert timing, entities, rules.json |
| `test_attack_intel_ueba.py` | ATT&CK mapping and coverage, TI decay, UEBA signals |
| `test_triage_routing.py` | Grouping, context, scoring, routing rules |
| `test_tools.py` | Gateway entitlements, templates, row cap, audit, as-of time |
| `test_investigation.py` | Scope, evidence order, runbooks, no ground-truth imports |
| `test_llm_guardrails.py` | Screen, redaction, pseudonyms, MAF structured output, validator, injection what-if |
| `test_response_audit.py` | Plans, approvals, policy, dry run, permissions, audit chain |
| `test_workflow_feedback.py` | Workflow pauses, QA sampling, feedback loop and promotion gate |
| `test_metrics_risk_isolation.py` | Metrics, risk evaluation, canary and crossings |
| `test_mcp_cli.py` | MCP server and CLI commands, gate, tamper detection |
| `test_iac.py` | Terraform, Bicep and workflow structure, offline |
| `test_render_docs.py` | Doc renderer behaviour |
| `test_repo_hygiene.py` | Doc completeness, no dates, no real identifiers, no copied PDF |
