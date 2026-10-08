# adr

Architecture decision records. Each has a status and the context, decision and consequences.

| File | What it does |
|---|---|
| `0001-code-decides-model-narrates.md` | Verdicts and plans come from code; the model only writes a validated summary |
| `0002-sentinel-mcp-shaped-gateway.md` | Read-only, template-only tool gateway shaped like the Sentinel MCP server |
| `0003-synthetic-data-and-mock-model.md` | Synthetic tenants, isolated ground truth, deterministic MAF mock client |
| `0004-human-approval-bound-to-digest.md` | Approvals bound to plan digest, TTL, dual control, dry run |
| `0005-earned-autonomy-with-replay-gate.md` | Per-detector, per-tenant thresholds behind a replay gate |
| `0006-dual-iac-gated-deploy.md` | Terraform and Bicep from one rules file; deployment gated off |
