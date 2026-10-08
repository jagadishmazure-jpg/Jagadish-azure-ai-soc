# docs

Documentation for three audiences: Jagadish (design and interview prep), recruiters and reviewers (what it
shows and how honest it is) and adopters (how to reuse it). Component and infra docs follow a 16-section
template; their outputs and code excerpts are rendered from the code and drift-checked in CI.

| File | What it does |
|---|---|
| `architecture.md` | System view, trust boundaries, component status, MAF usage, release gate |
| `threat-model.md` | STRIDE, OWASP Top 10 for LLM Applications, MITRE ATLAS, residual risks |
| `scenario-mapping.md` | The eight AI SOC scenarios mapped to code, in this repository's own words |
| `metrics.md` | Rendered comparison, per-story results and full run report, with caveats |
| `mssp-operating-model.md` | Multi-tenant model, Lighthouse mapping, isolation evidence, onboarding |
| `deployment.md` | One-time setup for the gated deployment (never run) |
| `implementation-guide.md` | Adopt this: what to keep, what to replace, phased rollout |
| `best-practices.md` | Practices applied and the built vs written vs planned list |
| `interview-guide.md` | Walkthrough, likely questions, numbers, caveats |
| `components/` | Fourteen component docs |
| `infra/` | Workspace, playbook, Terraform, Bicep and workflow docs |
| `adr/` | Architecture decision records |
