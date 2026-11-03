# docs

Documentation for three audiences: Jagadish (design and interview prep), recruiters and reviewers (what it
shows and how honest it is) and adopters (how to reuse it). Component and infra docs follow a 16-section
template; their outputs and code excerpts are rendered from the code and drift-checked in CI.

## Reading order

1. [../README.md](../README.md): what this is, in one page.
2. [USE_CASES.md](USE_CASES.md): the jobs it does, with commands.
3. [architecture.md](architecture.md): how the parts fit and where the trust boundaries are.
4. [components/README.md](components/README.md): one doc per part, in pipeline order: synthetic data, KQL,
   detections, packs (identity, endpoint), triage, exposure, consensus, investigation, response and authority.
5. [threat-model.md](threat-model.md): what can go wrong and what stops it.
6. [metrics.md](metrics.md): the measured results and their caveats.
7. [mssp-operating-model.md](mssp-operating-model.md): tenants, service tiers and monthly reports.
8. [implementation-guide.md](implementation-guide.md) and [deployment.md](deployment.md): how to adopt it.
9. [PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md) and [interview-guide.md](interview-guide.md): how to present it.

| File | What it does |
|---|---|
| `architecture.md` | System view, trust boundaries, component status, MAF usage, release gate |
| `threat-model.md` | STRIDE, OWASP Top 10 for LLM Applications, MITRE ATLAS, residual risks |
| `scenario-mapping.md` | The eight AI SOC scenarios mapped to code |
| `cognitive-soc-five-parts.md` | The five parts of a cognitive SOC explained, mapped to code with real output, verdict per part |
| `metrics.md` | Rendered comparison, per-story results and full run report, with caveats |
| `mssp-operating-model.md` | Multi-tenant model, Lighthouse mapping, isolation evidence, onboarding |
| `deployment.md` | One-time setup for the gated deployment (never run) |
| `implementation-guide.md` | Adopt this: what to keep, what to replace, phased rollout |
| `best-practices.md` | Practices applied and the built vs written vs planned list |
| `interview-guide.md` | Walkthrough, likely questions, numbers, caveats |
| `USE_CASES.md` | Fifteen jobs to be done, each with a command, a doc and a measured result |
| `PRESENTATION_GUIDE.md` | Ten-minute live walkthrough with commands and what to say |
| `case-studies/` | Real-world incidents replayed through the agents on synthetic data |
| `components/` | Twenty-two component docs |
| `infra/` | Workspace, playbook, Terraform, Bicep and workflow docs |
| `adr/` | Architecture decision records |
