# workflows

GitHub Actions workflows. Docs: [../../docs/infra/workflows.md](../../docs/infra/workflows.md).

| File | What it does |
|---|---|
| `ci.yml` | Lint, tests, release gate, drift checks, Bicep build, SBOM, gitleaks |
| `codeql.yml` | CodeQL for Python and Actions |
| `infra.yml` | Terraform fmt, validate, test, tflint, checkov, optional plan |
| `deploy.yml` | Gated dev then prod deployment with OIDC |
| `teardown.yml` | Gated teardown with typed confirmation |
