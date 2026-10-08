# terraform

Terraform stack (azurerm and azapi). Docs: [../../docs/infra/terraform.md](../../docs/infra/terraform.md).

| File | What it does |
|---|---|
| `versions.tf` | Terraform and provider versions |
| `providers.tf` | Provider configuration |
| `backend.tf` | Remote state (Entra ID auth) |
| `variables.tf` | Inputs with descriptions and validations |
| `locals.tf` | Naming, tags, rules from rules.json, entity map |
| `main.tf` | Workspace, Sentinel, rules, identities, playbook, diagnostics |
| `network.tf` | Optional private networking |
| `outputs.tf` | Outputs for the smoke test |
| `envs/` | dev and prod variables and backend config |
| `tests/` | Mocked plan tests |
| `.tflint.hcl` | tflint configuration (azurerm ruleset) |
