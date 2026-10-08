# envs

Per-environment inputs.

| File | What it does |
|---|---|
| `dev.tfvars` | dev: no rules, public endpoints, 1 GB cap |
| `prod.tfvars` | prod: rules created disabled, automation rule, private networking, 5 GB cap |
| `dev.backend.hcl` | dev state key |
| `prod.backend.hcl` | prod state key |
