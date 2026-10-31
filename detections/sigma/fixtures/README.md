# fixtures

Synthetic OCSF events per rule: `match` events the rule must fire on and `no_match` near-misses it must ignore. Each event may only use OCSF paths declared for its class in [../ocsf-mapping.yaml](../ocsf-mapping.yaml); an undeclared path (a typo) fails loading. Every rule also runs over every other rule's fixtures, in three engines, and the hits must agree.

| File | What it does |
|---|---|
| `ai-bulk-data-export.yaml` | 2 match, 3 no-match events for `ai-bulk-data-export.yml` |
| `ai-credential-file-read.yaml` | 2 match, 2 no-match events for `ai-credential-file-read.yml` |
| `ai-injection-in-tool-output.yaml` | 2 match, 2 no-match events for `ai-injection-in-tool-output.yml` |
| `ai-tool-download-exec.yaml` | 2 match, 2 no-match events for `ai-tool-download-exec.yml` |
| `cl-diagnostic-setting-deleted.yaml` | 2 match, 2 no-match events for `cl-diagnostic-setting-deleted.yml` |
| `cl-nsg-mgmt-port-open.yaml` | 2 match, 3 no-match events for `cl-nsg-mgmt-port-open.yml` |
| `cl-storage-public-access.yaml` | 1 match, 2 no-match events for `cl-storage-public-access.yml` |
| `dns-long-label.yaml` | 1 match, 3 no-match events for `dns-long-label.yml` |
| `ep-encoded-powershell.yaml` | 2 match, 3 no-match events for `ep-encoded-powershell.yml` |
| `ep-lsass-minidump.yaml` | 2 match, 2 no-match events for `ep-lsass-minidump.yml` |
| `ep-office-spawns-script.yaml` | 2 match, 2 no-match events for `ep-office-spawns-script.yml` |
| `ep-shadow-copy-delete.yaml` | 2 match, 2 no-match events for `ep-shadow-copy-delete.yml` |
| `id-legacy-auth-success.yaml` | 2 match, 3 no-match events for `id-legacy-auth-success.yml` |
| `id-mfa-disabled.yaml` | 2 match, 2 no-match events for `id-mfa-disabled.yml` |
| `id-privileged-role-added.yaml` | 1 match, 2 no-match events for `id-privileged-role-added.yml` |
| `id-single-factor-admin-app.yaml` | 1 match, 3 no-match events for `id-single-factor-admin-app.yml` |
| `id-sp-credential-added.yaml` | 1 match, 2 no-match events for `id-sp-credential-added.yml` |
| `nw-smb-to-internet.yaml` | 1 match, 3 no-match events for `nw-smb-to-internet.yml` |
| `nw-tor-ports.yaml` | 2 match, 2 no-match events for `nw-tor-ports.yml` |
