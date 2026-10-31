# rules

Curated Sigma rules, one per file. Each rule's `logsource` must be in [../ocsf-mapping.yaml](../ocsf-mapping.yaml) and every field it uses must be mapped there, or loading fails. File names start with the area: `ep` endpoint, `id` identity, `cl` cloud, `nw` / `dns` network, `ai` AI agent. Rule ids are UUIDs, as the Sigma spec asks; they are the only GUID-like strings the hygiene test allows, and only in this folder.

| File | What it does |
|---|---|
| `ai-bulk-data-export.yml` | Agent query tool returns a very large result (medium; T1213, AML.T0086) |
| `ai-credential-file-read.yml` | Agent file tool reads a credential file (high; T1552.001, AML.T0053, AML.T0055) |
| `ai-injection-in-tool-output.yml` | Tool result carries a prompt-injection phrase (medium; AML.T0051.001) |
| `ai-tool-download-exec.yml` | Agent shell tool downloads and runs a script (high; T1059.004, T1105, AML.T0053, AML.T0050) |
| `cl-diagnostic-setting-deleted.yml` | Diagnostic setting deleted (high; T1562.008) |
| `cl-nsg-mgmt-port-open.yml` | Network security rule opens RDP or SSH to the internet (high; T1562.007) |
| `cl-storage-public-access.yml` | Storage account opened to anonymous blob access (medium; T1530) |
| `dns-long-label.yml` | DNS query with a very long random-looking label (medium; T1071.004, T1048) |
| `ep-encoded-powershell.yml` | PowerShell started with an encoded command (medium; T1059.001, T1027) |
| `ep-lsass-minidump.yml` | LSASS memory dumped with a built-in or admin tool (high; T1003.001) |
| `ep-office-spawns-script.yml` | Office application starts a script interpreter (high; T1204.002, T1059) |
| `ep-shadow-copy-delete.yml` | Volume shadow copies deleted (high; T1490) |
| `id-legacy-auth-success.yml` | Successful sign-in over a legacy authentication protocol (medium; T1078.004) |
| `id-mfa-disabled.yml` | MFA removed from a user (high; T1556.006) |
| `id-privileged-role-added.yml` | User added to a highly privileged directory role (high; T1098.003) |
| `id-single-factor-admin-app.yml` | Single-factor sign-in to an admin portal (high; T1078.004, T1556.006) |
| `id-sp-credential-added.yml` | New credential added to a service principal (medium; T1098.001) |
| `nw-smb-to-internet.yml` | Outbound SMB to a public address (medium; T1048) |
| `nw-tor-ports.yml` | Connection to a Tor relay or proxy port (medium; T1090.003) |
