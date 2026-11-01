# detections/itdr

Identity threat detection pack for Microsoft 365 and Entra ID. The rules run locally over synthetic
sign-in, consent and mailbox telemetry from `aisoc.itdr` through the repository's KQL interpreter. See
[the component doc](../../docs/components/itdr-pack.md) for measured precision and the known false positive.

| File | What it does |
|---|---|
| `rules.yaml` | Rule metadata: id, file, severity, attack stage, ATT&CK technique, entity column |
| `token-replay.kql` | One sign-in session used from two networks, one of them hosting or anonymising |
| `oauth-consent-risky.kql` | A user grants an unverified app a mail or file scope |
| `device-code-signin.kql` | Device-code sign-in by an account outside the shared-device group |
| `legacy-auth-signin.kql` | Successful sign-in over a protocol that cannot do MFA (listed devices excluded) |
| `hosting-or-vpn-signin.kql` | Sign-in from a hosting or commercial VPN network (enrichment flag, low severity) |
| `inbox-rule-hides-security-mail.kql` | Inbox rule that hides mail about security, MFA, passwords or payments |
