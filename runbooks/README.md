# runbooks

Knowledge base seed: one runbook per attack family, written for this SOC. The investigation agent attaches the matching runbook to every case (matched on rule id or technique), and the knowledge-capture step adds analyst case notes per tenant under `out/knowledge/`. See [docs/components/knowledge-capture.md](../docs/components/knowledge-capture.md).

| File | What it does |
|---|---|
| `atypical-travel.md` | Atypical travel: VPN artefact versus token replay |
| `insider-data-theft.md` | Bulk download plus personal-cloud upload, judged against baselines |
| `password-spray.md` | Password spray and a successful sign-in from the spraying address |
| `phishing-account-takeover.md` | Phishing click, takeover sign-in and a forwarding rule |
| `ransomware-precursor.md` | Office macro to PowerShell, C2, LSASS dump and shadow-copy deletion |
