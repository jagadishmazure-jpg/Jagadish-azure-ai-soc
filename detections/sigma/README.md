# sigma

Sigma detection-as-code. Rules are written once in Sigma, mapped field by field to OCSF, tested on
positive and negative OCSF fixtures, and converted to SQL (SQLite dialect) and KQL. The evaluator, the SQL
and the KQL must return the same events, or the release gate fails. See
[../../docs/components/sigma-detections.md](../../docs/components/sigma-detections.md) and
[ADR 0007](../../docs/adr/0007-sigma-source-ocsf-contract.md).

| File | What it does |
|---|---|
| `ocsf-mapping.yaml` | The Sigma -> OCSF contract: logsources, OCSF class, table names, product filter, field map, value maps |
| `rules/` | Curated Sigma rules for endpoint, identity, cloud, network and AI-agent abuse |
| `fixtures/` | Synthetic OCSF match and no-match events, one file per rule |

```bash
aisoc sigma list                                   # rules, area, OCSF class, ATT&CK / ATLAS tags
aisoc sigma test                                   # fixtures + evaluator / SQL / KQL parity
aisoc sigma convert --rule ep-lsass-minidump --backend sql
```
