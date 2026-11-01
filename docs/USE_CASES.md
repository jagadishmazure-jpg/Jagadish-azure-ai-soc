# Use cases

What a small-business SOC team can do with this repository, one row per job, with the command to run and
the measured result. All data is synthetic and every customer is fictional; numbers are measured on that
data and are a regression check, not a claim about real-world accuracy.

| # | Job to be done | Command | Read | Measured on synthetic data |
|---|---|---|---|---|
| 1 | Triage and route every alert to Tier 1, 2 or 3 | `aisoc triage --tenant brightwater` | [triage-routing](components/triage-routing.md) | 37 incidents for this tenant; 0 attacks auto-closed |
| 2 | Investigate an incident with read-only tools | `aisoc investigate --tenant brightwater --incident <id>` | [investigation-agent](components/investigation-agent.md) | Cited timeline, scope and blast radius |
| 3 | Catch identity takeover in Microsoft 365 and Entra ID | `aisoc itdr` | [itdr-pack](components/itdr-pack.md) | 4 of 4 stories; 1 false positive named |
| 4 | Triage an endpoint alert with process tree and persistence | `aisoc endpoint` | [endpoint-triage](components/endpoint-triage.md) | 3 of 3 stories (one on macOS); 4 of 4 verdicts correct |
| 5 | Put the most exposed systems first in the queue | `aisoc exposure` | [exposure-context](components/exposure-context.md) | 20 rank changes; 0 verdicts changed |
| 6 | Auto-report only when independent checks agree | `aisoc consensus` | [consensus-gate](components/consensus-gate.md) | 0 false auto-reports (rule-only: 9) |
| 7 | Contain with written authority, verify, undo | `aisoc authority` | [authority-registry](components/authority-registry.md) | 2 verification failures caught; undo 6 of 6 |
| 8 | Quarantine a misbehaving AI agent | `aisoc authority` | [authority-registry](components/authority-registry.md) | Refused with one approval, done with two |
| 9 | Explain an incident as a timeline | `aisoc timeline --incident ITDR-001` | [timeline-search](components/timeline-search.md) | Built only from a verified audit chain |
| 10 | Ask a question in plain English and see the KQL | `aisoc search "..."` | [timeline-search](components/timeline-search.md) | 24 of 24 on the regression set; runs only on confirm |
| 11 | Cut log cost without losing detections | `aisoc smart-filter` | [service-operations](components/service-operations.md) | Modelled saving about 16% at assumed prices; 0 alerts lost |
| 12 | Sell and measure three service tiers | `aisoc tiers` | [service-operations](components/service-operations.md) | Every SLA breach printed |
| 13 | Prepare each customer's monthly report | `aisoc monthly-report --tenant pinecrest --write` | [service-operations](components/service-operations.md) | Preview files only; nothing is sent |
| 14 | Prove no customer can see another | `aisoc isolation` | [tenant-isolation](components/tenant-isolation.md) | Canary 0 times outside its tenant |
| 15 | Ship detections as code with tests | `aisoc sigma test` | [sigma-detections](components/sigma-detections.md) | 19 of 19 backends agree |

Each command prints its own numbers; the docs show the same output, re-rendered and drift-checked in CI.
