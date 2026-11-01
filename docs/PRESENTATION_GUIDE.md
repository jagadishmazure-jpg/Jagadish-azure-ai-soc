# Presentation guide

A ten-minute walkthrough for an interview or a design review. Every number on screen comes from a command
run live; say "synthetic data, measured" each time a number appears.

## Before you start

```bash
pip install -e ".[dev]"
aisoc gate        # one screen of PASS lines; proves the repo is healthy before you present
```

## Running order

| Minute | Show | Command | Say |
|---|---|---|---|
| 0-1 | The problem | README "At a glance" | A small MSSP, three fictional customers, more alerts than analysts |
| 1-2 | Triage and routing | `aisoc stories` | Every story detected; nothing malicious closed automatically |
| 2-3 | Identity attacks | `aisoc itdr` | Token replay, consent, device code, legacy auth, hidden inbox rule; one false positive shown by name |
| 3-4 | Endpoint triage | `aisoc endpoint` | Process tree and persistence; the signed installer is cleared with a reason; macOS covered |
| 4-5 | Exposure context | `aisoc exposure --tenant brightwater` | Order changes, verdicts never do; the backup server is the choke point |
| 5-6 | Consensus gate | `aisoc consensus` | Rule-only would have sent nine false alarms; the gate sent none, and here is what it cost |
| 6-7 | Authority and undo | `aisoc authority` | Directory sync re-enabled an account and the T+60 check caught it; AI agent quarantine needs two people |
| 7-8 | Timeline and search | `aisoc timeline` and `aisoc search "..."` | The timeline is the audit chain; the search shows KQL before it runs |
| 8-9 | Running the business | `aisoc tiers` and `aisoc monthly-report --tenant pinecrest` | SLA breaches are printed, not averaged away; reports are previews, never sent |
| 9-10 | Limits | README "Open gaps" | Nothing deployed; the model is a mock; numbers are synthetic |

## Questions to expect

* "Would this work on real data?" Not proven. The look-alikes are the honest test here; the independent
  assurance repository measures it on public recordings and finds it weaker.
* "Why not let the agent contain on its own?" No action reaches stage 4; the registry says who owns each
  action and how it is checked and undone.
* "What would you build next?" Live connectors behind the same gateway, and report delivery behind approval.
