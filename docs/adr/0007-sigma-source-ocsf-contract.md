# ADR 0007: Sigma as the rule source, OCSF as the field contract, three engines must agree

**Status:** Accepted

## Context

The KQL rules in `detections/` only run in Microsoft Sentinel. An MSSP also gets asked for the same
detections in a SQL data lake, and a customer may move SIEM. Converting Sigma with default field mappings
is easy, but a wrong or missing mapping does not fail: it produces a valid query that never matches.
Converters are also rarely tested by running their output.

## Decision

* Write the portable rules in Sigma (`detections/sigma/rules/`), a small subset that we parse ourselves.
* Map every Sigma field to an OCSF path in one reviewed file (`ocsf-mapping.yaml`). An unknown logsource,
  field, modifier or mapped value raises an error. Fields OCSF has no attribute for go under `unmapped.*`
  and must be marked `core: false`.
* Give every rule positive and negative OCSF fixtures. Fixtures may only use OCSF paths declared for their
  class.
* Generate SQL (SQLite dialect) and KQL from one condition tree, run both, and require the same hits as a
  Python evaluator over every fixture event. This is a release gate check.
* Map AI-agent tool calls to OCSF API Activity (6003), because OCSF has no AI-agent class, and say so.

## Consequences

* Adding a field is a deliberate mapping change, visible in review.
* The supported Sigma subset is narrower than pySigma (no aggregations, keywords or some modifiers). Rules
  that need counting over time stay in KQL.
* Parity is proven in SQLite and the in-repo KQL engine, not yet in Kusto or a production SQL engine.
* Sigma rules are not deployed: they are not in `rules.json` and stay `experimental`.
