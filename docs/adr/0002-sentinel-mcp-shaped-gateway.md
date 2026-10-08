# ADR 0002: A Sentinel-MCP-shaped, read-only tool gateway

**Status:** Accepted

## Context

Agents need data access. Free-form KQL from a model is an injection and cost risk, and these agents should
interoperate with Microsoft's tooling rather than replace it.

## Decision

All data access goes through `SentinelTools`, whose tool names and shapes follow the Microsoft Sentinel MCP
server's data-exploration tools plus three local ones. Agents may run only allow-listed templates with
regex-checked parameters; raw KQL is for human hunters. The same functions are served by a local MCP server
with read-only annotations and no containment tool.

## Consequences

* Prompt injection cannot become query injection; every call is audited.
* Investigations are limited to what the templates cover.
* Agents can be pointed at Microsoft's hosted server with little change.
