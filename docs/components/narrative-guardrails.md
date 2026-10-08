# Component: narrative agent and prompt guardrails

A Microsoft Agent Framework agent turns the computed verdict, evidence and containment plan into an
analyst-ready summary with structured output. The model never decides anything. Before a prompt is built,
attacker-controlled text is screened for instructions, PII is redacted, identities are pseudonymised and
untrusted fields are quoted; after the model answers, a validator rejects any summary that changes the
facts, and a template takes its place.

Sections: [1. Purpose](#1-purpose) · [2. Architecture](#2-architecture) · [3. How it works](#3-how-it-works) · [4. Key files](#4-key-files) · [5. Code excerpts](#5-code-excerpts) · [6. Configuration](#6-configuration) · [7. Commands](#7-commands) · [8. Real output](#8-real-output) · [9. Tests and gates](#9-tests-and-gates) · [10. Guardrails](#10-guardrails) · [11. Security and governance](#11-security-and-governance) · [12. Observability](#12-observability) · [13. Failure modes](#13-failure-modes) · [14. Mapping to Azure services](#14-mapping-to-azure-services) · [15. Limitations](#15-limitations) · [16. Interview talking points](#16-interview-talking-points)

## 1. Purpose

* Save analysts the write-up while keeping every fact traceable to code.
* Treat alert fields as hostile: an email subject or command line can carry instructions aimed at the AI.
* Keep identities and PII out of the model, so a model cannot leak them, within or across tenants.

## 2. Architecture

```mermaid
flowchart LR
  F[verdict, evidence, plan from code] --> P[build_prompt]
  U[alert fields, evidence text] --> SC[screen: instruction-like text]
  SC --> RD[redact PII]
  RD --> PS[pseudonymise USER-n HOST-n per tenant]
  PS --> Q[quote as untrusted data]
  Q --> P
  P --> AG[MAF Agent: response_format IncidentSummary]
  AG --> V{validate_summary}
  V -->|ok| N[narrative]
  V -->|rejected| T[template fallback]
```

## 3. How it works

1. `build_prompt` writes a FACTS block (verdict, confidence, techniques, pseudonymised scope, allowed
   actions) and the evidence lines. With guardrails on, each free-text field passes through `prepare`:
   screen, redact, pseudonymise, quote.
2. The agent is `Agent(client, instructions, name)` from Microsoft Agent Framework 1.19, run with
   `response_format=IncidentSummary` so the answer is a validated pydantic object.
3. Offline the client is `MockSocChatClient`, a real MAF chat client that writes the summary from the
   facts. Its `gullible` switch makes it obey unquoted instructions it finds in the prompt, the way a
   careless model might, so the tests can show what each layer stops.
4. `validate_summary` rejects a different verdict, unknown evidence IDs, actions outside the catalogue
   or the plan, and a malicious summary that drops the plan. Rejection means the template draft is used.
5. With `AISOC_LLM=foundry` the same agent uses `FoundryChatClient` with `DefaultAzureCredential`. That
   path is written but has never been run against Azure from this repository.

## 4. Key files

| File | Role |
|---|---|
| `src/aisoc/llm.py` | Instructions, `IncidentSummary`, mock and Foundry clients, prompt, validator, fallback |
| `src/aisoc/guardrails.py` | Injection screen, PII redaction, pseudonymiser, Prompt Shields adapter path |

## 5. Code excerpts

<!-- code: src/aisoc/llm.py::validate_summary -->
```python
def validate_summary(s: IncidentSummary, inc: Incident, inv: Investigation, plan: ContainmentPlan) -> list[str]:
    issues = []
    if s.verdict != inc.verdict:
        issues.append(f"summary verdict {s.verdict} differs from code verdict {inc.verdict}")
    known = {e.id for e in inv.evidence}
    bad = [x for x in s.key_evidence if x not in known]
    if bad:
        issues.append(f"cites unknown evidence {bad}")
    allowed = set(catalogue())
    planned = {a.action for a in plan.actions}
    for a in s.recommended_actions:
        if a not in allowed:
            issues.append(f"recommends {a}, which is not in the action catalogue")
        elif a not in planned:
            issues.append(f"recommends {a}, which is not in the containment plan")
    if inc.verdict == "true_positive" and plan.actions and not s.recommended_actions:
        issues.append("drops the containment plan for a malicious incident")
    return issues
```
<!-- /code -->

<!-- code: src/aisoc/llm.py::get_chat_client -->
```python
def get_chat_client(gullible: bool = False) -> BaseChatClient:
    if os.environ.get("AISOC_LLM", "mock") != "foundry":
        return MockSocChatClient(gullible=gullible)
    from agent_framework_foundry import FoundryChatClient  # pragma: no cover - needs the foundry extra and Azure
    from azure.identity import DefaultAzureCredential  # pragma: no cover

    return FoundryChatClient(  # pragma: no cover
        project_endpoint=os.environ["FOUNDRY_PROJECT_ENDPOINT"],
        model=os.environ.get("FOUNDRY_MODEL", "gpt-5-mini"),
        credential=DefaultAzureCredential(),
    )
```
<!-- /code -->

## 6. Configuration

| Variable | Effect |
|---|---|
| `AISOC_LLM` | `mock` (default) or `foundry` |
| `FOUNDRY_PROJECT_ENDPOINT`, `FOUNDRY_MODEL` | Foundry project and model deployment (Foundry path only) |
| `AISOC_CONTENT_SAFETY_ENDPOINT` | Where `PromptShieldsScreen` would send requests (adapter path only) |
| `--guard off`, `--gullible` | CLI switches for the what-if runs |

## 7. Commands

```bash
aisoc injection
aisoc investigate --tenant brightwater --incident INC-BR-027 --guard off --gullible
```

## 8. Real output

<!-- output: injection -->
```text
incidents whose alert fields carry instructions aimed at the AI:
guardrails  gullible model  incident    code verdict   tier  model obeyed  fallback used  final summary verdict
----------  --------------  ----------  -------------  ----  ------------  -------------  ---------------------
on          no              INC-BR-027  true_positive  3     False         False          true_positive
on          yes             INC-BR-027  true_positive  3     False         False          true_positive
off         no              INC-BR-027  true_positive  3     False         False          true_positive
off         yes             INC-BR-027  true_positive  3     True          True           true_positive
```
<!-- /output -->

With guardrails off and the gullible model, the model obeys the planted instruction and writes a benign
summary. The validator catches it, because the verdict differs from the code's, and the template is used.
The verdict and the tier never change, because neither comes from the model.

## 9. Tests and gates

`tests/test_llm_guardrails.py`: the screen flags instruction-like text and passes ordinary text;
redaction; pseudonyms are stable and per tenant; quoting neutralises markup; the Prompt Shields adapter
only builds a request; prompts carry no identities or PII; the insider prompt has a redacted file name;
structured output through MAF; the validator rejects bad summaries; the injection what-if; the token
estimate. The release gate requires zero obeyed injections with guardrails on and zero narratives that
changed a verdict.

## 10. Guardrails

Four layers, each tested alone: screen, redact, pseudonymise and quote before the model; validate after.
The injection attempt is also a triage feature (it raises suspicion) and a routing rule (at least tier 2,
tier 3 if malicious).

## 11. Security and governance

The pseudonym map stays server-side per tenant. The model sees `USER-1` and `HOST-1`, never a real name.
In Azure, the Foundry call uses Entra ID authentication and no API keys.

## 12. Observability

Per narrative: fallback used, injection obeyed, estimated prompt tokens. The learning run used about
17,243 prompt tokens across 37 narratives (see `aisoc metrics`); with a real model this is the cost meter.

## 13. Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Model obeys injected text | Wrong summary | Quoting stops it; validator catches what gets through |
| Model invents evidence | Misleading narrative | Unknown evidence IDs rejected |
| Model suggests a destructive action | Over-response | Actions must be in the catalogue and the plan |
| Foundry unavailable | No narrative | Template fallback; verdict unaffected |

## 14. Mapping to Azure services

| Here | In Azure |
|---|---|
| `MockSocChatClient` | Foundry model deployment through `FoundryChatClient` |
| Regex screen | Azure AI Content Safety Prompt Shields (`PromptShieldsScreen` adapter path) |
| PII redaction | Azure AI Language PII detection |
| Credential | Entra ID via `DefaultAzureCredential` |
| Token and fallback counters | Application Insights / Azure Monitor custom metrics |
| Narrative destination | Microsoft Sentinel incident comment; Defender XDR incident page |

## 15. Limitations

* The screen and the redaction are regex stand-ins; Prompt Shields and the PII service are adapter
  paths that have not been called.
* The mock model is deterministic and writes short summaries; a real model's quality must be evaluated
  with Foundry evaluations before use.
* Token counts are estimates (characters divided by four).

## 16. Interview talking points

* "The model writes prose, code writes facts. A validator compares the two and wins every disagreement."
* "I built a deliberately gullible mock so I could prove which layer stops an injection: quoting stops
  it, and if quoting is off, the validator catches it."
* "The model never sees a username. Pseudonyms are per tenant, so there is nothing to leak."
