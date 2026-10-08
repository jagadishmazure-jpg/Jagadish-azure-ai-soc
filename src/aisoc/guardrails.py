"""Guardrails for text that reaches a model.

Alert fields are attacker-controlled: an email subject, a process command line or a file name can carry
instructions aimed at an AI analyst. Three controls run before any prompt is built:

1. `screen` flags instruction-like text (regex stand-in; `PromptShieldsScreen` is the Azure adapter
   path for Azure AI Content Safety Prompt Shields). A flagged field is wrapped as quoted data, and the
   attempt itself becomes evidence: an alert that tries to talk to the SOC's AI is suspicious.
2. `redact` masks PII in free text (SSN-like numbers, phone numbers, payment cards, personal email).
3. `Pseudonymizer` swaps account names and host names for stable tokens (USER-1, HOST-1) per tenant;
   the mapping stays server-side, so the model never sees an identity and cannot leak one across tenants.

The model's output is also checked afterwards (see `aisoc.llm.validate_summary`): a summary whose
verdict differs from the verdict computed by code is discarded."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

INJECTION_PATTERNS = [
    r"\b(ignore|disregard|forget)\b.{0,40}\b(instructions|rules|previous|prior|above)\b",
    r"\b(assistant|ai|llm|copilot|triage|analyst)\b\s*(note|instruction|:)",
    r"\b(classify|mark|label|treat)\b.{0,40}\b(benign|false positive|safe|clean)\b",
    r"\b(close|dismiss|suppress|resolve)\b.{0,30}\b(this|the)\b.{0,15}\b(alert|incident|case|ticket|it)\b",
    r"\bdo not (isolate|escalate|alert|block|disable)\b",
    r"\b(system prompt|developer mode|jailbreak)\b",
    r"\balready (been )?reviewed by\b",
]
_INJ = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.I)

PII_PATTERNS = {
    "SSN": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "PHONE": re.compile(r"\+?1?[-. ]?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b|\+\d{1,2}-\d{3}-\d{4}\b"),
    "CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}
UPN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass(frozen=True)
class Screen:
    flagged: bool
    matches: tuple[str, ...]


def screen(text: str | None) -> Screen:
    if not text:
        return Screen(False, ())
    found = tuple(m.group(0) for m in _INJ.finditer(text))
    return Screen(bool(found), found)


def quote_untrusted(text: str) -> str:
    """Wrap untrusted text so a prompt presents it as data, never as instructions."""
    return "<untrusted_data>" + text.replace("<", "&lt;").replace(">", "&gt;") + "</untrusted_data>"


def redact(text: str | None) -> str:
    if not text:
        return ""
    out = text
    for label, pat in PII_PATTERNS.items():
        out = pat.sub(f"[{label}]", out)
    return out


@dataclass
class Pseudonymizer:
    """Stable, per-tenant tokens for identities. One instance per tenant; never shared."""

    tenant: str
    tenant_domain: str
    hosts: set[str] = field(default_factory=set)
    _fwd: dict[str, str] = field(default_factory=dict)

    def token(self, value: str, kind: str) -> str:
        key = value.lower()
        if key not in self._fwd:
            n = sum(1 for t in self._fwd.values() if t.startswith(kind)) + 1
            self._fwd[key] = f"{kind}-{n}"
        return self._fwd[key]

    def apply(self, text: str) -> str:
        def upn(m: re.Match) -> str:
            v = m.group(0)
            if v.lower().endswith("@" + self.tenant_domain):
                return self.token(v, "USER")
            return "[EMAIL]"

        out = UPN.sub(upn, text)
        for h in sorted(self.hosts, key=len, reverse=True):
            out = re.sub(re.escape(h), self.token(h, "HOST"), out, flags=re.I)
        return out

    def reverse(self) -> dict[str, str]:
        return {v: k for k, v in self._fwd.items()}


def prepare(text: str | None, pseudo: Pseudonymizer, guard: bool = True) -> tuple[str, Screen]:
    """The full pre-model pipeline for one untrusted field: screen, redact, pseudonymise, quote."""
    raw = text or ""
    s = screen(raw)
    if not guard:
        return raw, s
    clean = pseudo.apply(redact(raw))
    return quote_untrusted(clean), s


class PromptShieldsScreen:
    """Azure adapter path: Azure AI Content Safety `text:shieldPrompt` with Entra ID auth.

    Not called offline and never run against Azure from this repo; it shows where the regex stand-in
    is replaced. Set AISOC_CONTENT_SAFETY_ENDPOINT and install the `foundry` extra to use it."""

    API_VERSION = "2024-09-01"

    def __init__(self, endpoint: str, credential) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.credential = credential

    def request(self, documents: list[str]) -> dict:
        return {
            "url": f"{self.endpoint}/contentsafety/text:shieldPrompt?api-version={self.API_VERSION}",
            "body": {"userPrompt": "", "documents": documents},
        }
