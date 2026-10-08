"""Knowledge capture: runbooks (shared, committed) and case notes (per tenant, learned).

A case note is written only from an analyst's decision, never from an AI verdict, so the model cannot
teach itself a wrong answer (no self-poisoning). Triage looks notes up by alert signature, which is
how one analyst's call on Monday ("that encoded PowerShell is the SCCM inventory job") becomes the
whole team's starting point on Tuesday."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import cache
from pathlib import Path

from aisoc import OUT, RUNBOOKS


@dataclass(frozen=True)
class Runbook:
    file: str
    title: str
    techniques: tuple[str, ...]
    rules: tuple[str, ...]
    steps: tuple[str, ...]


@cache
def runbooks() -> list[Runbook]:
    out = []
    for p in sorted(RUNBOOKS.glob("*.md")):
        if p.name == "README.md":
            continue
        text = p.read_text()
        title = re.search(r"^# Runbook: (.+)$", text, re.M).group(1)
        tech = tuple(x.strip() for x in re.search(r"^Techniques: (.+)$", text, re.M).group(1).split(","))
        rules = tuple(x.strip() for x in re.search(r"^Rules: (.+)$", text, re.M).group(1).split(","))
        steps = tuple(re.findall(r"^(?:\d+\.|-) (.+)$", text, re.M))
        out.append(Runbook(p.name, title, tech, rules, steps))
    return out


def runbook_for(sources: list[str], techniques: list[str]) -> Runbook | None:
    best, score = None, 0
    for rb in runbooks():
        s = 3 * len(set(sources) & set(rb.rules)) + len(set(techniques) & set(rb.techniques))
        if s > score:
            best, score = rb, s
    return best


@dataclass(frozen=True)
class CaseNote:
    tenant: str
    signature: str
    verdict: str
    analyst: str
    incident_id: str
    note: str


@dataclass
class KnowledgeBase:
    """Per-tenant case notes. One instance per tenant; lookups never cross tenants."""

    tenant: str
    notes: list[CaseNote] = field(default_factory=list)

    def add(self, note: CaseNote) -> None:
        if note.tenant != self.tenant:
            raise PermissionError(f"case note for {note.tenant} written to the {self.tenant} knowledge base")
        if not note.analyst.startswith("analyst."):
            raise PermissionError("only analyst decisions become case notes")
        self.notes.append(note)

    def prior(self, signature: str) -> Counter:
        return Counter(n.verdict for n in self.notes if n.signature == signature)

    def save(self, root: Path = OUT / "knowledge") -> Path:
        root.mkdir(parents=True, exist_ok=True)
        p = root / f"{self.tenant}.jsonl"
        p.write_text("".join(json.dumps(asdict(n)) + "\n" for n in self.notes))
        return p
