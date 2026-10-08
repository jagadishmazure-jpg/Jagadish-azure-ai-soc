"""Hash-chained audit log, one chain per tenant.

Every tool call, routing decision, containment plan, approval request, approval decision and
execution record is appended with the hash of the previous record. `verify` recomputes the chain, so
an edited, deleted or re-ordered record is detected. In Azure the chain would be written to an
immutable (WORM) blob container and mirrored to the Log Analytics workspace."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o), separators=(",", ":"))


@dataclass
class AuditLog:
    tenant: str
    records: list[dict] = field(default_factory=list)

    def append(self, actor: str, event: str, data: dict[str, Any], at: datetime | None = None) -> dict:
        prev = self.records[-1]["hash"] if self.records else GENESIS
        rec = {
            "seq": len(self.records) + 1,
            "tenant": self.tenant,
            "at": at.isoformat() if at else None,
            "actor": actor,
            "event": event,
            "data": data,
            "prev": prev,
        }
        rec["hash"] = hashlib.sha256(_canon(rec).encode()).hexdigest()
        self.records.append(rec)
        return rec

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, rec in enumerate(self.records, 1):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec["seq"] != i:
                return False, f"record {i}: sequence {rec['seq']}"
            if rec["prev"] != prev:
                return False, f"record {i}: broken link"
            if hashlib.sha256(_canon(body).encode()).hexdigest() != rec["hash"]:
                return False, f"record {i}: hash mismatch"
            if rec["tenant"] != self.tenant:
                return False, f"record {i}: tenant {rec['tenant']} in the {self.tenant} chain"
            prev = rec["hash"]
        return True, f"{len(self.records)} records verified"

    def events(self, event: str) -> list[dict]:
        return [r for r in self.records if r["event"] == event]

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(_canon(r) + "\n" for r in self.records))
        return path
