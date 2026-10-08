"""Read-only summaries of the infrastructure code, for `aisoc iac` and the infra docs.

Nothing here runs Terraform, Bicep or Azure; it parses the files in infra/ and .github/workflows so the
docs list exactly what the code declares, and the doc drift check fails when the two diverge."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import yaml

from aisoc import ROOT

TF = ROOT / "infra" / "terraform"
BICEP = ROOT / "infra" / "bicep"
WORKFLOWS = ROOT / ".github" / "workflows"


def terraform() -> list[str]:
    out = []
    for f in sorted(TF.glob("*.tf")):
        for m in re.finditer(r'^resource "(\w+)" "(\w+)" \{\n((?:  .*\n|\n)*?)\}', f.read_text(), re.M):
            body = m.group(3)
            cond = re.search(r"^  (count|for_each)\s*=\s*(.+)$", body, re.M)
            gate = f"  [{cond.group(1)}: {cond.group(2).strip()}]" if cond else ""
            out.append(f"{f.name:<12} {m.group(1)}.{m.group(2)}{gate}")
    return out


def bicep() -> list[str]:
    out = []
    for f in [BICEP / "main.bicep", *sorted((BICEP / "modules").glob("*.bicep"))]:
        lines = f.read_text().splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"(resource|module) (\w+) '([^'@]+)(?:@[^']+)?'( existing)? = (.*)$", line)
            if not m:
                continue
            kind, name, typ, existing, rest = m.groups()
            if rest.strip() == "[":  # loop body starts on the next line
                rest = "[" + lines[i + 1].strip()
            notes = []
            if existing:
                notes.append("existing")
            if rest.startswith("["):
                notes.append("loop")
            cond = re.search(r"if \(([^)]*)\)", rest)
            if cond:
                notes.append(f"if {cond.group(1)}")
            out.append(f"{f.relative_to(BICEP).as_posix():<26} {kind:<8} {name:<18} {typ}" + (f"  [{'; '.join(notes)}]" if notes else ""))
    return out


def workflows() -> list[str]:
    out = []
    for f in sorted(WORKFLOWS.glob("*.yml")):
        d = yaml.safe_load(f.read_text())
        on = d.get(True, d.get("on"))
        triggers = ", ".join(on) if isinstance(on, dict) else str(on)
        out.append(f"{f.name}: triggers [{triggers}], top-level permissions {json.dumps(d.get('permissions'))}")
        for name, job in d["jobs"].items():
            bits = []
            if "if" in job:
                bits.append(f"if {job['if']}")
            if "environment" in job:
                bits.append(f"environment {job['environment']}")
            if job.get("permissions"):
                bits.append("permissions " + ", ".join(f"{k}: {v}" for k, v in job["permissions"].items()))
            out.append(f"  {name}" + (f" ({'; '.join(bits)})" if bits else ""))
    return out


def rules() -> list[str]:
    doc = json.loads((ROOT / "detections" / "rules.json").read_text())
    return [
        f"{r['id']:<24} {r['severity']:<7} {r['frequency']}/{r['period']:<5} {', '.join(r['techniques'])}  entities: {', '.join(r['entities'].values())}"
        for r in doc["rules"]
    ]


PARTS: dict[str, Callable[[], list[str]]] = {"terraform": terraform, "bicep": bicep, "workflows": workflows, "rules": rules}
