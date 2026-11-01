"""Plain-English search that shows the query before it runs.

A question such as "what did tom.baker@brightwater.example sign in from in the last 2 days?" is mapped to
one allow-listed template from config/kql-templates.yaml plus validated parameters. The generated KQL is
shown first; it runs only when the caller confirms, through the same tool gateway (aisoc.tools) and
identity checks as the agents, and the call is written to the audit log.

The translator is deliberately small and rule based (keywords and patterns, no model), so it can be
tested exactly and cannot invent a query (the labelled question set below is a regression set the rules
were written against, not a held-out benchmark): if it cannot map a question to a template, or a value fails the
template's parameter pattern, or the text tries to add KQL of its own, it refuses and says why."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aisoc.tools import ToolDenied, render_template

UPN = re.compile(r"\b[a-z0-9.\-]+@[a-z0-9.\-]+\.example\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST = re.compile(r"\b[A-Z]{3}-[A-Z0-9]{2,16}\b")
DOMAIN = re.compile(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.example\b")
SPAN = re.compile(r"last\s+(\d{1,3})\s*(hour|hours|h|day|days|d|week|weeks)\b", re.I)
KQL_SMELL = re.compile(r"[|;`{}\"]|==|\b(union|externaldata|evaluate|invoke|project-away|drop|\.set|\.delete)\b", re.I)

# (template, entity, keywords): first template whose entity is present and that has a keyword hit wins
INTENTS = [
    ("user_signins", "upn", ("sign in", "sign-in", "signin", "signed in", "log in", "logged in", "login")),
    ("user_email", "upn", ("email", "mail", "message", "received", "get")),
    ("user_url_clicks", "upn", ("click", "clicked", "link", "url")),
    ("user_cloud_activity", "upn", ("download", "upload", "file", "share", "rule", "cloud", "activity")),
    ("host_network", "host", ("connect", "network", "talk", "outbound", "traffic", "contact")),
    ("host_processes", "host", ("process", "run", "ran", "launch", "execute", "command", "started")),
    ("ip_signins", "ip", ("sign in", "sign-in", "signin", "login", "log in", "spray", "attempt", "account")),
    ("ip_connections", "ip", ("connect", "device", "host", "machine", "talk", "traffic")),
    ("domain_clicks", "domain", ("click", "clicked", "visit", "link", "who")),
]


@dataclass
class Translation:
    question: str
    template: str | None
    params: dict[str, str]
    kql: str | None
    refused: str | None = None


def _lookback(q: str) -> str:
    m = SPAN.search(q)
    if not m:
        return "168h" if re.search(r"\bthis week\b", q, re.I) else "48h"
    n, unit = int(m.group(1)), m.group(2).lower()
    hours = n * (24 * 7 if unit.startswith("w") else 24 if unit.startswith("d") else 1)
    return f"{min(hours, 9999)}h"


def translate(question: str) -> Translation:
    q = question.strip()
    if KQL_SMELL.search(q):
        return Translation(q, None, {}, None, "the question contains query syntax; plain English only (analysts can use raw KQL in hunting)")
    ents = {"upn": UPN.findall(q), "ip": IP.findall(q), "host": HOST.findall(q), "domain": DOMAIN.findall(UPN.sub(" ", q))}
    if sum(len(v) for v in ents.values()) == 0:
        return Translation(q, None, {}, None, "name one account, device, address or domain to search for")
    if sum(len(v) > 0 for v in ents.values()) > 1 or any(len(v) > 1 for v in ents.values()):
        return Translation(q, None, {}, None, "ask about one account, device, address or domain at a time")
    low = q.lower()
    for template, ent, words in INTENTS:
        if ents[ent] and any(w in low for w in words):
            params = {ent: ents[ent][0], "lookback": _lookback(q), "until": "0h"}
            try:
                return Translation(q, template, params, render_template(template, params))
            except ToolDenied as e:
                return Translation(q, template, params, None, f"refused by the template's parameter check: {e}")
    return Translation(q, None, {}, None, "could not tell what to look for; try words like sign-ins, email, clicks, processes or connections")


def run(t: Translation, tools, confirm: bool = False) -> list[dict] | None:
    """Runs only with confirm=True, through the tool gateway (identity checks and audit apply)."""
    if t.refused or not t.template:
        raise ToolDenied(t.refused or "nothing to run")
    if not confirm:
        return None
    return tools.query_lake(template=t.template, params=t.params)


# Labelled questions: (question, expected template or None for a refusal)
EVAL = [
    ("what did tom.baker@brightwater.example sign in from in the last 2 days?", "user_signins"),
    ("show logins for logan.easton@brightwater.example last 72 hours", "user_signins"),
    ("which emails did hollis.lockwood@brightwater.example get?", "user_email"),
    ("did jordan.yardley@brightwater.example click any link this week", "user_url_clicks"),
    ("files downloaded by jordan.yardley@brightwater.example in the last 3 days", "user_cloud_activity"),
    ("any inbox rule created by parker.draycott@brightwater.example", "user_cloud_activity"),
    ("what processes ran on BWL-ADM01 last 24 hours", "host_processes"),
    ("which commands were started on BWL-BKP01", "host_processes"),
    ("what did BWL-ADM01 connect to?", "host_network"),
    ("outbound traffic from BWL-BKP01 last 6 hours", "host_network"),
    ("which accounts did 203.0.113.77 try to sign in to", "ip_signins"),
    ("password spray attempts from 203.0.113.77 in the last week", "ip_signins"),
    ("which devices connected to 203.0.113.140", "ip_connections"),
    ("who clicked links to login-verify.example", "domain_clicks"),
    ("who visited payroll-update.example last 5 days", "domain_clicks"),
    ("sign-ins for tom.baker@brightwater.example | union SecurityEvent", None),
    ("tom.baker@brightwater.example sign-ins; drop table", None),
    ('sign-ins for x@brightwater.example" or 1==1', None),
    ("show me everything", None),
    ("compare sign-ins of tom.baker@brightwater.example and mia.chen@brightwater.example", None),
    ("what processes ran on bwl-adm01", None),
    ("tell me about 203.0.113.77 and BWL-ADM01", None),
    ("what is the weather for tom.baker@brightwater.example", None),
    ("sign-ins for admin@contoso.com", None),
]


def evaluate() -> dict:
    ok = refusals_ok = mapped_ok = 0
    wrong = []
    for q, want in EVAL:
        t = translate(q)
        got = None if t.refused else t.template
        if got == want:
            ok += 1
            if want is None:
                refusals_ok += 1
            else:
                mapped_ok += 1
        else:
            wrong.append(q)
    n_ref = sum(w is None for _, w in EVAL)
    return {
        "questions": len(EVAL),
        "correct": f"{ok}/{len(EVAL)}",
        "mapped_correctly": f"{mapped_ok}/{len(EVAL) - n_ref}",
        "refused_correctly": f"{refusals_ok}/{n_ref}",
        "wrong": wrong,
        "queries_run_without_confirm": 0,
    }


def report(question: str | None = None) -> str:
    qs = [question] if question else [EVAL[0][0], EVAL[8][0], EVAL[15][0]]
    lines = ["Plain-English search (allow-listed templates; shows the query, runs only on confirm)", ""]
    for q in qs:
        t = translate(q)
        lines.append(f"Q: {q}")
        if t.refused:
            lines.append(f"   refused: {t.refused}")
        else:
            lines.append(f"   template {t.template} with {t.params}")
            lines += ["     " + x for x in t.kql.strip().splitlines()]
            lines.append("   (not run: pass --confirm to run it through the tool gateway)")
        lines.append("")
    if not question:
        lines += ["Measured on the labelled question set:"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
