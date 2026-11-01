"""Identity threat detection and response (ITDR) pack for Microsoft 365 / Entra ID, on synthetic data.

Six detections over four attack stories and seven benign look-alikes for the fictional customer Orchid
Valley Clinics: adversary-in-the-middle session replay, rogue OAuth consent, device-code phishing, legacy
authentication replay, hosting and anonymising-VPN sign-ins, and inbox rules that hide security mail.

Everything is offline and synthetic. Addresses come from the documentation ranges (RFC 5737); autonomous
system numbers come from the private-use range (64512-65534); app and user names are invented. Ground truth
lives in `PackData.labels` (EventId -> label) and is read only by `evaluate`, never by detection or triage."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache

import yaml

from aisoc import DETECTIONS, kql

T0 = datetime(2026, 4, 6, tzinfo=UTC)  # synthetic epoch; reports print relative times only
TENANT = "orchidvalley"
DOMAIN = "orchidvalley.example"
SEED = 4242
DAYS = 7
RULES_DIR = DETECTIONS / "itdr"

# Autonomous systems (private-use numbers) and what kind of network each one is.
ASNS: dict[int, tuple[str, str]] = {
    64601: ("residential", "Cascade Home Broadband"),
    64602: ("residential", "Lakeshore Fiber"),
    64611: ("mobile", "Northwind Mobile"),
    64620: ("corporate", "Orchid Valley Clinics network"),
    64630: ("vpn-corporate", "Orchid Valley Clinics VPN"),
    64640: ("hosting", "Stratus Compute Cloud"),
    64641: ("hosting", "Rackline Hosting"),
    64650: ("anonymous-vpn", "Veilnet VPN"),
    64660: ("hosting", "Orchid Valley virtual desktops"),
}
KNOWN_EGRESS = {"198.51.100.20", "198.51.100.21", "10.40.0.5"}  # tenant VPN, virtual desktops, office
USERS = ["amira.costa", "ben.okoye", "chen.li", "dana.ruiz", "eli.novak", "farah.haddad", "gus.moreau", "hana.sato",
         "ivan.petrov", "jade.mensah", "kai.lund", "lena.fischer", "milo.grant", "nora.adeyemi", "omar.siddiqui",
         "pia.larsen", "quinn.ross", "rosa.medina"]  # fmt: skip
DEVICE_CODE_ALLOWED = {f"room-{n}@{DOMAIN}" for n in ("cedar", "maple")}
LEGACY_ALLOWED = {f"scan-to-email@{DOMAIN}"}


def upn(name: str) -> str:
    return name if "@" in name else f"{name}@{DOMAIN}"


def rel(ts: datetime) -> str:
    return f"D{(ts - T0).days:02d} {ts:%H:%M}"


@dataclass
class PackData:
    tables: dict[str, list[dict]] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)  # EventId -> attack:<story> | benign:<kind> | noise

    def rows(self, t: str) -> list[dict]:
        return self.tables.setdefault(t, [])


class _Gen:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(f"{seed}:itdr")
        self.d = PackData()
        self.n = 0
        self.sessions = 0

    def add(self, table: str, ts: datetime, label: str, **cols) -> str:
        self.n += 1
        e = f"id-e{self.n:05d}"
        self.d.labels[e] = label
        self.d.rows(table).append({"TimeGenerated": ts, **cols, "EventId": e})
        return e

    def at(self, day: int, hour: float, minute: float = 0) -> datetime:
        return T0 + timedelta(days=day, hours=hour, minutes=minute)

    def session(self) -> str:
        self.sessions += 1
        return f"sess-{self.sessions:05d}"

    def signin(self, ts, who, ip, asn, label, *, session="", device="", client="Browser", proto="none", app="Office 365", result="0"):
        u = upn(who)
        cat = ASNS[asn][0]
        return self.add("SigninLogs", ts, label, UserPrincipalName=u, IPAddress=ip, AutonomousSystemNumber=asn, AsnCategory=cat,
                        KnownEgress=ip in KNOWN_EGRESS, SessionId=session, DeviceId=device, ClientAppUsed=client,
                        AuthenticationProtocol=proto, AppDisplayName=app, ResultType=result,
                        DeviceCodeAllowed=u in DEVICE_CODE_ALLOWED, LegacyAllowListed=u in LEGACY_ALLOWED)  # fmt: skip

    def consent(self, ts, who, app, scopes, verified, label, admin=False):
        return self.add("AuditLogs", ts, label, OperationName="Consent to application", InitiatedBy=upn(who), TargetAppName=app,
                        ConsentedScopes=list(scopes), PublisherVerified=verified, AdminConsent=admin)  # fmt: skip

    def inbox_rule(self, ts, who, name, words, label, folder="", delete=False, read=False, ip="10.40.0.5"):
        return self.add("OfficeActivity", ts, label, Operation="New-InboxRule", UserId=upn(who), RuleName=name,
                        SubjectOrBodyContainsWords=list(words), MoveToFolder=folder, DeleteMessage=delete, MarkAsRead=read,
                        ClientIP=ip)  # fmt: skip

    def mail_access(self, ts, who, ip, items, label):
        return self.add("OfficeActivity", ts, label, Operation="MailItemsAccessed", UserId=upn(who), RuleName="",
                        SubjectOrBodyContainsWords=[], MoveToFolder="", DeleteMessage=False, MarkAsRead=False, ClientIP=ip,
                        Items=items)  # fmt: skip

    # -- normal week ----------------------------------------------------------------------------------
    def noise(self) -> None:
        for day in range(DAYS):
            for who in USERS:
                home = 64601 if hash(who) % 2 else 64602
                s = self.session()
                dev = f"dev-{who.split('.')[0]}"
                for k in range(self.rng.randint(2, 4)):
                    office = self.rng.random() < 0.6
                    ip = "10.40.0.5" if office else f"198.51.100.{100 + USERS.index(who)}"
                    asn = 64620 if office else home
                    app = self.rng.choice(["Office 365", "Microsoft Teams", "SharePoint Online", "Clinic Scheduling"])
                    self.signin(self.at(day, 8 + k * 2.5, self.rng.uniform(0, 50)), who, ip, asn, "noise", session=s, device=dev, app=app)
                if self.rng.random() < 0.08:
                    self.signin(self.at(day, 9, self.rng.uniform(0, 50)), who, "10.40.0.5", 64620, "noise", device=dev, result="50126")
            for room in DEVICE_CODE_ALLOWED:  # B4 meeting-room devices legitimately use device-code flow every morning
                self.signin(self.at(day, 7, 30), room, "10.40.0.5", 64620, "benign:meeting-room-device-code", proto="deviceCode",
                            app="Microsoft Teams Rooms", device=f"dev-{room[:10]}")  # fmt: skip
            # B5 the listed scan-to-email printer uses SMTP AUTH from the office network
            self.signin(self.at(day, 10), "scan-to-email", "10.40.0.5", 64620, "benign:listed-printer-smtp", client="Authenticated SMTP",
                        app="Exchange Online")  # fmt: skip

    # -- attack stories --------------------------------------------------------------------------------
    def stories(self) -> None:
        # A1 adversary-in-the-middle: the victim signs in through a phishing proxy; the stolen session cookie is
        # replayed from a hosting network 14 minutes later; an inbox rule hides security mail; mail is read in bulk.
        lab = "attack:aitm-token-replay"
        s = self.session()
        self.signin(self.at(2, 9, 2), "dana.ruiz", "198.51.100.103", 64602, lab, session=s, device="dev-dana")
        self.signin(self.at(2, 9, 16), "dana.ruiz", "203.0.113.200", 64640, lab, session=s, device="")
        self.inbox_rule(self.at(2, 9, 21), "dana.ruiz", "..", ["security", "mfa", "password", "unusual sign-in"], lab, folder="RSS Feeds",
                        read=True, ip="203.0.113.200")  # fmt: skip
        self.mail_access(self.at(2, 9, 25), "dana.ruiz", "203.0.113.200", 412, lab)
        # A2 rogue OAuth app: a user grants an unverified "document viewer" mail and file access
        lab = "attack:oauth-consent-phish"
        self.signin(self.at(3, 14, 5), "gus.moreau", "10.40.0.5", 64620, lab, session=self.session(), device="dev-gus", app="Office 365")
        self.consent(self.at(3, 14, 7), "gus.moreau", "QuickDoc Viewer Sync", ["User.Read", "Mail.Read", "Files.ReadWrite.All", "offline_access"],
                     False, lab)  # fmt: skip
        # A3 device-code phishing: the victim enters the attacker's code; the token lands on a hosting network
        lab = "attack:device-code-phish"
        self.signin(self.at(4, 11, 40), "kai.lund", "203.0.113.150", 64641, lab, session=self.session(), proto="deviceCode",
                    app="Microsoft Office")  # fmt: skip
        self.mail_access(self.at(4, 11, 52), "kai.lund", "203.0.113.150", 128, lab)
        # A4 legacy authentication replay after a spray: IMAP and ROPC succeed for one account from a hosting network
        lab = "attack:legacy-auth-replay"
        for k, who in enumerate(USERS[:8]):
            self.signin(self.at(5, 2, k), who, "203.0.113.77", 64641, lab, client="IMAP4", app="Exchange Online", result="50126")
        self.signin(self.at(5, 2, 9), "omar.siddiqui", "203.0.113.77", 64641, lab, client="IMAP4", app="Exchange Online")
        self.signin(self.at(5, 2, 12), "omar.siddiqui", "203.0.113.77", 64641, lab, proto="ropc", client="Mobile Apps and Desktop clients",
                    app="Exchange Online")  # fmt: skip

    # -- benign look-alikes ----------------------------------------------------------------------------
    def lookalikes(self) -> None:
        # B1 a phone keeps its session while moving from home broadband to the mobile carrier
        s = self.session()
        self.signin(self.at(1, 7, 50), "hana.sato", "198.51.100.107", 64601, "benign:roaming-phone", session=s, device="dev-hana-phone")
        self.signin(self.at(1, 8, 20), "hana.sato", "198.51.100.230", 64611, "benign:roaming-phone", session=s, device="dev-hana-phone")
        # B2 sign-ins through the clinic's own VPN and virtual desktops (hosting ASN, but known egress)
        for k, who in enumerate(USERS[:6]):
            self.signin(self.at(k % DAYS, 19), who, "198.51.100.20", 64630, "benign:corporate-vpn", session=self.session())
            self.signin(self.at(k % DAYS, 20), who, "198.51.100.21", 64660, "benign:virtual-desktop", session=self.session())
        # B3 admin consent to a verified publisher, and a user consenting to a verified app with a low scope
        self.consent(self.at(1, 10), "it.manager", "Clinic Scheduling", ["User.Read", "Calendars.ReadWrite"], True, "benign:verified-admin-consent",
                     admin=True)  # fmt: skip
        self.consent(self.at(3, 15), "pia.larsen", "Shift Swap Board", ["User.Read", "openid", "profile"], False, "benign:low-scope-consent")
        # B6 harmless inbox rules: newsletters to a folder, and accounts payable filing invoices
        self.inbox_rule(self.at(2, 16), "quinn.ross", "Newsletters", ["newsletter", "webinar"], "benign:newsletter-rule", folder="Newsletters")
        self.inbox_rule(self.at(4, 9), "rosa.medina", "Invoices", ["invoice", "remittance"], "benign:ap-invoice-rule", folder="Invoices")
        # B7 a clinician travelling abroad signs in through a commercial VPN from a hotel (a known false positive of the flag)
        self.signin(self.at(6, 21, 30), "lena.fischer", "203.0.113.180", 64650, "benign:traveller-commercial-vpn", session=self.session(),
                    device="dev-lena")  # fmt: skip


@cache
def generate(seed: int = SEED) -> PackData:
    g = _Gen(seed)
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
    technique: str
    entity: str
    at: datetime
    event_ids: tuple[str, ...]


def detect(data: PackData) -> list[Alert]:
    out: list[Alert] = []
    now = T0 + timedelta(days=DAYS)
    for r in rules():
        for row in kql.run((RULES_DIR / r["file"]).read_text(), data.tables, now):
            ids = tuple(row["EventIds"]) if "EventIds" in row else (row["EventId"],)
            out.append(Alert(r["id"], r["stage"], r["severity"], r["technique"], row[r["entity"]], row["TimeGenerated"], ids))
    return sorted(out, key=lambda a: (a.at, a.rule))


@dataclass
class Case:
    id: str
    entity: str
    alerts: list[Alert]
    kind: str = "identity"

    @property
    def event_ids(self) -> list[str]:
        return sorted({e for a in self.alerts for e in a.event_ids})

    @property
    def start(self) -> datetime:
        return min(a.at for a in self.alerts)

    @property
    def end(self) -> datetime:
        return max(a.at for a in self.alerts)


def cases(alerts: list[Alert], window: timedelta = timedelta(hours=6)) -> list[Case]:
    """One case per account; alerts more than `window` after the last one open a new case."""
    out: list[Case] = []
    open_by: dict[str, Case] = {}
    for a in alerts:
        c = open_by.get(a.entity)
        if c is None or a.at - c.end > window:
            c = Case(f"ITDR-{len(out) + 1:03d}", a.entity, [])
            out.append(c)
            open_by[a.entity] = c
        c.alerts.append(a)
    return out


def event(data: PackData, event_id: str) -> tuple[str, dict] | None:
    for name, rows in data.tables.items():
        for r in rows:
            if r["EventId"] == event_id:
                return name, r
    return None


def describe(table: str, r: dict) -> str:
    """One plain-English line for a telemetry row, used by the timeline."""
    if table == "SigninLogs":
        how = (
            "device-code flow"
            if r["AuthenticationProtocol"] == "deviceCode"
            else ("password flow (ROPC)" if r["AuthenticationProtocol"] == "ropc" else r["ClientAppUsed"])
        )
        ok = "succeeded" if r["ResultType"] == "0" else f"failed ({r['ResultType']})"
        return f"sign-in {ok} for {r['UserPrincipalName']} via {how} from {r['IPAddress']} ({r['AsnCategory']} network)"
    if table == "AuditLogs":
        return f"{r['InitiatedBy']} consented to '{r['TargetAppName']}' ({', '.join(r['ConsentedScopes'])}); publisher verified: {r['PublisherVerified']}"
    if r["Operation"] == "MailItemsAccessed":
        return f"{r.get('Items', 0)} mail items read in {r['UserId']} from {r['ClientIP']}"
    return f"inbox rule '{r['RuleName']}' created in {r['UserId']} (words: {', '.join(r['SubjectOrBodyContainsWords'])}; folder: {r['MoveToFolder'] or '-'})"


# --------------------------------------------------------------------------- response catalogue (dry run)
def plan_actions(c: Case, data: PackData) -> list[tuple[str, str]]:
    """(action, target) pairs from the fixed catalogue in config/authority.yaml."""
    rules_hit = {a.rule for a in c.alerts}
    acts: list[tuple[str, str]] = []
    if rules_hit & {"token-replay", "device-code-signin", "legacy-auth-signin"}:
        acts.append(("revoke_sessions", c.entity))
    if rules_hit & {"token-replay", "device-code-signin"}:
        acts.append(("reset_password", c.entity))
    if "legacy-auth-signin" in rules_hit:
        acts.append(("block_legacy_auth_for_user", c.entity))
    for e in c.event_ids:
        t, r = event(data, e) or ("", {})
        if t == "OfficeActivity" and r.get("Operation") == "New-InboxRule":
            acts.append(("remove_inbox_rule", f"{r['UserId']}/{r['RuleName']}"))
        if t == "AuditLogs":
            acts.append(("revoke_oauth_grant", f"{r['InitiatedBy']}/{r['TargetAppName']}"))
    return acts


# --------------------------------------------------------------------------- evaluation (reads labels)
STORIES = ("aitm-token-replay", "oauth-consent-phish", "device-code-phish", "legacy-auth-replay")


def _story(data: PackData, c: Case) -> str:
    labs = {data.labels[e] for e in c.event_ids}
    att = sorted(x[7:] for x in labs if x.startswith("attack:"))
    return (
        att[0]
        if att
        else ("benign:" + sorted(x[7:] for x in labs if x.startswith("benign:"))[0] if any(x.startswith("benign:") for x in labs) else "noise")
    )


def evaluate(seed: int = SEED) -> dict:
    data = generate(seed)
    alerts = detect(data)
    lab = data.labels
    is_attack = lambda a: any(lab[e].startswith("attack:") for e in a.event_ids)  # noqa: E731
    tp = [a for a in alerts if is_attack(a)]
    fp = [a for a in alerts if not is_attack(a)]
    caught = {lab[e][7:] for a in tp for e in a.event_ids if lab[e].startswith("attack:")}
    kinds = sorted({v[7:] for v in lab.values() if v.startswith("benign:")})
    fp_kinds = sorted({lab[e][7:] for a in fp for e in a.event_ids if lab[e].startswith("benign:")})
    per_rule = {r["id"]: sum(a.rule == r["id"] for a in alerts) for r in rules()}
    return {
        "events": sum(len(v) for v in data.tables.values()),
        "alerts": len(alerts),
        "true_positive_alerts": len(tp),
        "false_positive_alerts": len(fp),
        "precision": round(len(tp) / len(alerts), 3) if alerts else 0.0,
        "stories_detected": f"{len(caught)}/{len(STORIES)}",
        "lookalike_kinds": len(kinds),
        "lookalike_kinds_alerting": fp_kinds,
        "cases": len(cases(alerts)),
        "alerts_per_rule": per_rule,
    }


def report(seed: int = SEED) -> str:
    data = generate(seed)
    alerts = detect(data)
    lines = ["Identity threat pack (synthetic Orchid Valley Clinics week; documentation IP ranges, private-use ASNs)", ""]
    for c in cases(alerts):
        lines.append(f"{c.id}  {c.entity:<32} {rel(c.start)}  rules: {', '.join(sorted({a.rule for a in c.alerts}))}")
        for act, target in plan_actions(c, data):
            lines.append(f"         > {act} {target} (dry run, needs approval)")
    m = evaluate(seed)
    lines += ["", "Measured (regression check on synthetic data, not a quality claim):"]
    lines += [f"  {k}: {v}" for k, v in m.items()]
    return "\n".join(lines)
