"""Sigma detection-as-code: curated Sigma rules, an explicit Sigma -> OCSF field mapping, fixture tests and
two backends (SQLite SQL and KQL).

Flow: rule YAML -> validate -> map every field through detections/sigma/ocsf-mapping.yaml -> one condition
tree -> (a) evaluate it on OCSF fixture events, (b) emit SQL, (c) emit KQL. The parity check runs all three
over the same events and they must return the same event ids.

The supported Sigma subset is small on purpose. Anything outside it raises SigmaError instead of guessing:
  modifiers   contains startswith endswith all re cidr gt gte lt lte   (plus * and ? wildcards, and null)
  condition   and or not ( ) "1 of x*" "all of x*" "1 of them" "all of them"   (no | aggregations)
  values      strings match case-insensitively, as in Sigma; re matches case-sensitively, as in Sigma
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from aisoc import DETECTIONS, kql

SIGMA = DETECTIONS / "sigma"
RULES = SIGMA / "rules"
FIXTURES = SIGMA / "fixtures"
MAPPING = SIGMA / "ocsf-mapping.yaml"

# OCSF attributes every event carries, whatever its class.
BASE_PATHS = {"class_uid", "metadata.uid", "metadata.product.name"}
STRING_MODS = {"contains", "startswith", "endswith"}
NUMBER_MODS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
KNOWN_MODS = STRING_MODS | set(NUMBER_MODS) | {"all", "re", "cidr"}
RULE_KEYS = {"title", "id", "status", "description", "author", "references", "tags", "logsource", "detection", "falsepositives", "level"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TAG = re.compile(r"^(attack\.(t\d{4}(\.\d{3})?|[a-z-]+)|atlas\.aml\.t\d{4}(\.\d{3})?)$")


class SigmaError(ValueError):
    """A rule, fixture or condition is outside the supported subset or is malformed."""


class SigmaMappingError(SigmaError):
    """A Sigma field, value or logsource has no explicit OCSF mapping."""


# --------------------------------------------------------------------------- mapping
@dataclass(frozen=True)
class FieldMap:
    sigma: str
    ocsf: str
    core: bool = True
    values: dict[str, Any] | None = None


@dataclass(frozen=True)
class Logsource:
    name: str
    keys: dict[str, str]
    class_uid: int
    class_name: str
    sql_table: str
    kql_table: str
    filter: dict[str, Any]
    fields: dict[str, FieldMap]

    def field(self, sigma_name: str, where: str) -> FieldMap:
        if sigma_name not in self.fields:
            raise SigmaMappingError(f"{where}: field {sigma_name!r} has no OCSF mapping for logsource {self.name!r} (add it to {MAPPING.name})")
        return self.fields[sigma_name]


@dataclass(frozen=True)
class Mapping:
    logsources: tuple[Logsource, ...]

    def resolve(self, keys: dict[str, str], where: str) -> Logsource:
        for ls in self.logsources:
            if ls.keys == keys:
                return ls
        raise SigmaMappingError(f"{where}: logsource {keys} is not in {MAPPING.name}")

    def class_paths(self, class_uid: int) -> set[str]:
        """Every OCSF path a fixture event of this class may use."""
        paths = set(BASE_PATHS)
        for ls in self.logsources:
            if ls.class_uid == class_uid:
                paths |= {f.ocsf for f in ls.fields.values()} | set(ls.filter)
        return paths

    def table_columns(self, sql_table: str) -> list[str]:
        cols = set(BASE_PATHS)
        for ls in self.logsources:
            if ls.sql_table == sql_table:
                cols |= {f.ocsf for f in ls.fields.values()} | set(ls.filter)
        return sorted(cols)

    def tables(self) -> list[str]:
        return sorted({ls.sql_table for ls in self.logsources})


def load_mapping(path: Path = MAPPING) -> Mapping:
    raw = yaml.safe_load(path.read_text())
    out = []
    for ls in raw["logsources"]:
        fields = {}
        for name, spec in ls["fields"].items():
            unknown = set(spec) - {"ocsf", "core", "values"}
            if unknown:
                raise SigmaMappingError(f"{ls['name']}.{name}: unknown mapping keys {sorted(unknown)}")
            ocsf = spec["ocsf"]
            core = spec.get("core", True)
            if not core and not ocsf.startswith("unmapped."):
                raise SigmaMappingError(f"{ls['name']}.{name}: a non-core field must live under unmapped.*")
            if core and ocsf.startswith("unmapped."):
                raise SigmaMappingError(f"{ls['name']}.{name}: unmapped.* fields must say core: false")
            fields[name] = FieldMap(name, ocsf, core, spec.get("values"))
        out.append(
            Logsource(
                ls["name"],
                dict(ls["logsource"]),
                ls["class"]["uid"],
                ls["class"]["name"],
                ls["sql_table"],
                ls["kql_table"],
                dict(ls.get("filter", {})),
                fields,
            )
        )
    mapping = Mapping(tuple(out))
    for table in mapping.tables():
        kcols: dict[str, str] = {}
        for c in mapping.table_columns(table):
            k = kql_column(c)
            if k in kcols:
                raise SigmaMappingError(f"{table}: OCSF paths {kcols[k]!r} and {c!r} collide as KQL column {k!r}")
            kcols[k] = c
    return mapping


def kql_column(path: str) -> str:
    return path.replace(".", "_")


# --------------------------------------------------------------------------- condition tree
@dataclass(frozen=True)
class Match:
    """One field test. `values` are OR-ed unless `all_` is set. kind: glob, re, cidr, num, cmp, bool, null."""

    field: FieldMap
    kind: str
    values: tuple[Any, ...]
    all_: bool = False
    op: str = "=="


@dataclass(frozen=True)
class And:
    items: tuple[Any, ...]


@dataclass(frozen=True)
class Or:
    items: tuple[Any, ...]


@dataclass(frozen=True)
class Not:
    item: Any


Glob = tuple[tuple[str, str], ...]  # ("lit", text) | ("star", "") | ("one", "")


def parse_glob(value: str) -> Glob:
    """Sigma string value -> segments. \\* \\? \\\\ escape; any other backslash is literal (Windows paths)."""
    out: list[tuple[str, str]] = []
    buf, i = "", 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            buf += value[i + 1]
            i += 2
            continue
        if c in "*?":
            if buf:
                out.append(("lit", buf))
                buf = ""
            out.append(("star" if c == "*" else "one", ""))
        else:
            buf += c
        i += 1
    if buf:
        out.append(("lit", buf))
    return tuple(out)


def _match(fm: FieldMap, mods: list[str], raw: Any, where: str) -> Match:
    for m in mods:
        if m not in KNOWN_MODS:
            raise SigmaError(f"{where}: unsupported modifier {m!r}")
    all_ = "all" in mods
    kinds = [m for m in mods if m != "all"]
    if len(kinds) > 1:
        raise SigmaError(f"{where}: only one value modifier per field, got {kinds}")
    kind = kinds[0] if kinds else None
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        raise SigmaError(f"{where}: empty value list")
    if all_ and len(values) < 2:
        raise SigmaError(f"{where}: |all needs two or more values")
    if fm.values is not None:
        if kind or all_:
            raise SigmaMappingError(f"{where}: {fm.sigma} has a value map, so only plain equality is allowed")
        mapped = []
        for v in values:
            if v not in fm.values:
                raise SigmaMappingError(f"{where}: value {v!r} of {fm.sigma} has no OCSF value in {MAPPING.name}")
            mapped.append(fm.values[v])
        return Match(fm, "bool", tuple(mapped))
    if any(v is None for v in values):
        if kind or len(values) > 1:
            raise SigmaError(f"{where}: null cannot be combined with modifiers or other values")
        return Match(fm, "null", ())
    if kind in NUMBER_MODS:
        if len(values) > 1 or not all(isinstance(v, int | float) and not isinstance(v, bool) for v in values):
            raise SigmaError(f"{where}: |{kind} needs one number")
        return Match(fm, "cmp", tuple(values), op=NUMBER_MODS[kind])
    if kind == "cidr":
        try:
            nets = tuple(str(ipaddress.IPv4Network(str(v))) for v in values)
        except ValueError as exc:
            raise SigmaError(f"{where}: bad CIDR: {exc}") from exc
        return Match(fm, "cidr", nets, all_)
    if kind == "re":
        for v in values:
            try:
                re.compile(str(v))
            except re.error as exc:
                raise SigmaError(f"{where}: bad regex {v!r}: {exc}") from exc
            if re.search(r"\(\?[=!<]|\\[1-9]", str(v)):
                raise SigmaError(f"{where}: lookaround and backreferences are not portable to RE2 (KQL)")
        return Match(fm, "re", tuple(str(v) for v in values), all_)
    if all(isinstance(v, bool) for v in values):
        return Match(fm, "bool", tuple(values))
    if kind is None and all(isinstance(v, int | float) and not isinstance(v, bool) for v in values):
        return Match(fm, "num", tuple(values))
    if not all(isinstance(v, str) for v in values):
        raise SigmaError(f"{where}: mixed value types {values!r}")
    globs = []
    for v in values:
        g = parse_glob(v)
        if kind in ("contains", "endswith"):
            g = (("star", ""), *g)
        if kind in ("contains", "startswith"):
            g = (*g, ("star", ""))
        if not any(s[0] == "lit" for s in g):
            raise SigmaError(f"{where}: value {v!r} matches everything")
        globs.append(g)
    return Match(fm, "glob", tuple(globs), all_)


def _selection(name: str, body: Any, ls: Logsource, where: str) -> Any:
    w = f"{where}.{name}"
    if isinstance(body, dict):
        items = []
        for key, raw in body.items():
            fname, *mods = key.split("|")
            items.append(_match(ls.field(fname, w), mods, raw, w))
        return And(tuple(items)) if len(items) > 1 else items[0]
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        return Or(tuple(_selection(name, x, ls, where) for x in body))
    raise SigmaError(f"{w}: keyword (full-text) selections are not supported; name the field")


COND_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def parse_condition(text: str, selections: dict[str, Any], where: str) -> tuple[Any, set[str]]:
    if "|" in text:
        raise SigmaError(f"{where}: aggregation conditions ('|') are not supported")
    toks = []
    pos = 0
    while pos < len(text):
        m = COND_TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise SigmaError(f"{where}: cannot parse condition at {text[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
    used: set[str] = set()
    i = 0

    def peek() -> str:
        return toks[i].lower() if i < len(toks) else ""

    def take() -> str:
        nonlocal i
        if i >= len(toks):
            raise SigmaError(f"{where}: condition ends early")
        i += 1
        return toks[i - 1]

    def names(pattern: str) -> list[str]:
        if pattern == "them":
            found = list(selections)
        else:
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            found = [n for n in selections if rx.match(n)]
        if not found:
            raise SigmaError(f"{where}: {pattern!r} matches no selection")
        return found

    def or_expr():
        items = [and_expr()]
        while peek() == "or":
            take()
            items.append(and_expr())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def and_expr():
        items = [not_expr()]
        while peek() == "and":
            take()
            items.append(not_expr())
        return items[0] if len(items) == 1 else And(tuple(items))

    def not_expr():
        if peek() == "not":
            take()
            return Not(not_expr())
        return atom()

    def atom():
        t = take()
        if t == "(":
            inner = or_expr()
            if take() != ")":
                raise SigmaError(f"{where}: missing ')'")
            return inner
        if t.lower() in ("1", "all") and peek() == "of":
            take()
            found = names(take())
            used.update(found)
            parts = tuple(selections[n] for n in found)
            if len(parts) == 1:
                return parts[0]
            return Or(parts) if t == "1" else And(parts)
        if t in ("and", "or", "not", ")"):
            raise SigmaError(f"{where}: unexpected {t!r}")
        if t not in selections:
            raise SigmaError(f"{where}: condition names unknown selection {t!r}")
        used.add(t)
        return selections[t]

    tree = or_expr()
    if i != len(toks):
        raise SigmaError(f"{where}: unexpected {toks[i]!r} in condition")
    return tree, used


# --------------------------------------------------------------------------- rules
@dataclass(frozen=True)
class Rule:
    path: Path
    name: str
    id: str
    title: str
    status: str
    level: str
    tags: tuple[str, ...]
    logsource: Logsource
    tree: Any
    raw: dict[str, Any] = field(repr=False, compare=False)

    @property
    def attack(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d", t)]

    @property
    def atlas(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.startswith("atlas.")]

    @property
    def area(self) -> str:
        return {"ep": "endpoint", "id": "identity", "cl": "cloud", "nw": "network", "dns": "network", "ai": "ai-agent"}[self.name.split("-")[0]]


def parse_rule(path: Path, mapping: Mapping) -> Rule:
    where = path.name
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise SigmaError(f"{where}: not a YAML mapping")
    unknown = set(raw) - RULE_KEYS
    if unknown:
        raise SigmaError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("title", "id", "status", "level", "logsource", "detection"):
        if key not in raw:
            raise SigmaError(f"{where}: missing {key!r}")
    try:
        uuid.UUID(str(raw["id"]))
    except ValueError as exc:
        raise SigmaError(f"{where}: id must be a UUID") from exc
    if raw["status"] not in STATUSES:
        raise SigmaError(f"{where}: status {raw['status']!r} not in {sorted(STATUSES)}")
    if raw["level"] not in LEVELS:
        raise SigmaError(f"{where}: level {raw['level']!r} not in {sorted(LEVELS)}")
    tags = tuple(raw.get("tags", []))
    for t in tags:
        if not TAG.match(t):
            raise SigmaError(f"{where}: tag {t!r} is not attack.* or atlas.aml.*")
    ls = mapping.resolve(dict(raw["logsource"]), where)
    det = dict(raw["detection"])
    cond = det.pop("condition", None)
    if not isinstance(cond, str):
        raise SigmaError(f"{where}: detection needs one condition string")
    sels = {n: _selection(n, body, ls, where) for n, body in det.items()}
    tree, used = parse_condition(cond, sels, where)
    unused = set(sels) - used
    if unused:
        raise SigmaError(f"{where}: selections never used by the condition: {sorted(unused)}")
    return Rule(path, path.stem, str(raw["id"]), raw["title"], raw["status"], raw["level"], tags, ls, tree, raw)


def load_rules(mapping: Mapping | None = None, folder: Path = RULES) -> list[Rule]:
    mapping = mapping or load_mapping()
    rules = [parse_rule(p, mapping) for p in sorted(folder.glob("*.yml"))]
    seen: dict[str, str] = {}
    for r in rules:
        if r.id in seen:
            raise SigmaError(f"{r.path.name}: id also used by {seen[r.id]}")
        seen[r.id] = r.path.name
    return rules


def get_rule(name: str, rules: list[Rule]) -> Rule:
    for r in rules:
        if r.name == name:
            return r
    raise SigmaError(f"no rule named {name!r}; try: aisoc sigma list")


# --------------------------------------------------------------------------- evaluator
def flatten(event: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in event.items():
        p = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, p + "."))
        else:
            out[p] = v
    return out


def _glob_regex(g: Glob) -> str:
    return "".join(re.escape(t) if kind == "lit" else (".*" if kind == "star" else ".") for kind, t in g)


def _test(m: Match, v: Any) -> bool:
    if m.kind == "null":
        return v is None or v == ""
    if v is None:
        return False
    if m.kind == "bool":
        return isinstance(v, bool) and v in m.values
    if m.kind == "num":
        return isinstance(v, int | float) and not isinstance(v, bool) and v in m.values
    if m.kind == "cmp":
        if not isinstance(v, int | float) or isinstance(v, bool):
            return False
        return kql._cmp(m.op, v, m.values[0])
    if m.kind == "cidr":
        hits = [kql._ipv4_in_range(v, n) for n in m.values]
    elif m.kind == "re":
        hits = [re.search(p, str(v)) is not None for p in m.values]
    else:
        hits = [re.fullmatch(_glob_regex(g), str(v), re.I | re.S) is not None for g in m.values]
    return all(hits) if m.all_ else any(hits)


def evaluate(node: Any, flat: dict[str, Any]) -> bool:
    if isinstance(node, Match):
        return _test(node, flat.get(node.field.ocsf))
    if isinstance(node, And):
        return all(evaluate(x, flat) for x in node.items)
    if isinstance(node, Or):
        return any(evaluate(x, flat) for x in node.items)
    if isinstance(node, Not):
        return not evaluate(node.item, flat)
    raise SigmaError(f"unknown node {node!r}")


def matches(rule: Rule, event: dict[str, Any]) -> bool:
    """True when the event comes from the rule's logsource (class and product filter) and the condition holds."""
    flat = flatten(event)
    if flat.get("class_uid") != rule.logsource.class_uid:
        return False
    if any(flat.get(k) != v for k, v in rule.logsource.filter.items()):
        return False
    return evaluate(rule.tree, flat)


# --------------------------------------------------------------------------- SQL backend (SQLite dialect)
def _sq(v: Any) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int | float):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


def _col(path: str) -> str:
    return '"' + path.replace('"', '""') + '"'


def _sql_glob(col: str, g: Glob) -> str:
    if all(k == "lit" for k, _ in g):
        return f"LOWER({col}) = {_sq(''.join(t for _, t in g).lower())}"
    pat = ""
    for kind, t in g:
        if kind == "lit":
            pat += re.sub(r"([\\%_])", r"\\\1", t.lower())
        else:
            pat += "%" if kind == "star" else "_"
    return f"LOWER({col}) LIKE {_sq(pat)} ESCAPE '\\'"


def _sql_match(m: Match) -> str:
    col = _col(m.field.ocsf)
    if m.kind == "null":
        return f"({col} IS NULL OR {col} = '')"
    if m.kind == "cmp":
        return f"({col} IS NOT NULL AND {col} {m.op} {_sq(m.values[0])})"
    if m.kind in ("bool", "num"):
        parts = [f"{col} = {_sq(v)}" for v in m.values]
    elif m.kind == "cidr":
        parts = [f"cidr_match({col}, {_sq(n)})" for n in m.values]
    elif m.kind == "re":
        parts = [f"{col} REGEXP {_sq(p)}" for p in m.values]
    else:
        parts = [_sql_glob(col, g) for g in m.values]
    joined = parts[0] if len(parts) == 1 else "(" + (" AND " if m.all_ else " OR ").join(parts) + ")"
    # IS NOT NULL keeps NOT(...) two-valued, so SQL agrees with the evaluator on missing fields
    return f"({col} IS NOT NULL AND {joined})"


def _sql(node: Any) -> str:
    if isinstance(node, Match):
        return _sql_match(node)
    if isinstance(node, And):
        return "(" + " AND ".join(_sql(x) for x in node.items) + ")"
    if isinstance(node, Or):
        return "(" + " OR ".join(_sql(x) for x in node.items) + ")"
    return f"NOT {_sql(node.item)}"


def to_sql(rule: Rule) -> str:
    ls = rule.logsource
    where = [f"{_col('class_uid')} = {ls.class_uid}"] + [f"{_col(k)} = {_sq(v)}" for k, v in ls.filter.items()]
    return f"-- {rule.title}\nSELECT {_col('metadata.uid')}\nFROM {ls.sql_table}\nWHERE " + "\n  AND ".join(where) + f"\n  AND {_sql(rule.tree)}"


def sqlite_db(events: list[dict[str, Any]], mapping: Mapping) -> sqlite3.Connection:
    """In-memory SQLite with one table per OCSF table, a REGEXP function and cidr_match()."""
    db = sqlite3.connect(":memory:")
    db.create_function("REGEXP", 2, lambda p, v: v is not None and re.search(p, str(v)) is not None, deterministic=True)
    db.create_function("cidr_match", 2, kql._ipv4_in_range, deterministic=True)
    by_class = {ls.class_uid: ls.sql_table for ls in mapping.logsources}
    for table in mapping.tables():
        cols = mapping.table_columns(table)
        db.execute(f"CREATE TABLE {table} ({', '.join(_col(c) for c in cols)})")
        for e in events:
            flat = flatten(e)
            if by_class.get(flat.get("class_uid")) == table:
                db.execute(f"INSERT INTO {table} VALUES ({', '.join('?' * len(cols))})", [flat.get(c) for c in cols])
    return db


def run_sql(rule: Rule, db: sqlite3.Connection) -> set[str]:
    return {r[0] for r in db.execute(to_sql(rule))}


# --------------------------------------------------------------------------- KQL backend
def _kq(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return repr(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kql_glob(col: str, g: Glob) -> str:
    if all(k == "lit" for k, _ in g):
        return f"{col} =~ {_kq(''.join(t for _, t in g))}"
    if len(g) == 3 and g[0][0] == "star" and g[1][0] == "lit" and g[2][0] == "star":
        return f"{col} contains {_kq(g[1][1])}"
    if len(g) == 2 and g[0][0] == "lit" and g[1][0] == "star":
        return f"{col} startswith {_kq(g[0][1])}"
    if len(g) == 2 and g[0][0] == "star" and g[1][0] == "lit":
        return f"{col} endswith {_kq(g[1][1])}"
    return f"{col} matches regex {_kq('(?is)^' + _glob_regex(g) + '$')}"


def _kql_match(m: Match) -> str:
    col = kql_column(m.field.ocsf)
    if m.kind == "null":
        return f"isempty({col})"
    if m.kind == "cmp":
        return f"(isnotempty({col}) and {col} {m.op} {_kq(m.values[0])})"
    if m.kind in ("bool", "num"):
        parts = [f"{col} == {_kq(v)}" for v in m.values]
    elif m.kind == "cidr":
        parts = [f"ipv4_is_in_range({col}, {_kq(n)})" for n in m.values]
    elif m.kind == "re":
        parts = [f"{col} matches regex {_kq(p)}" for p in m.values]
    elif not m.all_ and len(m.values) > 1 and all(all(k == "lit" for k, _ in g) for g in m.values):
        return f"{col} in~ ({', '.join(_kq(g[0][1]) for g in m.values)})"
    else:
        parts = [_kql_glob(col, g) for g in m.values]
    joined = parts[0] if len(parts) == 1 else "(" + (" and " if m.all_ else " or ").join(parts) + ")"
    if m.kind in ("cidr", "re"):
        return f"(isnotempty({col}) and {joined})"
    return joined


def _kql(node: Any) -> str:
    if isinstance(node, Match):
        return _kql_match(node)
    if isinstance(node, And):
        return "(" + " and ".join(_kql(x) for x in node.items) + ")"
    if isinstance(node, Or):
        return "(" + " or ".join(_kql(x) for x in node.items) + ")"
    return f"not({_kql(node.item)})"


def to_kql(rule: Rule) -> str:
    ls = rule.logsource
    pre = [f"class_uid == {ls.class_uid}"] + [f"{kql_column(k)} == {_kq(v)}" for k, v in ls.filter.items()]
    return f"// {rule.title}\n{ls.kql_table}\n| where " + " and ".join(pre) + f"\n| where {_kql(rule.tree)}\n| project metadata_uid"


def kql_tables(events: list[dict[str, Any]], mapping: Mapping) -> dict[str, list[dict[str, Any]]]:
    by_class = {ls.class_uid: ls.kql_table for ls in mapping.logsources}
    tables: dict[str, list[dict[str, Any]]] = {ls.kql_table: [] for ls in mapping.logsources}
    for e in events:
        flat = flatten(e)
        if flat.get("class_uid") in by_class:
            tables[by_class[flat["class_uid"]]].append({kql_column(k): v for k, v in flat.items()})
    return tables


KQL_NOW = datetime(2000, 1, 1, tzinfo=UTC)  # the queries use no time functions; run() needs an anchor


def run_kql(rule: Rule, tables: dict[str, list[dict[str, Any]]]) -> set[str]:
    return {r["metadata_uid"] for r in kql.run(to_kql(rule), tables, KQL_NOW)}


# --------------------------------------------------------------------------- fixtures
@dataclass(frozen=True)
class Fixture:
    rule: str
    uid: str
    expect: bool
    note: str
    event: dict[str, Any]


def load_fixtures(mapping: Mapping, rules: list[Rule], folder: Path = FIXTURES) -> list[Fixture]:
    names = {r.name: r for r in rules}
    out: list[Fixture] = []
    seen: set[str] = set()
    for p in sorted(folder.glob("*.yaml")):
        raw = yaml.safe_load(p.read_text())
        if raw.get("rule") != p.stem or p.stem not in names:
            raise SigmaError(f"{p.name}: 'rule' must name an existing rule and match the file name")
        rule = names[p.stem]
        for i, item in enumerate(raw["events"]):
            where = f"{p.name}[{i}]"
            if item.get("expect") not in ("match", "no_match"):
                raise SigmaError(f"{where}: expect must be match or no_match")
            ev = item["event"]
            flat = flatten(ev)
            uid = flat.get("metadata.uid")
            if not uid or uid in seen:
                raise SigmaError(f"{where}: metadata.uid missing or repeated")
            seen.add(uid)
            cls = flat.get("class_uid")
            if cls != rule.logsource.class_uid:
                raise SigmaError(f"{where}: class_uid {cls} but the rule reads class {rule.logsource.class_uid}")
            extra = set(flat) - mapping.class_paths(cls)
            if extra:
                raise SigmaMappingError(f"{where}: OCSF paths not declared for class {cls}: {sorted(extra)}")
            out.append(Fixture(p.stem, uid, item["expect"] == "match", item.get("note", ""), ev))
    for r in rules:
        kinds = {f.expect for f in out if f.rule == r.name}
        if kinds != {True, False}:
            raise SigmaError(f"{r.name}: needs at least one positive and one negative fixture")
    return out


@dataclass(frozen=True)
class RuleResult:
    rule: Rule
    positives: int
    negatives: int
    failures: tuple[str, ...]
    evaluator: frozenset[str]
    sql: frozenset[str]
    kql: frozenset[str]

    @property
    def parity(self) -> bool:
        return self.evaluator == self.sql == self.kql

    @property
    def ok(self) -> bool:
        return not self.failures and self.parity


def check_all(rules: list[Rule] | None = None, mapping: Mapping | None = None) -> list[RuleResult]:
    """Run every rule over every fixture event with all three engines."""
    mapping = mapping or load_mapping()
    rules = rules if rules is not None else load_rules(mapping)
    fixtures = load_fixtures(mapping, rules)
    events = [f.event for f in fixtures]
    db = sqlite_db(events, mapping)
    tables = kql_tables(events, mapping)
    out = []
    for r in rules:
        own = [f for f in fixtures if f.rule == r.name]
        fails = tuple(f"{f.uid}: expected {'match' if f.expect else 'no match'}" for f in own if matches(r, f.event) != f.expect)
        ev = frozenset(f.uid for f in fixtures if matches(r, f.event))
        out.append(
            RuleResult(
                r, sum(f.expect for f in own), sum(not f.expect for f in own), fails, ev, frozenset(run_sql(r, db)), frozenset(run_kql(r, tables))
            )
        )
    return out
