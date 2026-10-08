"""A small, pure-Python interpreter for the subset of KQL this repository's queries use.

The same `.kql` files feed the Sentinel analytics rules in infra/ and run here over the synthetic tables.
They stay inside real KQL syntax, so they should also run in the Kusto emulator against tables with these
columns; that cross-check is planned, not done (docs/components/kql-engine.md). The subset is
deliberately small; anything outside it raises `KqlError` instead of guessing.

Supported:
  let Name = <scalar | dynamic([...])>;
  Table | where <expr> | project a, b = expr | extend x = expr | summarize agg(...) [, ...] [by k, bin(T, 1h)]
        | order by / sort by x [asc|desc] | top N by x [asc|desc] | take N | limit N | distinct a, b | count
        | join kind=inner ( <query> ) on Col[, Col]  |  on $left.A == $right.B
  operators: and or not == != =~ !~ < <= > >= + - * /  has !has contains !contains startswith endswith has_any in !in in~ !in~
  functions: ago now bin tolower toupper strlen isempty isnotempty tostring toint todouble iff strcat array_length startofday
             parse_url (with .Host / .Path member access)
  aggregates: count countif dcount sum min max avg make_set take_any
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

Row = dict[str, Any]
Env = dict[str, Any]


class KqlError(ValueError):
    pass


# --------------------------------------------------------------------------- tokens
TOKEN = re.compile(
    r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<span>\d+(?:\.\d+)?(?:ms|d|h|m|s)\b)
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<op>==|!=|=~|!~|<=|>=|!in~|in~|!has_any\b|!has\b|!contains\b|!startswith\b|!endswith\b|!in\b|[|(),;=<>+\-*/.\[\]!])
  | (?P<id>\$?[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.X,
)
SPAN = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass(frozen=True)
class Tok:
    kind: str
    value: str


def tokenize(text: str) -> list[Tok]:
    out, i = [], 0
    while i < len(text):
        m = TOKEN.match(text, i)
        if not m:
            raise KqlError(f"unexpected character at {i}: {text[i : i + 20]!r}")
        i = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        out.append(Tok(kind, m.group()))
    out.append(Tok("eof", ""))
    return out


def _span(tok: str) -> timedelta:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|d|h|m|s)", tok)
    assert m
    return timedelta(seconds=float(m.group(1)) * SPAN[m.group(2)])


# --------------------------------------------------------------------------- expressions
Expr = Callable[[Row, Env], Any]


def _term(value: Any, term: str) -> bool:
    if value is None:
        return False
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", str(value), re.I) is not None


def _cmp(op: str, a: Any, b: Any) -> bool:
    if op in ("==", "!="):
        eq = a == b
        return eq if op == "==" else not eq
    if op in ("=~", "!~"):
        eq = a is not None and b is not None and str(a).lower() == str(b).lower()
        return eq if op == "=~" else not eq
    if a is None or b is None:
        return False
    try:
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    except TypeError as exc:
        raise KqlError(f"cannot compare {type(a).__name__} {op} {type(b).__name__}") from exc


def _bin(v: Any, size: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, datetime):
        assert isinstance(size, timedelta)
        epoch = datetime(1970, 1, 1, tzinfo=v.tzinfo)
        secs = (v - epoch).total_seconds()
        step = size.total_seconds()
        return epoch + timedelta(seconds=secs - secs % step)
    return v - v % size


FUNCS: dict[str, Callable[..., Any]] = {
    "tolower": lambda s: None if s is None else str(s).lower(),
    "toupper": lambda s: None if s is None else str(s).upper(),
    "strlen": lambda s: 0 if s is None else len(str(s)),
    "isempty": lambda s: s is None or s == "" or s == [],
    "isnotempty": lambda s: not (s is None or s == "" or s == []),
    "tostring": lambda s: "" if s is None else str(s),
    "toint": lambda s: None if s in (None, "") else int(float(s)),
    "todouble": lambda s: None if s in (None, "") else float(s),
    "iff": lambda c, a, b: a if c else b,
    "strcat": lambda *xs: "".join("" if x is None else str(x) for x in xs),
    "array_length": lambda xs: len(xs) if isinstance(xs, list) else None,
    "bin": _bin,
    "startofday": lambda t: _bin(t, timedelta(days=1)),
    "parse_url": lambda u: _parse_url(u),
}
AGGS = {"count", "countif", "dcount", "sum", "min", "max", "avg", "make_set", "take_any"}


class Parser:
    def __init__(self, text: str) -> None:
        self.toks = tokenize(text)
        self.i = 0
        self.lets: dict[str, Expr] = {}

    # -- token helpers
    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def at(self, *values: str) -> bool:
        return self.tok.value.lower() in values and self.tok.kind in ("op", "id")

    def expect(self, value: str) -> Tok:
        if self.tok.value.lower() != value:
            raise KqlError(f"expected {value!r}, found {self.tok.value!r}")
        return self.next()

    def ident(self) -> str:
        if self.tok.kind != "id":
            raise KqlError(f"expected a name, found {self.tok.value!r}")
        return self.next().value

    # -- query
    def query(self) -> Callable[[dict[str, list[Row]], Env], list[Row]]:
        while self.at("let"):
            self.next()
            name = self.ident()
            self.expect("=")
            self.lets[name] = self.expr()
            self.expect(";")
        q = self.pipeline()
        if self.tok.kind != "eof":
            raise KqlError(f"unexpected {self.tok.value!r} after query")
        return q

    def pipeline(self):
        if self.at("("):
            self.next()
            src = self.pipeline()
            self.expect(")")
        else:
            table = self.ident()

            def src(tables, env, table=table):
                if table not in tables:
                    raise KqlError(f"unknown table {table!r}")
                return list(tables[table])

        stages = []
        while self.at("|"):
            self.next()
            stages.append(self.stage())

        def run(tables, env):
            rows = src(tables, env)
            for st in stages:
                rows = st(rows, tables, env)
            return rows

        return run

    def stage(self):
        kw = self.ident().lower()
        if kw == "where":
            pred = self.expr()
            return lambda rows, t, env: [r for r in rows if pred(r, env)]
        if kw in ("project", "extend"):
            items = self.assignments(allow_bare=kw == "project")
            if kw == "project":
                return lambda rows, t, env: [{n: f(r, env) for n, f in items} for r in rows]
            return lambda rows, t, env: [{**r, **{n: f(r, env) for n, f in items}} for r in rows]
        if kw == "summarize":
            return self.summarize()
        if kw in ("order", "sort"):
            self.expect("by")
            keys = self.sort_keys()
            return lambda rows, t, env: _sorted(rows, keys, env)
        if kw == "top":
            n = int(self.next().value)
            self.expect("by")
            keys = self.sort_keys()
            return lambda rows, t, env: _sorted(rows, keys, env)[:n]
        if kw in ("take", "limit"):
            n = int(self.next().value)
            return lambda rows, t, env: rows[:n]
        if kw == "distinct":
            cols = [self.ident()]
            while self.at(","):
                self.next()
                cols.append(self.ident())

            def distinct(rows, t, env):
                seen, out = set(), []
                for r in rows:
                    k = tuple(_hashable(r.get(c)) for c in cols)
                    if k not in seen:
                        seen.add(k)
                        out.append({c: r.get(c) for c in cols})
                return out

            return distinct
        if kw == "count":
            return lambda rows, t, env: [{"Count": len(rows)}]
        if kw == "join":
            return self.join()
        raise KqlError(f"unsupported operator {kw!r}")

    def assignments(self, allow_bare: bool) -> list[tuple[str, Expr]]:
        items = []
        while True:
            if self.tok.kind == "id" and self.peek().value == "=":
                name = self.next().value
                self.next()
                items.append((name, self.expr()))
            elif allow_bare:
                name = self.ident()
                items.append((name, lambda r, env, n=name: r.get(n)))
            else:
                raise KqlError("extend needs name = expression")
            if not self.at(","):
                return items
            self.next()

    def sort_keys(self):
        keys = []
        while True:
            e = self.expr()
            desc = True  # KQL sorts descending by default
            if self.at("asc", "desc"):
                desc = self.next().value.lower() == "desc"
            keys.append((e, desc))
            if not self.at(","):
                return keys
            self.next()

    def summarize(self):
        aggs = []
        while True:
            alias = None
            if self.tok.kind == "id" and self.peek().value == "=":
                alias = self.next().value
                self.next()
            fn = self.ident().lower()
            if fn not in AGGS:
                raise KqlError(f"unsupported aggregate {fn!r}")
            self.expect("(")
            args = []
            if not self.at(")"):
                args.append(self.expr())
                while self.at(","):
                    self.next()
                    args.append(self.expr())
            self.expect(")")
            default = {"count": "count_", "countif": "countif_"}.get(fn, f"{ {'make_set': 'set', 'take_any': 'any'}.get(fn, fn) }_")
            aggs.append((alias or default, fn, args))
            if not self.at(","):
                break
            self.next()
        keys: list[tuple[str, Expr]] = []
        if self.at("by"):
            self.next()
            while True:
                start = self.i
                if self.tok.kind == "id" and self.peek().value == "=":
                    name = self.next().value
                    self.next()
                    keys.append((name, self.expr()))
                else:
                    e = self.expr()
                    toks = self.toks[start : self.i]
                    name = next((t.value for t in toks if t.kind == "id" and t.value.lower() not in FUNCS), f"Column{len(keys) + 1}")
                    keys.append((name, e))
                if not self.at(","):
                    break
                self.next()

        def run(rows, t, env):
            groups: dict[tuple, list[Row]] = {}
            keyvals: dict[tuple, list[Any]] = {}
            for r in rows:
                vals = [f(r, env) for _, f in keys]
                k = tuple(_hashable(v) for v in vals)
                groups.setdefault(k, []).append(r)
                keyvals.setdefault(k, vals)
            if not keys and not groups:
                groups[()] = []
                keyvals[()] = []
            out = []
            for k, members in groups.items():
                row = {n: v for (n, _), v in zip(keys, keyvals[k], strict=True)}
                for name, fn, args in aggs:
                    row[name] = _aggregate(fn, args, members, env)
                out.append(row)
            return out

        return run

    def join(self):
        kind = "inner"
        if self.at("kind"):
            self.next()
            self.expect("=")
            kind = self.ident().lower()
        if kind != "inner":
            raise KqlError("only join kind=inner is supported")
        self.expect("(")
        right = self.pipeline()
        self.expect(")")
        self.expect("on")
        pairs: list[tuple[str, str]] = []
        while True:
            if self.tok.value.lower() == "$left":
                self.next()
                self.expect(".")
                lcol = self.ident()
                self.expect("==")
                if self.next().value.lower() != "$right":
                    raise KqlError("expected $right")
                self.expect(".")
                pairs.append((lcol, self.ident()))
            else:
                c = self.ident()
                pairs.append((c, c))
            if not self.at(","):
                break
            self.next()

        def run(rows, tables, env):
            rrows = right(tables, env)
            index: dict[tuple, list[Row]] = {}
            for rr in rrows:
                index.setdefault(tuple(_hashable(rr.get(b)) for _, b in pairs), []).append(rr)
            out = []
            for lr in rows:
                for rr in index.get(tuple(_hashable(lr.get(a)) for a, _ in pairs), []):
                    merged = dict(lr)
                    for k, v in rr.items():
                        merged[k + "1" if k in merged else k] = v
                    out.append(merged)
            return out

        return run

    # -- expressions (precedence climbing)
    def expr(self) -> Expr:
        left = self.and_expr()
        while self.at("or"):
            self.next()
            right, prev = self.and_expr(), left
            left = lambda r, e, a=prev, b=right: bool(a(r, e)) or bool(b(r, e))  # noqa: E731
        return left

    def and_expr(self) -> Expr:
        left = self.not_expr()
        while self.at("and"):
            self.next()
            right, prev = self.not_expr(), left
            left = lambda r, e, a=prev, b=right: bool(a(r, e)) and bool(b(r, e))  # noqa: E731
        return left

    def not_expr(self) -> Expr:
        if self.at("not") and self.peek().value == "(":
            self.next()
            inner = self.primary()
            return lambda r, e: not inner(r, e)
        return self.comparison()

    def comparison(self) -> Expr:
        left = self.additive()
        op = self.tok.value.lower()
        if op in ("==", "!=", "=~", "!~", "<", "<=", ">", ">="):
            self.next()
            right = self.additive()
            return lambda r, e: _cmp(op, left(r, e), right(r, e))
        if op in ("has", "!has", "contains", "!contains", "startswith", "!startswith", "endswith", "!endswith"):
            self.next()
            right = self.additive()
            neg = op.startswith("!")
            base = op.lstrip("!")

            def test(r, e):
                a, b = left(r, e), right(r, e)
                if base == "has":
                    res = _term(a, str(b))
                elif a is None:
                    res = False
                elif base == "contains":
                    res = str(b).lower() in str(a).lower()
                elif base == "startswith":
                    res = str(a).lower().startswith(str(b).lower())
                else:
                    res = str(a).lower().endswith(str(b).lower())
                return not res if neg else res

            return test
        if op in ("in~", "!in~"):
            self.next()
            items = self.list_operand()
            neg = op.startswith("!")

            def in_ci(r, e):
                v = left(r, e)
                hit = v is not None and str(v).lower() in {str(x).lower() for x in items(r, e)}
                return not hit if neg else hit

            return in_ci
        if op in ("has_any", "!has_any", "in", "!in"):
            self.next()
            items = self.list_operand()
            neg = op.startswith("!")
            if op.lstrip("!") == "has_any":
                return lambda r, e: (
                    (not any(_term(left(r, e), str(x)) for x in items(r, e))) if neg else any(_term(left(r, e), str(x)) for x in items(r, e))
                )
            return lambda r, e: (left(r, e) not in items(r, e)) if neg else (left(r, e) in items(r, e))
        return left

    def list_operand(self) -> Expr:
        if self.at("("):
            self.next()
            vals = [self.expr()]
            while self.at(","):
                self.next()
                vals.append(self.expr())
            self.expect(")")
            if len(vals) == 1:
                one = vals[0]
                return lambda r, e: (lambda v: v if isinstance(v, list) else [v])(one(r, e))
            return lambda r, e: [v(r, e) for v in vals]
        e = self.primary()
        return lambda r, env: list(e(r, env) or [])

    def additive(self) -> Expr:
        left = self.multiplicative()
        while self.at("+", "-"):
            op = self.next().value
            right, prev = self.multiplicative(), left
            left = (lambda r, e, a=prev, b=right: a(r, e) + b(r, e)) if op == "+" else (lambda r, e, a=prev, b=right: a(r, e) - b(r, e))
        return left

    def multiplicative(self) -> Expr:
        left = self.unary()
        while self.at("*", "/"):
            op = self.next().value
            right, prev = self.unary(), left
            left = (lambda r, e, a=prev, b=right: a(r, e) * b(r, e)) if op == "*" else (lambda r, e, a=prev, b=right: a(r, e) / b(r, e))
        return left

    def unary(self) -> Expr:
        if self.at("-"):
            self.next()
            inner = self.unary()
            return lambda r, e: -inner(r, e)
        return self.primary()

    def primary(self) -> Expr:
        e = self.atom()
        while self.at(".") and self.peek().kind == "id":
            self.next()
            prop, inner = self.next().value, e
            e = lambda r, env, p=prop, f=inner: (f(r, env) or {}).get(p) if isinstance(f(r, env), dict) else None  # noqa: E731
        return e

    def atom(self) -> Expr:
        t = self.next()
        if t.kind == "str":
            v = bytes(t.value[1:-1], "utf-8").decode("unicode_escape")
            return lambda r, e: v
        if t.kind == "num":
            n = float(t.value) if "." in t.value else int(t.value)
            return lambda r, e: n
        if t.kind == "span":
            s = _span(t.value)
            return lambda r, e: s
        if t.value == "(":
            inner = self.expr()
            self.expect(")")
            return inner
        if t.kind != "id":
            raise KqlError(f"unexpected {t.value!r}")
        name = t.value
        low = name.lower()
        if low in ("true", "false"):
            b = low == "true"
            return lambda r, e: b
        if self.at("("):
            self.next()
            if low == "dynamic":
                self.expect("[")
                vals = []
                if not self.at("]"):
                    vals.append(self.expr())
                    while self.at(","):
                        self.next()
                        vals.append(self.expr())
                self.expect("]")
                self.expect(")")
                return lambda r, e: [v(r, e) for v in vals]
            args = []
            if not self.at(")"):
                args.append(self.expr())
                while self.at(","):
                    self.next()
                    args.append(self.expr())
            self.expect(")")
            if low == "ago":
                return lambda r, e: e["now"] - args[0](r, e)
            if low == "now":
                return lambda r, e: e["now"]
            if low not in FUNCS:
                raise KqlError(f"unsupported function {name!r}")
            fn = FUNCS[low]
            return lambda r, e: fn(*(a(r, e) for a in args))
        if name in self.lets:
            let = self.lets[name]
            return lambda r, e: let(r, e)
        return lambda r, e: r.get(name)


def _parse_url(u: Any) -> dict[str, Any]:
    from urllib.parse import urlsplit

    if not u:
        return {}
    p = urlsplit(str(u))
    return {"Scheme": p.scheme, "Host": p.hostname or "", "Path": p.path, "Port": str(p.port or "")}


def _hashable(v: Any) -> Any:
    return tuple(v) if isinstance(v, list) else v


def _sorted(rows: list[Row], keys, env) -> list[Row]:
    out = list(rows)
    for e, desc in reversed(keys):
        out.sort(key=lambda r: (e(r, env) is None, e(r, env)), reverse=desc)
    return out


def _aggregate(fn: str, args: list[Expr], rows: list[Row], env: Env) -> Any:
    if fn == "count":
        return len(rows)
    if fn == "countif":
        return sum(1 for r in rows if args[0](r, env))
    vals = [args[0](r, env) for r in rows]
    present = [v for v in vals if v is not None]
    if fn == "dcount":
        return len({_hashable(v) for v in present})
    if fn == "sum":
        return round(sum(present), 6) if present else 0
    if fn == "min":
        return min(present) if present else None
    if fn == "max":
        return max(present) if present else None
    if fn == "avg":
        return sum(present) / len(present) if present else None
    if fn == "make_set":
        seen: list[Any] = []
        for v in present:
            for x in v if isinstance(v, list) else [v]:
                if x not in seen:
                    seen.append(x)
        return seen
    if fn == "take_any":
        return present[0] if present else None
    raise KqlError(fn)


def compile_query(text: str):
    return Parser(text).query()


def run(text: str, tables: dict[str, Iterable[Row]], now: datetime) -> list[Row]:
    """Run one KQL query over in-memory tables. `now` anchors ago() so results are reproducible."""
    return compile_query(text)({k: list(v) for k, v in tables.items()}, {"now": now})
