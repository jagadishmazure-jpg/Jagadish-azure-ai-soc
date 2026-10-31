"""Sigma detection-as-code: the curated rules, the Sigma -> OCSF mapping, fixtures, and SQL / KQL parity."""

import copy
import sqlite3
import uuid

import pytest
import yaml

from aisoc import sigma
from aisoc.cli import gate_checks, main
from aisoc.sigma import SigmaError, SigmaMappingError

MAPPING = sigma.load_mapping()
RULES = sigma.load_rules(MAPPING)
RESULTS = {r.rule.name: r for r in sigma.check_all(RULES, MAPPING)}
PROC = {"product": "windows", "category": "process_creation"}


def make_rule(tmp_path, detection, logsource=None, **extra):
    body = {
        "title": "test rule",
        "id": str(uuid.uuid4()),
        "status": "test",
        "level": "low",
        "logsource": logsource or PROC,
        "detection": detection,
        **extra,
    }
    p = tmp_path / f"t-{uuid.uuid4().hex[:6]}.yml"
    p.write_text(yaml.safe_dump(body))
    return sigma.parse_rule(p, MAPPING)


def proc_event(uid, **paths):
    e = {"class_uid": 1007, "activity_id": 1, "metadata": {"uid": uid, "product": {"name": "Sysmon"}}}
    for path, v in paths.items():
        node = e
        *head, last = path.split("__")
        for k in head:
            node = node.setdefault(k, {})
        node[last] = v
    return e


def three_engines(rule, events):
    """Ids matched by the evaluator, by SQLite running the SQL, and by the KQL engine running the KQL."""
    ev = {e["metadata"]["uid"] for e in events if sigma.matches(rule, e)}
    sql = sigma.run_sql(rule, sigma.sqlite_db(events, MAPPING))
    kq = sigma.run_kql(rule, sigma.kql_tables(events, MAPPING))
    return ev, sql, kq


# --------------------------------------------------------------------------- the curated rule set
def test_rule_set_covers_every_area():
    areas = {r.area for r in RULES}
    assert areas == {"endpoint", "identity", "cloud", "network", "ai-agent"}
    assert len(RULES) >= 15


def test_every_rule_is_tagged_and_unique():
    assert len({r.id for r in RULES}) == len(RULES)
    assert len({r.title for r in RULES}) == len(RULES)
    for r in RULES:
        assert r.attack or r.atlas, r.name
        assert r.raw.get("falsepositives"), f"{r.name} should say what else fires it"


def test_ai_agent_rules_carry_atlas_tags():
    for r in RULES:
        if r.area == "ai-agent":
            assert r.atlas, r.name


@pytest.mark.parametrize("name", sorted(RESULTS))
def test_rule_passes_its_fixtures(name):
    res = RESULTS[name]
    assert res.positives >= 1 and res.negatives >= 1
    assert not res.failures, res.failures


@pytest.mark.parametrize("name", sorted(RESULTS))
def test_evaluator_sql_and_kql_agree_over_all_fixtures(name):
    res = RESULTS[name]
    assert res.evaluator == res.sql == res.kql
    assert res.evaluator, "every rule should hit at least its own positives"


def test_no_rule_fires_on_another_rules_fixture_by_accident():
    fixtures = sigma.load_fixtures(MAPPING, RULES)
    own = {f.uid: f.rule for f in fixtures}
    for name, res in RESULTS.items():
        assert {own[u] for u in res.evaluator} == {name}, name


def test_every_logsource_in_the_mapping_is_used():
    assert {r.logsource.name for r in RULES} == {ls.name for ls in MAPPING.logsources}


def test_extension_fields_are_marked_and_namespaced():
    for ls in MAPPING.logsources:
        for f in ls.fields.values():
            assert f.core == (not f.ocsf.startswith("unmapped.")), (ls.name, f.sigma)


def test_shared_class_tables_are_split_by_product_filter():
    api = [ls for ls in MAPPING.logsources if ls.class_uid == 6003]
    assert len(api) == 2 and len({ls.sql_table for ls in api}) == 1
    assert len({ls.filter["metadata.product.name"] for ls in api}) == 2


# --------------------------------------------------------------------------- fail loudly
@pytest.mark.parametrize(
    "detection,logsource,err,msg",
    [
        ({"s": {"NoSuchField": "x"}, "condition": "s"}, None, SigmaMappingError, "no OCSF mapping"),
        ({"s": {"Image": "x"}, "condition": "s"}, {"product": "linux", "category": "auditd"}, SigmaMappingError, "logsource"),
        ({"s": {"Image|base64": "x"}, "condition": "s"}, None, SigmaError, "unsupported modifier"),
        ({"s": {"Image|contains|endswith": "x"}, "condition": "s"}, None, SigmaError, "one value modifier"),
        ({"s": ["mimikatz"], "condition": "s"}, None, SigmaError, "keyword"),
        ({"s": {"Image": "x"}, "condition": "s | count() > 5"}, None, SigmaError, "aggregation"),
        ({"s": {"Image": "x"}, "condition": "s and other"}, None, SigmaError, "unknown selection"),
        ({"s": {"Image": "x"}, "t": {"Image": "y"}, "condition": "s"}, None, SigmaError, "never used"),
        ({"s": {"Image": "x"}, "condition": "1 of nope_*"}, None, SigmaError, "matches no selection"),
        ({"s": {"Image": "x"}, "condition": "(s"}, None, SigmaError, "condition"),
        ({"s": {"CommandLine|re": "(unclosed"}, "condition": "s"}, None, SigmaError, "bad regex"),
        ({"s": {"CommandLine|re": "a(?=b)"}, "condition": "s"}, None, SigmaError, "RE2"),
        ({"s": {"CommandLine|contains|all": "only-one"}, "condition": "s"}, None, SigmaError, "two or more"),
        ({"s": {"CommandLine|contains": None}, "condition": "s"}, None, SigmaError, "null"),
        ({"s": {"CommandLine": "*"}, "condition": "s"}, None, SigmaError, "matches everything"),
        ({"s": {"ProcessId|gte": "10"}, "condition": "s"}, None, SigmaError, "one number"),
        ({"s": {"Image|cidr": "10.0.0.0/33"}, "condition": "s"}, None, SigmaError, "CIDR"),
    ],
)
def test_bad_rules_fail_loudly(tmp_path, detection, logsource, err, msg):
    with pytest.raises(err, match=msg):
        make_rule(tmp_path, detection, logsource)


def test_value_map_rejects_unknown_values_and_modifiers(tmp_path):
    ls = {"product": "azure", "service": "signinlogs"}
    with pytest.raises(SigmaMappingError, match="no OCSF value"):
        make_rule(tmp_path, {"s": {"AuthenticationRequirement": "passwordless"}, "condition": "s"}, ls)
    with pytest.raises(SigmaMappingError, match="plain equality"):
        make_rule(tmp_path, {"s": {"AuthenticationRequirement|contains": "single"}, "condition": "s"}, ls)


@pytest.mark.parametrize(
    "extra,msg",
    [({"id": "rule-1"}, "UUID"), ({"level": "urgent"}, "level"), ({"tags": ["mitre.t1059"]}, "tag"), ({"custom": 1}, "unknown keys")],
)
def test_bad_metadata_fails(tmp_path, extra, msg):
    with pytest.raises(SigmaError, match=msg):
        make_rule(tmp_path, {"s": {"Image": "x"}, "condition": "s"}, **extra)


def test_missing_condition_fails(tmp_path):
    with pytest.raises(SigmaError, match="condition"):
        make_rule(tmp_path, {"s": {"Image": "x"}})


def _fixture_dir(tmp_path, events):
    d = tmp_path / "fx"
    d.mkdir()
    rule = RULES[0]
    (d / f"{rule.name}.yaml").write_text(yaml.safe_dump({"rule": rule.name, "events": events}))
    return d, rule


def test_fixture_with_an_undeclared_ocsf_path_fails(tmp_path):
    good = sigma.load_fixtures(MAPPING, RULES)
    pos = next(f for f in good if f.rule == RULES[0].name and f.expect)
    bad = copy.deepcopy(pos.event)
    bad["api"]["operaton"] = "typo"
    d, rule = _fixture_dir(tmp_path, [{"expect": "match", "event": bad}])
    with pytest.raises(SigmaMappingError, match=r"api\.operaton"):
        sigma.load_fixtures(MAPPING, [rule], d)


def test_fixture_with_the_wrong_class_or_a_repeated_uid_fails(tmp_path):
    d, rule = _fixture_dir(tmp_path, [{"expect": "match", "event": proc_event("x1")}])
    with pytest.raises(SigmaError, match="class_uid"):
        sigma.load_fixtures(MAPPING, [rule], d)
    pos = next(f for f in sigma.load_fixtures(MAPPING, RULES) if f.rule == rule.name and f.expect)
    d2 = tmp_path / "again"
    d2.mkdir()
    (d2 / f"{rule.name}.yaml").write_text(yaml.safe_dump({"rule": rule.name, "events": [{"expect": "match", "event": pos.event}] * 2}))
    with pytest.raises(SigmaError, match="repeated"):
        sigma.load_fixtures(MAPPING, [rule], d2)


def test_rule_without_a_negative_fixture_fails(tmp_path):
    pos = next(f for f in sigma.load_fixtures(MAPPING, RULES) if f.rule == RULES[0].name and f.expect)
    d, rule = _fixture_dir(tmp_path, [{"expect": "match", "event": pos.event}])
    with pytest.raises(SigmaError, match="positive and one negative"):
        sigma.load_fixtures(MAPPING, [rule], d)


def test_kql_column_collision_is_caught(tmp_path):
    raw = yaml.safe_load(sigma.MAPPING.read_text())
    raw["logsources"][0]["fields"]["Clash"] = {"ocsf": "process_file.path"}
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(raw))
    with pytest.raises(SigmaMappingError, match="collide"):
        sigma.load_mapping(p)


def test_non_core_field_must_be_under_unmapped(tmp_path):
    raw = yaml.safe_load(sigma.MAPPING.read_text())
    raw["logsources"][0]["fields"]["Odd"] = {"ocsf": "process.odd", "core": False}
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(raw))
    with pytest.raises(SigmaMappingError, match="unmapped"):
        sigma.load_mapping(p)


# --------------------------------------------------------------------------- semantics
def test_glob_parsing_keeps_windows_backslashes_and_honours_escapes():
    assert sigma.parse_glob("C:\\Windows\\x.exe") == (("lit", "C:\\Windows\\x.exe"),)
    assert sigma.parse_glob("a\\*b") == (("lit", "a*b"),)
    assert sigma.parse_glob("a*b?") == (("lit", "a"), ("star", ""), ("lit", "b"), ("one", ""))


def test_bare_star_in_a_value_is_a_wildcard(tmp_path):
    """The cl-nsg-mgmt-port-open bug: '"src":"*"' matches any source unless the star is escaped."""
    events = [proc_event("w1", process__cmd_line='"src":"10.0.0.0/8"'), proc_event("w2", process__cmd_line='"src":"*"')]
    loose = make_rule(tmp_path, {"s": {"CommandLine|contains": '"src":"*"'}, "condition": "s"})
    strict = make_rule(tmp_path, {"s": {"CommandLine|contains": '"src":"\\*"'}, "condition": "s"})
    assert three_engines(loose, events) == ({"w1", "w2"},) * 3
    assert three_engines(strict, events) == ({"w2"},) * 3


@pytest.mark.parametrize(
    "detection,expected",
    [
        ({"s": {"Image|endswith": "\\CMD.EXE"}, "condition": "s"}, {"a"}),  # case-insensitive
        ({"s": {"CommandLine": "net user ?dmin*"}, "condition": "s"}, {"a"}),  # inner wildcards -> regex
        ({"s": {"CommandLine|re": "^net user [A-Z]"}, "condition": "s"}, set()),  # re is case-sensitive
        ({"s": {"CommandLine|re": "^net user [a-z]"}, "condition": "s"}, {"a"}),
        ({"s": {"User": None}, "condition": "s"}, {"b"}),  # null = missing
        ({"s": {"User": "x"}, "condition": "not s"}, {"a", "b"}),  # NOT over a missing field
        ({"s": {"ProcessId|gt": 100}, "condition": "s"}, {"a"}),
        ({"s": {"ProcessId": [300, 9]}, "condition": "s"}, {"a"}),
        ({"s": {"Computer|cidr": "10.0.0.0/8"}, "condition": "not s"}, {"a", "b"}),  # not an IP -> no match
        ({"s1": {"Image|contains": "cmd"}, "s2": {"Image|contains": "ps"}, "condition": "1 of them"}, {"a", "b"}),
        ({"s1": {"Image|contains": "cmd"}, "s2": {"Image|contains": "ps"}, "condition": "all of them"}, set()),
        ({"s": {"CommandLine|contains": "100%_off"}, "condition": "s"}, {"b"}),  # LIKE metacharacters stay literal
        ({"s": {"CommandLine|contains": "o'brien"}, "condition": "s"}, {"b"}),  # quotes are escaped
    ],
)
def test_three_engines_agree_on_edge_cases(tmp_path, detection, expected):
    events = [
        proc_event(
            "a",
            process__file__path="C:\\Windows\\cmd.exe",
            process__cmd_line="net user admin /add",
            process__pid=300,
            actor__user__name="BWL\\a",
            device__hostname="BWL-1",
        ),
        proc_event("b", process__file__path="C:\\x\\ps.exe", process__cmd_line="echo 100%_off o'brien", process__pid=7, device__hostname="BWL-2"),
        proc_event("c", process__file__path="C:\\x\\ps.exe", process__cmd_line="echo 100xxoff"),
    ]
    events[2]["metadata"]["product"]["name"] = "Other EDR"  # filtered out by the logsource
    rule = make_rule(tmp_path, detection)
    assert three_engines(rule, events) == (expected,) * 3


def test_sql_runs_on_sqlite_and_quotes_identifiers():
    rule = sigma.get_rule("ep-encoded-powershell", RULES)
    q = sigma.to_sql(rule)
    assert '"process.file.path"' in q and "ESCAPE" not in q.split("WHERE")[0]
    db = sigma.sqlite_db([], MAPPING)
    assert list(db.execute(q)) == []
    with pytest.raises(sqlite3.OperationalError):
        db.execute(q.replace('"process.file.path"', "process.file.path"))


def test_kql_output_is_one_query_with_flat_columns():
    for r in RULES:
        k = sigma.to_kql(r)
        assert k.splitlines()[1] == r.logsource.kql_table
        assert "." not in k.split("| where", 2)[2].split('"')[0], "columns use underscores, not dots"
        assert k.rstrip().endswith("| project metadata_uid")


def test_unknown_rule_name_is_an_error():
    with pytest.raises(SigmaError, match="no rule named"):
        sigma.get_rule("nope", RULES)


# --------------------------------------------------------------------------- CLI and gate
def test_cli_sigma_test_passes(capsys):
    assert main(["sigma", "test"]) == 0
    out = capsys.readouterr().out
    assert f"sigma: PASS ({len(RULES)}/{len(RULES)} rules" in out


def test_cli_sigma_list_mapping_and_convert(capsys):
    assert main(["sigma", "list"]) == 0
    assert f"{len(RULES)} rules:" in capsys.readouterr().out
    assert main(["sigma", "mapping"]) == 0
    assert "unmapped.result_rows" in capsys.readouterr().out
    assert main(["sigma", "convert", "--rule", "nw-smb-to-internet", "--backend", "sql"]) == 0
    assert "cidr_match" in capsys.readouterr().out
    assert main(["sigma", "convert", "--rule", "nw-smb-to-internet"]) == 0
    assert "ipv4_is_in_range" in capsys.readouterr().out
    assert main(["sigma", "convert"]) == 2


def test_release_gate_includes_sigma():
    names = {n: ok for n, ok, _ in gate_checks()}
    assert names["Sigma rules pass their fixtures; evaluator, SQL and KQL agree"]
