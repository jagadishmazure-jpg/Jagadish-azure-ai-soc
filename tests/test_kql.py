"""The pure-Python KQL subset: operators used by the detections and templates, and clean failure on the rest."""

from datetime import UTC, datetime, timedelta

import pytest

from aisoc import kql
from aisoc.kql import KqlError

NOW = datetime(2000, 1, 2, tzinfo=UTC)
T = {
    "S": [
        {"TimeGenerated": NOW - timedelta(hours=h), "U": u, "IP": ip, "R": r, "Url": url, "N": n}
        for h, u, ip, r, url, n in [
            (1, "a@x.example", "203.0.113.1", "0", "https://bad.example/p", 3),
            (2, "B@x.example", "203.0.113.1", "50126", "https://ok.example/", 5),
            (3, "c@x.example", "203.0.113.2", "50126", "", 7),
            (30, "a@x.example", "203.0.113.3", "0", "", 11),
        ]
    ],
    "I": [{"IP": "203.0.113.1", "Tag": "spray"}, {"IP": "203.0.113.9", "Tag": "c2"}],
}


def q(text):
    return kql.run(text, T, NOW)


@pytest.mark.parametrize(
    "text,count",
    [
        ('S | where R == "0"', 2),
        ('S | where R != "0"', 2),
        ('S | where U =~ "b@X.example"', 1),
        ('S | where U in~ ("B@X.EXAMPLE", "c@x.example")', 2),
        ('S | where U !in~ ("b@x.example")', 3),
        ('S | where IP in ("203.0.113.1")', 2),
        ('S | where Url has "bad"', 1),
        ('S | where Url !has "bad"', 3),
        ('S | where U contains "@X."', 4),
        ('S | where U startswith "a"', 2),
        ('S | where U endswith ".example"', 4),
        ('S | where Url has_any ("bad", "ok")', 2),
        ("S | where TimeGenerated > ago(1d)", 3),
        ("S | where N >= 5 and N < 11", 2),
        ('S | where not(R == "0")', 2),
        ("S | where isnotempty(Url)", 2),
        ("S | where isempty(Url)", 2),
        ("S | take 2", 2),
        ("S | limit 3", 3),
        ("S | distinct IP", 3),
    ],
)
def test_filters(text, count):
    assert len(q(text)) == count


def test_summarize_with_bin_and_aggregates():
    rows = q(
        'S | where TimeGenerated > ago(1d) | summarize Fails = countif(R != "0"), Users = dcount(U), Ips = make_set(IP), Total = sum(N) by bin(TimeGenerated, 1d)'
    )
    assert len(rows) >= 1
    assert sum(r["Fails"] for r in rows) == 2 and sum(r["Total"] for r in rows) == 15


def test_summarize_by_key_min_max_avg():
    rows = {r["IP"]: r for r in q("S | summarize C = count(), Lo = min(N), Hi = max(N), Avg = avg(N) by IP")}
    assert rows["203.0.113.1"]["C"] == 2 and rows["203.0.113.1"]["Lo"] == 3 and rows["203.0.113.1"]["Hi"] == 5
    assert rows["203.0.113.1"]["Avg"] == 4


def test_join_inner_and_column_suffix():
    rows = q("S | join kind=inner (I) on IP")
    assert len(rows) == 2 and all(r["Tag"] == "spray" for r in rows) and "IP1" in rows[0]


def test_join_left_right_syntax():
    rows = q("S | join kind=inner (I | project Addr = IP, Tag) on $left.IP == $right.Addr")
    assert len(rows) == 2


def test_extend_parse_url_member_access():
    rows = q('S | extend Host = tostring(parse_url(Url).Host) | where Host == "bad.example"')
    assert len(rows) == 1


def test_let_and_order_top():
    rows = q("let big = 5; S | where N >= big | top 1 by N desc")
    assert rows[0]["N"] == 11


def test_project_rename_and_functions():
    r = q('S | take 1 | project Upper = toupper(U), L = strlen(U), Pick = iff(N > 1, "big", "small"), Joined = strcat(U, "/", IP)')[0]
    assert r["Upper"].isupper() and r["Pick"] == "big" and "/" in r["Joined"]


def test_count_operator():
    assert q("S | count")[0]["Count"] == 4


@pytest.mark.parametrize("bad", ["S | mv-expand X", "S | where foo(U)", "S | evaluate bag_unpack(X)", "S | where U ==", "S | invoke f()"])
def test_unsupported_raises_kql_error(bad):
    with pytest.raises(KqlError):
        q(bad)
