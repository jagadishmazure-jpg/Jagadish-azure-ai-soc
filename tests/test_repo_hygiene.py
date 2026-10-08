"""Repository hygiene: complete docs, current outputs, no dates, no real identifiers, no copied PDF."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", ".terraform", "refs", "out"}
MD = sorted(p for p in ROOT.rglob("*.md") if not SKIP_PARTS & set(p.parts))
SECTIONS = [
    "Purpose", "Architecture", "How it works", "Key files", "Code excerpts", "Configuration", "Commands",
    "Real output", "Tests and gates", "Guardrails", "Security and governance", "Observability",
    "Failure modes", "Mapping to Azure services", "Limitations", "Interview talking points",
]  # fmt: skip
FULL_DOCS = sorted(p for d in ("components", "infra") for p in (ROOT / "docs" / d).glob("*.md") if p.name != "README.md")
SERVICES = ("Microsoft Sentinel", "Defender XDR", "Foundry", "Entra ID", "Azure Monitor")
MONTHS = r"\b(January|February|March|April|June|July|August|September|October|November|December)\b"
SUFFIXES = {".md", ".py", ".json", ".yml", ".yaml", ".tf", ".bicep", ".hcl", ".sh", ".toml", ".jsonl", ".tfvars", ".kql"}
TEXT_FILES = [p for p in ROOT.rglob("*") if p.is_file() and not SKIP_PARTS & set(p.parts) and p.suffix in SUFFIXES]
# Public Azure built-in role definition IDs (identical in every tenant), used in infra/bicep/modules/identity.bicep.
BUILT_IN_ROLE_IDS = {"3e150937-b8fe-4cfb-8069-0eaf05ecd056", "8d289c81-5878-46d4-8554-54e1e3d8b5cb"}
GUIDE_LINK = "https://www.conifers.ai/blog/ai-powered-soc/"


def flat(path: Path) -> str:
    """File text with whitespace collapsed, so phrases still match across wrapped lines."""
    return " ".join(path.read_text().split())


def folders():
    yield from sorted({p.parent for p in ROOT.rglob("*") if p.is_file() and not SKIP_PARTS & set(p.parts)} | {ROOT / "evidence"})


# .github has no README on purpose: GitHub would show .github/README.md instead of the root README.
@pytest.mark.parametrize("folder", [f for f in folders() if f != ROOT / ".github"], ids=lambda p: str(p.relative_to(ROOT)) or ".")
def test_every_folder_has_a_readme_with_a_file_table(folder):
    readme = folder / "README.md"
    assert readme.exists(), f"{folder} has no README.md"
    if folder != ROOT:
        assert "| File | What it does |" in readme.read_text()


def test_folder_readmes_list_every_child():
    for readme in ROOT.rglob("README.md"):
        if SKIP_PARTS & set(readme.parts) or readme.parent == ROOT:
            continue
        text = readme.read_text()
        for child in readme.parent.iterdir():
            if child.name in {"README.md", "__pycache__", ".terraform", ".terraform.lock.hcl"}:
                continue
            name = child.name + ("/" if child.is_dir() else "")
            assert f"`{name}`" in text, f"{readme.relative_to(ROOT)} does not list {name}"


def test_no_dates_in_markdown():
    for p in MD:
        t = re.sub(r"@\d{4}-\d{2}-\d{2}(-preview)?", "", p.read_text())
        assert not re.search(r"\b\d{4}-\d{2}-\d{2}\b", t), f"ISO date in {p}"
        assert not re.search(r"(?<![\w$,.])20[1-3]\d(?![\w,.%])", t), f"year in {p}"
        assert not re.search(MONTHS, t), f"month name in {p}"
        assert "Date:" not in t, f"Date line in {p}"


def test_no_todos_or_placeholders():
    for p in MD:
        t = p.read_text()
        for word in ("TODO", "TBD", "FIXME", "lorem ipsum", "coming soon", "<!-- nav -->"):
            assert word not in t, f"{word} in {p}"


def test_full_doc_set_exists():
    names = {p.relative_to(ROOT / "docs").as_posix() for p in FULL_DOCS}
    assert len([n for n in names if n.startswith("components/")]) == 14
    assert len([n for n in names if n.startswith("infra/")]) == 5
    for top in (
        "architecture", "threat-model", "scenario-mapping", "metrics", "mssp-operating-model", "deployment",
        "implementation-guide", "best-practices", "interview-guide",
    ):  # fmt: skip
        assert (ROOT / "docs" / f"{top}.md").exists(), top


@pytest.mark.parametrize("doc", FULL_DOCS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_full_doc_has_all_sections_in_order(doc):
    t = doc.read_text()
    pos = [t.find(f"## {i}. {s}") for i, s in enumerate(SECTIONS, 1)]
    assert all(x >= 0 for x in pos), [s for s, x in zip(SECTIONS, pos, strict=True) if x < 0]
    assert pos == sorted(pos)
    assert "```mermaid" in t and "<!-- output:" in t
    assert "<!-- code:" in t or "```bash" in t
    for svc in SERVICES:
        assert svc in t, f"{doc.name} does not map to {svc}"


def test_doc_links_resolve():
    for p in MD:
        for target in re.findall(r"\]\(([^)#\s]+\.md)(?:#[^)]*)?\)", p.read_text()):
            if target.startswith("http"):
                continue
            assert (p.parent / target).resolve().exists(), f"{p.relative_to(ROOT)} links to missing {target}"


def test_doc_outputs_and_excerpts_are_current():
    r = subprocess.run([sys.executable, "scripts/render_docs.py", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_no_secrets_or_real_identifiers():
    guid = re.compile(r"\b(?!00000000-)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
    bad = [re.compile(p, re.I) for p in (r"AccountKey=", r"-----BEGIN", r"client_secret\s*=", r"@gmail\.com", r"SharedAccessSignature=")]
    for p in TEXT_FILES:
        if p.name == "test_repo_hygiene.py":
            continue
        t = p.read_text(errors="ignore")
        found = {m.group(0).lower() for m in guid.finditer(t)}
        allowed = BUILT_IN_ROLE_IDS if p.name in {"identity.bicep", "test_iac.py"} else set()
        assert found <= allowed, f"GUID-like identifier in {p}: {sorted(found - allowed)}"
        for b in bad:
            assert not b.search(t), f"{b.pattern} in {p}"


def test_only_documentation_ip_ranges_and_example_domains_in_data():
    ips = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "0.0.0.0")
    for p in [ROOT / "data/ti/ioc-feed.json", ROOT / "config/tenants.yaml"]:
        for ip in ips.findall(p.read_text()):
            assert ip.startswith(allowed), f"{ip} in {p.name} is not a documentation or private range"
    for d in re.findall(r"@([a-z0-9.-]+)", (ROOT / "config/tenants.yaml").read_text()):
        assert d.endswith(".example"), d


def test_reference_pdf_is_never_committed():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not [f for f in tracked if f.lower().endswith(".pdf")]
    assert not [f for f in tracked if f.endswith("sec.txt")]
    assert "*.pdf" in (ROOT / ".gitignore").read_text()


def test_guide_is_attributed_not_copied():
    readme = flat(ROOT / "README.md")
    mapping = flat(ROOT / "docs/scenario-mapping.md")
    for t in (readme, mapping):
        assert "Conifers" in t and GUIDE_LINK in t
    assert "not included" in mapping and "quoted" in mapping


def test_organisations_are_fictional():
    readme = flat(ROOT / "README.md")
    assert "fictional" in readme
    for org in ("Halyard Security Services", "Brightwater Logistics", "Orchid Valley Clinics", "Pinecrest Credit Union"):
        assert org in readme


def test_readme_never_claims_deployment():
    t = flat(ROOT / "README.md").lower()
    assert "nothing is deployed" in t or "never been deployed" in t or "has not been deployed" in t
    assert "running in production" not in t and "live in production" not in t


def test_changelog_has_only_unreleased():
    versions = re.findall(r"^## (.+)$", (ROOT / "CHANGELOG.md").read_text(), re.M)
    assert versions == ["Unreleased"]


def test_six_adrs_without_date_lines():
    adrs = sorted((ROOT / "docs/adr").glob("0*.md"))
    assert len(adrs) == 6
    for a in adrs:
        t = a.read_text()
        assert "**Status:**" in t and "Date" not in t


def test_root_files_exist():
    for f in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "LICENSE"):
        assert (ROOT / f).exists(), f


def test_security_policy_has_a_fallback_contact():
    t = (ROOT / "SECURITY.md").read_text()
    assert "Report a vulnerability" in t and "Security contact request" in t


def test_readme_has_recruiter_section_and_honest_test_count():
    t = (ROOT / "README.md").read_text()
    assert "## At a glance (for recruiters)" in t
    m = re.search(r"\*\*(\d+) automated tests\*\*", t)
    assert m and int(m.group(1)) >= 250
