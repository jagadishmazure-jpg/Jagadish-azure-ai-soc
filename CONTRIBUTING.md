# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check . && ruff format --check .
pytest -q
aisoc gate
aisoc rules-json --check
python scripts/render_docs.py --check
```

If you change a detection, run `aisoc rules-json` to regenerate `detections/rules.json`. If you change
anything that affects output, run `python scripts/render_docs.py` to refresh the rendered blocks, and update
any hand-written number that quotes them.

## Rules

- Fictional organisations and synthetic data only: `.example` domains, documentation IP ranges
  (RFC 5737), mock workspace IDs starting with `00000000-`. No real people, customers or indicators.
- Never commit third-party documents. `*.pdf` is ignored and a test checks that no PDF is tracked.
  Paraphrase and attribute; run `python scripts/overlap_check.py <reference text>` on new prose and expect
  zero shared eight-word sequences.
- Product code must not import `aisoc.labels`, `aisoc.analyst` or `aisoc.metrics`.
- No dates, years or month names in markdown, and no placeholder words; component and infra docs need all
  16 sections. `tests/test_repo_hygiene.py` checks these.
- Keep the honest labels: built, written but not run, planned. Never describe anything as deployed.
