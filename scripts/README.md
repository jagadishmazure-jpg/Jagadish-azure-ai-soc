# scripts

Developer scripts.

| File | What it does |
|---|---|
| `render_docs.py` | Re-render output blocks and code excerpts in markdown; `--check` fails on drift (CI) |
| `overlap_check.py` | Count shared eight-word sequences between the repo and a local reference text (run before publishing) |
| `brand_check.py` | Fail if any file contains a blocklisted real company name (names stored only as SHA-256 hashes; CI) |
