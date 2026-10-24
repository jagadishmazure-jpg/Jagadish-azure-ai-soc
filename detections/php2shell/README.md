# detections/php2shell

Case-study detection rules for the PHP2Shell vulnerabilities (CVE numbers in the case study). They run
locally over synthetic telemetry from `aisoc.php2shell` through the repository's KQL interpreter. See
[the case study](../../docs/case-studies/php2shell.md) for the measured precision and recall.

| File | What it does |
|---|---|
| `rules.yaml` | Rule metadata: id, file, severity, attack stage, ATT&CK technique, host column |
| `multipart-upload-progress-probe.kql` | Multipart POST with the upload-progress field to a route that takes no uploads |
| `version-fingerprint-scan.kql` | One external source fingerprinting many paths within ten minutes |
| `web-worker-runs-from-tmp.kql` | A PHP or web-server worker starts a program from /tmp |
| `web-worker-drops-executable.kql` | A web worker writes an executable to /tmp (session and upload temp files excluded) |
| `tmp-binary-outbound.kql` | A program running from /tmp connects to a public address |
