# detections/endpoint

Endpoint pack: four detections written as six queries over synthetic Windows and macOS process, registry,
file and service telemetry from `aisoc.endpoint`. The triage agent then reads the process tree and the
persistence items before it proposes anything. See [the component doc](../../docs/components/endpoint-triage.md).

| File | What it does |
|---|---|
| `rules.yaml` | Rule metadata: id, query files, severity, attack stage, ATT&CK technique |
| `run-key-user-writable.kql` | Autostart (Windows): Run key pointing at a user-writable folder, set by an unsigned process |
| `scheduled-task-user-writable.kql` | Autostart (Windows): scheduled task running from a user-writable folder |
| `launch-agent-unsigned.kql` | Autostart (macOS): LaunchAgent or LaunchDaemon written by an untrusted process |
| `service-from-temp-path.kql` | New Windows service whose binary sits in a temporary folder |
| `rmm-tool-abuse.kql` | Remote-access tool that is not the approved one, or the approved one run from Downloads |
| `ransomware-canary-touched.kql` | A decoy file is modified, renamed or deleted |
