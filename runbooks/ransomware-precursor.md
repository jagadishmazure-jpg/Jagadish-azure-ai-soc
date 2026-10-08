# Runbook: ransomware precursor on an endpoint

Techniques: T1204.002, T1059.001, T1071.001, T1003.001, T1490
Rules: office-spawns-script, encoded-powershell, ti-c2-connection, lsass-dump, shadow-copy-delete, Suspicious PowerShell command line, Possible LSASS memory access

## Decide

1. Is the encoded PowerShell launched by the software-deployment agent (ccmexec.exe) on an admin workstation? That pattern is the IT team's inventory job: benign positive.
2. Is shadow-copy deletion run by the backup agent on the backup server with `/oldest`? That is retention housekeeping: benign positive.
3. An Office parent process, a connection to a threat-intel address, LSASS access and `delete shadows /all` on one host is a ransomware precursor chain. Treat it as tier 3.

## Contain (needs approval, dual approval for crown-jewel hosts)

- Isolate the host (selective isolation keeps the Defender channel open).
- Disable the signed-in account and revoke its sessions, because LSASS was dumped.
- Block the command-and-control address.

## Close

Collect the investigation package, reimage the host, and reset credentials for every account that logged on to it.
