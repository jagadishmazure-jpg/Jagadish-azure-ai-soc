# Runbook: bulk download and personal-cloud upload

Techniques: T1530, T1567.002
Rules: mass-download, exfil-personal-cloud

## Decide

1. Compare the volume with the user's own baseline and with their department. A data engineer who downloads sixty files every weekday is normal; a finance specialist who usually downloads three is not.
2. Were files uploaded to an external destination within hours of the download burst?
3. Did volume trend upward over the previous days (a slow ramp before the burst)?

## Contain (needs approval)

- Revoke sessions and disable the account; involve HR and legal before contacting the user.
- Preserve the audit trail; do not delete anything.

## Close

Record the file list (redacted), the destination and the HR case reference.
