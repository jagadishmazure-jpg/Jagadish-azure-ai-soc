# Runbook: phishing link leading to account takeover

Techniques: T1566.002, T1078.004, T1114.003
Rules: ti-url-click, phish-click, inbox-forward-external, Email messages containing malicious URL removed after delivery

## Decide

1. Was the sender the tenant's phishing-simulation vendor? If yes, record the click for awareness training and close as benign positive.
2. After the click, did the account sign in from a new country or a threat-intel address?
3. Was a mailbox rule created that forwards externally? That is the usual business-email-compromise step.

## Contain (needs approval)

- Revoke sessions, then disable the account until the password is reset and MFA re-registered.
- Remove the forwarding rule and block the sign-in address.

## Close

List every recipient of the same message and confirm nobody else clicked.
