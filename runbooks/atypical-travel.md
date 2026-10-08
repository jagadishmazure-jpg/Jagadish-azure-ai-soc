# Runbook: atypical travel

Techniques: T1078, T1078.004
Rules: Atypical travel

## Decide

1. Is the second address one of the tenant's VPN egress points? Then the travel is an artefact of the VPN: false positive.
2. Is the second address on threat intel, or did the same address fail sign-ins for this account recently (token replay)?
3. What did the session do after sign-in (downloads, mailbox rules)?

## Contain (needs approval)

- Revoke sessions and disable the account until the user confirms; block the address.

## Close

If the cause was the VPN, propose adding the egress range as a named location so the detection stops firing.
