# Runbook: password spray and follow-on sign-in

Techniques: T1110.003, T1078.004
Rules: password-spray, success-after-spray, Password spray

## Decide

1. Is the source address an authorised scanner for this tenant? If yes, confirm the scan window with the vulnerability-management owner and close as benign positive.
2. Did any account sign in successfully from the same address within the hour? A success turns a noisy alert into a likely account compromise.
3. Check the address against threat intel and against the tenant's VPN and corporate egress ranges.

## Contain (needs approval)

- Revoke sessions for every account that signed in successfully from the address.
- Disable the account if activity after sign-in shows data access.
- Block the source address with a Defender indicator.

## Close

Record which accounts were targeted, which succeeded, and whether MFA or conditional access stopped the rest.
