# Decision record: precautionary takedown vs patch (PHP2Shell)

**Status:** Accepted for the case study; implemented as `aisoc.php2shell.decide`.

## Context

When the PHP2Shell fixes shipped, many public bodies pulled websites offline while they patched. Taking a
site down removes the risk at once, but it also stops the service for citizens or customers, and it does
nothing for internal servers that attackers cannot reach anyway. Patching keeps the service up but leaves a
window, and it is impossible on end-of-life branches (8.1 and older), which get no fix at all.

## Decision

The response agent proposes one action per host from its PHP version and exposure. A person approves
every action before anything runs.

| Situation | Proposed action | Why |
|---|---|---|
| Evidence of execution or outbound traffic after the exploit request | `isolate_host` | It is an incident now, not a patching job |
| Fixed release (8.2.35, 8.3.36, 8.4.27, 8.5.12 or later) | `keep_online_monitor` | The flaw is closed; keep watching for other abuse |
| Vulnerable supported branch, internet-facing | `mitigate_and_patch_now` | Apply the published settings mitigation now and patch within hours; a takedown only if the patch slips |
| Vulnerable supported branch, internal only | `patch_next_window` | Not reachable from the internet; patch in the next short window |
| Distribution build with a lower upstream number | `verify_backport_then_patch` | Distributions backport fixes, so the version string alone cannot decide |
| End of life, internet-facing | `take_offline_until_migrated` | No fix will ever arrive; this is the one case where a takedown is the default |
| End of life, internal only | `restrict_and_migrate` | Restrict network access and move to a supported branch |

## Consequences

* Takedowns are rare and justified: in the case-study estate one of twelve hosts gets one.
* A failed attempt never leads to host isolation. It leads to patching and blocking the source.
* The agent never makes the takedown itself; the approval gate in `aisoc.php2shell.execute` holds every action.
* Risk accepted: a vulnerable internet-facing host stays online during the patch window, protected only by
  the settings mitigation and the detection rules.
