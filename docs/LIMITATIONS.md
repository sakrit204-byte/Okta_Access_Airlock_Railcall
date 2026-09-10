# Limitations

This file is kept current as the module is built, not written at the end. Every entry is
something that constrains what the module can honestly claim.

Entries marked **verified** were confirmed against a live Okta org. Entries marked
**documented** come from Okta's own documentation and are still to be measured.

## 1. Searching and writing use different consistency models

**documented**

Okta's Users API offers both `filter` and `search`. Okta states that search results
"are sourced from an eventually consistent datasource and may not reflect the latest
information."

This matters more here than it would in an ordinary integration. If a planning command
resolved its target set with `search`, the plan could be built on stale state, and the
matching apply would then act on a set the approving human never actually saw. That is
precisely the failure the plan and apply split exists to prevent, reintroduced quietly.

**What this module does.** Every command whose output can feed a write uses `filter`.
Where free text lookup is genuinely needed, the result is marked advisory and cannot be
passed into an apply.

## 2. Removing a user from a group can silently modify a group rule

**documented**

When an administrator manually removes a user from a group that a group rule manages,
Okta adds that user to the rule's exception list. The membership change is what you
asked for. The rule change is not, and it affects every other member the rule governs.

Undoing it is not one call either. The rule must be deactivated, edited, and
reactivated, which briefly suspends it for the whole organisation.

**What this module does.** Okta exposes an endpoint that reports which rules manage a
specific membership, so the preview can name the rule before anything happens rather
than discovering it afterwards. A removal that would modify a rule says so in the
approval, with the number of other members affected.

## 3. The System Log has no guaranteed maximum latency

**documented**

Okta states that it "doesn't guarantee a maximum duration between the occurrence of an
event and the delivery to a log stream."

The custody reporting in this module is built on the System Log. This sets a hard limit
on what it may claim.

**What this module does.** Every custody verdict carries the log watermark it was
computed against, and reports that no ungoverned change was **visible** as of that
timestamp. It will never report that no ungoverned change occurred. That is not
something this module can know, and saying so would be the most misleading thing it
could do.

## 4. Deactivating a user does not remove their group memberships

**documented**

A deactivated Okta user remains in their groups. Separately, live sessions, OAuth
grants and per client refresh tokens are three different things behind three different
endpoints, and deactivation does not necessarily clear all of them.

"I deactivated them" is widely assumed to mean access is gone. It does not mean that.

**What this module does.** There is no single off switch and this module does not
present one. The blast radius command enumerates what survives a deactivation, and the
composite offboarding command addresses each surviving path explicitly and reports each
outcome separately rather than returning one success flag.

## 5. There is no command to delete a user

**by design**

Deletion is permanent. For access review it adds nothing that deactivation does not
already provide, and shipping it would place the worst available outcome one approved
click away from an agent.

This is a design position rather than an oversight. If you need deletion, do it in the
Okta console, where the act is deliberate and attributable to a person.

## 6. Not built, and not planned

Stating these so nobody assumes coverage that does not exist:

* **No user creation or provisioning.** Joiners are a different problem with a different
  approval shape.
* **No policy or authenticator editing.** The blast radius is large and previewing it
  honestly is hard. A shallow implementation would be worse than none.
* **No static SSWS token support.** See the README for the reasoning.
* **No AI or language model commands.** The purpose of this module is to constrain
  agents. Embedding one would blur that.

## 7. Authentication requires DPoP, and that is not optional here

**verified**

Current Okta orgs require RFC 9449 Demonstrating Proof of Possession on the client
credentials grant. A token request without a DPoP proof is refused with
`invalid_dpop_proof` before any command runs.

Okta's application settings offer a switch to disable that requirement. **This module
does not ask you to use it.** DPoP binds the access token to a proof key, so a token
lifted from a log, a crash dump or a process listing cannot be replayed without the
private key that minted it. Turning it off to make integration easier would remove a
boundary for no benefit.

Two consequences worth knowing:

* The proof key is generated per process and never persisted. Restarting the Station
  mints a new one, which is intended.
* Okta enforces single use on the client assertion identifier, so every token attempt
  builds a fresh assertion rather than reusing one across the DPoP nonce handshake.
  Getting this wrong produces an intermittent authentication failure that only appears
  when a retry happens, which is why it is called out here.

## 8. What the development org could not prove

**verified**

This module is developed against an Okta Integrator Free Plan org, which caps at ten
active users. That is enough to exercise every code path, and it is not enough to
demonstrate behaviour at scale.

Paging is therefore tested by lowering the page size until a set spans several pages,
which proves the paging logic but not that a directory of several thousand users
behaves the same way. Rate limit accounting reads Okta's own response headers, so it
should hold at any size, but that has been reasoned about rather than observed under
real pressure.

Where a claim in this repository depends on scale that was never run, it says so. No
number in the documentation is an extrapolation presented as a measurement.

## 9. Scope of the claim

This module produces evidence that a human reviews. It is a human in the loop record,
not a certified compliance product, and it does not by itself satisfy any control in
SOC 2, ISO 27001, or any other framework.
