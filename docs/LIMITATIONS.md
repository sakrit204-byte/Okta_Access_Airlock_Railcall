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

## 2b. Okta omits the next page link even when more records exist

**verified**

Okta signals further pages with an RFC 5988 Link header. It does not always send one.
Measured on a live org:

```
GET /api/v1/groups?limit=1     2 groups exist
  -> 1 record returned
  -> Link: <...groups?limit=1>; rel="self"      and nothing else
```

There is no `rel="next"`, so a reader that trusts the Link header alone collects one of
two records **and reports the set as complete**. That is the worst shape this failure can
take. A short set that announces itself is an inconvenience; a short set that claims to
be whole silently corrupts any plan built on top of it, and the plan looks fine.

This module had exactly that bug until it was measured.

**What this module does.** The Link header is the fast path. A page that comes back
**full** with no next link is treated as "ask again", using an explicit `after` cursor
built from the last record id, which was verified to keep returning records where the
Link header had stopped. A page that comes back **short** is genuinely the end. Where the
reader cannot advance safely, because a record carries no id or a cursor repeats, it
reports the set as incomplete rather than guessing.

So `complete: true` means the set was read to the end. It is never a default.

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

## 8. Reading admin roles needs more than a read only admin role

**verified**

`okta.roles.read` is not sufficient on its own. With that scope granted and the
application assigned Okta's **Read-only Administrator** role, all of these still answer
403:

```
/users/{id}/roles
/iam/roles
/iam/assignees/users
/iam/resource-sets
```

The refusal comes from the admin role, not the OAuth scope, so granting more scope does
not help. Reading admin role assignments requires a more privileged admin role, which is
a genuine trade against the least privilege posture this module argues for elsewhere.

**What this module does.** It refuses to guess. `users.list_access` and
`radius.user_deactivation` return `admin_roles_available: false` together with the
reason, and never render an empty list. "This user holds no admin roles" and "we are not
allowed to see whether this user holds admin roles" are different answers, and a module
that collapses them is lying by omission in the one place it matters most.

`org.verify_connection` names the affected commands on first run, so this is discovered
before it matters rather than during an access review.

**The partial route that remains open.** Admin privilege changes stay visible in the
System Log as `user.account.privilege.grant` and `user.account.privilege.revoke`, with
actor, timestamp and client IP. So privilege changes can be observed even where the
current standing state cannot be read. That is genuinely weaker: the log shows changes
within its retention window, not the present truth, and a grant older than that window
is invisible. It is reported as what it is.

## 9. What the development org could not prove

**verified**

This module is developed against an Okta Integrator Free Plan org, which caps at ten
active users. That is enough to exercise every code path, and it is not enough to
demonstrate behaviour at scale.

Paging is proven against a real multi page response by lowering the page size until a
set spans pages, which is how the truncation bug in section 2 was found. What that does
not prove is behaviour across a directory of several thousand users. Rate limit
accounting reads Okta's own response headers, so it should hold at any size, but that has
been reasoned about rather than observed under
real pressure.

Where a claim in this repository depends on scale that was never run, it says so. No
number in the documentation is an extrapolation presented as a measurement.

## 10. Three contract mistakes found by installing the station

**verified**

Passing the marketplace listing linter says nothing about whether a module runs.
Installing the station and reading its loader found three things wrong with this
bundle that no amount of documentation reading had caught.

**The credential helper is injected, not global.** `vault_get` lives inside an
`__rc_helpers__` dict placed in the module namespace. A handler reaching for a bare
global `vault_get` finds nothing and fails at the first command.

**A returned failure is recorded as a success.** The station treats a returned dict as
a completed action and writes a receipt saying so. This module previously returned
structured failure envelopes, which would have produced receipts asserting that failed
operations succeeded. That is the precise opposite of the fail closed behaviour it
claims. Failures now raise, and the structured detail rides in the exception so it
reaches the fail safe receipt.

**The manifest needed more than the listing gate asks for.** Real modules carry
`manifest_version: 2`, `provider`, `category`, `credential_spec`, `allowed_destinations`,
and per command `mode`, `risk`, `preview`, `receipt_required` and `requires`. The listing
linter accepted a manifest without any of them.

`tools/station_check.py` now replicates the loader contract so these cannot regress. It
should be re run after a station upgrade, because it is a copy of behaviour read out of
one version.

## 11. Okta does not attribute every console change to the person who made it

**verified**

The custody design rests on the System Log naming who made a change. It does, but not
always usefully.

Assigning an administrator role through the Okta console was recorded as
`user.account.privilege.grant` with the actor set to **`system@okta.com`**, a
SystemPrincipal, rather than to the signed in administrator who clicked the button.

So a change a human genuinely made can arrive attributed to Okta itself. This module
classifies such an event as **system** rather than as ungoverned, which is the honest
reading of what the log says, and it means **a real ungoverned change can be recorded in
a way that does not look ungoverned**.

**What this module does.** It reports the actor Okta gave, and never invents one. The
verdict vocabulary keeps `system` separate from `governed` precisely so that a reader
can see the difference between "this module did it" and "Okta says it did it". Where a
change matters, the timeline shows the raw actor so a human can judge it.

This is a real limit on the custody claim and it is stated rather than buried.

## 12. Scope of the claim

This module produces evidence that a human reviews. It is a human in the loop record,
not a certified compliance product, and it does not by itself satisfy any control in
SOC 2, ISO 27001, or any other framework.
