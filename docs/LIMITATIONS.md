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
not help.

**Raising the role does not help either, which is worth knowing before you try.** These
were re tested after moving the application from Read only Administrator to
**Organization Administrator**, a role that can create and delete users and groups. Every
one of them still answers 403. So reading who holds administrative privilege appears to
need Super Administrator, which is precisely the role this module argues nobody should
give an integration.

That is not a trade worth making. The module works around it instead, at a stated cost.

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

This is a real limit on the custody claim and it is stated, not buried.

## 12. The station and the publish gate disagree about what a handler is

**verified**

The station resolves a command to its handler by **executing** the module and looking the
function up in the resulting namespace, so a function built by a factory and assigned to
a name works perfectly.

The marketplace publish gate resolves it by **reading the source** for a matching `def`.
A factory assigned handler is reported as missing and blocks the publish, even though the
station would have run it without complaint.

Four lifecycle commands here were originally generated from one shared builder, which is
the natural way to write four functions that differ only in a path and some wording. They
are now four literal `def`s that delegate to that builder, because only one of these two
gates decides whether the module can be published.

`tools/lint_listing.py` checks for a literal `def` locally so this is caught before a
publish attempt rather than by spending one of the five per hour.

## 13. A manifest field that silently voided the plan and apply split

**verified**

The workflow engine addresses a module command by an `action_id`, derived in
`routes/modules.py` as `provider + "_" + verb`, where `provider` is the command's own
`provider` field if it declares one, and `verb` is whatever follows the first dot in the
command id.

Every command here declared `"provider": "okta"`, which looked tidy and was correct in
the sense that this module does integrate with Okta. The consequence:

```
plan.deactivate_user   ->  okta_deactivate_user
apply.deactivate_user  ->  okta_deactivate_user      same id
plan.group_membership  ->  okta_group_membership
apply.group_membership ->  okta_group_membership     same id
users.find             ->  okta_find
groups.find            ->  okta_find                 same id
```

**A plan and the apply it is supposed to gate resolved to the same action.** The entire
safety pattern this module is built around would have been decorative inside a workflow,
and nothing in the module's own behaviour would have looked wrong.

The publish gate does not check this. The station's own collision guard would have
caught it at load time, but only as a refusal to register, and only once somebody tried.

**Fixed** by dropping the per command `provider` so the id derives from the command's own
prefix, giving twenty seven distinct action ids. The module still declares
`provider: okta` at the top level and in `credential_spec`, which is where it belongs.

`tools/station_check.py` now computes every action id and fails on any collision, so this
cannot come back.

## 14. Okta membership reads lag Okta membership writes

**verified**

A group membership write returns 204 and a read issued immediately afterwards still
reports the old set. Measured on a live org:

```
PUT  /groups/{g}/users/{u}   -> 204
GET  /groups/{g}/users       -> 0 members     immediately
GET  /groups/{g}/users       -> 1 member      one second later
```

This is not a curiosity. The apply path re reads the membership and compares it against
the approved fingerprint, so a change made moments before the apply is **invisible to
that re read**. The comparison matches, the write proceeds, and the approval appears to
have held while the thing it was pinned to had already moved.

The guarantee would have held everywhere except the case it exists for.

**What this module does.** Every apply that pins to a membership reads it **twice**, with
a pause, and proceeds only if both reads agree. A set caught mid change is refused as
`membership_unsettled` rather than trusted.

**This narrows the window. It does not close it.** Okta publishes no convergence bound,
so a change landing inside the gap between the two reads is still invisible. The honest
claim is that the fingerprint catches drift that has settled, not drift made in the last
instant, and no wording in this module claims otherwise.

Verified after the fix: a plan approved over one member, an intruder added, and the apply
refuses with `plan_drifted` naming both fingerprints.

## 15. A refusal that arrived looking like a crash

**verified, and it was our bug**

The guard wrapping every command turned any exception into `unexpected_error`. Deliberate
refusals raise, so a drift refusal reached the caller carrying the wrong code and none of
its detail: the one message a reader most needs to trust arrived indistinguishable from a
bug.

Found by running a live drift test and reading the output rather than the exit status.
The guard now re raises refusals unchanged and wraps only genuine crashes.

## 16. Directory text is written by strangers, and this module hands it to an agent

**verified**

Names, emails, group descriptions, application labels and System Log text are all set by
people, and several of them by the very people a review is examining. Anybody who can
edit their own profile can put an instruction in their display name.

A module whose entire purpose is constraining what an agent does cannot then pipe
unflagged attacker controlled text into that agent's context. That would be a hole in
exactly the thing being sold.

**What this module does.** Every response carries an `untrusted_content` block naming the
source and listing any provider field whose text is shaped like an instruction: attempts
to override earlier instructions, role hijacking, privilege requests, smuggled newlines
or control characters, embedded URLs, and unusual length. The field path is given so a
reader can go and look at it.

**Nothing is rewritten or removed.** Silently altering directory data would be its own
dishonesty, and a reader needs to see what is actually in the field to judge it. The
finding is surfaced beside the data, not instead of it.

**What this is not.** It is pattern matching, and pattern matching loses to a determined
author. It raises the cost of a careless attack and gives a reviewer somewhere to look.
It is not a filter and this module does not claim it stops anything. The real defences
remain the ones that do not depend on reading text: the OAuth scope, the admin role, and
a human approving every write.

Fields this module writes itself are excluded from the scan. Flagging our own
explanations for being long or quoting a URL would train a reader to ignore the signal,
which is worse than not having one.

## 17. The System Log cannot be paged

**verified**

Two separate limits, found together.

The log returns **no `rel="next"` link even on a full page**. And the `after` cursor,
which works on ordinary collections keyed by `id`, is rejected outright for log records,
which carry a `uuid` instead:

```
GET /api/v1/logs?limit=2&after=<uuid>
400  API validation failed: 'after': must be a valid value.
```

So the only lever is a bigger single page. Okta caps that at 1000 and refuses 1001, which
this module now requests.

**Consequence for custody.** Every custody command sees one page, not the whole log. A
read that fills the page reports `log_read_complete: false`, and no verdict built on a
partial read is presented as covering a period. This is a real ceiling on how far back
`custody.detect_ungoverned` and `access.dormant_admins` can look in one call, and
narrowing the window with `since` is the way to get a complete read of a shorter period
rather than a partial read of a longer one.

## 18. Scope of the claim

This module produces evidence that a human reviews. It is a human in the loop record,
not a certified compliance product, and it does not by itself satisfy any control in
SOC 2, ISO 27001, or any other framework.
