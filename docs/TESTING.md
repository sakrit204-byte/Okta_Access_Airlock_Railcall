# Testing

Two layers, kept apart on purpose.

## Layer 1: offline contract tests

`tests/test_handler.py`, run with:

```
python -m unittest discover tests
```

These need no Okta org and no network. They lock the properties that must hold no
matter what the provider does:

* **Redaction.** Secrets are removed from success envelopes, from error envelopes, and
  from the details attached to failures nobody planned for.
* **Egress.** The configured org host is allowed. A lookalike host, a different Okta
  org, and plain HTTP on the correct host are all refused by name.
* **Outcomes.** `unresolved` is a distinct third state and is never collapsed into
  success or failure. An unexpected exception becomes a closed failure that does not
  carry the exception message outward.
* **Credentials.** A missing vault resolver, an empty credential and a missing required
  field each fail with a specific code, and a missing field is named.
* **Rate accounting.** Absent headers record nothing rather than defaulting to zero,
  which would otherwise read as "no headroom left" and stop work for no reason.
* **Client assertion.** Structure, claims, a fresh identifier per assertion, and a
  named refusal for a malformed key.
* **Manifest agreement.** Every declared command resolves to a function, and the
  declared egress stays narrow.

Current state: **26 tests, all passing.**

There are deliberately no mocked Okta responses here. A mock would assert only that the
mock agrees with itself, and the interesting failures in this integration all come from
the provider behaving in ways a mock author would not have thought to imitate. Those
belong in layer 2.

## Layer 2: live evidence

Recorded here as it is gathered, against a real Okta developer org. Nothing in this
section is written before it has actually been run.

### The org this is developed against

An **Okta Integrator Free Plan** org. This is the successor to the old Developer
Edition org, and it was chosen over the thirty day Okta Platform trial for one reason:
it does not expire, so the module stays testable after the first month rather than
becoming unmaintainable.

What it gives us:

* A real Okta org and the real Management API. There are no mocks in this project.
* Lifecycle Management, which is what group rules run on. Group rule behaviour is
  central to this module, so an org without it would be useless here.
* API Access Management, and API Services applications authenticating with
  `private_key_jwt`.
* The System Log, which is the independent source of truth the custody commands
  reconcile against.

What it constrains, stated plainly:

* **Ten active users.** Every code path can be exercised at that size, but population
  scale cannot be demonstrated by having a large population. Paging is therefore
  exercised by lowering the page size rather than by holding thousands of users, and no
  claim is made about behaviour at a scale that was never run.
* The org deactivates after ninety consecutive days with no sign in.

### Status

**All 36 commands have been run against a live Okta org.** All 9 writes were exercised
against a disposable user and group created for the purpose and removed afterwards. Four
defects were found by that run and are recorded in the log below, along with the two
things about Okta that only a live run could have told us.

The org's own account was never used as a write subject. `apply.offboard_user` against
the only account in an org locks its owner out of it, which is a thing to know rather
than a thing to demonstrate.

### What is recorded per command

* The command, the scopes it needed, and whether it worked.
* Anything the provider did that the documentation did not predict, with enough detail
  that a reader can reproduce it.
* Anything that could not be proven on a free developer org, stated as such rather than
  quietly omitted.

### Log

**2026 09 10 · DPoP is mandatory on the token endpoint.**

The first live run against `integrator-6383370.okta.com` was refused before any command
ran:

```
http 400
error             = invalid_dpop_proof
error_description = The DPoP proof JWT header is missing.
```

Nothing in the Okta setup guides we worked from mentioned this. Current Okta orgs
require RFC 9449 Demonstrating Proof of Possession on the client credentials grant. The
app has a setting to switch it off; we did not use it.

DPoP is implemented instead, and it is worth having. It binds the access token to a
proof key, so a token lifted from a log, a crash dump or a process listing is unusable
without the private key that minted it. That is a third boundary on top of the OAuth
scope grant and the airlock, and it is one a bearer token cannot express.

Notes from implementing it:

* The proof key is generated fresh per client and never persisted. It is deliberately
  not the client assertion key, which is the application's registered identity.
* Okta answers the first proof with a nonce it expects echoed back in the next one.
  That is the documented handshake, so it is retried once internally rather than
  surfaced as a failure.
* A resource request can be challenged for a new nonce at any time, not only on the
  first call, so the same single retry exists on the API path.

**2026 09 10 · client assertions are single use.**

Once DPoP was working, the nonce retry failed:

```
http 401
error             = invalid_client
error_description = The client_assertion token has already been used.
```

The retry had reused the assertion built for the first attempt. Okta enforces one time
use on the assertion identifier, so **every attempt must mint a fresh assertion**, not
just a fresh proof. This is easy to get wrong precisely because the retry is internal
and invisible, and it would appear as an intermittent authentication failure under any
condition that triggers a second attempt.

**2026 09 10 · authentication confirmed working.**

With both fixed, Okta's answer became purely a configuration one:

```
http 400
error             = consent_required
error_description = You are not allowed any of the requested scopes.
```

The grant is accepted; the scopes are not yet granted in the console. This is the
correct behaviour to see from an application with a valid identity and no permissions,
and it confirms the whole auth path: assertion signing, DPoP proof, nonce handshake and
egress allowlist.

**2026 09 10 · first full probe, with all five read scopes granted.**

Scopes confirmed granted and working: `okta.apps.read`, `okta.groups.read`,
`okta.logs.read`, `okta.roles.read`, `okta.users.read`.

**Measured rate limits on the Integrator Free Plan**, per minute per bucket, read from
Okta's own response headers rather than from documentation:

```
/users    300
/groups   250
/logs      60
/apps      50
```

`/apps` at fifty a minute is the tight one. Any command that fans out across
applications has to budget against it, which is what `org.rate_budget` exists for.

**The rate budget was recording nothing, and the probe caught it.** Okta returns those
headers lowercase, and `dict(response.headers)` discards the case insensitivity the HTTP
layer provided, so looking them up by their documented capitalisation silently returned
nothing. The budget read as empty rather than as an error, which is the worst kind of
bug: a safety feature that is quietly switched off. Header lookup is now case
insensitive throughout, including the Link and DPoP nonce headers, which had the same
latent problem.

**Group rules are reachable on this tier.** `/groups/rules` answers 200. This was the
single biggest open risk, because `access.rule_entanglement` is one of the two things
that differentiate this module and it would have been worthless behind a paywall.

**Admin role reads are refused, and it is the admin role rather than the scope.**
`okta.roles.read` is granted, and every one of these still answers 403 "You do not have
permission to perform the requested action":

```
/users/{id}/roles
/iam/roles
/iam/assignees/users
/iam/resource-sets
```

The Read only Administrator role assigned to the application is not permitted to read
admin role assignments. Granting more OAuth scope does not fix it; it needs a more
privileged admin role, which is a trade against the least privilege posture this module
argues for. Commands now degrade rather than fail: `users.list_access` and
`radius.user_deactivation` return `admin_roles_available: false` with the reason, and
never render "not allowed to see admin roles" as "no admin roles", because those are
different answers.

**The System Log carries what custody needs.** A sample event exposes `actor` with id,
type, alternateId and displayName, `client` with userAgent, ipAddress and geo, and
`outcome` with result and reason. `user.account.privilege.grant` and
`user.account.privilege.revoke` are both queryable by `eventType` filter, so admin
privilege changes remain visible in the log even though the roles API is closed to us.

**Observed System Log watermark: 14 to 25 seconds** behind wall clock across two
samples. That is a measurement of one org at two moments and is not a bound. Okta
publishes no maximum delivery latency, so it never becomes one.

**Paging could not be exercised.** The org holds one user, so `/users?limit=1` returns
only `rel="self"` and no `rel="next"`. The paging logic is proven by the offline suite
against canned Link headers, including cursor carry over and refusal of a next page
pointing off the allowed host, but it has not been run against a genuinely multi page
Okta response. Stated rather than glossed.

**Commands run live and behaving:**

```
users.find                  ok    1 user, may_feed_write true
users.list_access           ok    1 group, 1 app, roles unavailable with reason
radius.user_deactivation    ok    see below
groups.find                 ok    2 groups, complete
access.rule_entanglement    ok    membership not rule managed
```

Worth recording what the blast radius command found on a **one user, freshly created
org**: two OAuth refresh tokens that survive a deactivation, and one group membership
that survives it. On an org that has done nothing. That is the argument for the command
existing, made by the org itself rather than by us.

***

**2026 09 10 · every write exercised, and a scope turns out to be half a permission.**

All nine writes ran against a disposable user and group. The first result was that every
one of them returned **403 while both write scopes were granted**, because the admin role
assigned to the application was Read only Administrator.

An OAuth scope and an Okta admin role are independent gates and both must permit a write.
`org.verify_connection` was reporting the scopes as granted, which would have told a buyer
their writes work right up until the first one failed.

It now probes the role directly, by sending a deliberately invalid write and reading the
status: **403 means the role refuses writes, 400 means it permits them** and only the body
was bad. Nothing is created either way. It reported `usable: false` across all nine until
the role was changed, then flipped to true. That is this module's own argument about
layered permissions, demonstrated by Okta against itself.

**`apply.unlock_user` reported `failed`, and that was correct.** The user was not locked,
Okta refused, and the three outcome model recorded a definite refusal rather than a
comfortable success.

**Defect found: membership reads lag membership writes.** A PUT returns 204 and a GET
issued immediately still reports the old set. One second later it is correct. The apply
path read once and compared against the approved fingerprint, so a change made moments
before the apply was invisible to it. The comparison matched, the write proceeded, and the
approval looked like it had held while the thing it was pinned to had already moved. The
guarantee held everywhere except the case it exists for.

Applies that pin to a membership now read twice with a pause and refuse a set still moving
as `membership_unsettled`. That narrows the window and does not close it, because Okta
publishes no convergence bound, and `LIMITATIONS.md` says exactly that rather than
implying a guarantee.

**Defect found: the guard turned deliberate refusals into crashes.** Every exception was
being wrapped as `unexpected_error`, including the refusals this module raises on purpose.
A drift refusal reached the caller with the wrong code and none of its detail,
indistinguishable from a crash, which is the worst possible outcome for the one message a
reader most needs to trust. Found by reading the output of a live drift test rather than
its exit status. Refusals now pass through unchanged and only genuine crashes are wrapped.

**Verified after both fixes:** a plan approved over one member, an intruder added to the
group, and the apply refuses with `plan_drifted`, naming both fingerprints and the user id
that appeared.

***

**2026 09 10 · injection flagging, checked for false positives before being trusted.**

Every read command was run against the live org with the `untrusted_content` scan active.
**Zero false positives.**

The first version flagged this module's own explanations, for being long or for quoting a
URL. A signal that fires on its own author's text trains a reader to ignore it, which is
worse than having no signal, so fields this module authors are excluded from the scan.

**Defect found: the System Log cannot be paged with what Okta exposes.** It rejects a uuid
as an `after` cursor, returning 400 `must be a valid value`, and it sends no `rel="next"`
link even on a full page. The cursor fallback now applies only where records carry `id`,
and custody commands report the watermark they actually reached instead of implying they
read everything. Recorded as `LIMITATIONS.md` 17.

**Defect found: the pager trusted the Link header alone and silently truncated.** Okta
omits `rel="next"` in cases where more records exist. Silent truncation in a review tool
is the failure that looks like success. Fixed, and covered by the offline suite.

***

**2026 09 10 · the five act demonstration, run end to end.**

`tools/demo.py` runs against the live org, creates its own fixtures, and removes them.
Exercised in one pass: `org.verify_connection`, `radius.user_deactivation`,
`plan.group_membership`, `apply.group_membership` refusing on drift, `access.review_pack`,
and `custody.detect_ungoverned`.

The org was confirmed unchanged afterwards. The demo never prints a credential, and that
is enforced in the code rather than left to care.

***

**2026 09 11 · a full reread of the handler, and what it turned up.**

Every line of `handlers/handler.py` read again from the top, as a reviewer would rather
than as its author. Five changes came out of it, one of them to the core guarantee.

**The approval bound to the state but not to the change.** The fingerprint hashed the
snapshot alone. An apply carrying the approved fingerprint next to a wider intent, say
`remove: [a]` swapped for `remove: [a, b, c]`, passed the drift check, because the group
had not moved. The human had approved removing one person. The intent is now hashed with
the state, so editing either changes the fingerprint, and a refusal whose state still
matches names the intent as the thing that moved. Locked by an offline test that tampers
the intent and expects the refusal, and the live drift demonstration was re run against
the org afterwards: plan, a joiner, `plan_drifted`, both fingerprints, the joiner's id.

**A refused read was rendered as an empty list.** `users.list_live_credentials` caught
any error on the clients and devices endpoints and returned `[]`, and
`radius.user_deactivation` then reported "0 refresh tokens survive". That is the
dishonesty `_paged_optional` exists to prevent, applied one function away from it. Both
now report `available: false` and a null count, with a warning saying why.

**EMEA orgs were refused.** The host check accepted `okta.com` and `oktapreview.com`
only. Okta serves EMEA customers from `okta-emea.com`. Accepted now, in the handler and
in the manifest's network allowlist, and a test pins the two lists to each other.

**The injection scan matched inside ordinary words.** "act as" fired on "Contact
Assistants", "elevate" on "Elevate Marketing", and every description over 120 characters
was flagged as unusually long. Needles are matched on word boundaries, bare verbs were
replaced with instruction phrases, and the length rule no longer applies to description
fields. The zero false positive figure recorded above was measured on a one user org and
should be read that way.

**The redactor knew "Bearer " and not "DPoP ".** Current orgs bind tokens with DPoP, so
the authorization header carries that prefix. No path was found that surfaced a request
header, and the redactor now catches both regardless.

Also removed from the workflow: a node that read the System Log a second time for
nothing, because `custody.audit_pack` reads it itself. `/logs` is the tightest bucket on
this org at sixty calls a minute. The workflow is 13 nodes and passes the marketplace
gate.
