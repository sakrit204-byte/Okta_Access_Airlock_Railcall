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

Authentication proven end to end against a live org. Command level probing is blocked
on scope grants in the Okta console, which is configuration rather than code.

### What will be recorded per command

* The command, the scopes it needed, and whether it worked.
* Anything the provider did that the documentation did not predict, with enough detail
  that a reader can reproduce it.
* Anything that could not be proven on a free developer org, stated as such rather than
  quietly omitted.

### Log

**2026 09 10 — DPoP is mandatory on the token endpoint.**

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

**2026 09 10 — client assertions are single use.**

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

**2026 09 10 — authentication confirmed working.**

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

**Still to measure**, once scopes are granted: feature availability per endpoint on this
org tier, which rate limit headers are returned and per which bucket, how paging is
signalled, and the observed System Log watermark.
