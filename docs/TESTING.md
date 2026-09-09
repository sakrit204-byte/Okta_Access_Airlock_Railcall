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

Not yet started. The Okta org is being created and the service application configured.

### What will be recorded per command

* The command, the scopes it needed, and whether it worked.
* Anything the provider did that the documentation did not predict, with enough detail
  that a reader can reproduce it.
* Anything that could not be proven on a free developer org, stated as such rather than
  quietly omitted.

### Log

_Empty. Entries are added only after a real run._
