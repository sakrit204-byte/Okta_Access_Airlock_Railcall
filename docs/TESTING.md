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
