# Okta Access Airlock

Governed Okta administration for RailCall. An AI agent holding Okta admin is the most
dangerous credential in a company. This module is the ceiling that stops it, and the
receipt that proves what it did.

Every write is held behind the RailCall airlock: preview, then human approval, then
execute, then a signed receipt. Every change is then reconciled against Okta's own
System Log, so custody can be proven rather than assumed.

## Who this is for

A team of ten to fifty people going through SOC 2 or ISO 27001, with one person who
carries compliance alongside another job, who is asked every quarter to evidence who
had access to what and who approved it. That evidence is usually assembled by hand from
spreadsheets and screenshots. This produces the same answer, generated and signed.

## Status

Early. The foundation is in place and passes the marketplace publish gate. Two of the
planned thirty six commands are implemented. See `docs/LIMITATIONS.md`, which is kept
current rather than written at the end.

## Quick start

### 1. Install the RailCall station

```
curl -fsSL https://railcall.ai/install.sh | bash
railcall version
```

Python 3 must be on your PATH before you run this. On Windows the Microsoft Store
placeholder at `WindowsApps\python` is not Python and the installer will stop on it.

### 2. Create an Okta OAuth service app

In your Okta admin console, create an API Services application. Set the client
authentication method to **Public key / Private key** and add a public key in JWK form.
Keep the matching private key; it stays on your machine and is never uploaded anywhere.

Grant only the scopes you actually want this module to hold. Read scopes:

* `okta.users.read`
* `okta.groups.read`
* `okta.logs.read`
* `okta.roles.read`
* `okta.apps.read`

Write scopes, only if you want the corresponding commands to work at all:

* `okta.users.manage`
* `okta.groups.manage`
* `okta.roles.manage`

Granting nothing but read scopes is a supported and sensible way to run this module.
`org.verify_connection` will tell you exactly which commands that costs you.

### 3. Store the credential in the Station vault

```
railcall set okta '{"org_url":"https://your.okta.com","client_id":"0oa...","key_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\n..."}'
```

The credential lives in the local Station vault. It is never sent to the marketplace and
never written to this repository.

### 4. Verify

```
railcall market install sakrit204/okta_access_airlock
```

Then run `org.verify_connection` from Studio. It probes every scope you granted and
names each missing one alongside the exact commands it blocks, so the first run tells
you what you can and cannot do rather than failing later on a command you needed.

## Why OAuth and not an API token

Okta offers two ways for a machine to authenticate. They are not equivalent.

A static SSWS API token has **no scopes at all**. It inherits the full privileges of
whichever admin created it, it does not expire on its own, and anybody who copies the
string has everything the token has. There is no way to say "this may only read users."

An OAuth service app using `private_key_jwt` is scoped, short lived, and authenticated
with a signature rather than a shared string. That gives this module two independent
boundaries instead of one:

* The **OAuth scope grant** is structural. The token cannot deactivate a user unless an
  Okta admin granted `okta.users.manage`.
* The **RailCall airlock** is procedural. Even with the scope, a human approves the call.

Which is the point: if the airlock were bypassed entirely, a read scoped token still
could not deactivate anybody. Okta itself recommends against static API tokens. This
module does not support them, on purpose.

## Trust surface

* Credentials resolve through the Station vault only. This module never reads a
  credentials file from disk.
* Network egress is allowlisted to the configured Okta org. A request to any other host
  is refused before it is sent.
* No subprocess. No filesystem writes. Both declared in `module.json` where they are
  machine checkable rather than merely claimed.
* Secrets are redacted from every returned envelope and from every error, including the
  ones raised by failures nobody planned for.
* Ambiguous outcomes fail closed. A write that Okta does not answer is recorded as
  `unresolved`, carrying what was attempted and the prior state, and is reported as
  neither success nor failure.

## Command surface

Two commands are implemented today. The planned surface is thirty six, in six groups:

* **Posture and connection.** Scope probing, org description, standing admin inventory,
  rate limit headroom.
* **Discovery.** Users, groups, memberships, live sessions and tokens.
* **Blast radius and access explanation.** What breaks if this user is deactivated, what
  survives it, and why a given person can reach a given application at all.
* **Plan.** Every write has a planning twin that snapshots and fingerprints the exact
  state it intends to change.
* **Apply.** The writes. Each one re reads, re hashes, and refuses if anything moved
  since the human approved it.
* **Custody, ledger and evidence.** Reconciliation against the Okta System Log, and the
  signed evidence bundle.

There is deliberately no command that deletes a user. Deletion is permanent, it adds
nothing over deactivation for access review, and shipping it would put the worst
available outcome one approved click away.

## Development

Lint the bundle against the real marketplace gate at any time. This is free and rate
limited at sixty calls a minute, unlike publishing, which is capped at five an hour.

```
python tools/lint_listing.py
```

Run the tests:

```
python -m unittest discover tests
```

## Documentation

* `docs/SETUP.md` covers the Okta service app in more detail.
* `docs/LIMITATIONS.md` records what this module cannot do and why, including specific
  Okta behaviours that constrain it.
* `docs/TESTING.md` records what has actually been run against a live org.

## License

MIT. See `LICENSE`.
