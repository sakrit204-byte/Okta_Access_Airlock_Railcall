# Okta Access Airlock

**An AI agent holding Okta admin is the most dangerous credential in your company.**
It can deactivate your CEO, wipe MFA off your finance lead, delete a group and silently
strip forty people of application access, or grant itself Super Administrator. None of
that is exotic. It is four ordinary API calls that any agent with the right token can
make in under a second, with no preview and no way back.

Which is why the honest answer to "should I connect an agent to my identity provider"
has been **no**.

This module changes that answer. It is the ceiling that stops the agent, and the receipt
that proves what it did.

## What it does

Every write goes through the RailCall airlock: preview, then human approval, then
execute, then a signed receipt. Nothing moves without a person.

Then it does the part most integrations cannot. It reconciles every change against
**Okta's own System Log**, which records the actor, the timestamp and the client IP for
every administrative event. So for any change you can ask which of three things it was:

* **governed**, bound to a specific approval
* **ungoverned**, made by a named admin in the console at a specific time from a
  specific address
* **unproven**, meaning we cannot account for it and say so rather than guessing

Most integrations have to infer that. Okta can be asked.

## Who this is for

**Teams putting an agent anywhere near their identity provider.** RailCall exposes
installed modules to Claude Desktop, Cursor, Windsurf and Zed over MCP. The moment any
Okta module is installed, an agent can call it. This is the module that makes that
survivable.

**Small teams carrying a compliance obligation.** Ten to fifty people, one person who
owns compliance alongside another job, going through SOC 2 or ISO 27001. Okta sells the
governed answer to this as an add on at roughly four to eleven dollars per user per
month, and access certification is not available standalone. Below a certain size that
maths does not work, and the review gets done by hand in a spreadsheet.

## Three things you get that a spreadsheet cannot give you

**1. A safe blast radius before you act.** Before deactivating someone, see which
applications they lose, which groups they *stay in*, which admin roles vanish, which
groups they own become ownerless, and how many live sessions and refresh tokens survive
the deactivation. There is no single off switch in Okta, and this module does not
pretend there is one.

**2. Dormant administrator detection.** Who holds a standing admin role and has not
performed a single administrative action in ninety days. Answering that means joining
role assignments against System Log activity. No CSV export can do it, at any team size.

**3. A signed evidence trail.** Not a report you assemble, a chain you can verify
offline months later, including every action the module refused.

## How a change gets approved

Every write has a planning twin. The plan reads current state, computes exactly what
would change, and **fingerprints the state the change depends on**. A human approves that
payload. The matching apply receives the fingerprint back, re reads, re hashes, and
**refuses if anything moved**, naming what moved.

```
plan                          approval              apply
----                          --------              -----
read current state
compute the change
hash the affected state
return a fingerprint    ->    a human reviews  ->   re read, re hash, compare
                              the payload             match  -> execute
                                                      drift  -> refuse and name it
```

So an approval binds to **the state the human reviewed**, not to the record ids they were
pointed at. Approve a change across forty users, let nine of them move while it sits in a
queue, and a naive system writes over state nobody saw. This one stops.

The fingerprint travels inside the approved payload, so none of this needs storage. That
is why `filesystem_writes` can honestly stay empty.

## Status

Early, and specific about where it is.

**13 of 36 commands implemented.** Authentication and every read are verified against a
live Okta org, not against mocks. 57 offline tests. The bundle passes the marketplace
publish gate with zero errors and zero warnings.

Not built yet: the apply commands, the custody group, and the companion workflow.

`docs/LIMITATIONS.md` is kept current as the module is built rather than written at the
end. It records nine things this module cannot do, most of them discovered by running it.

## Quick start

### 1. Install the RailCall station

```
curl -fsSL https://railcall.ai/install.sh | bash
railcall version
```

Python 3 must be on your PATH first. On Windows the Microsoft Store placeholder at
`WindowsApps\python` is not Python and the installer will stop on it.

### 2. Create an Okta OAuth service app

In your Okta admin console, create an **API Services** application. Set client
authentication to **Public key / Private key**.

Generate the key pair yourself and paste only the public half into Okta, so the private
key never leaves your machine and Okta never holds it. Okta accepts a JWK in that field.
`docs/SETUP.md` has the exact steps.

Grant only the scopes you want this module to hold:

* `okta.users.read`
* `okta.groups.read`
* `okta.logs.read`
* `okta.roles.read`
* `okta.apps.read`

Write scopes, only if you want the corresponding commands to work at all:

* `okta.users.manage`
* `okta.groups.manage`
* `okta.roles.manage`

**Granting read scopes only is a supported and sensible way to run this.** Everything in
the list above under "three things you get" works without a single write scope.

Assign the application an admin role. **Read Only Administrator** is enough for the read
scopes, and it is the right choice. Super Administrator would collapse the boundary this
module exists to create.

### 3. Store the credential

```
railcall set okta '{"org_url":"https://your.okta.com","client_id":"0oa...","key_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\n..."}'
```

The credential lives in the local Station vault. It is never sent to the marketplace and
never written to this repository.

### 4. Verify

Run `org.verify_connection`. It probes every scope you granted and names each missing
one alongside the exact commands it blocks, so the first run tells you what you can and
cannot do rather than failing later on the command you needed.

## Why OAuth and not an API token

Okta offers two ways for a machine to authenticate. They are not equivalent, and the
difference is the whole security argument of this module.

A static SSWS API token has **no scopes at all**. It inherits the full privileges of
whichever admin created it, it does not expire on its own, and anyone who copies the
string has everything it has. There is no way to say "this may only read users."

An OAuth service app using `private_key_jwt` is scoped, short lived, and authenticated
with a signature rather than a shared string. That gives you two independent boundaries
instead of one:

* The **OAuth scope grant** is structural. The token cannot deactivate a user unless an
  Okta admin granted `okta.users.manage`.
* The **RailCall airlock** is procedural. Even with the scope, a human approves the call.

Which is the point worth stating plainly: **if the airlock were bypassed entirely, a
read scoped token still could not deactivate anybody.**

Okta itself recommends against static API tokens. This module does not support them, on
purpose.

There is a third boundary, and we did not plan it. Current Okta orgs require **DPoP**
(RFC 9449) on the token endpoint, which binds the access token to a proof key. Okta
offers a switch to turn that requirement off. This module does not ask you to use it. A
token lifted from a log, a crash dump or a process listing cannot be replayed without the
private key that minted it, and a bearer token cannot express that.

```
ring 3   DPoP proof key        a stolen token is useless without the key
ring 2   OAuth scope grant     the token cannot deactivate without okta.users.manage
ring 1   the RailCall airlock  and even then, a human approves the call
```

## Trust surface

* Credentials resolve through the Station vault only. This module never reads a
  credentials file from disk.
* Network egress is allowlisted to your configured Okta org. A request to any other host
  is refused before it is sent.
* No subprocess. No filesystem writes. Both declared in `module.json`, where they are
  machine checkable rather than merely claimed.
* Secrets are redacted from every returned envelope and every error, including the ones
  raised by failures nobody planned for.
* Ambiguous outcomes fail closed. A write Okta does not answer is recorded as
  `unresolved`, carrying what was attempted and the prior state, and is reported as
  neither success nor failure.

## Command surface

### Implemented and verified live

**Posture**
* `org.verify_connection` probes every granted scope and names each missing one
  alongside the exact commands it blocks
* `org.rate_budget` reports remaining headroom per bucket, read from Okta's own
  response headers rather than from documentation

**Discovery**
* `users.find` filter based. A search result is marked advisory and carries
  `may_feed_write: false`, because Okta serves search from an eventually consistent
  datasource and a plan built on it can target state the approver never saw
* `users.get`, `users.list_access`, `users.list_live_credentials`
* `groups.find`, `groups.get_members`, both paged to completion

**Blast radius and access**
* `radius.user_deactivation` leads with what **survives** a deactivation, not what
  breaks, and names any group left with no owner
* `access.explain` answers why a user can reach an application: direct, through which
  group, or through which rule
* `access.rule_entanglement` reports whether removing a membership would also
  permanently modify a group rule

**Plan**
* `plan.group_membership`, `plan.deactivate_user`

### Still to come

The planned surface is thirty six, in six groups:

* **Posture and connection.** Scope probing, org description, standing admin inventory,
  rate limit headroom.
* **Discovery.** Users, groups, memberships, live sessions and tokens.
* **Blast radius and access explanation.** What breaks if this user is deactivated, what
  survives it, and why a given person can reach a given application at all.
* **Plan.** Every write has a planning twin that snapshots and fingerprints the exact
  state it intends to change.
* **Apply.** The writes. Each re reads, re hashes, and refuses if anything moved since
  the human approved it.
* **Custody, ledger and evidence.** Reconciliation against the System Log, and the signed
  evidence bundle.

There is deliberately no command that deletes a user. Deletion is permanent, it adds
nothing over deactivation for this use case, and shipping it would put the worst
available outcome one approved click away from an agent.

## Development

Lint against the real marketplace gate at any time. Free, and rate limited at sixty
calls a minute, unlike publishing which is capped at five an hour.

```
python tools/lint_listing.py
```

Run the offline contract tests:

```
python -m unittest discover tests
```

Probe a live org, read only, changing nothing:

```
python tools/live_probe.py
```

## Documentation

* `docs/SETUP.md` covers the Okta service app in detail, including generating the key
  pair locally so Okta never holds your private key.
* `docs/LIMITATIONS.md` records what this module cannot do and why.
* `docs/TESTING.md` records what has actually been run against a live org.

## License

MIT. See `LICENSE`.
