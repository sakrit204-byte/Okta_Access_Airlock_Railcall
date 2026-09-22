# Setup

Target: a working `org.verify_connection` in under ten minutes, starting from nothing.

## 1. Get an Okta org

A free Okta developer org is enough and is what this module is developed against. Sign
up at `developer.okta.com/signup`. You get a real org with a real API, which is what the
module needs; there are no mocks anywhere in this project.

Your org URL looks like `https://dev-12345678.okta.com`. Note it down. EMEA orgs sit on
`okta-emea.com` and preview orgs on `oktapreview.com`; the module accepts all three.

## 2. Create the API service application

In the Okta admin console:

1. Go to **Applications**, then **Create App Integration**.
2. Choose **API Services**.
3. Name it something you will recognise later, for example `RailCall Access Airlock`.
4. Create it, then open the application's **General** tab.

Now switch the client authentication method:

5. Under **Client Credentials**, choose **Edit**.
6. Set **Client authentication** to **Public key / Private key**.

Okta offers to generate the signing key for you. Do not take it. Okta would then hold
the private half, and the boundary this whole module rests on gets weaker before it has
run once. Generate the pair on your own machine instead:

```
python tools/setup_okta.py keygen
```

That writes the private half to `.secrets/okta_private_key.pem`, which never leaves your
machine and is excluded from the signed module tree, and prints the public half as a JWK
along with the key id it generated.

7. Under **PUBLIC KEYS**, choose **Add key**, then the **JSON** tab.
8. Paste the JWK the command printed. Save.

Okta now holds only the public half. Record the **Client ID** from the General tab; the
**Key ID** is the `kid` the command printed, and Okta will show the same value next to
the key.

If you would rather use Okta's **Generate new key** button, the module works the same
way. Copy the PEM Okta shows you once, save it as `.secrets/okta_private_key.pem`, and
carry on. You are accepting that Okta generated and displayed your private key.

## 3. Grant scopes

Still in the application, open the **Okta API Scopes** tab and grant what you want this
module to be able to do. Nothing here is required; granting less simply means fewer
commands work, and `org.verify_connection` will tell you exactly which ones.

Read scopes, which cover discovery, blast radius and custody:

* `okta.users.read`
* `okta.groups.read`
* `okta.logs.read`
* `okta.roles.read`
* `okta.apps.read`

Write scopes. There are two, and that is the complete list:

* `okta.users.manage` for suspend, unsuspend, unlock, deactivate, offboard, reset
  factors, and revoking live credentials
* `okta.groups.manage` for group membership and group sync

The module never asks for `okta.roles.manage`. It reads administrative role assignments
to measure blast radius and reconciles role changes from the System Log, but it does not
change them, so granting that scope would hand it a power it has no command for. Grant
it only if some other integration in the same application needs it.

**Start with read scopes only.** Run the module, look at what it reports, and add write
scopes when you have decided you want them. That order is the whole point of the
product, and the module is designed to be useful with no write scopes at all.

## 4. Admin role for the service app

An API service application also needs an administrator role before Okta will honour the
scopes. In **Admin roles** on the application, assign the narrowest role that covers
what you granted. Read only administrator is enough for the read scopes.

Avoid Super Administrator. If you assign it, the OAuth scope grant stops being a
meaningful second boundary, and you have given up the outer ring described in the
README for no benefit.

## 5. Store the credential in the Station vault

The module reads exactly one vault entry, named `okta`. It is a JSON object:

```
{
  "org_url": "https://dev-12345678.okta.com",
  "client_id": "0oa1a2b3c4d5e6f7g8h9",
  "key_id": "the kid of the public key you added",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
  "scopes": "okta.users.read okta.groups.read okta.logs.read okta.roles.read okta.apps.read"
}
```

`scopes` is optional, and the default is read only. Leave it out and the module asks
for the five read scopes and nothing else, so **a write scope you granted in step 3 is
never requested and every apply command fails**. If you granted write scopes, set the
field explicitly and list them:

```
"scopes": "okta.users.read okta.groups.read okta.logs.read okta.roles.read okta.apps.read okta.users.manage okta.groups.manage"
```

Okta issues the intersection of what you ask for and what you granted, so asking for a
scope you have not granted costs you nothing but that scope.

Store it through Studio. Run `railcall studio`, open **Integrations**, find **okta**, and
paste the values into the form the module declares: `OKTA_ORG_URL`, `OKTA_CLIENT_ID`,
`OKTA_KEY_ID`, `OKTA_PRIVATE_KEY`, and `OKTA_SCOPES` if you granted writes. To have
those printed for you, ready to paste:

```
python tools/setup_okta.py fields --org-url https://dev-12345678.okta.com --client-id 0oa... --key-id <kid>
```

It reads the PEM from the file and prints its length and first line rather than the key
itself. The station writes them to its
local vault with owner only permissions. There is no CLI setter for module credentials;
`railcall set` only knows the station's own settings and answers `Unknown setting` for
anything else.

The credential stays in the local Station vault. It is never sent to the marketplace,
never written into this repository, and never included in a receipt.

## 6. Verify

```
railcall market install sakrit204/okta-access-airlock
railcall studio
```

Run `org.verify_connection`. A healthy result lists every scope you granted, confirms
each one with a real read against your org, and names any command that is unavailable.

You can run the same check from a terminal before you touch Studio at all, which is the
fastest way to find a setup mistake:

```
python tools/setup_okta.py verify --org-url https://dev-12345678.okta.com --client-id 0oa... --key-id <kid>
```

It calls the real command against your real org, asks for every scope the module knows
so nothing is under reported, and prints what Okta granted, whether your admin role
permits writes, and which commands are blocked and why.

## Troubleshooting

**`credential_missing`**
No `okta` entry in the vault. Step 5.

**`credential_invalid: private_key is not a readable PEM private key`**
The private key was pasted with literal `\n` sequences rather than real newlines, or the
BEGIN and END lines were lost. Re paste it, or store the JSON from a file rather than
typing it at a shell prompt.

**Writes fail with an insufficient scope error even though I granted the write scopes**
The `scopes` field was left out, so the module only asked for the read scopes. Step 5.

**`token_denied`**
Okta refused the client credentials grant. The usual causes are a client authentication
method still set to client secret rather than public key, a `key_id` that does not match
the public key you added, or no administrator role assigned to the application. The
error detail carries Okta's own message.

**`egress_blocked`**
The module tried to reach a host other than your configured org and refused. If you see
this in normal use it is a bug worth reporting, because it should not be reachable.

**The installer cannot find Python**
On Windows, `python` may resolve to the Microsoft Store placeholder at
`AppData\Local\Microsoft\WindowsApps\python`, which is not Python. Install Python 3 from
python.org with the PATH option ticked, or `winget install Python.Python.3.12`, then
confirm `python --version` reports a real version.
