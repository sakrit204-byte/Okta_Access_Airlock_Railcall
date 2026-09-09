# Setup

Target: a working `org.verify_connection` in under ten minutes, starting from nothing.

## 1. Get an Okta org

A free Okta developer org is enough and is what this module is developed against. Sign
up at `developer.okta.com/signup`. You get a real org with a real API, which is what the
module needs; there are no mocks anywhere in this project.

Your org URL looks like `https://dev-12345678.okta.com`. Note it down.

## 2. Create the API service application

In the Okta admin console:

1. Go to **Applications**, then **Create App Integration**.
2. Choose **API Services**.
3. Name it something you will recognise later, for example `RailCall Access Airlock`.
4. Create it, then open the application's **General** tab.

Now switch the client authentication method:

5. Under **Client Credentials**, choose **Edit**.
6. Set **Client authentication** to **Public key / Private key**.
7. Under **PUBLIC KEYS**, choose **Add key**, then **Generate new key**.
8. Okta shows you the private key **once**. Copy it in PEM form and keep it somewhere
   safe. It is never shown again, and it never gets uploaded anywhere by this module.
9. Save.

Record the **Client ID** from the General tab, and the **Key ID** (`kid`) shown next to
the public key you just added.

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

Write scopes, each of which enables a specific set of apply commands:

* `okta.users.manage` for suspend, unsuspend, unlock, deactivate, offboard, reset
  factors, and revoking live credentials
* `okta.groups.manage` for group membership and group sync
* `okta.roles.manage` for administrative role changes

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

`scopes` is optional. Leave it out and the module asks for every read scope it knows
about, then reports which ones Okta actually granted.

Store it:

```
railcall set okta '<the JSON above on one line>'
```

The credential stays in the local Station vault. It is never sent to the marketplace,
never written into this repository, and never included in a receipt.

## 6. Verify

```
railcall market install sakrit204/okta_access_airlock
railcall studio
```

Run `org.verify_connection`. A healthy result lists every scope you granted, confirms
each one with a real read against your org, and names any command that is unavailable.

## Troubleshooting

**`credential_missing`**
No `okta` entry in the vault. Step 5.

**`credential_invalid: private_key is not a readable PEM private key`**
The private key was pasted with literal `\n` sequences rather than real newlines, or the
BEGIN and END lines were lost. Re paste it, or store the JSON from a file rather than
typing it at a shell prompt.

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
