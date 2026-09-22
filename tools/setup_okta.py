"""Set the Okta application up without the private key ever leaving this machine.

Okta will happily generate the signing key for you and show it to you once. That
is the easy path and it is the wrong one: Okta then holds the private half, and
the boundary this module is built on gets quietly weaker before it has run once.

This does it the other way round. The key pair is generated here, the private
half is written to a file you control, and only the public half, as a JWK, is
pasted into Okta.

    python tools/setup_okta.py keygen
        Generate the pair. Prints the JWK to paste into Okta, and the key id.

    python tools/setup_okta.py fields --org-url URL --client-id ID
        Print the four values to paste into Studio, Integrations, okta.
        The private key is read from the file and never displayed in full.

    python tools/setup_okta.py verify --org-url URL --client-id ID
        Call org.verify_connection for real and report what Okta actually
        granted: every scope, whether the admin role permits writes, and which
        commands are unavailable and why.

Nothing here talks to the marketplace, and nothing writes into the station.
"""

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_KEY = ROOT / ".secrets" / "okta_private_key.pem"


def _b64url(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def keygen(args):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    out = pathlib.Path(args.key_file)
    if out.exists() and not args.force:
        print("refusing to overwrite an existing key at", out)
        print("pass --force only if you are certain nothing uses it.")
        return 1

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pem)
    try:
        os.chmod(out, 0o600)
    except (OSError, NotImplementedError):
        pass

    numbers = key.public_key().public_numbers()
    key_id = args.key_id or ("railcall-" + _b64url(os.urandom(6)))
    jwk = {
        "kty": "RSA",
        "kid": key_id,
        "alg": "RS256",
        "use": "sig",
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
    }

    print("private key written to", out)
    if os.name == "nt":
        print("  On Windows the POSIX mode is not enforced; the file inherits the")
        print("  profile directory's ACL, which means local administrators can read")
        print("  it. Keep it where you would keep any other private key.")
    print()
    print("Paste this into Okta: Applications, your API Services app, Client")
    print("Credentials, Edit, Client authentication = Public key / Private key,")
    print("PUBLIC KEYS, Add key, then the JSON tab:")
    print()
    print(json.dumps(jwk, indent=2))
    print()
    print("key id (the kid Okta will show next to the key):", key_id)
    print()
    print("Okta never sees the private half. Next:")
    print("  python tools/setup_okta.py fields --org-url <your org> --client-id <id>")
    return 0


def _credential(args):
    key_file = pathlib.Path(args.key_file)
    if not key_file.exists():
        print("no private key at", key_file)
        print("run: python tools/setup_okta.py keygen")
        return None
    pem = key_file.read_text(encoding="utf8")
    key_id = args.key_id
    if not key_id:
        print("--key-id is required; it is the kid shown next to the public key in Okta")
        return None
    cred = {
        "OKTA_ORG_URL": args.org_url.rstrip("/"),
        "OKTA_CLIENT_ID": args.client_id,
        "OKTA_KEY_ID": key_id,
        "OKTA_PRIVATE_KEY": pem,
    }
    if getattr(args, "scopes", None):
        cred["OKTA_SCOPES"] = args.scopes
    return cred


def _every_known_scope():
    """Read and write, so a verification reports what Okta really granted.

    With no scopes configured the module asks only for the read scopes it knows.
    That is the right default for the module and the wrong one for a check: a
    user who granted the write scopes would be told their writes are
    unavailable, because nobody ever asked for them.
    """
    sys.path.insert(0, str(ROOT / "handlers"))
    import handler
    return list(handler.SCOPE_PROBES.keys()) + list(handler.WRITE_SCOPES.keys())


def fields(args):
    cred = _credential(args)
    if cred is None:
        return 1
    print("Studio, Integrations, okta:")
    print()
    for name in ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_KEY_ID"):
        print("  %-18s %s" % (name, cred[name]))
    body = cred["OKTA_PRIVATE_KEY"]
    print("  %-18s %s" % ("OKTA_PRIVATE_KEY", "the full contents of " + str(args.key_file)))
    print()
    print("  If you granted write scopes in Okta, add the optional fifth field, or")
    print("  every apply command will fail. With it unset the module asks only for")
    print("  the read scopes, so a granted write scope is never requested:")
    print()
    print("  %-18s %s" % ("OKTA_SCOPES", " ".join(_every_known_scope())))
    print()
    print("  The key is %d characters and begins %r. Paste it whole, including the"
          % (len(body), body.splitlines()[0] if body else ""))
    print("  BEGIN and END lines and real newlines. A key pasted with literal")
    print("  backslash n is the commonest setup failure and reports as")
    print("  credential_invalid.")
    print()
    print("Then: python tools/setup_okta.py verify --org-url %s --client-id %s --key-id %s"
          % (cred["OKTA_ORG_URL"], cred["OKTA_CLIENT_ID"], cred["OKTA_KEY_ID"]))
    return 0


def verify(args):
    cred = _credential(args)
    if cred is None:
        return 1
    sys.path.insert(0, str(ROOT / "handlers"))
    import handler

    if "OKTA_SCOPES" not in cred:
        cred["OKTA_SCOPES"] = " ".join(_every_known_scope())
        asked_for_everything = True
    else:
        asked_for_everything = False

    handler.vault_get = lambda name: cred
    try:
        result = handler.org_verify_connection({}, {})
    except RuntimeError as err:
        if asked_for_everything:
            # Some orgs refuse the whole grant when an ungranted scope is asked
            # for. Fall back to reads so the check still reports something.
            print("Asking for every scope was refused; retrying with reads only.")
            cred["OKTA_SCOPES"] = " ".join(handler.SCOPE_PROBES.keys())
            try:
                result = handler.org_verify_connection({}, {})
            except RuntimeError as second:
                err = second
            else:
                print("Reads alone were accepted. If you granted write scopes,")
                print("Okta refused to issue them; check the app's Okta API Scopes tab.")
                print()
                return _report(result)
        print("verify_connection refused:")
        print(" ", str(err)[:400])
        print()
        print("A token_denied here usually means one of: client authentication is")
        print("still set to client secret, the key id does not match the public key")
        print("you added, no admin role is assigned to the application, or this")
        print("machine's clock disagrees with Okta by more than five minutes.")
        return 1

    return _report(result)


def _report(result):
    data = result["data"]
    print("org           ", data["org_host"])
    print("auth          ", data["auth_method"])
    print("scopes granted", len(data["scopes_granted"]))
    for scope in sorted(data["scopes_granted"]):
        print("   ", scope)
    print()
    for probe in data["read_scope_probes"]:
        if not probe.get("verified") and probe.get("granted"):
            print("  granted but refused:", probe["scope"], probe.get("provider_message") or "")
    role = data["admin_role_permits_writes"]
    print("admin role permits writes:", "unknown" if role is None else role)
    for entry in data["write_scopes"]:
        print("   %-22s granted=%-5s usable=%s" % (entry["scope"], entry["granted"], entry["usable"]))
    blocked = data["blocked_commands"]
    print()
    if blocked:
        print("%d commands unavailable with this grant:" % len(blocked))
        for command in blocked:
            print("   ", command)
        print()
        print("That is a report, not a failure. Read scopes alone are a supported")
        print("way to run this module.")
    else:
        print("No commands are blocked. Every one of the 36 is available.")
    for warning in result.get("warnings") or []:
        print()
        print("warning:", warning)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, need_org=True):
        p.add_argument("--key-file", default=str(DEFAULT_KEY))
        p.add_argument("--key-id", default=None)
        p.add_argument("--scopes", default=None,
                       help="space separated; verify defaults to every scope the module knows")
        if need_org:
            p.add_argument("--org-url", required=True)
            p.add_argument("--client-id", required=True)
        return p

    g = sub.add_parser("keygen", help="generate the pair here, print the public JWK")
    common(g, need_org=False)
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=keygen)

    f = sub.add_parser("fields", help="the four values to paste into Studio")
    common(f)
    f.set_defaults(func=fields)

    v = sub.add_parser("verify", help="call org.verify_connection for real")
    common(v)
    v.set_defaults(func=verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
