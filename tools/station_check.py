"""Verify the bundle against the RailCall station's real loading contract.

The marketplace linter checks the listing. This checks the thing that actually
runs. They are not the same gate, and passing the first tells you nothing about
the second.

What the station does, replicated here:

  * execs handlers/handler.py in a namespace carrying an injected
    `__rc_helpers__` dict, which is where `vault_get` lives. A module reaching
    for a bare global `vault_get` finds nothing.
  * resolves each command id to a function by `id.replace(".", "_")`, with no
    prefix of any kind.
  * calls it as `fn(inputs, stamp)`.
  * treats a returned dict as a SUCCESSFUL action. A handler that returns a
    failure envelope therefore has its failure written into a receipt that says
    it succeeded. Failures must raise.

Read from the installed station at ~/.railcall/station/workbench/routes/modules.py
on 2026-09-10. Re check after a station upgrade.

Usage:
    python tools/station_check.py           offline contract only
    python tools/station_check.py --live    also call one read against the org
"""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER_KEYS = ("vault_get", "jload", "jsave", "http_post_json", "airlock_payload_hash")


def load_namespace(vault_entry=None):
    """Exec the handler the way the station does, helpers injected."""
    handler_path = ROOT / "handlers" / "handler.py"
    source = handler_path.read_text(encoding="utf8")

    def vault_get(provider):
        if vault_entry is None:
            raise RuntimeError("no credential wired for this check")
        return vault_entry

    namespace = {
        "__name__": "railcall_module_station_check",
        "__file__": str(handler_path),
        "__rc_helpers__": {
            "vault_get": vault_get,
            "jload": lambda *a, **k: None,
            "jsave": lambda *a, **k: None,
            "http_post_json": lambda *a, **k: None,
            "airlock_payload_hash": lambda cmd, inputs: "stub",
        },
    }
    exec(compile(source, str(handler_path), "exec"), namespace)
    return namespace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    manifest = json.loads((ROOT / "module.json").read_text(encoding="utf8"))
    problems = []

    print("bundle  :", manifest.get("id"), "v" + str(manifest.get("version")))
    print("manifest:", "version", manifest.get("manifest_version"))
    print()

    # 1. manifest shape the station and the review queue expect
    print("== manifest contract ==")
    for field in ("id", "name", "manifest_version", "provider", "category",
                  "credential_spec", "allowed_destinations", "requires", "commands"):
        present = field in manifest
        print("  {:22} {}".format(field, "ok" if present else "MISSING"))
        if not present:
            problems.append("manifest is missing " + field)

    spec = manifest.get("credential_spec") or {}
    declared = set(spec.get("required") or []) | set(spec.get("optional") or [])
    print()

    # 2. the loader contract
    print("== loader contract ==")
    namespace = load_namespace()
    print("  handler execs cleanly in the station namespace")

    for command in manifest.get("commands") or []:
        cid = command["id"]
        fn_name = cid.replace(".", "_").replace("-", "_")
        fn = namespace.get(fn_name)
        if not callable(fn):
            problems.append(cid + " has no callable named " + fn_name)
            print("  {:32} MISSING {}".format(cid, fn_name))
            continue
        for field in ("mode", "risk", "preview", "receipt_required", "requires"):
            if field not in command:
                problems.append(cid + " is missing " + field)
        unknown = [r for r in (command.get("requires") or []) if r not in declared]
        if unknown:
            problems.append(cid + " requires undeclared credentials: " + ", ".join(unknown))
    print("  {} commands resolved to callables".format(len(manifest.get("commands") or [])))

    # 3. fail closed: a failing command must raise, not return
    print()
    print("== fail closed ==")
    probe = namespace.get("org_verify_connection")
    try:
        probe({}, {"call_id": "station_check", "source": "check"})
        problems.append("a command with no credential returned instead of raising")
        print("  RETURNED a value with no credential wired  <-- would be receipted as success")
    except Exception as err:
        print("  raises with no credential wired:", type(err).__name__)
        if "no credential wired" not in str(err) and "credential" not in str(err).lower():
            print("   message:", str(err)[:120])

    # 4. optional live call through the same path the station uses
    if args.live:
        print()
        print("== live call through the station contract ==")
        secret = ROOT / ".secrets" / "okta.json"
        if not secret.exists():
            print("  skipped, no .secrets/okta.json")
        else:
            entry = json.loads(secret.read_text(encoding="utf8"))
            live_ns = load_namespace(vault_entry=entry)
            result = live_ns["users_find"]({}, {"call_id": "station_check"})
            print("  users.find ->", result.get("status"),
                  "| users:", result.get("data", {}).get("count"))
            if not isinstance(result, dict):
                problems.append("a command returned a non dict, which the station cannot receipt")

    print()
    if problems:
        print("FAILED")
        for problem in problems:
            print("  *", problem)
        return 1
    print("PASSED: the bundle satisfies the station loading contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
