"""Lock the manifest, the handler and the listing text to each other.

Reviewers ding "count drift" when a listing claims a number of commands the
manifest does not carry. That is cosmetic but avoidable, and avoiding it by hand
is exactly the kind of thing that rots. Nothing here is typed by a human.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    manifest = json.loads((ROOT / "module.json").read_text(encoding="utf8"))
    handler = (ROOT / "handlers" / "handler.py").read_text(encoding="utf8")
    listing = (ROOT / "docs" / "listing_description.txt").read_text(encoding="utf8")
    commands = manifest.get("commands") or []
    problems = []

    if str(len(commands)) not in listing:
        problems.append(
            "the listing does not state the actual command count of " + str(len(commands))
        )

    writes = [c for c in commands if c.get("mode") == "write_requires_approval"]
    reads = [c for c in commands if c.get("mode") == "read"]
    if len(writes) + len(reads) != len(commands):
        problems.append("some commands declare neither read nor write_requires_approval")

    for command in commands:
        name = command["id"].replace(".", "_").replace("-", "_")
        if ("def " + name + "(") not in handler:
            problems.append(command["id"] + " has no literal def named " + name)
        if command.get("side_effects") == "external" and command.get("mode") != "write_requires_approval":
            problems.append(command["id"] + " has external effects but is not approval gated")

    declared = set((manifest.get("credential_spec") or {}).get("required") or [])
    for command in commands:
        missing = [r for r in (command.get("requires") or []) if r not in declared]
        if missing:
            problems.append(command["id"] + " requires undeclared credentials: " + ", ".join(missing))

    # verify_connection is the first run experience. If it names a command that
    # does not exist, or omits one it really does block, it is lying at exactly
    # the moment a buyer is deciding whether to trust the module.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "h", ROOT / "handlers" / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    real = {c["id"] for c in commands}
    named = set()
    for probe in module.SCOPE_PROBES.values():
        named.update(probe["blocks"])
    for cmds in module.WRITE_SCOPES.values():
        named.update(cmds)
    ghosts = sorted(named - real)
    if ghosts:
        problems.append(
            "the scope tables name commands that do not exist: " + ", ".join(ghosts)
        )
    writes_named = set()
    for cmds in module.WRITE_SCOPES.values():
        writes_named.update(cmds)
    real_writes = {c["id"] for c in commands if c.get("mode") != "read"}
    unlisted = sorted(real_writes - writes_named)
    if unlisted:
        problems.append(
            "these writes are in no write scope table: " + ", ".join(unlisted)
        )

    if manifest.get("irreversible_effects") is None:
        problems.append("irreversible_effects is not declared")

    print("commands :", len(commands), "=", len(reads), "read +", len(writes), "write")
    print("listing  :", len(listing.strip()), "characters")
    print("irreversible_effects:", manifest.get("irreversible_effects"))
    print()

    if problems:
        print("PARITY FAILED")
        for problem in problems:
            print("  *", problem)
        return 1
    print("PARITY OK: manifest, handler and listing agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
