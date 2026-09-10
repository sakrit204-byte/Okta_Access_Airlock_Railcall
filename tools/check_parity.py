"""Lock the manifest, the handler and the listing text to each other.

Reviewers ding "count drift" when a listing claims a number of commands the
manifest does not carry. That is cosmetic but avoidable, and avoiding it by hand
is exactly the kind of thing that rots. Nothing here is typed by a human.
"""

import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
    8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
    14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
    19: "nineteen", 20: "twenty",
}


def _readme_counts(problems, commands, reads, writes):
    """The README states counts in prose. Prose goes stale silently, so it is checked.

    Every number here was wrong at least once during the build: the test count sat at
    77 after the suite reached 85, and LIMITATIONS was cited as sixteen entries when it
    held eighteen. A reviewer who checks one number and finds it wrong stops trusting
    the rest, which is the whole cost of this file being out of date.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf8")

    limitations = (ROOT / "docs" / "LIMITATIONS.md").read_text(encoding="utf8")
    entries = len(re.findall(r"^#{2,3}\s*\d+[\.\s]", limitations, re.M))
    word = WORDS.get(entries, str(entries))
    if ("%s entries" % word) not in readme and ("%d entries" % entries) not in readme:
        problems.append(
            "README does not say LIMITATIONS holds %d entries (expected \"%s entries\")"
            % (entries, word)
        )

    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"))
    if loader.errors:
        problems.append("tests could not be counted: " + str(loader.errors[0])[:120])
    else:
        total = suite.countTestCases()
        if ("%d offline contract tests" % total) not in readme:
            problems.append(
                "README states the wrong test count; the suite holds %d" % total
            )

    expected = "%d commands. %d read, %d write" % (
        len(commands), len(reads), len(writes))
    if expected.lower() not in readme.lower():
        problems.append("README does not state the command split as \"%s\"" % expected)

    testing = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf8")
    defects = len(re.findall(r"\*\*Defect found|and the probe caught it\.\*\*", testing))
    word = WORDS.get(defects, str(defects))
    if ("%s defects" % word) not in readme and ("%d defects" % defects) not in readme:
        problems.append(
            "README does not say the live run exposed %d defects (TESTING.md records %d)"
            % (defects, defects)
        )

    workflow = json.loads(
        (ROOT / "workflow" / "quarterly_access_review.json").read_text(encoding="utf8"))
    nodes = len(workflow.get("nodes", []))
    if ("%d nodes" % nodes) not in readme:
        problems.append("README does not state the workflow as %d nodes" % nodes)


# Built by code point so this file does not trip its own check.
DASHES = (chr(0x2014), chr(0x2013))


def _house_style(problems):
    """No em dashes or en dashes anywhere in the bundle.

    A house rule, not a marketplace one. It is here rather than in a style guide
    because a rule nobody checks is a rule that lasts until the next hurried edit.
    """
    offenders = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in (".md", ".txt", ".py", ".json"):
            continue
        if ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if DASHES[0] in line or DASHES[1] in line:
                offenders.append("%s:%d" % (path.relative_to(ROOT).as_posix(), number))
    if offenders:
        problems.append(
            "em or en dash in %d place(s): %s"
            % (len(offenders), ", ".join(offenders[:6]))
        )


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

    _readme_counts(problems, commands, reads, writes)
    _house_style(problems)

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
