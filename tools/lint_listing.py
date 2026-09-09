"""Lint the bundle against the RailCall marketplace gate before publishing.

Linting is free and rate limited at 60 calls a minute. Publishing is capped at 5
an hour. Run this as often as you like; never spend a publish slot on something
the gate would have rejected.

Usage:
    python tools/lint_listing.py
    python tools/lint_listing.py --description docs/listing_description.txt
"""

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

LINT_URL = "https://railcall-marketplace-lggm.onrender.com/listings/lint"
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Established empirically against the live gate on 2026 09 09. The published
# tutorial disagrees with all three of these, so they are pinned here rather than
# rediscovered under deadline pressure.
PAYLOAD_MANIFEST_KEY = "module_json"
PAYLOAD_HANDLER_KEY = "handler_py"
MINIMUM_HANDLER_BYTES = 200

# The gate rejects a longer description with a bare HTTP 400 rather than a lint
# finding, so it is checked here first. Note that both Round 1 winning listings run
# well past this, at 5978 and 7540 characters, so the cap arrived after they
# published and their length is not a target we can match.
MAXIMUM_DESCRIPTION_CHARS = 4096


def load_bundle():
    manifest_path = ROOT / "module.json"
    handler_path = ROOT / "handlers" / "handler.py"
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    handler = handler_path.read_text(encoding="utf8")
    return manifest, handler


def local_checks(manifest, handler, description):
    """Catch the failures we can see without spending a network call."""
    problems = []
    commands = manifest.get("commands") or []

    if not commands:
        problems.append("module.json declares no commands")

    if len(handler.encode("utf8")) < MINIMUM_HANDLER_BYTES:
        problems.append("handler.py is under the 200 byte trivial handler threshold")

    if len(description) > MAXIMUM_DESCRIPTION_CHARS:
        problems.append(
            "description is "
            + str(len(description))
            + " characters, over the gate limit of "
            + str(MAXIMUM_DESCRIPTION_CHARS)
        )

    for command in commands:
        cid = command.get("id")
        if not cid:
            problems.append("a command entry has no id")
            continue
        if len(command.get("title") or "") < 3:
            problems.append(cid + " has no title of at least 3 characters")
        expected = cid.replace(".", "_").replace("-", "_")
        if ("def " + expected) not in handler and (expected + " =") not in handler:
            problems.append(cid + " has no function named " + expected)
        schema = command.get("input_schema")
        if schema is not None and not isinstance(schema, dict):
            problems.append(cid + " has an input_schema that is not an object")

    # The gate warns when a stated command count disagrees with the manifest, so
    # the count is derived here and never typed by hand.
    stated = str(len(commands))
    if description and stated not in description:
        problems.append(
            "the description does not state the actual command count of " + stated
        )

    return problems


def remote_lint(manifest, handler, description, price_cents):
    body = json.dumps(
        {
            "listing_type": "module",
            "payload": {
                PAYLOAD_MANIFEST_KEY: json.dumps(manifest),
                PAYLOAD_HANDLER_KEY: handler,
            },
            "description": description,
            "price_cents": price_cents,
        }
    ).encode("utf8")
    request = urllib.request.Request(
        LINT_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf8"))
    except urllib.error.HTTPError as err:
        return {"transport_error": err.code, "body": err.read().decode("utf8", "replace")}
    except urllib.error.URLError as err:
        return {"transport_error": str(err.reason)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--description", default="docs/listing_description.txt")
    parser.add_argument("--price-cents", type=int, default=0)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    manifest, handler = load_bundle()

    description_path = ROOT / args.description
    description = (
        description_path.read_text(encoding="utf8").strip()
        if description_path.exists()
        else manifest.get("description", "")
    )

    print("bundle   :", manifest.get("id"), "v" + str(manifest.get("version")))
    print("commands :", len(manifest.get("commands") or []))
    print("handler  :", len(handler.encode("utf8")), "bytes")
    print()

    problems = local_checks(manifest, handler, description)
    if problems:
        print("LOCAL CHECKS FAILED")
        for problem in problems:
            print("  *", problem)
    else:
        print("LOCAL CHECKS PASSED")

    if args.offline:
        return 1 if problems else 0

    print()
    result = remote_lint(manifest, handler, description, args.price_cents)
    if "transport_error" in result:
        print("could not reach the gate:", result["transport_error"])
        return 2

    findings = result.get("findings") or []
    print(
        "GATE:",
        "PASS" if result.get("ok") else "FAIL",
        "errors=" + str(result.get("errorCount")),
        "warnings=" + str(result.get("warningCount")),
    )
    for finding in findings:
        print("  ", finding.get("severity"), "|", finding.get("code"))
        print("     ", finding.get("message"))
        if finding.get("hint"):
            print("      fix:", finding["hint"])

    return 0 if (result.get("ok") and not problems) else 1


if __name__ == "__main__":
    sys.exit(main())
