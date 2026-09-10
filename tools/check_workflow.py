"""Validate the workflow against the engine grammar and the publish gate.

Checks the things the gate does not, and the things the gate does but late:

  * every effect node points at an action_id this module actually produces,
    derived the way routes/modules.py derives it
  * no edge references a node that does not exist
  * every transform's Python compiles
  * no two nodes share an arg string of 20 or more characters, which the gate
    rejects as spec.duplicate_args. Note that identical context bindings across
    two genuinely different commands trip this too, so distinct nodes need
    distinct context keys.
"""

import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINT_URL = "https://railcall-marketplace-lggm.onrender.com/listings/lint"
DUPLICATE_ARG_THRESHOLD = 20


def action_id(command, slug):
    """Derive the action id the station will key this command by.

    Copied from the station's own `_module_provider_verb`, in
    `workbench/routes/modules.py`. Two things about it matter and both have
    bitten already.

    A per command `provider` field OVERRIDES the prefix. Setting `provider:
    okta` on every command once made `plan.group_membership` and
    `apply.group_membership` both resolve to `okta_group_membership`, so the
    plan and its apply became the same action. An earlier version of this
    function ignored that field, which meant the gate agreed with the manifest
    while the station disagreed, and it would have passed the exact defect it
    exists to catch.

    Remaining dots become underscores, so `probe.foo_bar` and `probe.foo.bar`
    also collide. `tools/station_check.py` is what refuses collisions; this
    function only has to derive the same id the station would.
    """
    cid = command["id"]
    parts = cid.split(".", 1)
    provider = command.get("provider") or (parts[0] if len(parts) == 2 else slug)
    verb = (parts[1] if len(parts) == 2 else cid).replace(".", "_")
    return provider + "_" + verb


def main():
    spec = json.loads(
        (ROOT / "workflow" / "quarterly_access_review.json").read_text(encoding="utf8")
    )
    manifest = json.loads((ROOT / "module.json").read_text(encoding="utf8"))
    description = (ROOT / "docs" / "workflow_description.txt").read_text(encoding="utf8").strip()

    slug = str(manifest.get("id", "")).split("/")[-1]
    ours = {action_id(c, slug) for c in manifest["commands"]}
    nodes = spec["nodes"]
    ids = {n["id"] for n in nodes}
    problems = []

    for node in nodes:
        if node.get("type") == "effect":
            if node.get("action_id") not in ours:
                problems.append(
                    node["id"] + " points at unknown action " + str(node.get("action_id"))
                )
        if node.get("type") == "transform":
            try:
                compile(node["code"], node["id"], "exec")
            except SyntaxError as err:
                problems.append(node["id"] + " transform does not compile: " + str(err))

    for edge in spec.get("edges") or []:
        for end in ("from", "to"):
            if edge[end] not in ids:
                problems.append("edge " + end + " references unknown node " + edge[end])

    shared = {}
    for node in nodes:
        for value in (node.get("args") or {}).values():
            if isinstance(value, str) and len(value) >= DUPLICATE_ARG_THRESHOLD:
                shared.setdefault(value, []).append(node["id"])
    for value, owners in shared.items():
        if len(owners) > 1:
            problems.append(
                "nodes " + ", ".join(owners) + " share the arg " + value
                + " which the gate rejects as duplicate_args"
            )

    effects = [n for n in nodes if n.get("type") == "effect"]
    writes = [n for n in effects if n.get("action_id", "").startswith("apply_")]
    print("nodes    :", len(nodes), "|", len(effects), "effect,",
          len(nodes) - len(effects), "transform")
    print("writes   :", len(writes), "->", [n["id"] for n in writes])
    print("edges    :", len(spec.get("edges") or []))
    print()

    if problems:
        print("LOCAL CHECKS FAILED")
        for problem in problems:
            print("  *", problem)
        return 1
    print("LOCAL CHECKS PASSED")

    body = json.dumps(
        {"listing_type": "workflow", "payload": spec,
         "description": description, "price_cents": 0}
    ).encode("utf8")
    request = urllib.request.Request(
        LINT_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        result = json.loads(urllib.request.urlopen(request, timeout=45).read())
    except urllib.error.HTTPError as err:
        print("gate refused:", err.code, err.read().decode("utf8", "replace")[:200])
        return 2
    except urllib.error.URLError as err:
        print("could not reach the gate:", err.reason)
        return 2

    print()
    print("GATE:", "PASS" if result.get("ok") else "FAIL",
          "errors=" + str(result.get("errorCount")),
          "warnings=" + str(result.get("warningCount")))
    for finding in result.get("findings") or []:
        print("  ", finding.get("severity"), "|", finding.get("code"))
        print("     ", finding.get("message"))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
