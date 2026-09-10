"""A scripted live demonstration, built for recording.

Runs against a real Okta org. Creates its own disposable fixtures, uses them, and
removes them, so the org is left as it was found. Never prints a credential.

Five acts, each runnable on its own so a fluffed take costs one act rather than
the whole recording:

    python tools/demo.py            all five, in order
    python tools/demo.py --act 3    just the drift refusal
    python tools/demo.py --cleanup  remove fixtures if a run was interrupted

Pauses between acts so a recording can be cut cleanly. --no-pause to disable.
"""

import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "handlers"))
import handler  # noqa: E402

FIXTURES = ROOT / ".secrets" / "demofixtures.json"
WIDTH = 74


def rule(char="="):
    print(char * WIDTH)


def title(number, text):
    print()
    rule()
    print("  ACT %s   %s" % (number, text))
    rule()
    print()


def say(text):
    print("  " + text)


def show(label, value):
    print("    {:<34} {}".format(label, value))


def pause(enabled):
    if enabled:
        print()
        input("  [enter to continue]")


def creds():
    entry = json.loads((ROOT / ".secrets" / "okta.json").read_text(encoding="utf8"))
    handler.vault_get = lambda name: entry
    return entry


def client():
    return handler.OktaClient(creds())


# ---------------------------------------------------------------- fixtures


def make_fixtures():
    c = client()
    stamp = time.strftime("%H%M%S")
    login = "demo.leaver.%s@example.com" % stamp
    status, _h, user = c.request("POST", "/users", query={"activate": "true"}, body={
        "profile": {"firstName": "Demo", "lastName": "Leaver",
                    "email": login, "login": login}})
    if status >= 400:
        raise SystemExit("could not create the demo user: " + json.dumps(user)[:200])
    second = "demo.colleague.%s@example.com" % stamp
    _s, _h, other = c.request("POST", "/users", query={"activate": "true"}, body={
        "profile": {"firstName": "Demo", "lastName": "Colleague",
                    "email": second, "login": second}})
    _s, _h, group = c.request("POST", "/groups", body={"profile": {
        "name": "Demo Finance %s" % stamp,
        "description": "Disposable, created for a demonstration."}})
    c.request("PUT", "/groups/%s/users/%s" % (group["id"], user["id"]))
    time.sleep(2)
    data = {"user_id": user["id"], "login": login,
            "other_id": other["id"], "other_login": second,
            "group_id": group["id"], "group_name": group["profile"]["name"]}
    FIXTURES.write_text(json.dumps(data, indent=2), encoding="utf8")
    return data


def load_fixtures():
    if not FIXTURES.exists():
        return make_fixtures()
    return json.loads(FIXTURES.read_text(encoding="utf8"))


def cleanup():
    if not FIXTURES.exists():
        print("  nothing to clean up")
        return
    f = json.loads(FIXTURES.read_text(encoding="utf8"))
    c = client()
    c.request("DELETE", "/groups/%s" % f["group_id"])
    for key in ("user_id", "other_id"):
        if f.get(key):
            c.request("POST", "/users/%s/lifecycle/deactivate" % f[key])
    FIXTURES.unlink()
    print("  fixtures removed, org left as found")


# ---------------------------------------------------------------- acts


def act_one():
    title(1, "What the module is allowed to do, and what it is not")
    say("First run against any org. Nothing is assumed.")
    print()
    data = handler.org_verify_connection({}, {})["data"]
    show("org", data["org_host"])
    show("auth", data["auth_method"])
    show("scopes granted", len(data["scopes_granted"]))
    print()
    say("An OAuth scope is only half a permission. The Okta admin role")
    say("assigned to the app is the other half, and it is probed separately.")
    print()
    for w in data["write_scopes"]:
        show(w["scope"], "granted=%s  role permits=%s  usable=%s" % (
            w["granted"], data["admin_role_permits_writes"], w["usable"]))
    print()
    show("commands blocked", len(data["blocked_commands"]))
    say("The first run tells you what you cannot do, rather than failing")
    say("later on the one command you needed.")


def act_two(f, real_user=False):
    title(2, "What survives a deactivation")
    say("Deactivating a leaver is assumed to remove their access.")
    say("Here is what it actually leaves behind.")
    print()
    # A read, so it changes nothing. The real account carries richer data than a
    # freshly created fixture, which makes the point better. --demo-user swaps to
    # the disposable one if the real login should stay off camera.
    target = f["user_id"]
    if real_user:
        target = handler.users_find({}, {})["data"]["users"][0]["id"]
    data = handler.radius_user_deactivation({"user_id": target}, {})["data"]
    show("user", data["user"]["login"])
    print()
    say("LOSES:")
    show("applications", data["lost"]["application_count"])
    print()
    say("SURVIVES:")
    for k, v in data["survives"].items():
        show(k, v)
    print()
    for group in data["groups_left_ownerless"]:
        show("group left ownerless", group["group_name"])
    print()
    say("There is no single off switch in Okta.")
    say("The module reports that rather than implying one.")


def act_three(f):
    title(3, "An approval binds to the state a human reviewed")
    say("Plan a removal. The plan fingerprints the exact state it depends on.")
    print()
    plan = handler.plan_group_membership(
        {"group_id": f["group_id"], "remove": [f["user_id"]]}, {})["data"]
    show("group", plan["preview"]["group_name"])
    show("members now", plan["preview"]["members_now"])
    show("will remove", len(plan["preview"]["will_remove"]))
    show("approved fingerprint", plan["fingerprint"][:32] + "...")
    print()
    say("A human approves that. Meanwhile, somebody else joins the group.")
    c = client()
    status, _h, _b = c.request(
        "PUT", "/groups/%s/users/%s" % (f["group_id"], f["other_id"]))
    show("colleague joins", "HTTP %s" % status)
    time.sleep(3)
    print()
    say("Now the approved change is applied.")
    print()
    try:
        handler.apply_group_membership(
            {"fingerprint": plan["fingerprint"], "intent": plan["intent"],
             "snapshot": plan["snapshot"]}, {})
        say("NOT REFUSED. That would be a bug.")
    except RuntimeError as err:
        text = str(err)
        say("REFUSED.")
        print()
        for line in _wrap(text.split(" | ")[0], 68):
            print("      " + line)
        detail = text.split(" | ", 1)[1] if " | " in text else ""
        if detail:
            try:
                d = json.loads(detail)
                print()
                show("approved fingerprint", d["approved_fingerprint"][:32] + "...")
                show("current fingerprint", d["current_fingerprint"][:32] + "...")
                for change in d.get("drifted", []):
                    show("changed field", change.get("field"))
                    if change.get("newly_present"):
                        show("  newly present", change["newly_present"])
            except (ValueError, KeyError):
                pass
    c.request("DELETE", "/groups/%s/users/%s" % (f["group_id"], f["other_id"]))
    print()
    say("The permission was for the situation a human looked at.")
    say("It was not a permission for a different one that arrived later.")


def act_four(f):
    title(4, "Where it cannot see, it says so")
    say("This org's admin role cannot read who holds administrative privilege.")
    print()
    data = handler.access_review_pack({"max_users": 5}, {})["data"]
    show("people reviewed", data["reviewed"])
    show("dormant", data["summary"]["dormant"])
    show("with standing admin", repr(data["summary"]["with_standing_admin"]))
    print()
    say("That is null, not zero.")
    say("'Nobody holds admin' and 'we are not permitted to see who holds")
    say("admin' are different answers, and only one of them is true.")


def act_five():
    title(5, "Proof, bounded by what was actually visible")
    say("Every change is reconciled against Okta's own System Log,")
    say("not against any record this module keeps.")
    print()
    data = handler.custody_detect_ungoverned({}, {})["data"]
    show("changes examined", data["events_examined"])
    show("verdicts", json.dumps(data["counts"]))
    show("log watermark", data["log_watermark"])
    show("log read complete", data["log_read_complete"])
    print()
    for line in _wrap(data["claim"], 68):
        print("      " + line)
    print()
    say("Visible as of a stated moment. Never a claim that none occurred.")


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--act", type=int)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--no-pause", action="store_true")
    parser.add_argument("--demo-user", action="store_true",
                        help="act 2 uses the disposable fixture instead of the "
                             "real account, to keep a real login off camera")
    args = parser.parse_args()

    if args.cleanup:
        creds(); cleanup(); return 0

    creds()
    print()
    rule()
    print("  OKTA ACCESS AIRLOCK")
    print("  36 commands. Running against a real Okta org.")
    rule()

    needs_fixtures = args.act in (2, 3) or args.act is None
    f = load_fixtures() if needs_fixtures else {}
    pausing = not args.no_pause

    acts = {1: lambda: act_one(), 2: lambda: act_two(f, not args.demo_user),
            3: lambda: act_three(f),
            4: lambda: act_four(f), 5: lambda: act_five()}
    order = [args.act] if args.act else [1, 2, 3, 4, 5]
    for i, n in enumerate(order):
        acts[n]()
        if i < len(order) - 1:
            pause(pausing)

    if args.act is None:
        print()
        rule()
        cleanup()
        rule()
    return 0


if __name__ == "__main__":
    sys.exit(main())
