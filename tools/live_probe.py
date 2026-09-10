"""Phase 1 spike. Answers the open questions against a real Okta org.

This script is strictly read only. It issues no POST, PUT, PATCH or DELETE against
your org, so it cannot change anything. It exists to replace assumptions with
measurements before any write path is designed on top of them.

It never prints a secret. The credential is read from .secrets/okta.json, which is
gitignored, and every printed structure passes through the same redaction the module
itself uses.

Usage:
    python tools/live_probe.py
    python tools/live_probe.py --out live_findings.json
"""

import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "handlers"))

import handler  # noqa: E402

CREDENTIAL_PATH = ROOT / ".secrets" / "okta.json"

RATE_HEADER_NAMES = (
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
)

# Each probe is a question the walkthrough listed as unanswered, paired with the
# cheapest read that settles it.
FEATURE_PROBES = (
    ("users_readable", "/users", {"limit": "1"}),
    ("groups_readable", "/groups", {"limit": "1"}),
    ("group_rules_available", "/groups/rules", {"limit": "1"}),
    ("apps_readable", "/apps", {"limit": "1"}),
    ("system_log_readable", "/logs", {"limit": "1"}),
    ("iam_roles_readable", "/iam/roles", None),
    ("resource_sets_available", "/iam/resource-sets", None),
    ("api_tokens_visible", "/api-tokens", None),
)


def load_credential():
    if not CREDENTIAL_PATH.exists():
        print("No credential found at", CREDENTIAL_PATH.relative_to(ROOT))
        print()
        print("Create it with this shape, then run again:")
        print(
            json.dumps(
                {
                    "org_url": "https://dev-12345678.okta.com",
                    "client_id": "0oa...",
                    "key_id": "the kid of your public key",
                    "private_key": "-----BEGIN PRIVATE KEY-----\\n...",
                },
                indent=2,
            )
        )
        print()
        print("That directory is gitignored. Nothing in it is committed or printed.")
        raise SystemExit(2)
    return json.loads(CREDENTIAL_PATH.read_text(encoding="utf8"))


def probe_scopes(client, findings):
    print("== token and scopes ==")
    try:
        client.access_token()
    except handler.AirlockError as err:
        print("  grant refused:", err.code, "|", err.message)
        detail = err.detail or {}
        print("  http status:", detail.get("http_status"))
        response = detail.get("response") or {}
        if isinstance(response, dict):
            for key in ("error", "error_description", "errorSummary", "errorCode"):
                if response.get(key):
                    print("  okta says:", key, "=", response[key])
        # Keyed "grant" rather than "token": the redaction pass strips any key
        # named token, which would hide this diagnostic from the findings file.
        findings["grant"] = {"ok": False, "code": err.code, "detail": detail}
        return False
    granted = client.granted_scopes
    findings["grant"] = {"ok": True, "granted_scopes": granted}
    print("  granted:", " ".join(granted) if granted else "(none reported)")
    print()
    return True


def probe_features(client, findings):
    print("== feature availability ==")
    results = {}
    for name, path, query in FEATURE_PROBES:
        try:
            status, headers, body = client.request("GET", path, query=query)
        except handler.AirlockError as err:
            results[name] = {"error": err.code, "message": err.message}
            print("  {:26} error {}".format(name, err.code))
            continue
        available = status < 400
        entry = {"path": path, "http_status": status, "available": available}
        if not available:
            entry["provider_message"] = handler._provider_message(body)
        elif isinstance(body, list):
            entry["returned_items"] = len(body)
        results[name] = entry
        note = "ok" if available else str(status) + " " + str(entry.get("provider_message"))
        print("  {:26} {}".format(name, note))
    findings["features"] = results
    print()


def probe_rate_headers(client, findings):
    """Which accounting headers does this org actually return, and per which bucket."""
    print("== rate limit headers ==")
    observed = {}
    for path in ("/users", "/groups", "/logs", "/apps"):
        try:
            _status, headers, _body = client.request("GET", path, query={"limit": "1"})
        except handler.AirlockError as err:
            observed[path] = {"error": err.code}
            continue
        present = {name: headers.get(name) for name in RATE_HEADER_NAMES if headers.get(name)}
        observed[path] = present or {"note": "no rate limit headers returned"}
        print("  {:10} {}".format(path, present or "none"))
    findings["rate_headers"] = observed
    findings["rate_budget_snapshot"] = client.budget.snapshot()
    print()


def probe_log_latency(client, findings, samples=3, gap_seconds=10):
    """Measure how far behind the System Log is running right now.

    This is not a guarantee and cannot become one: Okta publishes no maximum
    delivery latency. It is a measurement of one org at one moment, which is more
    useful to a reader than silence, and it is reported as exactly that.
    """
    print("== system log watermark ==")
    readings = []
    for index in range(samples):
        try:
            status, _headers, body = client.request(
                "GET", "/logs", query={"limit": "1", "sortOrder": "DESCENDING"}
            )
        except handler.AirlockError as err:
            print("  reading failed:", err.code)
            break
        if status >= 400 or not isinstance(body, list) or not body:
            print("  no events returned (http", status, ")")
            break
        published = body[0].get("published")
        lag = _lag_seconds(published)
        readings.append({"published": published, "lag_seconds": lag})
        print("  newest event", published, "| behind now by", lag, "seconds")
        if index < samples - 1:
            time.sleep(gap_seconds)
    findings["log_watermark"] = {
        "readings": readings,
        "note": (
            "A measurement of one org at one moment. Okta publishes no maximum "
            "delivery latency, so this can never become a guarantee."
        ),
    }
    print()


def _lag_seconds(published):
    if not published:
        return None
    try:
        stamp = published.replace("Z", "").split(".")[0]
        parsed = time.strptime(stamp, "%Y-%m-%dT%H:%M:%S")
        return int(time.time() - time.mktime(parsed) + time.timezone)
    except (ValueError, TypeError):
        return None


def probe_paging(client, findings):
    """Confirm how Okta signals more pages, since it is Link headers rather than offsets."""
    print("== paging mechanics ==")
    try:
        _status, headers, body = client.request("GET", "/users", query={"limit": "1"})
    except handler.AirlockError as err:
        findings["paging"] = {"error": err.code}
        print("  failed:", err.code)
        print()
        return
    link = headers.get("Link") or headers.get("link")
    findings["paging"] = {
        "link_header_present": bool(link),
        "link_header": link,
        "items_returned": len(body) if isinstance(body, list) else None,
    }
    print("  link header:", "present" if link else "absent")
    if link:
        print("  ", link[:300])
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="live_findings.json")
    parser.add_argument("--log-samples", type=int, default=3)
    args = parser.parse_args()

    creds = load_credential()
    client = handler.OktaClient(creds)

    findings = {
        "probed_at": handler._now_iso(),
        "org_host": client.host,
        "read_only": True,
    }
    print("probing", client.host, "read only, nothing will be changed")
    print()

    if probe_scopes(client, findings):
        probe_features(client, findings)
        probe_rate_headers(client, findings)
        probe_paging(client, findings)
        probe_log_latency(client, findings, samples=args.log_samples)

    out = ROOT / args.out
    out.write_text(json.dumps(handler._redact(findings), indent=2), encoding="utf8")
    print("findings written to", out.relative_to(ROOT))
    print("Copy the answers into docs/TESTING.md and docs/LIMITATIONS.md.")


if __name__ == "__main__":
    main()
