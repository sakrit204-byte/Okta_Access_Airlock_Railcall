"""Okta Access Airlock.

Governed Okta administration for RailCall. Every command in this module resolves
credentials from the local Station vault, reaches exactly one host, redacts secrets
from everything it returns, and fails closed when an outcome cannot be determined.
"""

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MODULE_ID = "sakrit204/okta_access_airlock"
VAULT_NAME = "okta"
API_PREFIX = "/api/v1"
TOKEN_PATH = "/oauth2/v1/token"
HTTP_TIMEOUT_SECONDS = 30
TOKEN_LIFETIME_SECONDS = 300
TOKEN_REFRESH_MARGIN_SECONDS = 30

SECRET_KEYS = (
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "access_token",
    "authorization",
    "assertion",
    "token",
)

REDACTED = "[redacted]"


class AirlockError(Exception):
    """Raised for every condition this module refuses to guess about."""

    def __init__(self, code, message, detail=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


# Each entry maps an OAuth scope to a cheap read that proves the scope was granted,
# plus the command ids that become unusable without it. verify_connection reports
# both, so a missing grant is named alongside what it costs.
SCOPE_PROBES = {
    "okta.users.read": {
        "method": "GET",
        "path": "/users",
        "query": {"limit": "1"},
        "blocks": [
            "users.find",
            "users.get",
            "users.list_access",
            "users.list_live_credentials",
            "radius.user_deactivation",
            "access.explain",
            "access.review_pack",
        ],
    },
    "okta.groups.read": {
        "method": "GET",
        "path": "/groups",
        "query": {"limit": "1"},
        "blocks": [
            "groups.find",
            "groups.get_members",
            "radius.group_deletion",
            "access.rule_entanglement",
        ],
    },
    "okta.logs.read": {
        "method": "GET",
        "path": "/logs",
        "query": {"limit": "1"},
        "blocks": [
            "custody.report",
            "custody.detect_ungoverned",
            "custody.reconcile_unresolved",
            "custody.audit_pack",
        ],
    },
    "okta.roles.read": {
        "method": "GET",
        "path": "/iam/roles",
        "query": {"limit": "1"},
        "blocks": ["org.list_admins", "plan.role_change"],
    },
    "okta.apps.read": {
        "method": "GET",
        "path": "/apps",
        "query": {"limit": "1"},
        "blocks": ["access.explain", "radius.group_deletion"],
    },
}

WRITE_SCOPES = {
    "okta.users.manage": [
        "apply.suspend_user",
        "apply.unsuspend_user",
        "apply.unlock_user",
        "apply.deactivate_user",
        "apply.offboard_user",
        "apply.reset_factors",
        "apply.revoke_live_credentials",
    ],
    "okta.groups.manage": ["apply.group_membership", "apply.group_sync"],
    "okta.roles.manage": ["apply.role_change"],
}


def _redact(value):
    """Recursively strip anything that could carry a credential."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower().replace("_", "") in {
                k.replace("_", "") for k in SECRET_KEYS
            }:
                out[key] = REDACTED
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and value.startswith("Bearer "):
        return REDACTED
    return value


def _ok(command, data, warnings=None):
    envelope = {
        "status": "ok",
        "command": command,
        "data": _redact(data),
    }
    if warnings:
        envelope["warnings"] = warnings
    return envelope


def _fail(command, code, message, detail=None):
    return {
        "status": "failed",
        "command": command,
        "error": {
            "code": code,
            "message": message,
            "detail": _redact(detail or {}),
        },
    }


def _unresolved(command, code, message, attempted=None, prior_state=None):
    """The third outcome. Used when Okta gave no answer we can trust.

    Never collapse this into success or failure: the whole point is that the
    question stays open and answerable later by custody.reconcile_unresolved.
    """
    return {
        "status": "unresolved",
        "command": command,
        "error": {"code": code, "message": message},
        "attempted": _redact(attempted or {}),
        "prior_state": _redact(prior_state or {}),
        "recorded_at": _now_iso(),
    }


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _vault_credentials():
    """Resolve credentials through the Station vault and nowhere else.

    Reading a credentials file directly is a review failure and, more to the point,
    would put the private key somewhere this module does not control.
    """
    resolver = globals().get("vault_get")
    if resolver is None:
        raise AirlockError(
            "vault_unavailable",
            "vault_get is not available in this runtime. Configure the okta "
            "credential through Station before running any command.",
        )
    creds = resolver(VAULT_NAME)
    if not isinstance(creds, dict) or not creds:
        raise AirlockError(
            "credential_missing",
            "No okta credential found in the Station vault.",
        )
    return creds


def _require(creds, field):
    value = creds.get(field)
    if not value:
        raise AirlockError(
            "credential_incomplete",
            "The okta credential is missing the required field " + field + ".",
            {"missing_field": field},
        )
    return value


def _org_host(creds):
    """Return the single host this module is permitted to reach."""
    raw = _require(creds, "org_url").strip()
    if not raw.startswith("https://"):
        raise AirlockError(
            "credential_invalid",
            "org_url must be an https URL, for example https://example.okta.com",
        )
    host = urllib.parse.urlsplit(raw).netloc
    if not host or not host.endswith((".okta.com", ".oktapreview.com")):
        raise AirlockError(
            "credential_invalid",
            "org_url must point at an okta.com or oktapreview.com host.",
        )
    return host


def _assert_allowed(url, org_host):
    """Close SSRF. Nothing leaves this module except to the configured Okta org."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc != org_host:
        raise AirlockError(
            "egress_blocked",
            "Refused an outbound request to a host outside the configured Okta org.",
            {"attempted_host": parts.netloc or "unknown", "allowed_host": org_host},
        )


class RateBudget:
    """Tracks what Okta says is left, per endpoint bucket.

    Okta returns its own accounting on every response. Reading it is cheaper and
    more honest than guessing at documented limits, which differ by org tier.
    """

    def __init__(self):
        self.buckets = {}

    def record(self, bucket, headers):
        limit = headers.get("X-Rate-Limit-Limit")
        remaining = headers.get("X-Rate-Limit-Remaining")
        reset = headers.get("X-Rate-Limit-Reset")
        if remaining is None:
            return
        self.buckets[bucket] = {
            "limit": _as_int(limit),
            "remaining": _as_int(remaining),
            "reset_epoch": _as_int(reset),
            "observed_at": _now_iso(),
        }

    def snapshot(self):
        return dict(self.buckets)

    def headroom(self, bucket):
        entry = self.buckets.get(bucket)
        if entry is None:
            return None
        return entry.get("remaining")


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bucket_for(path):
    segments = [part for part in path.split("/") if part]
    return "/" + segments[0] if segments else "/"


class OktaClient:
    """The single egress path. Every outbound call in this module goes through here."""

    def __init__(self, creds, budget=None):
        self.creds = creds
        self.host = _org_host(creds)
        self.base = "https://" + self.host
        self.budget = budget or RateBudget()
        self._token = None
        self._token_expires_at = 0.0
        self._granted_scopes = []

    def request(self, method, path, query=None, body=None, scopes=None):
        url = self.base + API_PREFIX + path
        if query:
            url = url + "?" + urllib.parse.urlencode(query)
        _assert_allowed(url, self.host)
        token = self.access_token(scopes)
        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
        }
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf8")
            headers["Content-Type"] = "application/json"
        status, response_headers, parsed = self._send(method, url, headers, payload)
        self.budget.record(_bucket_for(path), response_headers)
        return status, response_headers, parsed

    def access_token(self, scopes=None):
        wanted = sorted(set(scopes or self.default_scopes()))
        if self._token and time.time() < self._token_expires_at:
            if set(wanted).issubset(set(self._granted_scopes)):
                return self._token
        return self._mint(wanted)

    def default_scopes(self):
        configured = self.creds.get("scopes")
        if isinstance(configured, str):
            return [item for item in configured.split() if item]
        if isinstance(configured, list):
            return list(configured)
        return list(SCOPE_PROBES.keys())

    def _mint(self, scopes):
        client_id = _require(self.creds, "client_id")
        assertion = _client_assertion(
            client_id=client_id,
            audience=self.base + TOKEN_PATH,
            private_key_pem=_require(self.creds, "private_key"),
            key_id=self.creds.get("key_id"),
        )
        url = self.base + TOKEN_PATH
        _assert_allowed(url, self.host)
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "scope": " ".join(scopes),
                "client_assertion_type": (
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                "client_assertion": assertion,
            }
        ).encode("utf8")
        status, _headers, parsed = self._send(
            "POST",
            url,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            form,
        )
        if status != 200 or not isinstance(parsed, dict) or "access_token" not in parsed:
            raise AirlockError(
                "token_denied",
                "Okta refused the client credentials grant.",
                {"http_status": status, "response": _redact(parsed)},
            )
        self._token = parsed["access_token"]
        granted = parsed.get("scope", "")
        self._granted_scopes = granted.split() if isinstance(granted, str) else []
        lifetime = _as_int(parsed.get("expires_in")) or TOKEN_LIFETIME_SECONDS
        self._token_expires_at = time.time() + lifetime - TOKEN_REFRESH_MARGIN_SECONDS
        return self._token

    @property
    def granted_scopes(self):
        return list(self._granted_scopes)

    def _send(self, method, url, headers, payload):
        request = urllib.request.Request(
            url, data=payload, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as res:
                raw = res.read()
                return res.status, dict(res.headers), _parse(raw)
        except urllib.error.HTTPError as err:
            raw = err.read()
            return err.code, dict(err.headers or {}), _parse(raw)
        except urllib.error.URLError as err:
            raise AirlockError(
                "provider_unreachable",
                "The Okta org could not be reached.",
                {"reason": str(getattr(err, "reason", "unknown"))},
            )
        except TimeoutError:
            raise AirlockError(
                "provider_timeout",
                "Okta did not answer within the request timeout.",
            )


def _parse(raw):
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf8"))
    except (ValueError, UnicodeDecodeError):
        return {"raw": raw[:512].decode("utf8", "replace")}


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _client_assertion(client_id, audience, private_key_pem, key_id=None):
    """Build the private_key_jwt assertion Okta requires for scoped access.

    Okta accepts no other client authentication method for tokens carrying Okta
    scopes, and the key never leaves this process.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise AirlockError(
            "crypto_unavailable",
            "The cryptography package is required to sign the client assertion.",
        )

    try:
        key = serialization.load_pem_private_key(
            private_key_pem.encode("utf8"), password=None
        )
    except (ValueError, TypeError):
        raise AirlockError(
            "credential_invalid",
            "private_key is not a readable PEM private key.",
        )
    if not isinstance(key, rsa.RSAPrivateKey):
        raise AirlockError(
            "credential_invalid",
            "private_key must be an RSA key. Okta signs client assertions with RS256.",
        )

    header = {"alg": "RS256", "typ": "JWT"}
    if key_id:
        header["kid"] = key_id
    issued = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": issued,
        "exp": issued + TOKEN_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf8"))
    )
    signature = key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return signing_input + "." + _b64url(signature)


def _guard(command):
    """Turn every uncaught condition into a fail closed envelope."""

    def decorate(fn):
        def wrapped(inputs, context):
            try:
                return fn(inputs or {}, context or {})
            except AirlockError as err:
                return _fail(command, err.code, err.message, err.detail)
            except Exception as err:  # noqa: BLE001
                return _fail(
                    command,
                    "unexpected_error",
                    "The command stopped rather than continue on an unknown state.",
                    {"exception": type(err).__name__},
                )

        wrapped.__name__ = fn.__name__
        return wrapped

    return decorate


@_guard("org.verify_connection")
def org_verify_connection(inputs, context):
    """Probe every scope and name what each missing one costs."""
    creds = _vault_credentials()
    client = OktaClient(creds)
    requested = client.default_scopes()
    token_error = None
    try:
        client.access_token(requested)
    except AirlockError as err:
        if err.code != "token_denied":
            raise
        token_error = err.detail

    granted = set(client.granted_scopes)
    probes = []
    blocked_commands = set()

    for scope, probe in SCOPE_PROBES.items():
        if scope not in granted:
            probes.append(
                {
                    "scope": scope,
                    "granted": False,
                    "verified": False,
                    "blocks_commands": probe["blocks"],
                }
            )
            blocked_commands.update(probe["blocks"])
            continue
        status, _headers, parsed = client.request(
            probe["method"], probe["path"], query=probe.get("query"), scopes=[scope]
        )
        verified = status < 400
        entry = {"scope": scope, "granted": True, "verified": verified}
        if not verified:
            entry["http_status"] = status
            entry["blocks_commands"] = probe["blocks"]
            entry["provider_message"] = _provider_message(parsed)
            blocked_commands.update(probe["blocks"])
        probes.append(entry)

    write_status = []
    for scope, commands in WRITE_SCOPES.items():
        held = scope in granted
        write_status.append(
            {"scope": scope, "granted": held, "enables_commands": commands}
        )
        if not held:
            blocked_commands.update(commands)

    data = {
        "org_host": client.host,
        "auth_method": "oauth2_private_key_jwt",
        "scopes_requested": requested,
        "scopes_granted": sorted(granted),
        "read_scope_probes": probes,
        "write_scopes": write_status,
        "blocked_commands": sorted(blocked_commands),
        "rate_budget": client.budget.snapshot(),
        "checked_at": _now_iso(),
    }
    if token_error:
        data["token_error"] = token_error
    warnings = []
    if blocked_commands:
        warnings.append(
            str(len(blocked_commands))
            + " commands are unavailable with the scopes currently granted."
        )
    return _ok("org.verify_connection", data, warnings or None)


@_guard("org.rate_budget")
def org_rate_budget(inputs, context):
    """Report remaining headroom so a bulk plan never half runs."""
    creds = _vault_credentials()
    client = OktaClient(creds)
    for probe in ({"path": "/users"}, {"path": "/groups"}, {"path": "/logs"}):
        client.request("GET", probe["path"], query={"limit": "1"})
    snapshot = client.budget.snapshot()
    thin = [
        bucket
        for bucket, entry in snapshot.items()
        if entry.get("remaining") is not None and entry["remaining"] < 20
    ]
    warnings = None
    if thin:
        warnings = ["Low headroom in: " + ", ".join(sorted(thin))]
    return _ok(
        "org.rate_budget",
        {"buckets": snapshot, "observed_at": _now_iso()},
        warnings,
    )


def _provider_message(parsed):
    if isinstance(parsed, dict):
        for key in ("errorSummary", "error_description", "message"):
            if parsed.get(key):
                return parsed[key]
    return None


# The marketplace linter resolves a command id to a function by replacing dots and
# dashes with underscores. An older publisher FAQ documents an _h_ prefix instead.
# Both names are bound to the same function so neither loader can miss it.
_h_org_verify_connection = org_verify_connection
_h_org_rate_budget = org_rate_budget
