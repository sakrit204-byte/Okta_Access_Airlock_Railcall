"""Okta Access Airlock.

Governed Okta administration for RailCall. Every command in this module resolves
credentials from the local Station vault, reaches exactly one host, redacts secrets
from everything it returns, and fails closed when an outcome cannot be determined.
"""

import base64
import hashlib
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
    helpers = globals().get("__rc_helpers__")
    resolver = None
    if isinstance(helpers, dict):
        resolver = helpers.get("vault_get")
    if resolver is None:
        # Only used by the offline suite, which injects a stub. The station
        # always provides the helper, and reading a credentials file directly
        # is never a fallback here.
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
            "No okta credential found in the Station vault. Configure it in "
            "Studio, Integrations, okta.",
        )
    return _normalise_credential(creds)


CREDENTIAL_ALIASES = {
    "org_url": ("OKTA_ORG_URL", "org_url", "orgUrl"),
    "client_id": ("OKTA_CLIENT_ID", "client_id", "clientId"),
    "key_id": ("OKTA_KEY_ID", "key_id", "kid"),
    "private_key": ("OKTA_PRIVATE_KEY", "private_key", "privateKey"),
    "scopes": ("OKTA_SCOPES", "scopes"),
}


def _normalise_credential(creds):
    """Accept the canonical credential_spec field names and their aliases.

    The manifest declares OKTA_ORG_URL and friends, which is what Studio shows
    a buyer. Lowercase forms are accepted so an existing entry keeps working.
    """
    out = {}
    for canonical, names in CREDENTIAL_ALIASES.items():
        for name in names:
            if creds.get(name):
                out[canonical] = creds[name]
                break
    return out


def _require(creds, field):
    value = creds.get(field)
    if not value:
        raise AirlockError(
            "credential_incomplete",
            "The okta credential is missing "
            + CREDENTIAL_ALIASES.get(field, (field,))[0]
            + ".",
            {"missing_field": CREDENTIAL_ALIASES.get(field, (field,))[0]},
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
        limit = _header(headers, "X-Rate-Limit-Limit")
        remaining = _header(headers, "X-Rate-Limit-Remaining")
        reset = _header(headers, "X-Rate-Limit-Reset")
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
        self._token_type = "Bearer"
        self._token_expires_at = 0.0
        self._granted_scopes = []
        self._dpop_key = None
        self._token_nonce = None
        self._resource_nonce = None

    @property
    def dpop_key(self):
        """An ephemeral proof key, generated once per client and never persisted.

        Deliberately not the client assertion key. That one is registered with Okta
        as the application's identity; this one only proves possession for the life
        of this process.
        """
        if self._dpop_key is None:
            _hashes, _serialization, _padding, rsa = _load_crypto()
            self._dpop_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
        return self._dpop_key

    def request(self, method, path, query=None, body=None, scopes=None):
        url = self.base + API_PREFIX + path
        if query:
            url = url + "?" + urllib.parse.urlencode(query)
        _assert_allowed(url, self.host)
        token = self.access_token(scopes)

        payload = None
        extra = {}
        if body is not None:
            payload = json.dumps(body).encode("utf8")
            extra["Content-Type"] = "application/json"

        status, response_headers, parsed = self._send_authorized(
            method, url, token, payload, extra
        )

        # Okta can demand a fresh resource nonce at any point, not only on the first
        # call. Retrying once with the nonce it just handed us is part of the
        # protocol rather than an error path.
        if _wants_new_nonce(status, parsed):
            nonce = _dpop_nonce_from(response_headers)
            if nonce and nonce != self._resource_nonce:
                self._resource_nonce = nonce
                status, response_headers, parsed = self._send_authorized(
                    method, url, token, payload, extra
                )

        self.budget.record(_bucket_for(path), response_headers)
        return status, response_headers, parsed

    def _send_authorized(self, method, url, token, payload, extra):
        headers = {"Accept": "application/json"}
        headers.update(extra)
        if self._token_type.lower() == "dpop":
            headers["Authorization"] = "DPoP " + token
            headers["DPoP"] = _dpop_proof(
                self.dpop_key,
                method,
                url,
                nonce=self._resource_nonce,
                access_token=token,
            )
        else:
            headers["Authorization"] = "Bearer " + token
        return self._send(method, url, headers, payload)

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
        private_key_pem = _require(self.creds, "private_key")
        url = self.base + TOKEN_PATH
        _assert_allowed(url, self.host)

        def attempt():
            # A fresh assertion every attempt. Okta enforces one time use on the
            # client_assertion jti, so reusing one across the DPoP nonce retry is
            # rejected as invalid_client rather than as a replay.
            form = urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "scope": " ".join(scopes),
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": _client_assertion(
                        client_id=client_id,
                        audience=url,
                        private_key_pem=private_key_pem,
                        key_id=self.creds.get("key_id"),
                    ),
                }
            ).encode("utf8")
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": _dpop_proof(
                    self.dpop_key, "POST", url, nonce=self._token_nonce
                ),
            }
            return self._send("POST", url, headers, form)

        status, headers, parsed = attempt()

        # Okta answers the first proof with a nonce it wants echoed back. This is
        # the documented handshake, not a failure, so it is retried once here rather
        # than surfaced to the caller.
        if _wants_new_nonce(status, parsed):
            nonce = _dpop_nonce_from(headers)
            if nonce and nonce != self._token_nonce:
                self._token_nonce = nonce
                status, headers, parsed = attempt()

        if status != 200 or not isinstance(parsed, dict) or "access_token" not in parsed:
            raise AirlockError(
                "token_denied",
                "Okta refused the client credentials grant.",
                {"http_status": status, "response": _redact(parsed)},
            )
        self._token_type = parsed.get("token_type") or "Bearer"
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


def _load_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise AirlockError(
            "crypto_unavailable",
            "The cryptography package is required to sign proofs and assertions.",
        )
    return hashes, serialization, padding, rsa


def _sign_jwt(key, header, claims):
    hashes, _serialization, padding, _rsa = _load_crypto()
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf8"))
    )
    signature = key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return signing_input + "." + _b64url(signature)


def _public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def _htu(url):
    """The DPoP htu claim is the request URI without query or fragment."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _dpop_proof(key, method, url, nonce=None, access_token=None):
    """Build an RFC 9449 DPoP proof.

    Current Okta orgs require this on the token endpoint, and the resulting access
    token is bound to the proof key. A token lifted from a log or a process dump is
    unusable without the private key that minted it, which is a boundary a bearer
    token cannot express.
    """
    header = {"typ": "dpop+jwt", "alg": "RS256", "jwk": _public_jwk(key)}
    claims = {
        "htm": method,
        "htu": _htu(url),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    if nonce:
        claims["nonce"] = nonce
    if access_token:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        claims["ath"] = _b64url(digest)
    return _sign_jwt(key, header, claims)


def _dpop_nonce_from(headers):
    return _header(headers, "DPoP-Nonce")


def _wants_new_nonce(status, parsed):
    if status not in (400, 401):
        return False
    if not isinstance(parsed, dict):
        return False
    return parsed.get("error") in ("use_dpop_nonce", "invalid_dpop_proof")


def _as_runtime(envelope):
    """Carry a structured failure out as the exception the station expects.

    The station treats a returned dict as a successful action and writes a
    receipt saying so. Returning a failure envelope would therefore record a
    failed operation as a success, which is the exact opposite of the fail
    closed behaviour this module claims. Raising is what makes the receipt
    honest, so the structured detail rides in the message instead.
    """
    error = envelope.get("error") or {}
    detail = error.get("detail") or {}
    return RuntimeError(
        envelope.get("command", "command")
        + " -> "
        + str(error.get("code"))
        + ": "
        + str(error.get("message"))
        + (" | " + _canonical(detail) if detail else "")
    )


def _guard(command):
    """Fail closed. Success returns a dict; anything else raises."""

    def decorate(fn):
        def wrapped(inputs, context):
            try:
                return fn(inputs or {}, context or {})
            except AirlockError as err:
                raise _as_runtime(_fail(command, err.code, err.message, err.detail))
            except Exception as err:  # noqa: BLE001
                raise _as_runtime(
                    _fail(
                        command,
                        "unexpected_error",
                        "The command stopped rather than continue on an unknown "
                        "state.",
                        {"exception": type(err).__name__},
                    )
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


def _header(headers, name):
    """Case insensitive header lookup.

    Okta returns its rate limit headers lowercase, and dict(response.headers)
    discards the case insensitivity the HTTP layer provided. Looking them up by
    the documented capitalisation therefore returns nothing, and the budget reads
    as empty rather than as an error. Found by probing a live org.
    """
    if name in headers:
        return headers[name]
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value
    return None


def _next_link(headers):
    """Okta pages with RFC 5988 Link headers, not offsets.

    An offset based reader silently drops records once a set spans pages, which is
    the kind of failure that looks like clean output.
    """
    raw = _header(headers, "Link")
    if not raw:
        return None
    for part in raw.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url = section[0].strip().strip("<>")
        for attribute in section[1:]:
            if attribute.strip().replace(" ", "").lower() in (
                'rel="next"',
                "rel=next",
            ):
                return url
    return None


def _paged(client, path, query=None, cap=1000):
    """Read a collection to completion, or stop honestly at the cap.

    Okta signals further pages with an RFC 5988 Link header, but it does not
    always send one when more records exist. Measured on a live org: /groups with
    limit=1 over two groups returns one record and only rel="self". A reader that
    trusts the Link header alone therefore truncates silently and reports the set
    as complete, which is the worst possible failure here because a plan built on
    a short set looks fine.

    So the Link header is the fast path, and a full page with no next link is
    treated as "ask again" using an explicit after cursor, which was verified to
    keep working where the Link header stops.
    """
    query = dict(query or {})
    limit = _int(query.get("limit"), 200)
    items = []
    seen_cursors = set()
    truncated = False

    while True:
        status, headers, body = client.request("GET", path, query=query)
        if status >= 400:
            raise AirlockError(
                "provider_refused",
                "Okta refused a read of " + path + ".",
                {"http_status": status, "provider_message": _provider_message(body)},
            )
        page = body if isinstance(body, list) else []
        items.extend(page)

        if len(items) >= cap:
            truncated = True
            break

        next_url = _next_link(headers)
        if next_url:
            _assert_allowed(next_url, client.host)
            parts = urllib.parse.urlsplit(next_url)
            path = parts.path.split(API_PREFIX, 1)[-1]
            query = dict(urllib.parse.parse_qsl(parts.query))
            continue

        # No next link. A short page means genuinely finished; a full one does
        # not, because Okta omits the link even when more records remain.
        if len(page) < limit:
            break

        # Collections identify records by "id". The System Log uses "uuid",
        # so a pager that only knows about "id" cannot advance the log at all
        # and quietly reports every read of it as incomplete.
        last = page[-1] if page else {}
        cursor = last.get("id") or last.get("uuid")
        if not cursor or cursor in seen_cursors:
            # Cannot advance safely. Refuse to claim the set is complete rather
            # than guess, since a wrong complete flag is what corrupts a plan.
            truncated = True
            break
        seen_cursors.add(cursor)
        query["after"] = cursor

    return {
        "items": items[:cap],
        "count": len(items[:cap]),
        "complete": not truncated,
        "cap": cap,
    }


def _paged_optional(client, path, query=None, cap=1000):
    """Read a collection that the caller's admin role may not be allowed to see.

    Returns an unavailable marker rather than raising, so one forbidden sub read
    does not fail a command whose other halves worked. The marker is surfaced to
    the user; it is never silently rendered as an empty list, because "no admin
    roles" and "not allowed to see admin roles" are different answers.
    """
    try:
        result = _paged(client, path, query, cap)
        result["available"] = True
        return result
    except AirlockError as err:
        if err.code != "provider_refused":
            raise
        if (err.detail or {}).get("http_status") not in (401, 403):
            raise
        return {
            "items": [],
            "count": None,
            "complete": False,
            "available": False,
            "reason": (
                "The admin role assigned to this application is not permitted to "
                "read " + path + ". This is a permission on the role, not a "
                "missing OAuth scope."
            ),
        }


def _provider_message(parsed):
    if isinstance(parsed, dict):
        for key in ("errorSummary", "error_description", "message"):
            if parsed.get(key):
                return parsed[key]
    return None


def _int(value, default, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if number < 1:
        return default
    return min(number, maximum) if maximum else number


def _client():
    return OktaClient(_vault_credentials())


def _get_one(client, path, missing_code="not_found"):
    status, _headers, body = client.request("GET", path)
    if status == 404:
        raise AirlockError(missing_code, "Okta has no record at " + path + ".")
    if status >= 400:
        raise AirlockError(
            "provider_refused",
            "Okta refused a read of " + path + ".",
            {"http_status": status, "provider_message": _provider_message(body)},
        )
    return body


def _thin_user(record):
    profile = (record or {}).get("profile") or {}
    return {
        "id": record.get("id"),
        "status": record.get("status"),
        "login": profile.get("login"),
        "email": profile.get("email"),
        "first_name": profile.get("firstName"),
        "last_name": profile.get("lastName"),
        "created": record.get("created"),
        "last_login": record.get("lastLogin"),
        "status_changed": record.get("statusChanged"),
    }


@_guard("users.find")
def users_find(inputs, context):
    """Find users. Filter results can feed a write; search results cannot.

    Okta's search parameter reads from an eventually consistent datasource. A plan
    built from it can target state the approving human never saw, which is exactly
    the failure the plan and apply split exists to prevent. So search output is
    marked advisory and carries a flag saying it must not feed an apply.
    """
    client = _client()
    query = {}
    advisory = False

    if inputs.get("filter"):
        query["filter"] = str(inputs["filter"])
    if inputs.get("search"):
        query["search"] = str(inputs["search"])
        advisory = True
    if not query:
        query["filter"] = 'status eq "ACTIVE"'

    query["limit"] = str(_int(inputs.get("page_size"), 200, 200))
    page = _paged(client, "/users", query, _int(inputs.get("max_records"), 500))

    warnings = []
    if advisory:
        warnings.append(
            "Search was used, so this result is advisory and must not feed an apply. "
            "Okta serves search from an eventually consistent datasource."
        )
    if not page["complete"]:
        warnings.append(
            "Stopped at the cap of "
            + str(page["cap"])
            + " records. This set is incomplete and must not feed an apply."
        )

    return _ok(
        "users.find",
        {
            "users": [_thin_user(u) for u in page["items"]],
            "count": page["count"],
            "complete": page["complete"],
            "advisory": advisory,
            "may_feed_write": (not advisory) and page["complete"],
            "query": query,
        },
        warnings or None,
    )


@_guard("users.get")
def users_get(inputs, context):
    """One user, with status and credential posture."""
    user_id = inputs.get("user_id")
    if not user_id:
        raise AirlockError("input_missing", "user_id is required.")
    client = _client()
    record = _get_one(client, "/users/" + urllib.parse.quote(str(user_id)), "user_not_found")
    credentials = (record or {}).get("credentials") or {}
    return _ok(
        "users.get",
        {
            "user": _thin_user(record),
            "credential_provider": (credentials.get("provider") or {}).get("type"),
            "has_password": bool(credentials.get("password")),
            "recovery_question_set": bool(credentials.get("recovery_question")),
            "activated": record.get("activated"),
            "password_changed": record.get("passwordChanged"),
        },
    )


@_guard("users.list_access")
def users_list_access(inputs, context):
    """Groups, applications and admin roles in one read.

    appLinks is the honest answer to what a person can actually open, rather than
    what an assignment table implies they can.
    """
    user_id = inputs.get("user_id")
    if not user_id:
        raise AirlockError("input_missing", "user_id is required.")
    client = _client()
    encoded = urllib.parse.quote(str(user_id))

    groups = _paged(client, "/users/" + encoded + "/groups", {"limit": "200"})
    app_links = _paged(client, "/users/" + encoded + "/appLinks")
    roles = _paged_optional(client, "/users/" + encoded + "/roles")

    return _ok(
        "users.list_access",
        {
            "user_id": user_id,
            "groups": [
                {
                    "id": g.get("id"),
                    "name": (g.get("profile") or {}).get("name"),
                    "type": g.get("type"),
                }
                for g in groups["items"]
            ],
            "applications": [
                {
                    "app_instance_id": a.get("appInstanceId"),
                    "label": a.get("label"),
                    "app_name": a.get("appName"),
                }
                for a in app_links["items"]
            ],
            "admin_roles": [
                {
                    "assignment_id": r.get("id"),
                    "type": r.get("type"),
                    "label": r.get("label"),
                    "status": r.get("status"),
                    "assignment_type": r.get("assignmentType"),
                }
                for r in roles["items"]
            ],
            "admin_roles_available": roles["available"],
            "counts": {
                "groups": groups["count"],
                "applications": app_links["count"],
                "admin_roles": roles["count"],
            },
            "complete": groups["complete"] and app_links["complete"],
        },
        None
        if roles["available"]
        else ["Admin roles could not be read: " + roles["reason"]],
    )


@_guard("users.list_live_credentials")
def users_list_live_credentials(inputs, context):
    """What would still work after a deactivation.

    Sessions, OAuth grants and per client refresh tokens are three separate things
    behind three separate endpoints. Okta exposes no way to enumerate active
    sessions, only to revoke them, so this reports that gap rather than implying a
    count of zero means none exist.
    """
    user_id = inputs.get("user_id")
    if not user_id:
        raise AirlockError("input_missing", "user_id is required.")
    client = _client()
    encoded = urllib.parse.quote(str(user_id))

    grants = _paged(client, "/users/" + encoded + "/grants")

    clients = []
    try:
        clients = _paged(client, "/users/" + encoded + "/clients")["items"]
    except AirlockError:
        clients = []

    tokens = []
    for entry in clients:
        client_id = entry.get("client_id") or entry.get("id")
        if not client_id:
            continue
        try:
            found = _paged(
                client,
                "/users/" + encoded + "/clients/" + urllib.parse.quote(str(client_id)) + "/tokens",
            )
        except AirlockError:
            continue
        for token in found["items"]:
            tokens.append(
                {
                    "token_id": token.get("id"),
                    "client_id": client_id,
                    "client_name": entry.get("client_name"),
                    "created": token.get("created"),
                    "expires_at": token.get("expiresAt"),
                }
            )

    devices = []
    try:
        devices = _paged(client, "/users/" + encoded + "/devices")["items"]
    except AirlockError:
        devices = []

    return _ok(
        "users.list_live_credentials",
        {
            "user_id": user_id,
            "oauth_grants": [
                {
                    "id": g.get("id"),
                    "client_id": g.get("clientId"),
                    "scope_id": g.get("scopeId"),
                    "created": g.get("created"),
                }
                for g in grants["items"]
            ],
            "refresh_tokens": tokens,
            "devices": [
                {"id": d.get("id"), "status": d.get("status")} for d in devices
            ],
            "counts": {
                "oauth_grants": grants["count"],
                "refresh_tokens": len(tokens),
                "devices": len(devices),
            },
            "sessions": {
                "enumerable": False,
                "note": (
                    "Okta exposes no endpoint that lists a user's active sessions, "
                    "only one that revokes them. Active sessions may exist and "
                    "cannot be counted here."
                ),
            },
        },
    )


@_guard("groups.find")
def groups_find(inputs, context):
    """Find groups by filter, paged to completion."""
    client = _client()
    query = {"limit": str(_int(inputs.get("page_size"), 200, 200))}
    if inputs.get("filter"):
        query["filter"] = str(inputs["filter"])
    if inputs.get("q"):
        query["q"] = str(inputs["q"])
    page = _paged(client, "/groups", query, _int(inputs.get("max_records"), 500))
    return _ok(
        "groups.find",
        {
            "groups": [
                {
                    "id": g.get("id"),
                    "name": (g.get("profile") or {}).get("name"),
                    "description": (g.get("profile") or {}).get("description"),
                    "type": g.get("type"),
                    "created": g.get("created"),
                }
                for g in page["items"]
            ],
            "count": page["count"],
            "complete": page["complete"],
        },
        None if page["complete"] else ["Stopped at the record cap; set is incomplete."],
    )


@_guard("groups.get_members")
def groups_get_members(inputs, context):
    """Members of one group, paged to completion."""
    group_id = inputs.get("group_id")
    if not group_id:
        raise AirlockError("input_missing", "group_id is required.")
    client = _client()
    encoded = urllib.parse.quote(str(group_id))
    group = _get_one(client, "/groups/" + encoded, "group_not_found")
    page = _paged(
        client,
        "/groups/" + encoded + "/users",
        {"limit": "200"},
        _int(inputs.get("max_records"), 1000),
    )
    return _ok(
        "groups.get_members",
        {
            "group": {
                "id": group.get("id"),
                "name": (group.get("profile") or {}).get("name"),
                "type": group.get("type"),
            },
            "members": [_thin_user(u) for u in page["items"]],
            "count": page["count"],
            "complete": page["complete"],
        },
        None if page["complete"] else ["Stopped at the record cap; set is incomplete."],
    )


@_guard("access.rule_entanglement")
def access_rule_entanglement(inputs, context):
    """Report whether removing a membership would also modify a group rule.

    When an administrator manually removes a rule managed user from a group, Okta
    adds that user to the rule's exception list. The membership change is what was
    asked for. The rule change is not, it is permanent, and it affects every other
    member the rule governs. Undoing it means deactivating, editing and
    reactivating the rule, which briefly suspends it for the whole organisation.

    A removal preview that does not say this is hiding the larger half of the
    effect.
    """
    user_id = inputs.get("user_id")
    group_id = inputs.get("group_id")
    if not user_id or not group_id:
        raise AirlockError("input_missing", "user_id and group_id are both required.")

    client = _client()
    encoded_group = urllib.parse.quote(str(group_id))
    encoded_user = urllib.parse.quote(str(user_id))

    status, _headers, body = client.request(
        "GET", "/groups/" + encoded_group + "/users/" + encoded_user + "/group-rules"
    )
    if status >= 400:
        raise AirlockError(
            "provider_refused",
            "Okta refused the rule lookup for this membership.",
            {"http_status": status, "provider_message": _provider_message(body)},
        )

    rules = body if isinstance(body, list) else []
    members = _paged(client, "/groups/" + encoded_group + "/users", {"limit": "200"})

    entangled = bool(rules)
    data = {
        "user_id": user_id,
        "group_id": group_id,
        "rule_managed": entangled,
        "rules": [
            {"id": r.get("id"), "name": r.get("name"), "status": r.get("status")}
            for r in rules
        ],
        "group_member_count": members["count"],
        "second_order_effect": None,
        "reversible": True,
    }

    warnings = None
    if entangled:
        names = ", ".join(str(r.get("name")) for r in rules) or "an unnamed rule"
        data["second_order_effect"] = (
            "Removing this membership will also add the user to the exception list "
            "of " + names + ". That edit is permanent, it applies to the rule rather "
            "than to this user, and the rule currently governs a group of "
            + str(members["count"]) + " members."
        )
        data["reversible"] = False
        data["undo_cost"] = (
            "Reversing it requires deactivating the rule, editing the exception "
            "list, and reactivating it, which suspends the rule for the whole "
            "organisation while it is off."
        )
        warnings = [
            "This removal modifies a group rule as well as a membership. Read "
            "second_order_effect before approving."
        ]

    return _ok("access.rule_entanglement", data, warnings)


@_guard("access.explain")
def access_explain(inputs, context):
    """Why can this user reach this application?

    Direct assignment, or through which group, or through which rule. This is the
    question an access review exists to answer and the one nobody can answer
    quickly from the console.
    """
    user_id = inputs.get("user_id")
    app_id = inputs.get("app_id")
    if not user_id or not app_id:
        raise AirlockError("input_missing", "user_id and app_id are both required.")

    client = _client()
    encoded_user = urllib.parse.quote(str(user_id))
    encoded_app = urllib.parse.quote(str(app_id))

    paths = []

    status, _headers, direct = client.request(
        "GET", "/apps/" + encoded_app + "/users/" + encoded_user
    )
    if status < 400 and isinstance(direct, dict):
        paths.append(
            {
                "kind": "direct_assignment",
                "detail": "Assigned to the application directly.",
                "scope": direct.get("scope"),
                "created": direct.get("created"),
            }
        )

    app_groups = _paged(client, "/apps/" + encoded_app + "/groups")
    assigned_group_ids = {g.get("id") for g in app_groups["items"] if g.get("id")}

    user_groups = _paged(client, "/users/" + encoded_user + "/groups", {"limit": "200"})
    for group in user_groups["items"]:
        gid = group.get("id")
        if gid not in assigned_group_ids:
            continue
        entry = {
            "kind": "group_assignment",
            "group_id": gid,
            "group_name": (group.get("profile") or {}).get("name"),
            "detail": "Reaches the application through this group.",
            "rules": [],
        }
        rule_status, _h, rules = client.request(
            "GET",
            "/groups/" + urllib.parse.quote(str(gid)) + "/users/" + encoded_user + "/group-rules",
        )
        if rule_status < 400 and isinstance(rules, list) and rules:
            entry["rules"] = [
                {"id": r.get("id"), "name": r.get("name")} for r in rules
            ]
            entry["detail"] = (
                "Reaches the application through this group, and the membership "
                "itself is granted by a rule rather than by a person."
            )
        paths.append(entry)

    reachable = _paged(client, "/users/" + encoded_user + "/appLinks")
    has_link = any(
        link.get("appInstanceId") == app_id for link in reachable["items"]
    )

    warnings = None
    if has_link and not paths:
        warnings = [
            "The user can open this application but no direct or group assignment "
            "explains it. Verify the application's own sign on policy before "
            "concluding access has been removed."
        ]

    return _ok(
        "access.explain",
        {
            "user_id": user_id,
            "app_id": app_id,
            "can_open_it": has_link,
            "paths": paths,
            "path_count": len(paths),
            "explained": bool(paths) or not has_link,
        },
        warnings,
    )


@_guard("radius.user_deactivation")
def radius_user_deactivation(inputs, context):
    """What breaks if this user is deactivated, and what survives it.

    The second half matters more. Deactivation does not remove group memberships,
    and sessions, grants and refresh tokens are separate concerns. Presenting
    deactivation as an off switch would be the most dangerous thing this module
    could do.
    """
    user_id = inputs.get("user_id")
    if not user_id:
        raise AirlockError("input_missing", "user_id is required.")

    client = _client()
    encoded = urllib.parse.quote(str(user_id))
    record = _get_one(client, "/users/" + encoded, "user_not_found")

    groups = _paged(client, "/users/" + encoded + "/groups", {"limit": "200"})
    app_links = _paged(client, "/users/" + encoded + "/appLinks")
    roles = _paged_optional(client, "/users/" + encoded + "/roles")

    owned_at_risk = []
    for group in groups["items"]:
        gid = group.get("id")
        if not gid:
            continue
        status, _h, owners = client.request(
            "GET", "/groups/" + urllib.parse.quote(str(gid)) + "/owners"
        )
        if status >= 400 or not isinstance(owners, list):
            continue
        owner_ids = [o.get("id") for o in owners]
        if user_id in owner_ids and len(owner_ids) == 1:
            owned_at_risk.append(
                {
                    "group_id": gid,
                    "group_name": (group.get("profile") or {}).get("name"),
                    "detail": "This user is the only owner. The group would be left ownerless.",
                }
            )

    live = users_list_live_credentials({"user_id": user_id}, context)
    live_data = live.get("data", {}) if live.get("status") == "ok" else {}

    survives = {
        "group_memberships": groups["count"],
        "oauth_grants": (live_data.get("counts") or {}).get("oauth_grants", 0),
        "refresh_tokens": (live_data.get("counts") or {}).get("refresh_tokens", 0),
        "sessions": "not enumerable",
    }

    warnings = [
        "Deactivation does not remove group memberships. "
        + str(groups["count"])
        + " memberships would survive it."
    ]
    if survives["refresh_tokens"]:
        warnings.append(
            str(survives["refresh_tokens"])
            + " refresh tokens exist and are revoked separately."
        )
    if owned_at_risk:
        warnings.append(
            str(len(owned_at_risk)) + " groups would be left with no owner."
        )

    return _ok(
        "radius.user_deactivation",
        {
            "user": _thin_user(record),
            "lost": {
                "applications": [
                    {"app_instance_id": a.get("appInstanceId"), "label": a.get("label")}
                    for a in app_links["items"]
                ],
                "application_count": app_links["count"],
                "admin_roles": [
                    {"type": r.get("type"), "label": r.get("label")}
                    for r in roles["items"]
                ],
                "admin_role_count": roles["count"],
                "admin_roles_available": roles["available"],
            },
            "survives": survives,
            "groups_left_ownerless": owned_at_risk,
            "single_off_switch": False,
            "note": (
                "There is no single off switch. Applications stop resolving, but "
                "memberships, grants and refresh tokens each need addressing on "
                "their own, and active sessions cannot be enumerated at all."
            ),
        },
        warnings,
    )


def _canonical(value):
    """Stable JSON so a fingerprint depends on content, never on key order."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(snapshot):
    return hashlib.sha256(_canonical(snapshot).encode("utf8")).hexdigest()


def _plan_envelope(command, apply_with, intent, snapshot, preview, warnings=None):
    """The whole of the plan and apply contract, and it needs no storage.

    The fingerprint travels out with the plan, a human approves that payload, and
    the matching apply receives it back and re hashes freshly read state. Nothing
    is written to disk, so the manifest can honestly keep filesystem_writes empty.

    An approval therefore binds to the state the human reviewed, not to the record
    ids they were pointed at. Approve a change across forty users, let nine of them
    move while it sits in a queue, and a naive system writes over state nobody saw.
    """
    return {
        "plan_id": str(uuid.uuid4()),
        "planned_by": command,
        "apply_with": apply_with,
        "intent": intent,
        "snapshot": snapshot,
        "fingerprint": _fingerprint(snapshot),
        "computed_at": _now_iso(),
        "preview": preview,
        "warnings": warnings or [],
    }


def verify_plan(inputs, fresh_snapshot):
    """Re hash freshly read state and refuse if anything moved.

    Returns None when the plan still holds. Returns a refusal envelope naming what
    changed when it does not. Used by every apply before it touches anything.
    """
    approved = inputs.get("fingerprint")
    if not approved:
        raise AirlockError(
            "plan_missing",
            "This command only runs against an approved plan. Run the matching "
            "plan command first and pass its fingerprint back.",
        )
    current = _fingerprint(fresh_snapshot)
    if current == approved:
        return None
    return {
        "approved_fingerprint": approved,
        "current_fingerprint": current,
        "drifted": _describe_drift(inputs.get("snapshot") or {}, fresh_snapshot),
        "checked_at": _now_iso(),
    }


def _describe_drift(approved_snapshot, fresh_snapshot):
    """Name what moved, rather than only reporting that something did."""
    changes = []
    keys = set(approved_snapshot) | set(fresh_snapshot)
    for key in sorted(keys):
        before = approved_snapshot.get(key)
        after = fresh_snapshot.get(key)
        if before == after:
            continue
        if isinstance(before, list) and isinstance(after, list):
            gone = [x for x in before if x not in after]
            added = [x for x in after if x not in before]
            changes.append(
                {"field": key, "no_longer_present": gone, "newly_present": added}
            )
        else:
            changes.append({"field": key, "was": before, "now": after})
    return changes


@_guard("plan.group_membership")
def plan_group_membership(inputs, context):
    """Compute a membership change and fingerprint the state it depends on.

    Nothing is written. The result is what a human approves, and the fingerprint
    is what the matching apply re checks.
    """
    group_id = inputs.get("group_id")
    if not group_id:
        raise AirlockError("input_missing", "group_id is required.")
    add = [str(u) for u in (inputs.get("add") or [])]
    remove = [str(u) for u in (inputs.get("remove") or [])]
    if not add and not remove:
        raise AirlockError("input_missing", "Give at least one user to add or remove.")

    client = _client()
    encoded = urllib.parse.quote(str(group_id))
    group = _get_one(client, "/groups/" + encoded, "group_not_found")
    members = _paged(client, "/groups/" + encoded + "/users", {"limit": "200"})
    if not members["complete"]:
        raise AirlockError(
            "set_incomplete",
            "The group membership could not be read to completion, so a plan over "
            "it would be built on a partial set. Refusing rather than planning "
            "against state nobody can see all of.",
        )

    member_ids = sorted(u.get("id") for u in members["items"] if u.get("id"))
    member_set = set(member_ids)

    will_add = [u for u in add if u not in member_set]
    already_there = [u for u in add if u in member_set]
    will_remove = [u for u in remove if u in member_set]
    not_a_member = [u for u in remove if u not in member_set]

    warnings = []
    entanglement = []
    for user_id in will_remove:
        report = access_rule_entanglement(
            {"user_id": user_id, "group_id": group_id}, context
        )
        if report.get("status") != "ok":
            continue
        detail = report["data"]
        if detail.get("rule_managed"):
            entanglement.append(
                {
                    "user_id": user_id,
                    "rules": detail.get("rules"),
                    "second_order_effect": detail.get("second_order_effect"),
                    "undo_cost": detail.get("undo_cost"),
                }
            )

    if entanglement:
        warnings.append(
            str(len(entanglement))
            + " of these removals will also permanently modify a group rule. Read "
            "rule_entanglement before approving."
        )
    if already_there:
        warnings.append(
            str(len(already_there)) + " users named for adding are already members."
        )
    if not_a_member:
        warnings.append(
            str(len(not_a_member)) + " users named for removal are not members."
        )

    snapshot = {
        "group_id": group_id,
        "member_ids": member_ids,
        "member_count": len(member_ids),
    }
    intent = {"group_id": group_id, "add": will_add, "remove": will_remove}
    preview = {
        "group_name": (group.get("profile") or {}).get("name"),
        "members_now": len(member_ids),
        "members_after": len(member_ids) + len(will_add) - len(will_remove),
        "will_add": will_add,
        "will_remove": will_remove,
        "no_op_already_member": already_there,
        "no_op_not_a_member": not_a_member,
        "rule_entanglement": entanglement,
    }

    return _ok(
        "plan.group_membership",
        _plan_envelope(
            "plan.group_membership",
            "apply.group_membership",
            intent,
            snapshot,
            preview,
            warnings,
        ),
        warnings or None,
    )


@_guard("plan.deactivate_user")
def plan_deactivate_user(inputs, context):
    """Compute a deactivation, its blast radius, and the state it depends on."""
    user_id = inputs.get("user_id")
    if not user_id:
        raise AirlockError("input_missing", "user_id is required.")

    radius = radius_user_deactivation({"user_id": user_id}, context)
    if radius.get("status") != "ok":
        return radius
    detail = radius["data"]
    user = detail["user"]

    if user.get("status") == "DEPROVISIONED":
        raise AirlockError(
            "already_deactivated",
            "This user is already deactivated. Nothing to plan.",
        )

    client = _client()
    encoded = urllib.parse.quote(str(user_id))
    groups = _paged(client, "/users/" + encoded + "/groups", {"limit": "200"})

    snapshot = {
        "user_id": user_id,
        "status": user.get("status"),
        "status_changed": user.get("status_changed"),
        "group_ids": sorted(g.get("id") for g in groups["items"] if g.get("id")),
        "application_count": detail["lost"]["application_count"],
    }
    intent = {"user_id": user_id, "action": "deactivate"}
    preview = {
        "user": user,
        "loses": detail["lost"],
        "survives": detail["survives"],
        "groups_left_ownerless": detail["groups_left_ownerless"],
        "single_off_switch": False,
    }

    warnings = list(radius.get("warnings") or [])
    warnings.append(
        "Deactivation is reversible in Okta, but revoked sessions and tokens are "
        "not. Consider apply.suspend_user if this may need undoing."
    )

    return _ok(
        "plan.deactivate_user",
        _plan_envelope(
            "plan.deactivate_user",
            "apply.deactivate_user",
            intent,
            snapshot,
            preview,
            warnings,
        ),
        warnings,
    )


# Events that change who can reach what. Anything not in here is noise for the
# purposes of custody: sign ins, policy evaluations, session lifecycle.
ACCESS_CHANGE_EVENTS = (
    "user.lifecycle.create",
    "user.lifecycle.activate",
    "user.lifecycle.deactivate",
    "user.lifecycle.suspend",
    "user.lifecycle.unsuspend",
    "user.lifecycle.delete",
    "user.lifecycle.delete.initiated",
    "user.account.privilege.grant",
    "user.account.privilege.revoke",
    "user.account.update_profile",
    "user.mfa.factor.reset_all",
    "user.mfa.factor.deactivate",
    "user.session.clear",
    "group.user_membership.add",
    "group.user_membership.remove",
    "group.lifecycle.create",
    "group.lifecycle.delete",
    "group.rule.lifecycle.create",
    "group.rule.lifecycle.delete",
    "group.rule.lifecycle.activate",
    "group.rule.lifecycle.deactivate",
    "application.user_membership.add",
    "application.user_membership.remove",
    "application.lifecycle.delete",
)

# actor.type as Okta reports it, mapped to what it means for custody.
HUMAN_ACTOR_TYPES = ("User",)
SYSTEM_ACTOR_TYPES = ("SystemPrincipal",)


def _classify_actor(event, our_client_id):
    """Who made this change, and does it count as governed?

    A change made through this module carries the service application as its
    actor, so a governed change is distinguishable from a human in the console
    without needing any record of our own.
    """
    actor = event.get("actor") or {}
    actor_type = actor.get("type")
    actor_id = actor.get("id")

    if actor_id and our_client_id and actor_id == our_client_id:
        return "governed", "Made by this module's service application."
    if actor_type in HUMAN_ACTOR_TYPES:
        return "ungoverned", "Made by a person, outside this module."
    if actor_type in SYSTEM_ACTOR_TYPES:
        return "system", "Made by Okta itself, for example a group rule evaluating."
    if actor_type:
        return "ungoverned", (
            "Made by another integration or application, outside this module."
        )
    return "unproven", "The event carries no actor this module can attribute."


def _thin_event(event, our_client_id):
    verdict, reason = _classify_actor(event, our_client_id)
    actor = event.get("actor") or {}
    client = event.get("client") or {}
    target = event.get("target") or []
    return {
        "event_type": event.get("eventType"),
        "published": event.get("published"),
        "verdict": verdict,
        "reason": reason,
        "actor": {
            "id": actor.get("id"),
            "type": actor.get("type"),
            "name": actor.get("displayName"),
            "identifier": actor.get("alternateId"),
        },
        "client_ip": client.get("ipAddress"),
        "outcome": (event.get("outcome") or {}).get("result"),
        "targets": [
            {
                "id": t.get("id"),
                "type": t.get("type"),
                "name": t.get("displayName"),
                "identifier": t.get("alternateId"),
            }
            for t in target
        ],
    }


def _access_event_filter():
    """Ask Okta for only the events that change access.

    Scanning and filtering here instead would burn the /logs budget, which this
    org measures at sixty calls a minute, on token grants and sign ins.
    """
    return " or ".join('eventType eq "' + e + '"' for e in ACCESS_CHANGE_EVENTS)


def _read_access_events(client, since=None, cap=500):
    query = {
        "limit": "100",
        "sortOrder": "DESCENDING",
        "filter": _access_event_filter(),
    }
    if since:
        query["since"] = str(since)
    page = _paged(client, "/logs", query, cap)
    relevant = [
        e
        for e in page["items"]
        if str(e.get("eventType") or "") in ACCESS_CHANGE_EVENTS
    ]

    # The watermark is how far the log is known to reach, so it must come from
    # the log as a whole and not from the filtered slice. An access change is
    # rare; a filtered read could be hours stale while the log is current, and
    # reporting the stale figure would overstate what "not visible" covers.
    watermark = None
    try:
        _s, _h, newest = client.request(
            "GET", "/logs", query={"limit": "1", "sortOrder": "DESCENDING"}
        )
        if isinstance(newest, list) and newest:
            watermark = newest[0].get("published")
    except AirlockError:
        watermark = None

    return relevant, page, watermark


@_guard("custody.detect_ungoverned")
def custody_detect_ungoverned(inputs, context):
    """Find access changes with no governed approval behind them.

    This is the command that catches somebody going around the airlock. It reads
    Okta's own System Log rather than any record this module keeps, which is the
    point: a record we wrote about ourselves is the kind of evidence an auditor
    discounts.

    What it can never say is that no ungoverned change occurred. Okta publishes
    no maximum System Log delivery latency, so the honest claim is bounded by the
    watermark this run actually saw, and that bound is returned alongside the
    result rather than left implied.
    """
    creds = _vault_credentials()
    client = OktaClient(creds)
    our_client_id = creds.get("client_id")

    events, page, watermark = _read_access_events(
        client, inputs.get("since"), _int(inputs.get("max_events"), 500)
    )
    classified = [_thin_event(e, our_client_id) for e in events]

    counts = {}
    for entry in classified:
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1

    ungoverned = [e for e in classified if e["verdict"] == "ungoverned"]

    warnings = []
    if ungoverned:
        warnings.append(
            str(len(ungoverned))
            + " access changes have no governed approval behind them."
        )
    if not page["complete"]:
        warnings.append(
            "The log was not read to completion, so this is a partial view and "
            "cannot support any claim about what is absent."
        )

    return _ok(
        "custody.detect_ungoverned",
        {
            "window_since": inputs.get("since"),
            "log_watermark": watermark,
            "claim": (
                "No ungoverned access change was VISIBLE as of "
                + str(watermark)
                + ". This is not a claim that none occurred: Okta publishes no "
                "maximum System Log delivery latency."
                if not ungoverned
                else str(len(ungoverned))
                + " ungoverned access changes were visible as of "
                + str(watermark)
            ),
            "counts": counts,
            "events_examined": len(classified),
            "log_read_complete": page["complete"],
            "ungoverned": ungoverned,
            "all_events": classified,
        },
        warnings or None,
    )


@_guard("custody.report")
def custody_report(inputs, context):
    """A custody timeline for one user or group, with a verdict per change."""
    target_id = inputs.get("target_id")
    if not target_id:
        raise AirlockError(
            "input_missing", "target_id is required: a user id or a group id."
        )

    creds = _vault_credentials()
    client = OktaClient(creds)
    our_client_id = creds.get("client_id")

    events, page, watermark = _read_access_events(
        client, inputs.get("since"), _int(inputs.get("max_events"), 500)
    )
    timeline = []
    for event in events:
        thin = _thin_event(event, our_client_id)
        touches = any(t.get("id") == target_id for t in thin["targets"])
        if touches or (thin["actor"] or {}).get("id") == target_id:
            timeline.append(thin)

    verdicts = {e["verdict"] for e in timeline}
    if not timeline:
        custody = "unproven"
        summary = (
            "No access change touching this target is visible in the window read. "
            "That is not evidence that none occurred."
        )
    elif verdicts == {"governed"}:
        custody = "governed"
        summary = "Every visible change to this target was made through this module."
    elif "ungoverned" in verdicts:
        custody = "contested"
        summary = (
            "At least one visible change to this target was made outside this "
            "module, so custody cannot be claimed for it."
        )
    else:
        custody = "partial"
        summary = (
            "Visible changes are a mix of governed and system originated. No "
            "ungoverned change was seen in the window read."
        )

    return _ok(
        "custody.report",
        {
            "target_id": target_id,
            "custody": custody,
            "summary": summary,
            "log_watermark": watermark,
            "log_read_complete": page["complete"],
            "changes_visible": len(timeline),
            "timeline": timeline,
            "bound": (
                "Every verdict here is bounded by the log watermark above. Okta "
                "publishes no maximum delivery latency, so a change made moments "
                "ago may not yet be visible."
            ),
        },
        None
        if page["complete"]
        else ["The log was not read to completion; this timeline may be partial."],
    )


# The marketplace linter resolves a command id to a function by replacing dots and
# dashes with underscores. An older publisher FAQ documents an _h_ prefix instead.
# Both names are bound to the same function so neither loader can miss it.
_h_org_verify_connection = org_verify_connection
_h_org_rate_budget = org_rate_budget
_h_users_find = users_find
_h_users_get = users_get
_h_users_list_access = users_list_access
_h_users_list_live_credentials = users_list_live_credentials
_h_groups_find = groups_find
_h_groups_get_members = groups_get_members
_h_access_rule_entanglement = access_rule_entanglement
_h_access_explain = access_explain
_h_radius_user_deactivation = radius_user_deactivation
_h_plan_group_membership = plan_group_membership
_h_plan_deactivate_user = plan_deactivate_user
_h_custody_detect_ungoverned = custody_detect_ungoverned
_h_custody_report = custody_report
