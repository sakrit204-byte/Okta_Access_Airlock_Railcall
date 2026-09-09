"""Offline contract tests.

These run with no Okta org and no network. They lock the behaviour that must hold
regardless of what the provider does: secrets never leave, egress never widens, and
an unknown outcome is never rendered as a known one.

Behaviour that depends on live Okta responses is recorded in docs/TESTING.md instead,
because asserting it here against a mock would prove only that the mock agrees with
itself.
"""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "handlers"))

import handler  # noqa: E402


class RedactionTests(unittest.TestCase):
    def test_named_secret_fields_are_removed(self):
        payload = {
            "client_id": "0oaVisible",
            "private_key": "-----BEGIN PRIVATE KEY-----abc",
            "client_secret": "shh",
            "nested": {"access_token": "eyJ", "keep": "visible"},
        }
        cleaned = handler._redact(payload)
        self.assertEqual(cleaned["client_id"], "0oaVisible")
        self.assertEqual(cleaned["private_key"], handler.REDACTED)
        self.assertEqual(cleaned["client_secret"], handler.REDACTED)
        self.assertEqual(cleaned["nested"]["access_token"], handler.REDACTED)
        self.assertEqual(cleaned["nested"]["keep"], "visible")

    def test_bearer_values_are_removed_wherever_they_appear(self):
        cleaned = handler._redact({"Authorization": "Bearer abc", "list": ["Bearer x"]})
        self.assertEqual(cleaned["Authorization"], handler.REDACTED)
        self.assertEqual(cleaned["list"][0], handler.REDACTED)

    def test_redaction_survives_lists_of_objects(self):
        cleaned = handler._redact([{"token": "t"}, {"safe": 1}])
        self.assertEqual(cleaned[0]["token"], handler.REDACTED)
        self.assertEqual(cleaned[1]["safe"], 1)

    def test_error_envelopes_are_redacted(self):
        envelope = handler._fail("x.y", "code", "message", {"private_key": "leak"})
        self.assertEqual(envelope["error"]["detail"]["private_key"], handler.REDACTED)


class EgressTests(unittest.TestCase):
    def test_configured_host_is_allowed(self):
        handler._assert_allowed("https://example.okta.com/api/v1/users", "example.okta.com")

    def test_other_hosts_are_refused(self):
        for url in (
            "https://evil.example.com/api/v1/users",
            "https://example.okta.com.evil.com/api/v1/users",
            "https://other.okta.com/api/v1/users",
        ):
            with self.assertRaises(handler.AirlockError) as caught:
                handler._assert_allowed(url, "example.okta.com")
            self.assertEqual(caught.exception.code, "egress_blocked")

    def test_plain_http_is_refused_even_on_the_right_host(self):
        with self.assertRaises(handler.AirlockError):
            handler._assert_allowed("http://example.okta.com/api/v1/users", "example.okta.com")

    def test_org_url_must_be_an_okta_host(self):
        for org_url in ("https://example.com", "http://example.okta.com", "ftp://x"):
            with self.assertRaises(handler.AirlockError):
                handler._org_host({"org_url": org_url})

    def test_org_url_accepts_okta_and_preview_hosts(self):
        self.assertEqual(
            handler._org_host({"org_url": "https://acme.okta.com"}), "acme.okta.com"
        )
        self.assertEqual(
            handler._org_host({"org_url": "https://acme.oktapreview.com/"}),
            "acme.oktapreview.com",
        )


class OutcomeTests(unittest.TestCase):
    def test_unresolved_is_neither_success_nor_failure(self):
        envelope = handler._unresolved(
            "apply.group_membership",
            "no_answer",
            "Okta returned no usable response.",
            attempted={"group_id": "g1"},
            prior_state={"members": ["u1"]},
        )
        self.assertEqual(envelope["status"], "unresolved")
        self.assertNotIn(envelope["status"], ("ok", "failed"))
        self.assertIn("attempted", envelope)
        self.assertIn("prior_state", envelope)
        self.assertIn("recorded_at", envelope)

    def test_guard_converts_unexpected_exceptions_into_closed_failures(self):
        @handler._guard("test.command")
        def explode(inputs, context):
            raise ValueError("a secret value should not appear here")

        envelope = explode({}, {})
        self.assertEqual(envelope["status"], "failed")
        self.assertEqual(envelope["error"]["code"], "unexpected_error")
        self.assertNotIn("secret value", json.dumps(envelope))

    def test_guard_preserves_airlock_error_codes(self):
        @handler._guard("test.command")
        def refuse(inputs, context):
            raise handler.AirlockError("egress_blocked", "nope", {"private_key": "x"})

        envelope = refuse({}, {})
        self.assertEqual(envelope["error"]["code"], "egress_blocked")
        self.assertEqual(envelope["error"]["detail"]["private_key"], handler.REDACTED)


class CredentialTests(unittest.TestCase):
    def test_missing_vault_resolver_is_a_named_failure(self):
        saved = handler.__dict__.pop("vault_get", None)
        try:
            with self.assertRaises(handler.AirlockError) as caught:
                handler._vault_credentials()
            self.assertEqual(caught.exception.code, "vault_unavailable")
        finally:
            if saved is not None:
                handler.vault_get = saved

    def test_empty_credential_is_a_named_failure(self):
        handler.vault_get = lambda name: {}
        try:
            with self.assertRaises(handler.AirlockError) as caught:
                handler._vault_credentials()
            self.assertEqual(caught.exception.code, "credential_missing")
        finally:
            del handler.vault_get

    def test_missing_required_field_names_the_field(self):
        with self.assertRaises(handler.AirlockError) as caught:
            handler._require({"org_url": "https://a.okta.com"}, "client_id")
        self.assertEqual(caught.exception.detail["missing_field"], "client_id")


class RateBudgetTests(unittest.TestCase):
    def test_headers_are_recorded_per_bucket(self):
        budget = handler.RateBudget()
        budget.record(
            "/users",
            {
                "X-Rate-Limit-Limit": "600",
                "X-Rate-Limit-Remaining": "42",
                "X-Rate-Limit-Reset": "1757000000",
            },
        )
        self.assertEqual(budget.headroom("/users"), 42)
        self.assertEqual(budget.snapshot()["/users"]["limit"], 600)

    def test_absent_headers_record_nothing_rather_than_guessing_zero(self):
        budget = handler.RateBudget()
        budget.record("/users", {})
        self.assertEqual(budget.snapshot(), {})
        self.assertIsNone(budget.headroom("/users"))

    def test_unparsable_header_becomes_none_not_zero(self):
        budget = handler.RateBudget()
        budget.record("/users", {"X-Rate-Limit-Remaining": "unknown"})
        self.assertIsNone(budget.snapshot()["/users"]["remaining"])

    def test_bucket_is_the_first_path_segment(self):
        self.assertEqual(handler._bucket_for("/users/abc/groups"), "/users")
        self.assertEqual(handler._bucket_for("/logs"), "/logs")


class AssertionTests(unittest.TestCase):
    """The client assertion is the only place a private key is used."""

    RSA_KEY = None

    @classmethod
    def setUpClass(cls):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            raise unittest.SkipTest("cryptography is not installed")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.RSA_KEY = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def test_assertion_has_three_parts_and_the_expected_claims(self):
        token = handler._client_assertion(
            client_id="0oaTest",
            audience="https://acme.okta.com/oauth2/v1/token",
            private_key_pem=self.RSA_KEY,
            key_id="kid1",
        )
        parts = token.split(".")
        self.assertEqual(len(parts), 3)
        header = json.loads(_unb64(parts[0]))
        claims = json.loads(_unb64(parts[1]))
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["kid"], "kid1")
        self.assertEqual(claims["iss"], "0oaTest")
        self.assertEqual(claims["sub"], "0oaTest")
        self.assertEqual(claims["aud"], "https://acme.okta.com/oauth2/v1/token")
        self.assertGreater(claims["exp"], claims["iat"])

    def test_each_assertion_carries_a_fresh_jti(self):
        first = handler._client_assertion("c", "a", self.RSA_KEY)
        second = handler._client_assertion("c", "a", self.RSA_KEY)
        self.assertNotEqual(
            json.loads(_unb64(first.split(".")[1]))["jti"],
            json.loads(_unb64(second.split(".")[1]))["jti"],
        )

    def test_a_malformed_key_is_refused_by_name(self):
        with self.assertRaises(handler.AirlockError) as caught:
            handler._client_assertion("c", "a", "not a pem")
        self.assertEqual(caught.exception.code, "credential_invalid")


class ManifestTests(unittest.TestCase):
    """The manifest and the handler must not drift apart."""

    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parent.parent
        cls.manifest = json.loads((root / "module.json").read_text(encoding="utf8"))

    def test_every_declared_command_has_a_function(self):
        for command in self.manifest["commands"]:
            name = command["id"].replace(".", "_").replace("-", "_")
            self.assertTrue(
                hasattr(handler, name),
                "no function named " + name + " for command " + command["id"],
            )

    def test_every_command_has_an_id_and_a_usable_title(self):
        for command in self.manifest["commands"]:
            self.assertTrue(command.get("id"))
            self.assertGreaterEqual(len(command.get("title", "")), 3)

    def test_egress_is_declared_narrowly_and_nothing_else_is_claimed(self):
        requires = self.manifest["requires"]
        self.assertFalse(requires["subprocess"])
        self.assertEqual(requires["filesystem_writes"], [])
        for host in requires["network"]:
            self.assertTrue(host.endswith(("okta.com", "oktapreview.com")))

    def test_scope_probe_table_only_blocks_commands_that_could_exist(self):
        for probe in handler.SCOPE_PROBES.values():
            for command_id in probe["blocks"]:
                self.assertIn(".", command_id)


def _unb64(segment):
    import base64

    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding).decode("utf8")


if __name__ == "__main__":
    unittest.main()
