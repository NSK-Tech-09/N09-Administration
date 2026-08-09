import unittest
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from n09_admin.oidc import (
    OidcProviderConfig,
    create_authorization_session,
    principal_from_verified_claims,
    validate_callback_state,
)


ISSUER = "https://identity.example.org"
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def config():
    return OidcProviderConfig(
        provider_key="infomaniak",
        issuer=ISSUER,
        client_id="n09-administration",
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
    )


def claims(**overrides):
    values = {
        "iss": ISSUER,
        "sub": "opaque-user-42",
        "aud": "n09-administration",
        "exp": (NOW + timedelta(minutes=5)).timestamp(),
        "iat": NOW.timestamp(),
        "nonce": "expected-nonce",
        "email": "display-only@example.net",
        "name": "Utilisateur de test",
    }
    values.update(overrides)
    return values


class OidcTests(unittest.TestCase):
    def test_discovery_document_must_match_expected_issuer(self):
        document = {
            "issuer": "https://attacker.example",
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
        }

        with self.assertRaisesRegex(ValueError, "does not match"):
            OidcProviderConfig.from_discovery_document(
                provider_key="infomaniak",
                expected_issuer=ISSUER,
                client_id="n09-administration",
                document=document,
            )

    def test_provider_endpoints_require_https(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            OidcProviderConfig(
                "unsafe", "http://identity.example", "client",
                "https://identity.example/authorize",
                "https://identity.example/token",
                "https://identity.example/jwks",
            )

    def test_authorization_session_uses_state_nonce_and_pkce(self):
        session = create_authorization_session(
            config(), "http://localhost:3000/auth/callback"
        )
        query = parse_qs(urlparse(session.authorization_url).query)

        self.assertEqual(["code"], query["response_type"])
        self.assertEqual(["S256"], query["code_challenge_method"])
        self.assertEqual([session.state], query["state"])
        self.assertEqual([session.nonce], query["nonce"])
        self.assertNotEqual(session.code_verifier, query["code_challenge"][0])

    def test_callback_state_must_match_exactly(self):
        validate_callback_state("expected", "expected")
        with self.assertRaisesRegex(ValueError, "state mismatch"):
            validate_callback_state("expected", "different")

    def test_verified_claims_become_external_principal(self):
        principal = principal_from_verified_claims(
            config(), claims(), expected_nonce="expected-nonce", now=NOW
        )

        self.assertEqual("opaque-user-42", principal.subject)
        self.assertEqual("infomaniak", principal.provider_key)
        self.assertEqual("display-only@example.net", principal.email)

    def test_email_is_not_required(self):
        principal = principal_from_verified_claims(
            config(), claims(email=None), expected_nonce="expected-nonce", now=NOW
        )

        self.assertIsNone(principal.email)

    def test_wrong_audience_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "audience"):
            principal_from_verified_claims(
                config(), claims(aud="another-app"),
                expected_nonce="expected-nonce", now=NOW,
            )

    def test_expired_token_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            principal_from_verified_claims(
                config(), claims(exp=(NOW - timedelta(minutes=2)).timestamp()),
                expected_nonce="expected-nonce", now=NOW,
            )

    def test_wrong_nonce_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonce"):
            principal_from_verified_claims(
                config(), claims(nonce="wrong"),
                expected_nonce="expected-nonce", now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
