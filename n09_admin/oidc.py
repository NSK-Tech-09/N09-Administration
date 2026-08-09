from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
import secrets
from typing import Mapping, Sequence
from urllib.parse import urlencode, urlparse

from .federated_identity import ExternalPrincipal


def _require_https_url(value: str, label: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{label} must be an absolute HTTPS URL")


@dataclass(frozen=True, slots=True)
class OidcProviderConfig:
    provider_key: str
    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str

    def __post_init__(self) -> None:
        if not self.provider_key.strip() or not self.client_id.strip():
            raise ValueError("provider key and client ID must not be empty")
        _require_https_url(self.issuer, "issuer")
        _require_https_url(self.authorization_endpoint, "authorization endpoint")
        _require_https_url(self.token_endpoint, "token endpoint")
        _require_https_url(self.jwks_uri, "JWKS URI")

    @classmethod
    def from_discovery_document(
        cls,
        *,
        provider_key: str,
        expected_issuer: str,
        client_id: str,
        document: Mapping[str, object],
    ) -> OidcProviderConfig:
        """Construit une configuration seulement si la découverte est exacte."""

        issuer = document.get("issuer")
        if issuer != expected_issuer:
            raise ValueError("discovery issuer does not match expected issuer")
        required = ("authorization_endpoint", "token_endpoint", "jwks_uri")
        if any(not isinstance(document.get(key), str) for key in required):
            raise ValueError("discovery document is incomplete")
        return cls(
            provider_key=provider_key,
            issuer=expected_issuer,
            client_id=client_id,
            authorization_endpoint=str(document["authorization_endpoint"]),
            token_endpoint=str(document["token_endpoint"]),
            jwks_uri=str(document["jwks_uri"]),
        )


@dataclass(frozen=True, slots=True)
class OidcSession:
    authorization_url: str
    state: str
    nonce: str
    code_verifier: str


def create_authorization_session(
    config: OidcProviderConfig,
    redirect_uri: str,
    scopes: Sequence[str] = ("openid", "profile"),
) -> OidcSession:
    """Prépare Authorization Code + PKCE sans stocker de secret fournisseur."""

    parsed_redirect = urlparse(redirect_uri)
    is_local = parsed_redirect.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed_redirect.scheme != "https" and not (
        is_local and parsed_redirect.scheme == "http"
    ):
        raise ValueError("redirect URI must use HTTPS outside local development")
    if "openid" not in scopes:
        raise ValueError("openid scope is required")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    challenge = urlsafe_b64encode(sha256(code_verifier.encode()).digest()).rstrip(
        b"="
    ).decode()
    query = urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return OidcSession(
        authorization_url=f"{config.authorization_endpoint}?{query}",
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
    )


def validate_callback_state(expected: str, received: str | None) -> None:
    if received is None or not compare_digest(expected, received):
        raise ValueError("OIDC state mismatch")


def principal_from_verified_claims(
    config: OidcProviderConfig,
    claims: Mapping[str, object],
    *,
    expected_nonce: str,
    now: datetime | None = None,
    clock_skew_seconds: int = 60,
) -> ExternalPrincipal:
    """Valide les claims après vérification cryptographique du JWT.

    L'appelant doit d'abord vérifier la signature et l'algorithme du jeton à
    partir du JWKS du fournisseur. Cette fonction refuse les claims incohérents
    avant de les traduire en identité externe NSK.
    """

    current = (now or datetime.now(UTC)).timestamp()
    if claims.get("iss") != config.issuer:
        raise ValueError("token issuer mismatch")

    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or config.client_id not in audiences:
        raise ValueError("token audience mismatch")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("token subject is missing")

    expires_at = claims.get("exp")
    if not isinstance(expires_at, (int, float)) or expires_at <= current - clock_skew_seconds:
        raise ValueError("token is expired")

    issued_at = claims.get("iat")
    if isinstance(issued_at, (int, float)) and issued_at > current + clock_skew_seconds:
        raise ValueError("token was issued in the future")

    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not compare_digest(expected_nonce, nonce):
        raise ValueError("token nonce mismatch")

    email = claims.get("email")
    display_name = claims.get("name")
    return ExternalPrincipal(
        issuer=config.issuer,
        subject=subject,
        provider_key=config.provider_key,
        email=email if isinstance(email, str) else None,
        display_name=display_name if isinstance(display_name, str) else None,
    )
