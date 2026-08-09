from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Protocol
from urllib.parse import urlparse
from uuid import UUID, uuid4

from .domain import Identity, IdentityStatus


class ExternalIdentityStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class LoginResult(StrEnum):
    AUTHENTICATED = "authenticated"
    LINK_REQUIRED = "link_required"
    DENIED = "denied"


class AuthenticationProtocol(StrEnum):
    OIDC = "oidc"
    OAUTH2 = "oauth2"
    WEBAUTHN = "webauthn"
    EMAIL_LINK = "email_link"
    SMS = "sms"


class AssuranceLevel(IntEnum):
    LIMITED = 1
    STANDARD = 2
    STRONG = 3


@dataclass(frozen=True, slots=True)
class ProviderPolicy:
    provider_key: str
    display_name: str
    protocol: AuthenticationProtocol
    assurance: AssuranceLevel
    enabled: bool = True
    reason: str = ""


PROVIDER_POLICIES = {
    policy.provider_key: policy
    for policy in (
        ProviderPolicy(
            "infomaniak", "Infomaniak", AuthenticationProtocol.OIDC,
            AssuranceLevel.STANDARD,
        ),
        ProviderPolicy(
            "google", "Google", AuthenticationProtocol.OIDC,
            AssuranceLevel.STANDARD,
        ),
        ProviderPolicy(
            "microsoft", "Microsoft", AuthenticationProtocol.OIDC,
            AssuranceLevel.STANDARD,
        ),
        ProviderPolicy(
            "github", "GitHub", AuthenticationProtocol.OAUTH2,
            AssuranceLevel.STANDARD,
        ),
        ProviderPolicy(
            "passkey", "Clé d'accès", AuthenticationProtocol.WEBAUTHN,
            AssuranceLevel.STRONG,
        ),
        ProviderPolicy(
            "email", "Lien par e-mail", AuthenticationProtocol.EMAIL_LINK,
            AssuranceLevel.LIMITED,
            reason="A second method is required for sensitive actions",
        ),
        ProviderPolicy(
            "phone", "Téléphone", AuthenticationProtocol.SMS,
            AssuranceLevel.LIMITED,
            reason="Phone numbers can be reassigned or transferred",
        ),
    )
}


@dataclass(frozen=True, slots=True)
class ExternalPrincipal:
    """Identite attestee par un fournisseur OIDC, avant decision NSK."""

    issuer: str
    subject: str
    provider_key: str
    email: str | None = None
    display_name: str | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.issuer)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("OIDC issuer must be an absolute HTTPS URL")
        if not self.subject.strip():
            raise ValueError("OIDC subject must not be empty")
        if not self.provider_key.strip():
            raise ValueError("provider key must not be empty")


@dataclass(frozen=True, slots=True)
class ExternalIdentity:
    """Lien explicite entre une identite externe et une identite NSK stable."""

    identity_id: UUID
    issuer: str
    subject: str
    provider_key: str
    status: ExternalIdentityStatus = ExternalIdentityStatus.ACTIVE
    linked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    external_identity_id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class LoginResolution:
    result: LoginResult
    identity: Identity | None = None
    reason: str = ""
    assurance: AssuranceLevel | None = None


class IdentityDirectory(Protocol):
    def find_external_identity(
        self, issuer: str, subject: str
    ) -> ExternalIdentity | None: ...

    def get_identity(self, identity_id: UUID) -> Identity | None: ...


def resolve_login(
    principal: ExternalPrincipal, directory: IdentityDirectory
) -> LoginResolution:
    """Resout une connexion sans jamais deduire l'identite depuis l'email."""

    link = directory.find_external_identity(principal.issuer, principal.subject)
    policy = PROVIDER_POLICIES.get(principal.provider_key)
    if policy is None or not policy.enabled:
        return LoginResolution(LoginResult.DENIED, reason="provider is not enabled")
    if link is None:
        return LoginResolution(
            LoginResult.LINK_REQUIRED,
            reason="external identity is not linked to an NSK identity",
        )
    if link.status is not ExternalIdentityStatus.ACTIVE:
        return LoginResolution(LoginResult.DENIED, reason="external identity revoked")
    if link.provider_key != principal.provider_key:
        return LoginResolution(LoginResult.DENIED, reason="provider mismatch")

    identity = directory.get_identity(link.identity_id)
    if identity is None:
        return LoginResolution(LoginResult.DENIED, reason="NSK identity not found")
    if identity.status is not IdentityStatus.ACTIVE:
        return LoginResolution(
            LoginResult.DENIED,
            identity=identity,
            reason=f"NSK identity is {identity.status.value}",
        )
    return LoginResolution(
        LoginResult.AUTHENTICATED,
        identity=identity,
        assurance=policy.assurance,
    )


def requires_step_up(
    resolution: LoginResolution,
    required: AssuranceLevel = AssuranceLevel.STRONG,
) -> bool:
    """Indique si une preuve plus forte est requise pour continuer."""

    return (
        resolution.result is not LoginResult.AUTHENTICATED
        or resolution.assurance is None
        or resolution.assurance < required
    )
