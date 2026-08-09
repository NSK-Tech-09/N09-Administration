import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from n09_admin.audit import AuditEvent
from n09_admin.domain import Identity, IdentityStatus
from n09_admin.federated_identity import (
    AssuranceLevel,
    ExternalIdentity,
    ExternalIdentityLinkRequest,
    ExternalPrincipal,
    LinkRequestStatus,
    LoginResult,
    PROVIDER_POLICIES,
    requires_step_up,
    resolve_login,
)
from n09_admin.persistence import SQLiteRepository


ISSUER_INFOMANIAK = "https://login.infomaniak.com"
ISSUER_EXAMPLE = "https://identity.example.org"


def audit_for(identity_id):
    return AuditEvent(
        correlation_id=uuid4(),
        occurred_at=datetime.now(UTC),
        actor_id=identity_id,
        subject_id=identity_id,
        action="external_identity.linked",
        result="success",
        justification="Lien confirme par le proprietaire",
        source="test",
    )


class FederatedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.repository = SQLiteRepository()
        self.identity = Identity(
            uuid4(), "fred@example.net", "Fred", IdentityStatus.ACTIVE
        )
        self.repository.save_identity(self.identity, audit_for(self.identity.identity_id))

    def tearDown(self):
        self.repository.close()

    def link(
        self,
        issuer=ISSUER_INFOMANIAK,
        subject="infomaniak-42",
        provider_key=None,
    ):
        link = ExternalIdentity(
            identity_id=self.identity.identity_id,
            issuer=issuer,
            subject=subject,
            provider_key=provider_key
            or ("infomaniak" if issuer == ISSUER_INFOMANIAK else "example"),
        )
        self.repository.link_external_identity(
            link, audit_for(self.identity.identity_id)
        )
        return link

    def test_linked_principal_authenticates(self):
        self.link()
        principal = ExternalPrincipal(
            ISSUER_INFOMANIAK,
            "infomaniak-42",
            "infomaniak",
            email="changed@example.net",
        )

        resolution = resolve_login(principal, self.repository)

        self.assertEqual(LoginResult.AUTHENTICATED, resolution.result)
        self.assertEqual(self.identity.identity_id, resolution.identity.identity_id)
        self.assertEqual(AssuranceLevel.STANDARD, resolution.assurance)

    def test_email_never_links_an_unknown_principal(self):
        self.link()
        principal = ExternalPrincipal(
            ISSUER_EXAMPLE,
            "other-subject",
            "google",
            email=self.identity.email,
        )

        resolution = resolve_login(principal, self.repository)

        self.assertEqual(LoginResult.LINK_REQUIRED, resolution.result)
        self.assertIsNone(resolution.identity)

    def test_multiple_providers_can_link_to_one_nsk_identity(self):
        self.link()
        self.link(ISSUER_EXAMPLE, "passkey-user-9")

        links = self.repository.list_external_identities(self.identity.identity_id)

        self.assertEqual(2, len(links))
        self.assertEqual({ISSUER_INFOMANIAK, ISSUER_EXAMPLE}, {x.issuer for x in links})

    def test_external_identity_cannot_be_linked_to_two_nsk_identities(self):
        self.link()
        other = Identity(uuid4(), "other@example.net", "Other", IdentityStatus.ACTIVE)
        self.repository.save_identity(other, audit_for(other.identity_id))
        duplicate = ExternalIdentity(
            identity_id=other.identity_id,
            issuer=ISSUER_INFOMANIAK,
            subject="infomaniak-42",
            provider_key="infomaniak",
        )

        with self.assertRaisesRegex(ValueError, "already linked"):
            self.repository.link_external_identity(duplicate, audit_for(other.identity_id))

    def test_suspended_nsk_identity_is_denied(self):
        self.link()
        suspended = Identity(
            self.identity.identity_id,
            self.identity.email,
            self.identity.display_name,
            IdentityStatus.SUSPENDED,
        )
        self.repository.save_identity(
            suspended,
            AuditEvent(
                correlation_id=uuid4(),
                occurred_at=datetime.now(UTC),
                actor_id=self.identity.identity_id,
                subject_id=self.identity.identity_id,
                action="identity.suspended",
                result="success",
                previous_value={"status": "active"},
                justification="Test",
                source="test",
            ),
        )

        resolution = resolve_login(
            ExternalPrincipal(ISSUER_INFOMANIAK, "infomaniak-42", "infomaniak"),
            self.repository,
        )

        self.assertEqual(LoginResult.DENIED, resolution.result)
        self.assertIn("suspended", resolution.reason)

    def test_non_https_issuer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            ExternalPrincipal("http://unsafe.example", "subject", "unsafe")

    def test_link_is_audited_in_the_same_transaction(self):
        before = self.repository.audit_count()

        self.link()

        self.assertEqual(before + 1, self.repository.audit_count())
        self.assertTrue(self.repository.verify_audit_chain())

    def test_universal_provider_catalog_has_expected_entry_points(self):
        self.assertEqual(
            {"infomaniak", "google", "microsoft", "github", "passkey", "email", "phone"},
            set(PROVIDER_POLICIES),
        )
        self.assertEqual(AssuranceLevel.STRONG, PROVIDER_POLICIES["passkey"].assurance)
        self.assertEqual(AssuranceLevel.LIMITED, PROVIDER_POLICIES["phone"].assurance)

    def test_phone_login_requires_step_up_for_sensitive_action(self):
        self.link("https://phone.nsktech.fr", "+33600000000", "phone")

        resolution = resolve_login(
            ExternalPrincipal(
                "https://phone.nsktech.fr", "+33600000000", "phone"
            ),
            self.repository,
        )

        self.assertEqual(LoginResult.AUTHENTICATED, resolution.result)
        self.assertEqual(AssuranceLevel.LIMITED, resolution.assurance)
        self.assertTrue(requires_step_up(resolution))

    def test_provider_mismatch_is_denied(self):
        self.link()

        resolution = resolve_login(
            ExternalPrincipal(ISSUER_INFOMANIAK, "infomaniak-42", "google"),
            self.repository,
        )

        self.assertEqual(LoginResult.DENIED, resolution.result)
        self.assertEqual("provider mismatch", resolution.reason)

    def test_unknown_principal_creates_only_a_pending_link_request(self):
        now = datetime.now(UTC)
        request = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK, subject="external-user-2965",
            provider_key="infomaniak", email_hint=self.identity.email,
            display_name_hint=self.identity.display_name, requested_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        self.repository.save_link_request(
            request,
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                action="external_identity.link_requested", result="pending",
                source="infomaniak-callback",
                new_value={"request_id": str(request.request_id)},
            ),
        )

        stored = self.repository.get_link_request(request.request_id)
        self.assertEqual(LinkRequestStatus.PENDING, stored.status)
        self.assertIsNone(
            self.repository.find_external_identity(
                ISSUER_INFOMANIAK, "external-user-2965"
            )
        )
        self.assertEqual(
            [], self.repository.list_assignments(self.identity.identity_id, "tasks")
        )

    def test_explicit_approval_links_identity_without_granting_access(self):
        now = datetime.now(UTC)
        request = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK, subject="external-user-2965",
            provider_key="infomaniak", requested_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        self.repository.save_link_request(
            request,
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                action="external_identity.link_requested", result="pending",
                source="infomaniak-callback",
            ),
        )
        link = self.repository.approve_link_request(
            request.request_id, self.identity.identity_id,
            self.identity.identity_id, "Identite controlee par l'administrateur",
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                actor_id=self.identity.identity_id,
                subject_id=self.identity.identity_id,
                action="external_identity.link_approved", result="success",
                source="n09-administration",
                previous_value={"status": "pending"},
                new_value={"status": "approved"},
                justification="Identite controlee par l'administrateur",
            ),
            now=now + timedelta(seconds=5),
        )

        stored = self.repository.get_link_request(request.request_id)
        self.assertEqual(LinkRequestStatus.APPROVED, stored.status)
        self.assertEqual(self.identity.identity_id, link.identity_id)
        self.assertEqual(
            [], self.repository.list_assignments(self.identity.identity_id, "tasks")
        )
        self.assertTrue(self.repository.verify_audit_chain())

    def test_expired_link_request_cannot_be_approved(self):
        now = datetime.now(UTC)
        request = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK, subject="expired-subject",
            provider_key="infomaniak", requested_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=5),
        )
        self.repository.save_link_request(
            request,
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                action="external_identity.link_requested", result="pending",
                source="tests",
            ),
        )

        with self.assertRaisesRegex(ValueError, "expired"):
            self.repository.approve_link_request(
                request.request_id, self.identity.identity_id,
                self.identity.identity_id, "Too late",
                AuditEvent(
                    correlation_id=uuid4(), occurred_at=now,
                    actor_id=self.identity.identity_id,
                    subject_id=self.identity.identity_id,
                    action="external_identity.link_approved", result="denied",
                    source="tests", previous_value={"status": "pending"},
                    justification="Too late",
                ),
                now=now,
            )

    def test_expired_request_does_not_block_a_new_request(self):
        now = datetime.now(UTC)
        expired = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK,
            subject="returning-user",
            provider_key="infomaniak",
            requested_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=5),
        )
        replacement = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK,
            subject="returning-user",
            provider_key="infomaniak",
            requested_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        for request in (expired, replacement):
            self.repository.save_link_request(
                request,
                AuditEvent(
                    correlation_id=uuid4(),
                    occurred_at=now,
                    action="external_identity.link_requested",
                    result="pending",
                    source="tests",
                ),
            )

        self.assertTrue(expired.is_expired(now))
        self.assertFalse(replacement.is_expired(now))

    def test_rejection_closes_request_without_creating_identity_link(self):
        now = datetime.now(UTC)
        request = ExternalIdentityLinkRequest(
            issuer=ISSUER_INFOMANIAK, subject="rejected-subject",
            provider_key="infomaniak", requested_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        self.repository.save_link_request(
            request,
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                action="external_identity.link_requested", result="pending",
                source="tests",
            ),
        )
        self.repository.reject_link_request(
            request.request_id, self.identity.identity_id,
            "Compte externe non reconnu",
            AuditEvent(
                correlation_id=uuid4(), occurred_at=now,
                actor_id=self.identity.identity_id,
                action="external_identity.link_rejected", result="success",
                source="n09-administration",
                previous_value={"status": "pending"},
                new_value={"status": "rejected"},
                justification="Compte externe non reconnu",
            ),
        )

        stored = self.repository.get_link_request(request.request_id)
        self.assertEqual(LinkRequestStatus.REJECTED, stored.status)
        self.assertIsNone(
            self.repository.find_external_identity(
                ISSUER_INFOMANIAK, "rejected-subject"
            )
        )
        self.assertTrue(self.repository.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
