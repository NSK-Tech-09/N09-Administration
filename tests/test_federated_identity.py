import unittest
from datetime import UTC, datetime
from uuid import uuid4

from n09_admin.audit import AuditEvent
from n09_admin.domain import Identity, IdentityStatus
from n09_admin.federated_identity import (
    ExternalIdentity,
    ExternalPrincipal,
    LoginResult,
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

    def link(self, issuer=ISSUER_INFOMANIAK, subject="infomaniak-42"):
        link = ExternalIdentity(
            identity_id=self.identity.identity_id,
            issuer=issuer,
            subject=subject,
            provider_key="infomaniak" if issuer == ISSUER_INFOMANIAK else "example",
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

    def test_email_never_links_an_unknown_principal(self):
        self.link()
        principal = ExternalPrincipal(
            ISSUER_EXAMPLE,
            "other-subject",
            "example",
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


if __name__ == "__main__":
    unittest.main()
