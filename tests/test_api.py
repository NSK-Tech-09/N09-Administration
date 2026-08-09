import unittest
from datetime import datetime, timezone
from uuid import uuid4

from n09_admin.api import AuthenticatedApplication, evaluate_access_request
from n09_admin.audit import AuditEvent
from n09_admin.domain import (
    AccessAssignment,
    Application,
    AssignmentStatus,
    Identity,
    IdentityStatus,
)
from n09_admin.persistence import SQLiteRepository


class InternalApiTests(unittest.TestCase):
    def setUp(self):
        self.repository = SQLiteRepository()
        self.identity = Identity(
            uuid4(), "user@example.test", "Utilisateur", IdentityStatus.ACTIVE
        )
        self.application = Application("tasks", "N09 – Suivi des tâches")
        self.correlation_id = uuid4()
        self.principal = AuthenticatedApplication(
            "tasks", "tasks", self.correlation_id
        )
        self.repository.save_identity(
            self.identity, self.audit("identity.created", subject=True)
        )
        self.repository.save_application(
            self.application, self.audit("application.registered", application=True)
        )
        self.assignment = AccessAssignment(
            subject_id=self.identity.identity_id,
            application_id="tasks",
            role_id="reader",
            permissions=frozenset({"tasks:read"}),
            scope_type="site",
            scope_id="site-09",
            status=AssignmentStatus.ACTIVE,
        )
        self.repository.save_assignment(
            self.assignment,
            self.audit("assignment.created", subject=True, application=True, role=True),
        )

    def tearDown(self):
        self.repository.close()

    def audit(self, action, *, subject=False, application=False, role=False):
        return AuditEvent(
            action=action,
            result="success",
            source="tests",
            correlation_id=self.correlation_id,
            subject_id=self.identity.identity_id if subject else None,
            application_id="tasks" if application else None,
            role_id="reader" if role else None,
            new_value={"action": action},
        )

    def payload(self, **changes):
        value = {
            "identity_id": str(self.identity.identity_id),
            "application_id": "tasks",
            "required_permission": "tasks:read",
            "scope_type": "site",
            "scope_id": "site-09",
            "satisfied_conditions": [],
        }
        value.update(changes)
        return value

    def test_denies_anonymous_request(self):
        response = evaluate_access_request(
            repository=self.repository, principal=None, payload=self.payload()
        )
        self.assertEqual(401, response.status)

    def test_denies_invalid_audience(self):
        principal = AuthenticatedApplication("tasks", "energy", uuid4())
        response = evaluate_access_request(
            repository=self.repository, principal=principal, payload=self.payload()
        )
        self.assertEqual(403, response.status)

    def test_denies_cross_application_query(self):
        response = evaluate_access_request(
            repository=self.repository,
            principal=self.principal,
            payload=self.payload(application_id="energy"),
        )
        self.assertEqual("application_boundary_violation", response.body["error"])

    def test_rejects_unknown_fields(self):
        response = evaluate_access_request(
            repository=self.repository,
            principal=self.principal,
            payload=self.payload(password="forbidden"),
        )
        self.assertEqual(400, response.status)

    def test_returns_neutral_not_found(self):
        response = evaluate_access_request(
            repository=self.repository,
            principal=self.principal,
            payload=self.payload(identity_id=str(uuid4())),
        )
        self.assertEqual({"error": "resource_not_found"}, response.body)

    def test_returns_contextual_access_decision(self):
        response = evaluate_access_request(
            repository=self.repository,
            principal=self.principal,
            payload=self.payload(),
        )
        self.assertEqual(200, response.status)
        self.assertEqual({"allowed": True, "reason_code": "access_granted"}, response.body)
        self.assertEqual(self.correlation_id, response.correlation_id)

    def test_denied_access_is_a_successful_api_decision(self):
        response = evaluate_access_request(
            repository=self.repository,
            principal=self.principal,
            payload=self.payload(scope_id="site-11"),
        )
        self.assertEqual(200, response.status)
        self.assertFalse(response.body["allowed"])


if __name__ == "__main__":
    unittest.main()
