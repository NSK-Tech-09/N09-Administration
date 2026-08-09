import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from n09_admin.access import decide_access
from n09_admin.domain import (
    AccessAssignment,
    Application,
    ApplicationStatus,
    AssignmentStatus,
    Identity,
    IdentityStatus,
)


class AccessDecisionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 9, 12, tzinfo=timezone.utc)
        self.identity = Identity(
            identity_id=uuid4(),
            email="collegue@example.test",
            display_name="Collègue",
            status=IdentityStatus.ACTIVE,
        )
        self.application = Application("tasks", "N09 – Suivi des tâches")

    def assignment(self, **changes):
        values = {
            "subject_id": self.identity.identity_id,
            "application_id": "tasks",
            "role_id": "reader",
            "permissions": frozenset({"tasks:read"}),
            "scope_type": "site",
            "scope_id": "site-09",
            "status": AssignmentStatus.ACTIVE,
        }
        values.update(changes)
        return AccessAssignment(**values)

    def decide(self, assignments=None, **changes):
        values = {
            "identity": self.identity,
            "application": self.application,
            "assignments": [self.assignment()] if assignments is None else assignments,
            "required_permission": "tasks:read",
            "scope_type": "site",
            "scope_id": "site-09",
            "now": self.now,
        }
        values.update(changes)
        return decide_access(**values)

    def test_grants_explicit_contextual_permission(self):
        self.assertEqual("access_granted", self.decide().reason_code)

    def test_denies_without_assignment(self):
        self.assertEqual("assignment_missing", self.decide(assignments=[]).reason_code)

    def test_denies_suspended_identity(self):
        suspended = Identity(
            self.identity.identity_id,
            self.identity.email,
            self.identity.display_name,
            IdentityStatus.SUSPENDED,
        )
        self.assertEqual("identity_not_active", self.decide(identity=suspended).reason_code)

    def test_denies_expired_assignment(self):
        assignment = self.assignment(valid_until=self.now - timedelta(seconds=1))
        self.assertEqual(
            "permission_or_validity_missing",
            self.decide(assignments=[assignment]).reason_code,
        )

    def test_denies_unknown_permission(self):
        self.assertEqual(
            "permission_or_validity_missing",
            self.decide(required_permission="tasks:admin").reason_code,
        )

    def test_denies_other_scope(self):
        self.assertEqual("scope_mismatch", self.decide(scope_id="site-11").reason_code)

    def test_denies_unsatisfied_condition(self):
        assignment = self.assignment(conditions=frozenset({"mfa"}))
        self.assertEqual(
            "conditions_not_satisfied",
            self.decide(assignments=[assignment]).reason_code,
        )

    def test_accepts_inherited_group_assignment(self):
        assignment = self.assignment(inherited_from_group=uuid4())
        self.assertTrue(self.decide(assignments=[assignment]).allowed)

    def test_denies_assignment_for_another_application(self):
        assignment = self.assignment(application_id="energy")
        self.assertEqual("assignment_missing", self.decide(assignments=[assignment]).reason_code)

    def test_super_admin_role_does_not_bypass_business_scope(self):
        assignment = self.assignment(
            role_id="nsk_super_admin",
            permissions=frozenset({"administration:manage"}),
            scope_type=None,
            scope_id=None,
        )
        self.assertFalse(self.decide(assignments=[assignment]).allowed)

    def test_denies_application_in_maintenance(self):
        application = Application(
            "tasks",
            "N09 – Suivi des tâches",
            ApplicationStatus.MAINTENANCE,
        )
        self.assertEqual(
            "application_not_active",
            self.decide(application=application).reason_code,
        )


if __name__ == "__main__":
    unittest.main()
