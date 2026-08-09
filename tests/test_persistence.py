import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from n09_admin.audit import AuditEvent
from n09_admin.domain import (
    AccessAssignment,
    Application,
    AssignmentStatus,
    Identity,
    IdentityStatus,
    RegistrationPolicy,
)
from n09_admin.persistence import SQLiteRepository
from n09_admin.governance import (
    DecisionAction,
    Delegation,
    Group,
    GroupMembership,
    RequestStatus,
    decide_request_line,
    submit_access_request,
)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.repository = SQLiteRepository()
        self.actor_id = uuid4()
        self.correlation_id = uuid4()
        self.identity = Identity(
            uuid4(), "COLLEGUE@example.test", "Collègue", IdentityStatus.ACTIVE
        )
        self.application = Application("tasks", "N09 – Suivi des tâches")

    def tearDown(self):
        self.repository.close()

    def audit(self, action, *, subject_id=None, application_id=None, role_id=None,
              previous_value=None, new_value=None):
        return AuditEvent(
            action=action,
            result="success",
            source="tests",
            correlation_id=self.correlation_id,
            actor_id=self.actor_id,
            subject_id=subject_id,
            application_id=application_id,
            role_id=role_id,
            previous_value=previous_value,
            new_value=new_value,
            justification="Test reproductible",
        )

    def save_prerequisites(self):
        self.repository.save_identity(
            self.identity,
            self.audit(
                "identity.created",
                subject_id=self.identity.identity_id,
                new_value={"status": "active"},
            ),
        )
        self.repository.save_application(
            self.application,
            self.audit(
                "application.registered",
                application_id="tasks",
                new_value={"registration_policy": "closed"},
            ),
        )

    def test_round_trips_identity_and_normalizes_email(self):
        self.repository.save_identity(
            self.identity,
            self.audit(
                "identity.created",
                subject_id=self.identity.identity_id,
                new_value={"status": "active"},
            ),
        )
        loaded = self.repository.get_identity(self.identity.identity_id)
        self.assertEqual("collegue@example.test", loaded.email)
        self.assertEqual(IdentityStatus.ACTIVE, loaded.status)
        self.assertEqual(1, self.repository.audit_count())

    def test_business_write_and_audit_are_atomic(self):
        unsafe_event = self.audit(
            "identity.created",
            subject_id=self.identity.identity_id,
            new_value={"status": "active"},
        )
        duplicate = Identity(
            uuid4(), self.identity.email.lower(), "Doublon", IdentityStatus.ACTIVE
        )
        self.repository.save_identity(self.identity, unsafe_event)
        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.save_identity(
                duplicate,
                self.audit(
                    "identity.created",
                    subject_id=duplicate.identity_id,
                    new_value={"status": "active"},
                ),
            )
        self.assertIsNone(self.repository.get_identity(duplicate.identity_id))
        self.assertEqual(1, self.repository.audit_count())

    def test_round_trips_contextual_assignment(self):
        self.save_prerequisites()
        now = datetime(2026, 8, 9, 12, tzinfo=timezone.utc)
        assignment = AccessAssignment(
            subject_id=self.identity.identity_id,
            application_id="tasks",
            role_id="reader",
            permissions=frozenset({"tasks:read"}),
            scope_type="site",
            scope_id="site-09",
            conditions=frozenset({"mfa"}),
            status=AssignmentStatus.ACTIVE,
            valid_from=now,
            valid_until=now + timedelta(days=30),
            reason="Mission temporaire",
            decided_by=self.actor_id,
        )
        self.repository.save_assignment(
            assignment,
            self.audit(
                "assignment.created",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                role_id="reader",
                new_value={"scope_id": "site-09"},
            ),
        )
        self.assertEqual(
            assignment,
            self.repository.list_assignments(self.identity.identity_id, "tasks")[0],
        )
        self.assertTrue(self.repository.verify_audit_chain())

    def test_rejects_stale_assignment_update(self):
        self.save_prerequisites()
        assignment = AccessAssignment(
            subject_id=self.identity.identity_id,
            application_id="tasks",
            role_id="reader",
            status=AssignmentStatus.ACTIVE,
        )
        self.repository.save_assignment(
            assignment,
            self.audit(
                "assignment.created",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                role_id="reader",
                new_value={"status": "active"},
            ),
        )
        with self.assertRaises(ValueError):
            self.repository.save_assignment(
                assignment,
                self.audit(
                    "assignment.updated",
                    subject_id=self.identity.identity_id,
                    application_id="tasks",
                    role_id="reader",
                    previous_value={"status": "active"},
                    new_value={"status": "active"},
                ),
            )

    def test_accepts_next_assignment_version(self):
        self.save_prerequisites()
        assignment = AccessAssignment(
            subject_id=self.identity.identity_id,
            application_id="tasks",
            role_id="reader",
            status=AssignmentStatus.ACTIVE,
        )
        self.repository.save_assignment(
            assignment,
            self.audit(
                "assignment.created",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                role_id="reader",
                new_value={"status": "active"},
            ),
        )
        revoked = replace(
            assignment, status=AssignmentStatus.REVOKED, version=2
        )
        self.repository.save_assignment(
            revoked,
            self.audit(
                "assignment.revoked",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                role_id="reader",
                previous_value={"status": "active"},
                new_value={"status": "revoked"},
            ),
        )
        self.assertEqual(
            AssignmentStatus.REVOKED,
            self.repository.list_assignments(self.identity.identity_id, "tasks")[0].status,
        )

    def test_audit_rows_cannot_be_updated_or_deleted(self):
        self.save_prerequisites()
        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.connection.execute(
                "UPDATE audit_events SET result = 'failure' WHERE sequence = 1"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.connection.execute(
                "DELETE FROM audit_events WHERE sequence = 1"
            )

    def test_rejects_secret_shaped_audit_data(self):
        with self.assertRaisesRegex(ValueError, "forbidden audit field"):
            self.audit(
                "identity.created",
                subject_id=self.identity.identity_id,
                new_value={"access_token": "never-log-this"},
            )

    def test_update_requires_previous_value(self):
        self.repository.save_identity(
            self.identity,
            self.audit(
                "identity.created",
                subject_id=self.identity.identity_id,
                new_value={"status": "active"},
            ),
        )
        changed = replace(self.identity, display_name="Nouveau nom")
        with self.assertRaises(ValueError):
            self.repository.save_identity(
                changed,
                self.audit(
                    "identity.updated",
                    subject_id=self.identity.identity_id,
                    new_value={"display_name": "Nouveau nom"},
                ),
            )
        self.assertEqual("Collègue", self.repository.get_identity(self.identity.identity_id).display_name)

    def test_persists_group_membership_and_delegation_with_audit(self):
        self.save_prerequisites()
        group = Group(
            name="Responsables site 09",
            purpose="Administrer les accès du site 09",
            owner_id=self.identity.identity_id,
            review_due_at=datetime(2027, 2, 9, tzinfo=timezone.utc),
        )
        self.repository.save_group(
            group,
            self.audit("group.created", new_value={"name": group.name}),
        )
        membership = GroupMembership(group.group_id, self.identity.identity_id)
        self.repository.save_group_membership(
            membership,
            self.audit(
                "group.membership.created",
                subject_id=self.identity.identity_id,
                new_value={"group_id": str(group.group_id)},
            ),
        )
        delegation = Delegation(
            administrator_id=self.identity.identity_id,
            application_id="tasks",
            manageable_role_ids=frozenset({"reader"}),
            scope_type="site",
            manageable_scope_ids=frozenset({"site-09"}),
            allowed_actions=frozenset({DecisionAction.APPROVE}),
            justification="Responsable désigné",
            valid_from=datetime(2026, 8, 9, tzinfo=timezone.utc),
            valid_until=datetime(2027, 2, 9, tzinfo=timezone.utc),
        )
        self.repository.save_delegation(
            delegation,
            self.audit(
                "delegation.created",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                new_value={"scope_ids": ["site-09"]},
            ),
        )
        self.assertEqual(5, self.repository.audit_count())
        self.assertTrue(self.repository.verify_audit_chain())

    def test_persists_independent_request_lines_and_decision(self):
        self.save_prerequisites()
        request_id = uuid4()
        line = submit_access_request(
            application=replace(
                self.application,
                registration_policy=RegistrationPolicy.APPROVAL,
            ),
            subject_id=self.identity.identity_id,
            requested_role_id="reader",
            scope_type="site",
            scope_id="site-09",
            reason="Participer",
            request_id=request_id,
        )
        self.repository.save_request_line(
            line,
            self.audit(
                "access_request.submitted",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                new_value={"status": "pending"},
            ),
        )
        delegation = Delegation(
            administrator_id=self.actor_id,
            application_id="tasks",
            manageable_role_ids=frozenset({"reader"}),
            scope_type="site",
            manageable_scope_ids=frozenset({"site-09"}),
            allowed_actions=frozenset({DecisionAction.APPROVE}),
            justification="Délégation test",
            valid_from=datetime(2026, 8, 8, tzinfo=timezone.utc),
            valid_until=datetime(2026, 9, 9, tzinfo=timezone.utc),
        )
        approved = decide_request_line(
            line=line,
            delegation=delegation,
            action=DecisionAction.APPROVE,
            decided_by=self.actor_id,
            justification="Validé",
            now=datetime(2026, 8, 9, tzinfo=timezone.utc),
        ).line
        self.repository.save_request_line(
            approved,
            self.audit(
                "access_request.approved",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                previous_value={"status": "pending"},
                new_value={"status": "approved"},
            ),
        )
        loaded = self.repository.list_request_lines(request_id)
        self.assertEqual(1, len(loaded))
        self.assertEqual(RequestStatus.APPROVED, loaded[0].status)
        self.assertEqual("reader", loaded[0].granted_role_id)

    def test_request_write_rolls_back_when_audit_is_incomplete(self):
        self.save_prerequisites()
        line = submit_access_request(
            application=replace(
                self.application,
                registration_policy=RegistrationPolicy.APPROVAL,
            ),
            subject_id=self.identity.identity_id,
            requested_role_id="reader",
            scope_type="site",
            scope_id="site-09",
            reason="Participer",
        )
        self.repository.save_request_line(
            line,
            self.audit(
                "access_request.submitted",
                subject_id=self.identity.identity_id,
                application_id="tasks",
                new_value={"status": "pending"},
            ),
        )
        changed = replace(line, status=RequestStatus.CANCELLED)
        with self.assertRaises(ValueError):
            self.repository.save_request_line(
                changed,
                self.audit(
                    "access_request.cancelled",
                    subject_id=self.identity.identity_id,
                    application_id="tasks",
                    new_value={"status": "cancelled"},
                ),
            )
        self.assertEqual(RequestStatus.PENDING, self.repository.list_request_lines(line.request_id)[0].status)


if __name__ == "__main__":
    unittest.main()
