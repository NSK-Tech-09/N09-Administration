import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from n09_admin.domain import Application, RegistrationPolicy
from n09_admin.governance import (
    DecisionAction,
    Delegation,
    RequestStatus,
    decide_request_line,
    submit_access_request,
)


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 9, 12, tzinfo=timezone.utc)
        self.admin_id = uuid4()
        self.subject_id = uuid4()
        self.application = Application(
            "tasks",
            "N09 – Suivi des tâches",
            registration_policy=RegistrationPolicy.APPROVAL,
        )
        self.line = submit_access_request(
            application=self.application,
            subject_id=self.subject_id,
            requested_role_id="reader",
            scope_type="site",
            scope_id="site-09",
            reason="Participer au suivi",
        )
        self.delegation = Delegation(
            administrator_id=self.admin_id,
            application_id="tasks",
            manageable_role_ids=frozenset({"reader", "writer"}),
            scope_type="site",
            manageable_scope_ids=frozenset({"site-09"}),
            allowed_actions=frozenset(DecisionAction),
            justification="Responsable du site 09",
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=30),
        )

    def decide(self, **changes):
        values = {
            "line": self.line,
            "delegation": self.delegation,
            "action": DecisionAction.APPROVE,
            "decided_by": self.admin_id,
            "justification": "Besoin validé",
            "now": self.now,
        }
        values.update(changes)
        return decide_request_line(**values)

    def test_approval_policy_accepts_public_request_without_access(self):
        self.assertEqual(RequestStatus.PENDING, self.line.status)
        self.assertIsNone(self.line.granted_role_id)

    def test_closed_policy_requires_named_invitation(self):
        application = Application("admin", "Administration")
        with self.assertRaisesRegex(ValueError, "invitation_required"):
            submit_access_request(
                application=application,
                subject_id=self.subject_id,
                requested_role_id="viewer",
                scope_type="organization",
                scope_id="nsk-tech-09",
                reason="Consulter",
            )

    def test_each_application_has_an_independent_line(self):
        other = Application(
            "energy", "N09 – Énergie", registration_policy=RegistrationPolicy.APPROVAL
        )
        other_line = submit_access_request(
            application=other,
            subject_id=self.subject_id,
            requested_role_id="reader",
            scope_type="site",
            scope_id="site-09",
            reason="Consulter",
            request_id=self.line.request_id,
        )
        self.assertEqual(self.line.request_id, other_line.request_id)
        self.assertNotEqual(self.line.line_id, other_line.line_id)

    def test_delegated_admin_can_approve_within_bounds(self):
        decision = self.decide()
        self.assertTrue(decision.accepted)
        self.assertEqual(RequestStatus.APPROVED, decision.line.status)
        self.assertEqual("reader", decision.line.granted_role_id)

    def test_delegated_admin_cannot_grant_another_scope(self):
        decision = self.decide(granted_scope_id="site-11")
        self.assertEqual("scope_outside_delegation", decision.reason_code)

    def test_delegated_admin_cannot_grant_another_role(self):
        decision = self.decide(granted_role_id="administrator")
        self.assertEqual("role_outside_delegation", decision.reason_code)

    def test_delegated_admin_cannot_decide_another_application(self):
        other_line = self.line.__class__(
            request_id=self.line.request_id,
            subject_id=self.subject_id,
            application_id="energy",
            requested_role_id="reader",
            scope_type="site",
            scope_id="site-09",
            reason="Consulter",
        )
        self.assertEqual(
            "application_outside_delegation",
            self.decide(line=other_line).reason_code,
        )

    def test_expired_delegation_is_denied(self):
        self.assertEqual(
            "delegation_outside_validity",
            self.decide(now=self.now + timedelta(days=31)).reason_code,
        )

    def test_decision_requires_justification(self):
        self.assertEqual(
            "justification_required", self.decide(justification=" ").reason_code
        )

    def test_completed_line_cannot_be_decided_twice(self):
        completed = self.decide().line
        self.assertEqual("request_not_pending", self.decide(line=completed).reason_code)


if __name__ == "__main__":
    unittest.main()
