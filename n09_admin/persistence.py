from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import Iterator
from uuid import UUID

from .audit import AuditEvent, event_hash
from .domain import (
    AccessAssignment,
    Application,
    ApplicationStatus,
    AssignmentStatus,
    Identity,
    IdentityStatus,
    RegistrationPolicy,
)
from .governance import (
    AccessRequestLine,
    DecisionAction,
    Delegation,
    DelegationStatus,
    Group,
    GroupMembership,
    GroupStatus,
    RequestStatus,
)
from .federated_identity import ExternalIdentity, ExternalIdentityStatus


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS identities (
    identity_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS identities_email_ci
ON identities(lower(email));

CREATE TABLE IF NOT EXISTS external_identities (
    external_identity_id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(identity_id),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_key TEXT NOT NULL,
    status TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    UNIQUE(issuer, subject)
);

CREATE INDEX IF NOT EXISTS external_identities_identity
ON external_identities(identity_id);

CREATE TABLE IF NOT EXISTS applications (
    application_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    registration_policy TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_assignments (
    assignment_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES identities(identity_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    role_id TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    scope_type TEXT,
    scope_id TEXT,
    conditions_json TEXT NOT NULL,
    status TEXT NOT NULL,
    valid_from TEXT,
    valid_until TEXT,
    reason TEXT NOT NULL,
    decided_by TEXT,
    inherited_from_group TEXT,
    version INTEGER NOT NULL CHECK(version >= 1),
    CHECK ((scope_type IS NULL) = (scope_id IS NULL)),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS assignments_subject_application
ON access_assignments(subject_id, application_id);

CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES identities(identity_id),
    review_due_at TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_memberships (
    membership_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES groups(group_id),
    identity_id TEXT NOT NULL REFERENCES identities(identity_id),
    valid_from TEXT,
    valid_until TEXT,
    UNIQUE(group_id, identity_id),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE TABLE IF NOT EXISTS delegations (
    delegation_id TEXT PRIMARY KEY,
    administrator_id TEXT NOT NULL REFERENCES identities(identity_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    manageable_role_ids_json TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    manageable_scope_ids_json TEXT NOT NULL,
    allowed_actions_json TEXT NOT NULL,
    justification TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    status TEXT NOT NULL,
    CHECK (valid_until > valid_from)
);

CREATE TABLE IF NOT EXISTS access_request_lines (
    line_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    subject_id TEXT NOT NULL REFERENCES identities(identity_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    requested_role_id TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    invitation_id TEXT,
    status TEXT NOT NULL,
    decided_by TEXT,
    decision_justification TEXT NOT NULL,
    granted_role_id TEXT,
    granted_scope_id TEXT
);

CREATE INDEX IF NOT EXISTS request_lines_request
ON access_request_lines(request_id, application_id);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    correlation_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor_id TEXT,
    subject_id TEXT,
    application_id TEXT,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    cause TEXT,
    role_id TEXT,
    scope_type TEXT,
    scope_id TEXT,
    conditions_json TEXT NOT NULL,
    previous_value_json TEXT,
    new_value_json TEXT,
    justification TEXT NOT NULL,
    source TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
"""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _json(items: frozenset[str]) -> str:
    return json.dumps(sorted(items), ensure_ascii=False, separators=(",", ":"))


class SQLiteRepository:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> SQLiteRepository:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection:
            yield self.connection

    def save_identity(self, identity: Identity, audit_event: AuditEvent) -> None:
        if audit_event.subject_id != identity.identity_id:
            raise ValueError("audit subject must match identity")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM identities WHERE identity_id = ?",
                (str(identity.identity_id),),
            ).fetchone()
            connection.execute(
                """INSERT INTO identities(identity_id, email, display_name, status)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(identity_id) DO UPDATE SET
                     email = excluded.email,
                     display_name = excluded.display_name,
                     status = excluded.status""",
                (
                    str(identity.identity_id),
                    identity.email.strip().lower(),
                    identity.display_name.strip(),
                    identity.status.value,
                ),
            )
            self._append_audit(connection, audit_event, previous)

    def get_identity(self, identity_id: UUID) -> Identity | None:
        row = self.connection.execute(
            "SELECT * FROM identities WHERE identity_id = ?", (str(identity_id),)
        ).fetchone()
        if row is None:
            return None
        return Identity(
            UUID(row["identity_id"]),
            row["email"],
            row["display_name"],
            IdentityStatus(row["status"]),
        )

    def link_external_identity(
        self, external_identity: ExternalIdentity, audit_event: AuditEvent
    ) -> None:
        if audit_event.subject_id != external_identity.identity_id:
            raise ValueError("audit subject must match NSK identity")
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM external_identities WHERE issuer = ? AND subject = ?",
                (external_identity.issuer, external_identity.subject),
            ).fetchone()
            if existing is not None:
                if existing["identity_id"] != str(external_identity.identity_id):
                    raise ValueError("external identity is already linked")
                raise ValueError("external identity link already exists")
            connection.execute(
                """INSERT INTO external_identities(
                     external_identity_id, identity_id, issuer, subject,
                     provider_key, status, linked_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(external_identity.external_identity_id),
                    str(external_identity.identity_id),
                    external_identity.issuer,
                    external_identity.subject,
                    external_identity.provider_key,
                    external_identity.status.value,
                    _iso(external_identity.linked_at),
                ),
            )
            self._append_audit(connection, audit_event, None)

    def find_external_identity(
        self, issuer: str, subject: str
    ) -> ExternalIdentity | None:
        row = self.connection.execute(
            "SELECT * FROM external_identities WHERE issuer = ? AND subject = ?",
            (issuer, subject),
        ).fetchone()
        if row is None:
            return None
        return ExternalIdentity(
            external_identity_id=UUID(row["external_identity_id"]),
            identity_id=UUID(row["identity_id"]),
            issuer=row["issuer"],
            subject=row["subject"],
            provider_key=row["provider_key"],
            status=ExternalIdentityStatus(row["status"]),
            linked_at=_datetime(row["linked_at"]),
        )

    def list_external_identities(self, identity_id: UUID) -> list[ExternalIdentity]:
        rows = self.connection.execute(
            """SELECT * FROM external_identities
               WHERE identity_id = ? ORDER BY provider_key, external_identity_id""",
            (str(identity_id),),
        ).fetchall()
        return [
            ExternalIdentity(
                external_identity_id=UUID(row["external_identity_id"]),
                identity_id=UUID(row["identity_id"]),
                issuer=row["issuer"],
                subject=row["subject"],
                provider_key=row["provider_key"],
                status=ExternalIdentityStatus(row["status"]),
                linked_at=_datetime(row["linked_at"]),
            )
            for row in rows
        ]

    def save_application(self, application: Application, audit_event: AuditEvent) -> None:
        if audit_event.application_id != application.application_id:
            raise ValueError("audit application must match application")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM applications WHERE application_id = ?",
                (application.application_id,),
            ).fetchone()
            connection.execute(
                """INSERT INTO applications(
                     application_id, display_name, status, registration_policy
                   ) VALUES (?, ?, ?, ?)
                   ON CONFLICT(application_id) DO UPDATE SET
                     display_name = excluded.display_name,
                     status = excluded.status,
                     registration_policy = excluded.registration_policy""",
                (
                    application.application_id,
                    application.display_name,
                    application.status.value,
                    application.registration_policy.value,
                ),
            )
            self._append_audit(connection, audit_event, previous)

    def get_application(self, application_id: str) -> Application | None:
        row = self.connection.execute(
            "SELECT * FROM applications WHERE application_id = ?", (application_id,)
        ).fetchone()
        if row is None:
            return None
        return Application(
            row["application_id"],
            row["display_name"],
            ApplicationStatus(row["status"]),
            RegistrationPolicy(row["registration_policy"]),
        )

    def save_assignment(
        self, assignment: AccessAssignment, audit_event: AuditEvent
    ) -> None:
        if audit_event.subject_id != assignment.subject_id:
            raise ValueError("audit subject must match assignment")
        if audit_event.application_id != assignment.application_id:
            raise ValueError("audit application must match assignment")
        if audit_event.role_id != assignment.role_id:
            raise ValueError("audit role must match assignment")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM access_assignments WHERE assignment_id = ?",
                (str(assignment.assignment_id),),
            ).fetchone()
            if previous is not None and assignment.version != previous["version"] + 1:
                raise ValueError("assignment version conflict")
            connection.execute(
                """INSERT INTO access_assignments(
                     assignment_id, subject_id, application_id, role_id,
                     permissions_json, scope_type, scope_id, conditions_json,
                     status, valid_from, valid_until, reason, decided_by,
                     inherited_from_group, version
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(assignment_id) DO UPDATE SET
                     role_id = excluded.role_id,
                     permissions_json = excluded.permissions_json,
                     scope_type = excluded.scope_type,
                     scope_id = excluded.scope_id,
                     conditions_json = excluded.conditions_json,
                     status = excluded.status,
                     valid_from = excluded.valid_from,
                     valid_until = excluded.valid_until,
                     reason = excluded.reason,
                     decided_by = excluded.decided_by,
                     inherited_from_group = excluded.inherited_from_group,
                     version = excluded.version""",
                (
                    str(assignment.assignment_id),
                    str(assignment.subject_id),
                    assignment.application_id,
                    assignment.role_id,
                    _json(assignment.permissions),
                    assignment.scope_type,
                    assignment.scope_id,
                    _json(assignment.conditions),
                    assignment.status.value,
                    _iso(assignment.valid_from),
                    _iso(assignment.valid_until),
                    assignment.reason,
                    str(assignment.decided_by) if assignment.decided_by else None,
                    str(assignment.inherited_from_group)
                    if assignment.inherited_from_group
                    else None,
                    assignment.version,
                ),
            )
            self._append_audit(connection, audit_event, previous)

    def list_assignments(
        self, subject_id: UUID, application_id: str
    ) -> list[AccessAssignment]:
        rows = self.connection.execute(
            """SELECT * FROM access_assignments
               WHERE subject_id = ? AND application_id = ?
               ORDER BY assignment_id""",
            (str(subject_id), application_id),
        ).fetchall()
        return [
            AccessAssignment(
                subject_id=UUID(row["subject_id"]),
                application_id=row["application_id"],
                role_id=row["role_id"],
                permissions=frozenset(json.loads(row["permissions_json"])),
                scope_type=row["scope_type"],
                scope_id=row["scope_id"],
                conditions=frozenset(json.loads(row["conditions_json"])),
                status=AssignmentStatus(row["status"]),
                valid_from=_datetime(row["valid_from"]),
                valid_until=_datetime(row["valid_until"]),
                reason=row["reason"],
                decided_by=UUID(row["decided_by"]) if row["decided_by"] else None,
                inherited_from_group=UUID(row["inherited_from_group"])
                if row["inherited_from_group"]
                else None,
                version=row["version"],
                assignment_id=UUID(row["assignment_id"]),
            )
            for row in rows
        ]

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        event: AuditEvent,
        previous_record: sqlite3.Row | None,
    ) -> None:
        if previous_record is not None and event.previous_value is None:
            raise ValueError("an update audit event must include previous_value")
        last = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = last["event_hash"] if last else "0" * 64
        digest = event_hash(event, previous_hash)
        payload = event.payload()
        connection.execute(
            """INSERT INTO audit_events(
                 event_id, correlation_id, occurred_at, actor_id, subject_id,
                 application_id, action, result, cause, role_id, scope_type,
                 scope_id, conditions_json, previous_value_json, new_value_json,
                 justification, source, previous_hash, event_hash
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                payload["event_id"],
                payload["correlation_id"],
                payload["occurred_at"],
                payload["actor_id"],
                payload["subject_id"],
                payload["application_id"],
                payload["action"],
                payload["result"],
                payload["cause"],
                payload["role_id"],
                payload["scope_type"],
                payload["scope_id"],
                json.dumps(payload["conditions"], ensure_ascii=False),
                json.dumps(payload["previous_value"], ensure_ascii=False)
                if payload["previous_value"] is not None
                else None,
                json.dumps(payload["new_value"], ensure_ascii=False)
                if payload["new_value"] is not None
                else None,
                payload["justification"],
                payload["source"],
                previous_hash,
                digest,
            ),
        )

    def verify_audit_chain(self) -> bool:
        previous_hash = "0" * 64
        rows = self.connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ).fetchall()
        for row in rows:
            event = AuditEvent(
                event_id=UUID(row["event_id"]),
                correlation_id=UUID(row["correlation_id"]),
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                actor_id=UUID(row["actor_id"]) if row["actor_id"] else None,
                subject_id=UUID(row["subject_id"]) if row["subject_id"] else None,
                application_id=row["application_id"],
                action=row["action"],
                result=row["result"],
                cause=row["cause"],
                role_id=row["role_id"],
                scope_type=row["scope_type"],
                scope_id=row["scope_id"],
                conditions=frozenset(json.loads(row["conditions_json"])),
                previous_value=json.loads(row["previous_value_json"])
                if row["previous_value_json"]
                else None,
                new_value=json.loads(row["new_value_json"])
                if row["new_value_json"]
                else None,
                justification=row["justification"],
                source=row["source"],
            )
            if row["previous_hash"] != previous_hash:
                return False
            if row["event_hash"] != event_hash(event, previous_hash):
                return False
            previous_hash = row["event_hash"]
        return True

    def audit_count(self) -> int:
        return self.connection.execute(
            "SELECT count(*) FROM audit_events"
        ).fetchone()[0]

    def save_group(self, group: Group, audit_event: AuditEvent) -> None:
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM groups WHERE group_id = ?", (str(group.group_id),)
            ).fetchone()
            connection.execute(
                """INSERT INTO groups(group_id, name, purpose, owner_id, review_due_at, status)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(group_id) DO UPDATE SET
                     name=excluded.name, purpose=excluded.purpose,
                     owner_id=excluded.owner_id, review_due_at=excluded.review_due_at,
                     status=excluded.status""",
                (str(group.group_id), group.name.strip(), group.purpose.strip(),
                 str(group.owner_id), _iso(group.review_due_at), group.status.value),
            )
            self._append_audit(connection, audit_event, previous)

    def save_group_membership(
        self, membership: GroupMembership, audit_event: AuditEvent
    ) -> None:
        if audit_event.subject_id != membership.identity_id:
            raise ValueError("audit subject must match membership")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM group_memberships WHERE membership_id = ?",
                (str(membership.membership_id),),
            ).fetchone()
            connection.execute(
                """INSERT INTO group_memberships(
                     membership_id, group_id, identity_id, valid_from, valid_until
                   ) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(membership_id) DO UPDATE SET
                     valid_from=excluded.valid_from, valid_until=excluded.valid_until""",
                (str(membership.membership_id), str(membership.group_id),
                 str(membership.identity_id), _iso(membership.valid_from),
                 _iso(membership.valid_until)),
            )
            self._append_audit(connection, audit_event, previous)

    def save_delegation(
        self, delegation: Delegation, audit_event: AuditEvent
    ) -> None:
        if audit_event.subject_id != delegation.administrator_id:
            raise ValueError("audit subject must match delegated administrator")
        if audit_event.application_id != delegation.application_id:
            raise ValueError("audit application must match delegation")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM delegations WHERE delegation_id = ?",
                (str(delegation.delegation_id),),
            ).fetchone()
            connection.execute(
                """INSERT INTO delegations(
                     delegation_id, administrator_id, application_id,
                     manageable_role_ids_json, scope_type,
                     manageable_scope_ids_json, allowed_actions_json,
                     justification, valid_from, valid_until, status
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(delegation_id) DO UPDATE SET
                     manageable_role_ids_json=excluded.manageable_role_ids_json,
                     scope_type=excluded.scope_type,
                     manageable_scope_ids_json=excluded.manageable_scope_ids_json,
                     allowed_actions_json=excluded.allowed_actions_json,
                     justification=excluded.justification,
                     valid_from=excluded.valid_from, valid_until=excluded.valid_until,
                     status=excluded.status""",
                (str(delegation.delegation_id), str(delegation.administrator_id),
                 delegation.application_id, _json(delegation.manageable_role_ids),
                 delegation.scope_type, _json(delegation.manageable_scope_ids),
                 _json(frozenset(action.value for action in delegation.allowed_actions)),
                 delegation.justification, _iso(delegation.valid_from),
                 _iso(delegation.valid_until), delegation.status.value),
            )
            self._append_audit(connection, audit_event, previous)

    def save_request_line(
        self, line: AccessRequestLine, audit_event: AuditEvent
    ) -> None:
        if audit_event.subject_id != line.subject_id:
            raise ValueError("audit subject must match request")
        if audit_event.application_id != line.application_id:
            raise ValueError("audit application must match request")
        with self.transaction() as connection:
            previous = connection.execute(
                "SELECT * FROM access_request_lines WHERE line_id = ?",
                (str(line.line_id),),
            ).fetchone()
            connection.execute(
                """INSERT INTO access_request_lines(
                     line_id, request_id, subject_id, application_id,
                     requested_role_id, scope_type, scope_id, reason,
                     invitation_id, status, decided_by, decision_justification,
                     granted_role_id, granted_scope_id
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(line_id) DO UPDATE SET
                     status=excluded.status, decided_by=excluded.decided_by,
                     decision_justification=excluded.decision_justification,
                     granted_role_id=excluded.granted_role_id,
                     granted_scope_id=excluded.granted_scope_id""",
                (str(line.line_id), str(line.request_id), str(line.subject_id),
                 line.application_id, line.requested_role_id, line.scope_type,
                 line.scope_id, line.reason,
                 str(line.invitation_id) if line.invitation_id else None,
                 line.status.value, str(line.decided_by) if line.decided_by else None,
                 line.decision_justification, line.granted_role_id,
                 line.granted_scope_id),
            )
            self._append_audit(connection, audit_event, previous)

    def list_request_lines(self, request_id: UUID) -> list[AccessRequestLine]:
        rows = self.connection.execute(
            "SELECT * FROM access_request_lines WHERE request_id = ? ORDER BY application_id",
            (str(request_id),),
        ).fetchall()
        return [AccessRequestLine(
            request_id=UUID(row["request_id"]), subject_id=UUID(row["subject_id"]),
            application_id=row["application_id"],
            requested_role_id=row["requested_role_id"],
            scope_type=row["scope_type"], scope_id=row["scope_id"],
            reason=row["reason"],
            invitation_id=UUID(row["invitation_id"]) if row["invitation_id"] else None,
            status=RequestStatus(row["status"]),
            decided_by=UUID(row["decided_by"]) if row["decided_by"] else None,
            decision_justification=row["decision_justification"],
            granted_role_id=row["granted_role_id"],
            granted_scope_id=row["granted_scope_id"],
            line_id=UUID(row["line_id"]),
        ) for row in rows]
