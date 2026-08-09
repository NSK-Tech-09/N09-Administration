from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4


class IdentityStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    ARCHIVED = "archived"
    DELETED = "deleted"


class ApplicationStatus(StrEnum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    RETIRED = "retired"


class RegistrationPolicy(StrEnum):
    CLOSED = "closed"
    INVITATION = "invitation"
    APPROVAL = "approval"


class AssignmentStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class Identity:
    identity_id: UUID
    email: str
    display_name: str
    status: IdentityStatus = IdentityStatus.INVITED


@dataclass(frozen=True, slots=True)
class Application:
    application_id: str
    display_name: str
    status: ApplicationStatus = ApplicationStatus.ACTIVE
    registration_policy: RegistrationPolicy = RegistrationPolicy.CLOSED


@dataclass(frozen=True, slots=True)
class AccessAssignment:
    subject_id: UUID
    application_id: str
    role_id: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    scope_type: str | None = None
    scope_id: str | None = None
    conditions: frozenset[str] = field(default_factory=frozenset)
    status: AssignmentStatus = AssignmentStatus.PENDING
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    reason: str = ""
    decided_by: UUID | None = None
    inherited_from_group: UUID | None = None
    version: int = 1
    assignment_id: UUID = field(default_factory=uuid4)
