from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from .domain import Application, RegistrationPolicy


class GroupStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class DelegationStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RequestStatus(StrEnum):
    PENDING = "pending"
    NEEDS_INFORMATION = "needs_information"
    APPROVED = "approved"
    REFUSED = "refused"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DecisionAction(StrEnum):
    APPROVE = "approve"
    REFUSE = "refuse"
    REQUEST_INFORMATION = "request_information"


@dataclass(frozen=True, slots=True)
class Group:
    name: str
    purpose: str
    owner_id: UUID
    review_due_at: datetime
    status: GroupStatus = GroupStatus.ACTIVE
    group_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.purpose.strip():
            raise ValueError("group name and purpose are required")
        if self.review_due_at.tzinfo is None:
            raise ValueError("group review date must be timezone-aware")


@dataclass(frozen=True, slots=True)
class GroupMembership:
    group_id: UUID
    identity_id: UUID
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    membership_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if self.valid_from and self.valid_from.tzinfo is None:
            raise ValueError("valid_from must be timezone-aware")
        if self.valid_until and self.valid_until.tzinfo is None:
            raise ValueError("valid_until must be timezone-aware")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")


@dataclass(frozen=True, slots=True)
class Delegation:
    administrator_id: UUID
    application_id: str
    manageable_role_ids: frozenset[str]
    scope_type: str
    manageable_scope_ids: frozenset[str]
    allowed_actions: frozenset[DecisionAction]
    justification: str
    valid_from: datetime
    valid_until: datetime
    status: DelegationStatus = DelegationStatus.ACTIVE
    delegation_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.manageable_role_ids or not self.manageable_scope_ids:
            raise ValueError("delegation roles and scopes must be explicit")
        if not self.allowed_actions or not self.justification.strip():
            raise ValueError("delegation actions and justification are required")
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("delegation dates must be timezone-aware")
        if self.valid_until <= self.valid_from:
            raise ValueError("delegation must have a positive duration")


@dataclass(frozen=True, slots=True)
class AccessRequestLine:
    request_id: UUID
    subject_id: UUID
    application_id: str
    requested_role_id: str
    scope_type: str
    scope_id: str
    reason: str
    invitation_id: UUID | None = None
    status: RequestStatus = RequestStatus.PENDING
    decided_by: UUID | None = None
    decision_justification: str = ""
    granted_role_id: str | None = None
    granted_scope_id: str | None = None
    line_id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class GovernanceDecision:
    accepted: bool
    reason_code: str
    line: AccessRequestLine


def submit_access_request(
    *,
    application: Application,
    subject_id: UUID,
    requested_role_id: str,
    scope_type: str,
    scope_id: str,
    reason: str,
    invitation_id: UUID | None = None,
    request_id: UUID | None = None,
) -> AccessRequestLine:
    if application.registration_policy in {
        RegistrationPolicy.CLOSED,
        RegistrationPolicy.INVITATION,
    } and invitation_id is None:
        raise ValueError("invitation_required")
    if not requested_role_id or not scope_type or not scope_id or not reason.strip():
        raise ValueError("request_fields_required")
    return AccessRequestLine(
        request_id=request_id or uuid4(),
        subject_id=subject_id,
        application_id=application.application_id,
        requested_role_id=requested_role_id,
        scope_type=scope_type,
        scope_id=scope_id,
        reason=reason.strip(),
        invitation_id=invitation_id,
    )


def decide_request_line(
    *,
    line: AccessRequestLine,
    delegation: Delegation,
    action: DecisionAction,
    decided_by: UUID,
    justification: str,
    granted_role_id: str | None = None,
    granted_scope_id: str | None = None,
    now: datetime | None = None,
) -> GovernanceDecision:
    current_time = now or datetime.now(timezone.utc)
    if line.status not in {RequestStatus.PENDING, RequestStatus.NEEDS_INFORMATION}:
        return GovernanceDecision(False, "request_not_pending", line)
    if delegation.status is not DelegationStatus.ACTIVE:
        return GovernanceDecision(False, "delegation_not_active", line)
    if decided_by != delegation.administrator_id:
        return GovernanceDecision(False, "administrator_mismatch", line)
    if not (delegation.valid_from <= current_time < delegation.valid_until):
        return GovernanceDecision(False, "delegation_outside_validity", line)
    if line.application_id != delegation.application_id:
        return GovernanceDecision(False, "application_outside_delegation", line)
    if line.scope_type != delegation.scope_type:
        return GovernanceDecision(False, "scope_type_outside_delegation", line)
    if action not in delegation.allowed_actions:
        return GovernanceDecision(False, "action_outside_delegation", line)
    if not justification.strip():
        return GovernanceDecision(False, "justification_required", line)

    final_role = granted_role_id or line.requested_role_id
    final_scope = granted_scope_id or line.scope_id
    if final_role not in delegation.manageable_role_ids:
        return GovernanceDecision(False, "role_outside_delegation", line)
    if final_scope not in delegation.manageable_scope_ids:
        return GovernanceDecision(False, "scope_outside_delegation", line)

    status = {
        DecisionAction.APPROVE: RequestStatus.APPROVED,
        DecisionAction.REFUSE: RequestStatus.REFUSED,
        DecisionAction.REQUEST_INFORMATION: RequestStatus.NEEDS_INFORMATION,
    }[action]
    updated = replace(
        line,
        status=status,
        decided_by=decided_by,
        decision_justification=justification.strip(),
        granted_role_id=final_role if action is DecisionAction.APPROVE else None,
        granted_scope_id=final_scope if action is DecisionAction.APPROVE else None,
    )
    return GovernanceDecision(True, "decision_recorded", updated)
