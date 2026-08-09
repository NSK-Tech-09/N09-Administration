from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .domain import (
    AccessAssignment,
    Application,
    ApplicationStatus,
    AssignmentStatus,
    Identity,
    IdentityStatus,
)


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason_code: str
    assignment: AccessAssignment | None = None


def decide_access(
    *,
    identity: Identity,
    application: Application,
    assignments: Iterable[AccessAssignment],
    required_permission: str,
    scope_type: str | None = None,
    scope_id: str | None = None,
    satisfied_conditions: frozenset[str] = frozenset(),
    now: datetime | None = None,
) -> AccessDecision:
    """Évalue Subject + Application + Rôle + Périmètre + Conditions.

    La fonction est sans effet de bord. Toute situation absente, ambiguë ou
    inconnue est refusée par défaut.
    """
    current_time = now or datetime.now(timezone.utc)

    if identity.status is not IdentityStatus.ACTIVE:
        return AccessDecision(False, "identity_not_active")
    if application.status is not ApplicationStatus.ACTIVE:
        return AccessDecision(False, "application_not_active")

    matching_application = False
    matching_permission = False
    matching_scope = False
    matching_conditions = False

    for assignment in assignments:
        if assignment.subject_id != identity.identity_id:
            continue
        if assignment.application_id != application.application_id:
            continue
        matching_application = True
        if assignment.status is not AssignmentStatus.ACTIVE:
            continue
        if assignment.valid_from and current_time < assignment.valid_from:
            continue
        if assignment.valid_until and current_time >= assignment.valid_until:
            continue
        if required_permission not in assignment.permissions:
            continue
        matching_permission = True
        if (assignment.scope_type, assignment.scope_id) != (scope_type, scope_id):
            continue
        matching_scope = True
        if not assignment.conditions.issubset(satisfied_conditions):
            continue
        matching_conditions = True
        return AccessDecision(True, "access_granted", assignment)

    if not matching_application:
        return AccessDecision(False, "assignment_missing")
    if not matching_permission:
        return AccessDecision(False, "permission_or_validity_missing")
    if not matching_scope:
        return AccessDecision(False, "scope_mismatch")
    if not matching_conditions:
        return AccessDecision(False, "conditions_not_satisfied")
    return AccessDecision(False, "access_denied")
