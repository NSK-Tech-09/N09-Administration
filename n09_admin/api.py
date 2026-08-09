from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID, uuid4

from .access import decide_access
from .persistence import SQLiteRepository


@dataclass(frozen=True, slots=True)
class AuthenticatedApplication:
    application_id: str
    audience: str
    correlation_id: UUID


@dataclass(frozen=True, slots=True)
class ApiResponse:
    status: int
    body: Mapping[str, Any]
    correlation_id: UUID


def evaluate_access_request(
    *,
    repository: SQLiteRepository,
    principal: AuthenticatedApplication | None,
    payload: Mapping[str, Any],
) -> ApiResponse:
    correlation_id = principal.correlation_id if principal else uuid4()
    if principal is None:
        return ApiResponse(401, {"error": "authentication_required"}, correlation_id)
    if principal.audience != principal.application_id:
        return ApiResponse(403, {"error": "invalid_audience"}, correlation_id)

    allowed_fields = {
        "identity_id",
        "application_id",
        "required_permission",
        "scope_type",
        "scope_id",
        "satisfied_conditions",
    }
    if set(payload) - allowed_fields:
        return ApiResponse(400, {"error": "invalid_request"}, correlation_id)
    try:
        identity_id = UUID(str(payload["identity_id"]))
        application_id = str(payload["application_id"])
        permission = str(payload["required_permission"])
        scope_type = payload.get("scope_type")
        scope_id = payload.get("scope_id")
        conditions_value = payload.get("satisfied_conditions", [])
        if not isinstance(conditions_value, list) or not all(
            isinstance(item, str) for item in conditions_value
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return ApiResponse(400, {"error": "invalid_request"}, correlation_id)

    if application_id != principal.application_id:
        return ApiResponse(403, {"error": "application_boundary_violation"}, correlation_id)
    identity = repository.get_identity(identity_id)
    application = repository.get_application(application_id)
    if identity is None or application is None:
        return ApiResponse(404, {"error": "resource_not_found"}, correlation_id)

    assignments = repository.list_assignments(identity_id, application_id)
    decision = decide_access(
        identity=identity,
        application=application,
        assignments=assignments,
        required_permission=permission,
        scope_type=str(scope_type) if scope_type is not None else None,
        scope_id=str(scope_id) if scope_id is not None else None,
        satisfied_conditions=frozenset(conditions_value),
    )
    return ApiResponse(
        200,
        {"allowed": decision.allowed, "reason_code": decision.reason_code},
        correlation_id,
    )
