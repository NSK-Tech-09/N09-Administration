"""Noyau de domaine de N09 – Administration."""

from .access import AccessDecision, decide_access
from .api import ApiResponse, AuthenticatedApplication, evaluate_access_request
from .audit import AuditEvent
from .domain import AccessAssignment, Application, Identity
from .federated_identity import (
    AssuranceLevel,
    AuthenticationProtocol,
    ExternalIdentity,
    ExternalPrincipal,
    LoginResolution,
    LoginResult,
    PROVIDER_POLICIES,
    ProviderPolicy,
    requires_step_up,
    resolve_login,
)
from .persistence import SQLiteRepository
from .governance import (
    AccessRequestLine,
    DecisionAction,
    Delegation,
    Group,
    GroupMembership,
    decide_request_line,
    submit_access_request,
)

__all__ = [
    "AccessDecision",
    "ApiResponse",
    "AuthenticatedApplication",
    "Application",
    "AccessAssignment",
    "AuditEvent",
    "Identity",
    "AssuranceLevel",
    "AuthenticationProtocol",
    "ExternalIdentity",
    "ExternalPrincipal",
    "LoginResolution",
    "LoginResult",
    "PROVIDER_POLICIES",
    "ProviderPolicy",
    "SQLiteRepository",
    "AccessRequestLine",
    "DecisionAction",
    "Delegation",
    "Group",
    "GroupMembership",
    "decide_request_line",
    "submit_access_request",
    "decide_access",
    "evaluate_access_request",
    "resolve_login",
    "requires_step_up",
]
