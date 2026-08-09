"""Noyau de domaine de N09 – Administration."""

from .access import AccessDecision, decide_access
from .api import ApiResponse, AuthenticatedApplication, evaluate_access_request
from .audit import AuditEvent
from .domain import AccessAssignment, Application, Identity
from .federated_identity import (
    ExternalIdentity,
    ExternalPrincipal,
    LoginResolution,
    LoginResult,
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
    "ExternalIdentity",
    "ExternalPrincipal",
    "LoginResolution",
    "LoginResult",
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
]
