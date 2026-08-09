from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Mapping
from uuid import UUID, uuid4


FORBIDDEN_FIELD_PARTS = (
    "password",
    "secret",
    "token",
    "session_id",
    "authorization",
    "credential",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_safe(value: Any, path: str = "event") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in FORBIDDEN_FIELD_PARTS):
                raise ValueError(f"forbidden audit field: {path}.{key}")
            _assert_safe(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, child in enumerate(value):
            _assert_safe(child, f"{path}[{index}]")


def _json_value(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(_json_value(item) for item in value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    return value


@dataclass(frozen=True, slots=True)
class AuditEvent:
    action: str
    result: str
    source: str
    correlation_id: UUID
    actor_id: UUID | None = None
    subject_id: UUID | None = None
    application_id: str | None = None
    cause: str | None = None
    role_id: str | None = None
    scope_type: str | None = None
    scope_id: str | None = None
    conditions: frozenset[str] = field(default_factory=frozenset)
    previous_value: Mapping[str, Any] | None = None
    new_value: Mapping[str, Any] | None = None
    justification: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if not self.action.strip() or not self.result.strip() or not self.source.strip():
            raise ValueError("action, result and source are required")
        _assert_safe(self.previous_value)
        _assert_safe(self.new_value)

    def payload(self) -> dict[str, Any]:
        return _json_value(asdict(self))

    def canonical_json(self) -> str:
        return json.dumps(
            self.payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )


def event_hash(event: AuditEvent, previous_hash: str) -> str:
    material = f"{previous_hash}\n{event.canonical_json()}".encode("utf-8")
    return sha256(material).hexdigest()
