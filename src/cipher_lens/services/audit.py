"""Append-only audit logging service."""

from __future__ import annotations

from typing import Any

from cipher_lens.domain.models import AuditEvent
from cipher_lens.persistence.repositories import Repository


def record(
    repository: Repository,
    *,
    event_type: str,
    outcome: str,
    entity_type: str,
    entity_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        outcome=outcome,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail or {},
    )
    repository.append_audit(event)
    return event
