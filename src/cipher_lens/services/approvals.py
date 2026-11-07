"""Durable, auditable approvals for exact active-validation requests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cipher_lens.domain.models import ActionClass, ScopeRecord
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.audit import record

APPROVAL_TTL_MINUTES = 15


def record_approval(
    repository: Repository, scope: ScopeRecord, *, target: str, port: int, scheme: str | None,
    action: ActionClass, actor: str, rationale: str, approved: bool,
) -> str:
    """Save one immutable approval decision; only an exact approved request may use it."""
    approval_id = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=APPROVAL_TTL_MINUTES)
    status = "approved" if approved else "rejected"
    repository.save_adapter_approval(
        approval_id, scope.id, target, port, scheme, action.value, status, actor, rationale, expires_at
    )
    record(repository, event_type="active_validation_approval", outcome=status, entity_type="approval",
           entity_id=approval_id, detail={"scope_id": scope.id, "target": target, "port": port,
           "scheme": scheme, "action": action.value, "actor": actor, "expires_at": expires_at.isoformat()})
    return approval_id
