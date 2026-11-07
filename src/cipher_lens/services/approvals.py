"""Durable, auditable approval state machine for exact active-validation requests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from uuid import uuid4

from cipher_lens.domain.models import ActionClass, AuditEvent, ScopeRecord
from cipher_lens.domain.scope import is_in_scope, normalize_target
from cipher_lens.persistence.repositories import ApprovalSummary, Repository
from cipher_lens.services.audit import record

APPROVAL_TTL_MINUTES = 15


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


VALID_TRANSITIONS: dict[ApprovalStatus, set[ApprovalStatus]] = {
    ApprovalStatus.PENDING: {
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.CANCELLED,
    },
    ApprovalStatus.APPROVED: {
        ApprovalStatus.COMPLETED,
        ApprovalStatus.EXPIRED,
        ApprovalStatus.CANCELLED,
    },
    ApprovalStatus.REJECTED: set(),
    ApprovalStatus.EXPIRED: set(),
    ApprovalStatus.CANCELLED: set(),
    ApprovalStatus.COMPLETED: set(),
}


def create_approval_request(
    repository: Repository,
    scope: ScopeRecord,
    *,
    target: str,
    port: int,
    scheme: str | None = None,
    action: ActionClass = ActionClass.ACTIVE_VALIDATION,
    requested_by: str,
    rationale: str,
    finding_id: str | None = None,
) -> str:
    """Create a new pending human approval request after strict scope verification."""
    if not requested_by or not requested_by.strip():
        raise ValueError("Requester name or identifier is required.")
    if not rationale or not rationale.strip():
        raise ValueError("Request rationale is required.")

    in_scope, reason = is_in_scope(scope, target, port, action)
    if not in_scope:
        raise ValueError(
            f"Requested target {target}:{port} with action '{action.value}' is outside the authorized scope: {reason}"
        )

    if action not in scope.allowed_actions:
        raise ValueError(
            f"Action '{action.value}' is not permitted by scope authorization rules for {scope.canonical_target}."
        )

    approval_id = str(uuid4())
    canonical = normalize_target(target)

    repository.create_approval_request(
        approval_id=approval_id,
        scope_id=scope.id,
        target=canonical,
        port=port,
        scheme=scheme,
        action=action.value,
        status=ApprovalStatus.PENDING.value,
        requested_by=requested_by.strip(),
        requested_rationale=rationale.strip(),
        finding_id=finding_id,
    )

    record(
        repository,
        event_type="approval_requested",
        outcome=ApprovalStatus.PENDING.value,
        entity_type="approval",
        entity_id=approval_id,
        detail={
            "scope_id": scope.id,
            "target": canonical,
            "port": port,
            "scheme": scheme,
            "action": action.value,
            "requested_by": requested_by.strip(),
            "finding_id": finding_id,
        },
    )

    return approval_id


def transition_approval(
    repository: Repository,
    approval_id: str,
    new_status: ApprovalStatus,
    *,
    actor: str,
    rationale: str,
) -> ApprovalSummary:
    """Explicitly transition an approval through the state machine with immutable audit logging."""
    if not actor or not actor.strip():
        raise ValueError("Decision actor name or identifier is required.")
    if not rationale or not rationale.strip():
        raise ValueError("Decision rationale is required.")

    approval = repository.get_approval(approval_id)
    if approval is None:
        raise ValueError(f"No recorded approval exists with ID '{approval_id}'.")

    current_status = ApprovalStatus(approval.status)

    # Check for auto-expiry if currently marked approved but timestamp has passed
    if current_status == ApprovalStatus.APPROVED and approval.expires_at:
        try:
            if datetime.fromisoformat(approval.expires_at) <= datetime.now(timezone.utc):
                current_status = ApprovalStatus.EXPIRED
        except ValueError:
            current_status = ApprovalStatus.EXPIRED

    if new_status not in VALID_TRANSITIONS.get(current_status, set()):
        raise ValueError(
            f"Cannot transition approval from '{current_status.value}' to '{new_status.value}'. "
            f"Allowed transitions: {[s.value for s in VALID_TRANSITIONS.get(current_status, set())]}."
        )

    expires_at = None
    if new_status == ApprovalStatus.APPROVED:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=APPROVAL_TTL_MINUTES)

    repository.update_approval_decision(
        approval_id=approval_id,
        status=new_status.value,
        actor=actor.strip(),
        rationale=rationale.strip(),
        expires_at=expires_at,
    )

    record(
        repository,
        event_type="approval_decision",
        outcome=new_status.value,
        entity_type="approval",
        entity_id=approval_id,
        detail={
            "previous_status": current_status.value,
            "new_status": new_status.value,
            "actor": actor.strip(),
            "rationale": rationale.strip(),
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )

    updated = repository.get_approval(approval_id)
    if updated is None:
        raise RuntimeError("Failed to retrieve updated approval record.")
    return updated


def record_approval(
    repository: Repository,
    scope: ScopeRecord,
    *,
    target: str,
    port: int,
    scheme: str | None,
    action: ActionClass,
    actor: str,
    rationale: str,
    approved: bool,
) -> str:
    """Save one immutable approval decision; provides backward compatibility for adapter tests."""
    approval_id = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=APPROVAL_TTL_MINUTES)
    status = ApprovalStatus.APPROVED.value if approved else ApprovalStatus.REJECTED.value
    repository.save_adapter_approval(
        approval_id,
        scope.id,
        target,
        port,
        scheme,
        action.value,
        status,
        actor,
        rationale,
        expires_at,
    )
    record(
        repository,
        event_type="active_validation_approval",
        outcome=status,
        entity_type="approval",
        entity_id=approval_id,
        detail={
            "scope_id": scope.id,
            "target": target,
            "port": port,
            "scheme": scheme,
            "action": action.value,
            "actor": actor,
            "expires_at": expires_at.isoformat(),
        },
    )
    return approval_id


def list_audit_timeline(
    repository: Repository,
    query: str | None = None,
    event_type: str | None = None,
    outcome: str | None = None,
) -> list[AuditEvent]:
    """Retrieve and filter audit events for the searchable timeline."""
    events = repository.list_audit_events()
    filtered: list[AuditEvent] = []

    clean_query = query.strip().lower() if query else None
    clean_event_type = event_type.strip().lower() if event_type and event_type != "All" else None
    clean_outcome = outcome.strip().lower() if outcome and outcome != "All" else None

    for event in events:
        if clean_event_type and event.event_type.lower() != clean_event_type:
            continue
        if clean_outcome and event.outcome.lower() != clean_outcome:
            continue
        if clean_query:
            haystack = (
                f"{event.event_type} {event.outcome} {event.entity_type} {event.entity_id or ''} "
                f"{json.dumps(event.detail)}"
            ).lower()
            if clean_query not in haystack:
                continue
        filtered.append(event)

    return filtered
