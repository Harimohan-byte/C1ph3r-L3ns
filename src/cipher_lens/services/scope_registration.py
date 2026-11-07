"""Scope registration service that validates, persists, and audits each decision."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from cipher_lens.domain.models import ScopeRecord, ScopeRegistration
from cipher_lens.domain.scope import normalize_target
from cipher_lens.domain.validation import ValidationError, parse_ports, validate_target
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.audit import record


def register_scope(repository: Repository, registration: ScopeRegistration) -> ScopeRecord:
    try:
        validate_target(registration.target)
        parse_ports(registration.allowed_ports)
        parse_ports(registration.excluded_ports, allow_empty=True)
        if not registration.authorized_lab_attested:
            raise ValidationError("Authorization attestation is required before a scope can be saved.")
    except ValidationError as error:
        record(
            repository,
            event_type="scope_registration",
            outcome="rejected",
            entity_type="scope",
            detail={"reason": str(error), "target": registration.target},
        )
        raise

    scope = ScopeRecord(
        **registration.model_dump(),
        id=str(uuid4()),
        canonical_target=normalize_target(registration.target),
        created_at=datetime.now(timezone.utc),
    )
    repository.save_scope(scope)
    record(
        repository,
        event_type="scope_registration",
        outcome="approved",
        entity_type="scope",
        entity_id=scope.id,
        detail={"target": scope.canonical_target, "allowed_actions": sorted(a.value for a in scope.allowed_actions)},
    )
    return scope
