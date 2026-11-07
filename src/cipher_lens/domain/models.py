"""Typed records for scope registration and auditable safety decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ActionClass(StrEnum):
    RECON = "recon"
    ACTIVE_VALIDATION = "active_validation"


class ScopeRegistration(BaseModel):
    target: str
    allowed_ports: str = Field(min_length=1)
    excluded_ports: str = ""
    excluded_endpoints: str = ""
    engagement_note: str = Field(min_length=1, max_length=2_000)
    authorized_lab_attested: bool
    allowed_actions: set[ActionClass] = Field(default_factory=lambda: {ActionClass.RECON})


class ScopeRecord(ScopeRegistration):
    id: str
    canonical_target: str
    created_at: datetime


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    outcome: str
    entity_type: str
    entity_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
