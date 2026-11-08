"""Typed records for scope registration and auditable safety decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from pydantic import StrictInt, field_validator

from cipher_lens.domain.validation import validate_target
from cipher_lens.domain.findings import (
    FindingProvenance,
    NormalizedFinding,
    Severity,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    ValidationStatus,
)


class ActionClass(StrEnum):
    RECON = "recon"
    ACTIVE_VALIDATION = "active_validation"


class ToolName(StrEnum):
    NMAP = "nmap"
    NIKTO = "nikto"
    ZAP = "zap"


class ScanProfile(StrEnum):
    QUICK_RECON = "quick_recon"
    SERVICE_VERSION_SCAN = "service_version_scan"
    TARGETED_PORT_SCAN = "targeted_port_scan"
    FULL_PORT_SCAN = "full_port_scan"
    OS_DETECTION = "os_detection"
    WEB_QUICK = "web_quick"
    ACTIVE_SCAN = "active_scan"
    SPIDER = "spider"


class AnticipatedNextStep(BaseModel):
    """Non-executable analyst preview. It never includes target, port, or arguments."""

    model_config = ConfigDict(extra="forbid")

    tool: ToolName
    profile: ScanProfile
    rationale: str = Field(min_length=1, max_length=280)


class PlanProposal(BaseModel):
    """The only executable shape a provider may propose during Phase 2."""

    model_config = ConfigDict(extra="forbid")

    tool: ToolName
    profile: ScanProfile
    target: str
    port: StrictInt
    rationale: str = Field(min_length=1, max_length=1_000)
    anticipated_next_steps: list[AnticipatedNextStep] = Field(default_factory=list, max_length=3)

    @field_validator("target")
    @classmethod
    def target_must_be_valid(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        return value


class ProposalStatus(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"


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
