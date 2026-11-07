"""Domain models for normalized security findings and evidence provenance."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}


class ValidationStatus(StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    NOT_VALIDATED = "not_validated"
    FALSE_POSITIVE = "false_positive"
    VALIDATION_BLOCKED = "validation_blocked"


class FindingProvenance(BaseModel):
    """Immutable provenance record preserving evidence origin for a finding."""

    model_config = ConfigDict(extra="forbid")

    source_tool: str = Field(min_length=1, max_length=64)
    scan_run_id: str | None = None
    evidence_id: str | None = None
    file_path: str | None = None
    sha256: str | None = None
    raw_reference: str | None = None
    captured_at: str | None = None


class NormalizedFinding(BaseModel):
    """Consolidated, evidence-backed finding adhering to data-model specifications."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()))
    canonical_title: str = Field(min_length=1, max_length=256)
    affected_asset: str = Field(min_length=1, max_length=253)
    description: str = Field(min_length=1, max_length=10_000)
    severity: Severity = Severity.INFO
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    cve: str | None = None
    cwe: str | None = None
    confidence: str = "observed"
    validation_status: ValidationStatus = ValidationStatus.SUSPECTED
    priority_score: float = Field(default=0.0, ge=0.0, le=10.0)
    provenance: list[FindingProvenance] = Field(default_factory=list)
    scan_run_id: str | None = None
