"""Fail-closed contract for every live or import-only assessment adapter.

Default calls time out after 300 seconds and are polled every 2 seconds.  The
contract deliberately declares no profile-specific overrides: an adapter may
pass explicit values only after documenting its tool-specific rationale.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from cipher_lens.domain.models import ActionClass, AnticipatedNextStep, ScopeRecord
from cipher_lens.domain.scope import is_in_scope, normalize_target
from cipher_lens.domain.validation import ValidationError, parse_ports, validate_target
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.audit import record
from cipher_lens.services.planning import InMemoryRateLimiter, RateLimitDecision


DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_POLL_INTERVAL_SECONDS = 2


class ScanRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PARSING = "parsing"
    DONE = "done"
    FAILED = "failed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"


class Finding(BaseModel):
    """Evidence-backed common finding shape; parsers leave unsupported values unset."""

    model_config = ConfigDict(extra="forbid")

    source_tool: str = Field(min_length=1, max_length=64)
    affected_asset: str = Field(min_length=1, max_length=253)
    description: str = Field(min_length=1, max_length=10_000)
    severity: str | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    cve: str | None = None
    cwe: str | None = None
    confidence: str | None = None
    validation_status: str = "suspected"
    product: str | None = None
    version: str | None = None


class AdapterRequest(BaseModel):
    """Typed request accepted by the four-stage adapter lifecycle."""

    model_config = ConfigDict(extra="forbid")

    target: str
    port: StrictInt
    profile: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    action: ActionClass = ActionClass.RECON
    scheme: Literal["http", "https"] | None = None
    rationale: str = Field(min_length=1, max_length=1_000)
    anticipated_next_steps: list[AnticipatedNextStep] = Field(default_factory=list, max_length=3)
    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=1, le=3_600)
    poll_interval_seconds: int = Field(default=DEFAULT_POLL_INTERVAL_SECONDS, ge=1, le=60)

    @field_validator("target")
    @classmethod
    def target_must_be_valid(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, value: int) -> int:
        parse_ports(str(value))
        return value


@dataclass(frozen=True)
class AdapterContext:
    repository: Repository
    scope: ScopeRecord
    artifact_directory: Path
    rate_limiter: InMemoryRateLimiter
    approval_id: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    status: ScanRunStatus
    reason: str
    request: AdapterRequest
    ticket: str | None = None


@dataclass(frozen=True)
class RunHandle:
    run_id: str
    status: ScanRunStatus = ScanRunStatus.QUEUED
    reason: str = ""


@dataclass(frozen=True)
class PollResult:
    run_id: str
    status: ScanRunStatus
    reason: str = ""
    progress: int = 0


@dataclass(frozen=True)
class EvidenceArtifact:
    id: str
    file_path: Path
    sha256: str
    tool: str
    captured_at: datetime


@dataclass(frozen=True)
class ParseResult:
    evidence: EvidenceArtifact
    findings: list[Finding] = field(default_factory=list)
    status: ScanRunStatus = ScanRunStatus.DONE
    reason: str = ""


class ToolAdapter(ABC):
    """Shared lifecycle. Subclasses must never call ``start`` before ``validate`` succeeds."""

    tool_name: str
    allowed_profiles: frozenset[str]
    requires_approval: bool = False

    def validate(self, context: AdapterContext, request: AdapterRequest) -> ValidationResult:
        """Reuse central validators, scope, and rate policy before any external tool interaction."""
        try:
            target = validate_target(request.target)
            parse_ports(str(request.port))
        except ValidationError as error:
            return self._reject(context, request, ScanRunStatus.BLOCKED, str(error), "input_validation")
        if request.profile not in self.allowed_profiles:
            return self._reject(context, request, ScanRunStatus.BLOCKED, "Profile is not allow-listed.", "profile_allowlist")
        allowed, reason = is_in_scope(context.scope, target, request.port, request.action)
        if not allowed:
            return self._reject(context, request, ScanRunStatus.BLOCKED, reason, "scope_check")

        if request.action == ActionClass.ACTIVE_VALIDATION and context.approval_id is not None:
            approval_allowed, approval_reason = context.repository.verify_adapter_approval(
                context.approval_id, context.scope.id, request.target, request.port, request.scheme, request.action.value
            )
            record(context.repository, event_type="adapter_approval_verification",
                   outcome="allowed" if approval_allowed else "denied", entity_type="approval",
                   entity_id=context.approval_id, detail={"tool": self.tool_name, "reason": approval_reason})
            if not approval_allowed:
                return self._reject(context, request, ScanRunStatus.BLOCKED, approval_reason, "approval")
            self._audit_rate_limit_exemption(context, request)
        else:
            rate = context.rate_limiter(context.scope, request_to_plan_shape(request), request.action)
            self._audit_rate_limit(context, request, rate)
            if not rate.allowed:
                return self._reject(context, request, ScanRunStatus.BLOCKED, rate.reason, "rate_limit")
        if request.action == ActionClass.ACTIVE_VALIDATION and context.approval_id is None:
            return self._reject(
                context,
                request,
                ScanRunStatus.AWAITING_APPROVAL,
                "Active validation requires explicit human approval.",
                "approval",
            )
        self._audit(context, request, ScanRunStatus.QUEUED, "validated")
        ticket = str(uuid4())
        self._validated_tickets.add((context.scope.id, ticket))
        return ValidationResult(ScanRunStatus.QUEUED, "Validation passed.", request, ticket)

    @property
    def _validated_tickets(self) -> set[tuple[str, str]]:
        tickets = getattr(self, "__validated_tickets", None)
        if tickets is None:
            tickets = set()
            setattr(self, "__validated_tickets", tickets)
        return tickets

    def require_startable(self, context: AdapterContext, validated: ValidationResult) -> None:
        """Consume a successful validation ticket before any adapter may touch a tool."""
        ticket = validated.ticket
        if validated.status != ScanRunStatus.QUEUED or ticket is None:
            raise ValueError("A queued validation result is required before starting an adapter.")
        key = (context.scope.id, ticket)
        if key not in self._validated_tickets:
            raise ValueError("Validation result is missing, stale, or belongs to a different scope.")
        self._validated_tickets.remove(key)

    @abstractmethod
    def start(self, context: AdapterContext, validated: ValidationResult) -> RunHandle:
        """Launch an argument-list subprocess or open a daemon connection, then return immediately."""

    @abstractmethod
    def poll(self, context: AdapterContext, handle: RunHandle) -> PollResult:
        """Report queued/running/parsing/done/failed/blocked/awaiting_approval without blocking."""

    @abstractmethod
    def parse(self, context: AdapterContext, handle: RunHandle, raw_output: bytes) -> ParseResult:
        """Map completed XML/JSON to Findings and persist the immutable raw artifact."""

    def persist_raw_artifact(
        self, context: AdapterContext, run_id: str | None, raw_output: bytes, extension: str
    ) -> EvidenceArtifact:
        """Persist raw bytes locally and save their immutable SHA-256 reference in SQLite."""
        safe_extension = extension if extension.startswith(".") and extension[1:].isalnum() else ".bin"
        artifact_id = str(uuid4())
        path = context.artifact_directory / self.tool_name / f"{artifact_id}{safe_extension}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw_output)
        artifact = EvidenceArtifact(
            id=artifact_id,
            file_path=path.resolve(),
            sha256=hashlib.sha256(raw_output).hexdigest(),
            tool=self.tool_name,
            captured_at=datetime.now(timezone.utc),
        )
        context.repository.save_evidence(artifact, run_id)
        record(
            context.repository,
            event_type="raw_evidence_persisted",
            outcome="stored",
            entity_type="evidence",
            entity_id=artifact.id,
            detail={"tool": self.tool_name, "file_path": str(artifact.file_path), "sha256": artifact.sha256},
        )
        return artifact

    def parse_failure(
        self, context: AdapterContext, handle: RunHandle, evidence: EvidenceArtifact, reason: str
    ) -> ParseResult:
        """Preserve malformed evidence while making its failed interpretation auditable."""
        context.repository.update_scan_run(handle.run_id, ScanRunStatus.FAILED.value, reason)
        record(
            context.repository,
            event_type="adapter_parse",
            outcome="failed",
            entity_type="scan_run",
            entity_id=handle.run_id,
            detail={"tool": self.tool_name, "evidence_id": evidence.id, "reason": reason},
        )
        return ParseResult(evidence=evidence, status=ScanRunStatus.FAILED, reason=reason)

    def _audit_rate_limit(self, context: AdapterContext, request: AdapterRequest, decision: RateLimitDecision) -> None:
        record(
            context.repository,
            event_type="adapter_rate_limit",
            outcome="allowed" if decision.allowed else "denied",
            entity_type="adapter_request",
            detail={
                "tool": self.tool_name,
                "target": normalize_target(request.target),
                "port": request.port,
                "action": request.action.value,
                "remaining_wait_seconds": decision.remaining_seconds,
                "reason": decision.reason,
            },
        )

    def _audit_rate_limit_exemption(self, context: AdapterContext, request: AdapterRequest) -> None:
        record(
            context.repository,
            event_type="adapter_rate_limit",
            outcome="exempt",
            entity_type="adapter_request",
            detail={
                "tool": self.tool_name,
                "target": normalize_target(request.target),
                "port": request.port,
                "action": request.action.value,
                "reason": "Recorded human approval continues an already queued action.",
            },
        )

    def _reject(
        self, context: AdapterContext, request: AdapterRequest, status: ScanRunStatus, reason: str, gate: str
    ) -> ValidationResult:
        self._audit(context, request, status, gate, reason)
        return ValidationResult(status, reason, request)

    def _audit(
        self, context: AdapterContext, request: AdapterRequest, status: ScanRunStatus, gate: str, reason: str = ""
    ) -> None:
        record(
            context.repository,
            event_type="adapter_validation",
            outcome=status.value,
            entity_type="adapter_request",
            detail={
                "tool": self.tool_name,
                "target": request.target,
                "port": request.port,
                "profile": request.profile,
                "action": request.action.value,
                "scheme": request.scheme,
                "gate": gate,
                "reason": reason,
            },
        )


def request_to_plan_shape(request: AdapterRequest) -> Any:
    """Expose only the fields consumed by the existing central rate-limit implementation."""

    return type("RateLimitedRequest", (), {"target": request.target, "port": request.port})()
