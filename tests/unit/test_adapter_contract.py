from pathlib import Path

import pytest

from cipher_lens.adapters.base import (
    AdapterContext,
    AdapterRequest,
    ParseResult,
    PollResult,
    RunHandle,
    ScanRunStatus,
    ToolAdapter,
    ValidationResult,
)
from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.planning import InMemoryRateLimiter
from cipher_lens.services.scope_registration import register_scope


class FakeAdapter(ToolAdapter):
    tool_name = "fake"
    allowed_profiles = frozenset({"quick_recon"})
    requires_approval = True

    def __init__(self) -> None:
        self.started = 0

    def start(self, context, validated):
        self.started += 1
        return RunHandle("run-1", ScanRunStatus.RUNNING)

    def poll(self, context, handle):
        return PollResult(handle.run_id, ScanRunStatus.DONE)

    def parse(self, context, handle, raw_output):
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".xml")
        return ParseResult(evidence=evidence)


def adapter_context(tmp_path: Path, *, excluded_ports: str = "", approval_id: str | None = None):
    repository = Repository(tmp_path / "cipher.sqlite3")
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="lab.example",
            allowed_ports="80",
            excluded_ports=excluded_ports,
            excluded_endpoints="",
            engagement_note="Authorized lab.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    return repository, AdapterContext(
        repository=repository,
        scope=scope,
        artifact_directory=tmp_path / "artifacts",
        rate_limiter=InMemoryRateLimiter(clock=lambda: 0),
        approval_id=approval_id,
    )


def test_validate_scope_then_rate_and_never_starts_blocked_request(tmp_path: Path):
    repository, context = adapter_context(tmp_path, excluded_ports="80")
    adapter = FakeAdapter()
    result = adapter.validate(context, AdapterRequest(target="lab.example", port=80, profile="quick_recon", rationale="Check the approved service."))
    assert result.status == ScanRunStatus.BLOCKED
    assert adapter.started == 0
    events = repository.list_audit_events()
    assert any(event.event_type == "adapter_validation" and event.detail["gate"] == "scope_check" for event in events)
    assert not any(event.event_type == "adapter_rate_limit" for event in events)


def test_validate_audits_rate_and_waits_for_active_approval(tmp_path: Path):
    repository, context = adapter_context(tmp_path)
    adapter = FakeAdapter()
    request = AdapterRequest(
        target="lab.example", port=80, profile="quick_recon", action=ActionClass.ACTIVE_VALIDATION, rationale="Validate the approved service."
    )
    result = adapter.validate(context, request)
    assert result.status == ScanRunStatus.AWAITING_APPROVAL
    assert adapter.started == 0
    events = repository.list_audit_events()
    assert any(event.event_type == "adapter_rate_limit" and event.outcome == "allowed" for event in events)
    assert any(event.event_type == "adapter_validation" and event.outcome == "awaiting_approval" for event in events)


def test_parse_helper_persists_hashed_raw_artifact(tmp_path: Path):
    repository, context = adapter_context(tmp_path)
    adapter = FakeAdapter()
    evidence = adapter.persist_raw_artifact(context, None, b"<scan/>", ".xml")
    assert evidence.file_path.read_bytes() == b"<scan/>"
    assert len(evidence.sha256) == 64
    with repository.connection() as connection:
        row = connection.execute("SELECT file_path, sha256 FROM evidence WHERE id = ?", (evidence.id,)).fetchone()
    assert row["file_path"] == str(evidence.file_path)
    assert row["sha256"] == evidence.sha256


def test_start_rejects_a_fabricated_or_replayed_validation_result(tmp_path: Path):
    _, context = adapter_context(tmp_path)
    adapter = FakeAdapter()
    request = AdapterRequest(target="lab.example", port=80, profile="quick_recon", rationale="Check the approved service.")
    with pytest.raises(ValueError, match="queued validation"):
        adapter.require_startable(context, ValidationResult(ScanRunStatus.QUEUED, "fake", request))
    valid = adapter.validate(context, request)
    adapter.require_startable(context, valid)
    with pytest.raises(ValueError, match="stale"):
        adapter.require_startable(context, valid)


def test_tool_adapter_default_get_output_path_returns_none(tmp_path: Path):
    """Base ToolAdapter contract defines get_output_path defaulting to None."""
    _, context = adapter_context(tmp_path)
    adapter = FakeAdapter()
    assert adapter.get_output_path("nonexistent-run-id") is None
    assert adapter.get_output_path("nonexistent-run-id", context) is None

