from pathlib import Path
from urllib.error import URLError
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cipher_lens.adapters.base import AdapterContext, AdapterRequest, ScanRunStatus
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.nmap import NmapAdapter, PROFILE_FLAGS
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.planning import InMemoryRateLimiter
from cipher_lens.services.approvals import record_approval
from cipher_lens.services.scope_registration import register_scope


def context(tmp_path: Path, *, approval_id: str | None = None) -> AdapterContext:
    repository = Repository(tmp_path / "cipher.sqlite3")
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="lab.example", allowed_ports="80", excluded_ports="", excluded_endpoints="",
            engagement_note="Authorized lab.", authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    return AdapterContext(repository, scope, tmp_path / "artifacts", InMemoryRateLimiter(clock=lambda: 0), approval_id)


def test_nmap_unavailable_is_audited_after_successful_validation(tmp_path: Path):
    adapter = NmapAdapter()
    current = context(tmp_path)
    validated = adapter.validate(current, AdapterRequest(
        target="lab.example", port=80, profile="quick_recon", rationale="Check the approved web service.",
        anticipated_next_steps=[{
            "tool": "nmap", "profile": "service_version_scan", "rationale": "Inspect an observed service."
        }],
    ))
    with patch("shutil.which", return_value=None):
        handle = adapter.start(current, validated)
    assert handle.status == ScanRunStatus.FAILED
    assert "unavailable" in handle.reason.lower()
    assert PROFILE_FLAGS["targeted_port_scan"] == ("-sT", "-sV", "--reason", "-n", "-Pn", "--open", "-T3")
    saved = current.repository.list_scan_runs(current.scope.id)
    assert saved[0].rationale == "Check the approved web service."
    assert saved[0].anticipated_next_steps[0]["profile"] == "service_version_scan"


def test_nikto_unavailable_is_explicit(tmp_path: Path):
    adapter = NiktoAdapter()
    current = context(tmp_path)
    validated = adapter.validate(current, AdapterRequest(target="lab.example", port=80, profile="quick_recon", rationale="Check the web service."))
    with patch("shutil.which", return_value=None):
        handle = adapter.start(current, validated)
    assert handle.status == ScanRunStatus.FAILED
    assert "unavailable" in handle.reason.lower()


def test_every_adapter_blocks_active_validation_without_recorded_approval(tmp_path: Path):
    adapter = NmapAdapter()
    current = context(tmp_path)
    result = adapter.validate(
        current,
        AdapterRequest(target="lab.example", port=80, profile="quick_recon", scheme="http", action=ActionClass.ACTIVE_VALIDATION, rationale="Validate the approved service."),
    )
    assert result.status == ScanRunStatus.AWAITING_APPROVAL


def test_zap_active_request_waits_for_approval_before_daemon_access(tmp_path: Path):
    calls: list[str] = []
    adapter = ZapAdapter(base_url="http://127.0.0.1:8080", opener=lambda *args, **kwargs: calls.append(args[0]))
    current = context(tmp_path)
    result = adapter.validate(
        current,
        AdapterRequest(
            target="lab.example",
            port=80,
            profile="quick_recon",
            scheme="http",
            action=ActionClass.ACTIVE_VALIDATION,
            rationale="Validate the approved service.",
        ),
    )
    assert result.status == ScanRunStatus.AWAITING_APPROVAL
    assert calls == []


def test_zap_unreachable_daemon_fails_explicitly_after_recon_validation(tmp_path: Path):
    def unreachable(*args, **kwargs):
        raise URLError("offline")

    adapter = ZapAdapter(base_url="http://127.0.0.1:8080", opener=unreachable)
    current = context(tmp_path)
    validated = adapter.validate(current, AdapterRequest(target="lab.example", port=80, profile="quick_recon", scheme="http", rationale="Inspect the web service."))
    handle = adapter.start(current, validated)
    assert handle.status == ScanRunStatus.FAILED
    assert "unavailable" in handle.reason.lower()


def test_active_adapter_requires_a_matching_persisted_approval(tmp_path: Path):
    current = context(tmp_path)
    approval_id = record_approval(
        current.repository, current.scope, target="lab.example", port=80, scheme=None,
        action=ActionClass.ACTIVE_VALIDATION, actor="analyst", rationale="Authorized validation.", approved=True,
    )
    approved_context = AdapterContext(
        current.repository, current.scope, current.artifact_directory, current.rate_limiter, approval_id
    )
    result = NmapAdapter().validate(
        approved_context,
        AdapterRequest(target="lab.example", port=80, profile="quick_recon", action=ActionClass.ACTIVE_VALIDATION, rationale="Validate the approved service."),
    )
    assert result.status == ScanRunStatus.QUEUED


def test_active_adapter_rejects_a_rejected_or_expired_approval(tmp_path: Path):
    current = context(tmp_path)
    rejected = record_approval(
        current.repository, current.scope, target="lab.example", port=80, scheme=None,
        action=ActionClass.ACTIVE_VALIDATION, actor="analyst", rationale="Denied.", approved=False,
    )
    rejected_context = AdapterContext(
        current.repository, current.scope, current.artifact_directory, current.rate_limiter, rejected
    )
    request = AdapterRequest(target="lab.example", port=80, profile="quick_recon", action=ActionClass.ACTIVE_VALIDATION, rationale="Validate the approved service.")
    assert NmapAdapter().validate(rejected_context, request).status == ScanRunStatus.BLOCKED

    expired = "expired-approval"
    current.repository.save_adapter_approval(
        expired, current.scope.id, "lab.example", 80, None, ActionClass.ACTIVE_VALIDATION.value,
        "approved", "analyst", "Expired.", datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    expired_context = AdapterContext(
        current.repository, current.scope, current.artifact_directory, current.rate_limiter, expired
    )
    assert NmapAdapter().validate(expired_context, request).status == ScanRunStatus.BLOCKED


def test_zap_requires_explicit_scheme(tmp_path: Path):
    current = context(tmp_path)
    result = ZapAdapter(base_url="http://127.0.0.1:8080").validate(
        current, AdapterRequest(target="lab.example", port=80, profile="quick_recon", rationale="Inspect the service.")
    )
    assert result.status == ScanRunStatus.BLOCKED
    assert "scheme" in result.reason.lower()


def test_zap_uses_the_explicit_https_scheme_after_matching_approval(tmp_path: Path):
    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body
        def read(self) -> bytes:
            return self.body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    calls: list[str] = []
    def opener(url, timeout):
        calls.append(url)
        return Response(b'{"version":"1"}' if "version" in url else b'{"scan":"9"}')

    current = context(tmp_path)
    approval_id = record_approval(
        current.repository, current.scope, target="lab.example", port=80, scheme="https",
        action=ActionClass.ACTIVE_VALIDATION, actor="analyst", rationale="Approved.", approved=True,
    )
    approved_context = AdapterContext(
        current.repository, current.scope, current.artifact_directory, current.rate_limiter, approval_id
    )
    adapter = ZapAdapter(base_url="http://127.0.0.1:8080", opener=opener)
    validated = adapter.validate(approved_context, AdapterRequest(
        target="lab.example", port=80, profile="quick_recon", scheme="https", action=ActionClass.ACTIVE_VALIDATION, rationale="Validate the approved web service.",
    ))
    handle = adapter.start(approved_context, validated)
    assert handle.status == ScanRunStatus.RUNNING
    assert any("url=https%3A%2F%2Flab.example%3A80" in url for url in calls)


def test_malformed_adapter_outputs_are_preserved_and_audited_as_failures(tmp_path: Path):
    current = context(tmp_path)
    cases = [
        (NmapAdapter(), b"<nmaprun>"),
        (NiktoAdapter(), b"<scandetails>"),
        (ZapAdapter(base_url="http://127.0.0.1:8080"), b"{not-json"),
    ]
    for index, (adapter, raw_output) in enumerate(cases):
        handle = type("Handle", (), {"run_id": f"parse-{index}"})()
        current.repository.create_scan_run(handle.run_id, current.scope.id, adapter.tool_name, "quick_recon", "parsing")
        result = adapter.parse(current, handle, raw_output)
        assert result.status == ScanRunStatus.FAILED
        assert result.evidence.file_path.read_bytes() == raw_output
    parse_failures = [event for event in current.repository.list_audit_events() if event.event_type == "adapter_parse"]
    assert len([event for event in parse_failures if event.outcome == "failed"]) == 3
