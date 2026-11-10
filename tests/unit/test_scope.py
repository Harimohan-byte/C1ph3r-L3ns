from pathlib import Path

import pytest

from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.domain.scope import is_in_scope, normalize_target
from cipher_lens.domain.validation import ValidationError, parse_ports, validate_target
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.scope_registration import register_scope


def registered_scope(repository: Repository, **overrides):
    data = {
        "target": "Lab.Example.",
        "allowed_ports": "80,443,8000-8010",
        "excluded_ports": "443",
        "excluded_endpoints": "/admin",
        "engagement_note": "Authorized organizer lab.",
        "authorized_lab_attested": True,
        "allowed_actions": {ActionClass.RECON},
    }
    data.update(overrides)
    return register_scope(repository, ScopeRegistration(**data))


def test_target_validation_rejects_urls_and_whitespace():
    for value in ("https://lab.example", " lab.example", "lab.example ", "2001:db8::1"):
        with pytest.raises(ValidationError):
            validate_target(value)


def test_port_validation_rejects_invalid_or_descending_ranges():
    for value in ("0", "65536", "90-80", "80, 443", "80;443"):
        with pytest.raises(ValidationError):
            parse_ports(value)


def test_loopback_and_hostname_normalization():
    assert normalize_target("LOCALHOST.") == "127.0.0.1"
    assert normalize_target("127.0.0.1") == "127.0.0.1"
    assert normalize_target("Lab.Example.") == "lab.example"


def test_scope_enforces_target_ports_and_actions(tmp_path: Path):
    scope = registered_scope(Repository(tmp_path / "cipher.sqlite3"))
    assert is_in_scope(scope, "lab.example", 80, ActionClass.RECON)[0]
    assert not is_in_scope(scope, "lab.example", 443, ActionClass.RECON)[0]
    assert not is_in_scope(scope, "other.example", 80, ActionClass.RECON)[0]
    assert not is_in_scope(scope, "lab.example", 80, ActionClass.ACTIVE_VALIDATION)[0]


def test_rejected_scope_is_audited_and_approved_scope_persists(tmp_path: Path):
    repository = Repository(tmp_path / "cipher.sqlite3")
    with pytest.raises(ValidationError):
        registered_scope(repository, authorized_lab_attested=False)
    scope = registered_scope(repository)
    reopened = Repository(tmp_path / "cipher.sqlite3")
    assert [item.id for item in reopened.list_scopes()] == [scope.id]
    outcomes = [event.outcome for event in reopened.list_audit_events()]
    assert outcomes == ["approved", "rejected"]


def test_delete_scope_cascades_and_removes_records(tmp_path: Path):
    repository = Repository(tmp_path / "cipher.sqlite3")
    scope = registered_scope(repository)
    assert len(repository.list_scopes()) == 1

    # Create associated scan run
    repository.create_scan_run("run-1", scope.id, "nmap", "quick_recon", "done", "Initial scan")
    assert len(repository.list_scan_runs(scope.id)) == 1

    # Delete scope
    repository.delete_scope(scope.id)
    assert len(repository.list_scopes()) == 0
    assert len(repository.list_scan_runs(scope.id)) == 0
