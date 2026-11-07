"""Unit tests for approval state machine and audit timeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.approvals import (
    ApprovalStatus,
    APPROVAL_TTL_MINUTES,
    create_approval_request,
    list_audit_timeline,
    transition_approval,
)
from cipher_lens.services.scope_registration import register_scope
from cipher_lens.ui.audit_page import _approval_status_badge


@pytest.fixture
def test_repo(tmp_path: Path) -> Repository:
    db_file = tmp_path / "test_approvals.db"
    return Repository(db_file)


@pytest.fixture
def active_scope(test_repo: Repository):
    return register_scope(
        test_repo,
        ScopeRegistration(
            target="10.0.0.1",
            allowed_ports="80,443,8080",
            engagement_note="Lab assessment active testing",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )


@pytest.fixture
def recon_only_scope(test_repo: Repository):
    return register_scope(
        test_repo,
        ScopeRegistration(
            target="10.0.0.2",
            allowed_ports="80",
            engagement_note="Recon only scope",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON},
        ),
    )


def test_approval_request_creation_and_audit(test_repo: Repository, active_scope):
    approval_id = create_approval_request(
        test_repo,
        active_scope,
        target="10.0.0.1",
        port=8080,
        scheme="http",
        requested_by="Analyst Bob",
        rationale="Active verification of suspected SQL injection",
    )

    approval = test_repo.get_approval(approval_id)
    assert approval is not None
    assert approval.status == ApprovalStatus.PENDING.value
    assert approval.target == "10.0.0.1"
    assert approval.port == 8080
    assert approval.scheme == "http"
    assert approval.requested_by == "Analyst Bob"
    assert "SQL injection" in (approval.requested_rationale or "")

    # Audit event logged
    events = test_repo.list_audit_events()
    req_event = next(e for e in events if e.event_type == "approval_requested")
    assert req_event.outcome == "pending"
    assert req_event.entity_id == approval_id
    assert req_event.detail["target"] == "10.0.0.1"


def test_approval_request_out_of_scope_rejected(test_repo: Repository, active_scope):
    # Port 22 is outside allowed ports 80,443,8080
    with pytest.raises(ValueError, match="outside the authorized scope"):
        create_approval_request(
            test_repo,
            active_scope,
            target="10.0.0.1",
            port=22,
            requested_by="Analyst Bob",
            rationale="SSH brute force",
        )

    # Out of scope host
    with pytest.raises(ValueError, match="outside the authorized scope"):
        create_approval_request(
            test_repo,
            active_scope,
            target="192.168.1.99",
            port=80,
            requested_by="Analyst Bob",
            rationale="External test",
        )


def test_approval_request_action_not_permitted_by_scope(test_repo: Repository, recon_only_scope):
    with pytest.raises(ValueError, match="not authorized for this scope"):
        create_approval_request(
            test_repo,
            recon_only_scope,
            target="10.0.0.2",
            port=80,
            action=ActionClass.ACTIVE_VALIDATION,
            requested_by="Analyst Bob",
            rationale="Attempting active validation on recon-only scope",
        )


def test_approval_state_machine_valid_transitions(test_repo: Repository, active_scope):
    # 1. pending -> approved
    app_id_1 = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=80, requested_by="Requester", rationale="Rationale"
    )
    approved = transition_approval(
        test_repo, app_id_1, ApprovalStatus.APPROVED, actor="Lead Analyst", rationale="Evidence verified"
    )
    assert approved.status == ApprovalStatus.APPROVED.value
    assert approved.decision_actor == "Lead Analyst"
    assert approved.expires_at is not None

    # approved -> completed
    completed = transition_approval(
        test_repo, app_id_1, ApprovalStatus.COMPLETED, actor="Lead Analyst", rationale="Scan execution finished"
    )
    assert completed.status == ApprovalStatus.COMPLETED.value

    # 2. pending -> rejected
    app_id_2 = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=443, requested_by="Requester", rationale="Rationale"
    )
    rejected = transition_approval(
        test_repo, app_id_2, ApprovalStatus.REJECTED, actor="Lead Analyst", rationale="Risk too high"
    )
    assert rejected.status == ApprovalStatus.REJECTED.value

    # 3. pending -> cancelled
    app_id_3 = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=8080, requested_by="Requester", rationale="Rationale"
    )
    cancelled = transition_approval(
        test_repo, app_id_3, ApprovalStatus.CANCELLED, actor="Requester", rationale="No longer required"
    )
    assert cancelled.status == ApprovalStatus.CANCELLED.value


def test_approval_state_machine_invalid_transitions_rejected(test_repo: Repository, active_scope):
    app_id = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=80, requested_by="Requester", rationale="Rationale"
    )
    transition_approval(
        test_repo, app_id, ApprovalStatus.REJECTED, actor="Reviewer", rationale="Declined"
    )

    # Terminal state REJECTED cannot transition to APPROVED
    with pytest.raises(ValueError, match="Cannot transition approval from 'rejected' to 'approved'"):
        transition_approval(
            test_repo, app_id, ApprovalStatus.APPROVED, actor="Reviewer", rationale="Changed mind"
        )


def test_transition_requires_actor_and_rationale(test_repo: Repository, active_scope):
    app_id = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=80, requested_by="Requester", rationale="Rationale"
    )

    with pytest.raises(ValueError, match="Decision actor name or identifier is required"):
        transition_approval(test_repo, app_id, ApprovalStatus.APPROVED, actor="", rationale="Some rationale")

    with pytest.raises(ValueError, match="Decision rationale is required"):
        transition_approval(test_repo, app_id, ApprovalStatus.APPROVED, actor="Actor", rationale="  ")


def test_approval_expiry_enforcement(test_repo: Repository, active_scope):
    app_id = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=80, requested_by="Requester", rationale="Rationale"
    )
    transition_approval(
        test_repo, app_id, ApprovalStatus.APPROVED, actor="Reviewer", rationale="Approved"
    )

    # Manually backdate expiry to simulate time passage
    past_time = datetime.now(timezone.utc) - timedelta(minutes=1)
    test_repo.update_approval_decision(
        app_id,
        status="approved",
        actor="Reviewer",
        rationale="Approved",
        expires_at=past_time,
    )

    # verify_adapter_approval rejects expired
    valid, reason = test_repo.verify_adapter_approval(
        app_id, active_scope.id, "10.0.0.1", 80, None, ActionClass.ACTIVE_VALIDATION.value
    )
    assert not valid
    assert "expired" in reason.lower()

    # State machine detects expiry and rejects transition to approved
    with pytest.raises(ValueError, match="expired"):
        transition_approval(
            test_repo, app_id, ApprovalStatus.APPROVED, actor="Reviewer", rationale="Re-approve"
        )


def test_list_audit_timeline_filters(test_repo: Repository, active_scope):
    # Generate some distinct audit events
    app_id = create_approval_request(
        test_repo, active_scope, target="10.0.0.1", port=80, requested_by="Alice", rationale="Need testing"
    )
    transition_approval(
        test_repo, app_id, ApprovalStatus.APPROVED, actor="Bob", rationale="Approved for Alice"
    )

    # 1. No filters: returns all
    all_events = list_audit_timeline(test_repo)
    assert len(all_events) >= 2

    # 2. Query filter
    matched_alice = list_audit_timeline(test_repo, query="Alice")
    assert len(matched_alice) >= 1
    assert any("Alice" in str(e.detail) for e in matched_alice)

    # 3. Event type filter
    req_only = list_audit_timeline(test_repo, event_type="approval_requested")
    assert all(e.event_type == "approval_requested" for e in req_only)
    assert len(req_only) >= 1

    # 4. Outcome filter
    approved_only = list_audit_timeline(test_repo, outcome="approved")
    assert all(e.outcome == "approved" for e in approved_only)

    # 5. Non-matching search returns empty
    none_matched = list_audit_timeline(test_repo, query="nonexistent_xyz_keyword_12345")
    assert len(none_matched) == 0


def test_approval_status_badge_helper():
    badge = _approval_status_badge("pending")
    assert "cl-status-pending" in badge
    assert "pending" in badge
