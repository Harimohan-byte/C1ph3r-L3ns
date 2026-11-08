from pathlib import Path

from cipher_lens.persistence.repositories import Repository, ScanRunSummary
from cipher_lens.ui.assessment_page import recovery_guidance


def test_status_workspace_reads_scope_filtered_persisted_runs_and_approvals(tmp_path: Path):
    repository = Repository(tmp_path / "cipher.sqlite3")
    with repository.connection() as connection:
        connection.execute("""INSERT INTO scopes VALUES
            ('scope-1', 'lab.example', 'lab.example', '80', '', '', 'Authorized', 1, '[\"recon\"]', '2026-11-07T00:00:00+00:00'),
            ('scope-2', 'other.example', 'other.example', '443', '', '', 'Authorized', 1, '[\"recon\"]', '2026-11-07T00:00:00+00:00')""")
        connection.execute("INSERT INTO scan_runs (id, scope_id, tool, profile, status, rationale, anticipated_next_steps, started_at, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           ('run-1', 'scope-1', 'nmap', 'quick_recon', 'failed', 'Check service.', '[{\"tool\": \"nmap\", \"profile\": \"service_version_scan\", \"rationale\": \"Inspect observed service.\"}]', '2026-11-07T00:00:00+00:00', 'Nmap is unavailable.'))
        connection.execute("INSERT INTO scan_runs (id, scope_id, tool, profile, status) VALUES (?, ?, ?, ?, ?)",
                           ('run-2', 'scope-2', 'nikto', 'quick_recon', 'done'))
        connection.execute("""INSERT INTO approvals (id, scope_id, target, port, action, status, decision_actor,
            decision_rationale, decided_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ('approval-1', 'scope-1', 'lab.example', 80, 'active_validation', 'approved', 'analyst', 'Authorized.',
             '2026-11-07T00:00:00+00:00', '2026-11-07T00:15:00+00:00'))

    runs = repository.list_scan_runs('scope-1')
    approvals = repository.list_approvals('scope-1')

    assert [run.id for run in runs] == ['run-1']
    assert runs[0].target == 'lab.example'
    assert runs[0].rationale == 'Check service.'
    assert runs[0].anticipated_next_steps[0]['profile'] == 'service_version_scan'
    assert [approval.id for approval in approvals] == ['approval-1']
    assert approvals[0].status == 'approved'


def test_recovery_guidance_is_read_only_and_status_specific():
    failed = ScanRunSummary('run', 'scope', 'lab.example', 'nmap', 'quick_recon', 'failed', None, [], None, None, 'Unavailable')
    waiting = ScanRunSummary('run', 'scope', 'lab.example', 'zap', 'quick_recon', 'awaiting_approval', None, [], None, None, None)

    assert 'submit a new request' in recovery_guidance(failed)
    assert 'recorded analyst decision' in recovery_guidance(waiting)


def test_render_proposal_outcome_uses_modular_bento_chips():
    """Verify that _render_proposal_outcome renders modular bento chips instead of giant metrics."""
    from unittest.mock import patch
    from cipher_lens.domain.models import PlanProposal, ProposalStatus, ScanProfile, ToolName
    from cipher_lens.services.planning import ProposalOutcome
    from cipher_lens.ui.assessment_page import _render_proposal_outcome

    proposal = PlanProposal(
        tool=ToolName.NMAP,
        profile=ScanProfile.QUICK_RECON,
        target="127.0.0.1",
        port=3000,
        rationale="Initial port discovery.",
    )
    outcome = ProposalOutcome(
        status=ProposalStatus.APPROVED,
        proposal=proposal,
        reason="Target within authorized scope.",
        source="ai",
    )

    with patch("streamlit.markdown") as mock_markdown:
        _render_proposal_outcome(outcome, "ai")
        assert mock_markdown.called
        html = mock_markdown.call_args[0][0]
        # Verify modular Bento styling
        assert "Step Proposal" in html
        assert "127.0.0.1" in html
        assert "3000" in html
        assert "NMAP" in html
        assert "quick_recon" in html
        assert "Initial port discovery." in html

