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


def test_mid_scan_page_reload_does_not_fail_running_scan(tmp_path: Path):
    """Regression test: ordinary Streamlit reruns/reloads mid-scan must NOT mark running scans as failed."""
    from unittest.mock import MagicMock, patch
    from cipher_lens.adapters.base import PollResult, ScanRunStatus
    from cipher_lens.ui.assessment_page import _recover_orphaned_scans

    repository = Repository(tmp_path / "cipher.sqlite3")
    with repository.connection() as conn:
        conn.execute("""INSERT INTO scopes VALUES
            ('scope-1', '127.0.0.1', '127.0.0.1', '3000', '', '', 'Authorized', 1, '[\"recon\"]', '2026-11-08T00:00:00+00:00')""")
        # A scan that is currently executing in background
        conn.execute("""INSERT INTO scan_runs (id, scope_id, tool, profile, status, rationale, started_at)
            VALUES ('run-active', 'scope-1', 'nikto', 'web_quick', 'running', 'Web vulnerability scan.', datetime('now'))""")

    # Mock adapter poll returning ScanRunStatus.RUNNING (scan still in progress)
    mock_nikto = MagicMock()
    mock_nikto.poll.return_value = PollResult("run-active", ScanRunStatus.RUNNING)

    with patch("cipher_lens.ui.assessment_page._session_adapters", return_value={"nikto": mock_nikto}):
        # Simulate Streamlit page reload / widget interaction
        _recover_orphaned_scans(repository, "scope-1")

    # Confirm the scan is STILL running, NOT marked failed or interrupted!
    runs = repository.list_scan_runs("scope-1")
    assert len(runs) == 1
    assert runs[0].status == "running"
    assert runs[0].error_message is None


def test_execute_and_collect_scan_uses_get_output_path_for_all_adapters(tmp_path: Path):
    """Regression test: _execute_and_collect_scan retrieves output_path via get_output_path

    without touching private _runs, preventing TypeError on custom _ZapRun objects.
    """
    from unittest.mock import MagicMock, patch
    from cipher_lens.adapters.base import Finding, ParseResult, PollResult, RunHandle, ScanRunStatus, ValidationResult
    from cipher_lens.adapters.base import AdapterContext, Finding, ParseResult, PollResult, RunHandle, ScanRunStatus, ValidationResult
    from cipher_lens.adapters.nikto import NiktoAdapter
    from cipher_lens.adapters.nmap import NmapAdapter
    from cipher_lens.adapters.zap import ZapAdapter, _ZapRun
    from cipher_lens.domain.models import ActionClass, PlanProposal, ScanProfile, ScopeRegistration, ToolName
    from cipher_lens.services.planning import InMemoryRateLimiter
    from cipher_lens.services.scope_registration import register_scope
    from cipher_lens.ui.assessment_page import _execute_and_collect_scan

    repository = Repository(tmp_path / "test_collect.sqlite3")
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="127.0.0.1",
            allowed_ports="3000",
            excluded_ports="",
            excluded_endpoints="",
            engagement_note="Test note",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )

    rate_limiter = InMemoryRateLimiter(clock=lambda: 0)
    artifact_dir = tmp_path / "artifacts" / scope.id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    ctx = AdapterContext(repository, scope, artifact_dir, rate_limiter)

    # 1. Test NMAP
    nmap_adapter = NmapAdapter()
    run_id_nmap = "run-nmap-101"
    nmap_xml = artifact_dir / "nmap" / f"{run_id_nmap}.xml"
    nmap_xml.parent.mkdir(parents=True, exist_ok=True)
    nmap_xml.write_bytes(b"<nmaprun></nmaprun>")
    nmap_adapter._runs[run_id_nmap] = (MagicMock(), nmap_xml, 9999999.0)

    nmap_proposal = PlanProposal(
        tool=ToolName.NMAP, profile=ScanProfile.QUICK_RECON, target="127.0.0.1", port=3000, rationale="Port recon."
    )

    with patch.object(nmap_adapter, "validate", return_value=ValidationResult(ScanRunStatus.QUEUED, "OK", MagicMock(), "ticket")), \
         patch.object(nmap_adapter, "start", return_value=RunHandle(run_id_nmap, ScanRunStatus.RUNNING)), \
         patch.object(nmap_adapter, "poll", return_value=PollResult(run_id_nmap, ScanRunStatus.PARSING)), \
         patch.object(nmap_adapter, "parse", return_value=ParseResult(evidence=MagicMock(id="ev-1", file_path=nmap_xml, sha256="abc", tool="nmap"), findings=[])), \
         patch("cipher_lens.ui.assessment_page._session_adapters", return_value={"nmap": nmap_adapter}), \
         patch("streamlit.empty", return_value=MagicMock()):
        out_id, msg = _execute_and_collect_scan(repository, scope, nmap_proposal, ctx)
        assert out_id == run_id_nmap
        assert "completed successfully" in (msg or "")

    # 2. Test NIKTO
    nikto_adapter = NiktoAdapter()
    run_id_nikto = "run-nikto-202"
    nikto_xml = artifact_dir / "nikto" / f"{run_id_nikto}.xml"
    nikto_xml.parent.mkdir(parents=True, exist_ok=True)
    nikto_xml.write_bytes(b"<niktoscan></niktoscan>")
    nikto_adapter._runs[run_id_nikto] = (MagicMock(), nikto_xml, 9999999.0)

    nikto_proposal = PlanProposal(
        tool=ToolName.NIKTO, profile=ScanProfile.WEB_QUICK, target="127.0.0.1", port=3000, rationale="Web recon."
    )

    with patch.object(nikto_adapter, "validate", return_value=ValidationResult(ScanRunStatus.QUEUED, "OK", MagicMock(), "ticket")), \
         patch.object(nikto_adapter, "start", return_value=RunHandle(run_id_nikto, ScanRunStatus.RUNNING)), \
         patch.object(nikto_adapter, "poll", return_value=PollResult(run_id_nikto, ScanRunStatus.PARSING)), \
         patch.object(nikto_adapter, "parse", return_value=ParseResult(evidence=MagicMock(id="ev-2", file_path=nikto_xml, sha256="def", tool="nikto"), findings=[])), \
         patch("cipher_lens.ui.assessment_page._session_adapters", return_value={"nikto": nikto_adapter}), \
         patch("streamlit.empty", return_value=MagicMock()):
        out_id, msg = _execute_and_collect_scan(repository, scope, nikto_proposal, ctx)
        assert out_id == run_id_nikto
        assert "completed successfully" in (msg or "")

    # 3. Test ZAP — specifically with _ZapRun (dataclass, NOT a subscriptable tuple)
    zap_adapter = ZapAdapter()
    run_id_zap = "run-zap-303"
    zap_json = artifact_dir / "zap" / f"{run_id_zap}.json"
    zap_json.parent.mkdir(parents=True, exist_ok=True)
    zap_json.write_text('{"alerts": []}')
    # Note: _ZapRun object is NOT subscriptable (no __getitem__)
    zap_adapter._runs[run_id_zap] = _ZapRun(
        scan_id="1", endpoint="ascan", deadline=9999999.0, target_url="http://127.0.0.1:3000", output_path=zap_json
    )

    zap_proposal = PlanProposal(
        tool=ToolName.ZAP, profile=ScanProfile.ACTIVE_SCAN, target="127.0.0.1", port=3000, rationale="Active scan."
    )

    with patch.object(zap_adapter, "validate", return_value=ValidationResult(ScanRunStatus.QUEUED, "OK", MagicMock(), "ticket")), \
         patch.object(zap_adapter, "start", return_value=RunHandle(run_id_zap, ScanRunStatus.RUNNING)), \
         patch.object(zap_adapter, "poll", return_value=PollResult(run_id_zap, ScanRunStatus.PARSING, progress=100)), \
         patch.object(zap_adapter, "parse", return_value=ParseResult(evidence=MagicMock(id="ev-3", file_path=zap_json, sha256="ghi", tool="zap"), findings=[])), \
         patch("cipher_lens.ui.assessment_page._session_adapters", return_value={"zap": zap_adapter}), \
         patch("streamlit.empty", return_value=MagicMock()):
        # This call previously crashed with TypeError: '_ZapRun' object is not subscriptable
        out_id, msg = _execute_and_collect_scan(repository, scope, zap_proposal, ctx)
        assert out_id == run_id_zap
        assert "completed successfully" in (msg or "")


def test_session_adapters_includes_nessus_and_openvas():
    """Verify that _session_adapters registers NessusAdapter and OpenVASAdapter."""
    from cipher_lens.adapters.nessus import NessusAdapter
    from cipher_lens.adapters.openvas import OpenVASAdapter
    from cipher_lens.ui.assessment_page import _session_adapters

    adapters = _session_adapters()
    assert "nessus" in adapters
    assert "openvas" in adapters
    assert isinstance(adapters["nessus"], NessusAdapter)
    assert isinstance(adapters["openvas"], OpenVASAdapter)



