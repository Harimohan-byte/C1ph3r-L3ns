"""End-to-end integration test: from scope registration to auditable VAPT PDF report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from cipher_lens.adapters.base import EvidenceArtifact, Finding
from cipher_lens.domain.findings import Severity, ValidationStatus
from cipher_lens.domain.models import ActionClass, PlanProposal, ScanProfile, ScopeRegistration, ToolName
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.approvals import (
    ApprovalStatus,
    create_approval_request,
    list_audit_timeline,
    transition_approval,
)
from cipher_lens.services.findings import ingest_and_store_findings
from cipher_lens.services.planning import InMemoryRateLimiter, ProposalContext, gate_proposal
from cipher_lens.services.reporting import build_report_context, generate_vapt_pdf
from cipher_lens.services.scope_registration import register_scope


def test_complete_assessment_to_report_lifecycle(tmp_path: Path):
    db_file = tmp_path / "assessment_lifecycle.db"
    repository = Repository(db_file)

    # ---------------------------------------------------------
    # Step 1: Authorized Scope Registration
    # ---------------------------------------------------------
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="lab.target.internal",
            allowed_ports="80,443,8080",
            excluded_ports="22",
            excluded_endpoints="/admin",
            engagement_note="Authorized university security lab engagement",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    assert scope.canonical_target == "lab.target.internal"

    # ---------------------------------------------------------
    # Step 2: AI Proposal & Policy Gate Decision
    # ---------------------------------------------------------
    proposal = PlanProposal(
        tool=ToolName.NMAP,
        profile=ScanProfile.QUICK_RECON,
        target="lab.target.internal",
        port=80,
        rationale="Initial port discovery on primary web interface",
    )
    prop_context = ProposalContext(scope=scope, request="Initial port discovery")
    rate_limiter = InMemoryRateLimiter()
    gate_outcome = gate_proposal(
        repository,
        prop_context,
        proposal,
        source="local_plan",
        rate_limit_check=rate_limiter,
    )
    assert gate_outcome.status.value == "approved"
    assert gate_outcome.proposal == proposal

    # ---------------------------------------------------------
    # Step 3: Scan Run Execution & Evidence Ingestion
    # ---------------------------------------------------------
    run_id = str(uuid4())
    repository.create_scan_run(
        run_id,
        scope.id,
        "nmap",
        "quick_recon",
        "done",
        rationale=proposal.rationale,
    )

    evidence = EvidenceArtifact(
        id=str(uuid4()),
        file_path=tmp_path / "nmap_output.xml",
        sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        tool="nmap",
        captured_at=datetime.now(timezone.utc),
    )

    # Ingest raw findings with one duplicate signature to verify correlation
    raw_findings = [
        Finding(
            source_tool="nmap",
            affected_asset="http://lab.target.internal:80",
            description="Open HTTP service identified; Apache 2.4.41",
            severity="Info",
            confidence="observed",
        ),
        Finding(
            source_tool="zap",
            affected_asset="lab.target.internal:80/search",
            description="SQL Injection vulnerability discovered in search parameter q.",
            severity="High",
            cvss=8.6,
            cve="2023-4567",
            cwe="CWE-89",
            confidence="observed",
        ),
        # Duplicate with different protocol formatting on same asset & CVE
        Finding(
            source_tool="nikto",
            affected_asset="http://lab.target.internal:80/search/",
            description="Duplicate SQL Injection in search query.",
            severity="High",
            cvss=8.6,
            cve="CVE-2023-4567",
            confidence="observed",
        ),
    ]

    correlated = ingest_and_store_findings(repository, run_id, raw_findings, evidence)

    # Correlation verification: 3 raw findings deduplicated to 2 distinct findings
    assert len(correlated) == 2
    persisted_findings = repository.list_findings(scope_id=scope.id)
    assert len(persisted_findings) == 2

    sqli_finding = next(f for f in persisted_findings if f.cve == "CVE-2023-4567")
    assert sqli_finding.severity == Severity.HIGH
    assert sqli_finding.priority_score > 8.0
    # Provenance preserved across both ZAP and Nikto tools
    tools_observed = {p.source_tool for p in sqli_finding.provenance}
    assert tools_observed == {"zap", "nikto"}

    # ---------------------------------------------------------
    # Step 4: Active Validation Approval Gate (Human in the Loop)
    # ---------------------------------------------------------
    approval_id = create_approval_request(
        repository,
        scope,
        target="lab.target.internal",
        port=80,
        scheme="http",
        action=ActionClass.ACTIVE_VALIDATION,
        requested_by="Analyst Sarah",
        rationale="Active verification of CVE-2023-4567 payload execution",
        finding_id=sqli_finding.id,
    )

    # Analyst explicitly approves via state machine
    decided_approval = transition_approval(
        repository,
        approval_id,
        ApprovalStatus.APPROVED,
        actor="Security Lead Marcus",
        rationale="Evidence substantiated by two scanners; approval granted for lab verification.",
    )
    assert decided_approval.status == ApprovalStatus.APPROVED.value
    assert decided_approval.decision_actor == "Security Lead Marcus"

    # ---------------------------------------------------------
    # Step 5: Immutable Audit Trail Completeness
    # ---------------------------------------------------------
    timeline = list_audit_timeline(repository)
    event_types = {e.event_type for e in timeline}

    assert "scope_registration" in event_types
    assert "proposal_gate" in event_types
    assert "findings_ingested" in event_types
    assert "approval_requested" in event_types
    assert "approval_decision" in event_types

    # ---------------------------------------------------------
    # Step 6: Client-Ready Deterministic PDF Report
    # ---------------------------------------------------------
    report_pdf_path = tmp_path / "CIPHER_LENS_Final_Report.pdf"
    pdf_bytes = generate_vapt_pdf(repository, scope.id, output_path=report_pdf_path)

    assert pdf_bytes.startswith(b"%PDF-")
    assert report_pdf_path.is_file()
    assert report_pdf_path.stat().st_size > 3000

    # Traceability Verification:
    # All reported findings trace back to persisted evidence and audit events
    context = build_report_context(repository, scope.id)
    assert len(context["findings"]) == 2
    assert len(context["runs"]) == 1
    assert len(context["approvals"]) == 1
    assert context["distribution"]["High"] == 1
    assert context["distribution"]["Info"] == 1

    for finding in context["findings"]:
        # Each finding must have at least one valid evidence provenance item
        assert len(finding.provenance) >= 1
        for prov in finding.provenance:
            assert prov.sha256 == evidence.sha256
            assert prov.file_path == str(evidence.file_path)
            assert prov.source_tool in {"nmap", "zap", "nikto"}
