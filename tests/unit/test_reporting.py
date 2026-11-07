"""Unit tests for deterministic VAPT PDF report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from cipher_lens.domain.findings import FindingProvenance, NormalizedFinding, Severity, ValidationStatus
from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.approvals import record_approval
from cipher_lens.services.reporting import build_report_context, generate_vapt_pdf
from cipher_lens.services.scope_registration import register_scope


@pytest.fixture
def test_repo(tmp_path: Path) -> Repository:
    db_file = tmp_path / "test_report.db"
    return Repository(db_file)


@pytest.fixture
def populated_scope(test_repo: Repository):
    scope = register_scope(
        test_repo,
        ScopeRegistration(
            target="10.10.10.50",
            allowed_ports="80,443,8080",
            engagement_note="Pre-production authorized penetration test",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )

    # 1. Add scan runs (one successful, one failed)
    run_1 = str(uuid4())
    test_repo.create_scan_run(
        run_1, scope.id, "nmap", "quick_recon", "done", "Host discovery and port reconnaissance"
    )

    run_2 = str(uuid4())
    test_repo.create_scan_run(
        run_2, scope.id, "nikto", "quick_recon", "failed", "Web server scan",
    )
    test_repo.update_scan_run(run_2, "failed", "Connection timed out on port 8080.")

    # 2. Add normalized findings with evidence provenance
    findings = [
        NormalizedFinding(
            id=str(uuid4()),
            canonical_title="SQL Injection in Authentication Form",
            affected_asset="10.10.10.50:80/login",
            description="Time-based blind SQL injection observed on parameter 'username'.",
            severity=Severity.CRITICAL,
            cvss=9.8,
            cve="CVE-2023-9999",
            cwe="CWE-89",
            confidence="confirmed",
            validation_status=ValidationStatus.CONFIRMED,
            priority_score=10.0,
            provenance=[
                FindingProvenance(
                    source_tool="zap",
                    scan_run_id=run_1,
                    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    file_path="/var/evidence/zap_scan.json",
                )
            ],
            scan_run_id=run_1,
        ),
        NormalizedFinding(
            id=str(uuid4()),
            canonical_title="Outdated Web Server Version",
            affected_asset="10.10.10.50:80",
            description="Apache 2.4.29 observed; exposes known vulnerabilities.",
            severity=Severity.MEDIUM,
            cvss=5.3,
            cve=None,
            cwe="CWE-200",
            confidence="observed",
            validation_status=ValidationStatus.SUSPECTED,
            priority_score=4.8,
            provenance=[
                FindingProvenance(
                    source_tool="nmap",
                    scan_run_id=run_1,
                    sha256="d41d8cd98f00b204e9800998ecf8427e",
                    file_path="/var/evidence/nmap_scan.xml",
                )
            ],
            scan_run_id=run_1,
        ),
    ]
    test_repo.save_findings(findings)

    # 3. Add recorded approval
    record_approval(
        test_repo,
        scope,
        target="10.10.10.50",
        port=80,
        scheme="http",
        action=ActionClass.ACTIVE_VALIDATION,
        actor="Security Lead Dave",
        rationale="Approved verification of CVE-2023-9999",
        approved=True,
    )

    return scope


def test_generate_pdf_with_seeded_data(test_repo: Repository, populated_scope, tmp_path: Path):
    out_pdf = tmp_path / "report.pdf"
    pdf_bytes = generate_vapt_pdf(test_repo, populated_scope.id, output_path=out_pdf)

    # Valid PDF magic bytes
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000

    # File persisted
    assert out_pdf.is_file()
    assert out_pdf.stat().st_size == len(pdf_bytes)


def test_generate_pdf_no_data_empty_scope(test_repo: Repository):
    empty_scope = register_scope(
        test_repo,
        ScopeRegistration(
            target="192.168.1.1",
            allowed_ports="443",
            engagement_note="Empty scope test",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON},
        ),
    )

    pdf_bytes = generate_vapt_pdf(test_repo, empty_scope.id)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_generate_pdf_invalid_scope_raises(test_repo: Repository):
    with pytest.raises(ValueError, match="does not exist"):
        generate_vapt_pdf(test_repo, "nonexistent-scope-id-12345")


def test_report_context_severity_distribution(test_repo: Repository, populated_scope):
    context = build_report_context(test_repo, populated_scope.id)
    dist = context["distribution"]

    assert dist["Critical"] == 1
    assert dist["Medium"] == 1
    assert dist["High"] == 0
    assert dist["Low"] == 0
    assert dist["Info"] == 0
    assert len(context["findings"]) == 2
    assert len(context["runs"]) == 2
    assert len(context["approvals"]) == 1

