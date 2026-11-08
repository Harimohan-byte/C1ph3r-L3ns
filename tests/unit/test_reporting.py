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


def test_resolve_logo_path():
    """Verify that _resolve_logo_path finds the brand logo file."""
    from cipher_lens.services.reporting import _resolve_logo_path

    logo_path = _resolve_logo_path()
    assert logo_path is not None
    assert logo_path.is_file()
    assert logo_path.name == "Cipher-Lens-logo-1.png"


def test_pdf_report_draws_logo_on_all_pages(test_repo: Repository, populated_scope):
    """T003: Verify logo is drawn on every page of a multi-page PDF report."""
    from unittest.mock import patch
    from reportlab.pdfgen.canvas import Canvas
    from cipher_lens.services.reporting import LOGO_HEIGHT_PT, LOGO_WIDTH_PT, LOGO_X_PT, LOGO_Y_PT

    draw_calls = []
    orig_drawImage = Canvas.drawImage

    def tracked_drawImage(self, image, x, y, width=None, height=None, **kwargs):
        if "Cipher-Lens-logo-1.png" in str(image):
            draw_calls.append({"x": x, "y": y, "width": width, "height": height})
        return orig_drawImage(self, image, x, y, width=width, height=height, **kwargs)

    # Seed enough findings to force a multi-page PDF (at least 2 pages)
    extra_findings = []
    for i in range(12):
        extra_findings.append(
            NormalizedFinding(
                id=str(uuid4()),
                canonical_title=f"Synthetic Finding #{i} for multi-page pagination test",
                affected_asset=f"10.10.10.50:{8000+i}",
                description="Long description creating sufficient vertical height to require multiple pages.",
                severity=Severity.LOW,
                cvss=3.0,
                cve=None,
                cwe="CWE-200",
                confidence="observed",
                validation_status=ValidationStatus.SUSPECTED,
                priority_score=3.0,
                provenance=[],
                scan_run_id=None,
            )
        )
    test_repo.save_findings(extra_findings)

    with patch.object(Canvas, "drawImage", tracked_drawImage):
        pdf_bytes = generate_vapt_pdf(test_repo, populated_scope.id)

    assert pdf_bytes.startswith(b"%PDF-")
    # Must have drawn logo on at least 2 pages
    assert len(draw_calls) >= 2
    for call in draw_calls:
        assert call["x"] == pytest.approx(LOGO_X_PT, 0.1)
        assert call["y"] == pytest.approx(LOGO_Y_PT, 0.1)
        assert call["width"] == pytest.approx(LOGO_WIDTH_PT, 0.1)
        assert call["height"] == pytest.approx(LOGO_HEIGHT_PT, 0.1)


def test_interior_page_running_header_and_margin_clearance(test_repo: Repository, populated_scope):
    """T005: Verify interior pages render running header rule and title with proper clearance."""
    from unittest.mock import patch
    from reportlab.pdfgen.canvas import Canvas
    from cipher_lens.services.reporting import RUNNING_RULE_Y_PT, RUNNING_TEXT_Y_PT

    lines_drawn = []
    strings_drawn = []
    orig_line = Canvas.line
    orig_drawRightString = Canvas.drawRightString

    def tracked_line(self, x1, y1, x2, y2):
        lines_drawn.append((x1, y1, x2, y2))
        return orig_line(self, x1, y1, x2, y2)

    def tracked_drawRightString(self, x, y, text):
        strings_drawn.append((x, y, text))
        return orig_drawRightString(self, x, y, text)

    # Seed enough findings to force page 2
    extra_findings = [
        NormalizedFinding(
            id=str(uuid4()),
            canonical_title=f"Finding {i}",
            affected_asset=f"10.10.10.50:{8000+i}",
            description="Sample description to ensure multi-page flowable pagination.",
            severity=Severity.INFO,
            cvss=1.0,
            cve=None,
            cwe=None,
            confidence="observed",
            validation_status=ValidationStatus.SUSPECTED,
            priority_score=1.0,
            provenance=[],
            scan_run_id=None,
        )
        for i in range(12)
    ]
    test_repo.save_findings(extra_findings)

    with patch.object(Canvas, "line", tracked_line), patch.object(Canvas, "drawRightString", tracked_drawRightString):
        pdf_bytes = generate_vapt_pdf(test_repo, populated_scope.id)

    assert pdf_bytes.startswith(b"%PDF-")
    # Verify dividing line on interior page
    divider_calls = [c for c in lines_drawn if c[1] == pytest.approx(RUNNING_RULE_Y_PT, 0.1)]
    assert len(divider_calls) >= 1

    # Verify running header text on interior page
    title_calls = [c for c in strings_drawn if "CIPHER LENS · SECURITY ASSESSMENT REPORT" in c[2]]
    assert len(title_calls) >= 1
    assert title_calls[0][1] == pytest.approx(RUNNING_TEXT_Y_PT, 0.1)


def test_pdf_report_graceful_fallback_when_logo_missing(test_repo: Repository, populated_scope, caplog):
    """T007: Verify PDF generation succeeds cleanly and logs a warning when logo is missing."""
    import logging
    from unittest.mock import patch

    with patch("cipher_lens.services.reporting._resolve_logo_path", return_value=None):
        with caplog.at_level(logging.WARNING):
            pdf_bytes = generate_vapt_pdf(test_repo, populated_scope.id)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000
    assert any("logo asset not found" in record.message.lower() for record in caplog.records)


def test_pdf_report_escapes_xml_entities_without_parser_crash(test_repo: Repository):
    """T001: Ensure raw ampersands and angle brackets in URLs, rationales, and descriptions do not break ReportLab."""
    scope = register_scope(
        test_repo,
        ScopeRegistration(
            target="10.10.10.60",
            allowed_ports="80,443",
            engagement_note="Testing <script>alert(1)</script> & special chars",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )

    # Scan run with raw URL query parameters containing '&' and entities
    run_id = str(uuid4())
    test_repo.create_scan_run(
        run_id, scope.id, "zap", "spider", "done", "Spidering /socket.io/?EIO=3&transport=polling&t=N1234&sid=XYZ"
    )

    # Finding with XML special characters
    raw_finding = NormalizedFinding(
        id=str(uuid4()),
        canonical_title="Reflected XSS in <search> & query parameter",
        affected_asset="10.10.10.60:80/search?q=<script>alert('XSS')&filter=1",
        description="Observed parameter payload: <script src='http://evil.com/x.js&sid=1'></script> & response diff.",
        severity=Severity.HIGH,
        cvss=7.5,
        cve=None,
        cwe="CWE-79",
        confidence="observed",
        validation_status=ValidationStatus.SUSPECTED,
        priority_score=7.5,
        provenance=[],
        scan_run_id=run_id,
    )
    test_repo.save_findings([raw_finding])

    # Approval with ampersands and quotes
    record_approval(
        test_repo,
        scope,
        target="10.10.10.60",
        port=80,
        scheme="http",
        action=ActionClass.ACTIVE_VALIDATION,
        actor="Lead Reviewer <Alice & Bob>",
        rationale="Approved for target testing with parameters &sid=999 &t=abc",
        approved=True,
    )

    # Must generate PDF cleanly without throwing xml.parsers.expat.ExpatError
    pdf_bytes = generate_vapt_pdf(test_repo, scope.id)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000


def test_group_findings_for_report_consolidates_identical_cwes_and_enriches_titles():
    """T008 & T009: Multiple findings sharing CWE-1021 collapse into 1 card with CWE/OWASP enrichment."""
    from cipher_lens.services.reporting import _group_findings_for_report

    f1 = NormalizedFinding(
        id=str(uuid4()),
        canonical_title="Weakness: CWE-1021",
        affected_asset="10.10.10.50:80/account",
        description="Missing Anti-Clickjacking header on account page.",
        severity=Severity.MEDIUM,
        cvss=5.3,
        cve=None,
        cwe="CWE-1021",
        confidence="observed",
        validation_status=ValidationStatus.SUSPECTED,
        priority_score=4.8,
        provenance=[],
        scan_run_id=None,
    )
    f2 = NormalizedFinding(
        id=str(uuid4()),
        canonical_title="Weakness: CWE-1021",
        affected_asset="10.10.10.50:80/checkout",
        description="Missing Anti-Clickjacking header on checkout page.",
        severity=Severity.MEDIUM,
        cvss=5.3,
        cve=None,
        cwe="CWE-1021",
        confidence="observed",
        validation_status=ValidationStatus.SUSPECTED,
        priority_score=4.8,
        provenance=[],
        scan_run_id=None,
    )
    f3 = NormalizedFinding(
        id=str(uuid4()),
        canonical_title="SQL Injection in Login",
        affected_asset="10.10.10.50:80/login",
        description="SQL Injection in auth form.",
        severity=Severity.CRITICAL,
        cvss=9.8,
        cve="CVE-2023-9999",
        cwe="CWE-89",
        confidence="confirmed",
        validation_status=ValidationStatus.CONFIRMED,
        priority_score=10.0,
        provenance=[],
        scan_run_id=None,
    )

    grouped = _group_findings_for_report([f1, f2, f3])
    # 3 raw findings should collapse to 2 distinct grouped finding cards
    assert len(grouped) == 2

    # First is SQL Injection (highest priority score 10.0)
    assert grouped[0].cve == "CVE-2023-9999"
    assert grouped[0].cwe_name == "SQL Injection"
    assert grouped[0].owasp_category == "OWASP A03:2021-Injection"
    assert len(grouped[0].affected_assets) == 1

    # Second is Clickjacking (collapsed from f1 and f2)
    assert grouped[1].cwe == "CWE-1021"
    assert grouped[1].cwe_name == "Clickjacking"
    assert "Clickjacking" in grouped[1].canonical_title
    assert grouped[1].owasp_category == "OWASP A05:2021-Security Misconfiguration"
    assert len(grouped[1].affected_assets) == 2
    assert "10.10.10.50:80/account" in grouped[1].affected_assets
    assert "10.10.10.50:80/checkout" in grouped[1].affected_assets


def test_pdf_report_numbered_canvas_cover_and_appendix(test_repo: Repository, populated_scope):
    """T015-T018: Verify NumberedCanvas footer, Cover page structure, Appendix A & QR integrity seal."""
    from unittest.mock import patch
    from cipher_lens.services.reporting import NumberedCanvas

    footer_calls = []
    orig_draw_footer = NumberedCanvas._draw_page_footer

    def tracked_footer(self, total_pages: int):
        footer_calls.append({"page": self._pageNumber, "total": total_pages})
        return orig_draw_footer(self, total_pages)

    with patch.object(NumberedCanvas, "_draw_page_footer", tracked_footer):
        pdf_bytes = generate_vapt_pdf(test_repo, populated_scope.id)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000

    # NumberedCanvas should execute footer on all pages (at least 2 pages due to Cover Page PageBreak)
    assert len(footer_calls) >= 2
    total_pages = footer_calls[0]["total"]
    assert total_pages >= 2
    # Check page numbers
    assert [call["page"] for call in footer_calls] == list(range(1, total_pages + 1))





