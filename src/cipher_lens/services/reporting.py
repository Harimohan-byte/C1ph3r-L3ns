"""Deterministic, evidence-grounded VAPT PDF report generation."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from cipher_lens.domain.findings import NormalizedFinding, Severity
from cipher_lens.domain.models import ScopeRecord
from cipher_lens.persistence.repositories import ApprovalSummary, Repository, ScanRunSummary


def build_report_context(repository: Repository, scope_id: str) -> dict[str, Any]:
    """Compile persisted scope, run, finding, and approval records for the assessment."""
    scopes = repository.list_scopes()
    scope = next((s for s in scopes if s.id == scope_id), None)
    if scope is None:
        raise ValueError(f"Scope with ID '{scope_id}' does not exist.")

    runs = repository.list_scan_runs(scope_id)
    findings = repository.list_findings(scope_id=scope_id)
    approvals = repository.list_approvals(scope_id=scope_id)
    audit_events = [e for e in repository.list_audit_events() if e.detail.get("scope_id") == scope_id or e.entity_id == scope_id]

    # Calculate severity distribution
    distribution = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0,
    }
    for f in findings:
        distribution[f.severity.value] = distribution.get(f.severity.value, 0) + 1

    return {
        "scope": scope,
        "runs": runs,
        "findings": findings,
        "approvals": approvals,
        "audit_events": audit_events,
        "distribution": distribution,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def _severity_color(severity: str) -> colors.Color:
    sev = severity.lower()
    if sev == "critical":
        return colors.HexColor("#B42318")
    if sev == "high":
        return colors.HexColor("#D9381E")
    if sev == "medium":
        return colors.HexColor("#D97706")
    if sev == "low":
        return colors.HexColor("#155EEF")
    return colors.HexColor("#4B5563")


def generate_vapt_pdf(
    repository: Repository,
    scope_id: str,
    output_path: Path | None = None,
) -> bytes:
    """Generate a client-ready, evidence-backed PDF report from persisted records."""
    context = build_report_context(repository, scope_id)
    scope: ScopeRecord = context["scope"]
    runs: list[ScanRunSummary] = context["runs"]
    findings: list[NormalizedFinding] = context["findings"]
    approvals: list[ApprovalSummary] = context["approvals"]
    distribution: dict[str, int] = context["distribution"]
    generated_at: str = context["generated_at"]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom typography matching brand
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#064E56"),
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#516D18"),
        textTransform="uppercase",
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#064E56"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#20231B"),
    )
    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    callout_style = ParagraphStyle(
        "Callout",
        parent=body_style,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#4B5563"),
    )
    code_style = ParagraphStyle(
        "CodeText",
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#161616"),
    )

    elements: list[Any] = []

    # --- Header Banner ---
    elements.append(Paragraph("CIPHER LENS · SECURITY ASSESSMENT REPORT", subtitle_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(f"Vulnerability Assessment & Penetration Test Report", title_style))
    elements.append(Spacer(1, 4))
    elements.append(
        Paragraph(
            f"Authorized Target: <strong>{scope.canonical_target}</strong> · "
            f"Generated: {generated_at}",
            body_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#BBF351"), spaceAfter=14))

    # --- 1. Executive Summary ---
    elements.append(Paragraph("1. Executive Summary", h2_style))
    summary_text = (
        f"An authorized vulnerability assessment and penetration test was conducted on target "
        f"<strong>{scope.canonical_target}</strong> pursuant to explicitly registered boundaries. "
        f"Allowed port range: <code>{scope.allowed_ports}</code>. "
        f"Total findings discovered and correlated: <strong>{len(findings)}</strong> "
        f"(Critical: {distribution['Critical']}, High: {distribution['High']}, Medium: {distribution['Medium']}, "
        f"Low: {distribution['Low']}, Informational: {distribution['Info']}). "
        f"Engagement context: {scope.engagement_note}"
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 10))

    # --- 2. Assessment Methodology & Activity Timeline ---
    elements.append(Paragraph("2. Assessment Methodology & Tool Activity", h2_style))
    method_text = (
        "Assessment operations adhered to an adaptive, evidence-grounded workflow. "
        "Automated tools operated within registered scope rules, and active validation remained blocked "
        "pending explicit analyst review. Tool executions, errors, and imports are recorded below:"
    )
    elements.append(Paragraph(method_text, body_style))
    elements.append(Spacer(1, 8))

    if not runs:
        elements.append(Paragraph("No scan activities were executed for this assessment.", callout_style))
    else:
        run_table_data = [
            [
                Paragraph("<b>Tool</b>", body_bold),
                Paragraph("<b>Profile</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Rationale & Execution Notes</b>", body_bold),
            ]
        ]
        for r in runs:
            status_text = r.status.upper()
            notes = r.rationale or "Standard execution."
            if r.error_message:
                notes += f"<br/><font color='#B42318'><b>Failure:</b> {r.error_message}</font>"
            run_table_data.append([
                Paragraph(r.tool.upper(), code_style),
                Paragraph(r.profile or "default", code_style),
                Paragraph(status_text, body_bold),
                Paragraph(notes, body_style),
            ])

        run_table = Table(run_table_data, colWidths=[1.1 * inch, 1.4 * inch, 1.1 * inch, 3.4 * inch])
        run_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(run_table)

    elements.append(Spacer(1, 12))

    # --- 3. Severity Distribution ---
    elements.append(Paragraph("3. Severity Distribution", h2_style))
    dist_data = [
        [
            Paragraph("<b>Critical</b>", body_bold),
            Paragraph("<b>High</b>", body_bold),
            Paragraph("<b>Medium</b>", body_bold),
            Paragraph("<b>Low</b>", body_bold),
            Paragraph("<b>Info</b>", body_bold),
            Paragraph("<b>Total</b>", body_bold),
        ],
        [
            Paragraph(f"<font color='#B42318'><b>{distribution['Critical']}</b></font>", body_bold),
            Paragraph(f"<font color='#D9381E'><b>{distribution['High']}</b></font>", body_bold),
            Paragraph(f"<font color='#D97706'><b>{distribution['Medium']}</b></font>", body_bold),
            Paragraph(f"<font color='#155EEF'><b>{distribution['Low']}</b></font>", body_bold),
            Paragraph(f"<font color='#4B5563'><b>{distribution['Info']}</b></font>", body_bold),
            Paragraph(f"<b>{len(findings)}</b>", body_bold),
        ],
    ]
    dist_table = Table(dist_data, colWidths=[1.1 * inch] * 5 + [1.5 * inch])
    dist_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(dist_table)
    elements.append(Spacer(1, 14))

    # --- 4. Detailed Findings ---
    elements.append(Paragraph("4. Detailed Technical Findings", h2_style))

    if not findings:
        elements.append(
            Paragraph(
                "No security vulnerabilities or exposures were detected in the authorized scope. "
                "Note: the absence of findings does not guarantee complete security.",
                callout_style,
            )
        )
    else:
        for idx, f in enumerate(findings, start=1):
            sev_badge = f"<font color='{_severity_color(f.severity.value).hexval()}'><b>[{f.severity.value.upper()}]</b></font>"
            score_badge = f"<b>Priority: {f.priority_score:.1f}/10.0</b>"
            cvss_text = f"CVSS: {f.cvss}" if f.cvss is not None else "CVSS: N/A"
            cve_text = f"CVE: {f.cve}" if f.cve else "No CVE assigned"
            cwe_text = f"CWE: {f.cwe}" if f.cwe else "No CWE assigned"

            finding_header = f"{idx}. {sev_badge} {f.canonical_title}"
            meta_line = f"Asset: <code>{f.affected_asset}</code> · {score_badge} · {cvss_text} · {cve_text} · {cwe_text}"

            prov_lines = []
            for p in f.provenance:
                sha_short = (p.sha256[:12] + "…") if p.sha256 else "unhashed"
                prov_lines.append(f"• Tool: {p.source_tool} | Artifact SHA-256: <code>{sha_short}</code>")

            prov_text = "<br/>".join(prov_lines) if prov_lines else "No direct raw artifacts linked."

            card_content = [
                Paragraph(finding_header, body_bold),
                Spacer(1, 2),
                Paragraph(meta_line, callout_style),
                Spacer(1, 4),
                Paragraph(f"<b>Observed Evidence:</b> {f.description}", body_style),
                Spacer(1, 4),
                Paragraph(f"<b>Evidence Provenance:</b><br/>{prov_text}", callout_style),
                Spacer(1, 6),
            ]
            elements.append(KeepTogether(card_content))

    elements.append(Spacer(1, 12))

    # --- 5. Impact & Remediation Guidance ---
    elements.append(Paragraph("5. Impact Assessment & Remediation Recommendations", h2_style))
    remediation_items = []
    if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings):
        remediation_items.append(
            "<b>High-Priority Vulnerabilities:</b> Remediate detected high and critical issues immediately. "
            "Isolate affected services, apply official vendor security patches, or restrict network ingress."
        )
    if any(f.cwe and "CWE-79" in f.cwe for f in findings):
        remediation_items.append(
            "<b>Cross-Site Scripting (XSS):</b> Implement context-aware output encoding and strict Content Security Policy (CSP) headers."
        )
    if any(f.cwe and "CWE-89" in f.cwe for f in findings):
        remediation_items.append(
            "<b>SQL Injection:</b> Migrate all dynamic query construction to parameterized SQL queries / prepared statements."
        )
    remediation_items.append(
        "<b>General Hardening:</b> Enforce least-privilege service configurations, remove default administrative interfaces, "
        "and disable unused network ports and verbose debug headers."
    )

    for item in remediation_items:
        elements.append(Paragraph(f"• {item}", body_style))
        elements.append(Spacer(1, 4))

    elements.append(Spacer(1, 12))

    # --- 6. Assessment Limitations & Human Approvals ---
    elements.append(Paragraph("6. Assessment Limitations & Recorded Approvals", h2_style))
    limits_intro = (
        f"This report reflects observations collected on or before {generated_at}. "
        "Only explicitly registered ports and assets were tested. "
        "Human review decisions recorded for active validation on this scope include:"
    )
    elements.append(Paragraph(limits_intro, body_style))
    elements.append(Spacer(1, 6))

    if not approvals:
        elements.append(Paragraph("No active validation approval requests were recorded for this scope.", callout_style))
    else:
        app_rows = [
            [
                Paragraph("<b>Target</b>", body_bold),
                Paragraph("<b>Action</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Reviewer & Rationale</b>", body_bold),
            ]
        ]
        for a in approvals:
            actor = a.decision_actor or "Not decided"
            rat = a.decision_rationale or a.requested_rationale or "None"
            app_rows.append([
                Paragraph(f"{a.target}:{a.port or ''}", code_style),
                Paragraph(a.action, body_style),
                Paragraph(a.status.upper(), body_bold),
                Paragraph(f"{actor}: {rat}", body_style),
            ])

        app_table = Table(app_rows, colWidths=[1.5 * inch, 1.2 * inch, 1.1 * inch, 3.2 * inch])
        app_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(app_table)

    elements.append(Spacer(1, 14))
    elements.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#E5D7C0"), spaceAfter=10))
    elements.append(
        Paragraph(
            "CONFIDENTIALITY NOTICE: This security assessment report contains sensitive vulnerability and configuration details. "
            "Distribution must be restricted strictly to authorized stakeholders.",
            callout_style,
        )
    )

    doc.build(elements)
    pdf_bytes = buffer.getvalue()

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)

    return pdf_bytes
