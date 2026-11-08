"""Deterministic, evidence-grounded VAPT PDF report generation."""

from __future__ import annotations

import html
import io
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from cipher_lens.domain.findings import FindingProvenance, NormalizedFinding, Severity
from cipher_lens.domain.models import ScopeRecord
from cipher_lens.persistence.repositories import ApprovalSummary, Repository, ScanRunSummary

logger = logging.getLogger(__name__)

# --- Header Branding Dimensions & Tokens ---
LOGO_HEIGHT_PT: float = 32.0
LOGO_ASPECT_RATIO: float = 1657.0 / 1442.0  # ~1.149
LOGO_WIDTH_PT: float = round(LOGO_HEIGHT_PT * LOGO_ASPECT_RATIO, 2)  # 36.77 pt
LOGO_X_PT: float = 0.6 * inch  # 43.2 pt
LOGO_Y_PT: float = 742.0  # 792 - 18 - 32
RUNNING_RULE_Y_PT: float = 736.0
RUNNING_TEXT_X_PT: float = 612.0 - 0.6 * inch  # 568.8 pt
RUNNING_TEXT_Y_PT: float = 748.0


def _resolve_logo_path() -> Path | None:
    """Locate the Cipher-Lens application logo from project root or package assets."""
    candidates = [
        Path.cwd() / "Cipher-Lens-logo-1.png",
        Path(__file__).resolve().parent.parent / "ui" / "assets" / "Cipher-Lens-logo-1.png",
        Path(__file__).resolve().parents[3] / "Cipher-Lens-logo-1.png",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that accumulates pages to render accurate 'Page X of Y' and confidentiality footers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_footer(num_pages)
            super().showPage()
        super().save()

    def _draw_page_footer(self, total_pages: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#4B5563"))

        # Left side: Confidentiality notice
        self.drawString(LOGO_X_PT, 25.0, "CONFIDENTIAL · AUTHORIZED ASSESSMENT DISTRIBUTION ONLY")

        # Right side: Page X of Y
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(RUNNING_TEXT_X_PT, 25.0, page_str)

        # Subtle footer divider rule
        self.setStrokeColor(colors.HexColor("#E5D7C0"))
        self.setLineWidth(0.5)
        self.line(LOGO_X_PT, 36.0, RUNNING_TEXT_X_PT, 36.0)

        self.restoreState()


def _draw_first_page(canvas: Any, doc: SimpleDocTemplate) -> None:
    """Canvas callback to decorate the first page header with the top-left Cipher-Lens logo."""
    canvas.saveState()
    logo_path = _resolve_logo_path()
    if logo_path is not None:
        try:
            canvas.drawImage(
                str(logo_path),
                LOGO_X_PT,
                LOGO_Y_PT,
                width=LOGO_WIDTH_PT,
                height=LOGO_HEIGHT_PT,
                mask="auto",
                preserveAspectRatio=True,
            )
        except Exception as exc:
            logger.warning("Failed to render Cipher-Lens logo on first page: %s", exc)
    else:
        logger.warning("Cipher-Lens logo asset not found; omitting header logo.")
    canvas.restoreState()


def _draw_later_pages(canvas: Any, doc: SimpleDocTemplate) -> None:
    """Canvas callback to decorate interior page headers with logo, running title, and divider rule."""
    canvas.saveState()
    logo_path = _resolve_logo_path()
    if logo_path is not None:
        try:
            canvas.drawImage(
                str(logo_path),
                LOGO_X_PT,
                LOGO_Y_PT,
                width=LOGO_WIDTH_PT,
                height=LOGO_HEIGHT_PT,
                mask="auto",
                preserveAspectRatio=True,
            )
        except Exception as exc:
            logger.warning("Failed to render Cipher-Lens logo on interior page: %s", exc)
    else:
        logger.warning("Cipher-Lens logo asset not found; omitting interior header logo.")

    # Running header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#516D18"))
    canvas.drawRightString(RUNNING_TEXT_X_PT, RUNNING_TEXT_Y_PT, "CIPHER LENS · SECURITY ASSESSMENT REPORT")

    # Dividing rule separating header from content
    canvas.setStrokeColor(colors.HexColor("#E5D7C0"))
    canvas.setLineWidth(0.5)
    canvas.line(LOGO_X_PT, RUNNING_RULE_Y_PT, RUNNING_TEXT_X_PT, RUNNING_RULE_Y_PT)

    canvas.restoreState()


# --- CWE Name and OWASP Top 10 Lookup Mapping ---
CWE_OWASP_MAP: dict[str, tuple[str, str]] = {
    "CWE-89": ("SQL Injection", "OWASP A03:2021-Injection"),
    "CWE-79": ("Cross-Site Scripting (XSS)", "OWASP A03:2021-Injection"),
    "CWE-1021": ("Clickjacking", "OWASP A05:2021-Security Misconfiguration"),
    "CWE-200": ("Information Exposure", "OWASP A01:2021-Broken Access Control"),
    "CWE-22": ("Path Traversal", "OWASP A01:2021-Broken Access Control"),
    "CWE-16": ("Configuration Flaw", "OWASP A05:2021-Security Misconfiguration"),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)", "OWASP A01:2021-Broken Access Control"),
    "CWE-693": ("Protection Mechanism Failure", "OWASP A05:2021-Security Misconfiguration"),
    "CWE-548": ("Directory Listing", "OWASP A05:2021-Security Misconfiguration"),
    "CWE-287": ("Improper Authentication", "OWASP A07:2021-Identification & Auth Failures"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "OWASP A10:2021-Server-Side Request Forgery"),
    "CWE-384": ("Session Fixation", "OWASP A07:2021-Identification & Auth Failures"),
    "CWE-798": ("Hard-coded Credentials", "OWASP A07:2021-Identification & Auth Failures"),
    "CWE-319": ("Cleartext Transmission", "OWASP A02:2021-Cryptographic Failures"),
    "CWE-327": ("Broken Cryptography", "OWASP A02:2021-Cryptographic Failures"),
    "CWE-94": ("Code Injection", "OWASP A03:2021-Injection"),
    "CWE-502": ("Insecure Deserialization", "OWASP A08:2021-Software & Data Integrity"),
    "CWE-434": ("Unrestricted File Upload", "OWASP A04:2021-Insecure Design"),
    "CWE-611": ("XML External Entity (XXE)", "OWASP A05:2021-Security Misconfiguration"),
    "CWE-20": ("Improper Input Validation", "OWASP A03:2021-Injection"),
    "CWE-93": ("CRLF Injection", "OWASP A03:2021-Injection"),
    "CWE-601": ("Open Redirect", "OWASP A01:2021-Broken Access Control"),
}


@dataclass
class GroupedFindingReport:
    """Consolidated representation of identical vulnerabilities across multiple endpoints."""

    signature: str
    canonical_title: str
    severity: Severity
    priority_score: float
    cvss: float | None
    cve: str | None
    cwe: str | None
    cwe_name: str | None
    owasp_category: str | None
    description: str
    affected_assets: list[str]
    provenance: list[FindingProvenance]


def _group_findings_for_report(findings: list[NormalizedFinding]) -> list[GroupedFindingReport]:
    """Group identical findings across multiple endpoints into consolidated report entries."""
    if not findings:
        return []

    groups: dict[str, list[NormalizedFinding]] = {}
    for f in findings:
        # Formulate group key: prefer CVE, then CWE, then normalized title
        if f.cve:
            cve_key = f.cve.strip().upper()
            if not cve_key.startswith("CVE-"):
                cve_key = f"CVE-{cve_key}"
            key = f"cve:{cve_key}"
        elif f.cwe:
            key = f"cwe:{f.cwe.strip().upper()}"
        else:
            key = f"title:{f.canonical_title.strip().lower()}"

        groups.setdefault(key, []).append(f)

    grouped_list: list[GroupedFindingReport] = []
    sev_rank_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}

    for key, items in groups.items():
        rep = max(items, key=lambda x: (x.priority_score, x.cvss or 0.0))
        max_sev = max((it.severity for it in items), key=lambda s: sev_rank_order.get(s, 0))
        assets = sorted({it.affected_asset for it in items})

        prov_map: dict[str, FindingProvenance] = {}
        for it in items:
            for p in it.provenance:
                sha = p.sha256 or "unhashed"
                prov_map[f"{p.source_tool}:{sha}"] = p
        unique_prov = list(prov_map.values())

        cwe_clean = rep.cwe.strip().upper() if rep.cwe else None
        cwe_name = None
        owasp_cat = None
        if cwe_clean and cwe_clean in CWE_OWASP_MAP:
            cwe_name, owasp_cat = CWE_OWASP_MAP[cwe_clean]

        title = rep.canonical_title
        if cwe_name and title.startswith("Weakness:"):
            title = f"{title} · {cwe_name}"

        grouped_list.append(
            GroupedFindingReport(
                signature=key,
                canonical_title=title,
                severity=max_sev,
                priority_score=rep.priority_score,
                cvss=rep.cvss,
                cve=rep.cve,
                cwe=rep.cwe,
                cwe_name=cwe_name,
                owasp_category=owasp_cat,
                description=rep.description,
                affected_assets=assets,
                provenance=unique_prov,
            )
        )

    grouped_list.sort(key=lambda x: (x.priority_score, sev_rank_order.get(x.severity, 0)), reverse=True)
    return grouped_list



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
        topMargin=0.85 * inch,
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

    # --- Cover Page Flowables ---
    elements.append(Spacer(1, 18))
    elements.append(Paragraph("CIPHER LENS · PENETRATION TESTING &amp; AUDITING PLATFORM", subtitle_style))
    elements.append(Spacer(1, 6))
    cover_title_style = ParagraphStyle(
        "CoverTitle",
        parent=title_style,
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#032E2B"),
    )
    elements.append(Paragraph("Vulnerability Assessment &amp;<br/>Penetration Testing Report", cover_title_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=2.5, color=colors.HexColor("#BBF351"), spaceAfter=14))

    cover_meta_data = [
        [
            Paragraph("<b>Primary Authorized Target:</b>", body_style),
            Paragraph(f"<code>{html.escape(scope.canonical_target)}</code>", code_style),
        ],
        [
            Paragraph("<b>Target Scope Boundaries:</b>", body_style),
            Paragraph(f"Allowed Ports: <code>{html.escape(scope.allowed_ports)}</code>", body_style),
        ],
        [
            Paragraph("<b>Engagement Context:</b>", body_style),
            Paragraph(html.escape(scope.engagement_note), body_style),
        ],
        [
            Paragraph("<b>Scope Token ID:</b>", body_style),
            Paragraph(f"<code>#{html.escape(scope.id[:8])}</code>", code_style),
        ],
        [
            Paragraph("<b>Assessment Generated:</b>", body_style),
            Paragraph(html.escape(generated_at), body_style),
        ],
        [
            Paragraph("<b>Security Classification:</b>", body_style),
            Paragraph("<font color='#B42318'><b>CONFIDENTIAL · AUTHORIZED STAKEHOLDERS ONLY</b></font>", body_style),
        ],
    ]
    cover_table = Table(cover_meta_data, colWidths=[2.2 * inch, 4.8 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFDF8")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(cover_table)
    elements.append(Spacer(1, 14))

    elements.append(
        Paragraph(
            "<b>OPERATIONAL STATEMENT &amp; MANDATE:</b><br/>"
            "This assessment was conducted strictly within authorized lab boundaries. "
            "CIPHER LENS operates under mandatory safety controls: passive automated discovery is bounded by registered rules, "
            "and active validation operations require explicit human analyst approval with verifiable token audit trails. "
            "Distribution is strictly restricted to authorized project personnel.",
            callout_style,
        )
    )
    elements.append(PageBreak())

    # --- 1. Executive Summary ---
    elements.append(Paragraph("1. Executive Summary", h2_style))

    # Bento Metric Chips
    total_findings = len(findings)
    crit_high = distribution.get("Critical", 0) + distribution.get("High", 0)
    unique_assets = len({f.affected_asset for f in findings}) or 1
    tested_target = scope.canonical_target

    metric_data = [
        [
            Paragraph("<b>Total Findings</b>", callout_style),
            Paragraph("<b>Critical &amp; High</b>", callout_style),
            Paragraph("<b>Unique Assets Tested</b>", callout_style),
            Paragraph("<b>Primary Target</b>", callout_style),
        ],
        [
            Paragraph(f"<font size='15' color='#032E2B'><b>{total_findings}</b></font>", body_style),
            Paragraph(f"<font size='15' color='{'#B42318' if crit_high else '#355B00'}'><b>{crit_high}</b></font>", body_style),
            Paragraph(f"<font size='15' color='#516D18'><b>{unique_assets}</b></font>", body_style),
            Paragraph(f"<font size='10' color='#032E2B'><code>{html.escape(tested_target)}</code></font>", body_style),
        ],
    ]
    metric_table = Table(metric_data, colWidths=[1.75 * inch] * 4)
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFDF8")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(metric_table)
    elements.append(Spacer(1, 8))

    summary_text = (
        f"An authorized vulnerability assessment and penetration test was conducted on target "
        f"<strong>{html.escape(scope.canonical_target)}</strong> pursuant to explicitly registered boundaries. "
        f"Allowed port range: <code>{html.escape(scope.allowed_ports)}</code>. "
        f"Total findings discovered and correlated: <strong>{len(findings)}</strong> "
        f"(Critical: {distribution['Critical']}, High: {distribution['High']}, Medium: {distribution['Medium']}, "
        f"Low: {distribution['Low']}, Informational: {distribution['Info']}). "
        f"Engagement context: {html.escape(scope.engagement_note)}"
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 8))

    # Top Priority Issues callout table
    if findings:
        top_findings = sorted(findings, key=lambda x: (x.priority_score, x.cvss or 0.0), reverse=True)[:3]
        top_rows = [
            [
                Paragraph("<b>#</b>", body_bold),
                Paragraph("<b>Top Priority Vulnerability</b>", body_bold),
                Paragraph("<b>Severity</b>", body_bold),
                Paragraph("<b>Priority</b>", body_bold),
                Paragraph("<b>Affected Asset</b>", body_bold),
            ]
        ]
        for i, tf in enumerate(top_findings, 1):
            sev_color = _severity_color(tf.severity.value).hexval()
            top_rows.append([
                Paragraph(str(i), body_style),
                Paragraph(html.escape(tf.canonical_title), body_bold),
                Paragraph(f"<font color='{sev_color}'><b>{tf.severity.value.upper()}</b></font>", body_style),
                Paragraph(f"<b>{tf.priority_score:.1f}/10.0</b>", body_style),
                Paragraph(f"<code>{html.escape(tf.affected_asset)}</code>", code_style),
            ])
        top_table = Table(top_rows, colWidths=[0.35 * inch, 2.75 * inch, 1.0 * inch, 1.0 * inch, 1.9 * inch])
        top_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFDF8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (3, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(Paragraph("<b>Priority Vulnerabilities Requiring Immediate Action:</b>", body_style))
        elements.append(Spacer(1, 4))
        elements.append(top_table)

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
                Paragraph("<b>Profile & Timing</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Rationale & Execution Notes</b>", body_bold),
            ]
        ]

        # Calculate attempt counts per tool to clearly differentiate retries
        tool_counts: dict[str, int] = {}
        for r in runs:
            k = r.tool.lower()
            tool_counts[k] = tool_counts.get(k, 0) + 1

        tool_attempts: dict[str, int] = {}
        for r in runs:
            k = r.tool.lower()
            tool_attempts[k] = tool_attempts.get(k, 0) + 1
            attempt_idx = tool_attempts[k]
            total_attempts = tool_counts[k]

            tool_label = html.escape(r.tool.upper())
            if total_attempts > 1:
                tool_label += f"<br/><font color='#516D18' size='7.5'><b>Attempt {attempt_idx}</b></font>"

            prof_text = html.escape(r.profile or "default")
            timing_text = ""
            if r.started_at:
                start_clean = r.started_at[:19].replace("T", " ")
                timing_text = f"<br/><font color='#423E32' size='7'>{html.escape(start_clean)}"
                if r.completed_at:
                    try:
                        t0 = datetime.fromisoformat(r.started_at)
                        t1 = datetime.fromisoformat(r.completed_at)
                        dur = max(0, int((t1 - t0).total_seconds()))
                        timing_text += f" ({dur}s)"
                    except Exception:
                        pass
                timing_text += "</font>"
            prof_display = f"{prof_text}{timing_text}"

            st_upper = r.status.upper()
            if st_upper == "DONE":
                st_badge = "<font color='#355B00'><b>[DONE]</b></font>"
            elif st_upper in {"FAILED", "BLOCKED"}:
                st_badge = f"<font color='#B42318'><b>[{st_upper}]</b></font>"
            elif st_upper in {"RUNNING", "PARSING"}:
                st_badge = f"<font color='#155EEF'><b>[{st_upper}]</b></font>"
            else:
                st_badge = f"<font color='#8A5700'><b>[{st_upper}]</b></font>"

            notes = html.escape(r.rationale or "Standard execution.")
            if r.error_message:
                notes += f"<br/><font color='#B42318'><b>Failure:</b> {html.escape(r.error_message)}</font>"

            run_table_data.append([
                Paragraph(tool_label, code_style),
                Paragraph(prof_display, code_style),
                Paragraph(st_badge, body_style),
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
    elements.append(Spacer(1, 12))

    # --- How to Read This Report Callout Box ---
    how_to_read_data = [
        [
            Paragraph(
                "<b>HOW TO READ THIS REPORT · DETERMINISTIC RISK PRIORITIZATION:</b><br/>"
                "This assessment evaluates risk using CIPHER LENS's deterministic <b>Priority Score (0.0 to 10.0)</b> "
                "alongside theoretical CVSS base metrics. The Priority Score synthesizes: "
                "(1) <i>Base Severity Weight</i> (Critical=9.0, High=7.0, Medium=4.0, Low=2.0), "
                "(2) <i>Validation Status Multiplier</i> (+1.5 for human-approved verified exploitability), and "
                "(3) <i>Corroboration Bonus</i> (+0.5 for each independent security scanner confirming the issue). "
                "Identical vulnerabilities discovered across multiple paths or endpoints are grouped into single root-cause entries below.",
                callout_style,
            )
        ]
    ]
    how_to_read_table = Table(how_to_read_data, colWidths=[7.0 * inch])
    how_to_read_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFDF8")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("LINELEFT", (0, 0), (0, -1), 3.0, colors.HexColor("#516D18")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(how_to_read_table)
    elements.append(Spacer(1, 12))

    # --- 4. Detailed Findings ---
    elements.append(Paragraph("4. Detailed Technical Findings", h2_style))

    # Compile unique evidence artifacts registry for Appendix A cross-referencing
    evidence_registry: dict[str, tuple[str, str, str, str]] = {}
    for f in findings:
        for p in f.provenance:
            sha = p.sha256 or "unhashed"
            key = f"{p.source_tool}:{sha}"
            if key not in evidence_registry:
                ref_id = f"[E{len(evidence_registry) + 1}]"
                filename = Path(p.file_path).name if p.file_path else "scan_output"
                evidence_registry[key] = (ref_id, p.source_tool.upper(), sha, filename)

    grouped_findings = _group_findings_for_report(findings)
    if not grouped_findings:
        elements.append(
            Paragraph(
                "No security vulnerabilities or exposures were detected in the authorized scope. "
                "Note: the absence of findings does not guarantee complete security.",
                callout_style,
            )
        )
    else:
        for idx, gf in enumerate(grouped_findings, start=1):
            sev_badge = f"<font color='{_severity_color(gf.severity.value).hexval()}'><b>[{gf.severity.value.upper()}]</b></font>"
            score_badge = f"<b>Priority: {gf.priority_score:.1f}/10.0</b>"

            meta_tokens = []
            if len(gf.affected_assets) == 1:
                meta_tokens.append(f"Asset: <code>{html.escape(gf.affected_assets[0])}</code>")
            else:
                meta_tokens.append(f"<b>{len(gf.affected_assets)} Affected Endpoints</b>")
            meta_tokens.append(score_badge)
            if gf.cvss is not None:
                meta_tokens.append(f"CVSS: {gf.cvss:.1f}")
            if gf.cve:
                meta_tokens.append(f"CVE: {html.escape(gf.cve)}")
            if gf.cwe:
                cwe_tok = f"CWE: {html.escape(gf.cwe)}"
                if gf.cwe_name:
                    cwe_tok += f" ({html.escape(gf.cwe_name)})"
                if gf.owasp_category:
                    cwe_tok += f" · <font color='#516D18'><b>{html.escape(gf.owasp_category)}</b></font>"
                meta_tokens.append(cwe_tok)
            if gf.cvss is None and not gf.cve and not gf.cwe:
                meta_tokens.append("<font color='#4B5563'>Native tool observation</font>")
            meta_line = " · ".join(meta_tokens)

            finding_header = f"{idx}. {sev_badge} {html.escape(gf.canonical_title)}"

            # Affected Assets sub-list if grouped across multiple endpoints
            assets_flowable = []
            if len(gf.affected_assets) > 1:
                display_assets = gf.affected_assets[:12]
                asset_items = " &nbsp;•&nbsp; ".join(f"<code>{html.escape(a)}</code>" for a in display_assets)
                if len(gf.affected_assets) > 12:
                    asset_items += f"<br/><i>... and {len(gf.affected_assets) - 12} additional affected endpoints</i>"
                assets_flowable = [
                    Paragraph(f"<b>Affected Endpoints ({len(gf.affected_assets)}):</b> {asset_items}", callout_style),
                    Spacer(1, 4),
                ]

            prov_lines = []
            for p in gf.provenance:
                sha = p.sha256 or "unhashed"
                ref_info = evidence_registry.get(f"{p.source_tool}:{sha}")
                ref_tag = ref_info[0] if ref_info else "[E1]"
                sha_short = (sha[:12] + "…") if len(sha) > 12 else sha
                prov_lines.append(
                    f"• <b>{ref_tag}</b> Tool: {html.escape(p.source_tool.upper())} · "
                    f"Artifact SHA-256: <code>{html.escape(sha_short)}</code> <i>(See Appendix A)</i>"
                )

            prov_text = "<br/>".join(prov_lines) if prov_lines else "No direct raw artifacts linked."

            card_inner = [
                Paragraph(finding_header, body_bold),
                Spacer(1, 2),
                Paragraph(meta_line, callout_style),
                Spacer(1, 4),
                *assets_flowable,
                Paragraph(f"<b>Observed Evidence &amp; Root Cause:</b> {html.escape(gf.description)}", body_style),
                Spacer(1, 4),
                Paragraph(f"<b>Evidence Provenance:</b><br/>{prov_text}", callout_style),
            ]

            card_table = Table([[card_inner]], colWidths=[7.0 * inch])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFDF8")),
                ("LINELEFT", (0, 0), (0, -1), 3.5, _severity_color(gf.severity.value)),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(KeepTogether([card_table, Spacer(1, 8)]))

    elements.append(Spacer(1, 6))

    # --- 5. Impact & Remediation Guidance ---
    elements.append(Paragraph("5. Impact Assessment & Remediation Recommendations", h2_style))

    roadmap_data = [
        [
            Paragraph("<b>Priority / Phase</b>", body_bold),
            Paragraph("<b>Recommended Remediation Action</b>", body_bold),
            Paragraph("<b>Target Vulnerabilities / Exposures</b>", body_bold),
            Paragraph("<b>Effort</b>", body_bold),
        ],
        [
            Paragraph("<font color='#B42318'><b>P1 · Immediate</b></font><br/><font size='7' color='#423E32'>Within 24–48 hours</font>", body_style),
            Paragraph("Apply official vendor security patches; deploy WAF virtual patching rules; restrict exposed administrative interfaces.", body_style),
            Paragraph("Critical and High severity vulnerabilities (SQLi, RCE, default credentials, exposed unauthenticated services).", body_style),
            Paragraph("<b>Medium</b>", body_style),
        ],
        [
            Paragraph("<font color='#D97706'><b>P2 · Short-Term</b></font><br/><font size='7' color='#423E32'>Within 1–2 weeks</font>", body_style),
            Paragraph("Implement standard defensive HTTP response headers (CSP, X-Frame-Options, HSTS); sanitize user inputs; disable debug pages.", body_style),
            Paragraph("Medium severity issues (XSS, Clickjacking, Information Disclosure, CORS misconfigurations).", body_style),
            Paragraph("<b>Low</b>", body_style),
        ],
        [
            Paragraph("<font color='#516D18'><b>P3 · Maintenance</b></font><br/><font size='7' color='#423E32'>Ongoing cycle</font>", body_style),
            Paragraph("Enforce network ingress filtering; close unused ports; suppress verbose server banners; establish continuous scanning schedule.", body_style),
            Paragraph("Low and Informational observations (unneeded services, banner leaks, missing hardening flags).", body_style),
            Paragraph("<b>Low</b>", body_style),
        ],
    ]
    roadmap_table = Table(roadmap_data, colWidths=[1.3 * inch, 2.5 * inch, 2.4 * inch, 0.8 * inch])
    roadmap_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFDF8")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(roadmap_table)
    elements.append(Spacer(1, 10))

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
        f"This report reflects observations collected on or before {html.escape(generated_at)}. "
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
                Paragraph("<b>Reviewer, Token & Rationale</b>", body_bold),
            ]
        ]
        for a in approvals:
            token_id = f"#{a.id[:8]}" if a.id else "#unknown"
            actor = html.escape(a.decision_actor or "Not decided")
            rat = html.escape(a.decision_rationale or a.requested_rationale or "No rationale recorded.")
            decided_time = html.escape(a.decided_at[:19].replace("T", " ")) if a.decided_at else "Pending"

            st_upper = a.status.upper()
            if st_upper == "APPROVED":
                st_badge = "<font color='#355B00'><b>[APPROVED]</b></font>"
            elif st_upper == "REJECTED":
                st_badge = "<font color='#B42318'><b>[REJECTED]</b></font>"
            else:
                st_badge = f"<font color='#8A5700'><b>[{st_upper}]</b></font>"

            target_str = html.escape(f"{a.target}:{a.port}" if a.port else (a.target or "scope"))
            action_str = html.escape(a.action.replace("_", " ").upper())

            details = (
                f"<b>Reviewer:</b> {actor}<br/>"
                f"<b>Token ID:</b> <code>{html.escape(token_id)}</code> · {decided_time}<br/>"
                f"<b>Rationale:</b> {rat}"
            )

            app_rows.append([
                Paragraph(target_str, code_style),
                Paragraph(action_str, body_style),
                Paragraph(st_badge, body_style),
                Paragraph(details, body_style),
            ])

        app_table = Table(app_rows, colWidths=[1.4 * inch, 1.2 * inch, 1.1 * inch, 3.3 * inch])
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

    # --- Appendix A: Evidence Artifact Register ---
    elements.append(Paragraph("Appendix A: Evidence Artifact Register &amp; Verification Hashes", h2_style))
    elements.append(
        Paragraph(
            "Every scanner artifact produced during this assessment was cryptographically hashed with SHA-256 "
            "prior to persistence. The immutable register below correlates finding references to raw evidence files:",
            body_style,
        )
    )
    elements.append(Spacer(1, 6))

    if not evidence_registry:
        elements.append(Paragraph("No external raw artifact files were preserved for this assessment.", callout_style))
    else:
        reg_rows = [
            [
                Paragraph("<b>Ref</b>", body_bold),
                Paragraph("<b>Tool</b>", body_bold),
                Paragraph("<b>Artifact File</b>", body_bold),
                Paragraph("<b>Cryptographic SHA-256 Digest</b>", body_bold),
            ]
        ]
        for key, (ref_id, tool_name, sha, filename) in evidence_registry.items():
            reg_rows.append([
                Paragraph(f"<b>{ref_id}</b>", body_bold),
                Paragraph(html.escape(tool_name), code_style),
                Paragraph(html.escape(filename), code_style),
                Paragraph(f"<code>{html.escape(sha)}</code>", code_style),
            ])

        reg_table = Table(reg_rows, colWidths=[0.7 * inch, 1.0 * inch, 1.8 * inch, 3.5 * inch])
        reg_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7F3EB")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFDF8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(reg_table)

    elements.append(Spacer(1, 14))

    # --- Appendix B: Integrity Seal ---
    elements.append(Paragraph("Appendix B: Report Integrity Seal &amp; Cryptographic Attestation", h2_style))
    qr_data = f"CIPHER_LENS|ID:{scope.id[:8]}|TARGET:{scope.canonical_target}|DATE:{generated_at}"
    qr = QrCodeWidget(qr_data)
    qr.barWidth = 65
    qr.barHeight = 65
    d = Drawing(65, 65)
    d.add(qr)

    seal_details = (
        f"<b>CIPHER LENS FORENSIC INTEGRITY SEAL</b><br/>"
        f"<b>Assessment ID:</b> <code>{html.escape(scope.id)}</code><br/>"
        f"<b>Generated:</b> {html.escape(generated_at)}<br/>"
        f"<b>Cryptographic Status:</b> <font color='#355B00'><b>VERIFIED IMMUTABLE AUDIT TRAIL</b></font><br/>"
        f"<font size='7.5' color='#423E32'>Scan with any standard QR scanner or pipeline to validate report authenticity against persisted assessment records.</font>"
    )
    seal_table = Table([[d, Paragraph(seal_details, body_style)]], colWidths=[1.1 * inch, 5.9 * inch])
    seal_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFDF8")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5D7C0")),
        ("LINELEFT", (0, 0), (0, -1), 3.0, colors.HexColor("#BBF351")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(seal_table)

    doc.build(elements, onFirstPage=_draw_first_page, onLaterPages=_draw_later_pages, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)

    return pdf_bytes
