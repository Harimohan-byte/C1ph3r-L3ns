"""Executive VAPT report preview and downloadable PDF generation workspace."""

from __future__ import annotations

import html

import streamlit as st

from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.reporting import build_report_context, generate_vapt_pdf
from cipher_lens.ui.mono import heading, status_badge


def render(repository: Repository) -> None:
    """Render the executive report preview and PDF download interface."""
    heading(
        "Executive reporting",
        "Assessment VAPT report",
        "Generate and download immutable, evidence-backed security assessment reports.",
    )

    scopes = repository.list_scopes()
    if not scopes:
        st.markdown(
            '<div class="cl-card">No authorized scope registered yet. '
            'Register a scope before generating an assessment report.</div>',
            unsafe_allow_html=True,
        )
        return

    selected_scope = st.selectbox(
        "Select assessment scope",
        scopes,
        format_func=lambda s: s.canonical_target,
        key="report_scope_select",
    )

    try:
        context = build_report_context(repository, selected_scope.id)
    except ValueError as error:
        st.error(str(error))
        return

    distribution = context["distribution"]
    findings = context["findings"]
    runs = context["runs"]
    approvals = context["approvals"]

    # PDF Generator
    pdf_bytes = generate_vapt_pdf(repository, selected_scope.id)

    st.download_button(
        label="Download client-ready PDF report",
        data=pdf_bytes,
        file_name=f"CIPHER_LENS_VAPT_Report_{selected_scope.canonical_target}.pdf",
        mime="application/pdf",
        type="primary",
    )

    st.markdown("### Executive report preview")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker" style="color: #B42318;">Critical</span><br>'
            f'<strong style="font-size: 1.6rem; color: #B42318;">{distribution["Critical"]}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker" style="color: #D9381E;">High</span><br>'
            f'<strong style="font-size: 1.6rem; color: #D9381E;">{distribution["High"]}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker" style="color: #D97706;">Medium</span><br>'
            f'<strong style="font-size: 1.6rem; color: #D97706;">{distribution["Medium"]}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker" style="color: #155EEF;">Low</span><br>'
            f'<strong style="font-size: 1.6rem; color: #155EEF;">{distribution["Low"]}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker">Info</span><br>'
            f'<strong style="font-size: 1.6rem; color: #4B5563;">{distribution["Info"]}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )

    tab_summary, tab_findings, tab_activity = st.tabs(
        ["Scope & executive summary", "Prioritized findings", "Tool activity & approvals"]
    )

    with tab_summary:
        st.markdown(
            f'<div class="cl-card">'
            f'<strong>Target:</strong> {html.escape(selected_scope.canonical_target)}<br>'
            f'<strong>Allowed Ports:</strong> {html.escape(selected_scope.allowed_ports)}<br>'
            f'<strong>Engagement Context:</strong> {html.escape(selected_scope.engagement_note)}<br>'
            f'<strong>Attestation:</strong> Authorized lab engagement confirmed.'
            '</div>',
            unsafe_allow_html=True,
        )

    with tab_findings:
        if not findings:
            st.markdown(
                '<div class="cl-card">No findings recorded for this scope yet. '
                'Execute assessment scans or import results to populate findings.</div>',
                unsafe_allow_html=True,
            )
        else:
            for idx, f in enumerate(findings, start=1):
                st.markdown(
                    f'<div class="cl-card">'
                    f'<strong>{idx}. {html.escape(f.canonical_title)}</strong> · '
                    f'<span class="cl-tech">{html.escape(f.affected_asset)}</span> '
                    f'{status_badge(f.severity.value)}<br>'
                    f'<strong>Priority score:</strong> {f.priority_score:.1f}/10.0 · '
                    f'<strong>CVSS:</strong> {f.cvss or "N/A"} · '
                    f'<strong>CVE:</strong> {html.escape(f.cve or "None")}<br>'
                    f'<p style="margin: 0.4rem 0;">{html.escape(f.description)}</p>'
                    f'<span class="cl-muted">Provenance: {len(f.provenance)} supporting evidence artifact(s)</span>'
                    '</div>',
                    unsafe_allow_html=True,
                )

    with tab_activity:
        st.markdown("#### Executed scan runs")
        if not runs:
            st.caption("No scan runs recorded.")
        else:
            for r in runs:
                st.write(f"• **{r.tool.upper()}** ({r.profile or 'default'}) — {r.status.upper()}: {r.rationale or 'Standard run'}")

        st.markdown("#### Human approval records")
        if not approvals:
            st.caption("No approvals recorded.")
        else:
            for a in approvals:
                st.write(f"• **{a.action}** on {a.target}:{a.port or ''} — {a.status.upper()} by {a.decision_actor or 'pending'}")
