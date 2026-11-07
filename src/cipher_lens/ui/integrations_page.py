"""Honest seven-tool integration matrix workspace."""

from __future__ import annotations

import html

import streamlit as st

from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.integrations import IntegrationStatus, ToolCapability, get_integration_matrix
from cipher_lens.ui.mono import heading, status_badge


def _status_pill(status: IntegrationStatus) -> str:
    """Render a styled status badge appropriate for the integration status."""
    safe_name = status.value.lower().replace("-", "").replace(" ", "")
    if status == IntegrationStatus.LIVE:
        css = "cl-status-done"
    elif status == IntegrationStatus.IMPORT_ONLY:
        css = "cl-status-running"
    elif status == IntegrationStatus.PLANNED:
        css = "cl-status-awaiting-approval"
    else:
        css = "cl-status-failed"
    return f'<span class="cl-status {css}">{html.escape(status.value)}</span>'


def _render_tool_card(tool: ToolCapability) -> None:
    """Render one security tool's capability profile in a structured bento card."""
    live_indicator = "🟢 Operational locally" if tool.is_available and tool.status == IntegrationStatus.LIVE else "🔵 Import-first / External" if tool.status == IntegrationStatus.IMPORT_ONLY else "⚪ Planned / Inactive"

    formats_html = " ".join(
        f'<span class="cl-tech" style="background: #EFE6D5; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem;">{html.escape(fmt)}</span>'
        for fmt in tool.supported_formats
    ) if tool.supported_formats else '<span class="cl-muted">None (Direct API or Planned)</span>'

    st.markdown(
        f'<div class="cl-card">'
        f'<div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 0.35rem;">'
        f'  <div><strong style="font-size: 1.15rem;">{html.escape(tool.name)}</strong> · '
        f'  <span class="cl-kicker">{html.escape(tool.coverage_type)}</span></div>'
        f'  <div>{_status_pill(tool.status)}</div>'
        f'</div>'
        f'<p style="margin: 0.4rem 0 0.6rem 0;">{html.escape(tool.expected_role)}</p>'
        f'<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin: 0.6rem 0; font-size: 0.9rem;">'
        f'  <div><strong>Declared Mode:</strong> <span class="cl-tech">{html.escape(tool.declared_mode)}</span></div>'
        f'  <div><strong>State:</strong> {live_indicator}</div>'
        f'</div>'
        f'<div style="background: #FDF9F0; border: 1px solid #EBE0CE; border-radius: 8px; padding: 0.6rem 0.8rem; margin: 0.6rem 0; font-size: 0.88rem;">'
        f'  <strong>Availability details:</strong> {html.escape(tool.availability_details)}<br>'
        f'  <strong>Limitations & safety:</strong> {html.escape(tool.limitations)}'
        f'</div>'
        f'<div style="margin-top: 0.4rem; font-size: 0.85rem;">'
        f'  <strong>Supported formats:</strong> {formats_html} · '
        f'  <span class="cl-muted">Verified: {html.escape(tool.last_verified)}</span>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render(repository: Repository) -> None:
    """Render the truthful seven-tool integration status matrix."""
    heading(
        "Security tooling",
        "Tool integration matrix",
        "Truthful operational status, capabilities, and import boundaries across the seven core security tools.",
    )

    tools = get_integration_matrix()

    live_count = sum(1 for t in tools if t.status == IntegrationStatus.LIVE)
    import_count = sum(1 for t in tools if t.status == IntegrationStatus.IMPORT_ONLY)
    planned_count = sum(1 for t in tools if t.status == IntegrationStatus.PLANNED)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker">Core Tools</span><br>'
            f'<strong style="font-size: 1.6rem;">{len(tools)}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker">Live Active</span><br>'
            f'<strong style="font-size: 1.6rem; color: #355B00;">{live_count}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker">Import-Only</span><br>'
            f'<strong style="font-size: 1.6rem; color: #155EEF;">{import_count}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            '<div class="cl-card" style="text-align: center;">'
            '<span class="cl-kicker">Planned / Lab</span><br>'
            f'<strong style="font-size: 1.6rem; color: #8A5700;">{planned_count}</strong>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("### Integration directory")
    col_filter_status, col_filter_cov = st.columns(2)
    with col_filter_status:
        filter_status = st.selectbox("Filter by Status", ["All", "Live", "Import-only", "Planned", "Unsupported"])
    with col_filter_cov:
        filter_cov = st.selectbox(
            "Filter by Coverage",
            ["All", "Network", "Web", "Web / API", "Infrastructure", "Exploitation Validation"],
        )

    filtered = tools
    if filter_status != "All":
        filtered = [t for t in filtered if t.status.value == filter_status]
    if filter_cov != "All":
        filtered = [t for t in filtered if t.coverage_type == filter_cov]

    if not filtered:
        st.markdown(
            '<div class="cl-card">No security tools match the selected filters.</div>',
            unsafe_allow_html=True,
        )
    else:
        for tool in filtered:
            _render_tool_card(tool)

    st.info(
        "Truthful integration disclosure: Commercial scanner availability, automated REST APIs, or headless "
        "execution are never overstated. Tools without local automation fall back safely to verified report import."
    )
