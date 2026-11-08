"""Searchable audit history and human approval workspace."""

from __future__ import annotations

import html

import streamlit as st

from cipher_lens.config import zap_base_url
from cipher_lens.domain.models import ActionClass
from cipher_lens.persistence.repositories import ApprovalSummary, Repository
from cipher_lens.services.approvals import (
    ApprovalStatus,
    create_approval_request,
    list_audit_timeline,
    transition_approval,
)
from cipher_lens.ui.mono import friendly_validation_message, heading, inline_error, status_badge


def _approval_status_badge(status: str) -> str:
    """Return an accessible styled status badge for approvals."""
    safe_status = status.lower().replace("_", "-")
    return f'<span class="cl-status cl-status-{safe_status}">{html.escape(status.replace("_", " "))}</span>'


def _render_approval_card(approval: ApprovalSummary, repository: Repository) -> None:
    """Render a single approval item with actionable decision controls if pending."""
    asset = approval.target or "Scope-wide"
    if approval.port is not None:
        asset = f"{asset}:{approval.port}"
    if approval.scheme:
        asset = f"{approval.scheme}://{asset}"

    is_pending = approval.status == ApprovalStatus.PENDING.value
    badge = status_badge("awaiting-approval" if is_pending else approval.status)

    st.markdown(
        f'<div class="cl-card"><strong>{html.escape(asset)}</strong> · '
        f'<span class="cl-tech">{html.escape(approval.action.replace("_", " ").upper())}</span> '
        f'{badge}<br>'
        f'<span class="cl-muted">Requested by: {html.escape(approval.requested_by or "Analyst")}</span><br>'
        f'<em>{html.escape(approval.requested_rationale or "Active validation requested.")}</em>'
        '</div>',
        unsafe_allow_html=True,
    )

    if is_pending:
        with st.expander(f"Review and decide: {asset}", expanded=False):
            zap_url = zap_base_url()
            st.markdown(
                f"""
                <div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.85rem;">
                    <span style="color: #BBF351; font-weight: 700; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 0.35rem;">
                        ⚡ Pre-Approval Verification &amp; Site-Tree Warm-Up
                    </span>
                    <ol style="color: #D6DBC8; font-size: 0.82rem; margin: 0; padding-left: 1.2rem; line-height: 1.45;">
                        <li><strong>Confirm ZAP Daemon:</strong> Verify that OWASP ZAP is running and reachable at <code>{html.escape(zap_url)}</code>.</li>
                        <li><strong>Manual Proxy Warm-Up (Recommended):</strong> Before launching an active scan against a Single Page Application (like Juice Shop), proxy-browse the target through ZAP (e.g., register/login, search, and view items) so the active scan attacks real recorded API routes rather than just the static SPA shell.</li>
                    </ol>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.form(f"decision-form-{approval.id}"):
                actor = st.text_input("Reviewer name or identifier", placeholder="Analyst name")
                rationale = st.text_area(
                    "Decision rationale",
                    placeholder="Provide evidence-linked justification for your decision.",
                )
                col1, col2 = st.columns(2)
                with col1:
                    approve_btn = st.form_submit_button("Approve validation", type="primary")
                with col2:
                    reject_btn = st.form_submit_button("Reject validation")

            if approve_btn:
                actor_clean = (actor or "").strip()
                rationale_clean = (rationale or "").strip()
                if len(actor_clean) < 2:
                    inline_error("Reviewer name or identifier is required (minimum 2 characters).")
                elif len(rationale_clean) < 5:
                    inline_error("Decision rationale must provide evidence-linked justification (minimum 5 characters).")
                else:
                    try:
                        transition_approval(
                            repository,
                            approval.id,
                            ApprovalStatus.APPROVED,
                            actor=actor_clean,
                            rationale=rationale_clean,
                        )
                    except ValueError as error:
                        inline_error(friendly_validation_message(error))
                    else:
                        st.success("Approval granted. Active validation may now be executed within 15 minutes.")
                        st.rerun()

            elif reject_btn:
                actor_clean = (actor or "").strip()
                rationale_clean = (rationale or "").strip()
                if len(actor_clean) < 2:
                    inline_error("Reviewer name or identifier is required (minimum 2 characters).")
                elif len(rationale_clean) < 5:
                    inline_error("Decision rationale must provide justification (minimum 5 characters).")
                else:
                    try:
                        transition_approval(
                            repository,
                            approval.id,
                            ApprovalStatus.REJECTED,
                            actor=actor_clean,
                            rationale=rationale_clean,
                        )
                    except ValueError as error:
                        inline_error(friendly_validation_message(error))
                    else:
                        st.info("Validation request rejected.")
                        st.rerun()


def render(repository: Repository) -> None:
    """Render the compliance, approval state machine, and searchable audit trail."""
    heading(
        "Compliance & verification",
        "Audit trail & approvals",
        "Review human approval gates for active validation and search immutable audit logs.",
    )

    scopes = repository.list_scopes()
    if not scopes:
        st.markdown(
            '<div class="cl-card">No authorized scope registered yet. '
            'Register a scope before managing approvals or tracking activity.</div>',
            unsafe_allow_html=True,
        )
        return

    tab_approvals, tab_audit = st.tabs(["Active validation approvals", "Searchable audit trail"])

    with tab_approvals:
        st.subheader("Human approval gateway")
        st.caption(
            "Active validation actions are strictly blocked until an authorized analyst grants an explicit, "
            "time-limited decision with recorded rationale."
        )

        selected_scope = st.selectbox(
            "Authorized scope",
            scopes,
            format_func=lambda s: s.canonical_target,
            key="approval_scope_select",
        )

        with st.expander("Request active validation approval", expanded=False):
            with st.form("request-approval-form", clear_on_submit=True):
                target_val = st.text_input(
                    "Target hostname or IP",
                    value=selected_scope.canonical_target,
                    help="Must match the authorized scope target.",
                )
                port_val = st.number_input("Target port", min_value=1, max_value=65535, value=80)
                scheme_val = st.selectbox("Scheme", ["None", "http", "https"])
                req_by = st.text_input("Requested by", placeholder="Analyst or service identity")
                req_rationale = st.text_area(
                    "Request rationale",
                    placeholder="State the observed finding and why active validation is necessary.",
                )
                req_submit = st.form_submit_button("Submit approval request", type="primary")

            if req_submit:
                scheme = None if scheme_val == "None" else scheme_val
                try:
                    create_approval_request(
                        repository,
                        selected_scope,
                        target=target_val,
                        port=int(port_val),
                        scheme=scheme,
                        action=ActionClass.ACTIVE_VALIDATION,
                        requested_by=req_by,
                        rationale=req_rationale,
                    )
                except ValueError as error:
                    inline_error(friendly_validation_message(error))
                else:
                    st.success("Approval request registered in pending state.")
                    st.rerun()

        st.markdown("### Pending approvals")
        all_approvals = repository.list_approvals(selected_scope.id)
        pending_list = [a for a in all_approvals if a.status == ApprovalStatus.PENDING.value]

        if not pending_list:
            st.markdown(
                '<div class="cl-card">No approval requests are currently awaiting human review.</div>',
                unsafe_allow_html=True,
            )
        else:
            for pending in pending_list:
                _render_approval_card(pending, repository)

        st.markdown("### Approval history")
        status_filter = st.selectbox(
            "Filter history by status",
            ["All", "approved", "rejected", "pending", "expired", "cancelled", "completed"],
            key="history_status_filter",
        )

        history_items = all_approvals
        if status_filter != "All":
            history_items = [a for a in all_approvals if a.status == status_filter]

        if not history_items:
            st.markdown(
                '<div class="cl-card">No approval records match the selected status filter.</div>',
                unsafe_allow_html=True,
            )
        else:
            rows = []
            for item in history_items:
                asset = item.target or "Scope-wide"
                if item.port:
                    asset = f"{asset}:{item.port}"
                rows.append({
                    "Asset": asset,
                    "Action": item.action.replace("_", " "),
                    "Status": item.status,
                    "Reviewer": item.decision_actor or "Not decided",
                    "Rationale": item.decision_rationale or item.requested_rationale or "None",
                    "Decided at": item.decided_at or "Pending",
                    "Expires at": item.expires_at or "N/A",
                })
            st.dataframe(rows, hide_index=True, width="stretch")

    with tab_audit:
        st.subheader("Immutable audit trail")
        st.caption("Every assessment decision, validation gate, scan start, and finding change is permanently logged.")

        col_search, col_type, col_outcome = st.columns([2, 1, 1])
        with col_search:
            search_query = st.text_input("Search events", placeholder="Filter by event type, entity ID, or keyword...")
        with col_type:
            event_types = ["All", "scope_registration", "adapter_start", "adapter_poll", "adapter_parse",
                           "active_validation_approval", "approval_requested", "approval_decision", "findings_ingested", "proposal_gate"]
            selected_type = st.selectbox("Event type", event_types, key="audit_type_filter")
        with col_outcome:
            outcomes = ["All", "approved", "running", "done", "failed", "blocked", "rejected", "correlated", "pending"]
            selected_outcome = st.selectbox("Outcome", outcomes, key="audit_outcome_filter")

        timeline = list_audit_timeline(
            repository,
            query=search_query,
            event_type=selected_type,
            outcome=selected_outcome,
        )

        st.caption(f"Showing {len(timeline)} audit event(s)")

        if not timeline:
            st.markdown(
                '<div class="cl-card">No audit events match the selected search or filter criteria.</div>',
                unsafe_allow_html=True,
            )
        else:
            for event in timeline:
                event_name = event.event_type.replace("_", " ").upper()
                badge = status_badge(event.outcome)
                timestamp_str = event.occurred_at.strftime("%Y-%m-%d %H:%M:%S UTC")

                st.markdown(
                    f'<div class="cl-card">'
                    f'<strong>{html.escape(event_name)}</strong> · {badge} '
                    f'<span class="cl-muted" style="float: right;">{html.escape(timestamp_str)}</span><br>'
                    f'<span class="cl-tech">Entity: {html.escape(event.entity_type)} ({html.escape(event.entity_id or "global")})</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                if event.detail:
                    with st.expander(f"Audit details ({event.event_type})", expanded=False):
                        st.json(event.detail)

