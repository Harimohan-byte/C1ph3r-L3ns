"""Read-only live status workspace for persisted assessment activity."""

from __future__ import annotations

import streamlit as st

from cipher_lens.persistence.repositories import ApprovalSummary, Repository, ScanRunSummary
from cipher_lens.ui.mono import heading, status_badge


def recovery_guidance(run: ScanRunSummary) -> str:
    """Translate stored adapter failures into an analyst-facing next step without changing state."""
    if run.status == "awaiting_approval":
        return "This activity is waiting for a recorded analyst decision before it can continue."
    if run.status == "blocked":
        return "Review the registered scope and request details, then submit a new permitted request."
    if run.status == "failed":
        if run.error_message:
            return f"Review the recorded error, correct the local tool or connection issue, then submit a new request."
        return "Review the recorded failure and submit a new request when the issue is resolved."
    return "No recovery action is required."


def _run_card(run: ScanRunSummary) -> None:
    st.markdown(status_badge(run.status), unsafe_allow_html=True)
    st.markdown(f"**{run.tool.upper()}** · {run.target}:{run.profile or 'default'}")
    st.caption(f"Started: {run.started_at or 'not recorded'} · Completed: {run.completed_at or 'not completed'}")
    st.write(run.rationale or "No rationale was persisted for this activity.")
    if run.anticipated_next_steps:
        with st.expander("Possible next steps", expanded=False):
            for step in run.anticipated_next_steps:
                st.write(f"{step['tool']} · {step['profile']}: {step['rationale']}")
    if run.error_message:
        st.error(run.error_message)
    if run.status in {"failed", "blocked", "awaiting_approval"}:
        st.info(recovery_guidance(run))


def _approval_row(approval: ApprovalSummary) -> dict[str, str]:
    asset = approval.target or "Scope-wide"
    if approval.port is not None:
        asset = f"{asset}:{approval.port}"
    return {
        "Asset": asset,
        "Action": approval.action.replace("_", " "),
        "Status": approval.status,
        "Actor": approval.decision_actor or "Not recorded",
        "Decided": approval.decided_at or "Not recorded",
        "Expires": approval.expires_at or "Not applicable",
    }


def render(repository: Repository) -> None:
    """Render statuses only. This page deliberately has no adapter or approval mutation calls."""
    heading(
        "Assessment workspace",
        "Live activity status",
        "Review persisted activity, decisions, and recovery guidance. Actions are managed in their dedicated workflows.",
    )
    scopes = repository.list_scopes()
    if not scopes:
        st.markdown('<div class="cl-card">No authorized scope is available yet. Register a scope before reviewing activity.</div>', unsafe_allow_html=True)
        return
    selected = st.selectbox("Authorized scope", scopes, format_func=lambda scope: scope.canonical_target)
    runs = repository.list_scan_runs(selected.id)
    approvals = repository.list_approvals(selected.id)

    st.subheader("Activity timeline")
    if not runs:
        st.markdown('<div class="cl-card">No activity has been recorded for this scope yet.</div>', unsafe_allow_html=True)
    else:
        for run in runs:
            with st.container(border=True):
                _run_card(run)

    st.subheader("Approval status")
    if not approvals:
        st.markdown('<div class="cl-card">No approval decisions have been recorded for this scope.</div>', unsafe_allow_html=True)
        return
    st.dataframe([_approval_row(approval) for approval in approvals], hide_index=True, use_container_width=True)
