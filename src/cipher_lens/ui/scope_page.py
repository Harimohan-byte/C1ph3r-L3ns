"""Authorized-scope registration workspace."""

from __future__ import annotations

import html
import time

import streamlit as st
from pydantic import ValidationError as PydanticValidationError

from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.domain.validation import ValidationError
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.scope_registration import register_scope
from cipher_lens.ui.mono import friendly_validation_message, heading, inline_error


def registration_summary(target: str, actions: set[ActionClass]) -> str:
    """Produce a client-readable success summary from the persisted scope decision."""
    labels = {
        ActionClass.RECON: "Reconnaissance",
        ActionClass.ACTIVE_VALIDATION: "Active validation",
    }
    return f"{target} · {', '.join(labels[action] for action in sorted(actions, key=str))}"


def render(repository: Repository) -> None:
    heading(
        "Assessment control",
        "Register authorized scope",
        "Create a persistent boundary before any assessment activity is proposed or performed.",
    )
    st.info("Only organizer-provided or explicitly authorized lab targets may be registered.")

    pending = st.session_state.get("scope_registration_success")
    if pending:
        st.markdown(
            f'<div class="cl-card cl-success-card"><strong>Authorized scope saved</strong><br>{html.escape(pending)}</div>',
            unsafe_allow_html=True,
        )
        st.caption("Opening assessment status…")
        time.sleep(1.75)
        st.session_state.pending_workspace = "Assessment status"
        del st.session_state["scope_registration_success"]
        st.rerun()

    with st.form("scope-registration", clear_on_submit=True):
        target = st.text_input("Target IP or hostname", help="One IPv4 address or hostname. URLs are not accepted.")
        allowed_ports = st.text_input("Allowed ports", placeholder="80,443,8000-8010")
        excluded_ports = st.text_input("Excluded ports", placeholder="22,3306")
        excluded_endpoints = st.text_area("Excluded endpoints", placeholder="/admin\n/internal")
        engagement_note = st.text_area("Engagement note", help="State the purpose and authorization context.")
        allow_active = st.checkbox("Allow active validation requests", value=False)
        attested = st.checkbox("I confirm this is an organizer-provided or explicitly authorized lab target.")
        submitted = st.form_submit_button("Save authorized scope", type="primary")

    if submitted:
        actions = {ActionClass.RECON}
        if allow_active:
            actions.add(ActionClass.ACTIVE_VALIDATION)
        try:
            scope = register_scope(
                repository,
                ScopeRegistration(
                    target=target,
                    allowed_ports=allowed_ports,
                    excluded_ports=excluded_ports,
                    excluded_endpoints=excluded_endpoints,
                    engagement_note=engagement_note,
                    authorized_lab_attested=attested,
                    allowed_actions=actions,
                ),
            )
        except PydanticValidationError as error:
            inline_error(friendly_validation_message(error, {
                "target": "Target IP or hostname",
                "allowed_ports": "Allowed ports",
                "engagement_note": "Engagement note",
            }))
        except (ValidationError, ValueError) as error:
            inline_error(friendly_validation_message(error))
        else:
            st.session_state.scope_registration_success = registration_summary(
                scope.canonical_target, scope.allowed_actions
            )
            st.rerun()

    st.subheader("Saved scopes")
    scopes = repository.list_scopes()
    if not scopes:
        st.markdown('<div class="cl-card">No scope registered yet. Save an authorized lab boundary to begin.</div>', unsafe_allow_html=True)
        return

    for scope in scopes:
        st.markdown(
            f"<div class=\"cl-card\"><strong>{html.escape(scope.canonical_target)}</strong><br>"
            f"Ports: {html.escape(scope.allowed_ports)} · Actions: {html.escape(', '.join(sorted(a.value for a in scope.allowed_actions)))}<br>"
            f"<span class=\"cl-muted\">{html.escape(scope.engagement_note)}</span></div>",
            unsafe_allow_html=True,
        )

    with st.expander("🗑️ Delete a registered scope", expanded=True if len(scopes) == 1 else False):
        st.caption("Permanently remove a single scope and its associated scan runs, findings, and evidence.")
        col_scope_sel, col_del_btn = st.columns([3, 1])
        with col_scope_sel:
            scope_to_delete = st.selectbox(
                "Select scope to remove",
                scopes,
                format_func=lambda s: f"{s.canonical_target} (Ports: {s.allowed_ports})",
                key="scope_delete_selectbox",
                label_visibility="collapsed",
            )
        with col_del_btn:
            if st.button("🗑 Delete Scope", key="delete_single_scope_btn", type="secondary"):
                if scope_to_delete:
                    try:
                        from cipher_lens.config import data_directory
                        import shutil
                        art_path = data_directory() / "artifacts" / scope_to_delete.id
                        if art_path.exists():
                            shutil.rmtree(art_path, ignore_errors=True)
                    except Exception:
                        pass

                    repository.delete_scope(scope_to_delete.id)
                    if st.session_state.get("last_proposal_scope_id") == scope_to_delete.id:
                        st.session_state.pop("last_proposal", None)
                        st.session_state.pop("last_proposal_scope_id", None)
                        st.session_state.pop("last_proposal_executed", None)
                        st.session_state.pop("last_scan_msg", None)
                    st.success(f"Scope '{scope_to_delete.canonical_target}' and all its associated data deleted.")
                    time.sleep(0.5)
                    st.rerun()

    with st.expander("Reset lab database (start fresh)", expanded=False):
        st.caption("Remove all registered scopes, scan runs, findings, and approvals to begin a clean demonstration.")
        if st.button("Reset all lab data", type="secondary", key="reset_lab_data_btn"):
            repository.reset_database()
            for key in [
                "last_proposal",
                "last_proposal_scope_id",
                "last_run_id",
                "saved_assessment_objective",
                "last_proposal_executed",
                "last_scan_msg",
                "rate_limiter",
                "_adapters",
            ]:
                st.session_state.pop(key, None)
            st.success("Lab database reset. All scopes and runs cleared.")
            time.sleep(0.5)
            st.rerun()
