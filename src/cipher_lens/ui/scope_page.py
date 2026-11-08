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
