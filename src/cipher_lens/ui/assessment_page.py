"""Assessment workspace: AI-driven adaptive planning, scan execution, and live status."""

from __future__ import annotations

import html
import time
from pathlib import Path

import streamlit as st

from cipher_lens.adapters.base import (
    AdapterContext,
    AdapterRequest,
    ScanRunStatus,
)
from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.config import data_directory
from cipher_lens.domain.models import ActionClass, ProposalStatus
from cipher_lens.persistence.repositories import ApprovalSummary, Repository, ScanRunSummary
from cipher_lens.services.findings import ingest_and_store_findings
from cipher_lens.services.planning import InMemoryRateLimiter, ProposalContext, propose_and_gate
from cipher_lens.ui.mono import friendly_validation_message, heading, inline_error, status_badge


# ---------------------------------------------------------------------------
# Shared in-process rate limiter — lives for the Streamlit session
# ---------------------------------------------------------------------------
def _session_rate_limiter() -> InMemoryRateLimiter:
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = InMemoryRateLimiter()
    return st.session_state.rate_limiter


def _session_adapters() -> dict[str, object]:
    """Persistent adapter instances keep subprocess handles alive within a session."""
    if "_adapters" not in st.session_state:
        st.session_state._adapters = {
            "nmap": NmapAdapter(),
            "nikto": NiktoAdapter(),
            "zap": ZapAdapter(),
        }
    return st.session_state._adapters


# ---------------------------------------------------------------------------
# Recovery guidance
# ---------------------------------------------------------------------------
def recovery_guidance(run: ScanRunSummary) -> str:
    """Translate stored adapter failures into an analyst-facing next step without changing state."""
    if run.status == "awaiting_approval":
        return "This activity is waiting for a recorded analyst decision before it can continue."
    if run.status == "blocked":
        return "Review the registered scope and request details, then submit a new permitted request."
    if run.status == "failed":
        if run.error_message:
            return "Review the recorded error, correct the local tool or connection issue, then submit a new request."
        return "Review the recorded failure and submit a new request when the issue is resolved."
    return "No recovery action is required."


# ---------------------------------------------------------------------------
# Card renderers
# ---------------------------------------------------------------------------
def _run_card(run: ScanRunSummary) -> None:
    st.markdown(status_badge(run.status), unsafe_allow_html=True)
    st.markdown(f"**{run.tool.upper()}** · {run.target} · {run.profile or 'default'}")
    st.caption(f"Started: {run.started_at or 'not recorded'} · Completed: {run.completed_at or 'not completed'}")
    st.write(run.rationale or "No rationale was persisted for this activity.")
    if run.anticipated_next_steps:
        with st.expander("Possible next steps (non-binding preview)", expanded=False):
            for step in run.anticipated_next_steps:
                st.write(f"**{step['tool']}** · {step['profile']}: {step['rationale']}")
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


# ---------------------------------------------------------------------------
# AI proposal card renderer
# ---------------------------------------------------------------------------
def _render_proposal_outcome(outcome, source: str) -> None:
    """Display the AI-generated proposal outcome card in a styled card."""
    p = outcome.proposal
    status_map = {
        ProposalStatus.APPROVED: ("cl-success-card", "✓ Approved — ready to execute"),
        ProposalStatus.AWAITING_APPROVAL: ("", "⏳ Awaiting human approval"),
        ProposalStatus.REJECTED: ("", "✗ Rejected by scope gate"),
        ProposalStatus.BLOCKED: ("", "⚠ Blocked by rate limit"),
    }
    card_cls, label = status_map.get(outcome.status, ("", str(outcome.status)))

    st.markdown(
        f'<div class="cl-card {card_cls}">'
        f'<strong>AI Proposal · {html.escape(label)}</strong>'
        f'<br><span class="cl-tech">Source: {html.escape(source)}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if p:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tool", p.tool.value.upper())
        with col2:
            st.metric("Profile", p.profile.value)
        with col3:
            st.metric("Port", str(p.port))

        st.markdown(f"**Target:** `{p.target}`")
        st.markdown(f"**AI Rationale:** {html.escape(p.rationale)}")

        if p.anticipated_next_steps:
            with st.expander("Anticipated next steps (non-binding preview)", expanded=False):
                for step in p.anticipated_next_steps:
                    st.write(f"**{step.tool.value}** · {step.profile.value}: {step.rationale}")

    st.caption(f"Gate reason: {outcome.reason}")


# ---------------------------------------------------------------------------
# Execute a scan step from an approved proposal
# ---------------------------------------------------------------------------
def _execute_approved_proposal(repository: Repository, scope, proposal, context: AdapterContext) -> str | None:
    """
    Validate and start the adapter for an approved recon proposal.
    Returns run_id on success, None on failure. Displays status to the user.
    """
    adapters = _session_adapters()
    tool_name = proposal.tool.value
    adapter = adapters.get(tool_name)
    if adapter is None:
        st.error(f"No adapter registered for tool: {tool_name}")
        return None

    request = AdapterRequest(
        target=proposal.target,
        port=proposal.port,
        profile=proposal.profile.value,
        rationale=proposal.rationale,
        anticipated_next_steps=[
            {"tool": step.tool.value, "profile": step.profile.value, "rationale": step.rationale}
            for step in (proposal.anticipated_next_steps or [])
        ],
    )

    validated = adapter.validate(context, request)

    if validated.status == ScanRunStatus.AWAITING_APPROVAL:
        st.warning(
            "Active validation requires explicit human approval. "
            "Submit an approval request in the **Audit trail & approvals** workspace, then return here."
        )
        return None
    if validated.status in {ScanRunStatus.BLOCKED, ScanRunStatus.FAILED}:
        st.error(f"Validation blocked: {validated.reason}")
        return None

    handle = adapter.start(context, validated)

    if handle.status == ScanRunStatus.FAILED:
        st.error(f"Scan could not start: {handle.reason}")
        return None

    st.success(f"✓ {tool_name.upper()} scan started — run ID: `{handle.run_id}`")
    return handle.run_id


# ---------------------------------------------------------------------------
# Build an evidence summary from prior scan findings for the planning prompt
# ---------------------------------------------------------------------------
def _evidence_summary(repository: Repository, scope_id: str) -> str:
    runs = repository.list_scan_runs(scope_id)
    if not runs:
        return "No tool evidence has been collected yet."
    lines: list[str] = []
    done_runs = [r for r in runs if r.status in {"done", "parsing"}]
    if not done_runs:
        in_flight = [r for r in runs if r.status in {"running", "queued"}]
        if in_flight:
            return f"{len(in_flight)} scan(s) currently in progress; no parsed evidence yet."
        failed = [r for r in runs if r.status == "failed"]
        return f"{len(failed)} scan(s) failed — no usable evidence collected yet."
    for run in done_runs[-5:]:  # most recent 5 completed runs
        lines.append(
            f"- {run.tool.upper()} {run.profile} on {run.target}:{run.port if hasattr(run, 'port') else ''} → {run.status}"
        )
    return "\n".join(lines) if lines else "Prior runs completed but no evidence details available."


# ---------------------------------------------------------------------------
# Main page renderer
# ---------------------------------------------------------------------------
def render(repository: Repository) -> None:
    """Render the interactive AI planning panel and the read-only activity timeline."""
    heading(
        "Assessment workspace",
        "AI-driven assessment",
        "Enter your assessment objective below. The AI plans the next step, the gate checks scope and "
        "safety, and you approve execution — one step at a time.",
    )

    scopes = repository.list_scopes()
    if not scopes:
        st.markdown(
            '<div class="cl-card">No authorized scope is registered yet. '
            'Go to <strong>Authorized scope</strong> to register a lab target first.</div>',
            unsafe_allow_html=True,
        )
        return

    selected = st.selectbox(
        "Active authorized scope",
        scopes,
        format_func=lambda s: s.canonical_target,
        key="assessment_scope_select",
    )

    # -------------------------------------------------------------------
    # Section 1: AI Planner
    # -------------------------------------------------------------------
    st.subheader("🤖 AI Assessment Planner")
    st.caption(
        "Describe what you want to investigate. The LLM selects the right tool and profile "
        "based on your request, the registered scope, and evidence from prior steps."
    )

    slots_configured = bool(__import__("cipher_lens.config", fromlist=["provider_slots"]).provider_slots())
    if not slots_configured:
        st.warning(
            "No AI provider configured. Set `PROVIDER_1_BASE_URL`, `PROVIDER_1_API_KEY`, and "
            "`PROVIDER_1_MODEL` in your `.env` file and restart the application."
        )

    with st.form("ai-planner-form", clear_on_submit=False):
        analyst_request = st.text_area(
            "Assessment objective (natural language)",
            placeholder=(
                "Examples:\n"
                "• Perform initial port and service discovery on the web application\n"
                "• Check for web server misconfigurations and known CVEs\n"
                "• Identify the technology stack running on port 3000"
            ),
            height=120,
            help="Your plain-language request. The AI grounds its next-step proposal in this, the scope, and prior evidence.",
        )
        propose_btn = st.form_submit_button("Propose Next Assessment Step", type="primary")

    if propose_btn:
        if not analyst_request or not analyst_request.strip():
            inline_error("Please describe your assessment objective before proposing a step.")
        else:
            evidence_summary = _evidence_summary(repository, selected.id)
            context = ProposalContext(
                scope=selected,
                request=analyst_request.strip(),
                evidence_summary=evidence_summary,
            )
            with st.spinner("Asking the AI for the next assessment step…"):
                try:
                    outcome = propose_and_gate(
                        repository,
                        context,
                        rate_limit_check=_session_rate_limiter(),
                    )
                    st.session_state.last_proposal = outcome
                    st.session_state.last_proposal_scope_id = selected.id
                except Exception as exc:
                    st.error(f"Proposal generation failed: {exc}")
                    st.session_state.pop("last_proposal", None)

    # -------------------------------------------------------------------
    # Show the most recent proposal card + Execute button
    # -------------------------------------------------------------------
    if "last_proposal" in st.session_state and st.session_state.get("last_proposal_scope_id") == selected.id:
        outcome = st.session_state.last_proposal
        st.divider()
        st.subheader("📋 AI Proposal")
        _render_proposal_outcome(outcome, getattr(outcome, "source", "ai"))

        if outcome.status == ProposalStatus.APPROVED and outcome.proposal is not None:
            if st.button("▶ Execute Proposed Scan", type="primary", key="execute_scan_btn"):
                artifact_dir = data_directory() / "artifacts" / selected.id
                adapter_context = AdapterContext(
                    repository=repository,
                    scope=selected,
                    artifact_directory=artifact_dir,
                    rate_limiter=_session_rate_limiter(),
                    approval_id=None,
                )
                run_id = _execute_approved_proposal(
                    repository, selected, outcome.proposal, adapter_context
                )
                if run_id:
                    # Clear the last proposal so the analyst requests a new step next
                    st.session_state.pop("last_proposal", None)
                    st.session_state["last_run_id"] = run_id
                    time.sleep(0.5)
                    st.rerun()

        elif outcome.status == ProposalStatus.BLOCKED:
            remaining = getattr(getattr(outcome, "proposal", None), "port", "")
            st.info(
                f"This target+action combination was rate-limited. "
                f"Wait 45 seconds and try again, or adjust your request."
            )

    # -------------------------------------------------------------------
    # Poll the most recently started scan and attempt parse
    # -------------------------------------------------------------------
    if "last_run_id" in st.session_state:
        run_id = st.session_state["last_run_id"]
        runs = repository.list_scan_runs(selected.id)
        current_run = next((r for r in runs if r.id == run_id), None)
        if current_run:
            if current_run.status in {"queued", "running"}:
                st.info(f"⏳ Scan `{run_id}` is **{current_run.status}** — refresh to update status.")
            elif current_run.status == "parsing":
                # Trigger adapter parse
                adapters = _session_adapters()
                tool_name = current_run.tool
                adapter = adapters.get(tool_name)
                if adapter and hasattr(adapter, "_runs") and run_id in adapter._runs:
                    from cipher_lens.adapters.base import RunHandle
                    artifact_dir = data_directory() / "artifacts" / selected.id
                    ctx = AdapterContext(
                        repository=repository,
                        scope=selected,
                        artifact_directory=artifact_dir,
                        rate_limiter=_session_rate_limiter(),
                    )
                    handle = RunHandle(run_id, ScanRunStatus.PARSING)
                    output_path: Path = adapter._runs[run_id][1]
                    if output_path.exists():
                        raw = output_path.read_bytes()
                        parse_result = adapter.parse(ctx, handle, raw)
                        if parse_result.findings:
                            ingest_and_store_findings(repository, selected.id, parse_result.findings)
                            st.success(
                                f"✓ Scan complete — {len(parse_result.findings)} finding(s) ingested. "
                                "Request a new step to continue the adaptive assessment."
                            )
                        else:
                            st.info("Scan complete — no open findings found on this target/port.")
                        st.session_state.pop("last_run_id", None)
                        st.rerun()
                else:
                    st.info(f"Scan `{run_id}` is parsing — refresh to check results.")
            elif current_run.status == "done":
                st.success(f"✓ Scan `{run_id}` completed. Request a new step to continue.")
                st.session_state.pop("last_run_id", None)
            elif current_run.status == "failed":
                st.error(f"Scan `{run_id}` failed: {current_run.error_message or 'Unknown error'}")
                st.session_state.pop("last_run_id", None)

    st.divider()

    # -------------------------------------------------------------------
    # Section 2: Activity timeline (read-only)
    # -------------------------------------------------------------------
    st.subheader("📊 Activity Timeline")
    runs = repository.list_scan_runs(selected.id)
    approvals = repository.list_approvals(selected.id)

    if not runs:
        st.markdown(
            '<div class="cl-card">No activity recorded yet. '
            'Use the AI planner above to propose and execute your first assessment step.</div>',
            unsafe_allow_html=True,
        )
    else:
        for run in reversed(runs):  # newest first
            with st.container(border=True):
                _run_card(run)

    st.subheader("🔐 Approval Status")
    if not approvals:
        st.markdown(
            '<div class="cl-card">No approval decisions recorded for this scope.</div>',
            unsafe_allow_html=True,
        )
        return
    st.dataframe(
        [_approval_row(approval) for approval in approvals],
        hide_index=True,
        use_container_width=True,
    )
