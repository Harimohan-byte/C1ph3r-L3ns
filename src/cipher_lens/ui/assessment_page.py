"""Assessment workspace: AI-driven adaptive planning, scan execution, and live findings."""

from __future__ import annotations

import html
import time
from pathlib import Path

import streamlit as st

from cipher_lens.adapters.base import (
    AdapterContext,
    AdapterRequest,
    RunHandle,
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
# Execute and poll a scan synchronously with user feedback
# ---------------------------------------------------------------------------
def _execute_and_collect_scan(
    repository: Repository,
    scope,
    proposal,
    context: AdapterContext,
) -> tuple[str | None, str | None]:
    """
    Validate, start, poll, and parse the adapter for an approved proposal.
    Waits for the scan to finish (up to 45s), automatically parses findings,
    and returns (run_id, summary_message).
    """
    adapters = _session_adapters()
    tool_name = proposal.tool.value
    adapter = adapters.get(tool_name)
    if adapter is None:
        st.error(f"No adapter registered for tool: {tool_name}")
        return None, None

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
        return None, None
    if validated.status in {ScanRunStatus.BLOCKED, ScanRunStatus.FAILED}:
        st.error(f"Validation blocked: {validated.reason}")
        return None, None

    with st.spinner(f"Executing {tool_name.upper()} ({proposal.profile.value}) on {proposal.target}:{proposal.port}…"):
        handle = adapter.start(context, validated)
        if handle.status == ScanRunStatus.FAILED:
            st.error(f"Scan could not start: {handle.reason}")
            return None, None

        # Poll every 0.5s up to 45s for recon scan completion
        deadline = time.monotonic() + 45.0
        poll_res = None
        while time.monotonic() < deadline:
            poll_res = adapter.poll(context, handle)
            if poll_res.status != ScanRunStatus.RUNNING:
                break
            time.sleep(0.5)

        if poll_res is None or poll_res.status == ScanRunStatus.RUNNING:
            st.warning(f"Scan `{handle.run_id}` is taking longer than expected. It is still processing.")
            return handle.run_id, None

        if poll_res.status == ScanRunStatus.FAILED:
            st.error(f"Scan failed: {poll_res.reason or 'Tool execution error.'}")
            return handle.run_id, None

        # Status is PARSING — read raw output and parse findings
        if poll_res.status == ScanRunStatus.PARSING:
            output_path: Path | None = None
            if hasattr(adapter, "_runs") and handle.run_id in adapter._runs:
                output_path = adapter._runs[handle.run_id][1]

            if output_path and output_path.exists():
                raw = output_path.read_bytes()
                parse_result = adapter.parse(context, handle, raw)
                if parse_result.findings:
                    ingest_and_store_findings(repository, scope.id, parse_result.findings)
                    msg = (
                        f"✓ {tool_name.upper()} scan completed successfully: "
                        f"{len(parse_result.findings)} finding(s) discovered and correlated below."
                    )
                else:
                    msg = f"✓ {tool_name.upper()} scan completed successfully: target port {proposal.port} responded with no vulnerabilities."
                return handle.run_id, msg

        return handle.run_id, f"✓ {tool_name.upper()} scan completed."


# ---------------------------------------------------------------------------
# Auto-recover orphaned running scans
# ---------------------------------------------------------------------------
def _recover_orphaned_scans(repository: Repository, scope_id: str) -> None:
    """Recover any scans left in running state by a prior interrupted session."""
    runs = repository.list_scan_runs(scope_id)
    running_runs = [r for r in runs if r.status in {"running", "parsing"}]
    if not running_runs:
        return

    adapters = _session_adapters()
    artifact_dir = data_directory() / "artifacts" / scope_id

    for r in running_runs:
        adapter = adapters.get(r.tool)
        output_file = artifact_dir / f"{r.id}.xml"
        if not output_file.exists():
            output_file = artifact_dir / f"{r.id}.json"

        # If output file exists, attempt parsing
        if output_file.exists() and output_file.stat().st_size > 0 and adapter:
            try:
                raw = output_file.read_bytes()
                ctx = AdapterContext(
                    repository=repository,
                    scope=next(s for s in repository.list_scopes() if s.id == scope_id),
                    artifact_directory=artifact_dir,
                    rate_limiter=_session_rate_limiter(),
                )
                parse_result = adapter.parse(ctx, RunHandle(r.id, ScanRunStatus.PARSING), raw)
                if parse_result.findings:
                    ingest_and_store_findings(repository, scope_id, parse_result.findings)
            except Exception:
                repository.update_scan_run(r.id, ScanRunStatus.FAILED.value, "Could not parse artifact.")
        else:
            # Mark as failed so it does not hang forever in running status
            repository.update_scan_run(r.id, ScanRunStatus.FAILED.value, "Scan process was interrupted by page reload.")


# ---------------------------------------------------------------------------
# Build an evidence summary from prior scan findings for the planning prompt
# ---------------------------------------------------------------------------
def _evidence_summary(repository: Repository, scope_id: str) -> str:
    runs = repository.list_scan_runs(scope_id)
    findings = repository.list_findings(scope_id=scope_id)
    if not runs and not findings:
        return "No tool evidence has been collected yet."
    lines: list[str] = []
    if findings:
        lines.append("Discovered Findings:")
        for f in findings[:6]:
            lines.append(f"- {f.canonical_title} on {f.affected_asset} ({f.severity.value})")
    done_runs = [r for r in runs if r.status in {"done", "parsing"}]
    if done_runs:
        lines.append("Completed Scans:")
        for run in done_runs[-4:]:
            lines.append(f"- {run.tool.upper()} {run.profile} on {run.target} → {run.status}")
    return "\n".join(lines) if lines else "Prior runs completed but no evidence details available."


# ---------------------------------------------------------------------------
# Main page renderer
# ---------------------------------------------------------------------------
def render(repository: Repository) -> None:
    """Render the interactive AI planning panel, live findings, and activity timeline."""
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

    # Recover any orphaned scans from previous reloads
    _recover_orphaned_scans(repository, selected.id)

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

    # Persistent text area: keeps value across page navigation
    saved_obj = st.session_state.get("saved_assessment_objective", "")

    with st.form("ai-planner-form", clear_on_submit=False):
        analyst_request = st.text_area(
            "Assessment objective (natural language)",
            value=saved_obj,
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
            st.session_state["saved_assessment_objective"] = analyst_request.strip()
            st.session_state["last_proposal_executed"] = False
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

        is_executed = st.session_state.get("last_proposal_executed", False)
        scan_msg = st.session_state.get("last_scan_msg")

        if is_executed:
            if scan_msg:
                st.success(scan_msg)
            else:
                st.success("✓ Scan executed successfully. See discovered findings and timeline below.")
        elif outcome.status == ProposalStatus.APPROVED and outcome.proposal is not None:
            if st.button("▶ Execute Proposed Scan", type="primary", key="execute_scan_btn"):
                artifact_dir = data_directory() / "artifacts" / selected.id
                adapter_context = AdapterContext(
                    repository=repository,
                    scope=selected,
                    artifact_directory=artifact_dir,
                    rate_limiter=_session_rate_limiter(),
                    approval_id=None,
                )
                run_id, msg = _execute_and_collect_scan(
                    repository, selected, outcome.proposal, adapter_context
                )
                if run_id:
                    st.session_state["last_proposal_executed"] = True
                    st.session_state["last_scan_msg"] = msg
                    st.rerun()

        elif outcome.status == ProposalStatus.BLOCKED:
            st.info(
                "This target+action combination was rate-limited. "
                "Wait 45 seconds and try again, or adjust your request."
            )

    # -------------------------------------------------------------------
    # Section 2: Discovered Findings (Directly on Assessment Page)
    # -------------------------------------------------------------------
    st.divider()
    st.subheader("🎯 Discovered Assessment Findings")
    findings = repository.list_findings(scope_id=selected.id)
    if not findings:
        st.markdown(
            '<div class="cl-card">No findings recorded for this scope yet. '
            'Execute an assessment scan above to inspect findings.</div>',
            unsafe_allow_html=True,
        )
    else:
        # Severity metrics summary
        c1, c2, c3, c4, c5 = st.columns(5)
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            key = f.severity.value.capitalize()
            if key in sev_counts:
                sev_counts[key] += 1

        with c1:
            st.metric("Total Findings", len(findings))
        with c2:
            st.metric("Critical / High", sev_counts["Critical"] + sev_counts["High"])
        with c3:
            st.metric("Medium", sev_counts["Medium"])
        with c4:
            st.metric("Low", sev_counts["Low"])
        with c5:
            st.metric("Info", sev_counts["Info"])

        for idx, f in enumerate(findings, start=1):
            with st.container(border=True):
                st.markdown(
                    f"**{idx}. {html.escape(f.canonical_title)}** · `{f.affected_asset}` {status_badge(f.severity.value)}",
                    unsafe_allow_html=True,
                )
                st.write(f.description)
                st.caption(
                    f"Priority Score: {f.priority_score:.1f}/10.0 · "
                    f"CVSS: {f.cvss or 'N/A'} · "
                    f"CVE: {html.escape(f.cve or 'None')} · "
                    f"Validation: {f.validation_status.value} · "
                    f"Evidence: {len(f.provenance)} artifact(s)"
                )

    # -------------------------------------------------------------------
    # Section 3: Activity timeline (read-only)
    # -------------------------------------------------------------------
    st.divider()
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
