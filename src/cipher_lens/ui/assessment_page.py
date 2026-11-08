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
        st.session_state.rate_limiter = InMemoryRateLimiter(window_seconds=10)
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
    """Display the AI-generated proposal outcome card in a modular Bento card."""
    p = outcome.proposal
    status_map = {
        ProposalStatus.APPROVED: ("cl-success-card", "✓ Approved — Ready to Execute"),
        ProposalStatus.AWAITING_APPROVAL: ("", "⏳ Awaiting Human Approval"),
        ProposalStatus.REJECTED: ("", "✗ Rejected by Scope Gate"),
        ProposalStatus.BLOCKED: ("", "⚠ Blocked by Rate Limit"),
    }
    card_cls, label = status_map.get(outcome.status, ("", str(outcome.status)))
    badge_status = "done" if outcome.status == ProposalStatus.APPROVED else "failed"

    tool_text = html.escape(p.tool.value.upper() if p else "N/A")
    profile_text = html.escape(p.profile.value if p else "default")
    port_text = html.escape(str(p.port) if p and p.port else "All Allowed")
    target_text = html.escape(p.target if p else "N/A")
    rationale_text = html.escape(p.rationale if p else "No rationale provided.")
    gate_reason = html.escape(outcome.reason)

    st.markdown(
        f'<div class="cl-card {card_cls}">'
        f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">'
        f'<div><span class="cl-kicker" style="font-size: 0.78rem;">Step Proposal</span>'
        f'<h4 style="margin: 0.2rem 0 0 0; color: #032E2B; font-weight: 800;">{tool_text} · {profile_text}</h4></div>'
        f'<span class="cl-status cl-status-{badge_status}">{html.escape(label)}</span>'
        f'</div>'
        f'<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.6rem; margin: 0.6rem 0;">'
        f'<div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 8px; padding: 0.5rem 0.75rem;">'
        f'<span style="color: #5D7A42; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block;">Target</span>'
        f'<span style="color: #BBF351; font-family: \'JetBrains Mono\', monospace; font-size: 1rem; font-weight: 700;">{target_text}</span>'
        f'</div>'
        f'<div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 8px; padding: 0.5rem 0.75rem;">'
        f'<span style="color: #5D7A42; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block;">Port</span>'
        f'<span style="color: #BBF351; font-family: \'JetBrains Mono\', monospace; font-size: 1rem; font-weight: 700;">{port_text}</span>'
        f'</div>'
        f'<div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 8px; padding: 0.5rem 0.75rem;">'
        f'<span style="color: #5D7A42; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block;">Tool</span>'
        f'<span style="color: #BBF351; font-family: \'JetBrains Mono\', monospace; font-size: 1rem; font-weight: 700;">{tool_text}</span>'
        f'</div>'
        f'<div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 8px; padding: 0.5rem 0.75rem;">'
        f'<span style="color: #5D7A42; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block;">Profile</span>'
        f'<span style="color: #F7F3EB; font-family: \'JetBrains Mono\', monospace; font-size: 0.95rem; font-weight: 600;">{profile_text}</span>'
        f'</div>'
        f'</div>'
        f'<div style="background: #FFFDF8; border: 1px solid #E5D7C0; border-radius: 8px; padding: 0.65rem 0.85rem; margin: 0.6rem 0;">'
        f'<strong style="color: #032E2B; font-size: 0.88rem;">AI Rationale:</strong> '
        f'<span style="color: #20231B; font-size: 0.92rem;">{rationale_text}</span>'
        f'</div>'
        f'<span class="cl-muted" style="font-size: 0.8rem;">Safety Gate: {gate_reason} · Source: {html.escape(source.upper())}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if p and p.anticipated_next_steps:
        with st.expander("Anticipated next steps (non-binding preview)", expanded=False):
            for step in p.anticipated_next_steps:
                st.write(f"**{step.tool.value.upper()}** · `{step.profile.value}`: {step.rationale}")


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

    action_type = (
        ActionClass.ACTIVE_VALIDATION
        if proposal.profile.value == "active_scan"
        else ActionClass.RECON
    )
    scheme = "https" if proposal.port in {443, 8443} else "http"

    request = AdapterRequest(
        target=proposal.target,
        port=proposal.port,
        profile=proposal.profile.value,
        action=action_type,
        scheme=scheme,
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
                    ingest_and_store_findings(repository, handle.run_id, parse_result.findings, parse_result.evidence)
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
                    ingest_and_store_findings(repository, r.id, parse_result.findings, parse_result.evidence)
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
            print(f"\n[CIPHER LENS UI] >>> 'Propose Next Assessment Step' clicked.", flush=True)
            print(f"[CIPHER LENS UI] Scope: {selected.target} (ID: {selected.id[:8]}...)", flush=True)
            print(f"[CIPHER LENS UI] Objective: '{analyst_request.strip()}'", flush=True)
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
                    print(f"[CIPHER LENS UI] Proposal outcome generated: status={outcome.status.value}, source={getattr(outcome, 'source', 'ai')}", flush=True)
                except Exception as exc:
                    print(f"[CIPHER LENS UI] Proposal generation failed: {exc}", flush=True)
                    st.error(f"Proposal generation failed: {exc}")
                    st.session_state.pop("last_proposal", None)

    # -------------------------------------------------------------------
    # Show the most recent proposal card + Execute button
    # -------------------------------------------------------------------
    if "last_proposal" in st.session_state and st.session_state.get("last_proposal_scope_id") == selected.id:
        outcome = st.session_state.last_proposal
        st.divider()
        st.subheader("📋 Review AI Step Proposal")
        st.caption("The AI has planned the step below. Review the target, tool, and rationale. No tool runs until you click Execute.")
        _render_proposal_outcome(outcome, getattr(outcome, "source", "ai"))

        is_executed = st.session_state.get("last_proposal_executed", False)
        scan_msg = st.session_state.get("last_scan_msg")

        if is_executed:
            if scan_msg:
                st.success(scan_msg)
            else:
                st.success("✓ Scan executed successfully. See discovered findings and timeline below.")
        elif outcome.status == ProposalStatus.APPROVED and outcome.proposal is not None:
            st.write("")
            if st.button("▶ Execute Proposed Scan", type="primary", key="execute_scan_btn"):
                print(f"\n[CIPHER LENS UI] >>> 'Execute Proposed Scan' clicked by user.", flush=True)
                print(f"[CIPHER LENS UI] Tool: {outcome.proposal.tool.value} | Profile: {outcome.proposal.profile.value} | Target: {outcome.proposal.target}", flush=True)
                artifact_dir = data_directory() / "artifacts" / selected.id
                # Check for an active approved authorization for this target/port/action
                matched_approval_id = None
                approved_records = repository.list_approvals(selected.id, status="approved")
                for app in approved_records:
                    if app.target == outcome.proposal.target and (app.port is None or app.port == outcome.proposal.port):
                        matched_approval_id = app.id
                        break

                adapter_context = AdapterContext(
                    repository=repository,
                    scope=selected,
                    artifact_directory=artifact_dir,
                    rate_limiter=_session_rate_limiter(),
                    approval_id=matched_approval_id,
                )
                run_id, msg = _execute_and_collect_scan(
                    repository, selected, outcome.proposal, adapter_context
                )
                print(f"[CIPHER LENS UI] Execution finished: run_id={run_id}, result='{msg}'", flush=True)
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
        # Severity metrics summary Bento Grid
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            key = f.severity.value.capitalize()
            if key in sev_counts:
                sev_counts[key] += 1

        crit_high = sev_counts["Critical"] + sev_counts["High"]
        bento_metrics_html = f"""
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.6rem; margin: 0.75rem 0 1rem 0;">
            <div style="background: #0C0F0C; border: 1.5px solid #2D3D1E; border-radius: 10px; padding: 0.65rem 0.85rem; text-align: center;">
                <span style="color: #6C824E; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block; letter-spacing: 0.05em;">Total Findings</span>
                <strong style="color: #BBF351; font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800;">{len(findings)}</strong>
            </div>
            <div style="background: #0C0F0C; border: 1.5px solid {'#FF5252' if crit_high > 0 else '#2D3D1E'}; border-radius: 10px; padding: 0.65rem 0.85rem; text-align: center;">
                <span style="color: {'#FF5252' if crit_high > 0 else '#6C824E'}; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block; letter-spacing: 0.05em;">Critical / High</span>
                <strong style="color: {'#FF5252' if crit_high > 0 else '#8E928A'}; font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800;">{crit_high}</strong>
            </div>
            <div style="background: #0C0F0C; border: 1.5px solid {'#FFA726' if sev_counts['Medium'] > 0 else '#2D3D1E'}; border-radius: 10px; padding: 0.65rem 0.85rem; text-align: center;">
                <span style="color: {'#FFA726' if sev_counts['Medium'] > 0 else '#6C824E'}; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block; letter-spacing: 0.05em;">Medium</span>
                <strong style="color: {'#FFA726' if sev_counts['Medium'] > 0 else '#8E928A'}; font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800;">{sev_counts['Medium']}</strong>
            </div>
            <div style="background: #0C0F0C; border: 1.5px solid {'#FFD54F' if sev_counts['Low'] > 0 else '#2D3D1E'}; border-radius: 10px; padding: 0.65rem 0.85rem; text-align: center;">
                <span style="color: {'#FFD54F' if sev_counts['Low'] > 0 else '#6C824E'}; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block; letter-spacing: 0.05em;">Low</span>
                <strong style="color: {'#FFD54F' if sev_counts['Low'] > 0 else '#8E928A'}; font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800;">{sev_counts['Low']}</strong>
            </div>
            <div style="background: #0C0F0C; border: 1.5px solid {'#42A5F5' if sev_counts['Info'] > 0 else '#2D3D1E'}; border-radius: 10px; padding: 0.65rem 0.85rem; text-align: center;">
                <span style="color: {'#42A5F5' if sev_counts['Info'] > 0 else '#6C824E'}; font-size: 0.72rem; text-transform: uppercase; font-weight: 700; display: block; letter-spacing: 0.05em;">Info</span>
                <strong style="color: {'#42A5F5' if sev_counts['Info'] > 0 else '#8E928A'}; font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800;">{sev_counts['Info']}</strong>
            </div>
        </div>
        """
        st.markdown(bento_metrics_html, unsafe_allow_html=True)

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
