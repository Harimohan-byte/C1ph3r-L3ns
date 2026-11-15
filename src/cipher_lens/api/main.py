"""FastAPI backend service for CIPHER LENS.

Wraps existing persistence repositories and domain services, exposing a typed
REST and SSE interface for the modern React front end.
"""

from __future__ import annotations

import io
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensure src root is on sys.path
_src_root = str(Path(__file__).resolve().parent.parent.parent)
if _src_root not in sys.path:
    sys.path.insert(0, _src_root)

from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from cipher_lens.adapters.base import AdapterContext, AdapterRequest, ScanRunStatus
from cipher_lens.adapters.nessus import NessusAdapter
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.adapters.openvas import OpenVASAdapter
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.config import database_path
from cipher_lens.domain.models import (
    ActionClass,
    ScopeRecord,
    ScopeRegistration,
)
from cipher_lens.domain.validation import ValidationError
from cipher_lens.persistence.repositories import Repository, ScanRunSummary
from cipher_lens.services.approvals import (
    ApprovalStatus,
    create_approval_request,
    list_audit_timeline,
    record_approval,
    transition_approval,
)
from cipher_lens.domain.findings import (
    FindingProvenance,
    NormalizedFinding,
    Severity,
    ValidationStatus,
)
from cipher_lens.services.findings import (
    ingest_and_store_findings,
    normalize_and_correlate,
    sort_findings,
)
from cipher_lens.services.integrations import get_integration_matrix
from cipher_lens.services.planning import (
    InMemoryRateLimiter,
    ProposalContext,
    propose_and_gate,
)
from cipher_lens.services.reporting import build_report_context, generate_vapt_pdf
from cipher_lens.services.scope_registration import register_scope


# Shared application repository
repo = Repository(database_path())
rate_limiter = InMemoryRateLimiter()

# In-memory adapter instances for scanning executions
adapters: dict[str, Any] = {
    "nmap": NmapAdapter(),
    "nikto": NiktoAdapter(),
    "zap": ZapAdapter(),
    "nessus": NessusAdapter(),
    "openvas": OpenVASAdapter(),
}

app = FastAPI(
    title="CIPHER LENS API",
    description="Autonomous VAPT Planning & Security Telemetry Engine",
    version="2.2.0",
)

# Enable CORS for Vite local dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------
class ScopeCreateRequest(BaseModel):
    target: str
    allowed_ports: str = "80,443"
    excluded_ports: str = ""
    excluded_endpoints: str = ""
    engagement_note: str = "Authorized security evaluation"
    authorized_lab_attested: bool = True
    allowed_actions: list[str] = ["recon", "active_validation"]


class PlanRequest(BaseModel):
    scope_id: str
    request: str


class ExecuteRequest(BaseModel):
    scope_id: str
    tool: str
    target: str
    port: int = 80
    profile: str = "quick_recon"
    action_type: str = "recon"
    rationale: str = ""


class ApprovalTransitionRequest(BaseModel):
    to_status: str
    decision_reason: str = "Approved by operator"
    actor: str = "security-lead"


class ApprovalCreateRequest(BaseModel):
    scope_id: str
    tool: str
    target: str
    port: int = 80
    action: str = "active_validation"
    command_preview: str = ""
    rationale: str = ""
    requested_by: str = "operator"


class FindingUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# System & Scope Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/health")
def get_health() -> dict[str, str]:
    return {"status": "ok", "app": "CIPHER LENS", "version": "2.2.0"}


@app.get("/api/v1/scopes")
def list_scopes() -> list[dict[str, Any]]:
    scopes = repo.list_scopes()
    return [s.model_dump() for s in scopes]


@app.post("/api/v1/scopes", status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeCreateRequest) -> dict[str, Any]:
    try:
        actions = {ActionClass(a) for a in payload.allowed_actions if a in ActionClass._value2member_map_}
        if not actions:
            actions = {ActionClass.RECON}
        reg = ScopeRegistration(
            target=payload.target,
            allowed_ports=payload.allowed_ports,
            excluded_ports=payload.excluded_ports,
            excluded_endpoints=payload.excluded_endpoints,
            engagement_note=payload.engagement_note,
            authorized_lab_attested=payload.authorized_lab_attested,
            allowed_actions=actions,
        )
        record = register_scope(repo, reg)
        return record.model_dump()
    except ValidationError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to register scope: {err}")


@app.delete("/api/v1/scopes/{scope_id}")
def delete_scope(scope_id: str) -> dict[str, str]:
    success = repo.delete_scope(scope_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scope not found")
    return {"status": "deleted", "scope_id": scope_id}


@app.post("/api/v1/system/reset")
def reset_system() -> dict[str, str]:
    repo.reset_database()
    return {"status": "reset", "message": "Database and scopes cleared"}


# ---------------------------------------------------------------------------
# Planning & Execution Endpoints
# ---------------------------------------------------------------------------
def _build_evidence_summary(scope_id: str) -> str:
    runs = repo.list_scan_runs(scope_id=scope_id)
    findings = repo.list_findings(scope_id=scope_id)
    if not runs and not findings:
        return "No prior assessment actions or findings recorded for this scope yet."

    parts = [f"Prior runs: {len(runs)} completed/attempted."]
    if findings:
        crit = sum(1 for f in findings if f.severity.value == "critical")
        high = sum(1 for f in findings if f.severity.value == "high")
        med = sum(1 for f in findings if f.severity.value == "medium")
        low = sum(1 for f in findings if f.severity.value == "low")
        parts.append(f"Confirmed findings: {len(findings)} total ({crit} critical, {high} high, {med} medium, {low} low).")
        top_titles = [f.title for f in findings[:3]]
        parts.append(f"Key issues: {'; '.join(top_titles)}.")
    return " ".join(parts)


@app.post("/api/v1/planning/plan")
def create_plan(payload: PlanRequest) -> dict[str, Any]:
    scopes = [s for s in repo.list_scopes() if s.id == payload.scope_id]
    if not scopes:
        raise HTTPException(status_code=404, detail="Scope not found")
    scope = scopes[0]

    evidence = _build_evidence_summary(payload.scope_id)
    context = ProposalContext(
        scope=scope,
        request=payload.request.strip(),
        evidence_summary=evidence,
    )

    try:
        outcome = propose_and_gate(
            repo,
            context,
            rate_limit_check=rate_limiter,
        )
        agent_dict = None
        if outcome.agent_response:
            agent_dict = outcome.agent_response.model_dump()
            if outcome.agent_response.conversational and "suggested_follow_ups" not in agent_dict.get("conversational", {}):
                agent_dict["conversational"]["suggested_follow_ups"] = [
                    "Scan port 80 for vulnerabilities",
                    "Explain our strategic methodology",
                    "Review active scopes and targets",
                ]
            if outcome.agent_response.advisory:
                adv = agent_dict["advisory"]
                if "strategic_guidance" not in adv and "analysis" in adv:
                    adv["strategic_guidance"] = adv["analysis"]
                if "key_risks" not in adv:
                    adv["key_risks"] = [
                        "Exposed network attack surface on target ports",
                        "Unvalidated web application entry points",
                    ]
                if "methodology_notes" not in adv:
                    adv["methodology_notes"] = [
                        "Passive reconnaissance before active validation",
                        "Gated human sign-off on offensive scans",
                    ]

        prop_dict = None
        if outcome.proposal:
            prop_dict = outcome.proposal.model_dump()
            is_active = prop_dict.get("profile") == "active_scan" or prop_dict.get("tool") in ("zap", "nikto")
            prop_dict["action_type"] = "active_validation" if is_active else "recon"
            prop_dict["requires_approval"] = is_active
            prop_dict["reasoning"] = prop_dict.get("rationale", "")
            prop_dict["risk_assessment"] = (
                "Active validation probes may elicit HTTP 4xx/5xx errors or state changes."
                if is_active
                else "Passive reconnaissance poses minimal operational risk to network hosts."
            )
            t = str(prop_dict.get("tool", "")).lower()
            p = prop_dict.get("port", 80)
            tgt = prop_dict.get("target", "")
            prof = prop_dict.get("profile", "quick_recon")
            if "nmap" in t:
                prop_dict["command_preview"] = f"nmap -sV -T4 -p {p} {tgt}"
            elif "nikto" in t:
                prop_dict["command_preview"] = f"nikto -host http://{tgt}:{p} -Tuning 123b"
            elif "zap" in t:
                prop_dict["command_preview"] = f"zap-cli quick-scan --spider http://{tgt}:{p}"
            else:
                prop_dict["command_preview"] = f"{t} --target {tgt}:{p} --profile {prof}"

        return {
            "status": outcome.status.value if hasattr(outcome.status, "value") else str(outcome.status),
            "source": outcome.source,
            "reason": outcome.reason,
            "agent_response": agent_dict,
            "plan_proposal": prop_dict,
        }
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Planning failed: {err}")


@app.post("/api/v1/planning/execute")
def execute_scan(payload: ExecuteRequest) -> dict[str, Any]:
    scopes = [s for s in repo.list_scopes() if s.id == payload.scope_id]
    if not scopes:
        raise HTTPException(status_code=404, detail="Scope not found")
    scope = scopes[0]

    adapter = adapters.get(payload.tool.lower())
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter registered for tool: {payload.tool}")

    action_type = (
        ActionClass.ACTIVE_VALIDATION
        if payload.action_type in ("active_validation", "active_scan")
        else ActionClass.RECON
    )
    scheme = "https" if payload.port in {443, 8443} else "http"

    context = AdapterContext(
        scope=scope,
        repository=repo,
        evidence_path=Path("data/evidence"),
    )

    request = AdapterRequest(
        target=payload.target,
        port=payload.port,
        profile=payload.profile,
        action=action_type,
        scheme=scheme,
        rationale=payload.rationale,
    )

    validated = adapter.validate(context, request)
    if validated.status == ScanRunStatus.AWAITING_APPROVAL:
        return {
            "status": "awaiting_approval",
            "message": "Active validation requires explicit human approval before execution.",
            "reason": validated.reason,
        }
    if validated.status in {ScanRunStatus.BLOCKED, ScanRunStatus.FAILED}:
        return {
            "status": "blocked",
            "message": f"Scan validation blocked: {validated.reason}",
            "reason": validated.reason,
        }

    handle = adapter.start(context, validated)
    if handle.status == ScanRunStatus.FAILED:
        return {
            "status": "failed",
            "message": f"Scan could not start: {handle.reason}",
            "reason": handle.reason,
        }

    # Synchronous polling for completion
    timeout = 60.0 if payload.tool.lower() != "zap" else 180.0
    deadline = time.monotonic() + timeout
    poll_res = None

    while time.monotonic() < deadline:
        poll_res = adapter.poll(context, handle)
        if poll_res.status != ScanRunStatus.RUNNING:
            break
        time.sleep(1.0)

    if poll_res is None or poll_res.status == ScanRunStatus.RUNNING:
        return {
            "status": "timeout",
            "message": f"Scan execution timed out after {timeout}s",
            "run_id": getattr(handle, "run_id", None),
        }

    # Automatically parse findings if finished
    new_findings = []
    if poll_res.status == ScanRunStatus.COMPLETED:
        try:
            parsed = adapter.parse(context, poll_res)
            correlated = ingest_and_store_findings(repo, poll_res.run_id, parsed)
            for f in correlated:
                new_findings.append(f.model_dump())
        except Exception as err:
            print(f"[CIPHER LENS API] Warning: auto-parse failed: {err}")

    return {
        "status": poll_res.status.value if hasattr(poll_res.status, "value") else str(poll_res.status),
        "run_id": getattr(poll_res, "run_id", None),
        "stdout": getattr(poll_res, "stdout", ""),
        "stderr": getattr(poll_res, "stderr", ""),
        "findings_count": len(new_findings),
        "findings": new_findings,
    }


# ---------------------------------------------------------------------------
# Approvals & Governance Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/approvals")
def get_approvals(scope_id: Optional[str] = None) -> list[dict[str, Any]]:
    approvals = repo.list_approvals(scope_id=scope_id)
    return [a.model_dump() for a in approvals]


@app.post("/api/v1/approvals", status_code=status.HTTP_201_CREATED)
def create_approval(payload: ApprovalCreateRequest) -> dict[str, Any]:
    try:
        act = ActionClass.ACTIVE_VALIDATION if "active" in payload.action.lower() else ActionClass.RECON
        appr = create_approval_request(
            repository=repo,
            scope_id=payload.scope_id,
            tool=payload.tool,
            target=payload.target,
            port=payload.port,
            action=act,
            command_preview=payload.command_preview,
            reason=payload.rationale,
            requested_by=payload.requested_by,
        )
        return appr.model_dump()
    except Exception as err:
        raise HTTPException(status_code=400, detail=str(err))


@app.post("/api/v1/approvals/{approval_id}/transition")
def transition_approval_endpoint(
    approval_id: str,
    payload: ApprovalTransitionRequest,
) -> dict[str, Any]:
    try:
        to_st = ApprovalStatus(payload.to_status.lower())
        updated = transition_approval(
            repository=repo,
            approval_id=approval_id,
            to_status=to_st,
            actor=payload.actor,
            reason=payload.decision_reason,
        )
        return updated.model_dump()
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"Invalid transition: {err}")
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


# ---------------------------------------------------------------------------
# Audit Trail Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/audit/timeline")
def get_audit_timeline(
    query: Optional[str] = None,
    event_type: Optional[str] = None,
    outcome: Optional[str] = None,
) -> list[dict[str, Any]]:
    events = list_audit_timeline(
        repository=repo,
        query=query,
        event_type=event_type,
        outcome=outcome,
    )
    return [e.model_dump() for e in events]


# ---------------------------------------------------------------------------
# Tool Integrations Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/integrations")
def get_integrations() -> list[dict[str, Any]]:
    matrix = get_integration_matrix()
    return [t.model_dump() for t in matrix]


# ---------------------------------------------------------------------------
# Findings Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/findings")
def list_findings(scope_id: Optional[str] = None) -> list[dict[str, Any]]:
    findings = repo.list_findings(scope_id=scope_id)
    return [f.model_dump() for f in findings]


@app.patch("/api/v1/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingUpdateRequest) -> dict[str, Any]:
    findings = repo.list_findings()
    matches = [f for f in findings if f.id == finding_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Finding not found")
    f = matches[0]
    if payload.status:
        try:
            f.validation_status = ValidationStatus(payload.status.lower())
            repo.save_findings([f])
        except ValueError:
            pass
    return f.model_dump()


# ---------------------------------------------------------------------------
# Reports & PDF Download Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/reports/metrics")
def get_report_metrics(scope_id: str) -> dict[str, Any]:
    scopes = [s for s in repo.list_scopes() if s.id == scope_id]
    if not scopes:
        raise HTTPException(status_code=404, detail="Scope not found")
    ctx = build_report_context(repo, scope_id)
    # Convert non-serializable objects for JSON response
    return {
        "scope": ctx["scope"].model_dump() if hasattr(ctx["scope"], "model_dump") else str(ctx["scope"]),
        "runs_count": len(ctx["runs"]),
        "findings_count": len(ctx["findings"]),
        "approvals_count": len(ctx["approvals"]),
        "distribution": ctx["distribution"],
        "generated_at": ctx["generated_at"],
    }


@app.get("/api/v1/reports/pdf")
def download_pdf_report(scope_id: str) -> Response:
    scopes = [s for s in repo.list_scopes() if s.id == scope_id]
    if not scopes:
        raise HTTPException(status_code=404, detail="Scope not found")
    scope = scopes[0]

    try:
        pdf_bytes = generate_vapt_pdf(repo, scope_id)
        filename = f"CIPHER_LENS_VAPT_Report_{scope.canonical_target.replace('/', '_')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to compile PDF report: {err}")


# ---------------------------------------------------------------------------
# Production SPA Static Mounting
# ---------------------------------------------------------------------------
_frontend_dist = Path(_src_root).parent / "frontend" / "dist"
if _frontend_dist.exists() and (_frontend_dist / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")
