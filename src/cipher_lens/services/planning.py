"""Evidence-grounded, provider-resilient proposal generation and policy gates."""

from __future__ import annotations

import json
import math
import socket
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError as PydanticValidationError

from cipher_lens.config import ProviderSlot, provider_slots
from cipher_lens.domain.models import ActionClass, PlanProposal, ProposalStatus, ScanProfile, ScopeRecord
from cipher_lens.domain.scope import is_in_scope, normalize_target
from cipher_lens.domain.validation import parse_ports, port_in_ranges
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.audit import record


NMAP_PROFILES = tuple(profile.value for profile in ScanProfile)
SCHEMA_ATTEMPT_CAP = 2
RATE_LIMIT_WINDOW_SECONDS = 45

ALLOWED_PROFILES_BY_TOOL: dict[str, set[str]] = {
    "nmap": {p.value for p in ScanProfile},
    "nikto": {ScanProfile.QUICK_RECON.value, ScanProfile.WEB_QUICK.value},
    "zap": {
        ScanProfile.QUICK_RECON.value,
        ScanProfile.WEB_QUICK.value,
        ScanProfile.ACTIVE_SCAN.value,
        ScanProfile.SPIDER.value,
    },
    "nessus": {
        ScanProfile.IMPORT_REPORT.value,
        ScanProfile.QUICK_RECON.value,
    },
    "openvas": {
        ScanProfile.IMPORT_REPORT.value,
        ScanProfile.QUICK_RECON.value,
    },
}


class ProviderFailure(RuntimeError):
    """A safe description of why a provider response cannot be used."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CompletionClient(Protocol):
    def complete(self, slot: ProviderSlot, messages: list[dict[str, str]]) -> str: ...


class RateLimitCheck(Protocol):
    def __call__(
        self, scope: ScopeRecord, proposal: PlanProposal, action: ActionClass
    ) -> "RateLimitDecision": ...


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    reason: str
    remaining_seconds: int
    elapsed_seconds: int | None = None


@dataclass
class InMemoryRateLimiter:
    """MVP request throttle keyed by normalized target, tool name, and action class."""

    window_seconds: int = RATE_LIMIT_WINDOW_SECONDS
    clock: Callable[[], float] = time.monotonic
    _last_requests: dict[tuple[str, str, ActionClass], float] = field(default_factory=dict, init=False)

    def __call__(
        self, scope: ScopeRecord, proposal: PlanProposal, action: ActionClass
    ) -> RateLimitDecision:
        target = normalize_target(proposal.target)
        tool_attr = getattr(proposal, "tool", None)
        if tool_attr is not None:
            tool_name = tool_attr.value if hasattr(tool_attr, "value") else str(tool_attr)
        else:
            tool_name = "default"
        key = (target, tool_name, action)
        now = self.clock()
        previous = self._last_requests.get(key)
        if previous is None or now - previous >= self.window_seconds:
            self._last_requests[key] = now
            return RateLimitDecision(True, "Rate limit check passed.", 0)
        elapsed = max(0, int(now - previous))
        remaining = max(1, math.ceil(self.window_seconds - (now - previous)))
        port_val = getattr(proposal, "port", None) or "any"
        return RateLimitDecision(
            False,
            f"Rate limit: a request for {target}/{port_val} ({action.value}) was already made "
            f"{elapsed}s ago; wait {remaining}s.",
            remaining,
            elapsed,
        )


_default_rate_limiter = InMemoryRateLimiter()


@dataclass(frozen=True)
class ProposalContext:
    scope: ScopeRecord
    request: str
    evidence_summary: str = "No tool evidence has been collected yet."


@dataclass(frozen=True)
class ProposalOutcome:
    status: ProposalStatus
    proposal: PlanProposal | None
    source: str
    reason: str


class OpenAICompatibleClient:
    """Minimal chat-completions client; it sends only the supplied assessment context."""

    def complete(self, slot: ProviderSlot, messages: list[dict[str, str]]) -> str:
        payload = json.dumps({"model": slot.model, "messages": messages, "temperature": 0}).encode("utf-8")
        request = Request(
            f"{slot.base_url.rstrip('/')}/chat/completions",
            data=payload,
            headers={"Authorization": f"Bearer {slot.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=20) as response:  # nosec B310: URL comes only from local config
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            reason = "quota_or_http_error" if error.code == 429 else f"http_{error.code}"
            raise ProviderFailure(reason) from error
        except (URLError, TimeoutError, socket.timeout) as error:
            raise ProviderFailure("timeout_or_connection_error") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderFailure("malformed_provider_response") from error
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise ProviderFailure("missing_chat_completion_content") from error
        if not isinstance(content, str):
            raise ProviderFailure("non_text_chat_completion_content")
        return content


def _clean_json_content(raw: str) -> str:
    """Strip markdown code block fences and surrounding non-JSON commentary."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    return text


def _seven_tools_prompt_catalog() -> str:
    """Format all 7 security tools with their declared capability and integration statuses."""
    catalog = [
        ("Nmap", "Live", "Host, port, and service discovery, reconnaissance, and version enumeration", "Fixed scan profile bundles only; no free-form flags or aggressive script execution."),
        ("OWASP ZAP", "Live", "Web application and API vulnerability assessment and active scan validation", "Active validation scans strictly require a prior 15-minute human approval token."),
        ("Nikto", "Live", "Web-server configuration, outdated components, and known security issue checks", "Fixed quick_recon and web_quick mode only; tuning and mutation flags not permitted."),
        ("Burp Suite Community", "Import-only", "Web security testing, analyst-assisted validation, and proxy issue ingestion", "Free Community edition provides no automated REST API; manual export and report import supported via Integration Matrix."),
        ("Nessus", "Import-only", "Comprehensive infrastructure vulnerability scanning and compliance auditing", "Native .nessus XML report import supported via proposal card; no live daemon claimed."),
        ("OpenVAS / Greenbone", "Import-only", "Infrastructure vulnerability assessment, CVE mapping, and cross-tool correlation", "Greenbone GMP XML report import supported via proposal card; server daemon not automated locally."),
        ("Metasploit", "Planned", "Controlled, lab-only validation and proof-of-concept verification", "Autonomous exploitation is strictly forbidden by Constitution Principle I; lab-only proof validation planned."),
    ]
    lines = []
    for name, status, role, lim in catalog:
        if status == "Live":
            exec_note = f"[Status: {status}] Automated live adapter available. Can be selected as executable proposal 'tool'."
        elif status == "Import-only":
            if name in ("Nessus", "OpenVAS / Greenbone"):
                exec_note = f"[Status: {status}] Import-only parser active. Can be proposed with profile 'import_report' to prompt analyst for report upload."
            else:
                exec_note = f"[Status: {status}] Import-only. CANNOT be selected in proposal 'tool' field. If relevant, name it in 'rationale' to advise manual testing and report import via Integration Matrix."
        else:
            exec_note = f"[Status: {status}] Planned lab validation. CANNOT be selected in proposal 'tool' field."
        lines.append(f"• {name}: {exec_note} (Role: {role}. Limitations: {lim})")
    return "\n".join(lines)


def _messages(context: ProposalContext) -> list[dict[str, str]]:
    system = (
        "You are an expert, authorized VAPT security planner for authorized lab targets.\n"
        "Select the next single assessment step based on the analyst request, scope, and discovered evidence.\n\n"
        "Security Tool Catalog & Truthful Integration Statuses:\n"
        f"{_seven_tools_prompt_catalog()}\n\n"
        "CRITICAL EXECUTION GUARDRAIL:\n"
        "- The 'tool' field in your JSON response (and in anticipated_next_steps) must be one of: 'nmap', 'nikto', 'zap', 'nessus', or 'openvas'.\n"
        "- For live automated scans, select 'nmap', 'nikto', or 'zap'.\n"
        "- For infrastructure vulnerability report import, select 'nessus' or 'openvas' with profile 'import_report'.\n"
        "- Never select Burp Suite or Metasploit in the 'tool' field.\n\n"
        "Return ONLY one JSON object matching this exact schema:\n"
        '{"tool":"nmap|nikto|zap|nessus|openvas","profile":"named_profile","target":"IPv4 or hostname",'
        '"port":integer,"rationale":"evidence-grounded reason",'
        '"anticipated_next_steps":[{"tool":"nmap|nikto|zap|nessus|openvas","profile":"named_profile",'
        '"rationale":"non-binding preview"}]}\n\n'
        "Allowed executable tools and profiles:\n"
        "- nmap: quick_recon, service_version_scan, targeted_port_scan, full_port_scan, os_detection\n"
        "- nikto: web_quick, quick_recon\n"
        "- zap: web_quick, quick_recon, spider, active_scan\n"
        "- nessus: import_report, quick_recon\n"
        "- openvas: import_report, quick_recon\n\n"
        "Guidelines:\n"
        "1. For initial port discovery or general recon, choose tool 'nmap'.\n"
        "2. When web services (HTTP, HTTPS, port 80, 443, 3000, 8080) are already discovered or requested, choose tool 'nikto' (profile 'web_quick').\n"
        "3. When the analyst requests web application testing or active scanning, choose tool 'zap'.\n"
        "4. When comprehensive infrastructure report import is requested, choose 'nessus' or 'openvas' (profile 'import_report').\n"
        "5. target and port must strictly match the authorized scope.\n"
        "6. Output raw JSON only with no markdown fences."
    )
    user = (
        f"Authorized scope target: {context.scope.canonical_target}\n"
        f"Allowed ports: {context.scope.allowed_ports}\n"
        f"Excluded ports: {context.scope.excluded_ports or '(none)'}\n"
        f"Allowed actions: {', '.join(sorted(action.value for action in context.scope.allowed_actions))}\n"
        f"Analyst request: {context.request}\n"
        f"Evidence summary: {context.evidence_summary}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _parse_provider_proposal(raw: str) -> PlanProposal:
    cleaned = _clean_json_content(raw)
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderFailure("schema_rejection") from error

    if isinstance(data, dict):
        tool_raw = str(data.get("tool", "")).lower().strip()
        if "openvas" in tool_raw or "greenbone" in tool_raw:
            data["tool"] = "openvas"
        elif "nessus" in tool_raw:
            data["tool"] = "nessus"
        elif tool_raw == "nikto":
            data["tool"] = "nikto"
        elif tool_raw == "zap":
            data["tool"] = "zap"
        elif tool_raw == "nmap":
            data["tool"] = "nmap"

        prof_raw = str(data.get("profile", "")).lower().strip()
        if "import" in prof_raw:
            data["profile"] = "import_report"

        if "anticipated_next_steps" in data and isinstance(data["anticipated_next_steps"], list):
            for step in data["anticipated_next_steps"]:
                if isinstance(step, dict):
                    s_tool = str(step.get("tool", "")).lower().strip()
                    if "openvas" in s_tool or "greenbone" in s_tool:
                        step["tool"] = "openvas"
                    elif "nessus" in s_tool:
                        step["tool"] = "nessus"
                    s_prof = str(step.get("profile", "")).lower().strip()
                    if "import" in s_prof:
                        step["profile"] = "import_report"

    try:
        return PlanProposal.model_validate(data)
    except PydanticValidationError as error:
        raise ProviderFailure("schema_rejection") from error


def _schema_correction_message() -> dict[str, str]:
    return {
        "role": "user",
        "content": (
            "Your previous response was invalid. Return only one JSON object matching the exact schema "
            "from the system instruction. Do not include markdown, extra fields, flags, arguments, or findings."
        ),
    }


def _first_permitted_port(scope: ScopeRecord) -> int | None:
    excluded = parse_ports(scope.excluded_ports, allow_empty=True)
    for start, end in parse_ports(scope.allowed_ports):
        for port in range(start, end + 1):
            if not port_in_ranges(port, excluded):
                return port
    return None


def deterministic_fallback(context: ProposalContext) -> PlanProposal:
    """Safe local proposal used when configured AI providers are unavailable."""
    port = _first_permitted_port(context.scope)
    if port is None:
        raise ProviderFailure("no_permitted_port_for_local_fallback")

    req = context.request.lower()
    ev = context.evidence_summary.lower()

    # If the analyst asks for Nessus report import:
    if "nessus" in req:
        return PlanProposal(
            tool="nessus",
            profile="import_report",
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested Nessus Essentials scan report import.",
        )

    # If the analyst asks for OpenVAS / Greenbone report import:
    if any(k in req for k in ["openvas", "greenbone"]):
        return PlanProposal(
            tool="openvas",
            profile="import_report",
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested OpenVAS / Greenbone GMP XML report import.",
        )

    # If the analyst asks for web / nikto scanning or HTTP was already discovered:
    if any(k in req for k in ["nikto", "web", "http", "header", "misconfig", "juice"]) or (
        "http" in ev or "open" in ev
    ):
        return PlanProposal(
            tool="nikto",
            profile="web_quick",
            target=context.scope.canonical_target,
            port=port,
            rationale="Discovered HTTP service or web assessment objective indicates web server inspection using Nikto.",
        )

    # If the analyst asks for ZAP / active scanning / spider:
    if any(k in req for k in ["zap", "spider", "active", "api"]):
        return PlanProposal(
            tool="zap",
            profile="quick_recon",
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested web application vulnerability scan using OWASP ZAP.",
        )

    return PlanProposal(
        tool="nmap",
        profile="quick_recon",
        target=context.scope.canonical_target,
        port=port,
        rationale="A scoped quick reconnaissance step can establish service evidence before any further proposal.",
    )


def _record_transition(repository: Repository, source: str, reason: str) -> None:
    record(
        repository,
        event_type="proposal_provider_transition",
        outcome="failed",
        entity_type="plan_proposal",
        detail={"source": source, "reason": reason},
    )


def generate_proposal(
    repository: Repository,
    context: ProposalContext,
    *,
    slots: Sequence[ProviderSlot] | None = None,
    client: CompletionClient | None = None,
) -> tuple[PlanProposal, str]:
    """Try configured providers in order, auditing every safe failover, then use local fallback."""
    active_slots = list(provider_slots() if slots is None else slots)
    completion_client = client or OpenAICompatibleClient()

    slot_labels = [s.label for s in active_slots]
    print(f"\n[CIPHER LENS AI] Active provider slots: {slot_labels or '(None configured — local fallback will be used)'}", flush=True)

    for slot in active_slots:
        print(f"[CIPHER LENS AI] Calling {slot.label} (model: {slot.model}) at {slot.base_url}…", flush=True)
        messages = _messages(context)
        for attempt in range(1, SCHEMA_ATTEMPT_CAP + 1):
            try:
                record(
                    repository,
                    event_type="proposal_provider_attempt",
                    outcome="started",
                    entity_type="plan_proposal",
                    detail={"source": slot.label, "attempt": attempt},
                )
                raw = completion_client.complete(slot, messages)
                print(f"[CIPHER LENS AI] Response received from {slot.label} ({len(raw)} chars)", flush=True)
                proposal = _parse_provider_proposal(raw)
                print(f"[CIPHER LENS AI] ✓ LLM proposal accepted: Tool={proposal.tool.value.upper()}, Profile={proposal.profile.value}, Target={proposal.target}:{proposal.port}", flush=True)
            except ProviderFailure as error:
                print(f"[CIPHER LENS AI] Provider failure on {slot.label} (attempt {attempt}): {error.reason}", flush=True)
                if error.reason == "schema_rejection" and attempt < SCHEMA_ATTEMPT_CAP:
                    record(
                        repository,
                        event_type="proposal_provider_transition",
                        outcome="retrying",
                        entity_type="plan_proposal",
                        detail={"source": slot.label, "reason": error.reason, "attempt": attempt},
                    )
                    messages = [*messages, _schema_correction_message()]
                    continue
                _record_transition(repository, slot.label, error.reason)
                break
            record(
                repository,
                event_type="proposal_provider_attempt",
                outcome="accepted",
                entity_type="plan_proposal",
                detail={"source": slot.label, "attempt": attempt},
            )
            return proposal, slot.label

    print("[CIPHER LENS AI] Using local deterministic planner...", flush=True)
    try:
        proposal = deterministic_fallback(context)
    except ProviderFailure as error:
        _record_transition(repository, "deterministic_fallback", error.reason)
        raise
    record(
        repository,
        event_type="proposal_provider_attempt",
        outcome="accepted",
        entity_type="plan_proposal",
        detail={"source": "deterministic_fallback"},
    )
    print(f"[CIPHER LENS AI] ✓ Deterministic proposal: Tool={proposal.tool.value.upper()}, Profile={proposal.profile.value}, Target={proposal.target}:{proposal.port}", flush=True)
    return proposal, "deterministic_fallback"


def gate_proposal(
    repository: Repository,
    context: ProposalContext,
    proposal: PlanProposal,
    source: str,
    *,
    action: ActionClass = ActionClass.RECON,
    rate_limit_check: RateLimitCheck | None = None,
) -> ProposalOutcome:
    """Apply policy after AI proposal generation; no adapter is reachable from this function."""
    record(
        repository,
        event_type="plan_proposal",
        outcome="received",
        entity_type="plan_proposal",
        detail={
            "source": source,
            "tool": proposal.tool.value,
            "profile": proposal.profile.value,
            "port": proposal.port,
            "anticipated_next_steps": [step.model_dump(mode="json") for step in proposal.anticipated_next_steps],
        },
    )
    if normalize_target(proposal.target) != context.scope.canonical_target:
        reason = "Proposal target does not match the active scope."
        return _rejected(repository, proposal, source, reason, "target_match")
    allowed, reason = is_in_scope(context.scope, proposal.target, proposal.port, action)
    if not allowed:
        return _rejected(repository, proposal, source, reason, "scope_check")
    allowed_profiles = ALLOWED_PROFILES_BY_TOOL.get(proposal.tool.value, set())
    if proposal.profile.value not in allowed_profiles:
        return _rejected(repository, proposal, source, f"Profile '{proposal.profile.value}' is not allow-listed for {proposal.tool.value}.", "profile_allowlist")
    rate_decision = (rate_limit_check or _default_rate_limiter)(context.scope, proposal, action)
    record(
        repository,
        event_type="proposal_rate_limit",
        outcome="allowed" if rate_decision.allowed else "denied",
        entity_type="plan_proposal",
        detail={
            "source": source,
            "target": normalize_target(proposal.target),
            "port": proposal.port,
            "action": action.value,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "remaining_wait_seconds": rate_decision.remaining_seconds,
            "elapsed_seconds": rate_decision.elapsed_seconds,
            "reason": rate_decision.reason,
        },
    )
    if not rate_decision.allowed:
        print(f"[CIPHER LENS GATE] Rate limit check: BLOCKED — {rate_decision.reason}", flush=True)
        return _blocked(repository, proposal, source, rate_decision.reason)
    if action == ActionClass.ACTIVE_VALIDATION:
        # Check if an active, non-expired human approval exists in the repository
        approved_records = repository.list_approvals(context.scope.id, status="approved")
        matched_approval = None
        for app in approved_records:
            if app.target == normalize_target(proposal.target) and (app.port is None or app.port == proposal.port):
                if app.expires_at:
                    try:
                        exp = datetime.fromisoformat(app.expires_at)
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        if exp > datetime.now(timezone.utc):
                            matched_approval = app
                            break
                    except (ValueError, TypeError):
                        pass
                else:
                    matched_approval = app
                    break

        if matched_approval is not None:
            status = ProposalStatus.APPROVED
            reason = f"Active validation approved via human authorization token #{matched_approval.id[:8]}."
        else:
            status = ProposalStatus.AWAITING_APPROVAL
            reason = "Active validation requires explicit human approval."
    else:
        status = ProposalStatus.APPROVED
        reason = "Schema, scope, profile, and rate-limit gates passed."
    print(f"[CIPHER LENS GATE] Gate check for {proposal.tool.value.upper()} on {proposal.target}:{proposal.port} ({action.value}): {status.value.upper()}", flush=True)
    record(
        repository,
        event_type="proposal_gate",
        outcome=status.value,
        entity_type="plan_proposal",
        detail={"source": source, "target": proposal.target, "port": proposal.port, "action": action.value, "reason": reason},
    )
    return ProposalOutcome(status=status, proposal=proposal, source=source, reason=reason)


def _rejected(
    repository: Repository, proposal: PlanProposal, source: str, reason: str, gate: str
) -> ProposalOutcome:
    record(
        repository,
        event_type="proposal_gate",
        outcome="rejected",
        entity_type="plan_proposal",
        detail={"source": source, "target": proposal.target, "port": proposal.port, "gate": gate, "reason": reason},
    )
    return ProposalOutcome(status=ProposalStatus.REJECTED, proposal=proposal, source=source, reason=reason)


def _blocked(repository: Repository, proposal: PlanProposal, source: str, reason: str) -> ProposalOutcome:
    record(
        repository,
        event_type="proposal_gate",
        outcome=ProposalStatus.BLOCKED.value,
        entity_type="plan_proposal",
        detail={"source": source, "target": proposal.target, "port": proposal.port, "gate": "rate_limit", "reason": reason},
    )
    return ProposalOutcome(status=ProposalStatus.BLOCKED, proposal=proposal, source=source, reason=reason)


def propose_and_gate(
    repository: Repository,
    context: ProposalContext,
    *,
    slots: Sequence[ProviderSlot] | None = None,
    client: CompletionClient | None = None,
    action: ActionClass = ActionClass.RECON,
    rate_limit_check: RateLimitCheck | None = None,
) -> ProposalOutcome:
    proposal, source = generate_proposal(repository, context, slots=slots, client=client)
    effective_action = action
    if proposal.tool.value == "zap" and proposal.profile.value == "active_scan":
        effective_action = ActionClass.ACTIVE_VALIDATION
    elif proposal.profile == ScanProfile.OS_DETECTION:
        effective_action = ActionClass.ACTIVE_VALIDATION
    return gate_proposal(
        repository, context, proposal, source, action=effective_action, rate_limit_check=rate_limit_check
    )
