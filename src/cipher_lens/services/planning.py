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
from cipher_lens.domain.models import (
    ActionClass,
    AdvisoryPayload,
    AdvisoryToolRecommendation,
    AgentResponse,
    ConversationalPayload,
    PlanProposal,
    ProposalStatus,
    ResponseType,
    ScanProfile,
    ScopeRecord,
    ToolName,
)
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
    agent_response: AgentResponse | None = None


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
        "Analyze the analyst request, scope, and discovered evidence to provide the appropriate response.\n\n"
        "Security Tool Catalog & Truthful Integration Statuses:\n"
        f"{_seven_tools_prompt_catalog()}\n\n"
        "RESPONSE TYPES:\n"
        "You must respond in exactly ONE of three structured modes:\n\n"
        "1. 'scan_proposal': Use when the analyst requests a specific scan or immediate testing action.\n"
        "   Schema: {\"response_type\":\"scan_proposal\",\"scan_proposal\":{\"tool\":\"nmap|nikto|zap|nessus|openvas\",\"profile\":\"named_profile\",\"target\":\"IPv4 or hostname\",\"port\":integer,\"rationale\":\"reason\",\"anticipated_next_steps\":[{\"tool\":\"...\",\"profile\":\"...\",\"rationale\":\"...\"}]}}\n"
        "   Allowed tools & profiles:\n"
        "   - nmap: quick_recon, service_version_scan, targeted_port_scan, full_port_scan, os_detection\n"
        "   - nikto: web_quick, quick_recon\n"
        "   - zap: web_quick, quick_recon, spider, active_scan\n"
        "   - nessus: import_report, quick_recon\n"
        "   - openvas: import_report, quick_recon\n\n"
        "2. 'advisory': Use when the analyst asks a broad strategic question ('what should I do next', 'how should I test for web vulnerabilities', 'where to start').\n"
        "   Schema: {\"response_type\":\"advisory\",\"advisory\":{\"analysis\":\"strategic assessment grounded in evidence\",\"relevant_ports\":[integer],\"recommended_tools\":[{\"tool\":\"nmap|nikto|zap|nessus|openvas\",\"profile\":\"named_profile\",\"port\":integer,\"rationale\":\"reason\"}],\"directional_guidance\":\"optional directional follow-up note\"}}\n"
        "   CRITICAL ADVISORY RULES:\n"
        "   - 'relevant_ports' must only contain ports already discovered in evidence or explicitly registered in scope. Never invent ports.\n"
        "   - 'recommended_tools' must only recommend our integrated tools (nmap, nikto, zap, nessus, openvas).\n"
        "   - 'directional_guidance' may optionally mention manual outside-the-workflow tools (Burp Suite, Metasploit) in a purely directional manner (e.g., 'version documented with historical RCE issues — worth manual validation via Metasploit outside this workflow').\n"
        "   - NEVER include exploit payloads, attack code, module names, or how-to exploitation steps.\n"
        "   - NEVER assert specific CVEs or CVSS scores in advisory mode; present background knowledge as general software context, never as a confirmed finding on this target.\n\n"
        "3. 'conversational': Use for simple greetings, persona inquiries, or non-task small talk (e.g. 'hi', 'who are you').\n"
        "   Schema: {\"response_type\":\"conversational\",\"conversational\":{\"message\":\"short in-character reply\"}}\n\n"
        "Output raw JSON only with no markdown fences."
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


def _normalize_tool_dict(data: dict[str, Any]) -> None:
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


def _parse_provider_proposal(raw: str) -> AgentResponse:
    cleaned = _clean_json_content(raw)
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderFailure("schema_rejection") from error

    if not isinstance(data, dict):
        raise ProviderFailure("schema_rejection")

    # If top-level response_type is specified:
    if "response_type" in data:
        resp_type = str(data.get("response_type", "")).strip().lower()
        if resp_type == ResponseType.SCAN_PROPOSAL.value:
            sp = data.get("scan_proposal")
            if isinstance(sp, dict):
                _normalize_tool_dict(sp)
            try:
                return AgentResponse.model_validate(data)
            except PydanticValidationError as error:
                raise ProviderFailure("schema_rejection") from error
        elif resp_type == ResponseType.ADVISORY.value:
            adv = data.get("advisory")
            if isinstance(adv, dict) and "recommended_tools" in adv and isinstance(adv["recommended_tools"], list):
                for rec in adv["recommended_tools"]:
                    if isinstance(rec, dict):
                        _normalize_tool_dict(rec)
            try:
                return AgentResponse.model_validate(data)
            except PydanticValidationError as error:
                raise ProviderFailure("schema_rejection") from error
        elif resp_type == ResponseType.CONVERSATIONAL.value:
            try:
                return AgentResponse.model_validate(data)
            except PydanticValidationError as error:
                raise ProviderFailure("schema_rejection") from error
        else:
            raise ProviderFailure("schema_rejection")

    # Legacy flat PlanProposal dict support: auto-wrap into AgentResponse
    _normalize_tool_dict(data)
    try:
        prop = PlanProposal.model_validate(data)
        return AgentResponse(response_type=ResponseType.SCAN_PROPOSAL, scan_proposal=prop)
    except PydanticValidationError as error:
        raise ProviderFailure("schema_rejection") from error


def _schema_correction_message() -> dict[str, str]:
    return {
        "role": "user",
        "content": (
            "Your previous response was invalid. Return only one JSON object matching the exact schema "
            "from the system instruction (with 'response_type' set to 'scan_proposal', 'advisory', or 'conversational'). "
            "Do not include markdown fences, extra fields, flags, arguments, or raw unvalidated text."
        ),
    }


def _first_permitted_port(scope: ScopeRecord) -> int | None:
    excluded = parse_ports(scope.excluded_ports, allow_empty=True)
    for start, end in parse_ports(scope.allowed_ports):
        for port in range(start, end + 1):
            if not port_in_ranges(port, excluded):
                return port
    return None


def deterministic_fallback(context: ProposalContext) -> AgentResponse:
    """Safe local response used when configured AI providers are unavailable."""
    req = context.request.lower().strip()
    ev = context.evidence_summary.lower()

    # 1. Conversational intent (greetings / identity / small talk)
    greetings = {"hi", "hello", "hey", "who are you", "who are u", "what are you", "help", "good morning", "good evening"}
    if any(req == g or req.startswith(f"{g} ") or req.startswith(f"{g},") for g in greetings):
        return AgentResponse(
            response_type=ResponseType.CONVERSATIONAL,
            conversational=ConversationalPayload(
                message="Hello! I am Cipher-Lens, your human-supervised VAPT security agent. "
                        "I can propose targeted scans, offer advisory recommendations based on discovered evidence, "
                        "or guide your assessment. How can I assist with this target today?"
            ),
        )

    # 2. Advisory intent (broad requests, 'what should i do', 'what next', 'recommend', 'advice', 'test web')
    advisory_keywords = {"what should i do", "what next", "what to do", "recommend", "advice", "advise", "how to test", "where should i start"}
    is_exploratory = any(k in req for k in advisory_keywords) or (
        ("test" in req or "check" in req)
        and not any(t in req for t in ["nmap", "nikto", "zap", "nessus", "openvas", "port 80", "port 443", "port 3000"])
    )
    if is_exploratory:
        port = _first_permitted_port(context.scope)
        relevant_ports = [port] if port is not None else []
        recs: list[AdvisoryToolRecommendation] = []
        directional = None

        if "http" in ev or "open" in ev:
            analysis = (
                f"Discovered reconnaissance evidence indicates active network services on {context.scope.canonical_target}. "
                "Web service ports are responsive and ready for configuration inspection and application assessment."
            )
            if port:
                recs.append(AdvisoryToolRecommendation(
                    tool=ToolName.NIKTO,
                    profile=ScanProfile.WEB_QUICK,
                    port=port,
                    rationale="Inspect web server configuration, headers, and known security issues."
                ))
                recs.append(AdvisoryToolRecommendation(
                    tool=ToolName.ZAP,
                    profile=ScanProfile.QUICK_RECON,
                    port=port,
                    rationale="Spider the web application and discover endpoint attack surface."
                ))
            directional = (
                "For deeper application testing or authenticated endpoints, manual proxy testing via Burp Suite "
                "or controlled validation via Metasploit may be conducted outside this automated workflow."
            )
        else:
            analysis = (
                f"No service evidence has been collected yet for {context.scope.canonical_target}. "
                "Initial network reconnaissance is recommended to establish host availability and open port topology."
            )
            if port:
                recs.append(AdvisoryToolRecommendation(
                    tool=ToolName.NMAP,
                    profile=ScanProfile.QUICK_RECON,
                    port=port,
                    rationale="Establish initial port and service availability across registered scope."
                ))

        return AgentResponse(
            response_type=ResponseType.ADVISORY,
            advisory=AdvisoryPayload(
                analysis=analysis,
                relevant_ports=relevant_ports,
                recommended_tools=recs,
                directional_guidance=directional,
            ),
        )

    # 3. Specific scan proposals (existing fallback behavior)
    port = _first_permitted_port(context.scope)
    if port is None:
        raise ProviderFailure("no_permitted_port_for_local_fallback")

    if "nessus" in req:
        proposal = PlanProposal(
            tool=ToolName.NESSUS,
            profile=ScanProfile.IMPORT_REPORT,
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested Nessus Essentials scan report import.",
        )
    elif any(k in req for k in ["openvas", "greenbone"]):
        proposal = PlanProposal(
            tool=ToolName.OPENVAS,
            profile=ScanProfile.IMPORT_REPORT,
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested OpenVAS / Greenbone GMP XML report import.",
        )
    elif any(k in req for k in ["nikto", "web", "http", "header", "misconfig", "juice"]) or (
        "http" in ev or "open" in ev
    ):
        proposal = PlanProposal(
            tool=ToolName.NIKTO,
            profile=ScanProfile.WEB_QUICK,
            target=context.scope.canonical_target,
            port=port,
            rationale="Discovered HTTP service or web assessment objective indicates web server inspection using Nikto.",
        )
    elif any(k in req for k in ["zap", "spider", "active", "api"]):
        proposal = PlanProposal(
            tool=ToolName.ZAP,
            profile=ScanProfile.QUICK_RECON,
            target=context.scope.canonical_target,
            port=port,
            rationale="Analyst requested web application vulnerability scan using OWASP ZAP.",
        )
    else:
        proposal = PlanProposal(
            tool=ToolName.NMAP,
            profile=ScanProfile.QUICK_RECON,
            target=context.scope.canonical_target,
            port=port,
            rationale="A scoped quick reconnaissance step can establish service evidence before any further proposal.",
        )

    return AgentResponse(response_type=ResponseType.SCAN_PROPOSAL, scan_proposal=proposal)


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
) -> tuple[AgentResponse, str]:
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
                agent_resp = _parse_provider_proposal(raw)
                if agent_resp.response_type == ResponseType.SCAN_PROPOSAL and agent_resp.scan_proposal:
                    sp = agent_resp.scan_proposal
                    print(f"[CIPHER LENS AI] ✓ LLM proposal accepted: Tool={sp.tool.value.upper()}, Profile={sp.profile.value}, Target={sp.target}:{sp.port}", flush=True)
                elif agent_resp.response_type == ResponseType.ADVISORY and agent_resp.advisory:
                    adv = agent_resp.advisory
                    print(f"[CIPHER LENS AI] ✓ LLM advisory accepted: Ports={adv.relevant_ports}, Tools={[t.tool.value for t in adv.recommended_tools]}", flush=True)
                elif agent_resp.response_type == ResponseType.CONVERSATIONAL:
                    print(f"[CIPHER LENS AI] ✓ LLM conversational reply accepted", flush=True)
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
            return agent_resp, slot.label

    print("[CIPHER LENS AI] Using local deterministic planner...", flush=True)
    try:
        agent_resp = deterministic_fallback(context)
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
    if agent_resp.response_type == ResponseType.SCAN_PROPOSAL and agent_resp.scan_proposal:
        sp = agent_resp.scan_proposal
        print(f"[CIPHER LENS AI] ✓ Deterministic proposal: Tool={sp.tool.value.upper()}, Profile={sp.profile.value}, Target={sp.target}:{sp.port}", flush=True)
    elif agent_resp.response_type == ResponseType.ADVISORY and agent_resp.advisory:
        adv = agent_resp.advisory
        print(f"[CIPHER LENS AI] ✓ Deterministic advisory: Ports={adv.relevant_ports}, Tools={[t.tool.value for t in adv.recommended_tools]}", flush=True)
    else:
        print(f"[CIPHER LENS AI] ✓ Deterministic conversational reply", flush=True)
    return agent_resp, "deterministic_fallback"


def gate_proposal(
    repository: Repository,
    context: ProposalContext,
    proposal: PlanProposal | AgentResponse,
    source: str,
    *,
    action: ActionClass = ActionClass.RECON,
    rate_limit_check: RateLimitCheck | None = None,
) -> ProposalOutcome:
    """Apply policy after AI proposal generation; no adapter is reachable from this function."""
    if isinstance(proposal, AgentResponse):
        agent_resp = proposal
    else:
        agent_resp = AgentResponse(response_type=ResponseType.SCAN_PROPOSAL, scan_proposal=proposal)

    # 1. Conversational mode: small talk / greeting — no tool, scope, or rate limits needed
    if agent_resp.response_type == ResponseType.CONVERSATIONAL:
        record(
            repository,
            event_type="ai_conversational",
            outcome="provided",
            entity_type="agent_response",
            detail={"source": source},
        )
        return ProposalOutcome(
            status=ProposalStatus.APPROVED,
            proposal=None,
            source=source,
            reason="Conversational response.",
            agent_response=agent_resp,
        )

    # 2. Advisory mode: strategic guidance grounded strictly in authorized scope and recon evidence
    if agent_resp.response_type == ResponseType.ADVISORY:
        adv = agent_resp.advisory
        if adv is None:
            return _rejected(repository, None, source, "Malformed advisory payload.", "schema_check", agent_response=agent_resp)

        # Enforce that all relevant_ports are permitted in the registered scope
        for port in adv.relevant_ports:
            allowed, reason = is_in_scope(context.scope, context.scope.canonical_target, port, ActionClass.RECON)
            if not allowed:
                return _rejected(
                    repository,
                    None,
                    source,
                    f"Advisory referenced port {port} not permitted by registered scope: {reason}",
                    "scope_check",
                    agent_response=agent_resp,
                )

        # Check recommended tools and their ports
        for rec in adv.recommended_tools:
            if rec.port is not None:
                allowed, reason = is_in_scope(context.scope, context.scope.canonical_target, rec.port, ActionClass.RECON)
                if not allowed:
                    return _rejected(
                        repository,
                        None,
                        source,
                        f"Advisory recommended tool port {rec.port} not permitted by registered scope: {reason}",
                        "scope_check",
                        agent_response=agent_resp,
                    )

        # Audit the advisory event (separate event_type, never writes to findings)
        record(
            repository,
            event_type="ai_advisory",
            outcome="provided",
            entity_type="agent_response",
            detail={
                "source": source,
                "relevant_ports": adv.relevant_ports,
                "recommended_tools": [
                    {"tool": r.tool.value, "profile": r.profile.value, "port": r.port, "rationale": r.rationale}
                    for r in adv.recommended_tools
                ],
                "has_directional_guidance": bool(adv.directional_guidance),
            },
        )
        return ProposalOutcome(
            status=ProposalStatus.APPROVED,
            proposal=None,
            source=source,
            reason="Advisory recommendation validated against registered scope.",
            agent_response=agent_resp,
        )

    # 3. Scan proposal mode: standard pipeline
    plan_prop = agent_resp.scan_proposal
    if plan_prop is None:
        return _rejected(repository, None, source, "Malformed scan proposal payload.", "schema_check", agent_response=agent_resp)

    record(
        repository,
        event_type="plan_proposal",
        outcome="received",
        entity_type="plan_proposal",
        detail={
            "source": source,
            "tool": plan_prop.tool.value,
            "profile": plan_prop.profile.value,
            "port": plan_prop.port,
            "anticipated_next_steps": [step.model_dump(mode="json") for step in plan_prop.anticipated_next_steps],
        },
    )
    if normalize_target(plan_prop.target) != context.scope.canonical_target:
        reason = "Proposal target does not match the active scope."
        return _rejected(repository, plan_prop, source, reason, "target_match", agent_response=agent_resp)
    allowed, reason = is_in_scope(context.scope, plan_prop.target, plan_prop.port, action)
    if not allowed:
        return _rejected(repository, plan_prop, source, reason, "scope_check", agent_response=agent_resp)
    allowed_profiles = ALLOWED_PROFILES_BY_TOOL.get(plan_prop.tool.value, set())
    if plan_prop.profile.value not in allowed_profiles:
        return _rejected(
            repository,
            plan_prop,
            source,
            f"Profile '{plan_prop.profile.value}' is not allow-listed for {plan_prop.tool.value}.",
            "profile_allowlist",
            agent_response=agent_resp,
        )
    rate_decision = (rate_limit_check or _default_rate_limiter)(context.scope, plan_prop, action)
    record(
        repository,
        event_type="proposal_rate_limit",
        outcome="allowed" if rate_decision.allowed else "denied",
        entity_type="plan_proposal",
        detail={
            "source": source,
            "target": normalize_target(plan_prop.target),
            "port": plan_prop.port,
            "action": action.value,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "remaining_wait_seconds": rate_decision.remaining_seconds,
            "elapsed_seconds": rate_decision.elapsed_seconds,
            "reason": rate_decision.reason,
        },
    )
    if not rate_decision.allowed:
        print(f"[CIPHER LENS GATE] Rate limit check: BLOCKED — {rate_decision.reason}", flush=True)
        return _blocked(repository, plan_prop, source, rate_decision.reason, agent_response=agent_resp)
    if action == ActionClass.ACTIVE_VALIDATION:
        # Check if an active, non-expired human approval exists in the repository
        approved_records = repository.list_approvals(context.scope.id, status="approved")
        matched_approval = None
        for app in approved_records:
            if app.target == normalize_target(plan_prop.target) and (app.port is None or app.port == plan_prop.port):
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
    print(f"[CIPHER LENS GATE] Gate check for {plan_prop.tool.value.upper()} on {plan_prop.target}:{plan_prop.port} ({action.value}): {status.value.upper()}", flush=True)
    record(
        repository,
        event_type="proposal_gate",
        outcome=status.value,
        entity_type="plan_proposal",
        detail={"source": source, "target": plan_prop.target, "port": plan_prop.port, "action": action.value, "reason": reason},
    )
    return ProposalOutcome(status=status, proposal=plan_prop, source=source, reason=reason, agent_response=agent_resp)


def _rejected(
    repository: Repository,
    proposal: PlanProposal | None,
    source: str,
    reason: str,
    gate: str,
    agent_response: AgentResponse | None = None,
) -> ProposalOutcome:
    detail: dict[str, Any] = {"source": source, "gate": gate, "reason": reason}
    if proposal:
        detail["target"] = proposal.target
        detail["port"] = proposal.port
    record(
        repository,
        event_type="proposal_gate",
        outcome="rejected",
        entity_type="agent_response" if agent_response and not proposal else "plan_proposal",
        detail=detail,
    )
    return ProposalOutcome(
        status=ProposalStatus.REJECTED,
        proposal=proposal,
        source=source,
        reason=reason,
        agent_response=agent_response,
    )


def _blocked(
    repository: Repository,
    proposal: PlanProposal | None,
    source: str,
    reason: str,
    agent_response: AgentResponse | None = None,
) -> ProposalOutcome:
    detail: dict[str, Any] = {"source": source, "gate": "rate_limit", "reason": reason}
    if proposal:
        detail["target"] = proposal.target
        detail["port"] = proposal.port
    record(
        repository,
        event_type="proposal_gate",
        outcome=ProposalStatus.BLOCKED.value,
        entity_type="agent_response" if agent_response and not proposal else "plan_proposal",
        detail=detail,
    )
    return ProposalOutcome(
        status=ProposalStatus.BLOCKED,
        proposal=proposal,
        source=source,
        reason=reason,
        agent_response=agent_response,
    )


def propose_and_gate(
    repository: Repository,
    context: ProposalContext,
    *,
    slots: Sequence[ProviderSlot] | None = None,
    client: CompletionClient | None = None,
    action: ActionClass = ActionClass.RECON,
    rate_limit_check: RateLimitCheck | None = None,
) -> ProposalOutcome:
    agent_resp, source = generate_proposal(repository, context, slots=slots, client=client)
    effective_action = action
    if agent_resp.response_type == ResponseType.SCAN_PROPOSAL and agent_resp.scan_proposal:
        p = agent_resp.scan_proposal
        if p.tool.value == "zap" and p.profile.value == "active_scan":
            effective_action = ActionClass.ACTIVE_VALIDATION
        elif p.profile == ScanProfile.OS_DETECTION:
            effective_action = ActionClass.ACTIVE_VALIDATION
    return gate_proposal(
        repository, context, agent_resp, source, action=effective_action, rate_limit_check=rate_limit_check
    )
