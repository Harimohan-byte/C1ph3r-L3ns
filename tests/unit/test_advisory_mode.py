from pathlib import Path
import pytest
from pydantic import ValidationError

from cipher_lens.config import ProviderSlot
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
    ScopeRegistration,
    ToolName,
)
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.planning import (
    ProposalContext,
    RateLimitDecision,
    _parse_provider_proposal,
    deterministic_fallback,
    gate_proposal,
    propose_and_gate,
)
from cipher_lens.services.scope_registration import register_scope


class StaticClient:
    def __init__(self, response: str) -> None:
        self.response = response

    def complete(self, slot, messages):
        return self.response


def scope_context(tmp_path: Path) -> tuple[Repository, ProposalContext]:
    repository = Repository(tmp_path / "cipher_advisory.sqlite3")
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="10.0.0.50",
            allowed_ports="80,443",
            excluded_ports="",
            excluded_endpoints="",
            engagement_note="Authorized advisory lab.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    return repository, ProposalContext(scope=scope, request="What should I do next?")


def slot(number: int = 1) -> ProviderSlot:
    return ProviderSlot(
        label=f"provider_{number}",
        base_url="https://provider.invalid/v1",
        api_key="secret",
        model="model",
    )


# ===========================================================================
# T010: Schema Validation & Model Integrity
# ===========================================================================

def test_agent_response_validates_all_three_types():
    # 1. scan_proposal
    prop = PlanProposal(
        tool=ToolName.NMAP,
        profile=ScanProfile.QUICK_RECON,
        target="10.0.0.50",
        port=80,
        rationale="Initial scan.",
    )
    resp_scan = AgentResponse(
        response_type=ResponseType.SCAN_PROPOSAL,
        scan_proposal=prop,
    )
    assert resp_scan.response_type == ResponseType.SCAN_PROPOSAL
    assert resp_scan.proposal == prop

    # 2. advisory
    adv_payload = AdvisoryPayload(
        analysis="Web port 80 is open.",
        relevant_ports=[80],
        recommended_tools=[
            AdvisoryToolRecommendation(
                tool=ToolName.NIKTO,
                profile=ScanProfile.WEB_QUICK,
                port=80,
                rationale="Inspect headers.",
            )
        ],
        directional_guidance="Consider manual Burp testing.",
    )
    resp_adv = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=adv_payload,
    )
    assert resp_adv.response_type == ResponseType.ADVISORY
    assert resp_adv.proposal is None
    assert resp_adv.advisory == adv_payload

    # 3. conversational
    conv_payload = ConversationalPayload(message="Hi there! I am Cipher-Lens.")
    resp_conv = AgentResponse(
        response_type=ResponseType.CONVERSATIONAL,
        conversational=conv_payload,
    )
    assert resp_conv.response_type == ResponseType.CONVERSATIONAL
    assert resp_conv.proposal is None
    assert resp_conv.conversational.message == "Hi there! I am Cipher-Lens."


def test_agent_response_rejects_missing_matching_payload():
    with pytest.raises(ValidationError):
        AgentResponse.model_validate({"response_type": "scan_proposal"})

    with pytest.raises(ValidationError):
        AgentResponse.model_validate({"response_type": "advisory"})

    with pytest.raises(ValidationError):
        AgentResponse.model_validate({"response_type": "conversational"})


def test_agent_response_and_payloads_forbid_extra_fields():
    with pytest.raises(ValidationError):
        AgentResponse.model_validate(
            {
                "response_type": "conversational",
                "conversational": {"message": "Hello"},
                "extra_hack": True,
            }
        )

    with pytest.raises(ValidationError):
        ConversationalPayload.model_validate({"message": "Hello", "extra": 123})

    with pytest.raises(ValidationError):
        AdvisoryPayload.model_validate(
            {
                "analysis": "Test",
                "relevant_ports": [80],
                "recommended_tools": [],
                "unexpected": "blocked",
            }
        )


def test_parse_provider_proposal_auto_wraps_legacy_flat_dict():
    raw_flat = (
        '{"tool":"nmap","profile":"quick_recon","target":"10.0.0.50","port":80,"rationale":"Legacy scan."}'
    )
    parsed = _parse_provider_proposal(raw_flat)
    assert isinstance(parsed, AgentResponse)
    assert parsed.response_type == ResponseType.SCAN_PROPOSAL
    assert parsed.proposal is not None
    assert parsed.proposal.tool == ToolName.NMAP
    assert parsed.proposal.port == 80


# ===========================================================================
# T011: Advisory Gating, Port Scope Enforcement & Audit Logging
# ===========================================================================

def test_advisory_passes_gate_with_permitted_ports(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    advisory_response = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=AdvisoryPayload(
            analysis="Host topology indicates port 80 and 443 are in scope.",
            relevant_ports=[80, 443],
            recommended_tools=[
                AdvisoryToolRecommendation(
                    tool=ToolName.NIKTO,
                    profile=ScanProfile.WEB_QUICK,
                    port=80,
                    rationale="Check web misconfigurations.",
                )
            ],
            directional_guidance="For deep authentication checks, manual Burp Suite proxying is suggested.",
        ),
    )

    outcome = gate_proposal(repository, context, advisory_response, "provider_1")
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.proposal is None
    assert outcome.agent_response == advisory_response

    # Verify audit event ai_advisory was recorded
    advisory_events = [e for e in repository.list_audit_events() if e.event_type == "ai_advisory"]
    assert len(advisory_events) == 1
    event = advisory_events[0]
    assert event.outcome == "provided"
    assert event.detail["relevant_ports"] == [80, 443]
    assert event.detail["has_directional_guidance"] is True


def test_advisory_rejects_hallucinated_or_unpermitted_port(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    # Target only permits 80 and 443; 8080 is NOT in scope
    hallucinated_response = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=AdvisoryPayload(
            analysis="I think port 8080 might be running an admin console.",
            relevant_ports=[8080],
            recommended_tools=[],
        ),
    )

    outcome = gate_proposal(repository, context, hallucinated_response, "provider_1")
    assert outcome.status == ProposalStatus.REJECTED
    assert "8080" in outcome.reason
    assert "not permitted" in outcome.reason

    # Ensure gate recorded rejected outcome
    gate_events = [
        e for e in repository.list_audit_events()
        if e.event_type == "proposal_gate" and e.outcome == "rejected"
    ]
    assert len(gate_events) >= 1
    assert "8080" in gate_events[0].detail["reason"]


# ===========================================================================
# T012: Advisory Never Pollutes Findings & Follow-Up Is Fully Gated
# ===========================================================================

def test_advisory_never_writes_findings_table(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    advisory_response = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=AdvisoryPayload(
            analysis="Apache 2.4.49 detected on target with potential path traversal risk.",
            relevant_ports=[80],
            recommended_tools=[
                AdvisoryToolRecommendation(
                    tool=ToolName.NIKTO,
                    profile=ScanProfile.WEB_QUICK,
                    port=80,
                    rationale="Inspect server response headers.",
                )
            ],
            directional_guidance="Known RCE history — manual validation via Metasploit recommended outside app.",
        ),
    )

    outcome = gate_proposal(repository, context, advisory_response, "provider_1")
    assert outcome.status == ProposalStatus.APPROVED

    # CRITICAL: Verify findings table has ZERO entries
    findings = repository.list_findings(context.scope.id)
    assert len(findings) == 0

    # CRITICAL: Verify scan_runs table has ZERO entries
    runs = repository.list_scan_runs(context.scope.id)
    assert len(runs) == 0


def test_follow_up_from_advisory_goes_through_full_gating(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    # Analyst follows up by requesting the recommended Nikto scan
    context_followup = ProposalContext(
        scope=context.scope,
        request="Run nikto on port 80 as recommended",
        evidence_summary=context.evidence_summary,
    )
    proposal = PlanProposal(
        tool=ToolName.NIKTO,
        profile=ScanProfile.WEB_QUICK,
        target="10.0.0.50",
        port=80,
        rationale="Follow-up execution of advisory recommendation.",
    )
    outcome = gate_proposal(
        repository,
        context_followup,
        proposal,
        "follow_up",
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.proposal == proposal

    # If follow-up requests an active scan, human approval is still strictly required
    active_proposal = PlanProposal(
        tool=ToolName.ZAP,
        profile=ScanProfile.ACTIVE_SCAN,
        target="10.0.0.50",
        port=80,
        rationale="Active validation follow-up.",
    )
    outcome_active = gate_proposal(
        repository,
        context_followup,
        active_proposal,
        "follow_up",
        action=ActionClass.ACTIVE_VALIDATION,
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome_active.status == ProposalStatus.AWAITING_APPROVAL


# ===========================================================================
# T013: Conversational Response & Deterministic Fallback Routing
# ===========================================================================

def test_conversational_response_flow(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    conv_response = AgentResponse(
        response_type=ResponseType.CONVERSATIONAL,
        conversational=ConversationalPayload(
            message="Hello analyst! I am Cipher-Lens, your VAPT assistant."
        ),
    )
    outcome = gate_proposal(repository, context, conv_response, "provider_1")
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.proposal is None
    assert outcome.agent_response.conversational.message.startswith("Hello analyst!")

    # Verify ai_conversational audit event
    conv_events = [e for e in repository.list_audit_events() if e.event_type == "ai_conversational"]
    assert len(conv_events) == 1
    assert conv_events[0].outcome == "provided"


def test_deterministic_fallback_routes_intent_properly(tmp_path: Path):
    repository, base_context = scope_context(tmp_path)

    # 1. Greeting -> conversational
    ctx_greet = ProposalContext(scope=base_context.scope, request="Hi there!")
    fb_greet = deterministic_fallback(ctx_greet)
    assert fb_greet.response_type == ResponseType.CONVERSATIONAL
    assert "Cipher-Lens" in fb_greet.conversational.message

    # 2. Broad question -> advisory
    ctx_adv = ProposalContext(scope=base_context.scope, request="What should I do next?")
    fb_adv = deterministic_fallback(ctx_adv)
    assert fb_adv.response_type == ResponseType.ADVISORY
    assert fb_adv.advisory.relevant_ports == [80]
    assert len(fb_adv.advisory.recommended_tools) > 0

    # 3. Specific scan -> scan_proposal
    ctx_scan = ProposalContext(scope=base_context.scope, request="Run nmap quick recon on port 80")
    fb_scan = deterministic_fallback(ctx_scan)
    assert fb_scan.response_type == ResponseType.SCAN_PROPOSAL
    assert fb_scan.proposal.tool == ToolName.NMAP
    assert fb_scan.proposal.port == 80


# ===========================================================================
# T014-T016: UI Rendering & Action Button Interactions
# ===========================================================================

def test_render_proposal_outcome_conversational():
    from unittest.mock import patch
    from cipher_lens.services.planning import ProposalOutcome
    from cipher_lens.ui.assessment_page import _render_proposal_outcome

    conv_response = AgentResponse(
        response_type=ResponseType.CONVERSATIONAL,
        conversational=ConversationalPayload(message="Hi! I am Cipher-Lens."),
    )
    outcome = ProposalOutcome(
        status=ProposalStatus.APPROVED,
        proposal=None,
        reason="Conversational response.",
        source="deterministic_fallback",
        agent_response=conv_response,
    )

    with patch("streamlit.markdown") as mock_markdown:
        _render_proposal_outcome(outcome, "deterministic_fallback")
        assert mock_markdown.called
        rendered_html = mock_markdown.call_args[0][0]
        assert "Cipher-Lens Assistant" in rendered_html
        assert "Hi! I am Cipher-Lens." in rendered_html
        assert "Conversational response" in rendered_html


def test_render_proposal_outcome_advisory():
    from unittest.mock import MagicMock, patch
    from cipher_lens.services.planning import ProposalOutcome
    from cipher_lens.ui.assessment_page import _render_proposal_outcome

    adv_response = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=AdvisoryPayload(
            analysis="Host topology indicates HTTP port 80.",
            relevant_ports=[80],
            recommended_tools=[
                AdvisoryToolRecommendation(
                    tool=ToolName.NIKTO,
                    profile=ScanProfile.WEB_QUICK,
                    port=80,
                    rationale="Inspect server headers.",
                )
            ],
            directional_guidance="Consider manual Burp Suite testing.",
        ),
    )
    outcome = ProposalOutcome(
        status=ProposalStatus.APPROVED,
        proposal=None,
        reason="Advisory guidance.",
        source="ai",
        agent_response=adv_response,
    )

    with patch("streamlit.markdown") as mock_markdown, \
         patch("streamlit.columns", return_value=[MagicMock(), MagicMock()]), \
         patch("streamlit.button", return_value=False):
        _render_proposal_outcome(outcome, "ai")
        assert mock_markdown.called
        all_html = " ".join(str(call[0][0]) for call in mock_markdown.call_args_list)
        assert "Advisory Recommendations" in all_html
        assert "PORT 80" in all_html
        assert "Manual Testing &amp; Follow-up Options (Directional)" in all_html or "Manual Testing" in all_html
        assert "Consider manual Burp Suite testing." in all_html


def test_advisory_one_click_action_updates_saved_objective():
    import streamlit as st
    from unittest.mock import MagicMock, patch
    from cipher_lens.services.planning import ProposalOutcome
    from cipher_lens.ui.assessment_page import _render_proposal_outcome

    adv_response = AgentResponse(
        response_type=ResponseType.ADVISORY,
        advisory=AdvisoryPayload(
            analysis="Recon complete.",
            relevant_ports=[80],
            recommended_tools=[
                AdvisoryToolRecommendation(
                    tool=ToolName.NIKTO,
                    profile=ScanProfile.WEB_QUICK,
                    port=80,
                    rationale="Check web misconfigs.",
                )
            ],
        ),
    )
    outcome = ProposalOutcome(
        status=ProposalStatus.APPROVED,
        proposal=None,
        reason="Advisory guidance.",
        source="ai",
        agent_response=adv_response,
    )

    st.session_state.clear()
    with patch("streamlit.markdown"), \
         patch("streamlit.columns", return_value=[MagicMock(), MagicMock()]), \
         patch("streamlit.button", return_value=True), \
         patch("streamlit.rerun") as mock_rerun:
        _render_proposal_outcome(outcome, "ai")
        assert mock_rerun.called
        assert "saved_assessment_objective" in st.session_state
        assert "Run nikto (web_quick) on port 80" in st.session_state["saved_assessment_objective"]

