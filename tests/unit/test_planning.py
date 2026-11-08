import os
from pathlib import Path

import pytest

from cipher_lens.config import ProviderSlot, provider_slots
from cipher_lens.domain.models import ActionClass, PlanProposal, ProposalStatus, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.planning import (
    InMemoryRateLimiter,
    ProposalContext,
    ProviderFailure,
    RateLimitDecision,
    gate_proposal,
    propose_and_gate,
)
from cipher_lens.services.scope_registration import register_scope


class FailingClient:
    def complete(self, slot, messages):
        raise ProviderFailure("quota_or_http_error")


class StaticClient:
    def __init__(self, response: str) -> None:
        self.response = response

    def complete(self, slot, messages):
        return self.response


class SequenceClient:
    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.messages: list[list[dict[str, str]]] = []

    def complete(self, slot, messages):
        self.messages.append(messages)
        return self.responses.pop(0)


def scope_context(tmp_path: Path) -> tuple[Repository, ProposalContext]:
    repository = Repository(tmp_path / "cipher.sqlite3")
    scope = register_scope(
        repository,
        ScopeRegistration(
            target="lab.example",
            allowed_ports="80,443",
            excluded_ports="443",
            excluded_endpoints="",
            engagement_note="Authorized lab.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    return repository, ProposalContext(scope=scope, request="Discover permitted web services.")


def slot(number: int) -> ProviderSlot:
    return ProviderSlot(label=f"provider_{number}", base_url="https://provider.invalid/v1", api_key="secret", model="model")


def test_invalid_provider_responses_fall_back_and_are_audited(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1), slot(2)],
        client=FailingClient(),
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.source == "deterministic_fallback"
    transitions = [event for event in repository.list_audit_events() if event.event_type == "proposal_provider_transition"]
    assert [event.detail["source"] for event in transitions] == ["provider_2", "provider_1"]


def test_provider_proposal_is_gated_by_scope_and_rate_limit(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    client = StaticClient(
        '{"tool":"nmap","profile":"quick_recon","target":"lab.example","port":443,"rationale":"Check permitted web service."}'
    )
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1)],
        client=client,
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.REJECTED
    assert "excluded" in outcome.reason.lower()


def test_plan_proposal_rejects_freeform_or_invalid_port():
    with pytest.raises(Exception):
        PlanProposal.model_validate(
            {"tool": "nmap", "profile": "--script unsafe", "target": "lab.example", "port": "80", "rationale": "x"}
        )
    with pytest.raises(Exception):
        PlanProposal.model_validate(
            {
                "tool": "nmap",
                "profile": "quick_recon",
                "target": "lab.example",
                "port": 80,
                "rationale": "x",
                "arguments": "--unsafe",
            }
        )


def test_schema_rejection_gets_one_bounded_corrective_retry(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    client = SequenceClient(
        [
            '{"tool":"nmap","profile":"quick_recon","target":"lab.example","port":"80","rationale":"wrong type"}',
            '{"tool":"nmap","profile":"quick_recon","target":"lab.example","port":80,"rationale":"valid"}',
        ]
    )
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1)],
        client=client,
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert len(client.messages) == 2
    assert "previous response was invalid" in client.messages[1][-1]["content"].lower()
    transitions = [event for event in repository.list_audit_events() if event.event_type == "proposal_provider_transition"]
    assert transitions[0].outcome == "retrying"


def test_rate_limit_blocks_only_matching_target_and_action_and_audits(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    now = [0.0]
    limiter = InMemoryRateLimiter(clock=lambda: now[0])
    proposal = PlanProposal(
        tool="nmap", profile="quick_recon", target="lab.example", port=80, rationale="Scoped reconnaissance."
    )
    first = gate_proposal(repository, context, proposal, "test", rate_limit_check=limiter)
    now[0] = 12.0
    blocked = gate_proposal(repository, context, proposal, "test", rate_limit_check=limiter)
    active = gate_proposal(
        repository,
        context,
        proposal,
        "test",
        action=ActionClass.ACTIVE_VALIDATION,
        rate_limit_check=limiter,
    )
    assert first.status == ProposalStatus.APPROVED
    assert blocked.status == ProposalStatus.BLOCKED
    assert "12s ago; wait 33s" in blocked.reason
    assert active.status == ProposalStatus.AWAITING_APPROVAL
    rate_events = [event for event in repository.list_audit_events() if event.event_type == "proposal_rate_limit"]
    assert {event.outcome for event in rate_events} == {"allowed", "denied"}
    denied = next(event for event in rate_events if event.outcome == "denied")
    assert denied.detail["remaining_wait_seconds"] == 33


def test_provider_slots_load_from_local_dotenv(tmp_path: Path, monkeypatch):
    (tmp_path / ".env").write_text(
        "PROVIDER_1_BASE_URL=https://provider.example/v1\nPROVIDER_1_API_KEY=local-secret\nPROVIDER_1_MODEL=free-model\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    for name in (
        "PROVIDER_1_BASE_URL",
        "PROVIDER_1_API_KEY",
        "PROVIDER_1_MODEL",
        "PROVIDER_2_BASE_URL",
        "PROVIDER_2_API_KEY",
        "PROVIDER_2_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    slots = provider_slots()
    assert [(slot.label, slot.base_url, slot.model) for slot in slots] == [
        ("provider_1", "https://provider.example/v1", "free-model")
    ]


def test_provider_slots_picks_up_live_dotenv_changes_without_polluting_os_environ(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PROVIDER_1_BASE_URL=https://provider.example/v1\nPROVIDER_1_API_KEY=key-1\nPROVIDER_1_MODEL=model-1\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    for name in (
        "PROVIDER_1_BASE_URL",
        "PROVIDER_1_API_KEY",
        "PROVIDER_1_MODEL",
        "PROVIDER_2_BASE_URL",
        "PROVIDER_2_API_KEY",
        "PROVIDER_2_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)

    # Initial read: exactly 1 slot with model-1
    initial = provider_slots()
    assert [(s.label, s.model) for s in initial] == [("provider_1", "model-1")]

    # User modifies .env while app is running: update model-1 and add a second provider slot
    env_file.write_text(
        "PROVIDER_1_BASE_URL=https://provider.example/v1\nPROVIDER_1_API_KEY=key-1\nPROVIDER_1_MODEL=updated-model-1\n"
        "PROVIDER_2_BASE_URL=https://provider.example/v2\nPROVIDER_2_API_KEY=key-2\nPROVIDER_2_MODEL=model-2\n",
        encoding="utf-8",
    )
    updated = provider_slots()
    assert [(s.label, s.model) for s in updated] == [
        ("provider_1", "updated-model-1"),
        ("provider_2", "model-2"),
    ]

    # Confirm absolutely no PROVIDER_* keys were written into os.environ
    assert [k for k in os.environ if k.startswith("PROVIDER_")] == []


def test_llm_markdown_fenced_json_is_parsed_and_supports_nikto(tmp_path: Path):
    repository, context = scope_context(tmp_path)
    # LLM returning JSON inside markdown code fences
    llm_output = """```json
{
  "tool": "nikto",
  "profile": "web_quick",
  "target": "lab.example",
  "port": 80,
  "rationale": "Investigate web server configuration and misconfigurations."
}
```"""
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1)],
        client=StaticClient(llm_output),
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.source == "provider_1"
    assert outcome.proposal.tool.value == "nikto"
    assert outcome.proposal.profile.value == "web_quick"
    assert outcome.proposal.port == 80


def test_deterministic_fallback_selects_nikto_for_web_request(tmp_path: Path):
    repository, _ = scope_context(tmp_path)
    web_context = ProposalContext(
        scope=register_scope(
            repository,
            ScopeRegistration(
                target="127.0.0.1",
                allowed_ports="3000",
                engagement_note="Lab",
                authorized_lab_attested=True,
            ),
        ),
        request="Scan the web application for vulnerabilities and misconfigurations.",
    )
    outcome = propose_and_gate(
        repository,
        web_context,
        slots=[slot(1)],
        client=FailingClient(),
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.source == "deterministic_fallback"
    assert outcome.proposal.tool.value == "nikto"
    assert outcome.proposal.port == 3000


def test_rate_limiter_allows_different_tools_sequentially(tmp_path: Path):
    limiter = InMemoryRateLimiter(window_seconds=10)
    scope = register_scope(
        Repository(tmp_path / "repo.db"),
        ScopeRegistration(
            target="127.0.0.1",
            allowed_ports="3000",
            engagement_note="Lab",
            authorized_lab_attested=True,
        ),
    )
    nmap_proposal = PlanProposal(
        tool="nmap",
        profile="quick_recon",
        target="127.0.0.1",
        port=3000,
        rationale="Port scan",
    )
    nikto_proposal = PlanProposal(
        tool="nikto",
        profile="web_quick",
        target="127.0.0.1",
        port=3000,
        rationale="Web scan",
    )

    # First call for Nmap passes
    d1 = limiter(scope, nmap_proposal, ActionClass.RECON)
    assert d1.allowed is True

    # Immediate second call for Nmap is rate-limited
    d2 = limiter(scope, nmap_proposal, ActionClass.RECON)
    assert d2.allowed is False

    # But call for Nikto on the same target and port passes immediately!
    d3 = limiter(scope, nikto_proposal, ActionClass.RECON)
    assert d3.allowed is True


def test_planning_prompt_catalog_includes_all_seven_tools_with_correct_statuses(tmp_path: Path):
    """Verify that the planning system prompt includes all 7 security tools and their truthful statuses."""
    from cipher_lens.services.planning import _messages

    _, context = scope_context(tmp_path)
    messages = _messages(context)
    system_prompt = next(m["content"] for m in messages if m["role"] == "system")

    # All 7 tools must be named
    assert "Nmap" in system_prompt
    assert "OWASP ZAP" in system_prompt
    assert "Nikto" in system_prompt
    assert "Burp Suite Community" in system_prompt
    assert "Nessus" in system_prompt
    assert "OpenVAS / Greenbone" in system_prompt
    assert "Metasploit" in system_prompt

    # Real statuses must be accurately reflected
    assert "Status: Live" in system_prompt
    assert "Status: Import-only" in system_prompt
    assert "Status: Planned" in system_prompt


def test_llm_proposal_with_import_tool_in_rationale_is_valid(tmp_path: Path):
    """LLM can mention Burp Suite in rationale/guidance while selecting a Live tool for execution."""
    import json
    repository, context = scope_context(tmp_path)
    llm_output = json.dumps({
        "tool": "nikto",
        "profile": "web_quick",
        "target": "lab.example",
        "port": 80,
        "rationale": "Burp Suite Community would help with manual intercept/repeater testing here, but it has no REST automation API in the free tier; run it manually and import the exported report via the Integration Matrix page.",
        "anticipated_next_steps": [
            {
                "tool": "zap",
                "profile": "active_scan",
                "rationale": "Follow up with ZAP active scanning once initial web misconfigurations are cataloged."
            }
        ]
    })
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1)],
        client=StaticClient(llm_output),
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.source == "provider_1"
    assert outcome.proposal.tool.value == "nikto"
    assert "Burp Suite Community" in outcome.proposal.rationale


def test_llm_proposal_with_import_tool_in_executable_tool_field_is_rejected(tmp_path: Path):
    """If the LLM selects an Import-only or Planned tool as the executable tool, schema rejection occurs."""
    import json
    repository, context = scope_context(tmp_path)
    # LLM erroneously puts burp_suite as the executable tool
    invalid_llm_output = json.dumps({
        "tool": "burp_suite",
        "profile": "web_quick",
        "target": "lab.example",
        "port": 80,
        "rationale": "Attempting automated scan with Burp Suite."
    })
    outcome = propose_and_gate(
        repository,
        context,
        slots=[slot(1)],
        client=StaticClient(invalid_llm_output),
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    # The provider fails schema validation and falls back to deterministic fallback
    assert outcome.status == ProposalStatus.APPROVED
    assert outcome.source == "deterministic_fallback"
    assert outcome.proposal.tool.value in {"nmap", "nikto", "zap"}


def test_gate_proposal_approves_active_validation_when_approval_recorded(tmp_path: Path):
    """Active validation is unlocked once an unexpired human approval exists in repository."""
    from cipher_lens.services.approvals import record_approval

    repository, context = scope_context(tmp_path)
    proposal = PlanProposal(
        tool="zap", profile="active_scan", target="lab.example", port=80, rationale="Active scan."
    )
    # Without approval, it should be AWAITING_APPROVAL
    outcome_unapproved = gate_proposal(
        repository,
        context,
        proposal,
        "test",
        action=ActionClass.ACTIVE_VALIDATION,
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome_unapproved.status == ProposalStatus.AWAITING_APPROVAL

    # Record valid human approval
    app_id = record_approval(
        repository,
        context.scope,
        target="lab.example",
        port=80,
        scheme="http",
        action=ActionClass.ACTIVE_VALIDATION,
        actor="Security Officer",
        rationale="Approved for lab target.",
        approved=True,
    )

    # Now gating should recognize the approval and transition to APPROVED
    outcome_approved = gate_proposal(
        repository,
        context,
        proposal,
        "test",
        action=ActionClass.ACTIVE_VALIDATION,
        rate_limit_check=lambda *_: RateLimitDecision(True, "ok", 0),
    )
    assert outcome_approved.status == ProposalStatus.APPROVED
    assert f"#{app_id[:8]}" in outcome_approved.reason
