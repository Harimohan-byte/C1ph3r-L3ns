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

    # Initial read
    assert len(provider_slots()) == 1

    # User modifies .env while app is running to add second provider slot
    env_file.write_text(
        "PROVIDER_1_BASE_URL=https://provider.example/v1\nPROVIDER_1_API_KEY=key-1\nPROVIDER_1_MODEL=model-1\n"
        "PROVIDER_2_BASE_URL=https://provider.example/v2\nPROVIDER_2_API_KEY=key-2\nPROVIDER_2_MODEL=model-2\n",
        encoding="utf-8",
    )
    updated = provider_slots()
    assert len(updated) == 2
    assert updated[1].model == "model-2"

    # Confirm config did not leak into os.environ
    assert "PROVIDER_1_API_KEY" not in os.environ
    assert "PROVIDER_2_API_KEY" not in os.environ
