from pathlib import Path

from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.scope_registration import register_scope


def test_scope_registration_round_trip_and_audit_record(tmp_path: Path):
    database = tmp_path / "cipher.sqlite3"
    repository = Repository(database)
    created = register_scope(
        repository,
        ScopeRegistration(
            target="localhost",
            allowed_ports="8080",
            excluded_ports="",
            excluded_endpoints="",
            engagement_note="Authorized local lab.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON},
        ),
    )
    reopened = Repository(database)
    assert reopened.list_scopes()[0].canonical_target == "127.0.0.1"
    event = reopened.list_audit_events()[0]
    assert event.entity_id == created.id
    assert event.event_type == "scope_registration"
    assert event.outcome == "approved"
