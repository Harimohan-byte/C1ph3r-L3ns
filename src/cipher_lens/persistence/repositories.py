"""SQLite access layer. UI and adapters never write directly to the database."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from cipher_lens.domain.models import AuditEvent, ScopeRecord, ScopeRegistration
from cipher_lens.persistence.schema import initialize


class Repository:
    def __init__(self, database: Path) -> None:
        self.database = database
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            initialize(connection)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_scope(self, scope: ScopeRecord) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO scopes (
                    id, target, canonical_target, allowed_ports, excluded_ports, excluded_endpoints,
                    engagement_note, authorized_lab_attested, allowed_actions, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.id,
                    scope.target,
                    scope.canonical_target,
                    scope.allowed_ports,
                    scope.excluded_ports,
                    scope.excluded_endpoints,
                    scope.engagement_note,
                    int(scope.authorized_lab_attested),
                    json.dumps(sorted(action.value for action in scope.allowed_actions)),
                    scope.created_at.isoformat(),
                ),
            )

    def list_scopes(self) -> list[ScopeRecord]:
        from cipher_lens.domain.models import ActionClass
        from datetime import datetime

        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM scopes ORDER BY created_at DESC").fetchall()
        return [
            ScopeRecord(
                id=row["id"],
                target=row["target"],
                canonical_target=row["canonical_target"],
                allowed_ports=row["allowed_ports"],
                excluded_ports=row["excluded_ports"],
                excluded_endpoints=row["excluded_endpoints"],
                engagement_note=row["engagement_note"],
                authorized_lab_attested=bool(row["authorized_lab_attested"]),
                allowed_actions={ActionClass(action) for action in json.loads(row["allowed_actions"])},
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def append_audit(self, event: AuditEvent) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (id, occurred_at, event_type, outcome, entity_type, entity_id, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.occurred_at.isoformat(),
                    event.event_type,
                    event.outcome,
                    event.entity_type,
                    event.entity_id,
                    json.dumps(event.detail, sort_keys=True),
                ),
            )

    def list_audit_events(self) -> list[AuditEvent]:
        from datetime import datetime

        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY occurred_at DESC").fetchall()
        return [
            AuditEvent(
                id=row["id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                event_type=row["event_type"],
                outcome=row["outcome"],
                entity_type=row["entity_type"],
                entity_id=row["entity_id"],
                detail=json.loads(row["detail_json"]),
            )
            for row in rows
        ]
