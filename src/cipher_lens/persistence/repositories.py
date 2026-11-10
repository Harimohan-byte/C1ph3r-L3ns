"""SQLite access layer. UI and adapters never write directly to the database."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from cipher_lens.domain.models import AuditEvent, ScopeRecord, ScopeRegistration
from cipher_lens.domain.findings import (
    FindingProvenance,
    NormalizedFinding,
    Severity,
    ValidationStatus,
)
from cipher_lens.persistence.schema import initialize


@dataclass(frozen=True)
class ScanRunSummary:
    """Read-only projection for the analyst status workspace."""

    id: str
    scope_id: str
    target: str
    tool: str
    profile: str | None
    status: str
    rationale: str | None
    anticipated_next_steps: list[dict[str, str]]
    started_at: str | None
    completed_at: str | None
    error_message: str | None


@dataclass(frozen=True)
class ApprovalSummary:
    """Read-only approval projection; decisions remain owned by a later workflow."""

    id: str
    scope_id: str | None
    target: str | None
    port: int | None
    scheme: str | None
    action: str
    status: str
    decision_actor: str | None
    decision_rationale: str | None
    decided_at: str | None
    expires_at: str | None
    finding_id: str | None = None
    requested_by: str | None = None
    requested_rationale: str | None = None


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

    def save_evidence(self, artifact: object, scan_run_id: str | None) -> None:
        """Persist the immutable artifact fields owned by the adapter contract."""
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO evidence (id, scan_run_id, file_path, sha256, tool, captured_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.id,
                    scan_run_id,
                    str(artifact.file_path),
                    artifact.sha256,
                    artifact.tool,
                    artifact.captured_at.isoformat(),
                ),
            )

    def create_scan_run(
        self, run_id: str, scope_id: str, tool: str, profile: str, status: str,
        rationale: str | None = None, anticipated_next_steps: list[dict[str, str]] | None = None,
    ) -> None:
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO scan_runs (id, scope_id, tool, profile, status, rationale, anticipated_next_steps, started_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (run_id, scope_id, tool, profile, status, rationale, json.dumps(anticipated_next_steps or [])),
            )

    def update_scan_run(self, run_id: str, status: str, error_message: str | None = None) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE scan_runs SET status = ?, error_message = ?, completed_at = CASE WHEN ? IN ('done', 'failed', 'blocked') THEN datetime('now') ELSE completed_at END WHERE id = ?",
                (status, error_message, status, run_id),
            )

    def list_scan_runs(self, scope_id: str | None = None) -> list[ScanRunSummary]:
        """Read persisted run state for the status UI; this method never changes a run."""
        query = """
            SELECT scan_runs.*, scopes.canonical_target AS target
            FROM scan_runs JOIN scopes ON scopes.id = scan_runs.scope_id
        """
        parameters: tuple[str, ...] = ()
        if scope_id is not None:
            query += " WHERE scan_runs.scope_id = ?"
            parameters = (scope_id,)
        query += " ORDER BY scan_runs.started_at DESC, scan_runs.id DESC"
        with self.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            ScanRunSummary(
                id=row["id"], scope_id=row["scope_id"], target=row["target"], tool=row["tool"],
                profile=row["profile"], status=row["status"], rationale=row["rationale"],
                anticipated_next_steps=json.loads(row["anticipated_next_steps"] or "[]"),
                started_at=row["started_at"], completed_at=row["completed_at"], error_message=row["error_message"],
            )
            for row in rows
        ]

    def list_approvals(
        self, scope_id: str | None = None, status: str | None = None
    ) -> list[ApprovalSummary]:
        """Read durable approval decisions for display without exposing mutation from the UI."""
        query = "SELECT * FROM approvals"
        conditions: list[str] = []
        parameters: list[str] = []
        if scope_id is not None:
            conditions.append("scope_id = ?")
            parameters.append(scope_id)
        if status is not None:
            conditions.append("status = ?")
            parameters.append(status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY COALESCE(decided_at, id) DESC, id DESC"
        with self.connection() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        results: list[ApprovalSummary] = []
        for row in rows:
            keys = row.keys()
            results.append(
                ApprovalSummary(
                    id=row["id"],
                    scope_id=row["scope_id"],
                    target=row["target"],
                    port=row["port"],
                    scheme=row["scheme"],
                    action=row["action"],
                    status=row["status"],
                    decision_actor=row["decision_actor"],
                    decision_rationale=row["decision_rationale"],
                    decided_at=row["decided_at"],
                    expires_at=row["expires_at"],
                    finding_id=row["finding_id"] if "finding_id" in keys else None,
                    requested_by=row["requested_by"] if "requested_by" in keys else None,
                    requested_rationale=row["requested_rationale"] if "requested_rationale" in keys else None,
                )
            )
        return results

    def get_approval(self, approval_id: str) -> ApprovalSummary | None:
        """Fetch a single approval record by its unique identifier."""
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            return None
        keys = row.keys()
        return ApprovalSummary(
            id=row["id"],
            scope_id=row["scope_id"],
            target=row["target"],
            port=row["port"],
            scheme=row["scheme"],
            action=row["action"],
            status=row["status"],
            decision_actor=row["decision_actor"],
            decision_rationale=row["decision_rationale"],
            decided_at=row["decided_at"],
            expires_at=row["expires_at"],
            finding_id=row["finding_id"] if "finding_id" in keys else None,
            requested_by=row["requested_by"] if "requested_by" in keys else None,
            requested_rationale=row["requested_rationale"] if "requested_rationale" in keys else None,
        )

    def create_approval_request(
        self,
        approval_id: str,
        scope_id: str,
        target: str,
        port: int,
        scheme: str | None,
        action: str,
        status: str,
        requested_by: str,
        requested_rationale: str,
        finding_id: str | None = None,
    ) -> None:
        """Persist a new pending approval request awaiting human decision."""
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO approvals (id, scope_id, target, port, scheme, action, status,
                   requested_by, requested_rationale, finding_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (approval_id, scope_id, target, port, scheme, action, status,
                 requested_by, requested_rationale, finding_id),
            )

    def update_approval_decision(
        self,
        approval_id: str,
        status: str,
        actor: str,
        rationale: str,
        expires_at: datetime | None = None,
    ) -> None:
        """Update an existing approval with an auditable terminal decision."""
        with self.connection() as connection:
            connection.execute(
                """UPDATE approvals
                   SET status = ?, decision_actor = ?, decision_rationale = ?,
                       decided_at = datetime('now'),
                       expires_at = ?
                   WHERE id = ?""",
                (status, actor, rationale, expires_at.isoformat() if expires_at else None, approval_id),
            )

    def save_adapter_approval(
        self, approval_id: str, scope_id: str, target: str, port: int, scheme: str | None,
        action: str, status: str, actor: str, rationale: str, expires_at: datetime,
    ) -> None:
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO approvals (id, scope_id, target, port, scheme, action, status,
                   decision_actor, decision_rationale, decided_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (approval_id, scope_id, target, port, scheme, action, status, actor, rationale,
                 datetime.now(timezone.utc).isoformat(), expires_at.isoformat()),
            )

    def verify_adapter_approval(
        self, approval_id: str, scope_id: str, target: str, port: int, scheme: str | None, action: str
    ) -> tuple[bool, str]:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            return False, "No recorded approval exists for this request."
        if row["status"] != "approved":
            return False, "The recorded approval is not approved."
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            return False, "The recorded approval has expired."
        # Target, scope, port, and action must match.
        # Scheme matches if identical, or if the recorded approval has no scheme restriction (scheme is None).
        scheme_matches = (row["scheme"] is None) or (row["scheme"] == scheme)
        if (
            row["scope_id"] != scope_id
            or row["target"] != target
            or row["port"] != port
            or not scheme_matches
            or row["action"] != action
        ):
            return False, "The recorded approval does not match this exact request."
        return True, "Recorded approval matches this request."

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

    def save_findings(self, findings: list[NormalizedFinding]) -> None:
        """Persist normalized, correlated findings and their provenance."""
        with self.connection() as connection:
            for finding in findings:
                tools = (
                    ", ".join(sorted({p.source_tool for p in finding.provenance}))
                    if finding.provenance
                    else "unknown"
                )
                connection.execute(
                    """
                    INSERT INTO findings (
                        id, scan_run_id, source_tool, affected_asset, canonical_title,
                        description, severity, cvss, cve, cwe, confidence, validation_status,
                        priority, provenance_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        scan_run_id = excluded.scan_run_id,
                        source_tool = excluded.source_tool,
                        affected_asset = excluded.affected_asset,
                        canonical_title = excluded.canonical_title,
                        description = excluded.description,
                        severity = excluded.severity,
                        cvss = excluded.cvss,
                        cve = excluded.cve,
                        cwe = excluded.cwe,
                        confidence = excluded.confidence,
                        validation_status = excluded.validation_status,
                        priority = excluded.priority,
                        provenance_json = excluded.provenance_json
                    """,
                    (
                        finding.id,
                        finding.scan_run_id,
                        tools,
                        finding.affected_asset,
                        finding.canonical_title,
                        finding.description,
                        finding.severity.value,
                        finding.cvss,
                        finding.cve,
                        finding.cwe,
                        finding.confidence,
                        finding.validation_status.value,
                        finding.priority_score,
                        json.dumps([p.model_dump() for p in finding.provenance]),
                    ),
                )

    def list_findings(
        self, scan_run_id: str | None = None, scope_id: str | None = None
    ) -> list[NormalizedFinding]:
        """Read persisted normalized findings ordered by priority score descending."""
        query = "SELECT findings.* FROM findings"
        parameters: list[str] = []
        if scan_run_id is not None:
            query += " WHERE findings.scan_run_id = ?"
            parameters.append(scan_run_id)
        elif scope_id is not None:
            query += " JOIN scan_runs ON scan_runs.id = findings.scan_run_id WHERE scan_runs.scope_id = ?"
            parameters.append(scope_id)
        query += " ORDER BY findings.priority DESC, findings.affected_asset ASC"

        with self.connection() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()

        results: list[NormalizedFinding] = []
        for row in rows:
            prov_raw = json.loads(row["provenance_json"] or "[]")
            provenance = [FindingProvenance.model_validate(item) for item in prov_raw]
            sev_val = row["severity"]
            severity = (
                Severity(sev_val) if sev_val in Severity._value2member_map_ else Severity.INFO
            )
            val_stat = row["validation_status"]
            validation_status = (
                ValidationStatus(val_stat)
                if val_stat in ValidationStatus._value2member_map_
                else ValidationStatus.SUSPECTED
            )
            results.append(
                NormalizedFinding(
                    id=row["id"],
                    scan_run_id=row["scan_run_id"],
                    canonical_title=row["canonical_title"] or "Security finding",
                    affected_asset=row["affected_asset"],
                    description=row["description"] or "",
                    severity=severity,
                    cvss=row["cvss"],
                    cve=row["cve"],
                    cwe=row["cwe"],
                    confidence=row["confidence"] or "observed",
                    validation_status=validation_status,
                    priority_score=row["priority"] if row["priority"] is not None else 0.0,
                    provenance=provenance,
                )
            )
        return results

    def delete_scope(self, scope_id: str) -> None:
        """Delete a single scope and all its associated scan runs, findings, evidence, and approvals."""
        with self.connection() as connection:
            rows = connection.execute("SELECT id FROM scan_runs WHERE scope_id = ?", (scope_id,)).fetchall()
            run_ids = [row["id"] for row in rows]
            if run_ids:
                placeholders = ",".join("?" for _ in run_ids)
                connection.execute(f"DELETE FROM findings WHERE scan_run_id IN ({placeholders})", run_ids)
                connection.execute(f"DELETE FROM evidence WHERE scan_run_id IN ({placeholders})", run_ids)
            connection.execute("DELETE FROM approvals WHERE scope_id = ?", (scope_id,))
            connection.execute("DELETE FROM scan_runs WHERE scope_id = ?", (scope_id,))
            connection.execute("DELETE FROM scopes WHERE id = ?", (scope_id,))

    def reset_database(self) -> None:
        """Clear all stored data for lab reset/fresh demonstration."""
        with self.connection() as connection:
            connection.execute("DELETE FROM findings")
            connection.execute("DELETE FROM evidence")
            connection.execute("DELETE FROM approvals")
            connection.execute("DELETE FROM scan_runs")
            connection.execute("DELETE FROM audit_events")
            connection.execute("DELETE FROM scopes")

