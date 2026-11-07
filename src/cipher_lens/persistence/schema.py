"""SQLite schema for all persisted MVP entities, created before any scanner work."""

from __future__ import annotations

import sqlite3


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    canonical_target TEXT NOT NULL,
    allowed_ports TEXT NOT NULL,
    excluded_ports TEXT NOT NULL DEFAULT '',
    excluded_endpoints TEXT NOT NULL DEFAULT '',
    engagement_note TEXT NOT NULL,
    authorized_lab_attested INTEGER NOT NULL CHECK (authorized_lab_attested IN (0, 1)),
    allowed_actions TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES scopes(id),
    tool TEXT NOT NULL,
    profile TEXT,
    status TEXT NOT NULL,
    rationale TEXT,
    anticipated_next_steps TEXT NOT NULL DEFAULT '[]',
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT REFERENCES scan_runs(id),
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    tool TEXT NOT NULL,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT REFERENCES scan_runs(id),
    source_tool TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    canonical_title TEXT,
    description TEXT,
    severity TEXT,
    cvss REAL,
    cve TEXT,
    cwe TEXT,
    confidence TEXT,
    validation_status TEXT NOT NULL DEFAULT 'suspected',
    priority REAL,
    provenance_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT REFERENCES scan_runs(id),
    scope_id TEXT REFERENCES scopes(id),
    target TEXT,
    port INTEGER,
    scheme TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    decision_actor TEXT,
    decision_rationale TEXT,
    decided_at TEXT,
    expires_at TEXT,
    finding_id TEXT,
    requested_by TEXT,
    requested_rationale TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_scan_runs_scope_id ON scan_runs(scope_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_run_id ON evidence(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_run_id ON findings(scan_run_id);
"""


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    existing = {row[1] for row in connection.execute("PRAGMA table_info(approvals)")}
    for name, declaration in (
        ("scope_id", "TEXT"),
        ("target", "TEXT"),
        ("port", "INTEGER"),
        ("scheme", "TEXT"),
        ("decision_actor", "TEXT"),
        ("expires_at", "TEXT"),
        ("finding_id", "TEXT"),
        ("requested_by", "TEXT"),
        ("requested_rationale", "TEXT"),
    ):
        if name not in existing:
            connection.execute(f"ALTER TABLE approvals ADD COLUMN {name} {declaration}")
    scan_run_columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_runs)")}
    if "anticipated_next_steps" not in scan_run_columns:
        connection.execute("ALTER TABLE scan_runs ADD COLUMN anticipated_next_steps TEXT NOT NULL DEFAULT '[]'")
    findings_columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
    for name, declaration in (
        ("canonical_title", "TEXT"),
        ("priority", "REAL"),
        ("provenance_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        if name not in findings_columns:
            connection.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
    connection.commit()
