"""Unit tests for finding normalization, deduplication, priority, and provenance."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError as PydanticValidationError

from cipher_lens.adapters.base import EvidenceArtifact, Finding
from cipher_lens.domain.findings import (
    FindingProvenance,
    NormalizedFinding,
    Severity,
    ValidationStatus,
)
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.findings import (
    calculate_priority_score,
    deduplication_key,
    derive_canonical_title,
    ingest_and_store_findings,
    normalize_and_correlate,
    normalize_asset,
    normalize_severity,
    sort_findings,
)


def test_normalize_severity_maps_tool_formats_safely():
    # Standard values
    assert normalize_severity("Critical") == Severity.CRITICAL
    assert normalize_severity("high") == Severity.HIGH
    assert normalize_severity("Medium") == Severity.MEDIUM
    assert normalize_severity("LOW") == Severity.LOW
    assert normalize_severity("info") == Severity.INFO

    # Tool-specific codes (e.g. ZAP risk scores, Nikto tags)
    assert normalize_severity("3") == Severity.HIGH
    assert normalize_severity("2") == Severity.MEDIUM
    assert normalize_severity("1") == Severity.LOW
    assert normalize_severity("0") == Severity.INFO
    assert normalize_severity("sev 1") == Severity.CRITICAL
    assert normalize_severity("warning") == Severity.MEDIUM
    assert normalize_severity("informational") == Severity.INFO

    # Missing or unrecognized formats default safely to Info without inventing severity
    assert normalize_severity(None) == Severity.INFO
    assert normalize_severity("") == Severity.INFO
    assert normalize_severity("   ") == Severity.INFO
    assert normalize_severity("unrecognized_tool_category") == Severity.INFO


def test_normalize_asset_cleans_protocol_and_slashes():
    assert normalize_asset("http://127.0.0.1:8080/") == "127.0.0.1:8080"
    assert normalize_asset("https://TARGET.local:443/api/v1/") == "target.local:443/api/v1"
    assert normalize_asset("192.168.1.10:80///") == "192.168.1.10:80"
    assert normalize_asset("http://demo.lab/path?query=1") == "demo.lab/path?query=1"
    assert normalize_asset("  HOST.example.org:22  ") == "host.example.org:22"
    assert normalize_asset("") == "unknown"


def test_derive_canonical_title_prefers_cve_and_cwe():
    # CVE takes highest precedence
    finding_cve = Finding(
        source_tool="zap",
        affected_asset="127.0.0.1:80",
        description="SQL Injection in login form parameter user.",
        cve="2023-1234",
    )
    assert derive_canonical_title(finding_cve) == "Vulnerability: CVE-2023-1234"

    # CWE takes second precedence
    finding_cwe = Finding(
        source_tool="nikto",
        affected_asset="127.0.0.1:80",
        description="Missing Anti-Clickjacking header X-Frame-Options.",
        cwe="CWE-1021",
    )
    assert derive_canonical_title(finding_cwe) == "Weakness: CWE-1021"

    # Fallback to concise description summary
    finding_desc = Finding(
        source_tool="nmap",
        affected_asset="127.0.0.1:80",
        description="Open http port observed; Nmap reason: syn-ack.",
    )
    assert derive_canonical_title(finding_desc) == "Open http port observed"


def test_deduplication_matching_cve_and_signature():
    # Same asset, same CVE -> duplicate
    key1 = deduplication_key("http://127.0.0.1:8080", "2023-9999", None, "SQL Injection")
    key2 = deduplication_key("127.0.0.1:8080/", "CVE-2023-9999", None, "Blind SQLi")
    assert key1 == key2

    # Same asset, same CWE -> duplicate
    key3 = deduplication_key("10.0.0.1:443", None, "CWE-79", "Reflected XSS")
    key4 = deduplication_key("10.0.0.1:443", None, "cwe-79", "Cross-site scripting")
    assert key3 == key4

    # Same asset, normalized title -> duplicate
    key5 = deduplication_key("10.0.0.1:80", None, None, "Directory Listing   Enabled")
    key6 = deduplication_key("10.0.0.1:80", None, None, "directory listing enabled")
    assert key5 == key6


def test_distinct_assets_are_never_merged():
    # Identical vulnerability on different assets must remain distinct findings
    f1 = Finding(
        source_tool="zap",
        affected_asset="192.168.1.5:80",
        description="Apache outdated version",
        cve="CVE-2021-41773",
        severity="Critical",
    )
    f2 = Finding(
        source_tool="zap",
        affected_asset="192.168.1.6:80",
        description="Apache outdated version",
        cve="CVE-2021-41773",
        severity="Critical",
    )
    correlated = normalize_and_correlate([f1, f2])
    assert len(correlated) == 2
    assets = {f.affected_asset for f in correlated}
    assert assets == {"192.168.1.5:80", "192.168.1.6:80"}


def test_consolidation_merges_provenance_and_highest_metrics():
    evidence_nikto = EvidenceArtifact(
        id="evi-nikto-1",
        file_path=Path("/tmp/nikto.xml"),
        sha256="aaa111",
        tool="nikto",
        captured_at=datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc),
    )
    evidence_zap = EvidenceArtifact(
        id="evi-zap-1",
        file_path=Path("/tmp/zap.json"),
        sha256="bbb222",
        tool="zap",
        captured_at=datetime(2026, 11, 8, 12, 5, tzinfo=timezone.utc),
    )

    finding_nikto = Finding(
        source_tool="nikto",
        affected_asset="http://10.0.0.1:8080/app",
        description="Web application reveals internal debugging information.",
        severity="medium",
        cvss=4.5,
        cwe="CWE-200",
        confidence="observed",
        validation_status="suspected",
    )
    finding_zap = Finding(
        source_tool="zap",
        affected_asset="10.0.0.1:8080/app/",
        description="Information Disclosure: sensitive application stack trace disclosed in error page.",
        severity="high",
        cvss=7.5,
        cwe="CWE-200",
        confidence="confirmed",
        validation_status="confirmed",
    )

    # Ingest from both tools
    nikto_norm = normalize_and_correlate([finding_nikto], evidence_nikto, "run-1")
    zap_norm = normalize_and_correlate([finding_zap], evidence_zap, "run-2")

    # Ingest combined
    combined = normalize_and_correlate(
        [finding_nikto, finding_zap], evidence_zap, "run-combined"
    )

    assert len(combined) == 1
    merged = combined[0]
    assert merged.affected_asset == "10.0.0.1:8080/app"
    assert merged.severity == Severity.HIGH  # Highest severity
    assert merged.cvss == 7.5  # Highest CVSS
    assert merged.validation_status == ValidationStatus.CONFIRMED
    assert merged.confidence == "confirmed"

    # Multi-tool corroboration: Nikto and ZAP both reported this
    tools_in_provenance = {p.source_tool for p in merged.provenance}
    assert tools_in_provenance == {"nikto", "zap"}


def test_deterministic_priority_scoring_formula():
    # Critical without CVSS (base 10.0) + confirmed (+1.0) -> clamped to 10.0
    score1 = calculate_priority_score(Severity.CRITICAL, None, ValidationStatus.CONFIRMED, 1)
    assert score1 == 10.0

    # High with CVSS 7.2 + suspected (-0.5) + corroborated (+0.5) -> 7.2
    score2 = calculate_priority_score(Severity.HIGH, 7.2, ValidationStatus.SUSPECTED, 2)
    assert score2 == 7.2

    # Medium without CVSS (base 5.0) + not_validated (0.0) + 1 tool (0.0) -> 5.0
    score3 = calculate_priority_score(Severity.MEDIUM, None, ValidationStatus.NOT_VALIDATED, 1)
    assert score3 == 5.0

    # Low without CVSS (base 2.0) + suspected (-0.5) -> 1.5
    score4 = calculate_priority_score(Severity.LOW, None, ValidationStatus.SUSPECTED, 1)
    assert score4 == 1.5

    # Info without CVSS (base 0.0) + suspected (-0.5) -> clamped to 0.0
    score5 = calculate_priority_score(Severity.INFO, None, ValidationStatus.SUSPECTED, 1)
    assert score5 == 0.0


def test_deterministic_sort_order():
    f_info = NormalizedFinding(
        canonical_title="Open Port 80",
        affected_asset="127.0.0.1:80",
        description="Nmap open port",
        severity=Severity.INFO,
        priority_score=0.0,
    )
    f_med = NormalizedFinding(
        canonical_title="Missing CSP Header",
        affected_asset="127.0.0.1:80",
        description="Weakness in headers",
        severity=Severity.MEDIUM,
        priority_score=5.0,
    )
    f_high = NormalizedFinding(
        canonical_title="SQL Injection",
        affected_asset="127.0.0.1:80",
        description="Critical SQL injection",
        severity=Severity.HIGH,
        priority_score=8.5,
    )
    f_crit = NormalizedFinding(
        canonical_title="Remote Code Execution",
        affected_asset="127.0.0.1:8080",
        description="Unauthenticated RCE",
        severity=Severity.CRITICAL,
        priority_score=10.0,
    )

    sorted_list = sort_findings([f_info, f_crit, f_med, f_high])
    assert [f.canonical_title for f in sorted_list] == [
        "Remote Code Execution",
        "SQL Injection",
        "Missing CSP Header",
        "Open Port 80",
    ]


def test_missing_optional_fields_are_handled_safely():
    finding = Finding(
        source_tool="custom_tool",
        affected_asset="10.10.10.10",
        description="Service header disclosure.",
        severity=None,
        cvss=None,
        cve=None,
        cwe=None,
        confidence=None,
    )
    correlated = normalize_and_correlate([finding])
    assert len(correlated) == 1
    res = correlated[0]
    assert res.severity == Severity.INFO
    assert res.cvss is None
    assert res.cve is None
    assert res.cwe is None
    assert res.confidence == "observed"
    assert res.validation_status == ValidationStatus.SUSPECTED


def test_extra_fields_forbidden_in_domain_models():
    with pytest.raises(PydanticValidationError):
        NormalizedFinding(
            canonical_title="Test",
            affected_asset="127.0.0.1",
            description="Test description",
            severity=Severity.INFO,
            priority_score=0.0,
            ai_hallucinated_field="forbidden_payload",  # extra field
        )

    with pytest.raises(PydanticValidationError):
        FindingProvenance(
            source_tool="zap",
            unknown_parameter="forbidden",
        )


def test_ingest_and_store_findings_persists_to_repository_and_audits(tmp_path: Path):
    db_file = tmp_path / "test_findings.db"
    repository = Repository(db_file)

    # Setup parent scope and scan_run
    from cipher_lens.domain.models import ActionClass, ScopeRegistration
    from cipher_lens.services.scope_registration import register_scope

    scope = register_scope(
        repository,
        ScopeRegistration(
            target="127.0.0.1",
            allowed_ports="80,443",
            engagement_note="Finding ingestion test",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON},
        ),
    )
    run_id = str(uuid4())
    repository.create_scan_run(run_id, scope.id, "zap", "quick_recon", "done", "test run")

    evidence = EvidenceArtifact(
        id="evi-1",
        file_path=tmp_path / "zap.json",
        sha256="c0ffee1234",
        tool="zap",
        captured_at=datetime.now(timezone.utc),
    )

    raw_findings = [
        Finding(
            source_tool="zap",
            affected_asset="http://127.0.0.1:80/login",
            description="SQL Injection in auth form.",
            severity="High",
            cvss=8.1,
            cve="2023-5555",
            confidence="observed",
        ),
        Finding(
            source_tool="zap",
            affected_asset="127.0.0.1:80/login/",
            description="Duplicate SQL Injection in auth form.",
            severity="High",
            cvss=8.1,
            cve="CVE-2023-5555",
            confidence="observed",
        ),
    ]

    correlated = ingest_and_store_findings(repository, run_id, raw_findings, evidence)

    # Verification 1: Exactly 1 consolidated finding persisted (deduplicated)
    assert len(correlated) == 1
    persisted = repository.list_findings(scan_run_id=run_id)
    assert len(persisted) == 1
    assert persisted[0].canonical_title == "Vulnerability: CVE-2023-5555"
    assert persisted[0].severity == Severity.HIGH
    assert persisted[0].cvss == 8.1
    assert len(persisted[0].provenance) == 1  # Deduplicated provenance for identical tool/run
    assert persisted[0].provenance[0].sha256 == "c0ffee1234"

    # Verification 2: Query by scope_id returns the finding
    scope_findings = repository.list_findings(scope_id=scope.id)
    assert len(scope_findings) == 1
    assert scope_findings[0].id == persisted[0].id

    # Verification 3: Audit event recorded
    events = repository.list_audit_events()
    ingest_event = next(e for e in events if e.event_type == "findings_ingested")
    assert ingest_event.outcome == "correlated"
    assert ingest_event.entity_id == run_id
    assert ingest_event.detail["raw_count"] == 2
    assert ingest_event.detail["correlated_count"] == 1
    assert ingest_event.detail["duplicate_count"] == 1
