"""Evidence-grounded finding normalization, deduplication, and deterministic priority.

This service normalizes raw scanner/import outputs into standard, typed findings,
consolidates duplicate findings across tools without discarding evidence provenance,
and computes a stable review priority without LLM inference or arbitrary scoring.
"""

from __future__ import annotations

import re
from typing import Sequence
from urllib.parse import urlparse
from uuid import uuid4

from cipher_lens.adapters.base import EvidenceArtifact, Finding
from cipher_lens.config import nvd_api_key
from cipher_lens.domain.findings import (
    FindingProvenance,
    NormalizedFinding,
    Severity,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    ValidationStatus,
)
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.audit import record
from cipher_lens.services.nvd import enrich_finding_with_nvd


def normalize_severity(raw_severity: str | None) -> Severity:
    """Map tool-specific severity strings or numbers to standard Severity enum."""
    if not raw_severity:
        return Severity.INFO

    cleaned = raw_severity.strip().lower()
    if cleaned in {"critical", "crit", "sev1", "sev 1", "urgent"}:
        return Severity.CRITICAL
    if cleaned in {"high", "sev2", "sev 2", "error", "3"}:
        return Severity.HIGH
    if cleaned in {"medium", "med", "sev3", "sev 3", "warn", "warning", "moderate", "2"}:
        return Severity.MEDIUM
    if cleaned in {"low", "sev4", "sev 4", "1"}:
        return Severity.LOW
    if cleaned in {"info", "informational", "information", "notice", "note", "0", "none"}:
        return Severity.INFO

    return Severity.INFO


def normalize_asset(asset: str) -> str:
    """Normalize affected asset string (URL or host:port or IP) to canonical form."""
    cleaned = asset.strip()
    if not cleaned:
        return "unknown"

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        if parsed.query:
            path += f"?{parsed.query}"
        return f"{netloc}{path}" if path else netloc

    cleaned = cleaned.rstrip("/")
    if "/" in cleaned:
        parts = cleaned.split("/", 1)
        return f"{parts[0].lower()}/{parts[1]}"
    return cleaned.lower()


def derive_canonical_title(finding: Finding) -> str:
    """Derive a concise, standardized title without inventing facts."""
    if finding.cve:
        cve_clean = finding.cve.strip().upper()
        if not cve_clean.startswith("CVE-"):
            cve_clean = f"CVE-{cve_clean}"
        return f"Vulnerability: {cve_clean}"

    if finding.cwe:
        cwe_clean = finding.cwe.strip().upper()
        return f"Weakness: {cwe_clean}"

    desc = finding.description.strip()
    # Split on sentence ending (period followed by whitespace or end), newlines, or semicolons
    # Avoid splitting on internal periods in filenames (.txt, .php), version strings (2.4.41), or IPs
    clauses = re.split(r"(?:\.(?:\s+|$)|[\r\n]+|;\s*)", desc)
    first_clause = clauses[0].strip() if clauses else ""
    if first_clause:
        if len(first_clause) > 80:
            truncated = first_clause[:77]
            last_space = truncated.rfind(" ")
            if last_space > 40:
                truncated = truncated[:last_space]
            truncated = truncated.rstrip(",;- ")
            open_parens = truncated.count("(")
            close_parens = truncated.count(")")
            if open_parens > close_parens:
                truncated += ")" * (open_parens - close_parens)
            first_clause = f"{truncated}..."
        return first_clause

    return f"Security observation from {finding.source_tool}"


def deduplication_key(asset: str, cve: str | None, cwe: str | None, title: str) -> tuple[str, str]:
    """Formulate deterministic deduplication tuple (normalized_asset, signature)."""
    norm_asset = normalize_asset(asset)
    if cve and cve.strip():
        cve_clean = cve.strip().upper()
        if not cve_clean.startswith("CVE-"):
            cve_clean = f"CVE-{cve_clean}"
        return (norm_asset, f"cve:{cve_clean}")

    if cwe and cwe.strip():
        return (norm_asset, f"cwe:{cwe.strip().upper()}")

    norm_title = re.sub(r"\s+", " ", title.strip().lower())
    return (norm_asset, f"title:{norm_title}")


def calculate_priority_score(
    severity: Severity,
    cvss: float | None,
    validation_status: ValidationStatus,
    corroborating_tool_count: int,
) -> float:
    """Calculate deterministic review priority score from 0.0 to 10.0.

    Formula (approved in Phase 5 clarification):
      base = cvss if (cvss is not None and cvss > 0) else SEVERITY_WEIGHTS[severity]
      validation_adjustment = +1.0 (confirmed) | -0.5 (suspected) | 0.0 (not_validated)
      corroboration_bonus = +0.5 (if corroborated by >1 tool)
    """
    base_score = cvss if (cvss is not None and cvss > 0.0) else SEVERITY_WEIGHTS[severity]

    adjustment = 0.0
    if validation_status == ValidationStatus.CONFIRMED:
        adjustment += 1.0
    elif validation_status == ValidationStatus.SUSPECTED:
        adjustment -= 0.5

    if corroborating_tool_count > 1:
        adjustment += 0.5

    score = base_score + adjustment
    return round(max(0.0, min(10.0, score)), 2)


def sort_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Sort findings deterministically by priority, severity, asset, and title."""
    return sorted(
        findings,
        key=lambda item: (
            -item.priority_score,
            -SEVERITY_WEIGHTS[item.severity],
            item.affected_asset,
            item.canonical_title,
        ),
    )


def _merge_validation_status(statuses: Sequence[str]) -> ValidationStatus:
    """Derive merged validation status without lowering confirmed findings."""
    cleaned = {s.strip().lower() for s in statuses}
    if ValidationStatus.CONFIRMED.value in cleaned:
        return ValidationStatus.CONFIRMED
    if ValidationStatus.NOT_VALIDATED.value in cleaned:
        return ValidationStatus.NOT_VALIDATED
    if ValidationStatus.VALIDATION_BLOCKED.value in cleaned:
        return ValidationStatus.VALIDATION_BLOCKED
    if ValidationStatus.FALSE_POSITIVE.value in cleaned:
        return ValidationStatus.FALSE_POSITIVE
    return ValidationStatus.SUSPECTED


def _merge_confidence(confidences: Sequence[str | None]) -> str:
    """Derive merged confidence level prioritizing confirmed > observed > suspected."""
    cleaned = {c.strip().lower() for c in confidences if c}
    if "confirmed" in cleaned:
        return "confirmed"
    if "observed" in cleaned:
        return "observed"
    if cleaned:
        return next(iter(cleaned))
    return "observed"


def normalize_and_correlate(
    findings: Sequence[Finding],
    evidence: EvidenceArtifact | None = None,
    scan_run_id: str | None = None,
) -> list[NormalizedFinding]:
    """Pure transformation: normalize findings and consolidate duplicates with full provenance."""
    grouped: dict[tuple[str, str], list[tuple[Finding, FindingProvenance]]] = {}

    for finding in findings:
        prov = FindingProvenance(
            source_tool=finding.source_tool,
            scan_run_id=scan_run_id,
            evidence_id=evidence.id if evidence else None,
            file_path=str(evidence.file_path) if evidence else None,
            sha256=evidence.sha256 if evidence else None,
            raw_reference=None,
            captured_at=evidence.captured_at.isoformat() if evidence else None,
        )
        title = derive_canonical_title(finding)
        key = deduplication_key(finding.affected_asset, finding.cve, finding.cwe, title)
        grouped.setdefault(key, []).append((finding, prov))

    correlated: list[NormalizedFinding] = []

    for (_asset_key, _sig_key), pairs in grouped.items():
        raw_items = [p[0] for p in pairs]
        provenances = [p[1] for p in pairs]

        # Consolidated affected asset
        norm_asset = normalize_asset(raw_items[0].affected_asset)

        # Consolidated canonical title
        title = derive_canonical_title(raw_items[0])

        # Highest severity
        severities = [normalize_severity(f.severity) for f in raw_items]
        highest_severity = max(severities, key=lambda s: SEVERITY_ORDER.index(s))

        # Highest CVSS score if evidenced
        valid_cvss = [f.cvss for f in raw_items if f.cvss is not None and f.cvss > 0.0]
        highest_cvss = max(valid_cvss) if valid_cvss else None

        # Evidence-grounded CVE and CWE
        cve = next((f.cve.strip().upper() for f in raw_items if f.cve and f.cve.strip()), None)
        if cve and not cve.startswith("CVE-"):
            cve = f"CVE-{cve}"
        cwe = next((f.cwe.strip().upper() for f in raw_items if f.cwe and f.cwe.strip()), None)

        # Merged description (use longest / most detailed description)
        descriptions = [f.description.strip() for f in raw_items if f.description]
        primary_desc = max(descriptions, key=len) if descriptions else "No description available."

        # Merged status and confidence
        val_status = _merge_validation_status([f.validation_status for f in raw_items])
        confidence = _merge_confidence([f.confidence for f in raw_items])

        # Deduplicate provenance entries
        seen_prov: set[tuple[str, str | None, str | None]] = set()
        unique_prov: list[FindingProvenance] = []
        for prov in provenances:
            prov_key = (prov.source_tool, prov.scan_run_id, prov.sha256)
            if prov_key not in seen_prov:
                seen_prov.add(prov_key)
                unique_prov.append(prov)

        distinct_tools = len({p.source_tool for p in unique_prov})
        priority = calculate_priority_score(highest_severity, highest_cvss, val_status, distinct_tools)

        finding_id = str(uuid4())
        correlated.append(
            NormalizedFinding(
                id=finding_id,
                canonical_title=title,
                affected_asset=norm_asset,
                description=primary_desc,
                severity=highest_severity,
                cvss=highest_cvss,
                cve=cve,
                cwe=cwe,
                confidence=confidence,
                validation_status=val_status,
                priority_score=priority,
                provenance=unique_prov,
                scan_run_id=scan_run_id,
            )
        )

    return sort_findings(correlated)


def ingest_and_store_findings(
    repository: Repository,
    scan_run_id: str,
    findings: Sequence[Finding],
    evidence: EvidenceArtifact | None = None,
    api_key: str | None = None,
) -> list[NormalizedFinding]:
    """Correlate parsed scanner findings, persist to SQLite, and write an audit event.

    Enriches findings with CVE/CVSS at Result Ingestion time:
    - Tier 1: Scanners (Nikto, ZAP) natively populate CVE/CWE tokens.
    - Tier 2: If finding carries a scanner-captured product & version and lacks CVE,
      enrich via NIST NVD API 2.0 (if configured).
    """
    effective_api_key = api_key if api_key is not None else nvd_api_key()
    enriched = [enrich_finding_with_nvd(f, api_key=effective_api_key) for f in findings]

    correlated = normalize_and_correlate(enriched, evidence, scan_run_id)
    repository.save_findings(correlated)

    record(
        repository,
        event_type="findings_ingested",
        outcome="correlated",
        entity_type="scan_run",
        entity_id=scan_run_id,
        detail={
            "scan_run_id": scan_run_id,
            "raw_count": len(findings),
            "correlated_count": len(correlated),
            "duplicate_count": len(findings) - len(correlated),
            "finding_ids": [f.id for f in correlated],
        },
    )

    return correlated
