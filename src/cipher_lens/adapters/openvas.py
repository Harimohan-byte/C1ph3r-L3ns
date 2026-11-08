"""OpenVAS / Greenbone Community Edition import-only report adapter."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import uuid4

from cipher_lens.adapters.base import (
    AdapterContext,
    AdapterRequest,
    Finding,
    ParseResult,
    PollResult,
    RunHandle,
    ScanRunStatus,
    ToolAdapter,
    ValidationResult,
)
from cipher_lens.services.audit import record


def _matches_target(observed: str, canonical_target: str) -> bool:
    obs = observed.strip().lower()
    canonical = canonical_target.strip().lower()
    if obs == canonical:
        return True
    loopbacks = {"127.0.0.1", "localhost", "::1"}
    if obs in loopbacks and canonical in loopbacks:
        return True
    return False


def _parse_openvas_port(port_raw: str | None) -> int:
    if not port_raw:
        return 0
    clean = port_raw.strip().split("/")[0]
    try:
        return int(clean)
    except ValueError:
        return 0


def _map_openvas_severity(cvss_val: float | None, threat_raw: str | None) -> str:
    if cvss_val is not None:
        if cvss_val >= 9.0:
            return "Critical"
        if cvss_val >= 7.0:
            return "High"
        if cvss_val >= 4.0:
            return "Medium"
        if cvss_val > 0.0:
            return "Low"
        return "Info"

    threat = (threat_raw or "").strip().capitalize()
    threat_map = {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Log": "Info",
        "Info": "Info",
        "Debug": "Info",
    }
    return threat_map.get(threat, "Info")


class OpenVASAdapter(ToolAdapter):
    """Parses exported Greenbone / OpenVAS GMP XML reports into normalized findings."""

    tool_name = "openvas"
    allowed_profiles = frozenset({"import_report", "default", "quick_recon"})
    requires_approval = False

    def __init__(self) -> None:
        self._runs: dict[str, Path] = {}

    def start(self, context: AdapterContext, validated: ValidationResult) -> RunHandle:
        self.require_startable(context, validated)
        request = validated.request
        run_id = str(uuid4())
        context.repository.create_scan_run(
            run_id,
            context.scope.id,
            self.tool_name,
            request.profile,
            ScanRunStatus.PARSING.value,
            request.rationale,
            [step.model_dump() for step in request.anticipated_next_steps],
        )
        record(
            context.repository,
            event_type="adapter_start",
            outcome="parsing",
            entity_type="scan_run",
            entity_id=run_id,
            detail={"tool": self.tool_name, "target": request.target, "port": request.port},
        )
        return RunHandle(run_id, ScanRunStatus.PARSING)

    def poll(self, context: AdapterContext, handle: RunHandle) -> PollResult:
        return PollResult(handle.run_id, ScanRunStatus.PARSING, progress=100)

    def get_output_path(self, run_id: str, context: AdapterContext | None = None) -> Path | None:
        if run_id in self._runs:
            return self._runs[run_id]
        if context is not None:
            tool_dir = context.artifact_directory / self.tool_name
            if tool_dir.exists():
                for p in tool_dir.glob(f"*{run_id}*"):
                    if p.is_file():
                        return p
        return None

    def parse(self, context: AdapterContext, handle: RunHandle, raw_output: bytes) -> ParseResult:
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".xml")
        self._runs[handle.run_id] = evidence.file_path

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as error:
            return self.parse_failure(context, handle, evidence, f"OpenVAS returned malformed XML output: {error}")

        findings: list[Finding] = []
        canonical_target = context.scope.canonical_target

        for result in root.findall(".//result"):
            host_text = result.findtext("host") or ""
            if not _matches_target(host_text, canonical_target):
                continue

            port = _parse_openvas_port(result.findtext("port"))
            name = result.findtext("name") or "OpenVAS Finding"
            desc_body = result.findtext("description") or ""
            description = f"[{name}] {desc_body}" if desc_body else name

            # Parse severity and CVSS
            cvss_val: float | None = None
            sev_text = result.findtext("severity") or result.findtext(".//nvt/cvss_base")
            if sev_text:
                try:
                    cvss_val = float(sev_text.strip())
                except ValueError:
                    cvss_val = None

            threat_text = result.findtext("threat")
            severity = _map_openvas_severity(cvss_val, threat_text)

            cve = result.findtext(".//nvt/cve") or result.findtext("cve")
            if not cve:
                ref_cve = result.find(".//refs/ref[@type='cve']") or result.find(".//ref[@type='cve']")
                if ref_cve is not None:
                    cve = ref_cve.get("id") or ref_cve.text
            if not cve and description:
                cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", description, re.IGNORECASE)
                if cve_match:
                    cve = cve_match.group(0).upper()
            if cve and cve.lower() in ("nocve", "none"):
                cve = None

            findings.append(
                Finding(
                    source_tool=self.tool_name,
                    affected_asset=f"{canonical_target}:{port}",
                    description=description[:10000],
                    severity=severity,
                    cvss=cvss_val,
                    cve=cve,
                    cwe=None,
                    confidence="observed",
                    validation_status="suspected",
                )
            )

        context.repository.update_scan_run(handle.run_id, ScanRunStatus.DONE.value)
        record(
            context.repository,
            event_type="adapter_parse",
            outcome="success",
            entity_type="scan_run",
            entity_id=handle.run_id,
            detail={"tool": self.tool_name, "evidence_id": evidence.id, "finding_count": len(findings)},
        )
        return ParseResult(evidence=evidence, findings=findings, status=ScanRunStatus.DONE)

