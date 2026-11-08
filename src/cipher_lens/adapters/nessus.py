"""Nessus Essentials import-only report adapter."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

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


class NessusAdapter(ToolAdapter):
    """Parses exported .nessus (NessusClientData_v2) XML reports into normalized findings."""

    tool_name = "nessus"
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
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".nessus")
        self._runs[handle.run_id] = evidence.file_path

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as error:
            return self.parse_failure(context, handle, evidence, f"Nessus returned malformed XML output: {error}")

        findings: list[Finding] = []
        canonical_target = context.scope.canonical_target

        severity_map = {
            "0": "Info",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical",
        }

        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name") or ""
            host_ip = host_name
            for tag in report_host.findall("./HostProperties/tag"):
                if tag.get("name") == "host-ip" and tag.text:
                    host_ip = tag.text.strip()
                    break

            if not _matches_target(host_name, canonical_target) and not _matches_target(host_ip, canonical_target):
                continue

            for item in report_host.findall("./ReportItem"):
                port_str = item.get("port") or "0"
                try:
                    port = int(port_str)
                except ValueError:
                    port = 0

                raw_severity = item.get("severity") or "0"
                severity = severity_map.get(str(raw_severity), "Info")

                plugin_name = item.get("pluginName") or ""
                desc_body = item.findtext("description") or ""
                if plugin_name and desc_body:
                    description = f"[{plugin_name}] {desc_body}"
                elif plugin_name:
                    description = plugin_name
                else:
                    description = desc_body or "Nessus finding observed."

                cvss_val: float | None = None
                cvss_str = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
                if cvss_str:
                    try:
                        cvss_val = float(cvss_str.strip())
                    except ValueError:
                        cvss_val = None

                cve = item.findtext("cve")
                cwe = item.findtext("cwe")

                findings.append(
                    Finding(
                        source_tool=self.tool_name,
                        affected_asset=f"{canonical_target}:{port}",
                        description=description[:10000],
                        severity=severity,
                        cvss=cvss_val,
                        cve=cve,
                        cwe=cwe,
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
