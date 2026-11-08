"""Scoped OWASP ZAP REST adapter with explicit daemon availability reporting."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Callable
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen
from uuid import uuid4

from cipher_lens.adapters.base import AdapterContext, AdapterRequest, Finding, ParseResult, PollResult, RunHandle, ScanRunStatus, ToolAdapter, ValidationResult
from cipher_lens.config import zap_base_url
from cipher_lens.services.audit import record


@dataclass(frozen=True)
class _ZapRun:
    scan_id: str
    endpoint: str
    deadline: float
    target_url: str


class ZapAdapter(ToolAdapter):
    tool_name = "zap"
    allowed_profiles = frozenset({"quick_recon", "web_quick", "active_scan", "spider"})
    requires_approval = True

    def validate(self, context: AdapterContext, request: AdapterRequest):
        if request.scheme is None:
            return self._reject(context, request, ScanRunStatus.BLOCKED, "ZAP requires an explicit http or https scheme.", "scheme")
        return super().validate(context, request)

    def __init__(self, *, base_url: str | None = None, opener: Callable[..., object] = urlopen) -> None:
        self.base_url = (base_url or zap_base_url()).rstrip("/")
        self._opener = opener
        self._runs: dict[str, _ZapRun] = {}

    def start(self, context: AdapterContext, validated: ValidationResult) -> RunHandle:
        self.require_startable(context, validated)
        request = validated.request
        run_id = str(uuid4())
        context.repository.create_scan_run(
            run_id, context.scope.id, self.tool_name, request.profile, "queued", request.rationale,
            [step.model_dump() for step in request.anticipated_next_steps],
        )
        if not self._available():
            return self._fail(context, run_id, f"ZAP is unavailable at {self.base_url}.")
        target_url = f"{request.scheme}://{request.target}:{request.port}"
        if request.action.value == "active_validation":
            endpoint = "/JSON/ascan/action/scan/"
        else:
            endpoint = "/JSON/spider/action/scan/"
        try:
            payload = self._json(endpoint, {"url": target_url})
            scan_id = str(payload["scan"])
        except (KeyError, TypeError, URLError, ValueError):
            return self._fail(context, run_id, "ZAP rejected the requested scan.")
        self._runs[run_id] = _ZapRun(scan_id, endpoint.split("/")[2], time.monotonic() + request.timeout_seconds, target_url)
        context.repository.update_scan_run(run_id, ScanRunStatus.RUNNING.value)
        record(context.repository, event_type="adapter_start", outcome="running", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "target": request.target, "port": request.port, "mode": self._runs[run_id].endpoint})
        return RunHandle(run_id, ScanRunStatus.RUNNING)

    def poll(self, context: AdapterContext, handle: RunHandle) -> PollResult:
        run = self._runs.get(handle.run_id)
        if run is None:
            return PollResult(handle.run_id, handle.status, handle.reason)
        if time.monotonic() >= run.deadline:
            return self._failed_poll(context, handle.run_id, "ZAP timed out.")
        try:
            payload = self._json(f"/JSON/{run.endpoint}/view/status/", {"scanId": run.scan_id})
            complete = int(payload["status"]) >= 100
        except (KeyError, TypeError, URLError, ValueError):
            return self._failed_poll(context, handle.run_id, "ZAP status request failed.")
        if not complete:
            return PollResult(handle.run_id, ScanRunStatus.RUNNING)

        # Scan complete — fetch alerts from ZAP REST daemon and save artifact JSON
        output_path = context.artifact_directory / self.tool_name / f"{handle.run_id}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            alerts_data = self._json("/JSON/core/view/alerts/", {"baseurl": run.target_url})
            if not alerts_data.get("alerts"):
                alerts_data = self._json("/JSON/core/view/alerts/", {})
            output_path.write_text(json.dumps(alerts_data), encoding="utf-8")
        except Exception:
            if not output_path.exists():
                output_path.write_text(json.dumps({"alerts": []}), encoding="utf-8")

        context.repository.update_scan_run(handle.run_id, ScanRunStatus.PARSING.value)
        return PollResult(handle.run_id, ScanRunStatus.PARSING)

    def parse(self, context: AdapterContext, handle: RunHandle, raw_output: bytes) -> ParseResult:
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".json")
        try:
            payload = json.loads(raw_output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.parse_failure(context, handle, evidence, "ZAP returned malformed JSON output.")

        findings: list[Finding] = []
        for alert in payload.get("alerts", []):
            url = alert.get("url", "unknown")
            desc = alert.get("description", "ZAP alert observed.")
            ref = str(alert.get("reference", ""))
            other = str(alert.get("otherinfo", ""))
            combined_ref = f"{desc} {ref} {other}"

            # Extract CWE: ZAP JSON alerts usually have "cweid" (numeric)
            cwe = None
            raw_cweid = str(alert.get("cweid", "")).strip()
            if raw_cweid and raw_cweid not in {"0", "-1"}:
                cwe = f"CWE-{raw_cweid}"
            else:
                cwe_match = re.search(r"\bCWE-\d+\b", combined_ref, re.IGNORECASE)
                if cwe_match:
                    cwe = cwe_match.group(0).upper()

            # Extract CVE: from reference, description, etc.
            cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", combined_ref, re.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else None

            findings.append(Finding(
                source_tool=self.tool_name,
                affected_asset=url,
                description=desc,
                severity=alert.get("risk"),
                cve=cve,
                cwe=cwe,
                confidence=alert.get("confidence", "observed"),
                validation_status="not_validated",
            ))

        context.repository.update_scan_run(handle.run_id, ScanRunStatus.DONE.value)
        return ParseResult(evidence=evidence, findings=findings)

    def _available(self) -> bool:
        try:
            self._json("/JSON/core/view/version/", {})
        except (URLError, ValueError):
            return False
        return True

    def _json(self, endpoint: str, params: dict[str, str]) -> dict:
        url = f"{self.base_url}{endpoint}?{urlencode(params)}"
        with self._opener(url, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _fail(self, context: AdapterContext, run_id: str, reason: str) -> RunHandle:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        record(context.repository, event_type="adapter_start", outcome="failed", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "reason": reason})
        return RunHandle(run_id, ScanRunStatus.FAILED, reason)

    def _failed_poll(self, context: AdapterContext, run_id: str, reason: str) -> PollResult:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        return PollResult(run_id, ScanRunStatus.FAILED, reason)
