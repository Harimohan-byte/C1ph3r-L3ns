"""Scoped Nmap XML adapter with fixed, non-injectable profile bundles."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import uuid4

try:
    from ctypes import windll
except ImportError:
    windll = None  # Non-Windows systems

from cipher_lens.adapters.base import AdapterContext, AdapterRequest, Finding, ParseResult, PollResult, RunHandle, ScanRunStatus, ToolAdapter, ValidationResult
from cipher_lens.services.audit import record


def _is_pid_alive(pid: int) -> bool:
    """Check if process is active in OS without raising signals."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
        except Exception:
            pass
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def _kill_pid(pid: int) -> None:
    if pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            os.kill(pid, 9)
    except OSError:
        pass


PROFILE_FLAGS: dict[str, tuple[str, ...]] = {
    "quick_recon": ("-sT", "-n", "-Pn", "--open", "-T3"),
    "service_version_scan": ("-sT", "-sV", "--version-light", "-n", "-Pn", "--open", "-T3"),
    "targeted_port_scan": ("-sT", "-sV", "--reason", "-n", "-Pn", "--open", "-T3"),
    "os_detection": ("-sT", "-O", "-n", "-Pn", "--open", "-T3"),
}


class NmapAdapter(ToolAdapter):
    tool_name = "nmap"
    allowed_profiles = frozenset(PROFILE_FLAGS)

    def __init__(self) -> None:
        self._runs: dict[str, tuple[subprocess.Popen[bytes], Path, float]] = {}

    def start(self, context: AdapterContext, validated: ValidationResult) -> RunHandle:
        self.require_startable(context, validated)
        request = validated.request
        run_id = str(uuid4())
        context.repository.create_scan_run(
            run_id, context.scope.id, self.tool_name, request.profile, "queued", request.rationale,
            [step.model_dump() for step in request.anticipated_next_steps],
        )
        if request.profile == "os_detection" and not self._has_os_detection_privilege():
            return self._fail_unavailable(context, run_id, "Nmap OS detection requires elevated local privileges.")
        executable = shutil.which("nmap")
        if executable is None:
            return self._fail_unavailable(context, run_id, "Nmap is unavailable on PATH.")
        output_path = context.artifact_directory / self.tool_name / f"{run_id}.xml"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = [executable, *PROFILE_FLAGS[request.profile], "-p", str(request.port), "-oX", str(output_path), request.target]
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        except OSError as error:
            return self._fail_unavailable(context, run_id, f"Nmap could not start: {error.__class__.__name__}.")
        self._runs[run_id] = (process, output_path, time.monotonic() + request.timeout_seconds)

        # Persist run metadata so poll() survives page reloads and process restarts
        meta_path = context.artifact_directory / self.tool_name / f"{run_id}.meta.json"
        try:
            meta_path.write_text(
                json.dumps({
                    "run_id": run_id,
                    "pid": process.pid,
                    "output_path": str(output_path),
                    "deadline_epoch": time.time() + request.timeout_seconds,
                    "timeout_seconds": request.timeout_seconds,
                    "started_epoch": time.time(),
                }),
                encoding="utf-8",
            )
        except OSError:
            pass

        context.repository.update_scan_run(run_id, ScanRunStatus.RUNNING.value)
        record(context.repository, event_type="adapter_start", outcome="running", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "profile": request.profile, "target": request.target, "port": request.port})
        return RunHandle(run_id, ScanRunStatus.RUNNING)

    def poll(self, context: AdapterContext, handle: RunHandle) -> PollResult:
        state = self._runs.get(handle.run_id)
        if state is not None:
            process, _, deadline = state
            if process.poll() is None and time.monotonic() < deadline:
                return PollResult(handle.run_id, ScanRunStatus.RUNNING)
            if process.poll() is None:
                process.kill()
                return self._finish_failed(context, handle.run_id, "Nmap timed out.")
            if process.returncode != 0:
                return self._finish_failed(context, handle.run_id, "Nmap failed.")
            context.repository.update_scan_run(handle.run_id, ScanRunStatus.PARSING.value)
            return PollResult(handle.run_id, ScanRunStatus.PARSING)

        # Rerun recovery: check persisted .meta.json if in-memory handle was lost during page reload
        meta_path = context.artifact_directory / self.tool_name / f"{handle.run_id}.meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                pid = meta.get("pid")
                out_path = Path(meta.get("output_path", ""))
                deadline_epoch = meta.get("deadline_epoch", 0.0)

                if pid and _is_pid_alive(pid):
                    if time.time() < deadline_epoch:
                        return PollResult(handle.run_id, ScanRunStatus.RUNNING)
                    else:
                        _kill_pid(pid)
                        return self._finish_failed(context, handle.run_id, "Nmap timed out.")

                # Subprocess completed
                if out_path.exists() and out_path.stat().st_size > 0:
                    context.repository.update_scan_run(handle.run_id, ScanRunStatus.PARSING.value)
                    return PollResult(handle.run_id, ScanRunStatus.PARSING)
                else:
                    return self._finish_failed(context, handle.run_id, "Nmap process exited without generating output.")
            except Exception:
                pass

        return PollResult(handle.run_id, handle.status, handle.reason)

    def parse(self, context: AdapterContext, handle: RunHandle, raw_output: bytes) -> ParseResult:
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".xml")
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return self.parse_failure(context, handle, evidence, "Nmap returned malformed XML output.")
        findings: list[Finding] = []
        for host in root.findall("host"):
            address_element = host.find("address")
            address = address_element.get("addr") if address_element is not None else "unknown"
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                reason = state.get("reason", "unspecified")
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                desc_extra = ""
                if product:
                    desc_extra = f"; Product: {product}"
                    if version:
                        desc_extra += f" {version}"
                findings.append(Finding(
                    source_tool=self.tool_name,
                    affected_asset=f"{address}:{port.get('portid')}",
                    description=f"Open {service_name} port observed; Nmap reason: {reason}{desc_extra}.",
                    product=product,
                    version=version,
                    confidence="observed",
                    validation_status="not_validated",
                ))
        context.repository.update_scan_run(handle.run_id, ScanRunStatus.DONE.value)
        record(context.repository, event_type="adapter_parse", outcome="done", entity_type="scan_run", entity_id=handle.run_id,
               detail={"tool": self.tool_name, "finding_count": len(findings)})
        return ParseResult(evidence=evidence, findings=findings)

    def get_output_path(self, run_id: str, context: AdapterContext | None = None) -> Path | None:
        """Return the primary output XML path for this Nmap run."""
        state = self._runs.get(run_id)
        if state is not None:
            return state[1]
        if context is not None:
            candidate = context.artifact_directory / self.tool_name / f"{run_id}.xml"
            if candidate.exists():
                return candidate
        return None

    def _fail_unavailable(self, context: AdapterContext, run_id: str, reason: str) -> RunHandle:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        record(context.repository, event_type="adapter_start", outcome="failed", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "reason": reason})
        return RunHandle(run_id, ScanRunStatus.FAILED, reason)

    def _finish_failed(self, context: AdapterContext, run_id: str, reason: str) -> PollResult:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        record(context.repository, event_type="adapter_poll", outcome="failed", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "reason": reason})
        return PollResult(run_id, ScanRunStatus.FAILED, reason)

    @staticmethod
    def _has_os_detection_privilege() -> bool:
        if os.name != "nt":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        if windll is None:
            return False
        try:
            return bool(windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
