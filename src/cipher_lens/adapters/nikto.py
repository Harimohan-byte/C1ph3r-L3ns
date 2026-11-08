"""Scoped Nikto XML adapter with one fixed, auditable command bundle."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import uuid4

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


class NiktoAdapter(ToolAdapter):
    tool_name = "nikto"
    allowed_profiles = frozenset({"quick_recon", "web_quick"})

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
        executable = shutil.which("nikto")
        if executable is None:
            return self._fail(context, run_id, "Nikto is unavailable on PATH.")
        output_path = context.artifact_directory / self.tool_name / f"{run_id}.xml"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            executable,
            "-host", request.target,
            "-port", str(request.port),
            "-Format", "xml",
            "-output", str(output_path),
            "-Tuning", "1,2,3,b",
            "-timeout", "3",
            "-maxtime", "45s",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
            print(f"\n[CIPHER LENS NIKTO] Launched Nikto PID {process.pid}: {' '.join(command)}", flush=True)
        except OSError as error:
            return self._fail(context, run_id, f"Nikto could not start: {error.__class__.__name__}.")
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
               detail={"tool": self.tool_name, "target": request.target, "port": request.port})
        return RunHandle(run_id, ScanRunStatus.RUNNING)

    def poll(self, context: AdapterContext, handle: RunHandle) -> PollResult:
        state = self._runs.get(handle.run_id)
        if state is not None:
            process, _, deadline = state
            if process.poll() is None and time.monotonic() < deadline:
                return PollResult(handle.run_id, ScanRunStatus.RUNNING)
            if process.poll() is None:
                process.kill()
                return self._failed_poll(context, handle.run_id, "Nikto timed out.")
            if process.returncode != 0:
                return self._failed_poll(context, handle.run_id, "Nikto failed.")
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
                        return self._failed_poll(context, handle.run_id, "Nikto timed out.")

                # Subprocess completed
                if out_path.exists() and out_path.stat().st_size > 0:
                    context.repository.update_scan_run(handle.run_id, ScanRunStatus.PARSING.value)
                    return PollResult(handle.run_id, ScanRunStatus.PARSING)
                else:
                    return self._failed_poll(context, handle.run_id, "Nikto process exited without generating output.")
            except Exception:
                pass

        return PollResult(handle.run_id, handle.status, handle.reason)

    def parse(self, context: AdapterContext, handle: RunHandle, raw_output: bytes) -> ParseResult:
        evidence = self.persist_raw_artifact(context, handle.run_id, raw_output, ".xml")
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return self.parse_failure(context, handle, evidence, "Nikto returned malformed XML output.")

        findings: list[Finding] = []
        scandetails = root.find(".//scandetails")
        site_ip = (scandetails.get("targetip") or scandetails.get("siteip") or "unknown") if scandetails is not None else "unknown"
        target_banner = scandetails.get("targetbanner") if scandetails is not None else None

        product = None
        version = None
        if target_banner and "/" in target_banner:
            banner_parts = target_banner.split(" ")[0].split("/", 1)
            product = banner_parts[0].strip()
            version = banner_parts[1].strip() if len(banner_parts) > 1 else None

        for item in root.findall(".//item"):
            desc = item.findtext("description") or "Nikto finding observed."
            refs = item.findtext("references") or ""
            target_ip = item.get("targetip") or site_ip

            combined = f"{desc} {refs}"
            cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", combined, re.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else None

            cwe_match = re.search(r"\bCWE-\d+\b", combined, re.IGNORECASE)
            cwe = cwe_match.group(0).upper() if cwe_match else None

            findings.append(Finding(
                source_tool=self.tool_name,
                affected_asset=target_ip,
                description=desc,
                cve=cve,
                cwe=cwe,
                product=product,
                version=version,
                confidence="observed",
                validation_status="not_validated",
            ))
        context.repository.update_scan_run(handle.run_id, ScanRunStatus.DONE.value)
        return ParseResult(evidence=evidence, findings=findings)

    def _fail(self, context: AdapterContext, run_id: str, reason: str) -> RunHandle:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        record(context.repository, event_type="adapter_start", outcome="failed", entity_type="scan_run", entity_id=run_id,
               detail={"tool": self.tool_name, "reason": reason})
        return RunHandle(run_id, ScanRunStatus.FAILED, reason)

    def _failed_poll(self, context: AdapterContext, run_id: str, reason: str) -> PollResult:
        context.repository.update_scan_run(run_id, ScanRunStatus.FAILED.value, reason)
        return PollResult(run_id, ScanRunStatus.FAILED, reason)
