"""Truthful capability and availability matrix for the seven core security tools."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from enum import StrEnum
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from cipher_lens.config import zap_base_url


class IntegrationStatus(StrEnum):
    LIVE = "Live"
    IMPORT_ONLY = "Import-only"
    PLANNED = "Planned"
    UNSUPPORTED = "Unsupported"


class ToolCapability(BaseModel):
    """Declared and verified capability metadata for one security tool."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    status: IntegrationStatus
    expected_role: str = Field(min_length=1, max_length=256)
    coverage_type: str = Field(min_length=1, max_length=64)
    declared_mode: str = Field(min_length=1, max_length=64)
    availability_details: str = Field(min_length=1, max_length=512)
    is_available: bool
    limitations: str = Field(min_length=1, max_length=512)
    supported_formats: list[str] = Field(default_factory=list)
    last_verified: str = Field(min_length=1, max_length=64)


def check_nmap_availability() -> tuple[bool, str]:
    """Verify local presence of the Nmap executable without executing scans."""
    executable = shutil.which("nmap")
    if executable:
        return True, f"Installed and accessible on system PATH at {executable}."
    return False, "Nmap executable not found on system PATH; XML report import supported."


def check_nikto_availability() -> tuple[bool, str]:
    """Verify local presence of the Nikto executable without executing scans."""
    executable = shutil.which("nikto")
    if executable:
        return True, f"Installed and accessible on system PATH at {executable}."
    return False, "Nikto executable not found on system PATH; XML report import supported."


def check_zap_availability(timeout: float = 1.5) -> tuple[bool, str]:
    """Verify reachability of the OWASP ZAP REST daemon endpoint."""
    base_url = zap_base_url().rstrip("/")
    endpoint = f"{base_url}/JSON/core/view/version/"
    try:
        req = Request(endpoint, headers={"User-Agent": "CIPHER-LENS-Integrations-Probe"})
        with urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                return True, f"ZAP REST daemon reachable and responsive at {base_url}."
            return False, f"ZAP endpoint returned status {response.status} at {base_url}."
    except (URLError, TimeoutError, ValueError, OSError):
        return False, f"ZAP REST daemon unreachable at {base_url}; JSON report import supported."


def get_integration_matrix() -> list[ToolCapability]:
    """Return the truthful seven-tool capability matrix with live availability checks."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 1. Nmap
    nmap_live, nmap_details = check_nmap_availability()
    nmap = ToolCapability(
        name="Nmap",
        status=IntegrationStatus.LIVE if nmap_live else IntegrationStatus.IMPORT_ONLY,
        expected_role="Host, port, and service discovery, reconnaissance, and version enumeration",
        coverage_type="Network",
        declared_mode="CLI Subprocess (Non-shell)",
        availability_details=nmap_details,
        is_available=nmap_live,
        limitations="Fixed scan profile bundles only; no free-form flags or aggressive script execution.",
        supported_formats=[".xml"],
        last_verified=now_str,
    )

    # 2. OWASP ZAP
    zap_live, zap_details = check_zap_availability()
    zap = ToolCapability(
        name="OWASP ZAP",
        status=IntegrationStatus.LIVE if zap_live else IntegrationStatus.IMPORT_ONLY,
        expected_role="Web application and API vulnerability assessment and active scan validation",
        coverage_type="Web / API",
        declared_mode="REST API Daemon",
        availability_details=zap_details,
        is_available=zap_live,
        limitations="Active validation scans strictly require a prior 15-minute human approval token.",
        supported_formats=[".json"],
        last_verified=now_str,
    )

    # 3. Nikto
    nikto_live, nikto_details = check_nikto_availability()
    nikto = ToolCapability(
        name="Nikto",
        status=IntegrationStatus.LIVE if nikto_live else IntegrationStatus.IMPORT_ONLY,
        expected_role="Web-server configuration, outdated components, and known security issue checks",
        coverage_type="Web",
        declared_mode="CLI Subprocess (Non-shell)",
        availability_details=nikto_details,
        is_available=nikto_live,
        limitations="Fixed quick_recon mode only; tuning, mutation, and SSL-forcing flags are not permitted.",
        supported_formats=[".xml"],
        last_verified=now_str,
    )

    # 4. Nessus
    nessus = ToolCapability(
        name="Nessus",
        status=IntegrationStatus.IMPORT_ONLY,
        expected_role="Comprehensive infrastructure vulnerability scanning and compliance auditing",
        coverage_type="Infrastructure",
        declared_mode="Result Import",
        availability_details="Native .nessus XML report parser active in Assessment Workspace; no live daemon claimed.",
        is_available=True,
        limitations="Commercial tool; automated live orchestration is not claimed for free-tier MVP.",
        supported_formats=[".nessus", ".xml", ".csv"],
        last_verified=now_str,
    )

    # 5. OpenVAS / Greenbone
    openvas = ToolCapability(
        name="OpenVAS / Greenbone",
        status=IntegrationStatus.IMPORT_ONLY,
        expected_role="Infrastructure vulnerability assessment, CVE mapping, and cross-tool correlation",
        coverage_type="Infrastructure",
        declared_mode="Result Import",
        availability_details="OpenVAS / Greenbone GMP XML report parser active in Assessment Workspace; server daemon not automated locally.",
        is_available=True,
        limitations="Resource-heavy server daemon; external report import supported without live claim.",
        supported_formats=[".xml"],
        last_verified=now_str,
    )

    # 6. Burp Suite Community
    burp = ToolCapability(
        name="Burp Suite Community",
        status=IntegrationStatus.IMPORT_ONLY,
        expected_role="Web security testing, analyst-assisted validation, and proxy issue ingestion",
        coverage_type="Web",
        declared_mode="Result Import",
        availability_details="Burp Suite XML issue export supported; community edition lacks automated REST API.",
        is_available=True,
        limitations="Free Community edition provides no automated REST API; commercial claims are explicitly disclaimed.",
        supported_formats=[".xml"],
        last_verified=now_str,
    )

    # 7. Metasploit
    metasploit = ToolCapability(
        name="Metasploit",
        status=IntegrationStatus.PLANNED,
        expected_role="Controlled, lab-only validation and proof-of-concept verification",
        coverage_type="Exploitation Validation",
        declared_mode="Planned Lab Validation",
        availability_details="Human-approval architecture established; live RPC exploitation disabled by safety policy.",
        is_available=False,
        limitations="Autonomous exploitation is strictly forbidden by Constitution Principle I; lab-only proof validation planned.",
        supported_formats=[],
        last_verified=now_str,
    )

    return [nmap, zap, nikto, nessus, openvas, burp, metasploit]
