"""Unit tests for Nessus and OpenVAS import-only report adapters."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cipher_lens.adapters.base import (
    ActionClass,
    AdapterContext,
    AdapterRequest,
    RunHandle,
    ScanRunStatus,
)
from cipher_lens.domain.models import ScopeRegistration, ToolName, ScanProfile
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.planning import InMemoryRateLimiter
from cipher_lens.services.scope_registration import register_scope


SAMPLE_NESSUS_XML = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="127.0.0.1">
      <HostProperties>
        <tag name="host-ip">127.0.0.1</tag>
      </HostProperties>
      <ReportItem port="80" svc_name="http" protocol="tcp" severity="3" pluginID="10001" pluginName="Apache HTTP Server Vulnerability">
        <description>Apache HTTP Server outdated version with known issues.</description>
        <cvss3_base_score>7.5</cvss3_base_score>
        <cve>CVE-2023-1234</cve>
        <cwe>CWE-200</cwe>
        <plugin_output>Apache/2.4.41 detected on port 80</plugin_output>
      </ReportItem>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="4" pluginID="10002" pluginName="Critical OpenSSH Flaw">
        <description>OpenSSH Remote Code Execution vulnerability.</description>
        <cvss_base_score>9.8</cvss_base_score>
        <cve>CVE-2023-5678</cve>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="10003" pluginName="OS Identification">
        <description>Linux Kernel 5.15 detected.</description>
      </ReportItem>
    </ReportHost>
    <ReportHost name="192.168.1.99">
      <ReportItem port="80" svc_name="http" protocol="tcp" severity="4" pluginID="10004" pluginName="Out of Scope Flaw">
        <description>This host is not in scope.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

SAMPLE_OPENVAS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report id="rep-001" format_id="gmp-xml">
  <results max="100" start="1">
    <result id="res-1">
      <name>Node.js Insecure Component</name>
      <host>127.0.0.1</host>
      <port>3000/tcp</port>
      <threat>High</threat>
      <severity>7.5</severity>
      <description>Known vulnerable package in web service.</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.1001">
        <cve>CVE-2022-9999</cve>
        <cvss_base>7.5</cvss_base>
      </nvt>
    </result>
    <result id="res-2">
      <name>General Information Disclosure</name>
      <host>127.0.0.1</host>
      <port>general/tcp</port>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <description>Banner discloses sensitive version.</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.1002">
        <cve>CVE-2021-1111</cve>
      </nvt>
    </result>
    <result id="res-3">
      <name>Out of Scope Finding</name>
      <host>10.0.0.99</host>
      <port>80/tcp</port>
      <threat>High</threat>
      <severity>8.0</severity>
      <description>Should be filtered out.</description>
    </result>
  </results>
</report>
"""


@pytest.fixture
def test_context(tmp_path: Path):
    db_path = tmp_path / "test.db"
    repo = Repository(db_path)
    scope = register_scope(
        repo,
        ScopeRegistration(
            target="127.0.0.1",
            allowed_ports="22,80,3000",
            excluded_ports="",
            excluded_endpoints="",
            engagement_note="Authorized local lab.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON, ActionClass.ACTIVE_VALIDATION},
        ),
    )
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    rate_limiter = InMemoryRateLimiter(clock=lambda: 0)
    return AdapterContext(
        repository=repo,
        scope=scope,
        artifact_directory=artifact_dir,
        rate_limiter=rate_limiter,
    )


def test_nessus_adapter_parses_valid_xml(test_context: AdapterContext):
    from cipher_lens.adapters.nessus import NessusAdapter

    adapter = NessusAdapter()
    req = AdapterRequest(
        target="127.0.0.1",
        port=80,
        profile="import_report",
        action=ActionClass.RECON,
        rationale="Importing Nessus Essentials report.",
    )
    val = adapter.validate(test_context, req)
    assert val.status == ScanRunStatus.QUEUED

    handle = adapter.start(test_context, val)
    assert handle.status == ScanRunStatus.PARSING

    poll = adapter.poll(test_context, handle)
    assert poll.status == ScanRunStatus.PARSING
    assert poll.progress == 100

    result = adapter.parse(test_context, handle, SAMPLE_NESSUS_XML.encode("utf-8"))
    assert result.status == ScanRunStatus.DONE
    assert len(result.findings) == 3

    # Check finding details
    port_80 = next(f for f in result.findings if f.affected_asset == "127.0.0.1:80")
    assert port_80.severity == "High"
    assert port_80.cve == "CVE-2023-1234"
    assert port_80.cwe == "CWE-200"
    assert port_80.cvss == 7.5
    assert "Apache HTTP Server Vulnerability" in port_80.description

    port_22 = next(f for f in result.findings if f.affected_asset == "127.0.0.1:22")
    assert port_22.severity == "Critical"
    assert port_22.cve == "CVE-2023-5678"
    assert port_22.cvss == 9.8

    port_0 = next(f for f in result.findings if f.affected_asset == "127.0.0.1:0")
    assert port_0.severity == "Info"

    # Out-of-scope host 192.168.1.99 must not appear
    assert not any("192.168.1.99" in f.affected_asset for f in result.findings)

    # Output path check
    out_path = adapter.get_output_path(handle.run_id, test_context)
    assert out_path is not None
    assert out_path.exists()
    assert result.evidence.sha256 is not None


def test_nessus_adapter_handles_malformed_xml(test_context: AdapterContext):
    from cipher_lens.adapters.nessus import NessusAdapter

    adapter = NessusAdapter()
    req = AdapterRequest(
        target="127.0.0.1",
        port=80,
        profile="import_report",
        action=ActionClass.RECON,
        rationale="Importing malformed report.",
    )
    val = adapter.validate(test_context, req)
    handle = adapter.start(test_context, val)

    result = adapter.parse(test_context, handle, b"<<<not xml>>>")
    assert result.status == ScanRunStatus.FAILED
    assert "xml" in result.reason.lower()


def test_openvas_adapter_parses_valid_xml(test_context: AdapterContext):
    from cipher_lens.adapters.openvas import OpenVASAdapter

    adapter = OpenVASAdapter()
    req = AdapterRequest(
        target="127.0.0.1",
        port=3000,
        profile="import_report",
        action=ActionClass.RECON,
        rationale="Importing OpenVAS report.",
    )
    val = adapter.validate(test_context, req)
    assert val.status == ScanRunStatus.QUEUED

    handle = adapter.start(test_context, val)
    assert handle.status == ScanRunStatus.PARSING

    poll = adapter.poll(test_context, handle)
    assert poll.status == ScanRunStatus.PARSING
    assert poll.progress == 100

    result = adapter.parse(test_context, handle, SAMPLE_OPENVAS_XML.encode("utf-8"))
    assert result.status == ScanRunStatus.DONE
    assert len(result.findings) == 2

    # Port 3000 finding
    f3000 = next(f for f in result.findings if f.affected_asset == "127.0.0.1:3000")
    assert f3000.severity == "High"
    assert f3000.cvss == 7.5
    assert f3000.cve == "CVE-2022-9999"
    assert "Node.js Insecure Component" in f3000.description

    # General/tcp finding should map to port 0
    f_gen = next(f for f in result.findings if f.affected_asset == "127.0.0.1:0")
    assert f_gen.severity == "Medium"
    assert f_gen.cve == "CVE-2021-1111"

    # Out-of-scope host 10.0.0.99 must not appear
    assert not any("10.0.0.99" in f.affected_asset for f in result.findings)

    # Output path check
    out_path = adapter.get_output_path(handle.run_id, test_context)
    assert out_path is not None
    assert out_path.exists()


def test_openvas_adapter_handles_malformed_xml(test_context: AdapterContext):
    from cipher_lens.adapters.openvas import OpenVASAdapter

    adapter = OpenVASAdapter()
    req = AdapterRequest(
        target="127.0.0.1",
        port=3000,
        profile="import_report",
        action=ActionClass.RECON,
        rationale="Importing malformed report.",
    )
    val = adapter.validate(test_context, req)
    handle = adapter.start(test_context, val)

    result = adapter.parse(test_context, handle, b"INVALID_XML_CONTENT")
    assert result.status == ScanRunStatus.FAILED
    assert "xml" in result.reason.lower()
