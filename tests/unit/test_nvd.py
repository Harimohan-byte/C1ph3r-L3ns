"""Unit tests for CVE/CVSS enrichment and NVD API 2.0 integration.

Verifies:
1. Tier 1 zero-cost scanner extraction (Nikto XML, ZAP JSON) without network calls.
2. Gating: NVD lookup never fires on unvalidated/inferred/missing product or version strings.
3. Gating: App runs fully with NVD_API_KEY unset (cve=None, zero-cost, no error).
4. Priority: Findings with Tier 1 native CVE bypass NVD lookup completely.
5. Successful NVD 2.0 response parsing (CVE, CVSS v3.1 base score, base severity, CWE).
6. Graceful degradation: timeouts and HTTP errors retain cve=None without raising.
7. Direct contract tests for fetch_nvd_cve_for_product function.
8. End-to-end Result Ingestion pipeline integrating Tier 1, Tier 2, and unenriched findings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from urllib.error import URLError

import pytest

# Ensure src/ root is present on sys.path for direct test execution
_src_root = str(Path(__file__).resolve().parents[2] / "src")
if _src_root not in sys.path:
    sys.path.insert(0, _src_root)

from cipher_lens.adapters.base import AdapterContext, Finding, RunHandle
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.domain.findings import Severity
from cipher_lens.domain.models import ActionClass, ScopeRegistration
from cipher_lens.persistence.repositories import Repository
from cipher_lens.services.findings import ingest_and_store_findings
from cipher_lens.services.nvd import (
    _NVD_LOOKUP_CACHE,
    clear_nvd_cache,
    enrich_finding_with_nvd,
    fetch_nvd_cve_for_product,
)
from cipher_lens.services.planning import InMemoryRateLimiter
from cipher_lens.services.scope_registration import register_scope


@pytest.fixture(autouse=True)
def reset_cache():
    clear_nvd_cache()
    yield
    clear_nvd_cache()


def _make_context(tmp_path: Path, run_id: str, tool: str) -> tuple[AdapterContext, Repository]:
    repo = Repository(tmp_path / "test.db")
    scope = register_scope(
        repo,
        ScopeRegistration(
            target="lab.target.internal",
            allowed_ports="80,443",
            excluded_ports="",
            excluded_endpoints="",
            engagement_note="Lab testing.",
            authorized_lab_attested=True,
            allowed_actions={ActionClass.RECON},
        ),
    )
    repo.create_scan_run(run_id, scope.id, tool, "quick_recon", "parsing")
    context = AdapterContext(
        repository=repo,
        scope=scope,
        artifact_directory=tmp_path / "artifacts",
        rate_limiter=InMemoryRateLimiter(),
    )
    return context, repo


def test_tier1_nikto_extracts_native_cve_and_cwe_without_network(tmp_path: Path):
    """Nikto XML parser extracts native CVE and CWE tokens from <references> and <description>."""
    run_id = "run-nikto-1"
    context, repo = _make_context(tmp_path, run_id, "nikto")
    handle = RunHandle(run_id, "parsing")

    xml_content = b"""<?xml version="1.0" ?>
    <niktoscans>
      <niktoscan hoststest="test" nxmlversion="1.0" options="" scanelapsed="1" scanend="" scanstart="" version="2.1.6">
        <scandetails checks="1" errors="0" hostheader="target" siteip="192.168.1.10" sitename="target" starttime="" targetbanner="Apache/2.4.41" targethostname="target" targetip="192.168.1.10" targetport="80">
          <item id="000053" method="GET">
            <description>Vulnerable to path traversal; CWE-22 flaw.</description>
            <uri>/index.php?file=test</uri>
            <namelink></namelink>
            <iplink></iplink>
            <references>CVE-2001-1168 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1168</references>
          </item>
        </scandetails>
      </niktoscan>
    </niktoscans>
    """

    adapter = NiktoAdapter()
    result = adapter.parse(context, handle, xml_content)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source_tool == "nikto"
    assert f.cve == "CVE-2001-1168"
    assert f.cwe == "CWE-22"
    assert f.product == "Apache"
    assert f.version == "2.4.41"


def test_tier1_zap_extracts_native_cweid_and_cve_without_network(tmp_path: Path):
    """ZAP JSON parser extracts native cweid and CVE references without network access."""
    run_id = "run-zap-1"
    context, repo = _make_context(tmp_path, run_id, "zap")
    handle = RunHandle(run_id, "parsing")

    zap_json = json.dumps({
        "alerts": [
            {
                "url": "http://192.168.1.10/api/users",
                "description": "SQL Injection in parameter id.",
                "risk": "High",
                "confidence": "Medium",
                "cweid": "89",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-12345",
            }
        ]
    }).encode("utf-8")

    adapter = ZapAdapter(base_url="http://127.0.0.1:8080")
    result = adapter.parse(context, handle, zap_json)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source_tool == "zap"
    assert f.cwe == "CWE-89"
    assert f.cve == "CVE-2022-12345"
    assert f.severity == "High"


def test_nmap_extracts_product_and_version(tmp_path: Path):
    """Nmap XML parser extracts verified product and version from <service> element."""
    run_id = "run-nmap-1"
    context, repo = _make_context(tmp_path, run_id, "nmap")
    handle = RunHandle(run_id, "parsing")

    nmap_xml = b"""<?xml version="1.0" ?>
    <nmaprun>
      <host>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <ports>
          <port portid="80" protocol="tcp">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.41"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    adapter = NmapAdapter()
    result = adapter.parse(context, handle, nmap_xml)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source_tool == "nmap"
    assert f.product == "Apache httpd"
    assert f.version == "2.4.41"
    assert "Apache httpd 2.4.41" in f.description


def test_fetch_nvd_cve_for_product_direct_contract():
    """fetch_nvd_cve_for_product honors validation guardrails and parses payloads correctly."""
    # Guardrail 1: Empty product or version
    assert fetch_nvd_cve_for_product("", "2.4.49", api_key="test-key") is None
    assert fetch_nvd_cve_for_product("Apache", "  ", api_key="test-key") is None

    # Guardrail 2: Missing or blank api_key
    assert fetch_nvd_cve_for_product("Apache", "2.4.49", api_key=None) is None
    assert fetch_nvd_cve_for_product("Apache", "2.4.49", api_key="") is None

    # Direct query with mocked opener
    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                }
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(nvd_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_opener = MagicMock(return_value=mock_resp)

    res = fetch_nvd_cve_for_product("Apache", "2.4.49", api_key="key-abc", opener=mock_opener)
    assert res is not None
    assert res["cve"] == "CVE-2021-41773"
    assert res["cvss"] == 7.5
    assert res["severity"] == "High"
    assert res["cwe"] == "CWE-22"


def test_nvd_lookup_bypassed_if_finding_has_tier1_cve():
    """A finding with a pre-existing native CVE never triggers an NVD network call."""
    mock_opener = MagicMock()
    finding = Finding(
        source_tool="nikto",
        affected_asset="192.168.1.1:80",
        description="Path traversal",
        cve="CVE-2001-1168",
        product="Apache",
        version="2.4.41",
    )

    enriched = enrich_finding_with_nvd(finding, api_key="test-api-key", opener=mock_opener)

    assert enriched.cve == "CVE-2001-1168"
    mock_opener.assert_not_called()


def test_nvd_lookup_never_fires_on_unvalidated_or_missing_product_version():
    """NVD lookup is strictly gated: missing product or version never triggers network calls."""
    mock_opener = MagicMock()

    # Case 1: Neither product nor version
    f1 = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.1:80",
        description="Open port",
    )
    e1 = enrich_finding_with_nvd(f1, api_key="test-api-key", opener=mock_opener)
    assert e1.cve is None
    mock_opener.assert_not_called()

    # Case 2: Product only, missing version
    f2 = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.1:80",
        description="Open port",
        product="Apache",
        version=None,
    )
    e2 = enrich_finding_with_nvd(f2, api_key="test-api-key", opener=mock_opener)
    assert e2.cve is None
    mock_opener.assert_not_called()


def test_app_runs_fully_with_nvd_api_key_unset():
    """Without NVD_API_KEY, app operates in zero-cost mode without network calls or errors."""
    mock_opener = MagicMock()
    finding = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.1:80",
        description="Apache HTTP service",
        product="Apache",
        version="2.4.41",
    )

    enriched = enrich_finding_with_nvd(finding, api_key=None, opener=mock_opener)
    assert enriched.cve is None
    mock_opener.assert_not_called()


def test_successful_nvd_lookup_populates_cve_cvss_and_cwe():
    """Valid NVD API 2.0 JSON response populates CVE, CVSS v3.1 score, severity, and CWE."""
    nvd_response_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-22"}
                            ]
                        }
                    ],
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(nvd_response_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_opener = MagicMock(return_value=mock_resp)

    finding = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.1:80",
        description="Open Apache port",
        product="Apache",
        version="2.4.49",
    )

    enriched = enrich_finding_with_nvd(finding, api_key="valid-test-key", opener=mock_opener)

    assert enriched.cve == "CVE-2021-41773"
    assert enriched.cvss == 7.5
    assert enriched.severity == "High"
    assert enriched.cwe == "CWE-22"

    # Verify HTTP request was structured with apiKey header
    mock_opener.assert_called_once()
    req = mock_opener.call_args[0][0]
    api_header = req.get_header("Apikey") or req.headers.get("Apikey") or req.headers.get("apikey")
    assert api_header == "valid-test-key"
    assert "keywordSearch=Apache+2.4.49" in req.full_url


def test_nvd_lookup_failure_or_timeout_gracefully_keeps_cve_none():
    """Network failure, timeout, or HTTP 429 safely retains cve=None without raising."""
    mock_opener = MagicMock(side_effect=URLError("Connection refused / timed out"))

    finding = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.1:80",
        description="Open Apache port",
        product="Apache",
        version="2.4.49",
    )

    enriched = enrich_finding_with_nvd(finding, api_key="valid-test-key", opener=mock_opener)
    assert enriched.cve is None
    assert enriched.cvss is None


def test_nvd_lookup_caches_results_for_same_product_version():
    """Identical product and version strings reuse in-memory cache to prevent redundant queries."""
    nvd_response_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(nvd_response_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_opener = MagicMock(return_value=mock_resp)

    f1 = Finding(source_tool="nmap", affected_asset="10.0.0.1:80", description="Port 80", product="Apache", version="2.4.49")
    f2 = Finding(source_tool="nmap", affected_asset="10.0.0.2:80", description="Port 80", product="Apache", version="2.4.49")

    e1 = enrich_finding_with_nvd(f1, api_key="valid-test-key", opener=mock_opener)
    e2 = enrich_finding_with_nvd(f2, api_key="valid-test-key", opener=mock_opener)

    assert e1.cve == "CVE-2021-41773"
    assert e2.cve == "CVE-2021-41773"
    # Network call must have fired exactly once
    assert mock_opener.call_count == 1


def test_result_ingestion_integrates_tier1_and_tier2(tmp_path: Path):
    """Result Ingestion pipeline stores correlated findings into SQLite with audit events."""
    run_id = "run-ingest-step-1"
    context, repo = _make_context(tmp_path, run_id, "nmap")

    # Finding 1: Native CVE from ZAP (Tier 1)
    f1 = Finding(
        source_tool="zap",
        affected_asset="10.0.0.5:80/login",
        description="XSS in input field",
        cve="CVE-2020-9999",
        cwe="CWE-79",
        severity="Medium",
    )

    # Finding 2: Unverified finding with no product/version -> stays cve=None
    f2 = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.5:22",
        description="SSH port open",
        severity="Info",
    )

    # Finding 3: Finding with scanner-verified product & version, pre-cached NVD lookup
    _NVD_LOOKUP_CACHE["apache:2.4.49"] = {
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "High",
        "cwe": "CWE-22",
    }
    f3 = Finding(
        source_tool="nmap",
        affected_asset="10.0.0.5:8080",
        description="Apache HTTP service",
        product="Apache",
        version="2.4.49",
        severity="Info",
    )

    correlated = ingest_and_store_findings(repo, run_id, [f1, f2, f3], api_key="some-key")

    assert len(correlated) == 3

    # Check Tier 1
    cve_finding = next(f for f in correlated if f.cve == "CVE-2020-9999")
    assert cve_finding.cwe == "CWE-79"
    assert cve_finding.severity == Severity.MEDIUM

    # Check Tier 2 enriched via NVD
    enriched_finding = next(f for f in correlated if f.cve == "CVE-2021-41773")
    assert enriched_finding.cvss == 7.5
    assert enriched_finding.severity == Severity.HIGH
    assert enriched_finding.cwe == "CWE-22"

    # Check Unenriched
    non_cve_finding = next(f for f in correlated if f.cve is None)
    assert non_cve_finding.severity == Severity.INFO

    # Audit event verified
    events = [e for e in repo.list_audit_events() if e.event_type == "findings_ingested"]
    assert len(events) == 1
    assert events[0].detail["correlated_count"] == 3
