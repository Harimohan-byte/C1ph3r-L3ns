"""Unit tests for the truthful seven-tool integration matrix."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError as PydanticValidationError

from cipher_lens.services.integrations import (
    IntegrationStatus,
    ToolCapability,
    check_nikto_availability,
    check_nmap_availability,
    check_zap_availability,
    get_integration_matrix,
)
from cipher_lens.ui.integrations_page import _status_pill


def test_integration_matrix_contains_all_seven_tools():
    matrix = get_integration_matrix()
    assert len(matrix) == 7

    names = [tool.name for tool in matrix]
    expected_names = [
        "Nmap",
        "OWASP ZAP",
        "Nikto",
        "Nessus",
        "OpenVAS / Greenbone",
        "Burp Suite Community",
        "Metasploit",
    ]
    assert names == expected_names


def test_declared_statuses_truthful_and_honest():
    matrix = get_integration_matrix()
    tools = {tool.name: tool for tool in matrix}

    # Nessus: Import-only, native export formats
    nessus = tools["Nessus"]
    assert nessus.status == IntegrationStatus.IMPORT_ONLY
    assert ".nessus" in nessus.supported_formats
    assert "no live daemon claimed" in nessus.availability_details.lower()

    # OpenVAS: Import-only
    openvas = tools["OpenVAS / Greenbone"]
    assert openvas.status == IntegrationStatus.IMPORT_ONLY
    assert ".xml" in openvas.supported_formats

    # Burp Community: Import-only, honest free-tier disclosure
    burp = tools["Burp Suite Community"]
    assert burp.status == IntegrationStatus.IMPORT_ONLY
    assert "community" in burp.limitations.lower()
    assert "rest api" in burp.limitations.lower()

    # Metasploit: Planned, strictly forbids autonomous exploitation
    metasploit = tools["Metasploit"]
    assert metasploit.status == IntegrationStatus.PLANNED
    assert not metasploit.is_available
    assert "autonomous exploitation is strictly forbidden" in metasploit.limitations.lower()


def test_live_checks_graceful_fallback():
    # If tools are not installed or daemon is unreachable, check functions return (False, details)
    with patch("shutil.which", return_value=None):
        nmap_ok, nmap_msg = check_nmap_availability()
        assert not nmap_ok
        assert "not found" in nmap_msg.lower()

        nikto_ok, nikto_msg = check_nikto_availability()
        assert not nikto_ok
        assert "not found" in nikto_msg.lower()

    with patch("cipher_lens.services.integrations.urlopen", side_effect=OSError("Unreachable")):
        zap_ok, zap_msg = check_zap_availability()
        assert not zap_ok
        assert "unreachable" in zap_msg.lower()


def test_live_checks_mocked_available():
    with patch("shutil.which", return_value="/usr/local/bin/nmap"):
        nmap_ok, nmap_msg = check_nmap_availability()
        assert nmap_ok
        assert "/usr/local/bin/nmap" in nmap_msg

    with patch("shutil.which", return_value="/usr/local/bin/nikto"):
        nikto_ok, nikto_msg = check_nikto_availability()
        assert nikto_ok
        assert "/usr/local/bin/nikto" in nikto_msg

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    with patch("cipher_lens.services.integrations.urlopen", return_value=mock_resp):
        zap_ok, zap_msg = check_zap_availability()
        assert zap_ok
        assert "reachable" in zap_msg.lower()


def test_tool_capability_extra_fields_forbidden():
    with pytest.raises(PydanticValidationError):
        ToolCapability(
            name="Custom",
            status=IntegrationStatus.LIVE,
            expected_role="Testing",
            coverage_type="Network",
            declared_mode="CLI",
            availability_details="Available",
            is_available=True,
            limitations="None",
            supported_formats=[],
            last_verified="2026-11-08",
            unsupported_extra_field="invalid",
        )


def test_status_pill_helper():
    live_pill = _status_pill(IntegrationStatus.LIVE)
    assert "cl-status-done" in live_pill
    assert "Live" in live_pill

    import_pill = _status_pill(IntegrationStatus.IMPORT_ONLY)
    assert "cl-status-running" in import_pill
    assert "Import-only" in import_pill

    planned_pill = _status_pill(IntegrationStatus.PLANNED)
    assert "cl-status-awaiting-approval" in planned_pill
    assert "Planned" in planned_pill
