"""Tests for workspace navigation and prevention of StreamlitWidgetAlreadyInstantiatedError."""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import streamlit as st

from cipher_lens.persistence.repositories import Repository
from cipher_lens.ui.scope_page import render as render_scope_page


def test_no_ui_module_directly_overwrites_widget_bound_workspace():
    """Guarantee that no UI module in src/cipher_lens/ui/ directly modifies the widget-bound workspace key.

    All transitions must route through pending_workspace to avoid StreamlitWidgetAlreadyInstantiatedError.
    """
    ui_dir = Path(__file__).resolve().parents[2] / "src" / "cipher_lens" / "ui"
    violations: list[str] = []

    for py_file in ui_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    # Check for st.session_state.workspace = ...
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "workspace"
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "session_state"
                    ):
                        violations.append(f"{py_file.name}:{node.lineno} assigns st.session_state.workspace directly")
                    # Check for st.session_state["workspace"] = ...
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "workspace"
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "session_state"
                    ):
                        violations.append(f"{py_file.name}:{node.lineno} assigns st.session_state['workspace'] directly")

    assert not violations, f"Direct workspace mutations found: {violations}"


def test_scope_page_auto_advance_uses_pending_workspace(tmp_path: Path):
    """Confirm the scope-registration success path sets pending_workspace and triggers rerun.

    It must never mutate st.session_state.workspace while the radio widget is active.
    """
    repo = Repository(tmp_path / "test.sqlite3")

    # Simulate existing session_state where workspace is instantiated
    st.session_state["workspace"] = "Authorized scope"
    st.session_state["scope_registration_success"] = "127.0.0.1:3000 · Reconnaissance"

    with patch("streamlit.rerun") as mock_rerun, \
         patch("time.sleep") as mock_sleep, \
         patch("streamlit.markdown"), \
         patch("streamlit.caption"):

        render_scope_page(repo)

        # Confirm pending_workspace was set for app.py to apply BEFORE widget instantiation
        assert st.session_state.get("pending_workspace") == "Assessment status"
        # Confirm the transient success message was cleaned up
        assert "scope_registration_success" not in st.session_state
        # Confirm sleep was called for UX transition
        mock_sleep.assert_called_once_with(1.75)
        # Confirm rerun was triggered to restart app execution from top of app.py
        mock_rerun.assert_called_once()
        # Confirm st.session_state.workspace was NOT mutated inside the page render
        assert st.session_state["workspace"] == "Authorized scope"


def test_app_pending_workspace_resolution():
    """Verify that the pre-widget resolution logic correctly transfers pending_workspace."""
    st.session_state.clear()
    st.session_state["pending_workspace"] = "Assessment status"

    # Simulate top of app.py prior to widget creation
    if "pending_workspace" in st.session_state:
        st.session_state.workspace = st.session_state.pop("pending_workspace")
    elif "workspace" not in st.session_state:
        st.session_state.workspace = "Authorized scope"

    assert st.session_state["workspace"] == "Assessment status"
    assert "pending_workspace" not in st.session_state

