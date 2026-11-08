"""Streamlit entry point for CIPHER LENS."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ root is present on sys.path for direct streamlit execution
_src_root = str(Path(__file__).resolve().parent.parent)
if _src_root not in sys.path:
    sys.path.insert(0, _src_root)

import streamlit as st

from cipher_lens.config import database_path
from cipher_lens.persistence.repositories import Repository
from cipher_lens.ui.mono import apply_tokens
from cipher_lens.ui.assessment_page import render as render_assessment_page
from cipher_lens.ui.audit_page import render as render_audit_page
from cipher_lens.ui.integrations_page import render as render_integrations_page
from cipher_lens.ui.report_page import render as render_report_page
from cipher_lens.ui.scope_page import render as render_scope_page


st.set_page_config(page_title="CIPHER LENS", page_icon="◈", layout="wide")
apply_tokens()
repository = Repository(database_path())
if "pending_workspace" in st.session_state:
    st.session_state.workspace = st.session_state.pop("pending_workspace")
elif "workspace" not in st.session_state:
    st.session_state.workspace = "Authorized scope"
workspace = st.sidebar.radio(
    "Workspace",
    ("Authorized scope", "Assessment status", "Audit trail & approvals", "Tool integrations", "VAPT report"),
    key="workspace",
)
if workspace == "Authorized scope":
    render_scope_page(repository)
elif workspace == "Assessment status":
    render_assessment_page(repository)
elif workspace == "Audit trail & approvals":
    render_audit_page(repository)
elif workspace == "Tool integrations":
    render_integrations_page(repository)
else:
    render_report_page(repository)
