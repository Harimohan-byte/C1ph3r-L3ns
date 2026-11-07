"""Streamlit entry point for CIPHER LENS."""

from __future__ import annotations

import streamlit as st

from cipher_lens.config import database_path
from cipher_lens.persistence.repositories import Repository
from cipher_lens.ui.mono import apply_tokens
from cipher_lens.ui.assessment_page import render as render_assessment_page
from cipher_lens.ui.scope_page import render as render_scope_page


st.set_page_config(page_title="CIPHER LENS", page_icon="◈", layout="wide")
apply_tokens()
repository = Repository(database_path())
workspace = st.sidebar.radio("Workspace", ("Authorized scope", "Assessment status"))
if workspace == "Authorized scope":
    render_scope_page(repository)
else:
    render_assessment_page(repository)
