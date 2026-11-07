"""Compact, high-contrast Mono design tokens for Streamlit pages."""

from __future__ import annotations

import streamlit as st


def apply_tokens() -> None:
    st.markdown(
        """
        <style>
          :root { --cl-green: #37F712; --cl-blue: #00A6F4; --cl-surface: #121212; --cl-panel: #1b1b1b; --cl-text: #f3f4f6; --cl-muted: #cbd5e1; }
          .stApp { background: var(--cl-surface); color: var(--cl-text); }
          h1, h2, h3, p, label, div { font-family: "Space Mono", "JetBrains Mono", monospace; }
          [data-testid="stForm"] { border: 1px solid #475569; background: var(--cl-panel); padding: 1.25rem; }
          .cl-kicker { color: var(--cl-green); font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; }
          .cl-muted { color: var(--cl-muted); }
          .cl-card { border-left: 3px solid var(--cl-blue); padding: 0.75rem 1rem; margin: 0.5rem 0; background: var(--cl-panel); }
          .cl-status { display: inline-block; padding: 0.15rem 0.45rem; border: 1px solid #475569; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; }
          .cl-status-done { color: var(--cl-green); border-color: var(--cl-green); }
          .cl-status-running, .cl-status-parsing { color: var(--cl-blue); border-color: var(--cl-blue); }
          .cl-status-failed, .cl-status-blocked { color: #FF2157; border-color: #FF2157; }
          .cl-status-awaiting-approval { color: #FE9900; border-color: #FE9900; }
          button[kind="primary"] { background: var(--cl-green); color: #071007; font-weight: 700; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def heading(kicker: str, title: str, description: str) -> None:
    st.markdown(f'<div class="cl-kicker">{kicker}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="cl-muted">{description}</div>', unsafe_allow_html=True)


def status_badge(status: str) -> str:
    """Return a Mono status label for controlled values from persisted application state."""
    safe_status = status.lower().replace("_", "-")
    return f'<span class="cl-status cl-status-{safe_status}">{status.replace("_", " ")}</span>'
