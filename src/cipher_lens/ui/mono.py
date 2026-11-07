"""Shared accessible Neon-accented Bento tokens for Streamlit pages."""

from __future__ import annotations

import base64
import html
from functools import lru_cache
from pathlib import Path
from typing import Mapping

import streamlit as st
from pydantic import ValidationError as PydanticValidationError


HERO_ART_PATH = Path(__file__).resolve().parents[3] / "Logo-landscape.png"
# The user-approved landscape artwork layout is 2898 × 621. Keep the hero's
# ratio explicit so its composition remains stable when Streamlit rerenders.
HERO_ASPECT_RATIO = (2898, 621)


def apply_tokens() -> None:
    """Apply the shared cream workspace, dark rail, bento cards, and accessibility states."""
    st.markdown(
        """
        <style>
          :root { --cl-primary: #BBF351; --cl-surface: #FFF5E6; --cl-panel: #FFFDF8; --cl-text: #20231B; --cl-label: #064E56; --cl-muted: #625E52; --cl-line: #E5D7C0; --cl-rail: #161616; --cl-rail-text: #F7F3EB; --cl-danger: #B42318; --cl-warning: #8A5700; --cl-info: #155EEF; }
          .stApp { background: var(--cl-surface); color: var(--cl-text); font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
          h1, h2, h3, p, label, div, button, input, textarea { font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
          code, pre, .cl-tech, .cl-status { font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace; }
          [data-testid="stSidebar"] { background: var(--cl-rail); border-right: 1px solid #2A2A2A; }
          [data-testid="stSidebar"] * { color: var(--cl-rail-text); }
          [data-testid="stSidebar"] [role="radiogroup"] { gap: 0.4rem; }
          [data-testid="stSidebar"] label { min-height: 44px; border-radius: 10px; padding: 0.55rem 0.65rem; }
          [data-testid="stSidebar"] label:hover { background: #272727; }
          [data-testid="stForm"], [data-testid="stVerticalBlockBorderWrapper"] { border: 1px solid var(--cl-line); background: var(--cl-panel); border-radius: 18px; padding: 1.25rem; box-shadow: 0 10px 28px rgba(77, 57, 28, 0.08); }
          [data-testid="stForm"] { margin-top: 1rem; }
          .cl-kicker { color: #516D18; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
          .cl-muted { color: var(--cl-muted); max-width: 46rem; }
          [data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p, [data-testid="stWidgetLabel"] label { color: var(--cl-label) !important; font-weight: 700 !important; opacity: 1 !important; }
          .cl-inline-error { display: flex; align-items: center; min-height: 44px; margin: 0.75rem 0; padding: 0.65rem 0.85rem; border: 1px solid #EEB4AD; border-radius: 12px; background: #FFF4F2; color: #8C1D18; font-weight: 650; }
          .cl-hero-card { position: relative; display: flex; align-items: center; min-height: 0; overflow: hidden; background-color: #FFF1CE; background-size: cover; background-position: right center; background-repeat: no-repeat; border: 1px solid #E7D0A2; border-radius: 24px; padding: 1.5rem 1.75rem; box-shadow: 0 12px 28px rgba(77, 57, 28, 0.10); }
          .cl-hero-content { position: relative; z-index: 1; flex: 0 0 60%; max-width: 60%; }
          .cl-hero-title { color: var(--cl-label); font-size: clamp(2rem, 4vw, 3.5rem); font-weight: 800; letter-spacing: -0.04em; line-height: 1.05; margin: 0.45rem 0 0.75rem; }
          .cl-hero-copy { color: #2E3934; font-size: 1.05rem; line-height: 1.55; max-width: 43rem; }
          .cl-card { border: 1px solid var(--cl-line); border-radius: 16px; padding: 1rem 1.1rem; margin: 0.75rem 0; background: var(--cl-panel); box-shadow: 0 8px 20px rgba(77, 57, 28, 0.06); }
          .cl-success-card { border-color: #94C93D; background: #F7FFE8; }
          .cl-status { display: inline-block; padding: 0.22rem 0.55rem; border: 1px solid var(--cl-line); border-radius: 999px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
          .cl-status-done { color: #355B00; border-color: #8DBE39; background: #F4FFE0; }
          .cl-status-running, .cl-status-parsing { color: var(--cl-info); border-color: #84ADFF; background: #F0F5FF; }
          .cl-status-failed, .cl-status-blocked { color: var(--cl-danger); border-color: #F3A6A0; background: #FFF2F0; }
          .cl-status-awaiting-approval { color: var(--cl-warning); border-color: #E3B65D; background: #FFF7E4; }
          button, [data-testid="stFormSubmitButton"] button { min-height: 44px; border-radius: 10px !important; }
          button[kind="primary"], [data-testid="stFormSubmitButton"] button { background: var(--cl-primary); border-color: #9CCB42; color: #20231B; font-weight: 750; }
          button[kind="primary"]:hover, [data-testid="stFormSubmitButton"] button:hover { background: #C8FA6A; color: #20231B; }
          input, textarea { border-radius: 10px !important; }
          :focus-visible { outline: 3px solid #547D11 !important; outline-offset: 2px !important; }
          @media (max-width: 700px) { [data-testid="stForm"], [data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px; padding: 1rem; } .cl-hero-card { padding: 1.2rem; } .cl-hero-content { flex-basis: 76%; max-width: 76%; } }
        </style>
        """,
        unsafe_allow_html=True,
    )


@lru_cache(maxsize=1)
def _hero_image_data_uri() -> str:
    """Encode the user-supplied landscape asset for raw shared hero markup."""
    if not HERO_ART_PATH.is_file():
        return ""
    encoded = base64.b64encode(HERO_ART_PATH.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


@lru_cache(maxsize=1)
def _hero_aspect_ratio() -> tuple[int, int]:
    """Return the approved landscape composition ratio for the shared hero."""
    return HERO_ASPECT_RATIO


def heading(kicker: str, title: str, description: str) -> None:
    """Render one raw shared hero card with the supplied landscape file as its background."""
    image = _hero_image_data_uri()
    width, height = _hero_aspect_ratio()
    background = (
        f' style="aspect-ratio: {width} / {height}; background-image: url(\'{image}\');"'
        if image else f' style="aspect-ratio: {width} / {height};"'
    )
    st.markdown(
        f'<section class="cl-hero-card"{background}><div class="cl-hero-content">'
        f'<div class="cl-kicker">{html.escape(kicker)}</div>'
        f'<div class="cl-hero-title">{html.escape(title)}</div>'
        f'<div class="cl-hero-copy">{html.escape(description)}</div>'
        '</div></section>',
        unsafe_allow_html=True,
    )


def friendly_validation_message(error: Exception, field_labels: Mapping[str, str] | None = None) -> str:
    """Convert Pydantic's developer diagnostics into one concise analyst-facing message."""
    if isinstance(error, PydanticValidationError):
        labels = field_labels or {}
        missing = [
            labels.get(str(item["loc"][0]), str(item["loc"][0]).replace("_", " ").capitalize())
            for item in error.errors()
            if item.get("type") == "missing" and item.get("loc")
        ]
        if len(missing) == 1:
            return f"{missing[0]} is required."
        return "Please fill in the required fields before saving."
    return str(error)


def inline_error(message: str) -> None:
    """Display a compact shared alert without exposing developer validation detail."""
    st.markdown(f'<div class="cl-inline-error">{html.escape(message)}</div>', unsafe_allow_html=True)


def status_badge(status: str) -> str:
    """Return a styled status label for controlled persisted application state."""
    safe_status = status.lower().replace("_", "-")
    return f'<span class="cl-status cl-status-{safe_status}">{html.escape(status.replace("_", " "))}</span>'
