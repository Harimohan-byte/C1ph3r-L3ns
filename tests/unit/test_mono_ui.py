"""Unit tests for shared Mono UI tokens, landscape hero art, and styling."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cipher_lens.ui.mono import (
    _find_hero_art_path,
    _hero_image_data_uri,
    apply_tokens,
    heading,
)


def test_find_hero_art_path_resolves_existing_file():
    """Verify that the hero art locator finds Logo-landscape.png."""
    path = _find_hero_art_path()
    assert path is not None
    assert path.is_file()
    assert "landscape" in path.name.lower()


def test_hero_image_data_uri_returns_valid_png_base64():
    """Verify that _hero_image_data_uri produces a non-empty PNG data URI."""
    uri = _hero_image_data_uri()
    assert uri.startswith("data:image/png;base64,")
    assert len(uri) > 1000


def test_apply_tokens_contains_neon_inputs_and_bold_labels():
    """Verify that apply_tokens renders CSS with high-visibility bold labels and neon inputs."""
    with patch("streamlit.markdown") as mock_markdown:
        apply_tokens()
        assert mock_markdown.called
        css_rendered = mock_markdown.call_args[0][0]
        # High-contrast bold widget labels
        assert "font-weight: 850" in css_rendered
        assert "font-size: 1.15rem" in css_rendered
        # Neon text inside dark text box
        assert "#BBF351" in css_rendered
        assert "-webkit-text-fill-color: #BBF351" in css_rendered
        assert "background-color: #0C0F0C" in css_rendered


def test_heading_renders_card_with_background_image():
    """Verify that heading renders a hero card with the landscape background image."""
    with patch("streamlit.markdown") as mock_markdown:
        heading("Test Kicker", "Test Title", "Test Description")
        assert mock_markdown.called
        rendered = mock_markdown.call_args[0][0]
        assert "cl-hero-card" in rendered
        assert "Test Kicker" in rendered
        assert "Test Title" in rendered
        assert "background-image: url('data:image/png;base64," in rendered
