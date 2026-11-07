"""Strict input validation. Invalid values are rejected, never repaired."""

from __future__ import annotations

import ipaddress
import re


class ValidationError(ValueError):
    """Raised when a target or port expression does not match the accepted grammar."""


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)
PORT_TOKEN_RE = re.compile(r"^(?:[1-9]\d{0,4})(?:-[1-9]\d{0,4})?$")


def validate_target(value: str) -> str:
    """Accept one IPv4 address or DNS hostname; reject whitespace and URL syntax."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError("Enter one IP address or hostname without surrounding whitespace.")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        if not HOSTNAME_RE.fullmatch(value):
            raise ValidationError("Target must be a valid IPv4 address or hostname.") from None
        return value
    if parsed.version != 4:
        raise ValidationError("Only IPv4 addresses are accepted in this MVP.")
    return value


def parse_ports(value: str, *, allow_empty: bool = False) -> tuple[tuple[int, int], ...]:
    """Parse comma-separated port numbers/ranges without silently correcting input."""
    if value == "" and allow_empty:
        return ()
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError("Ports must be a comma-separated list such as 80,443,8000-8010.")
    parts = value.split(",")
    ranges: list[tuple[int, int]] = []
    for token in parts:
        if token != token.strip() or not PORT_TOKEN_RE.fullmatch(token):
            raise ValidationError("Each port must be a number or N-M range without spaces.")
        start_text, separator, end_text = token.partition("-")
        start = int(start_text)
        end = int(end_text) if separator else start
        if not (1 <= start <= end <= 65535):
            raise ValidationError("Ports must be between 1 and 65535, with ascending ranges.")
        ranges.append((start, end))
    return tuple(ranges)


def port_in_ranges(port: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= port <= end for start, end in ranges)
