"""The single scope gate that all future adapter paths must use."""

from __future__ import annotations

import ipaddress

from cipher_lens.domain.models import ActionClass, ScopeRecord
from cipher_lens.domain.validation import parse_ports, port_in_ranges, validate_target


def normalize_target(value: str) -> str:
    validated = validate_target(value)
    lowered = validated.rstrip(".").lower()
    if lowered == "localhost":
        return "127.0.0.1"
    try:
        parsed = ipaddress.ip_address(lowered)
    except ValueError:
        return lowered
    return "127.0.0.1" if parsed.is_loopback else str(parsed)


def is_in_scope(scope: ScopeRecord, target: str, port: int, action: ActionClass) -> tuple[bool, str]:
    """Return a decision for a previously validated target/port/action request.

    Callers must validate target and port grammar first. This function repeats target validation to
    maintain a fail-closed boundary if a caller violates that contract.
    """
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return False, "Port is invalid."
    try:
        candidate = normalize_target(target)
    except ValueError:
        return False, "Target is invalid."
    if candidate != scope.canonical_target:
        return False, "Target is not registered in this scope."
    if action not in scope.allowed_actions:
        return False, f"Action '{action.value}' is not authorized for this scope."
    if port_in_ranges(port, parse_ports(scope.excluded_ports, allow_empty=True)):
        return False, "Port is explicitly excluded from this scope."
    if not port_in_ranges(port, parse_ports(scope.allowed_ports)):
        return False, "Port is not in the registered allowed-port set."
    return True, "Target, port, and action are authorized."
