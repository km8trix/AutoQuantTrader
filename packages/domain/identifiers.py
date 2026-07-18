"""Deterministic identifiers make replay output byte-for-byte stable."""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from packages.domain.canonical import canonical_json_text


def deterministic_id(kind: str, *parts: object) -> str:
    material = ":".join((kind, *(str(part) for part in parts)))
    return str(uuid5(NAMESPACE_URL, f"autoquant-trader:{material}"))


def canonical_id(kind: str, *parts: object) -> str:
    """Return a typed, delimiter-safe deterministic UUID for new contracts."""

    if type(kind) is not str or not kind or kind != kind.strip():
        raise ValueError("canonical ID kind must be a non-empty, trimmed string")
    material = canonical_json_text(("canonical-id-v1", kind, parts))
    return str(uuid5(NAMESPACE_URL, f"autoquant-trader:{material}"))
