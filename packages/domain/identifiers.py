"""Deterministic identifiers make replay output byte-for-byte stable."""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5


def deterministic_id(kind: str, *parts: object) -> str:
    material = ":".join((kind, *(str(part) for part in parts)))
    return str(uuid5(NAMESPACE_URL, f"autoquant-trader:{material}"))
