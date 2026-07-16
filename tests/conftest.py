"""Test-suite environment isolation."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_operational_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent ambient runtime configuration from redirecting test migrations."""
    monkeypatch.delenv("AQT_DATABASE_URL", raising=False)
