"""Mutations exercise boundaries without running the injected code."""

from pathlib import Path

import pytest

from scripts.check_personal_architecture import check


def _source(root: Path, name: str, content: str = "") -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _source(
        tmp_path,
        "infra/architecture-boundaries.toml",
        """[scan]
source_roots = ["apps", "packages"]
domain_roots = ["packages/domain"]
forbidden_domain_imports = ["requests", "sqlalchemy"]
side_effect_free_roots = ["packages/domain/strategy.py"]
forbidden_side_effect_imports = ["os", "time", "subprocess"]
""",
    )
    _source(
        tmp_path, "apps/trader/personal_simulation.py", "from packages.application import local\n"
    )
    _source(tmp_path, "packages/application/local.py", "from datetime import UTC, datetime\n")
    return tmp_path


def test_standard_profile_accepts_plain_runtime(repository: Path) -> None:
    assert check(repository) == []


@pytest.mark.parametrize(
    ("name", "code", "message"),
    [
        ("packages/domain/order.py", "import sqlalchemy as db", "framework"),
        ("packages/domain/order.py", "from ..adapters import broker", "outside the domain"),
        ("packages/domain/strategy.py", "import os as host", "ambient effect"),
        ("packages/application/local.py", "import apps.api.main", "composition root"),
        ("packages/application/local.py", "from . import provider", "provider/native"),
        ("packages/__init__.py", "import requests", "provider/native"),
        ("apps/__init__.py", "import urllib.request", "provider/native"),
        ("apps/trader/__init__.py", "from http import client", "provider/native"),
        ("packages/application/local.py", "__import__('requests')", "dynamic code"),
    ],
)
def test_mutation_is_rejected(repository: Path, name: str, code: str, message: str) -> None:
    _source(repository, "packages/application/provider.py", "from requests import get")
    _source(repository, name, code)
    assert any(message in error for error in check(repository))


def test_missing_entry_does_not_pass(repository: Path) -> None:
    (repository / "apps/trader/personal_simulation.py").unlink()
    assert check(repository) == ["personal simulation composition root is missing"]
