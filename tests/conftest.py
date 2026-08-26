"""Test-suite environment isolation."""

from __future__ import annotations

import hashlib
import os

import pytest

_SHARD_COUNT_OPTION = "--aqt-shard-count"
_SHARD_INDEX_OPTION = "--aqt-shard-index"
_TEST_POSTGRES_URL_OPTION = "--aqt-test-postgres-url"
_TEST_POSTGRES_URL_ENVIRONMENT = "AQT_TEST_POSTGRES_URL"
_MAXIMUM_SHARD_COUNT = 32


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register explicit, outer-suite-only CI sharding controls."""
    group = parser.getgroup("autoquant-ci-sharding")
    group.addoption(
        _SHARD_COUNT_OPTION,
        action="store",
        default=None,
        dest="aqt_shard_count",
        metavar="COUNT",
        type=int,
        help="Run one of COUNT deterministic CI test shards.",
    )
    group.addoption(
        _SHARD_INDEX_OPTION,
        action="store",
        default=None,
        dest="aqt_shard_index",
        metavar="INDEX",
        type=int,
        help="Run zero-based deterministic CI test shard INDEX.",
    )
    group.addoption(
        _TEST_POSTGRES_URL_OPTION,
        action="store",
        default=None,
        dest="aqt_test_postgres_url",
        metavar="URL",
        help="Expose one explicit PostgreSQL URL to integration tests.",
    )


def _shard_configuration(config: pytest.Config) -> tuple[int, int] | None:
    shard_count = config.getoption("aqt_shard_count")
    shard_index = config.getoption("aqt_shard_index")
    if shard_count is None and shard_index is None:
        return None
    if shard_count is None or shard_index is None:
        raise pytest.UsageError(
            f"{_SHARD_COUNT_OPTION} and {_SHARD_INDEX_OPTION} must be provided together"
        )
    if not 1 <= shard_count <= _MAXIMUM_SHARD_COUNT:
        raise pytest.UsageError(
            f"{_SHARD_COUNT_OPTION} must be between 1 and {_MAXIMUM_SHARD_COUNT}"
        )
    if not 0 <= shard_index < shard_count:
        raise pytest.UsageError(
            f"{_SHARD_INDEX_OPTION} must be between 0 and {_SHARD_COUNT_OPTION} - 1"
        )
    return shard_index, shard_count


def _shard_for_nodeid(nodeid: str, shard_count: int) -> int:
    digest = hashlib.sha256(nodeid.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big") % shard_count


def _install_test_postgres_url(config: pytest.Config) -> None:
    test_postgres_url = config.getoption("aqt_test_postgres_url")
    if test_postgres_url is None:
        return
    if not test_postgres_url:
        raise pytest.UsageError(f"{_TEST_POSTGRES_URL_OPTION} must not be empty")
    os.environ[_TEST_POSTGRES_URL_ENVIRONMENT] = test_postgres_url


def pytest_configure(config: pytest.Config) -> None:
    """Validate sharding and restore an explicit sanitized test database input."""
    _shard_configuration(config)
    _install_test_postgres_url(config)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Select a stable, disjoint shard while retaining pytest's collection order."""
    shard_configuration = _shard_configuration(config)
    if shard_configuration is None:
        return
    shard_index, shard_count = shard_configuration
    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        destination = (
            selected if _shard_for_nodeid(item.nodeid, shard_count) == shard_index else deselected
        )
        destination.append(item)
    items[:] = selected
    if deselected:
        config.hook.pytest_deselected(items=deselected)


@pytest.fixture(autouse=True)
def isolate_operational_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent ambient runtime configuration from redirecting test migrations."""
    monkeypatch.delenv("AQT_DATABASE_URL", raising=False)
