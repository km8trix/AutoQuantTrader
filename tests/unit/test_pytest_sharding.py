"""Regression tests for deterministic outer-suite CI sharding."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import conftest as suite_conftest
import pytest

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class _Item:
    nodeid: str


@dataclass
class _DeselectionHook:
    items: list[_Item] = field(default_factory=list)

    def pytest_deselected(self, *, items: list[_Item]) -> None:
        self.items.extend(items)


class _Config:
    def __init__(
        self,
        *,
        shard_count: int | None,
        shard_index: int | None,
        test_postgres_url: str | None = None,
    ) -> None:
        self._options = {
            "aqt_shard_count": shard_count,
            "aqt_shard_index": shard_index,
            "aqt_test_postgres_url": test_postgres_url,
        }
        self.hook = _DeselectionHook()

    def getoption(self, name: str) -> int | str | None:
        return self._options[name]


def _configuration(
    *,
    shard_count: int | None,
    shard_index: int | None,
    test_postgres_url: str | None = None,
) -> _Config:
    return _Config(
        shard_count=shard_count,
        shard_index=shard_index,
        test_postgres_url=test_postgres_url,
    )


def test_sharding_is_disabled_when_both_options_are_absent() -> None:
    config = _configuration(shard_count=None, shard_index=None)
    items = [_Item("tests/unit/test_example.py::test_one")]

    suite_conftest.pytest_collection_modifyitems(config, items)

    assert [item.nodeid for item in items] == ["tests/unit/test_example.py::test_one"]
    assert config.hook.items == []


@pytest.mark.parametrize(
    ("shard_count", "shard_index"),
    (
        (None, 0),
        (4, None),
        (0, 0),
        (33, 0),
        (4, -1),
        (4, 4),
    ),
)
def test_invalid_or_partial_shard_coordinates_are_rejected(
    shard_count: int | None,
    shard_index: int | None,
) -> None:
    with pytest.raises(pytest.UsageError):
        suite_conftest._shard_configuration(
            _configuration(shard_count=shard_count, shard_index=shard_index)
        )


def test_sha256_shards_are_stable_disjoint_and_complete() -> None:
    nodeids = tuple(
        f"tests/unit/test_example.py::test_case[{case}]"
        for case in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")
    )
    assignments = {nodeid: suite_conftest._shard_for_nodeid(nodeid, 4) for nodeid in nodeids}

    assert assignments == {
        "tests/unit/test_example.py::test_case[alpha]": 3,
        "tests/unit/test_example.py::test_case[beta]": 3,
        "tests/unit/test_example.py::test_case[gamma]": 3,
        "tests/unit/test_example.py::test_case[delta]": 2,
        "tests/unit/test_example.py::test_case[epsilon]": 2,
        "tests/unit/test_example.py::test_case[zeta]": 3,
        "tests/unit/test_example.py::test_case[eta]": 2,
        "tests/unit/test_example.py::test_case[theta]": 0,
    }
    shards = tuple(
        {nodeid for nodeid in nodeids if assignments[nodeid] == shard_index}
        for shard_index in range(4)
    )
    assert set().union(*shards) == set(nodeids)
    assert sum(len(shard) for shard in shards) == len(nodeids)
    assert {
        nodeid: suite_conftest._shard_for_nodeid(nodeid, 4) for nodeid in reversed(nodeids)
    } == assignments


def test_collection_hook_preserves_selected_order_and_reports_deselections() -> None:
    original = [
        _Item(f"tests/unit/test_example.py::test_case[{case}]")
        for case in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")
    ]
    config = _configuration(shard_count=4, shard_index=3)
    items = list(original)

    suite_conftest.pytest_collection_modifyitems(config, items)

    assert [item.nodeid for item in items] == [
        "tests/unit/test_example.py::test_case[alpha]",
        "tests/unit/test_example.py::test_case[beta]",
        "tests/unit/test_example.py::test_case[gamma]",
        "tests/unit/test_example.py::test_case[zeta]",
    ]
    assert [item.nodeid for item in config.hook.items] == [
        item.nodeid for item in original if item not in items
    ]


def test_explicit_test_postgres_url_is_restored_after_launcher_sanitization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_url = "postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test"
    monkeypatch.delenv("AQT_TEST_POSTGRES_URL", raising=False)

    suite_conftest._install_test_postgres_url(
        _configuration(shard_count=None, shard_index=None, test_postgres_url=test_url)
    )

    assert os.environ["AQT_TEST_POSTGRES_URL"] == test_url


def test_absent_test_postgres_option_does_not_override_local_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_url = "postgresql+psycopg://local-only"
    monkeypatch.setenv("AQT_TEST_POSTGRES_URL", local_url)

    suite_conftest._install_test_postgres_url(_configuration(shard_count=None, shard_index=None))

    assert os.environ["AQT_TEST_POSTGRES_URL"] == local_url


def test_empty_explicit_test_postgres_url_is_rejected() -> None:
    with pytest.raises(pytest.UsageError):
        suite_conftest._install_test_postgres_url(
            _configuration(shard_count=None, shard_index=None, test_postgres_url="")
        )


def test_configured_test_postgres_url_is_visible_to_tests(request: pytest.FixtureRequest) -> None:
    configured_url = request.config.getoption("aqt_test_postgres_url")
    if configured_url is not None:
        assert os.environ["AQT_TEST_POSTGRES_URL"] == configured_url


def test_ci_workflow_runs_four_explicit_outer_suite_shards() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    backend_job = workflow.split("\n  backend:\n", 1)[1].split("\n  native-packaging:\n", 1)[0]
    native_job = workflow.split("\n  native-packaging:\n", 1)[1].split("\n  frontend:\n", 1)[0]
    matrix = """\
    strategy:
      fail-fast: false
      matrix:
        include:
          - shard_index: 0
            shard_number: 1
          - shard_index: 1
            shard_number: 2
          - shard_index: 2
            shard_number: 3
          - shard_index: 3
            shard_number: 4
"""
    invocation = """\
          test-suite
          --aqt-test-postgres-url
          postgresql+psycopg://autoquant:autoquant@localhost:5432/autoquant_test
          --aqt-shard-count 4
          --aqt-shard-index ${{ matrix.shard_index }}
"""

    assert backend_job.count(matrix) == 1
    assert backend_job.count(invocation) == 1
    assert "AQT_TEST_POSTGRES_URL:" not in backend_job
    assert "Backend quality and tests (shard ${{ matrix.shard_number }} of 4)" in backend_job
    assert "--aqt-shard-count" not in native_job
    assert "--aqt-shard-index" not in native_job
