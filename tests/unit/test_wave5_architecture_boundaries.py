from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

from scripts.check_architecture import Violation, _isolated_wave5_module_boundary_violations

REPOSITORY = Path(__file__).resolve().parents[2]


def _trusted_time_policy() -> tuple[
    dict[str, Path],
    dict[Path, frozenset[str]],
    dict[Path, str],
    frozenset[str],
]:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    return (
        {
            module: Path(path)
            for module, path in scan["trusted_time_v2_isolated_module_paths"].items()
        },
        {
            Path(path): frozenset(bindings)
            for path, bindings in scan["trusted_time_v2_allowed_imports"].items()
        },
        {Path(path): digest for path, digest in scan["trusted_time_v2_module_ast_sha256"].items()},
        frozenset(scan["trusted_time_v2_reserved_symbols"]),
    )


def _trusted_time_violations(source: str, *, relative_path: Path) -> list[Violation]:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _trusted_time_policy()
    return _isolated_wave5_module_boundary_violations(
        ast.parse(source),
        boundary="trusted-time lifecycle-v2 milestone-one boundary",
        policy_enabled=True,
        relative_path=relative_path,
        module_paths=module_paths,
        allowed_imports=allowed_imports,
        module_ast_sha256=module_ast_sha256,
        reserved_symbols=reserved_symbols,
    )


@pytest.mark.parametrize(
    "source",
    [
        "from packages.domain.trusted_time_graceful_stop_v2 import "
        "_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY",
        "from packages.persistence.trusted_time_graceful_stop_v2 import "
        "_open_injected_lifecycle_v2_repository",
        "import packages.application.trusted_time_graceful_stop_v2_admission",
        "from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts "
        "import _LIFECYCLE_V2_BRIDGE_CAPABILITY",
        "name = '_consume_' + 'loaded_decision_receipt_for_v2'",
        "owner._retain_progress(record)",
    ],
)
def test_trusted_time_v2_boundary_rejects_unreviewed_reachability(source: str) -> None:
    assert _trusted_time_violations(
        source,
        relative_path=Path("packages/application/adversarial_trusted_time_v2.py"),
    )


def test_trusted_time_v2_boundary_accepts_exact_reviewed_modules_and_importers() -> None:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _trusted_time_policy()
    reviewed_paths = frozenset(module_paths.values()) | frozenset(allowed_imports)
    for relative_path in reviewed_paths:
        tree = ast.parse((REPOSITORY / relative_path).read_text(encoding="utf-8"))
        assert not _isolated_wave5_module_boundary_violations(
            tree,
            boundary="trusted-time lifecycle-v2 milestone-one boundary",
            policy_enabled=True,
            relative_path=relative_path,
            module_paths=module_paths,
            allowed_imports=allowed_imports,
            module_ast_sha256=module_ast_sha256,
            reserved_symbols=reserved_symbols,
        )


def test_trusted_time_v2_boundary_rejects_protected_module_ast_drift() -> None:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _trusted_time_policy()
    relative_path = module_paths["packages.domain.trusted_time_graceful_stop_v2"]
    source = (REPOSITORY / relative_path).read_text(encoding="utf-8") + "\nDRIFT = True\n"
    assert _isolated_wave5_module_boundary_violations(
        ast.parse(source),
        boundary="trusted-time lifecycle-v2 milestone-one boundary",
        policy_enabled=True,
        relative_path=relative_path,
        module_paths=module_paths,
        allowed_imports=allowed_imports,
        module_ast_sha256=module_ast_sha256,
        reserved_symbols=reserved_symbols,
    )


def test_wave5_isolated_module_boundary_noops_when_policy_is_absent() -> None:
    assert not _isolated_wave5_module_boundary_violations(
        ast.parse("owner._retain_progress(record)"),
        boundary="absent Wave 5 policy",
        policy_enabled=False,
        relative_path=Path("packages/application/legacy.py"),
        module_paths={},
        allowed_imports={},
        module_ast_sha256={},
        reserved_symbols=frozenset(),
    )
