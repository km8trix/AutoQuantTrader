"""Enforce the repository's dependency direction without importing project code."""

from __future__ import annotations

import argparse
import ast
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_STRATEGY_START_AUTHORIZATION_MODULE = "packages.domain.strategy_invocation_lifecycle"
_STRATEGY_START_AUTHORIZATION_FACTORY = "_strategy_invocation_start_authorization"
_STRATEGY_START_AUTHORIZATION_ISSUER = Path("packages/persistence/strategy_invocation_lifecycle.py")


@dataclass(frozen=True, slots=True)
class Violation:
    path: Path
    line: int
    message: str


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("infra/architecture-boundaries.toml"),
        help="TOML boundary configuration, relative to the repository root",
    )
    return parser.parse_args()


def _is_below(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def _matches_namespace(module: str, namespaces: tuple[str, ...]) -> bool:
    return any(
        module == namespace or module.startswith(f"{namespace}.") for namespace in namespaces
    )


def _imports(tree: ast.AST) -> list[tuple[int, str, bool]]:
    imports: list[tuple[int, str, bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((node.lineno, alias.name, False) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.lineno, node.module, node.level > 0))
    return imports


def _load_config(config_path: Path) -> dict[str, Any]:
    try:
        with config_path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except FileNotFoundError as error:
        raise SystemExit(f"Architecture configuration not found: {config_path}") from error

    scan = config.get("scan")
    if not isinstance(scan, dict):
        raise SystemExit(f"Missing [scan] table in {config_path}")
    return scan


def _resolve_roots(repository: Path, values: list[str]) -> tuple[Path, ...]:
    return tuple((repository / value).resolve() for value in values)


def check(repository: Path, config_path: Path) -> list[Violation]:
    scan = _load_config(config_path)
    source_roots = _resolve_roots(repository, scan["source_roots"])
    package_roots = _resolve_roots(repository, scan["package_roots"])
    primitive_roots = _resolve_roots(repository, scan["primitive_roots"])
    domain_roots = _resolve_roots(repository, scan["domain_roots"])
    side_effect_free_roots = _resolve_roots(repository, scan["side_effect_free_roots"])
    primitive_namespaces = tuple(scan["primitive_namespaces"])
    composition_namespaces = tuple(scan["composition_namespaces"])
    forbidden_domain_imports = tuple(scan["forbidden_domain_imports"])
    forbidden_side_effect_imports = tuple(scan["forbidden_side_effect_imports"])

    violations: list[Violation] = []
    python_files = sorted(
        path
        for source_root in source_roots
        if source_root.exists()
        for path in source_root.rglob("*.py")
    )

    for path in python_files:
        resolved_path = path.resolve()
        relative_path = path.relative_to(repository)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
        except SyntaxError as error:
            violations.append(
                Violation(relative_path, error.lineno or 1, f"cannot parse file: {error.msg}")
            )
            continue

        if relative_path != _STRATEGY_START_AUTHORIZATION_ISSUER:
            for node in ast.walk(tree):
                imports_private_factory = (
                    isinstance(node, ast.ImportFrom)
                    and node.module == _STRATEGY_START_AUTHORIZATION_MODULE
                    and any(
                        alias.name == _STRATEGY_START_AUTHORIZATION_FACTORY for alias in node.names
                    )
                )
                accesses_private_factory = (
                    isinstance(node, ast.Attribute)
                    and node.attr == _STRATEGY_START_AUTHORIZATION_FACTORY
                )
                if imports_private_factory or accesses_private_factory:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            "only the durable strategy lifecycle repository may "
                            "issue sealed strategy start authorization",
                        )
                    )

        for line, module, is_relative in _imports(tree):
            if _is_below(resolved_path, package_roots) and _matches_namespace(
                module, composition_namespaces
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"package code cannot import composition root '{module}'",
                    )
                )

            if _is_below(resolved_path, domain_roots) and _matches_namespace(
                module, forbidden_domain_imports
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"domain code cannot import framework/adapter dependency '{module}'",
                    )
                )

            if _is_below(resolved_path, side_effect_free_roots) and _matches_namespace(
                module, forbidden_side_effect_imports
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        "pure strategy replay cannot import ambient side-effect authority "
                        f"'{module}'",
                    )
                )

            if not _is_below(resolved_path, primitive_roots):
                continue
            top_level = module.partition(".")[0]
            is_stdlib = top_level in sys.stdlib_module_names
            is_self_import = is_relative or _matches_namespace(module, primitive_namespaces)
            if not is_stdlib and not is_self_import:
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        "domain primitives may only import the standard library or "
                        f"themselves: '{module}'",
                    )
                )

    return violations


def main() -> int:
    args = _parse_args()
    repository = Path(__file__).resolve().parents[1]
    config_path = args.config if args.config.is_absolute() else repository / args.config
    violations = check(repository, config_path)

    if violations:
        for violation in violations:
            print(f"{violation.path}:{violation.line}: {violation.message}")
        print(f"Architecture boundary check failed with {len(violations)} violation(s).")
        return 1

    print("Architecture boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
