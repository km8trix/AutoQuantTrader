"""Check personal-profile import boundaries without importing application code.

The historical native seal checker remains a separate diagnostic. This checker
retains its layer and pure-code rules and checks the complete local simulation
import graph. It is a static regression guard, not a Python security sandbox.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

_SIMULATION_ENTRY = "apps.trader.personal_simulation"
_RESEARCH_ENTRY = "apps.worker.personal_research"
_SIMULATION_FORBIDDEN = (
    "packages.adapters.broker",
    "packages.adapters.trusted_time",
    "packages.persistence",
    "apps.trusted_time_supervisor",
    "http",
    "urllib",
    "ssl",
    "aiohttp",
    "httpx",
    "requests",
    "socket",
    "subprocess",
    "ctypes",
    "sqlalchemy",
)
_DYNAMIC_CALLS = {"eval", "exec", "__import__", "importlib.import_module"}


def _matches(module: str, prefixes: Iterable[str]) -> bool:
    return any(module == prefix or module.startswith(prefix + ".") for prefix in prefixes)


def _below(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _imports(tree: ast.AST, module: str, is_package: bool) -> list[tuple[int, str]]:
    imports = []
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                if node.level > len(parts):
                    imports.append((node.lineno, "<invalid-relative-import>"))
                    continue
                base = ".".join(parts[: len(parts) - node.level + 1] + ([base] if base else []))
            imports.append((node.lineno, base))
            # Include possible imported submodules, including `from . import x`.
            imports.extend((node.lineno, f"{base}.{alias.name}") for alias in node.names)
    return imports


def check(repository: Path) -> list[str]:
    config = tomllib.loads((repository / "infra/architecture-boundaries.toml").read_text())["scan"]
    errors: set[str] = set()
    modules: dict[str, tuple[str, ast.AST, list[tuple[int, str]]]] = {}
    pure_roots = [*config["side_effect_free_roots"], "packages/domain/research_dataset.py"]
    for source_root in config["source_roots"]:
        for path in sorted((repository / source_root).rglob("*.py")):
            if "node_modules" in path.parts:
                continue
            relative = path.relative_to(repository).as_posix()
            module = relative.removesuffix(".py").replace("/", ".")
            is_package = module.endswith(".__init__")
            if is_package:
                module = module.removesuffix(".__init__")
            try:
                tree = ast.parse(path.read_text(), filename=relative)
            except (SyntaxError, UnicodeError) as exc:
                errors.add(f"{relative}: invalid Python: {exc}")
                continue
            imports = _imports(tree, module, is_package)
            modules[module] = relative, tree, imports
            for line, imported in imports:
                reason = None
                if imported == "<invalid-relative-import>":
                    reason = "relative import escapes the package"
                elif relative.startswith("packages/") and _matches(imported, ["apps"]):
                    reason = "package code imports a composition root"
                elif _below(relative, config["domain_roots"]) and _matches(
                    imported, config["forbidden_domain_imports"]
                ):
                    reason = "domain code imports a framework or adapter dependency"
                elif relative.startswith("packages/domain/") and not (
                    imported.partition(".")[0] in sys.stdlib_module_names
                    or _matches(imported, ["packages.domain"])
                ):
                    reason = "domain primitives import outside the domain and standard library"
                elif _below(relative, pure_roots) and _matches(
                    imported, config["forbidden_side_effect_imports"]
                ):
                    reason = "pure financial/strategy code imports ambient effect authority"
                if reason:
                    errors.add(f"{relative}:{line}: {reason}: {imported}")

    if _SIMULATION_ENTRY not in modules:
        errors.add("personal simulation composition root is missing")
    parts = _SIMULATION_ENTRY.split(".")
    pending = [".".join(parts[:end]) for end in range(1, len(parts) + 1)]
    visited: set[str] = set()
    while pending:
        module = pending.pop()
        if module in visited or module not in modules:
            continue
        visited.add(module)
        relative, tree, imports = modules[module]
        for line, imported in imports:
            if _matches(imported, _SIMULATION_FORBIDDEN) or "trusted_time" in imported:
                errors.add(
                    f"{relative}:{line}: simulation reaches provider/native authority: {imported}"
                )
            # Python executes ancestor __init__ modules as well as the leaf.
            parts = imported.split(".")
            pending.extend(".".join(parts[:end]) for end in range(1, len(parts) + 1))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) in _DYNAMIC_CALLS:
                errors.add(f"{relative}:{node.lineno}: simulation uses dynamic code/imports")

    # The offline research parent owns a single bounded Python child. Only that
    # composition root may acquire subprocess authority; its transitive imports
    # still cannot reach a broker, operational configuration or network client.
    if _RESEARCH_ENTRY in modules:
        parts = _RESEARCH_ENTRY.split(".")
        pending = [".".join(parts[:end]) for end in range(1, len(parts) + 1)]
        visited = set()
        while pending:
            module = pending.pop()
            if module in visited or module not in modules:
                continue
            visited.add(module)
            relative, tree, imports = modules[module]
            for line, imported in imports:
                permitted_subprocess = module == _RESEARCH_ENTRY and imported == "subprocess"
                if not permitted_subprocess and (
                    _matches(imported, (*_SIMULATION_FORBIDDEN, "apps.api.config"))
                    or "trusted_time" in imported
                ):
                    errors.add(
                        f"{relative}:{line}: research reaches provider/native authority: {imported}"
                    )
                parts = imported.split(".")
                pending.extend(".".join(parts[:end]) for end in range(1, len(parts) + 1))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and ast.unparse(node.func) in _DYNAMIC_CALLS:
                    errors.add(f"{relative}:{node.lineno}: research uses dynamic code/imports")

    return sorted(errors)


def main() -> int:
    errors = check(Path(__file__).resolve().parents[1])
    for error in errors:
        print(error)
    if errors:
        print(f"Personal architecture check failed: {len(errors)} violation(s).")
        return 1
    print("Personal architecture check passed (layers, pure code, simulation import closure).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
