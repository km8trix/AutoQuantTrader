"""Enforce the repository's dependency direction without importing project code."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_STRATEGY_START_AUTHORIZATION_MODULE = "packages.domain.strategy_invocation_lifecycle"
_STRATEGY_START_AUTHORIZATION_FACTORY = "_strategy_invocation_start_authorization"
_STRATEGY_START_AUTHORIZATION_ISSUER = Path("packages/persistence/strategy_invocation_lifecycle.py")

_TRUSTED_TIME_TOPOLOGY_PRODUCTION_AST_SHA256 = (
    "9d251d93304f36eebe5d1f0a12880b90cfd5e027b27a136998f4587ad518ea04"
)
_TRUSTED_TIME_TOPOLOGY_PRODUCTION_AST_SENTINEL = "trusted-time-topology-production-ast-sha256-v1"

_NATIVE_BUILD_REQUIREMENTS = (
    "hatchling==1.32.0",
    "packaging==26.3",
    "pathspec==1.1.1",
    "pluggy==1.6.0",
    "tomlkit==0.15.1",
    "trove-classifiers==2026.6.1.19",
)
_NATIVE_BUILD_CONSTRAINTS_TEXT = """\
hatchling==1.32.0 \\
    --hash=sha256:0bdbde4a52b06c37e3eca395f85a762bf0ef06fe374fd8ae429dc6be10230f5f \\
    --hash=sha256:0e17c9c3b9aa7c625acc8d0f5b622f107d5049af9ecf5ada4de1aada5be7cdbc
packaging==26.3 \\
    --hash=sha256:94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79 \\
    --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pathspec==1.1.1 \\
    --hash=sha256:17db5ecd524104a120e173814c90367a96a98d07c45b2e10c2f3919fff91bf5a \\
    --hash=sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189
pluggy==1.6.0 \\
    --hash=sha256:7dcc130b76258d33b90f61b658791dede3486c3e6bfb003ee5c9bfb396dd22f3 \\
    --hash=sha256:e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746
tomlkit==0.15.1 \\
    --hash=sha256:177a05aece5a8ca5266fd3c448abb47b8d352f09d477d3ca8332db4d89b24304 \\
    --hash=sha256:e25bbf38843005246210a12982776f27f99cb9be67160e14434d0c0d21ee1e97
trove-classifiers==2026.6.1.19 \\
    --hash=sha256:ab4c4ec93cc4a4e7815fa759906e05e6bb3f2fbd92ea0f897288c6a43efd15b3 \\
    --hash=sha256:c5132b4b61a829d11cfbd2d72e97f20a45ed6edb95e45c5efdeb5e00836b2745
"""


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


def _project_import_bindings(tree: ast.AST) -> list[tuple[int, str]]:
    """Return exact project import bindings, preserving imported symbol names."""

    bindings: list[tuple[int, str]] = []
    project_namespaces = {"apps", "packages", "scripts"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] in project_namespaces:
                    bindings.append((node.lineno, f"{alias.name}:*"))
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                module = "." * node.level + (node.module or "")
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
                continue
            module = node.module or ""
            if module.partition(".")[0] in project_namespaces:
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
    return bindings


def _nonproject_import_bindings(tree: ast.AST) -> list[tuple[int, str]]:
    """Return exact non-project import bindings, including standard-library symbols."""

    bindings: list[tuple[int, str]] = []
    project_namespaces = {"apps", "packages", "scripts"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] not in project_namespaces:
                    bindings.append((node.lineno, f"{alias.name}:*"))
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                module = "." * node.level + (node.module or "")
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
                continue
            module = node.module or ""
            if module.partition(".")[0] not in project_namespaces:
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
    return bindings


def _project_import_modules(tree: ast.AST) -> list[tuple[int, str]]:
    """Return the exact project modules reached by imports."""

    modules: list[tuple[int, str]] = []
    project_namespaces = {"apps", "packages", "scripts"}
    bindings = _imported_symbol_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(
                (node.lineno, alias.name)
                for alias in node.names
                if alias.name.partition(".")[0] in project_namespaces
            )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.partition(".")[0] not in project_namespaces:
                continue
            if node.module in project_namespaces:
                modules.extend(
                    (node.lineno, f"{node.module}.{alias.name}")
                    for alias in node.names
                    if alias.name != "*"
                )
            else:
                modules.append((node.lineno, node.module))
        elif (
            isinstance(node, ast.Call)
            and _qualified_symbol(node.func, bindings) in {"__import__", "importlib.import_module"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is str
            and node.args[0].value.partition(".")[0] in project_namespaces
        ):
            modules.append((node.lineno, node.args[0].value))
    return modules


def _exact_project_module_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: frozenset[str],
) -> list[Violation]:
    modules = _project_import_modules(tree)
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed project module '{module}'",
        )
        for line, module in modules
        if module not in allowed
    ]
    observed = frozenset(module for _, module in modules)
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed project module '{module}'",
        )
        for module in sorted(allowed - observed)
    )
    return violations


def _exact_project_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: frozenset[str],
) -> list[Violation]:
    bindings = _project_import_bindings(tree)
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed project binding '{binding}'",
        )
        for line, binding in bindings
        if binding not in allowed
    ]
    observed = frozenset(binding for _, binding in bindings)
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed project binding '{binding}'",
        )
        for binding in sorted(allowed - observed)
    )
    return violations


def _origin_module_import_bindings(tree: ast.AST, module: str) -> list[tuple[int, str]]:
    """Return exact bindings imported from one project module.

    Namespace imports and dynamic imports are represented by ``module:*`` so
    an audited consumer cannot widen an exact from-import allowlist.
    """

    bindings: list[tuple[int, str]] = []
    parent, _, leaf = module.rpartition(".")
    imported_bindings = _imported_symbol_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bindings.extend(
                (node.lineno, f"{module}:*")
                for alias in node.names
                if alias.name == module or alias.name.startswith(f"{module}.")
            )
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == module:
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
            elif (node.module == parent and any(alias.name == leaf for alias in node.names)) or (
                node.module is not None and node.module.startswith(f"{module}.")
            ):
                bindings.append((node.lineno, f"{module}:*"))
        elif (
            isinstance(node, ast.Call)
            and _qualified_symbol(node.func, imported_bindings)
            in {"__import__", "importlib.import_module"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is str
            and (node.args[0].value == module or node.args[0].value.startswith(f"{module}."))
        ):
            bindings.append((node.lineno, f"{module}:*"))
    return bindings


def _exact_origin_module_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    module: str,
    allowed: frozenset[str],
) -> list[Violation]:
    """Require one consumer's exact binding set from one origin module."""

    bindings = _origin_module_import_bindings(tree, module)
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed binding '{binding}'",
        )
        for line, binding in bindings
        if binding not in allowed
    ]
    observed = frozenset(binding for _, binding in bindings)
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed binding '{binding}'",
        )
        for binding in sorted(allowed - observed)
    )
    return violations


def _native_owned_file_descriptor_usage_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    module: str,
    captured_defaults: dict[str, dict[str, str]],
    captured_call_counts: dict[str, dict[str, int]],
    captured_owner_consumers: dict[str, dict[str, tuple[str, int]]],
) -> list[Violation]:
    """Keep native capabilities as direct calls inside their consuming frame."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    imported: dict[str, str] = {}
    native_import_aliases: set[ast.alias] = set()
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level != 0 or node.module != module:
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            imported[local] = alias.name
            native_import_aliases.add(alias)

    admitted_native_import_aliases = set(native_import_aliases)
    if captured_defaults:
        admitted_native_import_aliases = set()
        aliases_by_origin: dict[str, list[ast.alias]] = {}
        for alias in native_import_aliases:
            aliases_by_origin.setdefault(alias.name, []).append(alias)
        for origin, aliases in aliases_by_origin.items():
            valid = [
                alias
                for alias in aliases
                if alias.asname is None
                and isinstance(parents.get(alias), ast.ImportFrom)
                and parents.get(alias) in getattr(tree, "body", ())
            ]
            if len(aliases) != 1 or len(valid) != 1:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(aliases[0], "lineno", 1),
                        "captured native owned-file-descriptor imports must be exact, "
                        f"unconditional, top-level, and unaliased: '{origin}'",
                    )
                )
                continue
            admitted_native_import_aliases.add(valid[0])

    def bound_names(node: ast.AST) -> frozenset[str]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return frozenset((node.name,))
        if isinstance(node, ast.arg):
            return frozenset((node.arg,))
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return frozenset((node.id,))
        if isinstance(node, ast.alias):
            return frozenset(((node.asname or node.name.partition(".")[0]),))
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            return frozenset((node.name,))
        if isinstance(node, ast.MatchMapping) and node.rest:
            return frozenset((node.rest,))
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return frozenset(node.names)
        return frozenset()

    for node in ast.walk(tree):
        if node in admitted_native_import_aliases:
            continue
        rebound = bound_names(node).intersection(imported)
        if rebound:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    "native owned-file-descriptor imported binding cannot be rebound or deleted: "
                    + ", ".join(sorted(rebound)),
                )
            )

    def enclosing_function(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            if isinstance(
                current,
                (
                    ast.ClassDef,
                    ast.DictComp,
                    ast.GeneratorExp,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                ),
            ):
                return None
            current = parents.get(current)
        return None

    top_level_functions: dict[
        str,
        list[ast.FunctionDef | ast.AsyncFunctionDef],
    ] = {}
    if isinstance(tree, ast.Module):
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                top_level_functions.setdefault(statement.name, []).append(statement)

    captured_default_nodes: set[ast.AST] = set()
    captured_parameters: dict[
        ast.FunctionDef | ast.AsyncFunctionDef,
        dict[str, str],
    ] = {}
    configured_function_nodes: set[ast.FunctionDef | ast.AsyncFunctionDef] = set()
    captured_origins = {
        binding.partition(":")[2]
        for parameters in captured_defaults.values()
        for binding in parameters.values()
        if binding.partition(":")[0] == module and binding.partition(":")[1] == ":"
    }
    for origin in sorted(captured_origins):
        aliases = [
            alias
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module
            for alias in node.names
            if alias.name == origin
        ]
        if len(aliases) != 1 or aliases[0].asname is not None:
            violations.append(
                Violation(
                    relative_path,
                    getattr(aliases[0], "lineno", 1) if aliases else 1,
                    "captured native owned-file-descriptor operation must use one exact "
                    f"unaliased import for '{origin}'",
                )
            )

    for function_name, parameters in captured_defaults.items():
        functions = top_level_functions.get(function_name, [])
        if len(functions) != 1:
            violations.append(
                Violation(
                    relative_path,
                    getattr(functions[0], "lineno", 1) if functions else 1,
                    "captured native owned-file-descriptor function must be one exact "
                    f"top-level definition '{function_name}'",
                )
            )
            continue
        function = functions[0]
        configured_function_nodes.add(function)
        if function.decorator_list:
            violations.append(
                Violation(
                    relative_path,
                    function.lineno,
                    "captured native owned-file-descriptor function cannot be decorated",
                )
            )
        kw_defaults = {
            argument.arg: default
            for argument, default in zip(
                function.args.kwonlyargs,
                function.args.kw_defaults,
                strict=True,
            )
        }
        captured_parameters[function] = dict(parameters)
        for parameter, expected_binding in parameters.items():
            expected_module, separator, expected_origin = expected_binding.partition(":")
            default = kw_defaults.get(parameter)
            if (
                separator != ":"
                or expected_module != module
                or not expected_origin
                or not isinstance(default, ast.Name)
                or default.id != expected_origin
                or imported.get(default.id) != expected_origin
            ):
                violations.append(
                    Violation(
                        relative_path,
                        getattr(default, "lineno", function.lineno),
                        "captured native owned-file-descriptor default must preserve exact "
                        "function/parameter/origin "
                        f"'{function_name}:{parameter}:{expected_binding}'",
                    )
                )
                continue
            captured_default_nodes.add(default)

    configured_function_names = frozenset(captured_defaults)
    for node in ast.walk(tree):
        if node in configured_function_nodes:
            continue
        rebound = bound_names(node).intersection(configured_function_names)
        if rebound:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    "captured native owned-file-descriptor function binding must be sole: "
                    + ", ".join(sorted(rebound)),
                )
            )

    protected_callable_keywords = {
        function_name: set(parameters) for function_name, parameters in captured_defaults.items()
    }
    expected_owner_helper_names = {
        expected_helper
        for parameters in captured_owner_consumers.values()
        for expected_helper, _expected_calls in parameters.values()
    }
    for helper_name in expected_owner_helper_names:
        protected_callable_keywords.setdefault(helper_name, set())
        helper_functions = top_level_functions.get(helper_name, [])
        if len(helper_functions) != 1:
            violations.append(
                Violation(
                    relative_path,
                    getattr(helper_functions[0], "lineno", 1) if helper_functions else 1,
                    "native owner-consuming helper must be one exact top-level definition: "
                    f"'{helper_name}'",
                )
            )
    for function_name, owner_helper_parameters in captured_owner_consumers.items():
        protected_callable_keywords.setdefault(function_name, set()).update(owner_helper_parameters)

    for function_name, owner_helper_parameters in captured_owner_consumers.items():
        functions = top_level_functions.get(function_name, [])
        if len(functions) != 1:
            continue
        function = functions[0]
        kw_defaults = {
            argument.arg: default
            for argument, default in zip(
                function.args.kwonlyargs,
                function.args.kw_defaults,
                strict=True,
            )
        }
        for parameter, (expected_helper, expected_calls) in owner_helper_parameters.items():
            default = kw_defaults.get(parameter)
            calls = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == parameter
                and enclosing_function(node) is function
            ]
            if not isinstance(default, ast.Name) or default.id != expected_helper:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(default, "lineno", function.lineno),
                        "native owner-consuming helper default must preserve its exact "
                        f"binding: '{function_name}:{parameter}:{expected_helper}'",
                    )
                )
            if len(calls) != expected_calls:
                violations.append(
                    Violation(
                        relative_path,
                        function.lineno,
                        "native owner-consuming helper must preserve its exact direct-call "
                        f"count: '{function_name}:{parameter}'",
                    )
                )
    protected_callable_default_nodes: set[ast.Name] = set()
    protected_callable_parameters: dict[
        ast.FunctionDef | ast.AsyncFunctionDef,
        dict[str, frozenset[str]],
    ] = {}
    changed = True
    while changed:
        changed = False
        for functions in top_level_functions.values():
            if len(functions) != 1:
                continue
            function = functions[0]
            for argument, default in zip(
                function.args.kwonlyargs,
                function.args.kw_defaults,
                strict=True,
            ):
                if not (
                    isinstance(default, ast.Name) and default.id in protected_callable_keywords
                ):
                    continue
                protected_callable_default_nodes.add(default)
                protected = frozenset(protected_callable_keywords[default.id])
                protected_callable_parameters.setdefault(function, {})[argument.arg] = protected
                outer_keywords = protected_callable_keywords.setdefault(function.name, set())
                if argument.arg not in outer_keywords:
                    outer_keywords.add(argument.arg)
                    changed = True

    protected_callable_nodes = {
        functions[0]
        for name, functions in top_level_functions.items()
        if name in protected_callable_keywords and len(functions) == 1
    }
    for function in protected_callable_nodes:
        if function.decorator_list:
            violations.append(
                Violation(
                    relative_path,
                    function.lineno,
                    "native captured-default callable chain cannot be decorated",
                )
            )
    for node in ast.walk(tree):
        if node in protected_callable_nodes:
            continue
        rebound = bound_names(node).intersection(protected_callable_keywords)
        if rebound:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    "native captured-default callable chain binding must be sole: "
                    + ", ".join(sorted(rebound)),
                )
            )

    def reject_protected_keyword_override(
        call: ast.Call,
        *,
        protected: frozenset[str] | set[str],
        line: int,
    ) -> None:
        if any(keyword.arg is None or keyword.arg in protected for keyword in call.keywords):
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "native captured-default callable cannot accept a protected keyword "
                    "override or expansion",
                )
            )

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in protected_callable_keywords
        ):
            continue
        if node in protected_callable_default_nodes:
            continue
        parent = parents.get(node)
        if not (isinstance(parent, ast.Call) and parent.func is node):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native captured-default callable cannot be aliased or reexported",
                )
            )
            continue
        reject_protected_keyword_override(
            parent,
            protected=protected_callable_keywords[node.id],
            line=node.lineno,
        )

    for function, protected_parameters in protected_callable_parameters.items():
        exact_parameter_nodes = {
            argument
            for argument in function.args.kwonlyargs
            if argument.arg in protected_parameters
        }
        for node in ast.walk(function):
            if node not in exact_parameter_nodes:
                rebound = bound_names(node).intersection(protected_parameters)
                if rebound:
                    violations.append(
                        Violation(
                            relative_path,
                            getattr(node, "lineno", function.lineno),
                            "native captured-default callable parameter cannot be rebound: "
                            + ", ".join(sorted(rebound)),
                        )
                    )
            if not (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in protected_parameters
            ):
                continue
            if enclosing_function(node) is not function:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native captured-default callable parameter cannot be closed over",
                    )
                )
                continue
            parent = parents.get(node)
            callable_check = (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "callable"
                and parent.args == [node]
                and not parent.keywords
            )
            if callable_check:
                continue
            if not (isinstance(parent, ast.Call) and parent.func is node):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native captured-default callable parameter must be called directly",
                    )
                )
                continue
            reject_protected_keyword_override(
                parent,
                protected=protected_parameters[node.id],
                line=node.lineno,
            )

    annotation_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        annotations: tuple[ast.AST | None, ...] = ()
        if isinstance(node, (ast.arg, ast.AnnAssign)):
            annotations = (node.annotation,)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            annotations = (node.returns,)
        for annotation in annotations:
            if annotation is not None:
                annotation_nodes.update(ast.walk(annotation))

    owner_factory_bindings = {
        local
        for local, origin in imported.items()
        if origin
        in {
            "_create_child_regular_exclusive",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
        }
    }
    owner_type_bindings = {
        local for local, origin in imported.items() if origin == "_OwnedFileDescriptor"
    }
    operation_bindings = frozenset(imported) - frozenset(owner_type_bindings)
    owner_targets_by_function: dict[
        ast.FunctionDef | ast.AsyncFunctionDef,
        set[str],
    ] = {}

    def record_owner_factory_call(
        call: ast.Call,
        *,
        line: int,
        required_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
    ) -> None:
        assignment = parents.get(call)
        targets: tuple[ast.AST, ...] = ()
        if isinstance(assignment, ast.Assign) and assignment.value is call:
            targets = tuple(assignment.targets)
        elif isinstance(assignment, ast.AnnAssign) and assignment.value is call:
            targets = (assignment.target,)
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "native owned-file-descriptor owner must be stored in one local slot",
                )
            )
            return
        function = enclosing_function(call)
        if function is None:
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "native owned-file-descriptor owner cannot be created at module scope",
                )
            )
            return
        if required_function is not None and function is not required_function:
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "captured native owned-file-descriptor owner factory cannot be closed over",
                )
            )
            return
        target = targets[0].id
        declarations = [
            declaration
            for declaration in ast.walk(function)
            if isinstance(declaration, (ast.Global, ast.Nonlocal))
            and target in declaration.names
            and enclosing_function(declaration) is function
        ]
        if declarations:
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "native owned-file-descriptor owner must be stored in a frame-local slot",
                )
            )
            return
        owner_targets_by_function.setdefault(function, set()).add(target)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        if node.id in owner_type_bindings:
            if node not in annotation_nodes:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        "native owned-file-descriptor type may appear only in annotations",
                    )
                )
            continue
        if node.id not in operation_bindings:
            continue
        if node in captured_default_nodes:
            continue
        if captured_defaults:
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native captured-default consumer cannot reload an imported operation "
                    f"outside its exact admitted default: '{node.id}'",
                )
            )
            continue
        parent = parents.get(node)
        if not (isinstance(parent, ast.Call) and parent.func is node):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native owned-file-descriptor operation cannot be aliased or reexported",
                )
            )
            continue
        if node.id not in owner_factory_bindings:
            continue
        record_owner_factory_call(parent, line=node.lineno)

    owner_factory_origins = {
        "_create_child_regular_exclusive",
        "_open_child_directory",
        "_open_child_regular",
        "_open_root_directory",
    }
    for function, parameters in captured_parameters.items():
        exact_parameter_nodes = {
            argument for argument in function.args.kwonlyargs if argument.arg in parameters
        }
        for node in ast.walk(function):
            if node not in exact_parameter_nodes:
                rebound = bound_names(node).intersection(parameters)
                if rebound:
                    violations.append(
                        Violation(
                            relative_path,
                            getattr(node, "lineno", function.lineno),
                            "captured native owned-file-descriptor operation cannot be rebound: "
                            + ", ".join(sorted(rebound)),
                        )
                    )
            if not isinstance(node, ast.Name) or node.id not in parameters:
                continue
            frame = enclosing_function(node)
            if frame is not function:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "captured native owned-file-descriptor operation cannot be closed over",
                    )
                )
                continue
            if not isinstance(node.ctx, ast.Load):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "captured native owned-file-descriptor operation cannot be rebound",
                    )
                )
                continue
            parent = parents.get(node)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "captured native owned-file-descriptor operation must be called directly",
                    )
                )
                continue
            origin = parameters[node.id].partition(":")[2]
            if origin in owner_factory_origins:
                record_owner_factory_call(
                    parent,
                    line=node.lineno,
                    required_function=function,
                )

        parameter_calls = {
            parameter: [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == parameter
                and enclosing_function(node) is function
            ]
            for parameter in parameters
        }
        expected_counts = captured_call_counts.get(function.name, {})
        for parameter, calls in parameter_calls.items():
            expected_count = expected_counts.get(parameter)
            count_is_valid = (
                len(calls) == expected_count if expected_count is not None else bool(calls)
            )
            if not count_is_valid:
                violations.append(
                    Violation(
                        relative_path,
                        function.lineno,
                        "captured native owned-file-descriptor operation must preserve its "
                        f"exact direct-call count: '{function.name}:{parameter}'",
                    )
                )
        captured_origins_in_function = {
            binding.partition(":")[2] for binding in parameters.values()
        }
        for node in ast.walk(function):
            if not (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in captured_origins_in_function
                and node not in captured_default_nodes
                and enclosing_function(node) is function
            ):
                continue
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "captured native owned-file-descriptor function cannot reload the "
                    f"module-global origin '{node.id}'",
                )
            )

    for function, owner_targets in owner_targets_by_function.items():
        tainted_owner_names = set(owner_targets)
        if captured_defaults:
            reported_aliases: set[ast.AST] = set()
            changed = True
            while changed:
                changed = False
                for node in ast.walk(function):
                    value: ast.AST | None = None
                    targets: tuple[ast.AST, ...] = ()
                    if isinstance(node, ast.Assign):
                        value = node.value
                        targets = tuple(node.targets)
                    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                        value = node.value
                        targets = (node.target,)
                    if (
                        value is None
                        or isinstance(value, ast.Call)
                        or enclosing_function(node) is not function
                        or not any(
                            isinstance(candidate, ast.Name)
                            and isinstance(candidate.ctx, ast.Load)
                            and candidate.id in tainted_owner_names
                            for candidate in ast.walk(value)
                        )
                    ):
                        continue
                    new_aliases = {
                        target.id for target in targets if isinstance(target, ast.Name)
                    } - tainted_owner_names
                    if new_aliases:
                        tainted_owner_names.update(new_aliases)
                        changed = True
                    if node not in reported_aliases:
                        reported_aliases.add(node)
                        violations.append(
                            Violation(
                                relative_path,
                                getattr(node, "lineno", 1),
                                "native owned-file-descriptor owner cannot be aliased or stored "
                                "in a container or attribute",
                            )
                        )

        for node in ast.walk(function):
            if (
                captured_defaults
                and isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in tainted_owner_names
                and enclosing_function(node) is not function
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native owned-file-descriptor owner cannot be closed over",
                    )
                )
            if captured_defaults and isinstance(node, ast.Call):
                direct_owner_arguments: list[ast.Name] = []
                for owner_argument in (
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                ):
                    for candidate in ast.walk(owner_argument):
                        if not (
                            isinstance(candidate, ast.Name)
                            and isinstance(candidate.ctx, ast.Load)
                            and candidate.id in tainted_owner_names
                        ):
                            continue
                        current = parents.get(candidate)
                        while current is not None and current is not node:
                            if isinstance(current, ast.Call):
                                break
                            current = parents.get(current)
                        if current is node:
                            direct_owner_arguments.append(candidate)
                function_name = function.name
                allowed_consumers = frozenset(captured_parameters.get(function, {})) | frozenset(
                    captured_owner_consumers.get(function_name, {})
                )
                allowed_call = isinstance(node.func, ast.Name) and node.func.id in allowed_consumers
                if direct_owner_arguments and not allowed_call:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            "native owned-file-descriptor owner cannot reach an unreviewed "
                            "callable",
                        )
                    )
            if not isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                continue
            if any(
                isinstance(candidate, ast.Name) and candidate.id in tainted_owner_names
                for candidate in ast.walk(node)
            ):
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        "Python helper cannot return a live native owned-file-descriptor owner",
                    )
                )
    return violations


def _native_captured_function_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    protected_functions: dict[str, frozenset[str]],
) -> list[Violation]:
    """Keep native-capturing helper callsites inside their defining module."""

    violations: list[Violation] = []
    for module, functions in protected_functions.items():
        for line, binding in _origin_module_import_bindings(tree, module):
            _origin, _separator, imported = binding.rpartition(":")
            if imported != "*" and imported not in functions:
                continue
            violations.append(
                Violation(
                    relative_path,
                    line,
                    "native captured-default helper cannot be imported or reached through a "
                    f"module namespace: '{binding}'",
                )
            )
    return violations


def _native_captured_consumer_reflection_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
) -> list[Violation]:
    """Reject dynamic namespace paths in definition-time native capture modules."""

    forbidden_names = frozenset(
        {
            "__builtins__",
            "__import__",
            "__loader__",
            "__spec__",
            "compile",
            "delattr",
            "eval",
            "exec",
            "getattr",
            "globals",
            "locals",
            "setattr",
            "vars",
        }
    )
    forbidden_attributes = forbidden_names | frozenset(
        {
            "__code__",
            "__dict__",
            "__getattribute__",
            "__globals__",
            "__setattr__",
            "ag_frame",
            "attrgetter",
            "cr_frame",
            "create_module",
            "exec_module",
            "f_globals",
            "f_locals",
            "find_spec",
            "get_referents",
            "get_referrers",
            "getmodule",
            "gi_frame",
            "import_module",
            "load_module",
            "loader",
            "module_from_spec",
            "modules",
            "resolve_name",
            "tb_frame",
        }
    )
    forbidden_import_roots = frozenset(
        {"_imp", "ctypes", "gc", "importlib", "inspect", "operator", "pkgutil"}
    )
    allowed_getattr_name: ast.Name | None = None
    if isinstance(tree, ast.Module):
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_boottime_ns"
        ]
        if len(functions) == 1:
            function = functions[0]
            defaults = {
                argument.arg: default
                for argument, default in zip(
                    function.args.kwonlyargs,
                    function.args.kw_defaults,
                    strict=True,
                )
            }
            default = defaults.get("_clock_id")
            if (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id == "getattr"
                and len(default.args) == 3
                and isinstance(default.args[0], ast.Name)
                and default.args[0].id == "time"
                and isinstance(default.args[1], ast.Constant)
                and default.args[1].value == "CLOCK_BOOTTIME"
                and isinstance(default.args[2], ast.Constant)
                and default.args[2].value is None
                and not default.keywords
            ):
                allowed_getattr_name = default.func

    violations: list[Violation] = []
    for node in ast.walk(tree):
        forbidden = False
        if (
            isinstance(node, ast.Name)
            and node.id in forbidden_names
            and node is not allowed_getattr_name
        ):
            forbidden = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            forbidden = node.name in forbidden_names
        elif isinstance(node, ast.arg):
            forbidden = node.arg in forbidden_names
        elif isinstance(node, ast.alias):
            local = node.asname or node.name.partition(".")[0]
            forbidden = (
                node.name == "*"
                or node.name.partition(".")[0] in forbidden_import_roots
                or node.name in forbidden_names
                or local in forbidden_names
            )
        elif isinstance(node, ast.Attribute):
            forbidden = node.attr in forbidden_attributes
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            forbidden = node.name in forbidden_names if node.name else False
        elif isinstance(node, ast.MatchMapping):
            forbidden = node.rest in forbidden_names if node.rest else False
        if not forbidden:
            continue
        violations.append(
            Violation(
                relative_path,
                getattr(node, "lineno", 1),
                "native captured-default consumer cannot use dynamic namespace or reflection "
                "authority",
            )
        )
    return violations


def _native_bounded_process_usage_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    module: str,
    expected_call_count: int,
    expected_function_ast_sha256: str,
) -> list[Violation]:
    """Keep the bounded process capability on its one reviewed direct call path."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    imported: dict[str, str] = {}
    violations: list[Violation] = []
    exact_imports: list[ast.ImportFrom] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level != 0 or node.module != module:
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            imported[local] = alias.name
            if alias.name == "_run_bounded_process" and alias.asname is None:
                exact_imports.append(node)
            if alias.name == "_run_bounded_process" and alias.asname is not None:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native bounded-process capability cannot use a local import alias",
                    )
                )

    expected_import_count = 1 if expected_call_count else 0
    valid_exact_imports = [
        node
        for node in {id(candidate): candidate for candidate in exact_imports}.values()
        if node in getattr(tree, "body", ())
        and len(node.names) == 1
        and node.names[0].name == "_run_bounded_process"
        and node.names[0].asname is None
    ]
    if (
        len({id(node) for node in exact_imports}) != expected_import_count
        or len(valid_exact_imports) != expected_import_count
    ):
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process capability must have one exact unconditional import",
            )
        )

    process_bindings = {
        local for local, origin in imported.items() if origin == "_run_bounded_process"
    }
    if expected_call_count:
        for node in ast.walk(tree):
            exact_import_alias = (
                isinstance(node, ast.alias)
                and node.name == "_run_bounded_process"
                and node.asname is None
                and parents.get(node) in valid_exact_imports
            )
            binds_operation = (
                (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and node.name == "_run_bounded_process"
                )
                or (isinstance(node, ast.arg) and node.arg == "_run_bounded_process")
                or (
                    isinstance(node, ast.Name)
                    and node.id == "_run_bounded_process"
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                )
                or (
                    isinstance(node, ast.alias)
                    and (node.asname or node.name.partition(".")[0]) == "_run_bounded_process"
                )
                or (
                    isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                    and node.name == "_run_bounded_process"
                )
                or (isinstance(node, ast.MatchMapping) and node.rest == "_run_bounded_process")
            )
            if binds_operation and not exact_import_alias:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        "native bounded-process imported binding cannot be rebound or deleted",
                    )
                )
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        if node.id not in process_bindings:
            continue
        parent = parents.get(node)
        if not (isinstance(parent, ast.Call) and parent.func is node):
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    "native bounded-process capability cannot be aliased or reexported",
                )
            )
            continue
        calls.append(parent)

    if len(calls) != expected_call_count:
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process consumer must preserve exactly three reviewed calls",
            )
        )

    expected_shapes = (
        ("revision_argv", "resolved", b"", 64),
        ("tree_argv", "tree", b"", 1_024),
        ("blob_argv", "blob", "request", 4_353),
    )
    for position, call in enumerate(sorted(calls, key=lambda value: value.lineno)):
        current: ast.AST | None = call
        while current is not None and not isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            current = parents.get(current)
        if not isinstance(current, ast.FunctionDef) or current.name != (
            "_head_reviewed_operator_authority_object"
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process call must remain in the reviewed Git object reader",
                )
            )
        ancestor = parents.get(call)
        while ancestor is not None and ancestor is not current:
            if isinstance(
                ancestor,
                (
                    ast.AsyncFor,
                    ast.DictComp,
                    ast.For,
                    ast.GeneratorExp,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.While,
                    ast.comprehension,
                ),
            ):
                violations.append(
                    Violation(
                        relative_path,
                        call.lineno,
                        "native bounded-process call cannot appear in a repeated callable scope",
                    )
                )
                break
            ancestor = parents.get(ancestor)
        if (
            len(call.args) != 7
            or call.keywords
            or any(isinstance(argument, ast.Starred) for argument in call.args)
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process call must use seven exact positional arguments",
                )
            )
            continue
        if position >= len(expected_shapes):
            continue
        argv_name, result_name, stdin_value, stdout_cap = expected_shapes[position]
        expected_name_arguments = (
            (0, argv_name),
            (1, "exact_cwd"),
            (2, "exact_environment"),
        )

        def exact_name_argument(current_call: ast.Call, index: int, name: str) -> bool:
            argument = current_call.args[index]
            return isinstance(argument, ast.Name) and argument.id == name

        if any(
            not exact_name_argument(call, index, name) for index, name in expected_name_arguments
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process call must preserve exact argv/cwd/environment locals",
                )
            )
        stdin_argument = call.args[3]
        if type(stdin_value) is bytes:
            stdin_matches = (
                isinstance(stdin_argument, ast.Constant)
                and type(stdin_argument.value) is bytes
                and stdin_argument.value == stdin_value
            )
        else:
            stdin_matches = (
                isinstance(stdin_argument, ast.Name) and stdin_argument.id == stdin_value
            )
        exact_integer_arguments = (
            (4, stdout_cap),
            (5, 16_384),
            (6, 5_000_000_000),
        )

        def exact_integer_argument(current_call: ast.Call, index: int, value: int) -> bool:
            argument = current_call.args[index]
            return (
                isinstance(argument, ast.Constant)
                and type(argument.value) is int
                and argument.value == value
            )

        if not stdin_matches or any(
            not exact_integer_argument(call, index, value)
            for index, value in exact_integer_arguments
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process call must preserve exact stdin, caps, and deadline",
                )
            )
        assignment = parents.get(call)
        if (
            not isinstance(assignment, ast.Assign)
            or assignment.value is not call
            or len(assignment.targets) != 1
            or not isinstance(assignment.targets[0], ast.Name)
            or assignment.targets[0].id != result_name
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process result must enter its one reviewed local slot",
                )
            )
            continue
        result_scope: ast.AST = current if isinstance(current, ast.FunctionDef) else tree
        result_writes = [
            candidate
            for candidate in ast.walk(result_scope)
            if isinstance(candidate, ast.Name)
            and candidate.id == result_name
            and isinstance(candidate.ctx, (ast.Store, ast.Del))
        ]
        if result_writes != [assignment.targets[0]]:
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process result local cannot be rebound or deleted",
                )
            )
        result_loads = [
            candidate
            for candidate in ast.walk(result_scope)
            if isinstance(candidate, ast.Name)
            and isinstance(candidate.ctx, ast.Load)
            and candidate.id == result_name
        ]
        if len(result_loads) != 1:
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process result must be consumed exactly once",
                )
            )
            continue
        result_parent = parents.get(result_loads[0])
        expected_keyword = argv_name
        if (
            not isinstance(result_parent, ast.Call)
            or not isinstance(result_parent.func, ast.Name)
            or result_parent.func.id != "require_native_result"
            or tuple(result_parent.args) != (result_loads[0],)
            or len(result_parent.keywords) != 1
            or result_parent.keywords[0].arg != "expected_argv"
            or not isinstance(result_parent.keywords[0].value, ast.Name)
            or result_parent.keywords[0].value.id != expected_keyword
        ):
            violations.append(
                Violation(
                    relative_path,
                    result_loads[0].lineno,
                    "native bounded-process result must use the numeric immutable decoder",
                )
            )

    reviewed_bindings = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == "_head_reviewed_operator_authority_object"
    ]
    top_level_reviewed_functions = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.FunctionDef)
        and node.name == "_head_reviewed_operator_authority_object"
    ]
    if expected_call_count and (
        len(reviewed_bindings) != 1 or reviewed_bindings != top_level_reviewed_functions
    ):
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process Git object reader must be one top-level binding",
            )
        )
    if expected_call_count and len(top_level_reviewed_functions) == 1:
        reviewed_function = top_level_reviewed_functions[0]
        if (
            reviewed_function.decorator_list
            or not re.fullmatch(r"[0-9a-f]{64}", expected_function_ast_sha256)
            or _canonical_ast_sha256(reviewed_function) != expected_function_ast_sha256
        ):
            violations.append(
                Violation(
                    relative_path,
                    reviewed_function.lineno,
                    "native bounded-process Git object reader must preserve its exact semantic AST",
                )
            )
        if any(
            (
                isinstance(node, ast.Name)
                and node.id == "_head_reviewed_operator_authority_object"
                and isinstance(node.ctx, (ast.Load, ast.Store, ast.Del))
            )
            or (
                isinstance(node, ast.arg) and node.arg == "_head_reviewed_operator_authority_object"
            )
            or (
                isinstance(node, (ast.Import, ast.ImportFrom))
                and any(
                    (alias.asname or alias.name) == "_head_reviewed_operator_authority_object"
                    for alias in node.names
                )
            )
            or (
                isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                and node.name == "_head_reviewed_operator_authority_object"
            )
            or (
                isinstance(node, ast.MatchMapping)
                and node.rest == "_head_reviewed_operator_authority_object"
            )
            for node in ast.walk(tree)
        ):
            violations.append(
                Violation(
                    relative_path,
                    reviewed_function.lineno,
                    "native bounded-process Git object reader binding cannot be replaced",
                )
            )
        decoders = [
            node
            for node in reviewed_function.body
            if isinstance(node, ast.FunctionDef) and node.name == "require_native_result"
        ]
        if len(decoders) != 1:
            violations.append(
                Violation(
                    relative_path,
                    reviewed_function.lineno,
                    "native bounded-process result decoder must be one function-local binding",
                )
            )
        else:
            numeric_reads = [
                node
                for node in ast.walk(decoders[0])
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "tuple"
                and node.func.attr == "__getitem__"
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "value"
                and isinstance(node.args[1], ast.Constant)
                and type(node.args[1].value) is int
            ]
            if sorted(
                cast(int, cast(ast.Constant, node.args[1]).value) for node in numeric_reads
            ) != [
                0,
                1,
                2,
                3,
            ]:
                violations.append(
                    Violation(
                        relative_path,
                        decoders[0].lineno,
                        "native bounded-process result decoder must read four literal tuple slots",
                    )
                )
            if any(
                isinstance(node, (ast.Attribute, ast.Subscript))
                and (
                    (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name))
                    or (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name))
                )
                and node.value.id == "value"
                for node in ast.walk(decoders[0])
            ):
                violations.append(
                    Violation(
                        relative_path,
                        decoders[0].lineno,
                        "native bounded-process result cannot use heap descriptors or subscripts",
                    )
                )
            value_loads = [
                node
                for node in ast.walk(decoders[0])
                if isinstance(node, ast.Name)
                and node.id == "value"
                and isinstance(node.ctx, ast.Load)
            ]
            for value_load in value_loads:
                parent = parents.get(value_load)
                allowed_load = False
                if isinstance(parent, ast.Call) and value_load in parent.args:
                    allowed_load = (
                        isinstance(parent.func, ast.Name)
                        and parent.func.id in {"len", "type"}
                        and tuple(parent.args) == (value_load,)
                        and not parent.keywords
                    ) or (
                        isinstance(parent.func, ast.Attribute)
                        and isinstance(parent.func.value, ast.Name)
                        and parent.func.value.id == "tuple"
                        and parent.func.attr == "__getitem__"
                        and len(parent.args) == 2
                        and parent.args[0] is value_load
                        and isinstance(parent.args[1], ast.Constant)
                        and type(parent.args[1].value) is int
                        and not parent.keywords
                    )
                if not allowed_load:
                    violations.append(
                        Violation(
                            relative_path,
                            value_load.lineno,
                            "native bounded-process result decoder cannot reflect "
                            "or alias its input",
                        )
                    )
            forbidden_local_names = {"getattr", "len", "setattr", "tuple", "type", "vars"}
            if any(
                (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and node.name in forbidden_local_names
                )
                or (isinstance(node, ast.arg) and node.arg in forbidden_local_names)
                or (
                    isinstance(node, ast.Name)
                    and node.id in forbidden_local_names
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                )
                for node in ast.walk(reviewed_function)
            ):
                violations.append(
                    Violation(
                        relative_path,
                        reviewed_function.lineno,
                        "native bounded-process reader cannot shadow validation builtins",
                    )
                )
    return violations


_NATIVE_BOUNDED_PROCESS_REFLECTION_MODULE_AST_SHA256 = {
    Path("packages/domain/_trusted_time_post_enrollment_projection_bootstrap.py"): (
        "59bfdea9c8740d0df92b00bb74fc619d69b0593196b5e53fb39709ba7cae3df6"
    ),
    Path("scripts/trusted_time_post_enrollment_topology_reader.py"): (
        "a38808e452a92cad0fc63141bb234c579357b07ddb1f17f78bd00b3ca57cef48"
    ),
}

_NATIVE_BOUNDED_PROCESS_REFLECTION_ATTESTATIONS = {
    Path("packages/domain/_trusted_time_post_enrollment_projection_bootstrap.py"): (
        "<module>|Attribute|sys._getframe()|f_globals|assign:_EXACT_BOOTSTRAP_MODULE_GLOBALS",
        "_build_start_projection_bootstrap.caller_module_sha256|Constant|frame|f_code|"
        "call:_frame_getattribute",
        "_build_start_projection_bootstrap.caller_module_sha256|Constant|frame|f_globals|"
        "call:_frame_getattribute",
    ),
    Path("scripts/trusted_time_post_enrollment_topology_reader.py"): (
        "<module>|Attribute|candidate|__dict__|module/contains:_raw_paths",
        "<module>|Attribute|_EXACT_PATH_SLOT_OWNER|__dict__|module/subscript:_raw_paths",
        "<module>|Attribute|_EXACT_PATH_SLOT_OWNER|__dict__|module/subscript:_str",
        "<module>|Attribute|MemberDescriptorType|__dict__|module/subscript:__objclass__",
        "<module>|Attribute|MemberDescriptorType|__dict__|module/subscript:__name__",
        "<module>|Attribute|weakref.ReferenceType|__dict__|module/subscript:__callback__",
        "<module>|Attribute|type(_NativeOwnedFileDescriptor.closed)|__dict__|"
        "module/subscript:__get__",
        "<module>|Attribute|sys._getframe()|f_globals|assign:_EXACT_READER_MODULE_GLOBALS",
        "_build_observation_sealer|Attribute|_EXACT_RLOCK_TYPE|__dict__|"
        "default:_rlock_recursion_count/subscript:_recursion_count",
        "_build_observation_sealer|Attribute|_thread._local|__dict__|"
        "default:_thread_local_getattribute/subscript:__getattribute__",
        "_build_observation_sealer|Attribute|_thread._local|__dict__|"
        "default:_thread_local_setattr/subscript:__setattr__",
        "_build_observation_sealer|Attribute|_ChoreographyCheckpoint|__dict__|"
        "default:_choreography_checkpoint_descriptors/subscript:lease_sha256",
        "_build_observation_sealer|Attribute|_ChoreographyCheckpoint|__dict__|"
        "default:_choreography_checkpoint_descriptors/subscript:started_monotonic_ns",
        "_build_observation_sealer|Attribute|_ChoreographyCheckpoint|__dict__|"
        "default:_choreography_checkpoint_descriptors/subscript:deadline_monotonic_ns",
        "_build_observation_sealer|Attribute|_ChoreographyCheckpoint|__dict__|"
        "default:_choreography_checkpoint_descriptors/subscript:observed_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:retained_claim",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:artifact_directory",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:ignored_root",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:started_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:deadline_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentRecoveryRetentionCheckpoint|__dict__|"
        "default:_recovery_checkpoint_descriptors/subscript:observed_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:retained_claim",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:outcome_kind",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:artifact_directory",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:ignored_root",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:started_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:action_deadline_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:deadline_monotonic_ns",
        "_build_observation_sealer|Attribute|"
        "_TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint|__dict__|"
        "default:_controller_checkpoint_descriptors/subscript:observed_monotonic_ns",
        "_build_observation_sealer|Attribute|type|__getattribute__|default:_type_getattribute",
        "_build_observation_sealer|Attribute|object|__getattribute__|default:_object_getattribute",
        "_build_observation_sealer|Attribute|_EXACT_FRAME_TYPE|__getattribute__|"
        "default:_frame_getattribute",
        "_build_observation_sealer|Constant|reader_builder_frame|f_globals|"
        "call:_frame_getattribute",
        "_build_observation_sealer|Constant|reader_builder_frame|f_code|call:_frame_getattribute",
        "_build_observation_sealer|Constant|reader_builder_frame|f_code|call:_frame_getattribute",
        "_build_observation_sealer.require_projection_caller|Constant|frame|f_code|"
        "call:_frame_getattribute",
        "_build_observation_sealer.require_projection_caller|Constant|frame|f_globals|"
        "call:_frame_getattribute",
        "_build_observation_sealer.require_reader_module_caller|Constant|frame|f_code|"
        "call:_frame_getattribute",
        "_build_observation_sealer.require_reader_module_caller|Constant|frame|f_globals|"
        "call:_frame_getattribute",
    ),
}


def _native_bounded_process_reflection_attestation_nodes(
    tree: ast.Module,
    *,
    relative_path: Path,
    expected_attestations: tuple[str, ...],
    expected_module_ast_sha256: str,
) -> tuple[frozenset[ast.AST], list[Violation]]:
    """Admit only exact descriptor/frame reads proven by receiver and callsite."""

    if not expected_attestations and not expected_module_ast_sha256:
        return frozenset(), []
    boundary = "native bounded-process reflection attestation"
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_module_ast_sha256) is None
        or _canonical_ast_sha256(tree) != expected_module_ast_sha256
    ):
        return frozenset(), [
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve its exact module AST",
            )
        ]

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def enclosing_callable(node: ast.AST) -> str:
        names: list[str] = []
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(current.name)
        return ".".join(reversed(names)) if names else "<module>"

    def receiver_text(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = receiver_text(node.value)
            return f"{parent}.{node.attr}" if parent else None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "type"
            and len(node.args) == 1
            and not node.keywords
        ):
            argument = receiver_text(node.args[0])
            return f"type({argument})" if argument is not None else None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and receiver_text(node.func) == "sys._getframe"
            and not node.args
            and not node.keywords
        ):
            return "sys._getframe()"
        return None

    def containing_default(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        candidate: ast.AST,
    ) -> str | None:
        positional = [*function.args.posonlyargs, *function.args.args]
        positional_defaults = [
            *([None] * (len(positional) - len(function.args.defaults))),
            *function.args.defaults,
        ]
        pairs = [
            *zip(positional, positional_defaults, strict=True),
            *zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True),
        ]
        matches = [
            argument.arg
            for argument, default in pairs
            if default is not None and any(node is candidate for node in ast.walk(default))
        ]
        return matches[0] if len(matches) == 1 else None

    def top_level_assignment_target(node: ast.AST) -> str | None:
        current = node
        while current in parents and not isinstance(parents[current], ast.Module):
            current = parents[current]
        parent = parents.get(current)
        is_top_level_assignment = isinstance(parent, ast.Module) and isinstance(
            current, (ast.Assign, ast.AnnAssign)
        )
        if not is_top_level_assignment:
            return None
        targets = current.targets if isinstance(current, ast.Assign) else (current.target,)
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        return names[0] if len(targets) == 1 and len(names) == 1 else None

    def context_for_attribute(node: ast.Attribute, callsite: str) -> str | None:
        if node.attr == "f_globals" and receiver_text(node.value) == "sys._getframe()":
            target = top_level_assignment_target(node)
            return f"assign:{target}" if callsite == "<module>" and target else None
        parent = parents.get(node)
        if node.attr == "__dict__" and isinstance(parent, ast.Subscript) and parent.value is node:
            key = _constant_folded_text(parent.slice)
            if key is None:
                return None
            if callsite == "<module>":
                return f"module/subscript:{key}"
            functions = [
                candidate
                for candidate in ast.walk(tree)
                if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
                and candidate.name == callsite.rpartition(".")[2]
                and any(descendant is node for descendant in ast.walk(candidate))
            ]
            if len(functions) != 1:
                return None
            parameter = containing_default(functions[0], node)
            return f"default:{parameter}/subscript:{key}" if parameter else None
        if node.attr == "__dict__" and isinstance(parent, ast.Compare):
            if not (
                len(parent.ops) == 1
                and isinstance(parent.ops[0], ast.In)
                and len(parent.comparators) == 1
                and parent.comparators[0] is node
                and _constant_folded_text(parent.left) == "_raw_paths"
            ):
                return None
            return "module/contains:_raw_paths" if callsite == "<module>" else None
        if node.attr == "__getattribute__" and callsite == "_build_observation_sealer":
            functions = [
                candidate
                for candidate in tree.body
                if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
                and candidate.name == "_build_observation_sealer"
            ]
            parameter = containing_default(functions[0], node) if len(functions) == 1 else None
            return f"default:{parameter}" if parameter else None
        return None

    def attestation(node: ast.AST) -> str | None:
        callsite = enclosing_callable(node)
        if isinstance(node, ast.Attribute):
            receiver = receiver_text(node.value)
            context = context_for_attribute(node, callsite)
            if receiver is None or context is None:
                return None
            return f"{callsite}|Attribute|{receiver}|{node.attr}|{context}"
        if isinstance(node, ast.Constant) and node.value in {"f_code", "f_globals"}:
            parent = parents.get(node)
            if not (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "_frame_getattribute"
                and len(parent.args) == 2
                and parent.args[1] is node
                and isinstance(parent.args[0], ast.Name)
                and not parent.keywords
            ):
                return None
            return f"{callsite}|Constant|{parent.args[0].id}|{node.value}|call:_frame_getattribute"
        return None

    unmatched = list(expected_attestations)
    admitted: set[ast.AST] = set()
    observed: list[str] = []
    for node in ast.walk(tree):
        candidate = attestation(node)
        if candidate is None or candidate not in unmatched:
            continue
        unmatched.remove(candidate)
        observed.append(candidate)
        admitted.add(node)
    violations: list[Violation] = []
    if unmatched or sorted(observed) != sorted(expected_attestations):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve every exact receiver/callsite shape",
            )
        )
    return frozenset(admitted), violations


def _native_bounded_process_reserved_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    wrapper_module: str,
    allowed_consumer: bool,
    allowed_reflection_nodes: frozenset[ast.AST] = frozenset(),
) -> list[Violation]:
    """Deny transitive imports, reflection, and reexports of the process builtin."""

    reserved = "_run_bounded_process"
    reader = "_head_reviewed_operator_authority_object"
    owner_module = "scripts.verify_trusted_time_images"
    reader_consumer_module = "scripts.trusted_time_post_enrollment_execution_admission"
    forbidden_runtime_attributes = {
        "__closure__",
        "__code__",
        "__defaults__",
        "__globals__",
        "__kwdefaults__",
        "ag_frame",
        "cr_frame",
        "f_back",
        "f_code",
        "f_globals",
        "f_locals",
        "gi_frame",
        "tb_frame",
    }
    imports_owner = any(
        isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == owner_module
        for node in ast.walk(tree)
    )
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if node in allowed_reflection_nodes:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] in {"importlib", "inspect"}:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            "native bounded-process boundary forbids reflective module imports",
                        )
                    )
                if alias.name in {owner_module, reader_consumer_module}:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            "native bounded-process authority carrier cannot be namespace imported",
                        )
                    )
        if isinstance(node, ast.ImportFrom):
            if node.module in {"builtins", "importlib", "inspect"} and any(
                alias.name in {"__import__", "import_module"}
                or node.module in {"importlib", "inspect"}
                for alias in node.names
            ):
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        "native bounded-process boundary forbids reflective module imports",
                    )
                )
            if node.module == "scripts" and any(
                alias.name
                in {
                    "trusted_time_post_enrollment_execution_admission",
                    "verify_trusted_time_images",
                }
                for alias in node.names
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native bounded-process authority carrier cannot be namespace imported",
                    )
                )
            for alias in node.names:
                local = alias.asname or alias.name
                if node.module == owner_module and alias.name in {
                    "__dict__",
                    "__getattribute__",
                    "__globals__",
                }:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            "native bounded-process owner internals cannot be imported",
                        )
                    )
                if reserved not in {alias.name, local}:
                    continue
                if (
                    allowed_consumer
                    and node.level == 0
                    and node.module == wrapper_module
                    and alias.name == reserved
                    and alias.asname is None
                ):
                    continue
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native bounded-process symbol cannot be transitively imported "
                        "or reexported",
                    )
                )
        elif isinstance(node, ast.Attribute) and (
            node.attr == reserved
            or node.attr == "__import__"
            or node.attr in forbidden_runtime_attributes
            or (
                (allowed_consumer or imports_owner)
                and node.attr in {"__dict__", "__getattribute__"}
            )
        ):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native bounded-process authority cannot be reached through reflection",
                )
            )
        elif isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)) or (
            isinstance(node, ast.Call) and _constant_folded_text(node) is not None
        ):
            folded = _constant_folded_text(node)
            if folded in {
                owner_module,
                reader,
                reader_consumer_module,
                reserved,
                wrapper_module,
                *forbidden_runtime_attributes,
            }:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native bounded-process symbol cannot be reflected or exported by name",
                    )
                )
        elif (
            (allowed_consumer or imports_owner)
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"compile", "eval", "exec", "globals", "locals", "vars"}
        ):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native bounded-process owner cannot use dynamic namespace reflection",
                )
            )
        elif isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id == "__import__")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
        ):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native bounded-process boundary forbids dynamic module imports",
                )
            )
        elif not allowed_consumer and (
            (isinstance(node, ast.Name) and node.id in {"__import__", reserved})
            or (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == reserved
            )
        ):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    "native bounded-process symbol is reserved to its reviewed consumer",
                )
            )
    return violations


def _native_bounded_process_reader_usage_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    owner_module: str,
    allowed_consumer: bool,
) -> list[Violation]:
    """Keep the exported Git reader on its three reviewed downstream uses."""

    reader = "_head_reviewed_operator_authority_object"
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    imports: list[tuple[ast.ImportFrom, ast.alias]] = []
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            if reader not in {alias.name, local}:
                continue
            imports.append((node, alias))
            if not (
                allowed_consumer
                and node in getattr(tree, "body", ())
                and node.level == 0
                and node.module == owner_module
                and alias.name == reader
                and alias.asname is None
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        "native bounded-process Git reader cannot be transitively imported",
                    )
                )
    if allowed_consumer and len(imports) != 1:
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process Git reader must have one exact downstream import",
            )
        )
    if not allowed_consumer:
        return violations

    for node in ast.walk(tree):
        is_exact_import_alias = any(node is alias for _, alias in imports)
        binds_reader = (
            (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == reader
            )
            or (isinstance(node, ast.arg) and node.arg == reader)
            or (
                isinstance(node, ast.Name)
                and node.id == reader
                and isinstance(node.ctx, (ast.Store, ast.Del))
            )
            or (
                isinstance(node, ast.alias)
                and (node.asname or node.name.partition(".")[0]) == reader
            )
            or (
                isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                and node.name == reader
            )
            or (isinstance(node, ast.MatchMapping) and node.rest == reader)
        )
        if binds_reader and not is_exact_import_alias:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    "native bounded-process Git reader binding cannot be replaced",
                )
            )

    reader_loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == reader and isinstance(node.ctx, ast.Load)
    ]
    direct_calls: list[ast.Call] = []
    keyword_passes: list[ast.keyword] = []
    for load in reader_loads:
        parent = parents.get(load)
        if isinstance(parent, ast.Call) and parent.func is load:
            direct_calls.append(parent)
            continue
        if isinstance(parent, ast.keyword) and parent.value is load:
            keyword_passes.append(parent)
            continue
        violations.append(
            Violation(
                relative_path,
                load.lineno,
                "native bounded-process Git reader cannot be aliased or reflected",
            )
        )
    if len(direct_calls) != 2 or any(
        len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != "exact_revision"
        for call in direct_calls
    ):
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process Git reader must preserve two exact direct calls",
            )
        )
    for call in direct_calls:
        current: ast.AST | None = call
        while current is not None and not isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            current = parents.get(current)
        if not isinstance(current, ast.FunctionDef) or current.name != (
            "_load_post_enrollment_operator_attested_execution_approval_with_snapshot"
        ):
            violations.append(
                Violation(
                    relative_path,
                    call.lineno,
                    "native bounded-process Git reader direct call must remain in "
                    "its reviewed loader",
                )
            )
    if len(keyword_passes) != 1:
        violations.append(
            Violation(
                relative_path,
                1,
                "native bounded-process Git reader must preserve one exact callback handoff",
            )
        )
    else:
        keyword = keyword_passes[0]
        callback_call = parents.get(keyword)
        if (
            keyword.arg != "git_operator_authority_loader"
            or not isinstance(callback_call, ast.Call)
            or not isinstance(callback_call.func, ast.Name)
            or callback_call.func.id != "_load_post_enrollment_operator_attested_execution_approval"
        ):
            violations.append(
                Violation(
                    relative_path,
                    keyword.lineno,
                    "native bounded-process Git reader callback handoff must remain exact",
                )
            )
        current = callback_call
        while current is not None and not isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            current = parents.get(current)
        if not isinstance(current, ast.FunctionDef) or current.name != (
            "load_post_enrollment_operator_attested_execution_approval"
        ):
            violations.append(
                Violation(
                    relative_path,
                    keyword.lineno,
                    "native bounded-process Git reader callback must remain in "
                    "its reviewed public loader",
                )
            )
    return violations


def _native_executable_loading_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    wrapper_path: Path,
    wrapper_module: str,
    image_import_root: bool,
) -> list[Violation]:
    """Reject alternate native loaders from production image import roots."""

    if relative_path in {wrapper_path, Path("scripts/check_architecture.py")}:
        return []
    forbidden_modules = {"_imp", "cffi", "ctypes"}
    forbidden_attributes = {
        "CDLL",
        "ExtensionFileLoader",
        "PyDLL",
        "create_dynamic",
        "dlopen",
        "dlsym",
        "exec_dynamic",
        "memfd_create",
        "spec_from_file_location",
    }
    forbidden_private_names = {
        "_native_functions",
        "_native_module",
        "_native_owned_file_descriptor_capabilities",
        "_native_owned_file_descriptor_self_test",
        "_native_owner_type",
    }
    private_native_module = "packages.adapters.trusted_time._native_owned_file_descriptor"
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if image_import_root and alias.name.partition(".")[0] in forbidden_modules:
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            f"alternate native loader import '{alias.name}' is forbidden",
                        )
                    )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if image_import_root and node.module.partition(".")[0] in forbidden_modules:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"alternate native loader import '{node.module}' is forbidden",
                    )
                )
            if image_import_root:
                for alias in node.names:
                    if alias.name in forbidden_attributes:
                        violations.append(
                            Violation(
                                relative_path,
                                node.lineno,
                                f"alternate native loader capability '{alias.name}' is forbidden",
                            )
                        )
        elif isinstance(node, ast.Attribute) and (
            (image_import_root and node.attr in forbidden_attributes)
            or node.attr in forbidden_private_names
        ):
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"alternate native loader capability '{node.attr}' is forbidden",
                )
            )
        elif isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)):
            value = _constant_folded_text(node)
            if (
                value in forbidden_private_names
                or value
                in {
                    wrapper_module,
                    private_native_module,
                }
                or (value is not None and "/proc/self/fd" in value)
            ):
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        "reflective or raw-descriptor native capability access is forbidden",
                    )
                )
    return violations


def _exact_nonproject_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: frozenset[str],
) -> list[Violation]:
    bindings = _nonproject_import_bindings(tree)
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed non-project binding '{binding}'",
        )
        for line, binding in bindings
        if binding not in allowed
    ]
    observed = frozenset(binding for _, binding in bindings)
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed non-project binding '{binding}'",
        )
        for binding in sorted(allowed - observed)
    )
    return violations


def _exact_class_method_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    class_name: str,
    allowed: frozenset[str],
) -> list[Violation]:
    """Require one top-level class with one exact method surface."""

    classes = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(classes) != 1:
        return [
            Violation(
                relative_path,
                1,
                f"{boundary} must define exactly one class '{class_name}'",
            )
        ]
    observed = frozenset(
        node.name
        for node in classes[0].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    violations = [
        Violation(
            relative_path,
            classes[0].lineno,
            f"{boundary} cannot expose unreviewed method '{class_name}.{method}'",
        )
        for method in sorted(observed - allowed)
    ]
    violations.extend(
        Violation(
            relative_path,
            classes[0].lineno,
            f"{boundary} must preserve reviewed method '{class_name}.{method}'",
        )
        for method in sorted(allowed - observed)
    )
    return violations


def _exact_top_level_definition_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: tuple[str, ...],
) -> list[Violation]:
    """Require an exact module-level function/class definition surface."""

    observed = tuple(
        sorted(
            node.name
            for node in getattr(tree, "body", ())
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        )
    )
    expected = tuple(sorted(allowed))
    if observed == expected and len(observed) == len(set(observed)):
        return []
    return [
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve its exact reviewed top-level definition surface",
        )
    ]


def _exact_literal_assignment_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, str],
) -> list[Violation]:
    """Pin security-relevant module constants to exact literal strings."""

    assignments: dict[str, list[ast.Assign]] = {name: [] for name in expected}
    for node in getattr(tree, "body", ()):
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in assignments
        ):
            continue
        assignments[node.targets[0].id].append(node)
    violations: list[Violation] = []
    for name, expected_value in expected.items():
        candidates = assignments[name]
        if (
            len(candidates) == 1
            and isinstance(candidates[0].value, ast.Constant)
            and type(candidates[0].value.value) is str
            and candidates[0].value.value == expected_value
        ):
            continue
        violations.append(
            Violation(
                relative_path,
                candidates[0].lineno if candidates else 1,
                f"{boundary} must preserve exact literal constant '{name}'",
            )
        )
    return violations


def _exact_frozenset_assignment_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    name: str,
    expected: frozenset[str],
) -> list[Violation]:
    """Pin one literal ``frozenset({...})`` security-field assignment."""

    assignments = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    observed: frozenset[str] | None = None
    if len(assignments) == 1:
        value = assignments[0].value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Set)
            and all(
                isinstance(item, ast.Constant) and type(item.value) is str
                for item in value.args[0].elts
            )
        ):
            values = tuple(cast(str, cast(ast.Constant, item).value) for item in value.args[0].elts)
            if len(values) == len(set(values)):
                observed = frozenset(values)
    if observed == expected:
        return []
    return [
        Violation(
            relative_path,
            assignments[0].lineno if assignments else 1,
            f"{boundary} must preserve exact literal frozenset '{name}'",
        )
    ]


def _exact_closed_payload_builder_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
) -> list[Violation]:
    """Require ``_closed_payload`` to map every closed field to literal false."""

    functions = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.FunctionDef) and node.name == "_closed_payload"
    ]
    valid = False
    if len(functions) == 1 and len(functions[0].body) == 1:
        statement = functions[0].body[0]
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.DictComp):
            expression = statement.value
            generator = expression.generators[0] if len(expression.generators) == 1 else None
            valid = (
                isinstance(expression.value, ast.Constant)
                and expression.value.value is False
                and generator is not None
                and isinstance(generator.target, ast.Name)
                and isinstance(expression.key, ast.Name)
                and expression.key.id == generator.target.id
                and isinstance(generator.iter, ast.Name)
                and generator.iter.id == "_CLOSED_FIELDS"
                and not generator.ifs
                and generator.is_async == 0
            )
    if valid:
        return []
    return [
        Violation(
            relative_path,
            functions[0].lineno if functions else 1,
            f"{boundary} must map every closed field to literal false",
        )
    ]


def _exact_callable_true_payload_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, frozenset[str]],
) -> list[Violation]:
    """Pin literal-true payload facts inside exact module/class callables."""

    violations: list[Violation] = []
    for qualified_name, expected_keys in expected.items():
        owner_name, separator, callable_name = qualified_name.rpartition(".")
        owners: tuple[ast.AST, ...] = tuple(getattr(tree, "body", ()))
        if separator:
            classes = [
                node
                for node in getattr(tree, "body", ())
                if isinstance(node, ast.ClassDef) and node.name == owner_name
            ]
            owners = tuple(classes[0].body) if len(classes) == 1 else ()
        functions = [
            node
            for node in owners
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == callable_name
        ]
        observed: list[str] = []
        if len(functions) == 1:
            for node in ast.walk(functions[0]):
                if isinstance(node, ast.Dict):
                    observed.extend(
                        key.value
                        for key, value in zip(node.keys, node.values, strict=True)
                        if isinstance(key, ast.Constant)
                        and type(key.value) is str
                        and isinstance(value, ast.Constant)
                        and value.value is True
                    )
                elif (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True
                ):
                    targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                    observed.extend(
                        target.slice.value
                        for target in targets
                        if isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and type(target.slice.value) is str
                    )
        if frozenset(observed) == expected_keys and len(observed) == len(expected_keys):
            continue
        violations.append(
            Violation(
                relative_path,
                functions[0].lineno if functions else 1,
                f"{boundary} must preserve exact literal-true payload facts in '{qualified_name}'",
            )
        )
    return violations


def _canonical_ast_sha256(node: ast.AST) -> str:
    """Hash an AST without relying on version-specific ``ast.dump`` rendering."""

    def encode(value: object) -> object:
        if isinstance(value, ast.AST):
            fields = (
                field
                for field in value._fields
                if not (
                    field == "default_value"
                    and type(value).__name__ in {"ParamSpec", "TypeVar", "TypeVarTuple"}
                    and getattr(value, field, None) is None
                )
            )
            return [
                "ast",
                type(value).__name__,
                [[field, encode(getattr(value, field, None))] for field in fields],
            ]
        if isinstance(value, list):
            return ["list", [encode(item) for item in value]]
        if isinstance(value, tuple):
            return ["tuple", [encode(item) for item in value]]
        if value is None:
            return ["none"]
        if type(value) is bool:
            return ["bool", value]
        if type(value) is int:
            return ["int", str(value)]
        if type(value) is float:
            return ["float", value.hex()]
        if type(value) is complex:
            return ["complex", value.real.hex(), value.imag.hex()]
        if type(value) is str:
            return ["str", value]
        if type(value) is bytes:
            return ["bytes", value.hex()]
        if value is Ellipsis:
            return ["ellipsis"]
        raise TypeError(f"unsupported AST field value: {type(value).__name__}")

    canonical = json.dumps(
        encode(node),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _trusted_time_topology_production_ast_sha256(
    repository: Path,
    production_files: set[Path],
) -> str:
    """Hash the exact path/module-AST set admitted to topology production reach."""

    checker_relative = Path("scripts/check_architecture.py")
    normalized_paths: dict[str, Path] = {}
    trees: dict[str, ast.Module] = {}
    normalized_literal_count = 0
    for path in production_files:
        try:
            relative = path.relative_to(repository)
        except ValueError as error:
            raise ValueError("topology production AST path is outside the repository") from error
        relative_text = relative.as_posix()
        if (
            relative.is_absolute()
            or relative == Path(".")
            or ".." in relative.parts
            or relative.suffix != ".py"
            or relative_text in normalized_paths
        ):
            raise ValueError("topology production AST path collision")
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("topology production AST entries must be regular files")
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative_text)
        if relative == checker_relative:
            assignments = [
                node
                for node in tree.body
                if isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "_TRUSTED_TIME_TOPOLOGY_PRODUCTION_AST_SHA256"
            ]
            if (
                len(assignments) != 1
                or not isinstance(assignments[0].value, ast.Constant)
                or type(assignments[0].value.value) is not str
                or re.fullmatch(r"[0-9a-f]{64}", assignments[0].value.value) is None
            ):
                raise ValueError("topology production AST self-digest literal must be exact")
            assignments[0].value = ast.Constant(
                value=_TRUSTED_TIME_TOPOLOGY_PRODUCTION_AST_SENTINEL
            )
            normalized_literal_count += 1
        normalized_paths[relative_text] = path
        trees[relative_text] = tree
    if normalized_literal_count != 1:
        raise ValueError("topology production AST must normalize exactly one self-digest")

    digest = hashlib.sha256()
    digest.update(b"trusted-time-topology-production-ast-v1\0")
    digest.update(len(trees).to_bytes(8, "big"))
    for relative_text, tree in sorted(trees.items()):
        relative_bytes = relative_text.encode("utf-8")
        module_digest = bytes.fromhex(_canonical_ast_sha256(tree))
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(b"\0")
        digest.update(len(module_digest).to_bytes(8, "big"))
        digest.update(module_digest)
        digest.update(b"\0")
    return digest.hexdigest()


def _production_python_source_manifest_sha256(
    repository: Path,
    roots: tuple[Path, ...],
    pruned_subtrees: tuple[Path, ...],
) -> str:
    """Hash the exact path/source-byte set for parseable production Python."""

    paths: dict[str, Path] = {}
    pruned = frozenset(pruned_subtrees)
    if len(pruned) != len(pruned_subtrees):
        raise ValueError("production Python manifest prune collision")
    if any(not any(subtree.is_relative_to(root) for root in roots) for subtree in pruned_subtrees):
        raise ValueError("production Python manifest prune must be beneath a reviewed root")
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("production Python manifest root must be a regular directory")
        pending = [root]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                if path in pruned:
                    if path.is_symlink() or not path.is_dir():
                        raise ValueError(
                            "production Python manifest prune must be a regular directory"
                        )
                    continue
                metadata = path.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("production Python manifest cannot contain symlinks")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                    continue
                lower_name = path.name.lower()
                is_native_extension = lower_name.endswith((".so", ".pyd", ".dylib", ".dll")) or any(
                    marker in lower_name for marker in (".so.", ".dylib.")
                )
                if is_native_extension:
                    raise ValueError(
                        "production Python manifest cannot contain native extension artifacts"
                    )
                if path.suffix.lower() in {".pyc", ".pyo"}:
                    raise ValueError("production Python manifest cannot contain bytecode artifacts")
                if path.suffix.lower() != ".py":
                    continue
                if "__pycache__" in path.relative_to(root).parts:
                    raise ValueError(
                        "production Python manifest cannot contain source inside __pycache__"
                    )
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("production Python manifest entries must be regular files")
                relative = path.relative_to(repository).as_posix()
                if relative in paths:
                    raise ValueError("production Python manifest path collision")
                paths[relative] = path
    digest = hashlib.sha256()
    digest.update(len(paths).to_bytes(8, "big"))
    for relative, path in sorted(paths.items()):
        relative_bytes = relative.encode("utf-8")
        source = path.read_bytes()
        ast.parse(source.decode("utf-8"), filename=relative)
        source_digest = hashlib.sha256(source).digest()
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(b"\0")
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(source_digest)
        digest.update(b"\0")
    return digest.hexdigest()


def _project_build_bootstrap_manifest_sha256(
    repository: Path,
    relative_paths: tuple[str, ...],
) -> str:
    """Hash an exact path-framed set before repository build code may execute."""

    if len(relative_paths) != len(frozenset(relative_paths)):
        raise ValueError("project build bootstrap manifest path collision")
    paths: dict[str, Path] = {}
    for relative in relative_paths:
        candidate = Path(relative)
        if (
            type(relative) is not str
            or not relative
            or candidate.is_absolute()
            or candidate.as_posix() != relative
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ValueError("project build bootstrap manifest path is invalid")
        cursor = repository
        for part in candidate.parts:
            cursor = cursor / part
            metadata = cursor.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("project build bootstrap manifest cannot contain symlinks")
        metadata = cursor.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("project build bootstrap manifest entries must be regular files")
        paths[relative] = cursor

    digest = hashlib.sha256()
    digest.update(len(paths).to_bytes(8, "big"))
    for relative, path in sorted(paths.items()):
        relative_bytes = relative.encode("utf-8")
        source = path.read_bytes()
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(b"\0")
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(hashlib.sha256(source).digest())
        digest.update(b"\0")
    return digest.hexdigest()


def _project_build_bootstrap_configuration_violations(repository: Path) -> list[Violation]:
    """Reject alternate local PEP-517 configuration before project synchronization."""

    pyproject_path = repository / "pyproject.toml"
    python_version_path = repository / ".python-version"
    build_constraints_path = repository / "build_support/native_build_constraints.txt"
    violations: list[Violation] = []
    try:
        with pyproject_path.open("rb") as stream:
            pyproject = tomllib.load(stream)
        python_version = python_version_path.read_text(encoding="utf-8")
        build_constraints = build_constraints_path.read_text(encoding="utf-8")
    except (OSError, tomllib.TOMLDecodeError, UnicodeError):
        return [
            Violation(
                Path("pyproject.toml"),
                1,
                "project build bootstrap configuration is unavailable",
            )
        ]

    build_system = pyproject.get("build-system")
    project = pyproject.get("project")
    tool = pyproject.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    hatch = tool.get("hatch") if isinstance(tool, dict) else None
    build = hatch.get("build") if isinstance(hatch, dict) else None
    targets = build.get("targets") if isinstance(build, dict) else None
    wheel = targets.get("wheel") if isinstance(targets, dict) else None
    sdist = targets.get("sdist") if isinstance(targets, dict) else None
    wheel_hooks = wheel.get("hooks") if isinstance(wheel, dict) else None
    custom_hook = wheel_hooks.get("custom") if isinstance(wheel_hooks, dict) else None
    wheel_exclude = wheel.get("exclude") if isinstance(wheel, dict) else None
    sdist_exclude = sdist.get("exclude") if isinstance(sdist, dict) else None
    force_include = sdist.get("force-include") if isinstance(sdist, dict) else None
    if build_system != {
        "requires": list(_NATIVE_BUILD_REQUIREMENTS),
        "build-backend": "hatchling.build",
    }:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project build backend must remain exact and fully pinned",
            )
        )
    if uv != {"build-constraint-dependencies": list(_NATIVE_BUILD_REQUIREMENTS)}:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project native build constraints must remain exact and fully pinned",
            )
        )
    if not isinstance(project, dict) or project.get("requires-python") != ">=3.12,<3.14":
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project Python range must match the reviewed native ABI matrix",
            )
        )
    if custom_hook != {"path": "build_support/native_owned_file_descriptor_hook.py"}:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project native wheel hook path must remain exact",
            )
        )
    if wheel_exclude != ["packages/adapters/trusted_time/_bounded_process.py"]:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project native wheel exclusion set must remain exact",
            )
        )
    if sdist_exclude != [
        "/.uv-cache",
        "build_support/build_native_test_launcher.py",
    ]:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project native sdist exclusion set must remain exact",
            )
        )
    if force_include != {
        "build_support/native_build_constraints.txt": (
            "build_support/native_build_constraints.txt"
        ),
        "build_support/native_image_manifest.py": "build_support/native_image_manifest.py",
        "build_support/native_owned_file_descriptor_hook.py": (
            "build_support/native_owned_file_descriptor_hook.py"
        ),
        "native/bounded_process.c": "native/bounded_process.c",
        "native/owned_file_descriptor.c": "native/owned_file_descriptor.c",
        "native/trusted_time_python_launcher.c": "native/trusted_time_python_launcher.c",
        "packages/adapters/trusted_time/_bounded_process.py": (
            "packages/adapters/trusted_time/_bounded_process.py"
        ),
    }:
        violations.append(
            Violation(
                Path("pyproject.toml"),
                1,
                "project native sdist source set must remain exact",
            )
        )
    if build_constraints != _NATIVE_BUILD_CONSTRAINTS_TEXT:
        violations.append(
            Violation(
                Path("build_support/native_build_constraints.txt"),
                1,
                "project native build constraint hashes must remain exact",
            )
        )
    if python_version != "3.12\n":
        violations.append(
            Violation(
                Path(".python-version"),
                1,
                "project Python bootstrap pin must remain exact",
            )
        )
    return violations


def _architecture_checker_invocation_violations(repository: Path) -> list[Violation]:
    """Require every authoritative checker entrypoint to use isolated startup."""

    def exact_line_block_starts(source: str, expected: str) -> tuple[int, ...]:
        source_lines = source.splitlines()
        expected_lines = expected.splitlines()
        return tuple(
            index
            for index in range(len(source_lines) - len(expected_lines) + 1)
            if source_lines[index : index + len(expected_lines)] == expected_lines
        )

    def count_exact_line_block(source: str, expected: str) -> int:
        return len(exact_line_block_starts(source, expected))

    def checker_steps_have_control_overrides(source: str, expected: tuple[str, ...]) -> bool:
        source_lines = source.splitlines()
        forbidden_step_keys = (
            "continue-on-error:",
            "env:",
            "if:",
            "shell:",
            "working-directory:",
        )
        starts = tuple(
            start for command in expected for start in exact_line_block_starts(source, command)
        )
        for start in starts:
            cursor = start - 1
            while cursor >= 0:
                line = source_lines[cursor]
                indentation = len(line) - len(line.lstrip(" "))
                if indentation <= 6:
                    break
                if line.strip().startswith(forbidden_step_keys):
                    return True
                cursor -= 1
        return any(
            len(line) - len(line.lstrip(" ")) <= 4
            and line.strip().startswith(("continue-on-error:", "if:"))
            for line in source_lines
        )

    expected_command = (
        "uv run --isolated --no-project --no-config --offline --no-python-downloads "
        "--python 3.12 python -I -B scripts/check_architecture.py"
    )
    expected_make_block = (
        "\t$(UV) run --isolated --no-project --no-config --offline --no-python-downloads \\\n"
        "\t\t--python 3.12 python -I -B scripts/check_architecture.py"
    )
    workflow_command_prefix = (
        "        run: >-\n"
        "          uv run\n"
        "          --isolated\n"
        "          --no-project\n"
        "          --no-config\n"
        "          --offline\n"
        "          --no-python-downloads\n"
    )
    workflow_command_suffix = (
        "          python\n          -I\n          -B\n          scripts/check_architecture.py"
    )
    workflow_python_312_command = (
        workflow_command_prefix + "          --python 3.12\n" + workflow_command_suffix
    )
    workflow_matrix_command = (
        workflow_command_prefix
        + "          --python ${{ matrix.python-version }}\n"
        + workflow_command_suffix
    )
    makefile = repository / "Makefile"
    workflow_root = repository / ".github/workflows"
    documentation = (
        repository / "docs/ARCHITECTURE.md",
        repository / "docs/IMPLEMENTATION_PLAN.md",
        repository / "docs/adr/0111-dormant-operation-bound-clean-stop-supervisor-bridge.md",
        repository / "docs/runbooks/trusted-time-supervisor.md",
    )
    violations: list[Violation] = []
    try:
        make_source = makefile.read_text(encoding="utf-8")
        workflow_paths = tuple(
            sorted(
                path
                for path in workflow_root.iterdir()
                if path.is_file() and path.suffix in {".yaml", ".yml"}
            )
        )
        workflow_sources = {path: path.read_text(encoding="utf-8") for path in workflow_paths}
        documentation_sources = {path: path.read_text(encoding="utf-8") for path in documentation}
    except OSError:
        return [
            Violation(
                Path("infra/architecture-boundaries.toml"),
                1,
                "architecture checker invocation contract is unavailable",
            )
        ]
    make_lines = make_source.splitlines()
    make_bytecode_controls = [
        line.strip() for line in make_lines if "PYTHONDONTWRITEBYTECODE" in line
    ]
    check_headers = [
        index
        for index, line in enumerate(make_lines)
        if line == "check:" or line.startswith("check: ##")
    ]
    check_runs_architecture_first = (
        len(check_headers) == 1
        and check_headers[0] + 1 < len(make_lines)
        and make_lines[check_headers[0] + 1] == "\t$(MAKE) architecture-check"
    )
    if (
        count_exact_line_block(make_source, expected_make_block) != 1
        or make_source.count("check_architecture.py") != 1
        or not check_runs_architecture_first
        or make_bytecode_controls
        != [
            "override PYTHONDONTWRITEBYTECODE := 1",
            "export PYTHONDONTWRITEBYTECODE",
        ]
    ):
        violations.append(
            Violation(
                Path("Makefile"),
                1,
                "architecture checker Make invocation must be exact, isolated, and bytecode-free",
            )
        )
    expected_workflow = repository / ".github/workflows/ci.yml"
    workflow_source = workflow_sources.get(expected_workflow, "")
    architecture_marker = "  architecture:\n"
    backend_marker = "  backend:\n"
    native_marker = "  native-packaging:\n"
    frontend_marker = "  frontend:\n"
    containers_marker = "  containers:\n"
    architecture_position = workflow_source.find(architecture_marker)
    backend_position = workflow_source.find(backend_marker)
    native_position = workflow_source.find(native_marker)
    frontend_position = workflow_source.find(frontend_marker)
    containers_position = workflow_source.find(containers_marker)
    architecture_source = (
        workflow_source[architecture_position:backend_position]
        if 0 <= architecture_position < backend_position
        else ""
    )
    backend_source = (
        workflow_source[backend_position:native_position]
        if 0 <= backend_position < native_position
        else ""
    )
    native_source = (
        workflow_source[native_position:frontend_position]
        if 0 <= native_position < frontend_position
        else ""
    )
    containers_source = workflow_source[containers_position:] if containers_position >= 0 else ""
    exact_binary_dependency_sync = (
        "run: uv sync --all-groups --locked --no-install-project --no-build"
    )
    if (
        workflow_paths != (expected_workflow,)
        or count_exact_line_block(workflow_source, workflow_python_312_command) != 5
        or count_exact_line_block(workflow_source, workflow_matrix_command) != 2
        or workflow_source.count("scripts/check_architecture.py") != 7
        or workflow_source.count('PYTHONDONTWRITEBYTECODE: "1"') != 4
        or workflow_source.count("UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt")
        != 3
        or workflow_source.count(exact_binary_dependency_sync) != 3
        or workflow_source.count("--build-constraints build_support/native_build_constraints.txt")
        != 7
        or workflow_source.count("--require-hashes") != 7
        or workflow_source.count("uv pip install") != 3
        or workflow_source.count("--no-deps") != 3
        or checker_steps_have_control_overrides(
            workflow_source,
            (workflow_python_312_command, workflow_matrix_command),
        )
        or count_exact_line_block(architecture_source, workflow_python_312_command) != 1
        or "uv sync" in architecture_source
        or "uv build" in architecture_source
        or "needs:" in architecture_source
        or count_exact_line_block(backend_source, workflow_python_312_command) != 2
        or backend_source.count("      - architecture") != 1
        or backend_source.find(exact_binary_dependency_sync)
        >= backend_source.find(workflow_python_312_command)
        or backend_source.find("uv build --sdist")
        <= backend_source.find(workflow_python_312_command)
        or backend_source.find("uv build --sdist")
        >= backend_source.rfind(workflow_python_312_command)
        or count_exact_line_block(native_source, workflow_matrix_command) != 2
        or native_source.count("      - architecture") != 1
        or native_source.find(exact_binary_dependency_sync)
        >= native_source.find(workflow_matrix_command)
        or native_source.find("uv build --sdist") <= native_source.find(workflow_matrix_command)
        or native_source.find("uv build --sdist") >= native_source.rfind(workflow_matrix_command)
        or count_exact_line_block(containers_source, workflow_python_312_command) != 2
        or containers_source.count("      - architecture") != 1
        or containers_source.find(exact_binary_dependency_sync)
        >= containers_source.find(workflow_python_312_command)
        or containers_source.find("uv build --sdist")
        <= containers_source.find(workflow_python_312_command)
        or containers_source.find("uv build --sdist")
        >= containers_source.rfind(workflow_python_312_command)
    ):
        violations.append(
            Violation(
                Path(".github/workflows"),
                1,
                "architecture checker CI invocation must be exact, isolated, and bytecode-free",
            )
        )
    for path, source in documentation_sources.items():
        if source.count(expected_command) != 1:
            violations.append(
                Violation(
                    path.relative_to(repository),
                    1,
                    "architecture checker documented invocation must be exact and singular",
                )
            )
    return violations


def _architecture_checker_invocation_source_sha256_violations(
    repository: Path,
    config_path: Path,
    expected: dict[str, str],
) -> list[Violation]:
    """Pin the complete Make and CI sources that invoke this checker."""

    expected_paths = {"Makefile", ".github/workflows/ci.yml"}
    if set(expected) != expected_paths or any(
        re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in expected.values()
    ):
        return [
            Violation(
                config_path,
                1,
                "architecture checker invocation source digests must be mandatory and exact",
            )
        ]
    violations: list[Violation] = []
    for relative in sorted(expected):
        path = repository / relative
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            metadata = None
        valid = (
            metadata is not None
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_ISREG(metadata.st_mode)
        )
        source = b""
        if valid:
            try:
                source = path.read_bytes()
            except OSError:
                valid = False
        if not valid or hashlib.sha256(source).hexdigest() != expected[relative]:
            violations.append(
                Violation(
                    Path(relative),
                    1,
                    "architecture checker invocation source must match its exact raw digest",
                )
            )
    return violations


def _exact_module_ast_sha256_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected_sha256: str,
) -> list[Violation]:
    """Pin the complete semantic AST of a reviewed dormant bridge module."""

    if _canonical_ast_sha256(tree) == expected_sha256:
        return []
    return [
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve its exact semantic module AST",
        )
    ]


def _module_ast_sha256_config_violations(
    *,
    repository: Path,
    config_path: Path,
    boundary: str,
    roots: tuple[Path, ...],
    module_name: str,
    expected_sha256: str,
    required: bool = False,
) -> list[Violation]:
    """Require one exact file root, its dotted module, and its AST digest."""

    if not required and not expected_sha256 and (not roots or not module_name):
        return []
    expected_module = ""
    if len(roots) == 1 and roots[0].suffix == ".py":
        try:
            expected_module = ".".join(roots[0].relative_to(repository).with_suffix("").parts)
        except ValueError:
            expected_module = ""
    if (
        expected_module
        and module_name == expected_module
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None
    ):
        return []
    try:
        relative_config = config_path.relative_to(repository)
    except ValueError:
        relative_config = config_path
    return [
        Violation(
            relative_config,
            1,
            f"{boundary} must configure one exact root, dotted module, and semantic AST digest",
        )
    ]


def _constant_folded_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_folded_text(node.left)
        right = _constant_folded_text(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or type(value.value) is not str:
                return None
            parts.append(value.value)
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and not node.keywords
        and len(node.args) == 1
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _constant_folded_text(node.func.value)
        joined_parts = tuple(_constant_folded_text(value) for value in node.args[0].elts)
        if separator is not None and all(part is not None for part in joined_parts):
            return separator.join(cast(tuple[str, ...], joined_parts))
    return None


def _builtin_namespace_integrity_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    allowed_imports: tuple[str, ...],
    allowed_reads: tuple[str, ...],
    allowed_sys_modules_callsites: tuple[str, ...],
) -> list[Violation]:
    """Forbid production code from poisoning Python's ambient builtins namespace."""

    boundary = "production builtin namespace integrity"
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    bindings = _imported_symbol_bindings(tree)
    module_aliases = {
        local_name
        for local_name, qualified_name in bindings.items()
        if qualified_name == "builtins"
    }
    observed_imports = tuple(
        binding
        for _, binding in _nonproject_import_bindings(tree)
        if binding == "builtins:*" or binding.startswith("builtins:")
    )
    violations: list[Violation] = []
    if sorted(observed_imports) != sorted(allowed_imports):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve exact reviewed builtins imports",
            )
        )

    annotation_roots = {
        annotation
        for node in ast.walk(tree)
        for annotation in (
            (node.annotation,)
            if isinstance(node, (ast.arg, ast.AnnAssign)) and node.annotation is not None
            else (node.returns,)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.returns is not None
            else ()
        )
    }

    def is_within_annotation(node: ast.AST) -> bool:
        current = node
        while True:
            if current in annotation_roots:
                return True
            if current not in parents:
                return False
            current = parents[current]

    def read_context(attribute: ast.Attribute) -> str:
        if is_within_annotation(attribute):
            return "annotation"
        parent = parents.get(attribute)
        if isinstance(parent, ast.Compare) and all(
            isinstance(operator, (ast.Is, ast.IsNot)) for operator in parent.ops
        ):
            return "identity"
        return "unreviewed"

    observed_reads: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name) and node.id == "__builtins__") or (
            isinstance(node, ast.Attribute) and node.attr == "__builtins__"
        ):
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} cannot reference __builtins__",
                )
            )
        folded = _constant_folded_text(node)
        if folded in {"builtins", "__builtins__"}:
            parent = parents.get(node)
            if _constant_folded_text(parent) == folded if isinstance(parent, ast.AST) else False:
                continue
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} cannot dynamically resolve the builtins module",
                )
            )
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in module_aliases
        ):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            qualified = _qualified_symbol(parent, bindings)
            reference = f"{qualified}@{read_context(parent)}"
            observed_reads.append(reference)
            continue
        violations.append(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot pass through a builtins module alias",
            )
        )
    if sorted(observed_reads) != sorted(allowed_reads):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve exact read-only builtins references",
            )
        )

    def enclosing_callable(node: ast.AST) -> str:
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current.name
        return "<module>"

    native_module_name_assignments = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_NATIVE_MODULE_NAME"
    ]
    exact_private_native_module_name = (
        len(native_module_name_assignments) == 1
        and isinstance(native_module_name_assignments[0].value, ast.Constant)
        and native_module_name_assignments[0].value.value
        in {
            "_autoquant_native_owned_file_descriptor",
            "_autoquant_native_bounded_process",
        }
    )

    def captured_sys_modules_flow(node: ast.Attribute) -> str | None:
        """Recognize one sealed builder's exact default-to-dict.get module lookup."""

        function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = current
                break
        if function is None or function not in getattr(tree, "body", ()):
            return None
        positional = [*function.args.posonlyargs, *function.args.args]
        positional_defaults = [
            *([None] * (len(positional) - len(function.args.defaults))),
            *function.args.defaults,
        ]
        default_pairs = [
            *zip(positional, positional_defaults, strict=True),
            *zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True),
        ]
        captured_arguments = [
            argument
            for argument, default in default_pairs
            if default is node and argument.arg == "_sys_modules"
        ]
        if len(captured_arguments) != 1:
            return None
        captured_loads = [
            candidate
            for candidate in ast.walk(function)
            if isinstance(candidate, ast.Name)
            and isinstance(candidate.ctx, ast.Load)
            and candidate.id == "_sys_modules"
        ]
        if len(captured_loads) != 1:
            return None
        captured_load = captured_loads[0]
        lookup = parents.get(captured_load)
        if not (
            isinstance(lookup, ast.Call)
            and isinstance(lookup.func, ast.Name)
            and lookup.func.id == "_dict_get"
            and len(lookup.args) == 2
            and lookup.args[0] is captured_load
            and isinstance(lookup.args[1], ast.Name)
            and lookup.args[1].id == "module_name"
            and not lookup.keywords
        ):
            return None
        return f"{function.name}:capture-private-module-map"

    observed_sys_modules_callsites: list[str] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Attribute) and _qualified_symbol(node, bindings) == "sys.modules"
        ):
            continue
        parent = parents.get(node)
        callsite = enclosing_callable(node)
        if (
            exact_private_native_module_name
            and isinstance(parent, ast.Compare)
            and isinstance(parent.left, ast.Name)
            and parent.left.id == "_NATIVE_MODULE_NAME"
            and isinstance(parent.left.ctx, ast.Load)
            and len(parent.ops) == 1
            and isinstance(parent.ops[0], ast.In)
            and parent.comparators == [node]
        ):
            observed_sys_modules_callsites.append(f"{callsite}:contains-private-native")
            continue
        pop_attribute = parent
        pop_call = parents.get(pop_attribute) if isinstance(pop_attribute, ast.AST) else None
        if (
            exact_private_native_module_name
            and isinstance(pop_attribute, ast.Attribute)
            and pop_attribute.value is node
            and pop_attribute.attr == "pop"
            and isinstance(pop_call, ast.Call)
            and pop_call.func is pop_attribute
            and len(pop_call.args) == 2
            and isinstance(pop_call.args[0], ast.Name)
            and pop_call.args[0].id == "_NATIVE_MODULE_NAME"
            and isinstance(pop_call.args[0].ctx, ast.Load)
            and isinstance(pop_call.args[1], ast.Constant)
            and pop_call.args[1].value is None
            and not pop_call.keywords
        ):
            observed_sys_modules_callsites.append(f"{callsite}:pop-private-native")
            continue
        captured_flow = captured_sys_modules_flow(node)
        if captured_flow is not None:
            observed_sys_modules_callsites.append(captured_flow)
            continue
        items_attribute = parents.get(node)
        items_call = parents.get(items_attribute) if isinstance(items_attribute, ast.AST) else None
        tuple_call = parents.get(items_call) if isinstance(items_call, ast.AST) else None
        for_node = parents.get(tuple_call) if isinstance(tuple_call, ast.AST) else None
        valid = (
            isinstance(items_attribute, ast.Attribute)
            and items_attribute.value is node
            and items_attribute.attr == "items"
            and isinstance(items_call, ast.Call)
            and items_call.func is items_attribute
            and not items_call.args
            and not items_call.keywords
            and isinstance(tuple_call, ast.Call)
            and isinstance(tuple_call.func, ast.Name)
            and tuple_call.func.id == "tuple"
            and tuple_call.args == [items_call]
            and not tuple_call.keywords
            and isinstance(for_node, ast.For)
            and for_node.iter is tuple_call
            and isinstance(for_node.target, (ast.Tuple, ast.List))
            and len(for_node.target.elts) == 2
            and isinstance(for_node.target.elts[1], ast.Name)
        )
        if not valid:
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot access sys.modules outside reviewed attestation",
                )
            )
            continue
        observed_sys_modules_callsites.append(callsite)
        reviewed_for = cast(ast.For, for_node)
        reviewed_target = cast(ast.Tuple | ast.List, reviewed_for.target)
        module_name = cast(ast.Name, reviewed_target.elts[1]).id
        for candidate in ast.walk(reviewed_for):
            if not (
                isinstance(candidate, ast.Name)
                and isinstance(candidate.ctx, ast.Load)
                and candidate.id == module_name
            ):
                continue
            call = parents.get(candidate)
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "getattr"
                and len(call.args) == 3
                and call.args[0] is candidate
                and isinstance(call.args[1], ast.Constant)
                and call.args[1].value == "__file__"
                and isinstance(call.args[2], ast.Constant)
                and call.args[2].value is None
                and not call.keywords
            ):
                continue
            violations.append(
                Violation(
                    relative_path,
                    candidate.lineno,
                    f"{boundary} cannot pass through a sys.modules value",
                )
            )
    if sorted(observed_sys_modules_callsites) != sorted(allowed_sys_modules_callsites):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve exact read-only sys.modules callsites",
            )
        )
    return violations


def _exact_callable_ast_sha256_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, str],
) -> list[Violation]:
    """Pin the exact semantic AST of security-relevant payload builders."""

    violations: list[Violation] = []
    for qualified_name, expected_sha256 in expected.items():
        owner_name, separator, callable_name = qualified_name.rpartition(".")
        owners: tuple[ast.AST, ...] = tuple(getattr(tree, "body", ()))
        if separator:
            classes = [
                node
                for node in getattr(tree, "body", ())
                if isinstance(node, ast.ClassDef) and node.name == owner_name
            ]
            owners = tuple(classes[0].body) if len(classes) == 1 else ()
        functions = [
            node
            for node in owners
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == callable_name
        ]
        observed_sha256 = _canonical_ast_sha256(functions[0]) if len(functions) == 1 else None
        if observed_sha256 == expected_sha256:
            continue
        violations.append(
            Violation(
                relative_path,
                functions[0].lineno if functions else 1,
                f"{boundary} must preserve exact payload-builder AST '{qualified_name}'",
            )
        )
    return violations


def _exact_class_ast_sha256_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, str],
    required_classes: frozenset[str],
) -> list[Violation]:
    """Pin the complete semantic AST of reviewed security-evidence classes."""

    violations: list[Violation] = []
    if set(expected) != required_classes:
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must pin every AST-pinned callable owner class",
            )
        )
    for class_name, expected_sha256 in expected.items():
        classes = [
            node
            for node in getattr(tree, "body", ())
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        observed_sha256 = _canonical_ast_sha256(classes[0]) if len(classes) == 1 else None
        if observed_sha256 == expected_sha256:
            continue
        violations.append(
            Violation(
                relative_path,
                classes[0].lineno if classes else 1,
                f"{boundary} must preserve exact evidence-class AST '{class_name}'",
            )
        )
    return violations


def _exact_ast_owner_class_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, str],
) -> list[Violation]:
    """Keep every class owning a pinned callable sole-bound and unaliased."""

    owner_names = {
        qualified_name.rpartition(".")[0] for qualified_name in expected if "." in qualified_name
    }
    if not owner_names:
        return []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def binding_owner(node: ast.AST) -> ast.AST:
        current = node
        while current in parents and not isinstance(current, ast.stmt):
            current = parents[current]
        return current

    bindings: dict[str, list[ast.AST]] = {name: [] for name in owner_names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in bindings:
                bindings[node.id].append(binding_owner(node))
        elif isinstance(node, ast.arg) and node.arg in bindings:
            bindings[node.arg].append(binding_owner(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in bindings:
                bindings[node.name].append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.partition(".")[0]
                if name in bindings:
                    bindings[name].append(node)
        elif (
            isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
            and node.name in bindings
        ):
            bindings[node.name].append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest in bindings:
            bindings[node.rest].append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in owner_names & set(node.names):
                bindings[name].append(node)

    top_level_classes = {
        name: [
            node
            for node in getattr(tree, "body", ())
            if isinstance(node, ast.ClassDef) and node.name == name
        ]
        for name in owner_names
    }
    valid = all(
        len(top_level_classes[name]) == 1
        and len(bindings[name]) == 1
        and bindings[name][0] is top_level_classes[name][0]
        for name in owner_names
    )

    annotation_roots = {
        annotation
        for node in ast.walk(tree)
        for annotation in (
            (node.annotation,)
            if isinstance(node, (ast.arg, ast.AnnAssign)) and node.annotation is not None
            else (node.returns,)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.returns is not None
            else ()
        )
    }

    def is_within_annotation(node: ast.AST) -> bool:
        current = node
        while True:
            if current in annotation_roots:
                return True
            if current not in parents:
                return False
            current = parents[current]

    def is_exact_type_identity_check(node: ast.Name) -> bool:
        comparison = parents.get(node)
        return (
            isinstance(comparison, ast.Compare)
            and node in comparison.comparators
            and all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in comparison.ops)
            and isinstance(comparison.left, ast.Call)
            and isinstance(comparison.left.func, ast.Name)
            and comparison.left.func.id == "type"
            and len(comparison.left.args) == 1
            and not comparison.left.keywords
        )

    def is_exact_cast_assignment(node: ast.Name) -> bool:
        call = parents.get(node)
        statement = binding_owner(node)
        return (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "cast"
            and len(call.args) == 2
            and call.args[0] is node
            and not call.keywords
            and isinstance(statement, ast.Assign)
            and statement.value is call
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "exact_request"
        )

    def is_reviewed_object_new_load(node: ast.Name) -> bool:
        statement = binding_owner(node)
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "candidate"
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == "cast"
            and len(statement.value.args) == 2
            and not statement.value.keywords
            and isinstance(statement.value.args[0], ast.Name)
            and statement.value.args[0].id == node.id
        ):
            return False
        outer_cast = statement.value
        new_call = outer_cast.args[1]
        if not (
            isinstance(new_call, ast.Call)
            and isinstance(new_call.func, ast.Attribute)
            and isinstance(new_call.func.value, ast.Name)
            and new_call.func.value.id == "object"
            and new_call.func.attr == "__new__"
            and len(new_call.args) == 1
            and not new_call.keywords
        ):
            return False
        inner_cast = new_call.args[0]
        return (
            isinstance(inner_cast, ast.Call)
            and isinstance(inner_cast.func, ast.Name)
            and inner_cast.func.id == "cast"
            and len(inner_cast.args) == 2
            and not inner_cast.keywords
            and isinstance(inner_cast.args[1], ast.Name)
            and inner_cast.args[1].id == node.id
            and node in {outer_cast.args[0], inner_cast.args[1]}
        )

    def contains_type_call(node: ast.AST) -> bool:
        return any(
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Name)
            and candidate.func.id == "type"
            for candidate in ast.walk(node)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in owner_names:
            parent = parents.get(node)
            if not (
                is_within_annotation(node)
                or (isinstance(parent, ast.Call) and parent.func is node and node.id in owner_names)
                or is_exact_type_identity_check(node)
                or is_exact_cast_assignment(node)
                or is_reviewed_object_new_load(node)
            ):
                valid = False
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.value, ast.Name)
            and node.value.id in owner_names
        ):
            valid = False
        elif isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"})
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__setattr__", "__delattr__"}
            )
        ):
            owner = node.args[0] if node.args else None
            if isinstance(owner, ast.Name) and owner.id in owner_names:
                valid = False
        if (
            (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
            )
            or (
                isinstance(node, ast.Attribute)
                and node.attr in {"__setattr__", "__delattr__"}
                and not (
                    node.attr == "__setattr__"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "object"
                )
            )
            or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
            or (
                isinstance(node, ast.Call)
                and (
                    (isinstance(node.func, ast.Name) and node.func.id == "getattr")
                    or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "__getattribute__"
                    )
                )
                and len(node.args) >= 2
                and (
                    (
                        isinstance(node.args[1], ast.Constant)
                        and node.args[1].value in {"__dict__", "__setattr__", "__delattr__"}
                    )
                    or contains_type_call(node.args[0])
                )
            )
        ):
            valid = False
    if valid:
        return []
    lines = [getattr(node, "lineno", 1) for nodes in bindings.values() for node in nodes]
    return [
        Violation(
            relative_path,
            min(lines, default=1),
            f"{boundary} must preserve sole-bound AST-pinned callable owner classes",
        )
    ]


def _protected_module_binding_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    protected: frozenset[str],
    function_bindings: frozenset[str],
    function_callsites: dict[str, tuple[str, ...]],
    closed_field_loads: tuple[str, ...] | None,
) -> list[Violation]:
    """Reject alternate bindings and mutation of reviewed module constants."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    scope_nodes = (
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )

    def belongs_to_module_scope(node: ast.AST) -> bool:
        current = node
        while current in parents:
            parent = parents[current]
            if isinstance(parent, scope_nodes):
                return False
            current = parent
        return True

    def binding_owner(node: ast.AST) -> ast.AST:
        current = node
        while current in parents and not isinstance(current, ast.stmt):
            current = parents[current]
        return current

    mutable_protected = {"__all__", "_CLOSED_FIELDS"} | function_bindings
    bindings: dict[str, list[ast.AST]] = {name: [] for name in protected}
    for node in ast.walk(tree):
        is_mutable_name_binding = (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in mutable_protected
        )
        if not belongs_to_module_scope(node) and not is_mutable_name_binding:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in bindings:
                bindings[node.id].append(binding_owner(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in bindings:
                bindings[node.name].append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.partition(".")[0]
                if name in bindings:
                    bindings[name].append(node)
        elif (
            isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
            and node.name in bindings
        ):
            bindings[node.name].append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest in bindings:
            bindings[node.rest].append(node)

    valid = set(function_callsites) == function_bindings and all(
        len(nodes) == 1
        and (
            isinstance(nodes[0], (ast.FunctionDef, ast.AsyncFunctionDef)) and nodes[0].name == name
            if name in function_bindings
            else isinstance(nodes[0], ast.Assign)
            and len(nodes[0].targets) == 1
            and isinstance(nodes[0].targets[0], ast.Name)
            and nodes[0].targets[0].id == name
        )
        for name, nodes in bindings.items()
    )
    mutator_names = {
        "__delitem__",
        "__iadd__",
        "__iand__",
        "__ifloordiv__",
        "__ilshift__",
        "__imatmul__",
        "__imod__",
        "__imul__",
        "__ior__",
        "__ipow__",
        "__irshift__",
        "__setitem__",
        "__isub__",
        "__itruediv__",
        "__ixor__",
        "add",
        "append",
        "clear",
        "difference_update",
        "discard",
        "extend",
        "insert",
        "intersection_update",
        "pop",
        "remove",
        "reverse",
        "sort",
        "symmetric_difference_update",
        "update",
    }
    mutable_protected &= protected

    def enclosing_callable(node: ast.AST) -> str:
        current = node
        while current in parents:
            current = parents[current]
            if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            owner = parents.get(current)
            return (
                f"{owner.name}.{current.name}" if isinstance(owner, ast.ClassDef) else current.name
            )
        return "<module>"

    def closed_field_load_context(node: ast.Name) -> str | None:
        parent = parents.get(node)
        if isinstance(parent, ast.comprehension) and parent.iter is node:
            return f"comprehension:{enclosing_callable(node)}"
        starred = parent
        set_node = parents.get(starred) if isinstance(starred, ast.Starred) else None
        call = parents.get(set_node) if isinstance(set_node, ast.Set) else None
        assignment = parents.get(call) if isinstance(call, ast.Call) else None
        if not (
            isinstance(starred, ast.Starred)
            and starred.value is node
            and isinstance(set_node, ast.Set)
            and starred in set_node.elts
            and isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "frozenset"
            and call.args == [set_node]
            and not call.keywords
            and isinstance(assignment, ast.Assign)
            and assignment.value is call
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Name)
        ):
            return None
        return f"frozenset-assignment:{assignment.targets[0].id}"

    observed_closed_field_loads: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in mutable_protected
        ):
            parent = parents.get(node)
            if node.id == "__all__":
                valid = False
            elif node.id == "_CLOSED_FIELDS":
                context = closed_field_load_context(node)
                if context is None:
                    valid = False
                else:
                    observed_closed_field_loads.append(context)
            elif not (
                isinstance(parent, ast.Call)
                and parent.func is node
                and enclosing_callable(node) in function_callsites[node.id]
            ):
                valid = False
        elif (
            (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"globals", "locals", "vars"}
            )
            or (isinstance(node, ast.Global) and protected & set(node.names))
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in protected
                and node.func.attr in mutator_names
            )
        ):
            valid = False
        elif isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if isinstance(node.value, ast.Name) and node.value.id in protected:
                valid = False
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            if isinstance(node.value, ast.Name) and node.value.id in mutable_protected:
                valid = False
        elif (
            (
                isinstance(node, ast.Call)
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in protected
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in mutator_names
                and (
                    (isinstance(node.func, ast.Name) and node.func.id == "getattr")
                    or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "__getattribute__"
                    )
                )
            )
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in mutator_names
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in protected
            )
            or (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and type(node.slice.value) is str
                and node.slice.value in protected
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in {"globals", "locals", "vars"}
            )
        ):
            valid = False
    if closed_field_loads is not None and sorted(observed_closed_field_loads) != sorted(
        closed_field_loads
    ):
        valid = False
    if valid:
        return []
    lines = [getattr(node, "lineno", 1) for nodes in bindings.values() for node in nodes]
    return [
        Violation(
            relative_path,
            min(lines, default=1),
            f"{boundary} must preserve exact protected module bindings",
        )
    ]


def _exact_utc_suffix_replace_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
) -> list[Violation]:
    """Allow only the reviewed string suffix replacement in ``_utc_text``."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    attributes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "replace"
    ]
    dynamic_references = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id in {"getattr", "setattr", "delattr"})
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "__getattribute__")
        )
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "replace"
    ]
    valid = False
    if len(attributes) == 1 and not dynamic_references:
        attribute = attributes[0]
        call = parents.get(attribute)
        isoformat_call = attribute.value
        astimezone_call = (
            isoformat_call.func.value
            if isinstance(isoformat_call, ast.Call)
            and isinstance(isoformat_call.func, ast.Attribute)
            and isoformat_call.func.attr == "isoformat"
            else None
        )
        current: ast.AST = attribute
        while current in parents and not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            current = parents[current]
        valid = (
            isinstance(call, ast.Call)
            and call.func is attribute
            and len(call.args) == 2
            and all(isinstance(argument, ast.Constant) for argument in call.args)
            and [cast(ast.Constant, argument).value for argument in call.args] == ["+00:00", "Z"]
            and not call.keywords
            and isinstance(isoformat_call, ast.Call)
            and not isoformat_call.args
            and len(isoformat_call.keywords) == 1
            and isoformat_call.keywords[0].arg == "timespec"
            and isinstance(isoformat_call.keywords[0].value, ast.Constant)
            and isoformat_call.keywords[0].value.value == "microseconds"
            and isinstance(astimezone_call, ast.Call)
            and isinstance(astimezone_call.func, ast.Attribute)
            and astimezone_call.func.attr == "astimezone"
            and len(astimezone_call.args) == 1
            and isinstance(astimezone_call.args[0], ast.Name)
            and astimezone_call.args[0].id == "UTC"
            and not astimezone_call.keywords
            and isinstance(current, ast.FunctionDef)
            and current.name == "_utc_text"
        )
    if valid:
        return []
    lines = [node.lineno for node in (*attributes, *dynamic_references)]
    return [
        Violation(
            relative_path,
            min(lines, default=1),
            f"{boundary} must preserve its sole reviewed UTC string replace call",
        )
    ]


def _exact_evidence_property_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    closed_class_name: str,
    closed_fields: frozenset[str],
    positive_class_name: str,
    positive_properties: frozenset[str],
    positive_callable_names: frozenset[str],
) -> list[Violation]:
    """Pin closed-false descriptors and the only literal-true public facts."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    scope_nodes = (
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )

    def belongs_to_class_scope(node: ast.AST, class_node: ast.ClassDef) -> bool:
        current = node
        while current in parents:
            parent = parents[current]
            if parent is class_node:
                return True
            if isinstance(parent, scope_nodes):
                return False
            current = parent
        return False

    def binding_owner(node: ast.AST) -> ast.AST:
        current = node
        while current in parents and not isinstance(current, ast.stmt):
            current = parents[current]
        return current

    def class_bindings(class_node: ast.ClassDef) -> dict[str, list[ast.AST]]:
        bindings: dict[str, list[ast.AST]] = {}

        def add(name: str | None, owner: ast.AST) -> None:
            if name is not None:
                bindings.setdefault(name, []).append(owner)

        for node in ast.walk(class_node):
            if node is class_node or not belongs_to_class_scope(node, class_node):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                add(node.id, binding_owner(node))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                add(node.name, node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    add(alias.asname or alias.name.partition(".")[0], node)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                add(node.name, node)
            elif isinstance(node, ast.MatchMapping):
                add(node.rest, node)
        return bindings

    def is_false_property(statement: ast.AST) -> bool:
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id in {"property", "_EVIDENCE_PROPERTY"}
            and len(statement.value.args) == 1
            and not statement.value.keywords
            and isinstance(statement.value.args[0], ast.Lambda)
        ):
            return False
        function = statement.value.args[0]
        return (
            len(function.args.args) == 1
            and not function.args.posonlyargs
            and not function.args.kwonlyargs
            and not function.args.defaults
            and not function.args.kw_defaults
            and function.args.vararg is None
            and function.args.kwarg is None
            and isinstance(function.body, ast.Constant)
            and function.body.value is False
        )

    class_nodes = [node for node in getattr(tree, "body", ()) if isinstance(node, ast.ClassDef)]
    closed_classes = [node for node in class_nodes if node.name == closed_class_name]
    positive_classes = [node for node in class_nodes if node.name == positive_class_name]
    closed_class = closed_classes[0] if len(closed_classes) == 1 else None
    positive_class = positive_classes[0] if len(positive_classes) == 1 else None
    valid = closed_class is not None and positive_class is not None

    evidence_class_names = {closed_class_name, positive_class_name}
    class_name_bindings: dict[str, list[ast.AST]] = {name: [] for name in evidence_class_names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in class_name_bindings:
                class_name_bindings[node.id].append(binding_owner(node))
        elif isinstance(node, ast.arg) and node.arg in class_name_bindings:
            class_name_bindings[node.arg].append(binding_owner(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in class_name_bindings:
                class_name_bindings[node.name].append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.partition(".")[0]
                if name in class_name_bindings:
                    class_name_bindings[name].append(node)
        elif (
            isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
            and node.name in class_name_bindings
        ):
            class_name_bindings[node.name].append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest in class_name_bindings:
            class_name_bindings[node.rest].append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in evidence_class_names & set(node.names):
                class_name_bindings[name].append(node)

    valid = valid and all(
        len(class_name_bindings[name]) == 1 and class_name_bindings[name][0] is expected_class
        for name, expected_class in (
            (closed_class_name, closed_class),
            (positive_class_name, positive_class),
        )
    )

    def is_exact_dataclass_decorator(class_node: ast.ClassDef) -> bool:
        if len(class_node.decorator_list) != 1:
            return False
        decorator = class_node.decorator_list[0]
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "dataclass"
            and not decorator.args
            and all(
                keyword.arg is not None
                and isinstance(keyword.value, ast.Constant)
                and type(keyword.value.value) is bool
                for keyword in decorator.keywords
            )
        ):
            return False
        options = {
            cast(str, keyword.arg): cast(bool, cast(ast.Constant, keyword.value).value)
            for keyword in decorator.keywords
        }
        return options in (
            {"eq": False, "frozen": True, "init": False, "slots": True},
            {
                "eq": False,
                "frozen": True,
                "init": False,
                "slots": True,
                "weakref_slot": True,
            },
        )

    if closed_class is not None:
        closed_bindings = class_bindings(closed_class)
        property_assignments = [
            statement.targets[0].id
            for statement in closed_class.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id in {"property", "_EVIDENCE_PROPERTY"}
        ]
        valid = valid and (
            not closed_class.bases
            and not closed_class.keywords
            and not closed_class.decorator_list
            and frozenset(property_assignments) == closed_fields
            and len(property_assignments) == len(closed_fields)
            and all(
                len(closed_bindings.get(name, [])) == 1
                and is_false_property(closed_bindings[name][0])
                for name in closed_fields
            )
            and not ({"__getattr__", "__getattribute__"} & closed_bindings.keys())
        )

    literal_true_properties: list[str] = []
    valid_positive_properties: set[str] = set()
    if positive_class is not None:
        positive_bindings = class_bindings(positive_class)
        valid = valid and (
            len(positive_class.bases) == 1
            and isinstance(positive_class.bases[0], ast.Name)
            and positive_class.bases[0].id == closed_class_name
            and not positive_class.keywords
            and is_exact_dataclass_decorator(positive_class)
            and not (closed_fields & positive_bindings.keys())
            and not ({"__getattr__", "__getattribute__"} & positive_bindings.keys())
            and all(
                len(positive_bindings.get(name, [])) == 1
                and isinstance(positive_bindings[name][0], ast.FunctionDef)
                for name in positive_callable_names
            )
        )
        for node in positive_class.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id in {"property", "_EVIDENCE_PROPERTY"}
                    and len(value.args) == 1
                    and isinstance(value.args[0], ast.Lambda)
                    and isinstance(value.args[0].body, ast.Constant)
                    and value.args[0].body.value is True
                ):
                    literal_true_properties.append(node.targets[0].id)
                continue
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not any(
                isinstance(decorator, ast.Name)
                and decorator.id in {"property", "_EVIDENCE_PROPERTY"}
                for decorator in node.decorator_list
            ):
                continue
            returns_literal_true = any(
                isinstance(candidate, ast.Return)
                and isinstance(candidate.value, ast.Constant)
                and candidate.value.value is True
                for candidate in ast.walk(node)
            )
            if returns_literal_true:
                literal_true_properties.append(node.name)
            if node.name not in positive_properties:
                continue
            valid_getter = (
                len(positive_bindings.get(node.name, [])) == 1
                and len(node.decorator_list) == 1
                and isinstance(node.decorator_list[0], ast.Name)
                and node.decorator_list[0].id in {"property", "_EVIDENCE_PROPERTY"}
                and not node.args.posonlyargs
                and len(node.args.args) == 1
                and node.args.args[0].arg == "self"
                and node.args.vararg is None
                and not node.args.kwonlyargs
                and node.args.kwarg is None
                and not node.args.defaults
                and not node.args.kw_defaults
                and len(node.body) == 2
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Call)
                and isinstance(node.body[0].value.func, ast.Attribute)
                and isinstance(node.body[0].value.func.value, ast.Name)
                and node.body[0].value.func.value.id == "self"
                and node.body[0].value.func.attr == "__post_init__"
                and not node.body[0].value.args
                and not node.body[0].value.keywords
                and isinstance(node.body[1], ast.Return)
                and isinstance(node.body[1].value, ast.Constant)
                and node.body[1].value.value is True
            )
            if valid_getter:
                valid_positive_properties.add(node.name)
    valid = valid and (
        frozenset(literal_true_properties) == positive_properties
        and len(literal_true_properties) == len(positive_properties)
        and valid_positive_properties == positive_properties
    )

    annotation_roots = {
        annotation
        for node in ast.walk(tree)
        for annotation in (
            (node.annotation,)
            if isinstance(node, (ast.arg, ast.AnnAssign)) and node.annotation is not None
            else (node.returns,)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.returns is not None
            else ()
        )
    }

    def is_within_annotation(node: ast.AST) -> bool:
        current = node
        while True:
            if current in annotation_roots:
                return True
            if current not in parents:
                return False
            current = parents[current]

    def is_exact_type_identity_check(node: ast.Name) -> bool:
        comparison = parents.get(node)
        return (
            isinstance(comparison, ast.Compare)
            and node in comparison.comparators
            and all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in comparison.ops)
            and isinstance(comparison.left, ast.Call)
            and isinstance(comparison.left.func, ast.Name)
            and comparison.left.func.id == "type"
            and len(comparison.left.args) == 1
            and not comparison.left.keywords
        )

    def is_reviewed_object_new_load(node: ast.Name) -> bool:
        statement = binding_owner(node)
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "candidate"
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == "cast"
            and len(statement.value.args) == 2
            and not statement.value.keywords
            and isinstance(statement.value.args[0], ast.Name)
            and statement.value.args[0].id == positive_class_name
        ):
            return False
        outer_cast = statement.value
        new_call = outer_cast.args[1]
        if not (
            isinstance(new_call, ast.Call)
            and isinstance(new_call.func, ast.Attribute)
            and isinstance(new_call.func.value, ast.Name)
            and new_call.func.value.id == "object"
            and new_call.func.attr == "__new__"
            and len(new_call.args) == 1
            and not new_call.keywords
        ):
            return False
        inner_cast = new_call.args[0]
        return (
            isinstance(inner_cast, ast.Call)
            and isinstance(inner_cast.func, ast.Name)
            and inner_cast.func.id == "cast"
            and len(inner_cast.args) == 2
            and not inner_cast.keywords
            and isinstance(inner_cast.args[1], ast.Name)
            and inner_cast.args[1].id == positive_class_name
            and node in {outer_cast.args[0], inner_cast.args[1]}
        )

    def is_allowed_evidence_class_load(node: ast.Name) -> bool:
        parent = parents.get(node)
        return (
            is_within_annotation(node)
            or (isinstance(parent, ast.ClassDef) and any(base is node for base in parent.bases))
            or (
                node.id == positive_class_name
                and isinstance(parent, ast.Call)
                and parent.func is node
            )
            or (node.id == positive_class_name and is_exact_type_identity_check(node))
            or (node.id == positive_class_name and is_reviewed_object_new_load(node))
        )

    protected_names = (
        closed_fields
        | positive_properties
        | positive_callable_names
        | evidence_class_names
        | {"__getattr__", "__getattribute__"}
    )
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in evidence_class_names
            and not is_allowed_evidence_class_load(node)
        ) or (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and (
                node.attr in protected_names
                or (isinstance(node.value, ast.Name) and node.value.id in evidence_class_names)
            )
        ):
            valid = False
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            assigned_value = node.value
            if isinstance(assigned_value, ast.Name) and assigned_value.id in evidence_class_names:
                valid = False
        elif isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"})
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__setattr__", "__delattr__"}
            )
        ):
            owner = node.args[0] if node.args else None
            field = node.args[1] if len(node.args) >= 2 else None
            if (isinstance(owner, ast.Name) and owner.id in evidence_class_names) or (
                isinstance(field, ast.Constant)
                and type(field.value) is str
                and field.value in protected_names
            ):
                valid = False
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in evidence_class_names
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"globals", "locals", "vars"}
        ) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id in {"globals", "locals", "vars"}
            and node.func.attr
            in {
                "__delitem__",
                "__setitem__",
                "clear",
                "pop",
                "popitem",
                "setdefault",
                "update",
            }
        ):
            valid = False
    if valid:
        return []
    line = (
        closed_class.lineno
        if closed_class is not None
        else positive_class.lineno
        if positive_class is not None
        else 1
    )
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} must preserve exact closed-false and positive-true properties",
        )
    ]


def _exact_enum_member_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, dict[str, str]],
) -> list[Violation]:
    """Pin each reviewed lifecycle enum to exact string-valued members."""

    violations: list[Violation] = []
    for class_name, expected_members in expected.items():
        classes = [
            node
            for node in getattr(tree, "body", ())
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        observed: dict[str, str] | None = None
        if len(classes) == 1:
            observed = {}
            for node in classes[0].body:
                if not (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant)
                    and type(node.value.value) is str
                ):
                    continue
                observed[node.targets[0].id] = node.value.value
        if observed == expected_members and len(observed) == len(expected_members):
            continue
        violations.append(
            Violation(
                relative_path,
                classes[0].lineno if classes else 1,
                f"{boundary} must preserve exact enum members for '{class_name}'",
            )
        )
    return violations


def _top_level_bound_names(tree: ast.AST) -> frozenset[str]:
    """Return names defined or assigned directly in one module."""

    def target_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.List, ast.Tuple)):
            return set().union(*(target_names(item) for item in target.elts))
        return set()

    names: set[str] = set()
    for node in getattr(tree, "body", ()):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(target_names(target))
        elif isinstance(node, ast.AnnAssign):
            names.update(target_names(node.target))
    return frozenset(names)


def _private_symbol_presence_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: frozenset[str],
) -> list[Violation]:
    """Ensure the private-seam denylist cannot silently retain stale names."""

    observed = _top_level_bound_names(tree)
    return [
        Violation(
            relative_path,
            1,
            f"{boundary} must define reviewed private seam '{name}'",
        )
        for name in sorted(expected - observed)
    ]


def _reviewed_filesystem_call_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden_unqualified: frozenset[str],
    forbidden_methods: frozenset[str],
    allowed_qualified: frozenset[str],
) -> list[Violation]:
    """Reject builtin and object filesystem calls outside reviewed ``os`` APIs."""

    bindings = _imported_symbol_bindings(tree)
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_symbol(node.func, bindings)
        forbidden = (isinstance(node.func, ast.Name) and node.func.id in forbidden_unqualified) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in forbidden_methods
            and qualified not in allowed_qualified
        )
        if not forbidden:
            continue
        violations.append(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot call unreviewed filesystem capability '{qualified}'",
            )
        )
    return violations


def _exact_private_callsite_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, tuple[str, ...]],
) -> list[Violation]:
    """Pin private writer/registry callables to exact direct internal callsites."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def callsite(node: ast.Call) -> str:
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            owner = parents.get(current)
            if isinstance(owner, ast.ClassDef):
                return f"{owner.name}.{current.name}"
            return current.name
        return "<module>"

    violations: list[Violation] = []
    for binding, expected_callsites in expected.items():
        literal_references = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and type(node.value) is str and node.value == binding
        ]
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == binding
        ]
        observed = tuple(sorted(callsite(node) for node in calls))
        if observed != tuple(sorted(expected_callsites)):
            violations.append(
                Violation(
                    relative_path,
                    calls[0].lineno if calls else 1,
                    f"{boundary} must preserve exact private callsites for '{binding}'",
                )
            )
        violations.extend(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot dynamically reference private callable '{binding}'",
            )
            for node in literal_references
        )
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Name) and node.id == binding and isinstance(node.ctx, ast.Load)
            ):
                continue
            parent = parents.get(node)
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot alias or re-export private callable '{binding}'",
                )
            )
    return violations


def _exact_private_attribute_callsite_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected: dict[str, tuple[str, ...]],
    owner_function_ast_sha256: dict[str, str],
) -> list[Violation]:
    """Pin proof-minting class attributes to exact direct production calls."""

    if relative_path == Path("scripts/check_architecture.py"):
        return []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    bindings = _imported_symbol_bindings(tree)
    nodes = tuple(ast.walk(tree))
    relative_name = relative_path.as_posix()
    module_name = relative_path.with_suffix("").as_posix().replace("/", ".")
    top_level_functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            top_level_functions.setdefault(node.name, []).append(node)

    def enclosing_callable(node: ast.AST) -> ast.AST | None:
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return current
        return None

    def callsite(node: ast.Call) -> str:
        owner = enclosing_callable(node)
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parent = parents.get(owner)
            return f"{parent.name}.{owner.name}" if isinstance(parent, ast.ClassDef) else owner.name
        return "<module>"

    annotation_roots = {
        annotation
        for node in nodes
        for annotation in (
            (node.annotation,)
            if isinstance(node, (ast.arg, ast.AnnAssign)) and node.annotation is not None
            else (node.returns,)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.returns is not None
            else ()
        )
    }

    def is_within_annotation(node: ast.AST) -> bool:
        current = node
        while True:
            if current in annotation_roots:
                return True
            if current not in parents:
                return False
            current = parents[current]

    def is_exact_type_identity_check(node: ast.AST) -> bool:
        comparison = parents.get(node)
        return (
            isinstance(comparison, ast.Compare)
            and node in comparison.comparators
            and all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in comparison.ops)
            and isinstance(comparison.left, ast.Call)
            and isinstance(comparison.left.func, ast.Name)
            and comparison.left.func.id == "type"
            and len(comparison.left.args) == 1
            and not comparison.left.keywords
        )

    violations: list[Violation] = []
    expected_functions_here = {
        configured.rpartition(":")[2]
        for callsites in expected.values()
        for configured in callsites
        if configured.rpartition(":")[0] == relative_name and configured.rpartition(":")[1]
    }
    for function_name in expected_functions_here:
        functions = top_level_functions.get(function_name, [])
        configured_key = f"{relative_name}:{function_name}"
        expected_digest = owner_function_ast_sha256.get(configured_key, "")
        if (
            len(functions) != 1
            or not expected_digest
            or _canonical_ast_sha256(functions[0]) != expected_digest
        ):
            violations.append(
                Violation(
                    relative_path,
                    functions[0].lineno if functions else 1,
                    f"{boundary} must preserve exact owner-function AST for '{configured_key}'",
                )
            )

    for qualified_binding, expected_callsites in expected.items():
        owner_binding, separator, attribute_name = qualified_binding.rpartition(".")
        owner_module, owner_separator, owner_name = owner_binding.rpartition(".")
        if not separator or not owner_name or not attribute_name:
            violations.append(
                Violation(
                    relative_path,
                    1,
                    f"{boundary} has an invalid private attribute binding '{qualified_binding}'",
                )
            )
            continue
        expected_here = tuple(
            callsite_name
            for configured in expected_callsites
            for configured_path, found, callsite_name in (configured.rpartition(":"),)
            if found and configured_path == relative_name
        )
        if expected_here:
            direct_import_aliases = {
                alias
                for node in getattr(tree, "body", ())
                if isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module == owner_module
                for alias in node.names
                if alias.name == owner_name and alias.asname is None
            }
            import_bindings = [
                alias
                for node in nodes
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
                if (alias.asname or alias.name.partition(".")[0]) == owner_name
            ]
            rebound = any(
                (
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.id == owner_name
                )
                or (isinstance(node, ast.arg) and node.arg == owner_name)
                or (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and node.name == owner_name
                )
                or (
                    isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                    and node.name == owner_name
                )
                or (isinstance(node, ast.MatchMapping) and node.rest == owner_name)
                or (isinstance(node, (ast.Global, ast.Nonlocal)) and owner_name in node.names)
                for node in nodes
            )
            if (
                not owner_separator
                or len(direct_import_aliases) != 1
                or set(import_bindings) != direct_import_aliases
                or rebound
            ):
                violations.append(
                    Violation(
                        relative_path,
                        1,
                        f"{boundary} must preserve the sole direct owner import '{owner_binding}'",
                    )
                )

        if module_name != owner_module:
            for node in nodes:
                is_owner_reference = (
                    isinstance(node, (ast.Name, ast.Attribute))
                    and isinstance(node.ctx, ast.Load)
                    and _qualified_symbol(node, bindings) == owner_binding
                )
                if not is_owner_reference:
                    continue
                parent = parents.get(node)
                direct_private_owner = (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr == attribute_name
                )
                if (
                    is_within_annotation(node)
                    or direct_private_owner
                    or is_exact_type_identity_check(node)
                ):
                    continue
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} cannot alias or reflect private owner '{owner_binding}'",
                    )
                )

        violations.extend(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot dynamically name private attribute '{attribute_name}'",
            )
            for node in nodes
            if isinstance(node, ast.Constant)
            and type(node.value) is str
            and node.value == attribute_name
        )
        references = [
            node
            for node in nodes
            if isinstance(node, ast.Attribute) and node.attr == attribute_name
        ]
        calls: list[ast.Call] = []
        for node in references:
            parent = parents.get(node)
            owner_is_local = (
                module_name == owner_module
                and isinstance(node.value, ast.Name)
                and node.value.id == owner_name
                and owner_name not in bindings
            )
            direct_owner = (
                isinstance(node.value, ast.Name)
                and node.value.id == owner_name
                and (bindings.get(owner_name) == owner_binding or owner_is_local)
            )
            if isinstance(parent, ast.Call) and parent.func is node and direct_owner:
                calls.append(parent)
                call_owner = enclosing_callable(parent)
                if not any(
                    len(top_level_functions.get(expected_name, [])) == 1
                    and call_owner is top_level_functions[expected_name][0]
                    for expected_name in expected_here
                ):
                    violations.append(
                        Violation(
                            relative_path,
                            node.lineno,
                            f"{boundary} private attribute call must belong to its exact "
                            "top-level owner function",
                        )
                    )
                continue
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot alias, re-export, or indirectly call "
                    f"private attribute '{qualified_binding}'",
                )
            )
        observed_here = tuple(sorted(callsite(node) for node in calls))
        if observed_here != tuple(sorted(expected_here)):
            violations.append(
                Violation(
                    relative_path,
                    calls[0].lineno if calls else 1,
                    f"{boundary} must preserve exact private attribute callsites for "
                    f"'{qualified_binding}'",
                )
            )
    return violations


def _resolved_import_from_module(node: ast.ImportFrom, relative_path: Path) -> str:
    """Resolve one import-from module without importing repository code."""

    if node.level == 0:
        return node.module or ""
    package_parts = list(relative_path.with_suffix("").parts[:-1])
    retained = len(package_parts) - (node.level - 1)
    if retained < 0:
        return ""
    suffix = (node.module or "").split(".") if node.module else []
    return ".".join([*package_parts[:retained], *suffix])


def _isolated_origin_module_import_bindings(
    tree: ast.AST,
    *,
    relative_path: Path,
    module: str,
) -> list[tuple[int, str]]:
    """Find direct, relative, descendant, and parent-namespace access to a module."""

    bindings: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported = alias.name
                if (
                    imported == module
                    or imported.startswith(f"{module}.")
                    or module.startswith(f"{imported}.")
                ):
                    bindings.append((node.lineno, f"{module}:*"))
        elif isinstance(node, ast.ImportFrom):
            imported_from = _resolved_import_from_module(node, relative_path)
            if imported_from == module:
                bindings.extend((node.lineno, f"{module}:{alias.name}") for alias in node.names)
                continue
            if imported_from.startswith(f"{module}."):
                bindings.append((node.lineno, f"{module}:*"))
                continue
            for alias in node.names:
                imported = (
                    imported_from
                    if alias.name == "*"
                    else f"{imported_from}.{alias.name}"
                    if imported_from
                    else alias.name
                )
                if imported == module or module.startswith(f"{imported}."):
                    bindings.append((node.lineno, f"{module}:*"))
    return bindings


def _phase3h_proof_boundary_violations(
    tree: ast.AST,
    *,
    policy_enabled: bool,
    relative_path: Path,
    proof_module: str,
    proof_path: Path,
    execution_module: str,
    execution_path: Path,
    allowed_proof_imports: frozenset[str],
    module_ast_sha256: dict[Path, str],
    dynamic_code_exception_module_ast_sha256: dict[Path, str],
) -> list[Violation]:
    """Keep Phase 3H proof construction inside two exact reviewed modules."""

    if not policy_enabled:
        return []
    boundary = "Phase 3H isolated economic-proof boundary"
    checker_path = Path("scripts/check_architecture.py")
    protected_paths = {proof_path, execution_path}
    expected_imports = allowed_proof_imports if relative_path == execution_path else frozenset()
    proof_imports = _isolated_origin_module_import_bindings(
        tree,
        relative_path=relative_path,
        module=proof_module,
    )
    execution_imports = _isolated_origin_module_import_bindings(
        tree,
        relative_path=relative_path,
        module=execution_module,
    )
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed binding '{binding}'",
        )
        for line, binding in proof_imports
        if binding not in expected_imports
    ]
    observed_imports = frozenset(binding for _, binding in proof_imports)
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed binding '{binding}'",
        )
        for binding in sorted(expected_imports - observed_imports)
    )
    violations.extend(
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import or reexport execution module '{execution_module}'",
        )
        for line, _binding in execution_imports
    )

    expected_digest = module_ast_sha256.get(relative_path)
    if relative_path in protected_paths and (
        expected_digest is None or _canonical_ast_sha256(tree) != expected_digest
    ):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve its exact reviewed module AST",
            )
        )

    dynamic_code_exception_digest = dynamic_code_exception_module_ast_sha256.get(relative_path)
    if dynamic_code_exception_digest is not None:
        if _canonical_ast_sha256(tree) != dynamic_code_exception_digest:
            violations.append(
                Violation(
                    relative_path,
                    1,
                    f"{boundary} dynamic-code exception must preserve its exact module AST",
                )
            )
        else:
            return violations

    if relative_path in protected_paths or relative_path == checker_path:
        return violations

    reserved_names = frozenset(
        {
            "FixtureEconomicProcessEvidence",
            "FixtureEconomicSegmentReceipt",
            "_FIXTURE_ECONOMIC_PROCESS_FACTORY_PROOF",
            "_FIXTURE_ECONOMIC_RECEIPT_FACTORY_PROOF",
            "_from_supervisor",
            "_from_verified_execution",
            "_process_factory_proof",
            "_receipt_factory_proof",
            "execute_fixture_segment_economics",
        }
    )
    dynamic_loader_names = frozenset(
        {
            "__import__",
            "compile_command",
            "exec_module",
            "find_spec",
            "get_loader",
            "import_module",
            "load_module",
            "locate",
            "module_from_spec",
            "resolve_name",
            "run_module",
            "run_path",
            "runcode",
        }
    )
    dangerous_import_roots = frozenset(
        {
            "_frozen_importlib",
            "_frozen_importlib_external",
            "cloudpickle",
            "code",
            "codeop",
            "copyreg",
            "dill",
            "gc",
            "imp",
            "importlib",
            "inspect",
            "joblib",
            "marshal",
            "mock",
            "operator",
            "pickle",
            "pydoc",
            "pkgutil",
            "runpy",
            "shelve",
            "unittest",
            "zipimport",
        }
    )
    dynamic_code_names = frozenset({"compile", "eval", "exec"})
    reserved_text = reserved_names | dynamic_loader_names | {proof_module, execution_module}
    reserved_fragments = reserved_names | {
        proof_module,
        execution_module,
        proof_path.as_posix(),
        execution_path.as_posix(),
    }
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    builtins_names = {"__builtins__"}
    builtins_names.update(
        alias.asname or "builtins"
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "builtins"
    )

    def is_builtins_namespace(node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in builtins_names

    def reflected_builtin_dynamic_code(node: ast.AST) -> str | None:
        if isinstance(node, ast.Attribute):
            return node.attr if is_builtins_namespace(node.value) else None
        if isinstance(node, ast.Call) and len(node.args) >= 2:
            direct_getattr = isinstance(node.func, ast.Name) and node.func.id == "getattr"
            builtin_getattr = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "getattr"
                and is_builtins_namespace(node.func.value)
            )
            if (direct_getattr or builtin_getattr) and is_builtins_namespace(node.args[0]):
                return _constant_folded_text(node.args[1])
        if isinstance(node, ast.Subscript):
            namespace = node.value
            if isinstance(namespace, ast.Attribute) and namespace.attr == "__dict__":
                namespace = namespace.value
            if is_builtins_namespace(namespace):
                return _constant_folded_text(node.slice)
        return None

    for node in ast.walk(tree):
        dangerous_import: str | None = None
        if isinstance(node, ast.Import):
            dangerous_import = next(
                (
                    alias.name.partition(".")[0]
                    for alias in node.names
                    if alias.name.partition(".")[0] in dangerous_import_roots
                ),
                None,
            )
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            root = node.module.partition(".")[0]
            dangerous_import = root if root in dangerous_import_roots else None
        if dangerous_import is not None:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} forbids dynamic-code import root '{dangerous_import}'",
                )
            )
            continue

        dynamic_code: str | None = None
        if isinstance(node, ast.Name) and node.id in dynamic_code_names:
            dynamic_code = node.id
        elif reflected_builtin_dynamic_code(node) in dynamic_code_names:
            dynamic_code = reflected_builtin_dynamic_code(node)
        elif isinstance(node, ast.alias):
            origin = node.name.rpartition(".")[2]
            local = node.asname or origin
            if origin in dynamic_code_names or local in dynamic_code_names:
                dynamic_code = origin
        if dynamic_code is not None:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} forbids dynamic code capability '{dynamic_code}'",
                )
            )
            continue

        dynamic_loader: str | None = None
        if isinstance(node, ast.Name) and node.id in dynamic_loader_names:
            dynamic_loader = node.id
        elif isinstance(node, ast.Attribute) and node.attr in dynamic_loader_names:
            dynamic_loader = node.attr
        elif isinstance(node, ast.alias):
            origin = node.name.rpartition(".")[2]
            local = node.asname or origin
            if origin in dynamic_loader_names or local in dynamic_loader_names:
                dynamic_loader = origin
        if dynamic_loader is not None:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} forbids dynamic production loader '{dynamic_loader}'",
                )
            )
            continue
        symbol: str | None = None
        if isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = node.name
        elif isinstance(node, ast.arg):
            symbol = node.arg
        elif isinstance(node, ast.alias):
            local = node.asname or node.name.rpartition(".")[2]
            if local in reserved_names:
                symbol = local
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            symbol = node.name
        elif isinstance(node, ast.MatchMapping):
            symbol = node.rest
        if symbol in reserved_names:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} reserves proof symbol '{symbol}'",
                )
            )
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            value = node.value.encode("utf-8") if isinstance(node.value, str) else node.value
            reflected_fragment = next(
                (fragment for fragment in reserved_fragments if fragment.encode("utf-8") in value),
                None,
            )
            if reflected_fragment is not None:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        f"{boundary} reserves embedded proof name '{reflected_fragment}'",
                    )
                )
        folded = _constant_folded_text(node)
        if folded not in reserved_text:
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.AST) and _constant_folded_text(parent) == folded:
            continue
        violations.append(
            Violation(
                relative_path,
                getattr(node, "lineno", 1),
                f"{boundary} reserves reflected proof name '{folded}'",
            )
        )
    return violations


def _isolated_wave5_module_boundary_violations(
    tree: ast.AST,
    *,
    boundary: str,
    policy_enabled: bool,
    relative_path: Path,
    module_paths: dict[str, Path],
    allowed_imports: dict[Path, frozenset[str]],
    module_ast_sha256: dict[Path, str],
    reserved_symbols: frozenset[str],
) -> list[Violation]:
    """Seal exact Wave 5 modules and their reviewed production import graph."""

    if not policy_enabled:
        return []
    checker_path = Path("scripts/check_architecture.py")
    protected_paths = frozenset(module_paths.values())
    observed_imports = frozenset(
        binding
        for module in module_paths
        for _line, binding in _isolated_origin_module_import_bindings(
            tree,
            relative_path=relative_path,
            module=module,
        )
    )
    expected_imports = allowed_imports.get(relative_path, frozenset())
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unreviewed binding '{binding}'",
        )
        for module in module_paths
        for line, binding in _isolated_origin_module_import_bindings(
            tree,
            relative_path=relative_path,
            module=module,
        )
        if binding not in expected_imports
    ]
    violations.extend(
        Violation(
            relative_path,
            1,
            f"{boundary} must preserve reviewed binding '{binding}'",
        )
        for binding in sorted(expected_imports - observed_imports)
    )

    expected_digest = module_ast_sha256.get(relative_path)
    if relative_path in protected_paths and (
        expected_digest is None or _canonical_ast_sha256(tree) != expected_digest
    ):
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve its exact reviewed module AST",
            )
        )
    if relative_path in protected_paths or relative_path == checker_path:
        return violations

    reserved_text = reserved_symbols | frozenset(module_paths)
    reserved_fragments = reserved_text | frozenset(path.as_posix() for path in protected_paths)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        symbol: str | None = None
        if isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = node.name
        elif isinstance(node, ast.arg):
            symbol = node.arg
        elif isinstance(node, ast.alias):
            local = node.asname or node.name.rpartition(".")[2]
            if local in reserved_symbols:
                symbol = local
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            symbol = node.name
        elif isinstance(node, ast.MatchMapping):
            symbol = node.rest
        if symbol in reserved_symbols:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} reserves private symbol '{symbol}'",
                )
            )
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            value = node.value.encode("utf-8") if isinstance(node.value, str) else node.value
            reflected_fragment = next(
                (fragment for fragment in reserved_fragments if fragment.encode("utf-8") in value),
                None,
            )
            if reflected_fragment is not None:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        f"{boundary} reserves embedded private name '{reflected_fragment}'",
                    )
                )
        folded = _constant_folded_text(node)
        if folded not in reserved_text:
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.AST) and _constant_folded_text(parent) == folded:
            continue
        violations.append(
            Violation(
                relative_path,
                getattr(node, "lineno", 1),
                f"{boundary} reserves reflected private name '{folded}'",
            )
        )
    return violations


def _exact_self_owned_attribute_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    class_name: str,
    owner_attribute: str,
    allowed: frozenset[str],
) -> list[Violation]:
    """Constrain capabilities reached through one ``self``-owned object."""

    classes = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(classes) != 1:
        return []
    references: list[tuple[int, str]] = []
    for node in ast.walk(classes[0]):
        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and node.value.attr == owner_attribute
        ):
            continue
        references.append((node.lineno, node.attr))
    violations = [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot reach unreviewed capability 'self.{owner_attribute}.{attribute}'",
        )
        for line, attribute in references
        if attribute not in allowed
    ]
    observed = frozenset(attribute for _, attribute in references)
    violations.extend(
        Violation(
            relative_path,
            classes[0].lineno,
            f"{boundary} must preserve reviewed capability 'self.{owner_attribute}.{attribute}'",
        )
        for attribute in sorted(allowed - observed)
    )
    return violations


def _forbidden_project_module_import_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden_module: str,
) -> list[Violation]:
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot import unconnected module '{forbidden_module}'",
        )
        for line, module in _project_import_modules(tree)
        if module == forbidden_module
    ]


def _forbidden_module_private_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    module: str,
    forbidden: frozenset[str],
) -> list[Violation]:
    """Reject direct, aliased, module-attribute, and re-export seam access."""

    references: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            references.update(
                (node.lineno, alias.name) for alias in node.names if alias.name in forbidden
            )
    prefix = f"{module}."
    for line, qualified in _qualified_symbol_references(tree):
        if not qualified.startswith(prefix):
            continue
        symbol = qualified.removeprefix(prefix)
        if symbol in forbidden:
            references.add((line, symbol))
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot reference private seam '{module}.{symbol}'",
        )
        for line, symbol in sorted(references)
    ]


def _forbidden_seam_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden: frozenset[str],
) -> list[Violation]:
    """Reject direct, aliased, re-exported, attribute, and getattr seam use."""

    references: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        symbol: str | None = None
        if isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            references.update(
                (node.lineno, alias.name.rpartition(".")[2])
                for alias in node.names
                if alias.name.rpartition(".")[2] in forbidden
            )
        elif (
            isinstance(node, ast.Call)
            and (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"getattr", "setattr", "delattr"}
                )
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "__getattribute__")
            )
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
        ):
            symbol = node.args[1].value
        if symbol in forbidden:
            references.add((getattr(node, "lineno", 1), symbol))
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot reference reviewed seam '{symbol}'",
        )
        for line, symbol in sorted(references)
    ]


def _forbidden_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden: frozenset[str],
) -> list[Violation]:
    violations: list[Violation] = []
    for node in ast.walk(tree):
        symbol = None
        if isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
        elif (
            isinstance(node, ast.Call)
            and (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"getattr", "setattr", "delattr"}
                )
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "__getattribute__")
            )
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
        ):
            symbol = node.args[1].value
        if symbol in forbidden:
            violations.append(
                Violation(
                    relative_path,
                    getattr(node, "lineno", 1),
                    f"{boundary} cannot reference effect API '{symbol}'",
                )
            )
    return violations


def _forbidden_qualified_call_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden: frozenset[str],
    allowed_isinstance_callsites: dict[str, tuple[str, ...]],
) -> list[Violation]:
    """Permit forbidden callables only as reviewed annotations/type checks."""

    bindings = _imported_symbol_bindings(tree)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    annotation_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        annotations: list[ast.AST] = []
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns is not None:
                annotations.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
        for annotation in annotations:
            annotation_nodes.update(ast.walk(annotation))

    def callsite(node: ast.AST) -> str:
        current = node
        while current in parents:
            current = parents[current]
            if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            owner = parents.get(current)
            if isinstance(owner, ast.ClassDef):
                return f"{owner.name}.{current.name}"
            return current.name
        return "<module>"

    observed_isinstance_callsites: dict[str, list[str]] = {qualified: [] for qualified in forbidden}
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        qualified = _qualified_symbol(node, bindings)
        if qualified not in forbidden:
            continue
        if node in annotation_nodes:
            continue
        parent = parents.get(node)
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "isinstance"
            and len(parent.args) == 2
            and parent.args[1] is node
            and not parent.keywords
            and callsite(parent) in allowed_isinstance_callsites.get(qualified, ())
        ):
            observed_isinstance_callsites[qualified].append(callsite(parent))
            continue
        violations.append(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot reference effect callable '{qualified}'",
            )
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        for alias in node.names:
            qualified = f"{node.module}.{alias.name}"
            if qualified in forbidden:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} cannot import effect callable '{qualified}'",
                    )
                )

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
            and (
                (isinstance(node.func, ast.Name) and node.func.id == "getattr")
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "__getattribute__")
            )
        ):
            continue
        owner = _qualified_symbol(node.args[0], bindings)
        qualified = f"{owner}.{node.args[1].value}" if owner is not None else None
        if qualified in forbidden:
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot dynamically reference effect callable '{qualified}'",
                )
            )

    for qualified in forbidden:
        observed = tuple(sorted(observed_isinstance_callsites[qualified]))
        expected = tuple(sorted(allowed_isinstance_callsites.get(qualified, ())))
        if observed == expected:
            continue
        violations.append(
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve exact isinstance callsites for '{qualified}'",
            )
        )
    return violations


def _imported_symbol_bindings(tree: ast.AST) -> dict[str, str]:
    """Map locally bound import names to their exact qualified symbols."""

    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.partition(".")[0]
                bindings[local_name] = alias.name if alias.asname else local_name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bindings


def _qualified_symbol(node: ast.AST, bindings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_symbol(node.value, bindings)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _qualified_symbol_references(tree: ast.AST) -> list[tuple[int, str]]:
    """Return exact references, including import aliases and literal getattr."""

    bindings = _imported_symbol_bindings(tree)
    references: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        symbol: str | None = None
        if isinstance(node, ast.Attribute):
            symbol = _qualified_symbol(node, bindings)
        elif isinstance(node, ast.Name):
            symbol = bindings.get(node.id, node.id)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
        ):
            owner = _qualified_symbol(node.args[0], bindings)
            if owner:
                symbol = f"{owner}.{node.args[1].value}"
        if symbol is not None:
            references.append((getattr(node, "lineno", 1), symbol))
    return references


def _forbidden_qualified_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    forbidden: frozenset[str],
) -> list[Violation]:
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot reference process/control API '{symbol}'",
        )
        for line, symbol in _qualified_symbol_references(tree)
        if symbol in forbidden
    ]


def _unreviewed_namespace_symbol_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    namespace: str,
    allowed: frozenset[str],
    kind: str = "FFI API",
) -> list[Violation]:
    prefix = f"{namespace}."
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} cannot reference unreviewed {kind} '{symbol}'",
        )
        for line, symbol in _qualified_symbol_references(tree)
        if symbol.startswith(prefix) and symbol not in allowed
    ]


def _namespace_alias_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    namespace: str,
) -> list[Violation]:
    """Reject passing or aliasing a capability-bearing imported namespace."""

    bindings = _imported_symbol_bindings(tree)
    local_names = frozenset(
        local_name for local_name, symbol in bindings.items() if symbol == namespace
    )
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name) and node.id in local_names and isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "getattr"
            and len(parent.args) >= 2
            and parent.args[0] is node
            and isinstance(parent.args[1], ast.Constant)
            and type(parent.args[1].value) is str
        ):
            continue
        violations.append(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot alias imported namespace '{namespace}'",
            )
        )
    return violations


def _dynamic_attribute_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: frozenset[str],
) -> list[Violation]:
    """Reject dynamic attribute dispatch except exact reviewed literal reads."""

    bindings = _imported_symbol_bindings(tree)
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "setattr", "delattr"}
        ):
            continue
        qualified: str | None = None
        if (
            node.func.id == "getattr"
            and len(node.args) in {2, 3}
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
        ):
            owner = _qualified_symbol(node.args[0], bindings)
            if owner is not None:
                qualified = f"{owner}.{node.args[1].value}"
        if qualified not in allowed:
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot use unreviewed dynamic attribute dispatch",
                )
            )
    return violations


def _ffi_library_binding_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    factory: str,
    binding: str,
) -> list[Violation]:
    """Require one exact errno-aware CDLL binding and no aliasable factory use."""

    factory_references = [
        (line, symbol) for line, symbol in _qualified_symbol_references(tree) if symbol == factory
    ]
    exact_assignments = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        value = node.value
        if (
            isinstance(target, ast.Name)
            and target.id == binding
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and f"{value.func.value.id}.{value.func.attr}" == factory
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value is None
            and len(value.keywords) == 1
            and value.keywords[0].arg == "use_errno"
            and isinstance(value.keywords[0].value, ast.Constant)
            and value.keywords[0].value.value is True
        ):
            exact_assignments += 1
    violations: list[Violation] = []
    if len(factory_references) != 1 or exact_assignments != 1:
        line = factory_references[0][0] if factory_references else 1
        violations.append(
            Violation(
                relative_path,
                line,
                f"{boundary} must preserve exact FFI library binding "
                f"'{binding} = {factory}(None, use_errno=True)'",
            )
        )

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name) and node.id == binding and isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue
        violations.append(
            Violation(
                relative_path,
                node.lineno,
                f"{boundary} cannot alias FFI library binding '{binding}'",
            )
        )
    return violations


def _exact_dunder_all_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    allowed: tuple[str, ...],
) -> list[Violation]:
    """Require one exact, duplicate-free literal ``__all__`` sequence."""

    assignments = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "__all__"
    ]
    observed: tuple[str, ...] | None = None
    if len(assignments) == 1 and isinstance(assignments[0].value, (ast.List, ast.Tuple)):
        values = assignments[0].value.elts
        if all(isinstance(value, ast.Constant) and type(value.value) is str for value in values):
            observed = tuple(cast(str, cast(ast.Constant, value).value) for value in values)
    if observed == allowed and len(observed) == len(set(observed)):
        return []
    line = assignments[0].lineno if assignments else 1
    return [
        Violation(
            relative_path,
            line,
            f"{boundary} must preserve its exact reviewed public __all__ surface",
        )
    ]


def _exact_ffi_function_binding_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    bindings: dict[str, str],
) -> list[Violation]:
    """Pin exact libc function bindings, signatures, and direct invocation."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    violations: list[Violation] = []
    reviewed_targets = frozenset(bindings)
    for local_name, qualified_source in bindings.items():
        source_owner, _, source_attribute = qualified_source.partition(".")
        binding_assignments = [
            node
            for node in assignments
            if len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == local_name
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == source_owner
            and node.value.attr == source_attribute
        ]
        signature_assignments = {
            attribute: [
                node
                for node in assignments
                if len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id == local_name
                and node.targets[0].attr == attribute
            ]
            for attribute in ("argtypes", "restype")
        }
        direct_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == local_name
        ]
        if (
            len(binding_assignments) != 1
            or any(len(items) != 1 for items in signature_assignments.values())
            or len(direct_calls) != 1
        ):
            line = binding_assignments[0].lineno if binding_assignments else 1
            violations.append(
                Violation(
                    relative_path,
                    line,
                    f"{boundary} must preserve exact direct FFI binding "
                    f"'{local_name} = {qualified_source}'",
                )
            )
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Name)
                and node.id == local_name
                and isinstance(node.ctx, ast.Load)
            ):
                continue
            parent = parents.get(node)
            if (isinstance(parent, ast.Call) and parent.func is node) or (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr in {"argtypes", "restype"}
            ):
                continue
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot alias or re-export FFI binding '{local_name}'",
                )
            )
    for node in assignments:
        if not (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "_LIBC"
        ):
            continue
        if node.targets[0].id not in reviewed_targets:
            violations.append(
                Violation(
                    relative_path,
                    node.lineno,
                    f"{boundary} cannot bind unreviewed libc function '{node.value.attr}'",
                )
            )
    return violations


def _fixed_staging_unlink_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    publisher: str,
    staging_names: frozenset[str],
) -> list[Violation]:
    """Allow unlink only for the fixed staging name consumed by one publisher."""

    functions = [
        node
        for node in getattr(tree, "body", ())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == publisher
    ]
    violations: list[Violation] = []
    if len(functions) != 1:
        return [
            Violation(
                relative_path,
                1,
                f"{boundary} must preserve exact staging publisher '{publisher}'",
            )
        ]
    function = functions[0]
    publisher_nodes = frozenset(ast.walk(function))
    unlink_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "unlink"
    ]
    exact_unlink = (
        len(unlink_calls) == 1
        and unlink_calls[0] in publisher_nodes
        and len(unlink_calls[0].args) == 1
        and isinstance(unlink_calls[0].args[0], ast.Name)
        and unlink_calls[0].args[0].id == "staging_file_name"
        and len(unlink_calls[0].keywords) == 1
        and unlink_calls[0].keywords[0].arg == "dir_fd"
        and isinstance(unlink_calls[0].keywords[0].value, ast.Name)
        and unlink_calls[0].keywords[0].value.id == "directory_descriptor"
    )
    if not exact_unlink:
        line = unlink_calls[0].lineno if unlink_calls else function.lineno
        violations.append(
            Violation(
                relative_path,
                line,
                f"{boundary} may unlink only its exact fixed staging file",
            )
        )
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == publisher
    ]
    observed_staging_names: list[str] = []
    for call in calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        value = keywords.get("staging_file_name")
        if isinstance(value, ast.Name):
            observed_staging_names.append(value.id)
    if (
        len(calls) != len(staging_names)
        or frozenset(observed_staging_names) != staging_names
        or len(observed_staging_names) != len(set(observed_staging_names))
    ):
        violations.append(
            Violation(
                relative_path,
                function.lineno,
                f"{boundary} must publish each exact fixed staging name once",
            )
        )
    return violations


def _nonblocking_flock_violations(
    tree: ast.AST,
    *,
    relative_path: Path,
    boundary: str,
    expected_acquisitions: int,
    expected_unlocks: int,
) -> list[Violation]:
    """Require every reviewed flock acquisition to be explicitly nonblocking."""

    bindings = _imported_symbol_bindings(tree)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _qualified_symbol(node.func, bindings) == "fcntl.flock"
    ]
    acquisitions = 0
    unlocks = 0
    violations: list[Violation] = []
    for call in calls:
        flags = call.args[1] if len(call.args) == 2 and not call.keywords else None
        symbols = (
            {
                qualified
                for node in ast.walk(flags)
                if (qualified := _qualified_symbol(node, bindings)) is not None
                and qualified.startswith("fcntl.LOCK_")
            }
            if flags is not None
            else set()
        )
        if "fcntl.LOCK_UN" in symbols:
            unlocks += 1
            exact = symbols == {"fcntl.LOCK_UN"}
        else:
            acquisitions += 1
            lock_modes = symbols & {"fcntl.LOCK_EX", "fcntl.LOCK_SH"}
            exact = (
                "fcntl.LOCK_NB" in symbols
                and (
                    len(lock_modes) == 1
                    or (
                        lock_modes == {"fcntl.LOCK_EX", "fcntl.LOCK_SH"}
                        and flags is not None
                        and any(isinstance(node, ast.IfExp) for node in ast.walk(flags))
                    )
                )
                and "fcntl.LOCK_UN" not in symbols
            )
        if exact:
            continue
        violations.append(
            Violation(
                relative_path,
                call.lineno,
                f"{boundary} must use an exact nonblocking acquisition or exact unlock",
            )
        )
    if acquisitions != expected_acquisitions or unlocks != expected_unlocks:
        violations.append(
            Violation(
                relative_path,
                calls[0].lineno if calls else 1,
                f"{boundary} must preserve exact nonblocking flock acquisition/unlock counts",
            )
        )
    return violations


def _trusted_time_topology_launch_lock_violations(
    *,
    repository: Path,
    config_path: Path,
    scan: dict[str, Any],
    production_files: set[Path],
) -> list[Violation]:
    """Freeze the topology reader's one opaque native launch-lock lease lifecycle."""

    boundary = "trusted-time topology opaque launch-lock lifecycle"
    reader_relative = Path("scripts/trusted_time_post_enrollment_topology_reader.py")
    host_relative = Path("scripts/trusted_time_post_enrollment_host_orchestrator.py")
    wrapper_relative = Path("packages/adapters/trusted_time/_owned_file_descriptor.py")
    if not (repository / reader_relative).is_file() and not any(
        key.startswith("trusted_time_topology_launch_lock_") for key in scan
    ):
        return []
    wrapper_module = "packages.adapters.trusted_time._owned_file_descriptor"
    reader_module = "scripts.trusted_time_post_enrollment_topology_reader"
    lease_symbols = (
        "_acquire_trusted_time_launch_lock",
        "_TrustedTimeLaunchLockLease",
        "_validate_trusted_time_launch_lock",
    )
    allowed_imports = tuple(f"{wrapper_module}:{symbol}" for symbol in lease_symbols)
    reader_native_aliases = (
        "_flock|_native_flock",
        "_fstat|_native_fstat",
        "_fsync|_native_fsync",
        "_list_snapshot|_native_list_snapshot",
        "_open_child_directory|_native_open_child_directory",
        "_open_child_regular|_native_open_child_regular",
        "_open_root_directory|_native_open_root_directory",
        "_OwnedFileDescriptor|_NativeOwnedFileDescriptor",
        "_read_snapshot|_native_read_snapshot",
        "_statat|_native_statat",
    )
    reader_reserved_exports = (
        *lease_symbols,
        "_authenticated_issuer_scope_is_live",
        "_bind_authenticated_issuer_activation_launch_lock_lease",
        "_bound_authenticated_issuer_lifecycle_lock",
        "_burn_authenticated_issuer_keep_launch_lock",
        "_teardown_authenticated_issuer_launch_lock_binding",
        "_validated_authenticated_issuer_launch_lock_binding",
        "_launch_lock_lease",
        "_validate_lock",
        "_activate_with_dependencies",
        "_require_usable",
    )
    host_allowed_reader_private_imports = ("_abort_authenticated_issuer_activation",)
    legacy_launch_lock_origin = "scripts.start_trusted_time_supervisor"
    legacy_launch_lock_symbols = (
        "TRUSTED_TIME_LAUNCH_LOCK_PATH",
        "_acquire_trusted_time_launch_lock",
        "_release_trusted_time_launch_lock",
    )
    legacy_launch_lock_boundary_paths = (
        "scripts/start_trusted_time_supervisor.py",
        "scripts/enroll_trusted_time_head_anchor.py",
    )
    reachable_fcntl_paths = (
        "scripts/start_trusted_time_supervisor.py",
        "scripts/trusted_time_post_enrollment_controller_outcome.py",
        "scripts/trusted_time_post_enrollment_execution_admission.py",
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
        "scripts/trusted_time_post_enrollment_outcome.py",
        "scripts/trusted_time_post_enrollment_topology_reader.py",
    )
    reachable_fileio_paths = (
        "scripts/start_trusted_time_supervisor.py",
        "scripts/trusted_time_post_enrollment_outcome.py",
    )
    reachable_wrapper_flock_paths = (
        "scripts/trusted_time_post_enrollment_controller_outcome.py",
        "scripts/trusted_time_post_enrollment_execution_admission.py",
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
        "scripts/trusted_time_post_enrollment_topology_reader.py",
    )
    documentation_paths = (
        "docs/ARCHITECTURE.md",
        "docs/IMPLEMENTATION_PLAN.md",
        "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        "docs/runbooks/trusted-time-supervisor.md",
    )
    documentation_claim = (
        "Closure-owned issuance/choreography live-call tokens and the callback-only exact "
        "`RLock` runner are audited here solely for opaque-lease retention and close "
        "disposition, not as authentication of mutable choreography, checkpoint, retention, "
        "recovery, or effect authority. No held lock or opaque-lease authority crosses a "
        "function `RETURN`, generator `yield`, or context-manager handoff."
    )
    documentation_blocker_claim = (
        "Mutable `ChoreographyRegistration`, `_ChoreographyCheckpoint`, recovery, post-effect, "
        "and controller retention checkpoints/outcome state, and the effect-authority graph are "
        "a separate production-activation blocker outside this signoff. Every effect remains "
        "blocked until their tuple state is hardened and their entire transitive path proves "
        "exact `KeyboardInterrupt`/`SystemExit` identity and cleanup. The legacy "
        "unenrolled/enrollment Python launch-lock and runner/Popen spawn paths, hostile "
        "same-UID writer/path replacement after validation, and executable/tool-byte admission "
        "also remain explicit blockers."
    )
    reader_module_ast_sha256 = "a38808e452a92cad0fc63141bb234c579357b07ddb1f17f78bd00b3ca57cef48"
    issuer_class_ast_sha256 = "b64f79e1679e2bdefe40f6b36c82142fa367f6e6981c1b2e8fee1366a7d39bcd"
    host_module_ast_sha256 = "15c3e62437dc070d223038e21097ce85cbbb68de71ced3a6574f506236ebf56c"
    production_ast_sha256 = _TRUSTED_TIME_TOPOLOGY_PRODUCTION_AST_SHA256
    lifecycle_tag = "trusted-time-issuer-lifecycle-v3"
    launch_lock_binding_tag = "trusted-time-launch-lock-binding-v1"
    runtime_registration_tag = "trusted-time-issuer-runtime-registration-v1"
    issuer_slots = (
        "__weakref__",
        "_artifact_directory_value",
        "_authentication_capability",
        "_busy",
        "_choreography_consumed",
        "_choreography_inflight",
        "_choreography_scope_nonce",
        "_closed",
        "_cursor_count",
        "_daemon_identity",
        "_daemon_identity_registration_value",
        "_docker_executable_identity_value",
        "_docker_executable_path",
        "_docker_executable_path_value",
        "_environment",
        "_environment_identity_value",
        "_environment_sha256_value",
        "_final_action_observation_sha256",
        "_first_staged_snapshot_sha256",
        "_ignored_root",
        "_ignored_root_value",
        "_issued_created_observation_sha256",
        "_last_observation_sha256",
        "_launch_lock_lease",
        "_lifecycle_lock",
        "_monotonic_ns",
        "_owner_pid",
        "_poisoned",
        "_reviewed_mutation_binding_sha256",
        "_reviewed_mutation_created_registration",
        "_reviewed_mutation_prepared_registration",
        "_reviewed_mutation_state",
        "_runner",
        "_runner_identity_value",
        "_session_sha256",
        "_socket_identity_value",
        "_socket_path_value",
        "_staged_observation_count",
    )
    protected_defaults = (
        "scripts/trusted_time_post_enrollment_topology_reader.py|_run_under_exact_rlock|_depth|_exact_rlock_depth",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_run_under_exact_rlock|_restore|_restore_rlock_depth",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_run_under_exact_rlock|_preferred|_preferred_control_error",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_rlock_type|_EXACT_RLOCK_TYPE",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_rlock_acquire|_EXACT_RLOCK_TYPE.acquire",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_rlock_release|_EXACT_RLOCK_TYPE.release",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_rlock_recursion_count|_EXACT_RLOCK_TYPE.__dict__['_recursion_count']",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_thread_local_type|_thread._local",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_thread_local_getattribute|_thread._local.__dict__['__getattribute__']",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_thread_local_setattr|_thread._local.__dict__['__setattr__']",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_launch_lock_lease_type|_TrustedTimeLaunchLockLease",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_close_launch_lock|_TrustedTimeLaunchLockLease.close",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_validate_launch_lock|_validate_trusted_time_launch_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_type|_NativeOwnedFileDescriptor",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_close|_NativeOwnedFileDescriptor.close",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_closed|_NativeOwnedFileDescriptor.closed",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_closed_get|_EXACT_NATIVE_OWNER_CLOSED_GET",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_open_root|_native_open_root_directory",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_open_directory|_native_open_child_directory",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_open_regular|_native_open_child_regular",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_fstat|_native_fstat",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_statat|_native_statat",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_read|_native_read_snapshot",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_list|_native_list_snapshot",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_flock|_native_flock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_native_owner_fsync|_native_fsync",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|"
        "_native_lock_shared_nonblocking|fcntl.LOCK_SH | fcntl.LOCK_NB",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert|_rlock_type|threading.RLock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert|_rlock_depth|_exact_rlock_depth",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert|_getpid|os.getpid",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert|_path_type|Path",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_acquire_launch_lock|_acquire_trusted_time_launch_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_bind_activation_launch_lock_lease|_bind_authenticated_issuer_activation_launch_lock_lease",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_validate_launch_lock|_validate_trusted_time_launch_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_close_launch_lock|_TrustedTimeLaunchLockLease.close",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_abort_activation|_abort_authenticated_issuer_activation",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_path_type|Path",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_rlock_depth|_exact_rlock_depth",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_getpid|os.getpid",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._require_usable|_validated_binding|_validated_authenticated_issuer_launch_lock_binding",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._require_usable|_run_under_lock|_run_under_exact_rlock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_close_launch_lock|_TrustedTimeLaunchLockLease.close",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_validate_launch_lock|_validate_trusted_time_launch_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_abort_activation|_abort_authenticated_issuer_activation",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_burn_keep_launch_lock|_burn_authenticated_issuer_keep_launch_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_scope_is_live|_authenticated_issuer_scope_is_live",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_revoke_choreography|_revoke_authenticated_choreography",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_revoke_choreography_scope|_revoke_authenticated_choreography_scope",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_bound_lifecycle_lock|_bound_authenticated_issuer_lifecycle_lock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_teardown_binding|_teardown_authenticated_issuer_launch_lock_binding",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_run_under_lock|_run_under_exact_rlock",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_preferred|_preferred_control_error",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_fspath|os.fspath",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_path_type|_EXACT_PATH_TYPE",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_getpid|os.getpid",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_implementation|_run_operator_attested_post_enrollment_start_once_with_dependencies",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_issuer_type|TrustedTimePostEnrollmentTopologyObservationIssuer",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_allocate_inert_issuer|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_activate_issuer|TrustedTimePostEnrollmentTopologyObservationIssuer.activate",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_close_issuer|TrustedTimePostEnrollmentTopologyObservationIssuer.close",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_build_operator_attested_post_enrollment_start_once|_abort_issuer_activation|_abort_authenticated_issuer_activation",
    )
    sealed_replacements = (
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_preferred|sealed_preferred_control_error",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_rlock_depth|sealed_rlock_depth",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_run_under_lock|sealed_run_under_rlock",
    )
    operation_call_counts = (
        "scripts/trusted_time_post_enrollment_topology_reader.py|_run_under_exact_rlock|operation|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_run_under_lock|29",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|run_under_registry_lock|82",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_validate_launch_lock|6",
        "scripts/trusted_time_post_enrollment_topology_reader.py|_build_observation_sealer|_close_launch_lock|2",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert|_rlock_type|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_acquire_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_bind_activation_launch_lock_lease|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_validate_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_close_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._activate_with_dependencies|_abort_activation|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer._require_usable|_run_under_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_run_under_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_validate_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_close_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_abort_activation|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_burn_keep_launch_lock|1",
        "scripts/trusted_time_post_enrollment_topology_reader.py|TrustedTimePostEnrollmentTopologyObservationIssuer.close|_scope_is_live|1",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_run_operator_attested_post_enrollment_start_once_with_dependencies|allocate_inert_issuer|1",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_run_operator_attested_post_enrollment_start_once_with_dependencies|activate_issuer|1",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_run_operator_attested_post_enrollment_start_once_with_dependencies|close_issuer|1",
        "scripts/trusted_time_post_enrollment_host_orchestrator.py|_run_operator_attested_post_enrollment_start_once_with_dependencies|abort_issuer_activation|1",
    )
    frozen_source_sha256 = {
        "build_support/build_native_admission_launcher.py": (
            "08572042780300ac80d77fc90fbb49dac6c0dbf05bd3ebcdfe719ff69c515754"
        ),
        "build_support/build_native_test_launcher.py": (
            "54ecaa0ca5572a988c222a44555ef569987e467efe0e2203d02864c825713686"
        ),
        "build_support/install_native_admission_launcher.py": (
            "3cf730aefc89e588ca77fec79e6c2662c9b363e121089398469a1097a760f5e5"
        ),
        "build_support/native_owned_file_descriptor_hook.py": (
            "75313b842c4f0ace7ca3111fc28edb6048afca724b6002b3a6131d24771819eb"
        ),
        "native/bounded_process.c": (
            "be08d5c95a2a5ce6aa9b06a4434c09473ee74ad941a417b8022885a7ef1f5cbd"
        ),
        "native/owned_file_descriptor.c": (
            "01b9834c343f4b173198ac7bfb22df37c6da6fb3093e7a93875aef56410b9fd9"
        ),
        "native/trusted_time_python_launcher.c": (
            "8f21c008571b4ed04166ae120cea9be2da73955c891a7c026833779dca3381f8"
        ),
        "packages/adapters/trusted_time/_bounded_process.py": (
            "0bdf6cda1f0ab75d08df768d0d75bb40f2c8ef0cb490d09a18d843fb96a2a006"
        ),
        "packages/adapters/trusted_time/_owned_file_descriptor.py": (
            "a5c3a0f1ec32ae95d6a058cdf52f8530fe505c5a97f1a2cf61106d94c2baa9ab"
        ),
    }
    expected_prefix_keys = {
        "trusted_time_topology_launch_lock_allowed_imports",
        "trusted_time_topology_launch_lock_downstream_lifecycle_with_count",
        "trusted_time_topology_launch_lock_documentation_paths",
        "trusted_time_topology_launch_lock_frozen_source_sha256",
        "trusted_time_topology_launch_lock_host_module_ast_sha256",
        "trusted_time_topology_launch_lock_host_allowed_reader_private_imports",
        "trusted_time_topology_launch_lock_host_path",
        "trusted_time_topology_launch_lock_issuer_class_ast_sha256",
        "trusted_time_topology_launch_lock_issuer_lifecycle_tuple_length",
        "trusted_time_topology_launch_lock_issuer_registration_tuple_length",
        "trusted_time_topology_launch_lock_issuer_slots",
        "trusted_time_topology_launch_lock_launch_binding_tuple_length",
        "trusted_time_topology_launch_lock_launch_lock_binding_tag",
        "trusted_time_topology_launch_lock_launch_lock_binding_tag_count",
        "trusted_time_topology_launch_lock_legacy_launch_lock_boundary_paths",
        "trusted_time_topology_launch_lock_legacy_launch_lock_origin",
        "trusted_time_topology_launch_lock_legacy_launch_lock_symbols",
        "trusted_time_topology_launch_lock_lifecycle_tag",
        "trusted_time_topology_launch_lock_lifecycle_tag_count",
        "trusted_time_topology_launch_lock_operation_call_counts",
        "trusted_time_topology_launch_lock_production_ast_sha256",
        "trusted_time_topology_launch_lock_protected_defaults",
        "trusted_time_topology_launch_lock_reader_module_ast_sha256",
        "trusted_time_topology_launch_lock_reader_native_aliases",
        "trusted_time_topology_launch_lock_reader_path",
        "trusted_time_topology_launch_lock_reader_reserved_exports",
        "trusted_time_topology_launch_lock_reachable_fcntl_paths",
        "trusted_time_topology_launch_lock_reachable_fileio_paths",
        "trusted_time_topology_launch_lock_reachable_wrapper_flock_paths",
        "trusted_time_topology_launch_lock_registry_runner_call_count",
        "trusted_time_topology_launch_lock_runtime_registration_tag",
        "trusted_time_topology_launch_lock_runtime_registration_tag_count",
        "trusted_time_topology_launch_lock_sealed_replacements",
        "trusted_time_topology_launch_lock_wrapper_module",
    }
    observed_prefix_keys = {
        key for key in scan if key.startswith("trusted_time_topology_launch_lock_")
    }
    expected_config: dict[str, object] = {
        "trusted_time_topology_launch_lock_allowed_imports": list(allowed_imports),
        "trusted_time_topology_launch_lock_downstream_lifecycle_with_count": 40,
        "trusted_time_topology_launch_lock_documentation_paths": list(documentation_paths),
        "trusted_time_topology_launch_lock_frozen_source_sha256": frozen_source_sha256,
        "trusted_time_topology_launch_lock_host_module_ast_sha256": host_module_ast_sha256,
        "trusted_time_topology_launch_lock_host_allowed_reader_private_imports": list(
            host_allowed_reader_private_imports
        ),
        "trusted_time_topology_launch_lock_host_path": host_relative.as_posix(),
        "trusted_time_topology_launch_lock_issuer_class_ast_sha256": issuer_class_ast_sha256,
        "trusted_time_topology_launch_lock_issuer_lifecycle_tuple_length": 9,
        "trusted_time_topology_launch_lock_issuer_registration_tuple_length": 12,
        "trusted_time_topology_launch_lock_issuer_slots": list(issuer_slots),
        "trusted_time_topology_launch_lock_launch_binding_tuple_length": 5,
        "trusted_time_topology_launch_lock_launch_lock_binding_tag": launch_lock_binding_tag,
        "trusted_time_topology_launch_lock_launch_lock_binding_tag_count": 5,
        "trusted_time_topology_launch_lock_legacy_launch_lock_boundary_paths": list(
            legacy_launch_lock_boundary_paths
        ),
        "trusted_time_topology_launch_lock_legacy_launch_lock_origin": legacy_launch_lock_origin,
        "trusted_time_topology_launch_lock_legacy_launch_lock_symbols": list(
            legacy_launch_lock_symbols
        ),
        "trusted_time_topology_launch_lock_lifecycle_tag": lifecycle_tag,
        "trusted_time_topology_launch_lock_lifecycle_tag_count": 13,
        "trusted_time_topology_launch_lock_operation_call_counts": list(operation_call_counts),
        "trusted_time_topology_launch_lock_production_ast_sha256": production_ast_sha256,
        "trusted_time_topology_launch_lock_protected_defaults": list(protected_defaults),
        "trusted_time_topology_launch_lock_reader_module_ast_sha256": reader_module_ast_sha256,
        "trusted_time_topology_launch_lock_reader_native_aliases": list(reader_native_aliases),
        "trusted_time_topology_launch_lock_reader_path": reader_relative.as_posix(),
        "trusted_time_topology_launch_lock_reader_reserved_exports": list(reader_reserved_exports),
        "trusted_time_topology_launch_lock_reachable_fcntl_paths": list(reachable_fcntl_paths),
        "trusted_time_topology_launch_lock_reachable_fileio_paths": list(reachable_fileio_paths),
        "trusted_time_topology_launch_lock_reachable_wrapper_flock_paths": list(
            reachable_wrapper_flock_paths
        ),
        "trusted_time_topology_launch_lock_registry_runner_call_count": 82,
        "trusted_time_topology_launch_lock_runtime_registration_tag": runtime_registration_tag,
        "trusted_time_topology_launch_lock_runtime_registration_tag_count": 5,
        "trusted_time_topology_launch_lock_sealed_replacements": list(sealed_replacements),
        "trusted_time_topology_launch_lock_wrapper_module": wrapper_module,
    }
    violations: list[Violation] = []
    if observed_prefix_keys != expected_prefix_keys or any(
        scan.get(key) != value for key, value in expected_config.items()
    ):
        violations.append(
            Violation(
                config_path,
                1,
                f"{boundary} configuration must remain mandatory and exact",
            )
        )

    try:
        observed_production_ast_sha256 = _trusted_time_topology_production_ast_sha256(
            repository,
            production_files,
        )
    except Exception as error:
        violations.append(
            Violation(
                config_path,
                getattr(error, "lineno", 1) or 1,
                f"{boundary} production path/module AST aggregate cannot be constructed",
            )
        )
    else:
        if observed_production_ast_sha256 != production_ast_sha256:
            violations.append(
                Violation(
                    config_path,
                    1,
                    f"{boundary} must preserve the exact production path/module AST aggregate",
                )
            )

    for documentation_path_text in documentation_paths:
        documentation_path = Path(documentation_path_text)
        try:
            documentation_source = (repository / documentation_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            violations.append(
                Violation(
                    documentation_path,
                    1,
                    f"{boundary} documentation claim is unavailable",
                )
            )
            continue
        if documentation_source.count(documentation_claim) != 1:
            violations.append(
                Violation(
                    documentation_path,
                    1,
                    f"{boundary} documentation claim must remain exact and singular",
                )
            )
        normalized_documentation_source = " ".join(documentation_source.split())
        if normalized_documentation_source.count(documentation_blocker_claim) != 1:
            violations.append(
                Violation(
                    documentation_path,
                    1,
                    f"{boundary} activation-blocker claim must remain exact and singular",
                )
            )

    trees: dict[Path, ast.Module] = {}
    for relative_path in (reader_relative, host_relative):
        path = repository / relative_path
        try:
            trees[relative_path] = ast.parse(
                path.read_text(encoding="utf-8"),
                filename=str(relative_path),
            )
        except (OSError, SyntaxError, UnicodeError) as error:
            violations.append(
                Violation(
                    relative_path,
                    getattr(error, "lineno", 1) or 1,
                    f"{boundary} source cannot be parsed",
                )
            )
    reader_tree = trees.get(reader_relative)
    host_tree = trees.get(host_relative)
    if reader_tree is None or host_tree is None:
        return violations

    if _canonical_ast_sha256(reader_tree) != reader_module_ast_sha256:
        violations.append(
            Violation(reader_relative, 1, f"{boundary} must preserve the exact reader module AST")
        )
    if _canonical_ast_sha256(host_tree) != host_module_ast_sha256:
        violations.append(
            Violation(reader_relative, 1, f"{boundary} must preserve the exact host module AST")
        )

    issuer_classes = [
        node
        for node in reader_tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "TrustedTimePostEnrollmentTopologyObservationIssuer"
    ]
    if (
        len(issuer_classes) != 1
        or _canonical_ast_sha256(issuer_classes[0]) != issuer_class_ast_sha256
    ):
        violations.append(
            Violation(
                reader_relative,
                issuer_classes[0].lineno if issuer_classes else 1,
                f"{boundary} must preserve the exact issuer class AST",
            )
        )
    if len(issuer_classes) == 1:
        slot_assignments = [
            node
            for node in issuer_classes[0].body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__slots__" for target in node.targets
            )
        ]
        observed_slots: object = None
        if len(slot_assignments) == 1:
            try:
                observed_slots = ast.literal_eval(slot_assignments[0].value)
            except (TypeError, ValueError):
                observed_slots = None
        if observed_slots != issuer_slots:
            violations.append(
                Violation(
                    reader_relative,
                    slot_assignments[0].lineno if slot_assignments else issuer_classes[0].lineno,
                    f"{boundary} must preserve exact issuer slots",
                )
            )

    direct_native_imports = [
        node
        for node in reader_tree.body
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == wrapper_module
    ]
    lease_imports = [
        node
        for node in direct_native_imports
        if tuple(alias.name for alias in node.names) == lease_symbols
        and all(alias.asname is None for alias in node.names)
    ]
    observed_native_aliases: list[str] = []
    invalid_native_imports = False
    for node in direct_native_imports:
        if node in lease_imports:
            continue
        if len(node.names) != 1 or node.names[0].asname is None:
            invalid_native_imports = True
            continue
        observed_native_aliases.append(f"{node.names[0].name}|{node.names[0].asname}")
    if len(lease_imports) != 1 or invalid_native_imports:
        violations.append(
            Violation(
                reader_relative,
                lease_imports[0].lineno if lease_imports else 1,
                f"{boundary} must retain one exact top-level unaliased native lease import trio",
            )
        )
    if tuple(observed_native_aliases) != reader_native_aliases:
        violations.append(
            Violation(
                reader_relative,
                direct_native_imports[0].lineno if direct_native_imports else 1,
                f"{boundary} must retain every exact top-level native operation alias",
            )
        )

    production_trees: dict[Path, ast.Module] = dict(trees)
    for path in sorted(production_files):
        try:
            relative_path = path.relative_to(repository)
        except ValueError:
            continue
        tree = trees.get(relative_path)
        if tree is None:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
            except (OSError, SyntaxError, UnicodeError):
                continue
        production_trees[relative_path] = tree
        origin_bindings = _origin_module_import_bindings(tree, wrapper_module)
        for line, binding in origin_bindings:
            if binding == f"{wrapper_module}:*" or (
                binding in allowed_imports and relative_path != reader_relative
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"{boundary} native lease imports are reserved to the topology reader",
                    )
                )
        reader_origin_bindings = _origin_module_import_bindings(tree, reader_module)
        for line, binding in reader_origin_bindings:
            _, _, imported_name = binding.rpartition(":")
            allowed_host_private = (
                relative_path == host_relative
                and imported_name in host_allowed_reader_private_imports
            )
            if binding == f"{reader_module}:*" or (
                (
                    imported_name in reader_reserved_exports
                    or imported_name in host_allowed_reader_private_imports
                )
                and not allowed_host_private
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"{boundary} reader authority exports are private and non-reexportable",
                    )
                )
        if relative_path in {
            reader_relative,
            wrapper_relative,
            Path("scripts/check_architecture.py"),
        }:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in lease_symbols:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} symbols cannot be reached through namespace attributes",
                    )
                )
            elif (
                isinstance(node, ast.Constant)
                and type(node.value) is str
                and node.value in lease_symbols
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} symbols cannot be reached by reflection",
                    )
                )
            elif isinstance(node, ast.Attribute) and node.attr in reader_reserved_exports:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} reader authority cannot escape through attributes",
                    )
                )
            elif (
                isinstance(node, ast.Constant)
                and type(node.value) is str
                and node.value in reader_reserved_exports
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} reader authority cannot be reached by reflection",
                    )
                )

    def qualified_callables(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[node.name] = node
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        found[f"{node.name}.{child.name}"] = child
        return found

    functions_by_path = {
        reader_relative: qualified_callables(reader_tree),
        host_relative: qualified_callables(host_tree),
    }

    def callable_defaults(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> dict[str, ast.expr]:
        positional = [*function.args.posonlyargs, *function.args.args]
        positional_defaults = [
            *([None] * (len(positional) - len(function.args.defaults))),
            *function.args.defaults,
        ]
        defaults: dict[str, ast.expr] = {
            argument.arg: default
            for argument, default in zip(positional, positional_defaults, strict=True)
            if default is not None
        }
        defaults.update(
            {
                argument.arg: default
                for argument, default in zip(
                    function.args.kwonlyargs,
                    function.args.kw_defaults,
                    strict=True,
                )
                if default is not None
            }
        )
        return defaults

    for specification in sealed_replacements:
        path_text, qualified_name, binding, expression = specification.split("|", 3)
        relative_path = Path(path_text)
        function = functions_by_path.get(relative_path, {}).get(qualified_name)
        expected_value = ast.parse(expression, mode="eval").body
        assignments = (
            [
                node
                for node in function.body
                if isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == binding
            ]
            if function is not None
            else []
        )
        if len(assignments) != 1 or _canonical_ast_sha256(
            assignments[0].value
        ) != _canonical_ast_sha256(expected_value):
            violations.append(
                Violation(
                    relative_path,
                    assignments[0].lineno if assignments else getattr(function, "lineno", 1),
                    f"{boundary} must preserve sealed replacement binding "
                    f"'{qualified_name}.{binding}'",
                )
            )

    builder = functions_by_path[reader_relative].get("_build_observation_sealer")
    builder_defaults = callable_defaults(builder) if builder is not None else {}
    native_operation_default_aliases = {
        "_native_open_root": "_native_open_root_directory",
        "_native_open_directory": "_native_open_child_directory",
        "_native_open_regular": "_native_open_child_regular",
        "_native_owner_fstat": "_native_fstat",
        "_native_owner_statat": "_native_statat",
        "_native_owner_read": "_native_read_snapshot",
        "_native_owner_list": "_native_list_snapshot",
        "_native_owner_flock": "_native_flock",
        "_native_owner_fsync": "_native_fsync",
    }
    for parameter, alias in native_operation_default_aliases.items():
        default = builder_defaults.get(parameter)
        loads = [
            node
            for node in ast.walk(reader_tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == alias
        ]
        if not (isinstance(default, ast.Name) and default.id == alias and loads == [default]):
            violations.append(
                Violation(
                    reader_relative,
                    getattr(default or builder, "lineno", 1),
                    f"{boundary} native operation alias must flow only into its exact "
                    f"captured default '{parameter}'",
                )
            )

    allowed_raw_lock_nodes: set[ast.AST] = set()
    native_lock_default = builder_defaults.get("_native_lock_shared_nonblocking")
    exact_native_lock_default = ast.parse("fcntl.LOCK_SH | fcntl.LOCK_NB", mode="eval").body
    if native_lock_default is not None and _canonical_ast_sha256(
        native_lock_default
    ) == _canonical_ast_sha256(exact_native_lock_default):
        allowed_raw_lock_nodes.update(
            node
            for node in ast.walk(native_lock_default)
            if isinstance(node, ast.Name) and node.id == "fcntl"
        )

    protected_parameters_by_leaf: dict[str, set[str]] = {}
    for specification in protected_defaults:
        path_text, qualified_name, parameter, expression = specification.split("|", 3)
        relative_path = Path(path_text)
        function = functions_by_path.get(relative_path, {}).get(qualified_name)
        observed_default = callable_defaults(function).get(parameter) if function else None
        try:
            expected_default = ast.parse(expression, mode="eval").body
        except SyntaxError:
            expected_default = None
        if (
            observed_default is None
            or expected_default is None
            or _canonical_ast_sha256(observed_default) != _canonical_ast_sha256(expected_default)
        ):
            violations.append(
                Violation(
                    relative_path,
                    getattr(observed_default or function, "lineno", 1),
                    f"{boundary} must preserve protected default '{qualified_name}.{parameter}'",
                )
            )
        protected_parameters_by_leaf.setdefault(qualified_name.rpartition(".")[2], set()).add(
            parameter
        )

    for specification in operation_call_counts:
        path_text, qualified_name, operation, count_text = specification.split("|", 3)
        relative_path = Path(path_text)
        function = functions_by_path.get(relative_path, {}).get(qualified_name)
        observed_count = 0
        if function is not None:
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                leaf = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else None
                )
                if leaf == operation:
                    observed_count += 1
        if observed_count != int(count_text):
            violations.append(
                Violation(
                    relative_path,
                    function.lineno if function else 1,
                    f"{boundary} must preserve exact call count for '{qualified_name}:{operation}'",
                )
            )

    private_callable_paths = {
        "_activate_with_dependencies": reader_relative,
        "_build_observation_sealer": reader_relative,
        "_require_usable": reader_relative,
        "_run_under_exact_rlock": reader_relative,
        "allocate_inert": host_relative,
        "_build_operator_attested_post_enrollment_start_once": host_relative,
    }
    for relative_path, tree in production_trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            leaf = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            protected = protected_parameters_by_leaf.get(leaf or "")
            if protected is not None and any(
                keyword.arg is None or keyword.arg in protected for keyword in node.keywords
            ):
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} protected defaults cannot be overridden or widened",
                    )
                )
            allowed_path = private_callable_paths.get(leaf or "")
            if allowed_path is not None and relative_path != allowed_path:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} private lifecycle callables cannot be invoked externally",
                    )
                )

    protected_reflection_names = frozenset(
        {
            *reader_reserved_exports,
            *(
                name
                for name in protected_parameters_by_leaf
                if name.startswith("_") or name == "allocate_inert"
            ),
            *(
                parameter
                for parameters in protected_parameters_by_leaf.values()
                for parameter in parameters
            ),
        }
    )
    for relative_path, tree in production_trees.items():
        if relative_path in {
            reader_relative,
            wrapper_relative,
            Path("scripts/check_architecture.py"),
        }:
            continue
        for node in ast.walk(tree):
            folded = (
                _constant_folded_text(node)
                if isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr))
                else None
            )
            if folded in protected_reflection_names:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        f"{boundary} protected lifecycle bindings cannot be reached by reflection",
                    )
                )
            if not (isinstance(node, ast.Attribute) and node.attr in {"__dict__", "__wrapped__"}):
                continue
            protected_owner = (
                node.value.id
                if isinstance(node.value, ast.Name)
                else node.value.attr
                if isinstance(node.value, ast.Attribute)
                else None
            )
            if protected_owner in {
                *protected_parameters_by_leaf,
                "TrustedTimePostEnrollmentTopologyObservationIssuer",
            }:
                violations.append(
                    Violation(
                        relative_path,
                        node.lineno,
                        f"{boundary} protected lifecycle bindings cannot be reached by reflection",
                    )
                )

    module_paths: dict[str, Path] = {}
    for relative_path in production_trees:
        module_parts = relative_path.with_suffix("").parts
        if module_parts and module_parts[-1] == "__init__":
            module_parts = module_parts[:-1]
        module_paths[".".join(module_parts)] = relative_path
    reachable_modules: set[str] = set()
    pending_modules = [
        "scripts.trusted_time_post_enrollment_topology_reader",
        "scripts.trusted_time_post_enrollment_host_orchestrator",
    ]
    while pending_modules:
        module = pending_modules.pop()
        if module in reachable_modules:
            continue
        reachable_relative_path = module_paths.get(module)
        if reachable_relative_path is None:
            continue
        reachable_modules.add(module)
        for _, imported_module in _project_import_modules(
            production_trees[reachable_relative_path]
        ):
            if imported_module in module_paths and imported_module not in reachable_modules:
                pending_modules.append(imported_module)
    reachable_paths = {
        module_paths[module] for module in reachable_modules if module in module_paths
    }
    observed_fcntl_paths: set[str] = set()
    observed_fileio_paths: set[str] = set()
    observed_wrapper_flock_paths: set[str] = set()
    legacy_boundary_path_set = frozenset(Path(path) for path in legacy_launch_lock_boundary_paths)
    raw_authority_exempt_paths = legacy_boundary_path_set | {
        reader_relative,
        wrapper_relative,
    }
    for relative_path in sorted(reachable_paths):
        tree = production_trees[relative_path]
        imports_fcntl = any(
            (isinstance(node, ast.Import) and any(alias.name == "fcntl" for alias in node.names))
            or (isinstance(node, ast.ImportFrom) and node.module == "fcntl")
            for node in ast.walk(tree)
        )
        uses_fileio = any(
            (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "io"
                and node.attr == "FileIO"
            )
            or (
                isinstance(node, ast.ImportFrom)
                and node.module == "io"
                and any(alias.name == "FileIO" for alias in node.names)
            )
            for node in ast.walk(tree)
        )
        wrapper_flock_imported = any(
            binding == f"{wrapper_module}:_flock"
            for _, binding in _origin_module_import_bindings(tree, wrapper_module)
        )
        if imports_fcntl:
            observed_fcntl_paths.add(relative_path.as_posix())
        if uses_fileio:
            observed_fileio_paths.add(relative_path.as_posix())
        if wrapper_flock_imported:
            observed_wrapper_flock_paths.add(relative_path.as_posix())
        for line, binding in _origin_module_import_bindings(tree, legacy_launch_lock_origin):
            _, _, imported_name = binding.rpartition(":")
            if binding == f"{legacy_launch_lock_origin}:*" or (
                imported_name in legacy_launch_lock_symbols
                and relative_path not in legacy_boundary_path_set
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"{boundary} cannot reach the legacy Python launch-lock API",
                    )
                )
        if relative_path in raw_authority_exempt_paths:
            continue
        for node in ast.walk(tree):
            candidate: str | None = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                candidate = node.name
            elif isinstance(node, ast.Name):
                candidate = node.id
            elif isinstance(node, ast.Attribute):
                candidate = node.attr
            elif isinstance(node, ast.arg):
                candidate = node.arg
            if candidate in legacy_launch_lock_symbols:
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        f"{boundary} cannot reconstruct legacy launch-lock authority",
                    )
                )
            launch_lock_text = (
                _constant_folded_text(node)
                if isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr))
                else None
            )
            if launch_lock_text == "trusted-time-launch.lock":
                violations.append(
                    Violation(
                        relative_path,
                        getattr(node, "lineno", 1),
                        f"{boundary} cannot reconstruct the raw launch-lock path",
                    )
                )
    present_production_paths = {path.as_posix() for path in production_trees}
    if observed_fcntl_paths != set(reachable_fcntl_paths).intersection(present_production_paths):
        violations.append(
            Violation(
                config_path,
                1,
                f"{boundary} must preserve exact reachable fcntl boundaries",
            )
        )
    if observed_fileio_paths != set(reachable_fileio_paths).intersection(present_production_paths):
        violations.append(
            Violation(
                config_path,
                1,
                f"{boundary} must preserve exact reachable FileIO boundaries",
            )
        )
    if observed_wrapper_flock_paths != set(reachable_wrapper_flock_paths).intersection(
        present_production_paths
    ):
        violations.append(
            Violation(
                config_path,
                1,
                f"{boundary} must preserve exact reachable wrapper flock boundaries",
            )
        )

    def tuple_alias_arity(tree: ast.Module, name: str) -> int | None:
        assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in (node.targets if isinstance(node, ast.Assign) else (node.target,))
            )
        ]
        if len(assignments) != 1:
            return None
        value = assignments[0].value
        if not (
            isinstance(value, ast.Subscript)
            and isinstance(value.value, ast.Name)
            and value.value.id == "tuple"
            and isinstance(value.slice, ast.Tuple)
        ):
            return None
        return len(value.slice.elts)

    tuple_arities = {
        "_LaunchLockBinding": 5,
        "IssuerRegistration": 12,
        "IssuerLifecycle": 9,
    }
    for alias, expected_arity in tuple_arities.items():
        if tuple_alias_arity(reader_tree, alias) != expected_arity:
            violations.append(
                Violation(
                    reader_relative,
                    1,
                    f"{boundary} must preserve exact '{alias}' tuple slots",
                )
            )

    for tag, expected_count in (
        (lifecycle_tag, 13),
        (launch_lock_binding_tag, 5),
        (runtime_registration_tag, 5),
    ):
        observed_count = sum(
            isinstance(node, ast.Constant) and node.value == tag for node in ast.walk(reader_tree)
        )
        if observed_count != expected_count:
            violations.append(
                Violation(reader_relative, 1, f"{boundary} must preserve exact lifecycle tags")
            )

    lifecycle_with_nodes = [
        node
        for node in ast.walk(reader_tree)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Attribute)
            and item.context_expr.attr == "_lifecycle_lock"
            for item in node.items
        )
    ]
    if len(lifecycle_with_nodes) != 40:
        violations.append(
            Violation(
                reader_relative,
                1,
                f"{boundary} must preserve the explicitly deferred lifecycle-lock surface",
            )
        )
    parents = {
        child: parent for parent in ast.walk(reader_tree) for child in ast.iter_child_nodes(parent)
    }
    central_callables = {
        "_run_under_exact_rlock",
        "activate",
        "_activate_with_dependencies",
        "_require_usable",
        "close",
    }
    for node in lifecycle_with_nodes:
        current: ast.AST | None = node
        while current is not None and not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            current = parents.get(current)
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            current.name in central_callables
        ):
            violations.append(
                Violation(
                    reader_relative,
                    node.lineno,
                    f"{boundary} central lifecycle cannot yield a held lock through 'with'",
                )
            )

    registry_runner_calls = sum(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_under_registry_lock"
        for node in ast.walk(reader_tree)
    )
    if registry_runner_calls != 82:
        violations.append(
            Violation(
                reader_relative,
                1,
                f"{boundary} must preserve exact callback-style registry locking",
            )
        )
    for node in ast.walk(reader_tree):
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            violations.append(
                Violation(
                    reader_relative,
                    node.lineno,
                    f"{boundary} cannot publish held authority through a generator",
                )
            )
        if isinstance(node, ast.With):
            for item in node.items:
                context_expression = item.context_expr
                if (
                    isinstance(context_expression, ast.Name)
                    and context_expression.id == "registry_lock"
                ) or (
                    isinstance(context_expression, ast.Call)
                    and isinstance(context_expression.func, ast.Name)
                    and context_expression.func.id
                    in {
                        "run_under_registry_lock",
                        "_run_under_exact_rlock",
                    }
                ):
                    violations.append(
                        Violation(
                            reader_relative,
                            node.lineno,
                            f"{boundary} cannot expose a registry lock context manager",
                        )
                    )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "registry_lock"
            and node.func.attr in {"acquire", "release"}
        ):
            violations.append(
                Violation(
                    reader_relative,
                    node.lineno,
                    f"{boundary} registry lock transitions are private to the exact runner",
                )
            )

    banned_raw_lock_names = {
        "FileIO",
        "fcntl",
        "flock",
        "_release_trusted_time_launch_lock",
        "_lock_descriptor",
        "_lock_identity",
        "_lock_owner",
        "_lock_path",
        "lock_descriptor",
        "lock_identity",
        "lock_owner",
    }
    for node in ast.walk(reader_tree):
        if node in allowed_raw_lock_nodes:
            continue
        raw_candidate: str | None = None
        if isinstance(node, ast.Name):
            raw_candidate = node.id
        elif isinstance(node, ast.Attribute):
            raw_candidate = node.attr
        elif isinstance(node, ast.arg):
            raw_candidate = node.arg
        elif isinstance(node, ast.Constant) and type(node.value) is str:
            raw_candidate = node.value
        if raw_candidate in banned_raw_lock_names:
            violations.append(
                Violation(
                    reader_relative,
                    getattr(node, "lineno", 1),
                    f"{boundary} cannot restore the legacy Python/raw-descriptor lock graph",
                )
            )

    for relative_text, expected_sha256 in frozen_source_sha256.items():
        path = repository / relative_text
        try:
            metadata = path.stat(follow_symlinks=False)
            observed_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            metadata = None
            observed_sha256 = ""
        if (
            metadata is None
            or not stat.S_ISREG(metadata.st_mode)
            or observed_sha256 != expected_sha256
        ):
            violations.append(
                Violation(
                    Path(relative_text),
                    1,
                    f"{boundary} must preserve frozen native/build source bytes",
                )
            )

    return violations


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


def _python_files(
    roots: tuple[Path, ...],
    *,
    pruned_subtrees: tuple[Path, ...] = (),
) -> set[Path]:
    paths: set[Path] = set()
    for root in roots:
        if root.is_file():
            if root.suffix == ".py" and not _is_below(root, pruned_subtrees):
                paths.add(root)
            continue
        if root.exists():
            paths.update(
                path for path in root.rglob("*.py") if not _is_below(path, pruned_subtrees)
            )
    return paths


def check(repository: Path, config_path: Path) -> list[Violation]:
    scan = _load_config(config_path)
    source_roots = _resolve_roots(repository, scan["source_roots"])
    package_roots = _resolve_roots(repository, scan["package_roots"])
    production_python_source_manifest_root_values = tuple(
        str(root) for root in scan.get("production_python_source_manifest_roots", [])
    )
    production_python_source_manifest_roots = tuple(
        repository / value for value in production_python_source_manifest_root_values
    )
    production_python_source_manifest_pruned_values = tuple(
        str(root) for root in scan.get("production_python_source_manifest_pruned_subtrees", [])
    )
    production_python_source_manifest_pruned_subtrees = tuple(
        repository / value for value in production_python_source_manifest_pruned_values
    )

    def reviewed_python_files(roots: tuple[Path, ...]) -> set[Path]:
        return _python_files(
            roots,
            pruned_subtrees=production_python_source_manifest_pruned_subtrees,
        )

    production_python_source_manifest_sha256 = str(
        scan.get("production_python_source_manifest_sha256", "")
    )
    project_build_bootstrap_manifest_paths = tuple(
        str(path) for path in scan.get("project_build_bootstrap_manifest_paths", [])
    )
    project_build_bootstrap_manifest_sha256 = str(
        scan.get("project_build_bootstrap_manifest_sha256", "")
    )
    project_build_bootstrap_forbidden_paths = tuple(
        str(path) for path in scan.get("project_build_bootstrap_forbidden_paths", [])
    )
    architecture_checker_invocation_source_sha256 = {
        str(path): str(digest)
        for path, digest in scan.get("architecture_checker_invocation_source_sha256", {}).items()
    }
    builtin_namespace_integrity_roots = _resolve_roots(
        repository,
        scan.get("builtin_namespace_integrity_roots", []),
    )
    builtin_namespace_integrity_excluded_roots = _resolve_roots(
        repository,
        scan.get("builtin_namespace_integrity_excluded_roots", []),
    )
    builtin_namespace_integrity_allowed_imports = {
        (repository / str(path)).resolve(): tuple(str(binding) for binding in bindings)
        for path, bindings in scan.get("builtin_namespace_integrity_allowed_imports", {}).items()
    }
    builtin_namespace_integrity_allowed_reads = {
        (repository / str(path)).resolve(): tuple(str(binding) for binding in bindings)
        for path, bindings in scan.get("builtin_namespace_integrity_allowed_reads", {}).items()
    }
    builtin_namespace_integrity_sys_modules_callsites = {
        (repository / str(path)).resolve(): tuple(str(callsite) for callsite in callsites)
        for path, callsites in scan.get(
            "builtin_namespace_integrity_sys_modules_callsites", {}
        ).items()
    }
    native_owned_file_descriptor_wrapper_roots = _resolve_roots(
        repository,
        scan.get("native_owned_file_descriptor_wrapper_roots", []),
    )
    native_owned_file_descriptor_wrapper_module = str(
        scan.get("native_owned_file_descriptor_wrapper_module", "")
    )
    native_owned_file_descriptor_wrapper_module_ast_sha256 = str(
        scan.get("native_owned_file_descriptor_wrapper_module_ast_sha256", "")
    )
    native_bounded_process_wrapper_roots = _resolve_roots(
        repository,
        scan.get("native_bounded_process_wrapper_roots", []),
    )
    native_bounded_process_wrapper_module = str(
        scan.get("native_bounded_process_wrapper_module", "")
    )
    native_bounded_process_wrapper_module_ast_sha256 = str(
        scan.get("native_bounded_process_wrapper_module_ast_sha256", "")
    )
    raw_native_bounded_process_allowed_imports = scan.get(
        "native_bounded_process_allowed_imports", {}
    )
    if not isinstance(raw_native_bounded_process_allowed_imports, dict):
        raise SystemExit("native_bounded_process_allowed_imports must be a table")
    native_bounded_process_allowed_imports = {
        (repository / str(path)).resolve(): frozenset(str(binding) for binding in bindings)
        for path, bindings in raw_native_bounded_process_allowed_imports.items()
    }
    raw_native_bounded_process_consumer_function_ast_sha256 = scan.get(
        "native_bounded_process_consumer_function_ast_sha256", {}
    )
    if not isinstance(raw_native_bounded_process_consumer_function_ast_sha256, dict):
        raise SystemExit("native_bounded_process_consumer_function_ast_sha256 must be a table")
    native_bounded_process_consumer_function_ast_sha256 = {
        (repository / str(path)).resolve(): str(digest)
        for path, digest in raw_native_bounded_process_consumer_function_ast_sha256.items()
    }
    raw_native_bounded_process_consumer_module_ast_sha256 = scan.get(
        "native_bounded_process_consumer_module_ast_sha256", {}
    )
    if not isinstance(raw_native_bounded_process_consumer_module_ast_sha256, dict):
        raise SystemExit("native_bounded_process_consumer_module_ast_sha256 must be a table")
    native_bounded_process_consumer_module_ast_sha256 = {
        (repository / str(path)).resolve(): str(digest)
        for path, digest in raw_native_bounded_process_consumer_module_ast_sha256.items()
    }
    raw_native_bounded_process_reflection_attestations = scan.get(
        "native_bounded_process_reflection_attestations", {}
    )
    if not isinstance(raw_native_bounded_process_reflection_attestations, dict):
        raise SystemExit("native_bounded_process_reflection_attestations must be a table")
    native_bounded_process_reflection_attestations = {
        (repository / str(path)).resolve(): tuple(str(value) for value in values)
        for path, values in raw_native_bounded_process_reflection_attestations.items()
    }
    raw_native_bounded_process_reflection_module_ast_sha256 = scan.get(
        "native_bounded_process_reflection_module_ast_sha256", {}
    )
    if not isinstance(raw_native_bounded_process_reflection_module_ast_sha256, dict):
        raise SystemExit("native_bounded_process_reflection_module_ast_sha256 must be a table")
    native_bounded_process_reflection_module_ast_sha256 = {
        (repository / str(path)).resolve(): str(digest)
        for path, digest in raw_native_bounded_process_reflection_module_ast_sha256.items()
    }
    raw_native_bounded_process_reader_allowed_imports = scan.get(
        "native_bounded_process_reader_allowed_imports", {}
    )
    if not isinstance(raw_native_bounded_process_reader_allowed_imports, dict):
        raise SystemExit("native_bounded_process_reader_allowed_imports must be a table")
    native_bounded_process_reader_allowed_imports = {
        (repository / str(path)).resolve(): frozenset(str(binding) for binding in bindings)
        for path, bindings in raw_native_bounded_process_reader_allowed_imports.items()
    }
    raw_native_bounded_process_reader_consumer_module_ast_sha256 = scan.get(
        "native_bounded_process_reader_consumer_module_ast_sha256", {}
    )
    if not isinstance(raw_native_bounded_process_reader_consumer_module_ast_sha256, dict):
        raise SystemExit("native_bounded_process_reader_consumer_module_ast_sha256 must be a table")
    native_bounded_process_reader_consumer_module_ast_sha256 = {
        (repository / str(path)).resolve(): str(digest)
        for path, digest in raw_native_bounded_process_reader_consumer_module_ast_sha256.items()
    }
    native_bounded_process_allowed_binding_universe = frozenset(
        (f"{native_bounded_process_wrapper_module}:_run_bounded_process",)
    )
    raw_native_owned_file_descriptor_allowed_imports = scan.get(
        "native_owned_file_descriptor_allowed_imports", {}
    )
    if not isinstance(raw_native_owned_file_descriptor_allowed_imports, dict):
        raise SystemExit("native_owned_file_descriptor_allowed_imports must be a table")
    native_owned_file_descriptor_allowed_imports = {
        (repository / str(path)).resolve(): frozenset(str(binding) for binding in bindings)
        for path, bindings in raw_native_owned_file_descriptor_allowed_imports.items()
    }
    raw_native_owned_file_descriptor_captured_defaults = scan.get(
        "native_owned_file_descriptor_captured_defaults", {}
    )
    if not isinstance(raw_native_owned_file_descriptor_captured_defaults, dict):
        raise SystemExit("native_owned_file_descriptor_captured_defaults must be a table")
    native_owned_file_descriptor_captured_defaults: dict[
        Path,
        dict[str, dict[str, str]],
    ] = {}
    for raw_path, raw_functions in raw_native_owned_file_descriptor_captured_defaults.items():
        if not isinstance(raw_functions, dict):
            raise SystemExit(
                "native_owned_file_descriptor_captured_defaults paths must contain tables"
            )
        functions: dict[str, dict[str, str]] = {}
        for raw_function, raw_parameters in raw_functions.items():
            if not isinstance(raw_parameters, dict):
                raise SystemExit(
                    "native_owned_file_descriptor_captured_defaults functions must contain tables"
                )
            parameters: dict[str, str] = {}
            for raw_parameter, raw_origin in raw_parameters.items():
                if type(raw_origin) is not str:
                    raise SystemExit(
                        "native_owned_file_descriptor_captured_defaults origins must be strings"
                    )
                parameters[str(raw_parameter)] = raw_origin
            functions[str(raw_function)] = parameters
        native_owned_file_descriptor_captured_defaults[(repository / str(raw_path)).resolve()] = (
            functions
        )
    raw_native_owned_file_descriptor_captured_consumer_module_ast_sha256 = scan.get(
        "native_owned_file_descriptor_captured_consumer_module_ast_sha256", {}
    )
    if not isinstance(
        raw_native_owned_file_descriptor_captured_consumer_module_ast_sha256,
        dict,
    ):
        raise SystemExit(
            "native_owned_file_descriptor_captured_consumer_module_ast_sha256 must be a table"
        )
    native_owned_file_descriptor_captured_consumer_module_ast_sha256 = {
        (repository / str(path)).resolve(): str(digest)
        for path, digest in (
            raw_native_owned_file_descriptor_captured_consumer_module_ast_sha256.items()
        )
    }
    raw_native_owned_file_descriptor_owner_consumer_function_ast_sha256 = scan.get(
        "native_owned_file_descriptor_owner_consumer_function_ast_sha256", {}
    )
    if not isinstance(
        raw_native_owned_file_descriptor_owner_consumer_function_ast_sha256,
        dict,
    ):
        raise SystemExit(
            "native_owned_file_descriptor_owner_consumer_function_ast_sha256 must be a table"
        )
    native_owned_file_descriptor_owner_consumer_function_ast_sha256: dict[
        Path,
        dict[str, str],
    ] = {}
    for (
        raw_path,
        raw_functions,
    ) in raw_native_owned_file_descriptor_owner_consumer_function_ast_sha256.items():
        if not isinstance(raw_functions, dict) or any(
            type(digest) is not str for digest in raw_functions.values()
        ):
            raise SystemExit(
                "native_owned_file_descriptor_owner_consumer_function_ast_sha256 paths "
                "must contain string digest tables"
            )
        native_owned_file_descriptor_owner_consumer_function_ast_sha256[
            (repository / str(raw_path)).resolve()
        ] = {str(function): str(digest) for function, digest in raw_functions.items()}
    native_owned_file_descriptor_allowed_binding_universe = frozenset(
        f"{native_owned_file_descriptor_wrapper_module}:{name}"
        for name in (
            "_OwnedFileDescriptor",
            "_create_child_regular_exclusive",
            "_fchmod_0600",
            "_flock",
            "_fstat",
            "_fsync",
            "_ftruncate",
            "_list_snapshot",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
            "_write_all",
        )
    )
    primitive_roots = _resolve_roots(repository, scan["primitive_roots"])
    domain_roots = _resolve_roots(repository, scan["domain_roots"])
    side_effect_free_roots = _resolve_roots(repository, scan["side_effect_free_roots"])
    phase3h_proof_module = str(scan.get("phase3h_proof_module", ""))
    phase3h_proof_module_path = Path(str(scan.get("phase3h_proof_module_path", "")))
    phase3h_execution_module = str(scan.get("phase3h_execution_module", ""))
    phase3h_execution_module_path = Path(str(scan.get("phase3h_execution_module_path", "")))
    raw_phase3h_proof_consumer_allowed_imports = scan.get(
        "phase3h_proof_consumer_allowed_imports", []
    )
    if not isinstance(raw_phase3h_proof_consumer_allowed_imports, list) or any(
        type(binding) is not str for binding in raw_phase3h_proof_consumer_allowed_imports
    ):
        raise SystemExit("phase3h_proof_consumer_allowed_imports must be a string list")
    phase3h_proof_consumer_allowed_imports = frozenset(raw_phase3h_proof_consumer_allowed_imports)
    raw_phase3h_isolated_module_ast_sha256 = scan.get("phase3h_isolated_module_ast_sha256", {})
    if not isinstance(raw_phase3h_isolated_module_ast_sha256, dict) or any(
        type(path) is not str or type(digest) is not str
        for path, digest in raw_phase3h_isolated_module_ast_sha256.items()
    ):
        raise SystemExit("phase3h_isolated_module_ast_sha256 must be a string table")
    phase3h_isolated_module_ast_sha256 = {
        Path(path): digest for path, digest in raw_phase3h_isolated_module_ast_sha256.items()
    }
    raw_phase3h_dynamic_code_exception_module_ast_sha256 = scan.get(
        "phase3h_dynamic_code_exception_module_ast_sha256", {}
    )
    if not isinstance(raw_phase3h_dynamic_code_exception_module_ast_sha256, dict) or any(
        type(path) is not str or type(digest) is not str
        for path, digest in raw_phase3h_dynamic_code_exception_module_ast_sha256.items()
    ):
        raise SystemExit("phase3h_dynamic_code_exception_module_ast_sha256 must be a string table")
    phase3h_dynamic_code_exception_module_ast_sha256 = {
        Path(path): digest
        for path, digest in raw_phase3h_dynamic_code_exception_module_ast_sha256.items()
    }
    phase3h_policy_keys = frozenset(
        {
            "phase3h_proof_module",
            "phase3h_proof_module_path",
            "phase3h_execution_module",
            "phase3h_execution_module_path",
            "phase3h_proof_consumer_allowed_imports",
            "phase3h_isolated_module_ast_sha256",
            "phase3h_dynamic_code_exception_module_ast_sha256",
        }
    )
    phase3h_policy_keys_present = phase3h_policy_keys & scan.keys()
    raw_trusted_time_v2_isolated_module_paths = scan.get(
        "trusted_time_v2_isolated_module_paths", {}
    )
    if not isinstance(raw_trusted_time_v2_isolated_module_paths, dict) or any(
        type(module) is not str or type(path) is not str
        for module, path in raw_trusted_time_v2_isolated_module_paths.items()
    ):
        raise SystemExit("trusted_time_v2_isolated_module_paths must be a string table")
    trusted_time_v2_isolated_module_paths = {
        module: Path(path) for module, path in raw_trusted_time_v2_isolated_module_paths.items()
    }
    raw_trusted_time_v2_module_ast_sha256 = scan.get("trusted_time_v2_module_ast_sha256", {})
    if not isinstance(raw_trusted_time_v2_module_ast_sha256, dict) or any(
        type(path) is not str or type(digest) is not str
        for path, digest in raw_trusted_time_v2_module_ast_sha256.items()
    ):
        raise SystemExit("trusted_time_v2_module_ast_sha256 must be a string table")
    trusted_time_v2_module_ast_sha256 = {
        Path(path): digest for path, digest in raw_trusted_time_v2_module_ast_sha256.items()
    }
    raw_trusted_time_v2_allowed_imports = scan.get("trusted_time_v2_allowed_imports", {})
    if not isinstance(raw_trusted_time_v2_allowed_imports, dict) or any(
        type(path) is not str
        or not isinstance(bindings, list)
        or any(type(binding) is not str for binding in bindings)
        for path, bindings in raw_trusted_time_v2_allowed_imports.items()
    ):
        raise SystemExit("trusted_time_v2_allowed_imports must be a string-list table")
    trusted_time_v2_allowed_imports = {
        Path(path): frozenset(bindings)
        for path, bindings in raw_trusted_time_v2_allowed_imports.items()
    }
    raw_trusted_time_v2_reserved_symbols = scan.get("trusted_time_v2_reserved_symbols", [])
    if not isinstance(raw_trusted_time_v2_reserved_symbols, list) or any(
        type(symbol) is not str for symbol in raw_trusted_time_v2_reserved_symbols
    ):
        raise SystemExit("trusted_time_v2_reserved_symbols must be a string list")
    trusted_time_v2_reserved_symbols = frozenset(raw_trusted_time_v2_reserved_symbols)
    trusted_time_v2_policy_keys = frozenset(
        {
            "trusted_time_v2_isolated_module_paths",
            "trusted_time_v2_module_ast_sha256",
            "trusted_time_v2_allowed_imports",
            "trusted_time_v2_reserved_symbols",
        }
    )
    trusted_time_v2_policy_keys_present = trusted_time_v2_policy_keys & scan.keys()
    raw_exact_private_attribute_callsites = scan.get("exact_private_attribute_callsites", {})
    if not isinstance(raw_exact_private_attribute_callsites, dict) or any(
        type(binding) is not str
        or not isinstance(callsites, list)
        or any(type(callsite) is not str for callsite in callsites)
        for binding, callsites in raw_exact_private_attribute_callsites.items()
    ):
        raise SystemExit("exact_private_attribute_callsites must be a string-list table")
    exact_private_attribute_callsites = {
        binding: tuple(callsites)
        for binding, callsites in raw_exact_private_attribute_callsites.items()
    }
    raw_exact_private_attribute_owner_function_ast_sha256 = scan.get(
        "exact_private_attribute_owner_function_ast_sha256", {}
    )
    if not isinstance(raw_exact_private_attribute_owner_function_ast_sha256, dict) or any(
        type(owner) is not str or type(digest) is not str
        for owner, digest in raw_exact_private_attribute_owner_function_ast_sha256.items()
    ):
        raise SystemExit("exact_private_attribute_owner_function_ast_sha256 must be a string table")
    exact_private_attribute_owner_function_ast_sha256 = {
        owner: digest
        for owner, digest in raw_exact_private_attribute_owner_function_ast_sha256.items()
    }
    primitive_namespaces = tuple(scan["primitive_namespaces"])
    composition_namespaces = tuple(scan["composition_namespaces"])
    forbidden_domain_imports = tuple(scan["forbidden_domain_imports"])
    forbidden_side_effect_imports = tuple(scan["forbidden_side_effect_imports"])
    offline_public_artifact_roots = _resolve_roots(
        repository,
        scan.get("offline_public_artifact_roots", []),
    )
    forbidden_offline_public_artifact_imports = tuple(
        scan.get("forbidden_offline_public_artifact_imports", [])
    )
    forbidden_offline_public_artifact_symbols = frozenset(
        scan.get("forbidden_offline_public_artifact_symbols", [])
    )
    raw_offline_project_imports = scan.get("offline_public_artifact_allowed_project_imports", {})
    if not isinstance(raw_offline_project_imports, dict):
        raise SystemExit("offline_public_artifact_allowed_project_imports must be a table")
    offline_public_artifact_allowed_project_imports = {
        (repository / str(relative_root)).resolve(): frozenset(
            str(module) for module in allowed_modules
        )
        for relative_root, allowed_modules in raw_offline_project_imports.items()
    }
    offline_public_artifact_allowed_os_symbols = frozenset(
        scan.get("offline_public_artifact_allowed_os_symbols", [])
    )
    offline_public_artifact_ffi_roots = _resolve_roots(
        repository,
        scan.get("offline_public_artifact_ffi_roots", []),
    )
    offline_public_artifact_ffi_allowed_imports = frozenset(
        scan.get("offline_public_artifact_ffi_allowed_imports", [])
    )
    offline_public_artifact_ffi_allowed_symbols = frozenset(
        scan.get("offline_public_artifact_ffi_allowed_symbols", [])
    )
    offline_public_artifact_ffi_allowed_library_symbols = frozenset(
        scan.get("offline_public_artifact_ffi_allowed_library_symbols", [])
    )
    offline_public_artifact_ffi_library_factory = str(
        scan.get("offline_public_artifact_ffi_library_factory", "")
    )
    offline_public_artifact_ffi_library_binding = str(
        scan.get("offline_public_artifact_ffi_library_binding", "")
    )
    shutdown_locator_roots = _resolve_roots(
        repository,
        scan.get("shutdown_locator_roots", []),
    )
    forbidden_shutdown_locator_imports = tuple(scan.get("forbidden_shutdown_locator_imports", []))
    shutdown_locator_allowed_project_imports = frozenset(
        scan.get("shutdown_locator_allowed_project_imports", [])
    )
    forbidden_shutdown_locator_symbols = frozenset(
        scan.get("forbidden_shutdown_locator_symbols", [])
    )
    graceful_stop_structural_bridge_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_structural_bridge_roots", []),
    )
    forbidden_graceful_stop_structural_bridge_imports = tuple(
        scan.get("forbidden_graceful_stop_structural_bridge_imports", [])
    )
    graceful_stop_structural_bridge_allowed_project_imports = frozenset(
        scan.get("graceful_stop_structural_bridge_allowed_project_imports", [])
    )
    forbidden_graceful_stop_structural_bridge_symbols = frozenset(
        scan.get("forbidden_graceful_stop_structural_bridge_symbols", [])
    )
    graceful_stop_decision_artifact_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_decision_artifact_roots", []),
    )
    forbidden_graceful_stop_decision_artifact_imports = tuple(
        scan.get("forbidden_graceful_stop_decision_artifact_imports", [])
    )
    graceful_stop_decision_artifact_allowed_project_imports = frozenset(
        scan.get("graceful_stop_decision_artifact_allowed_project_imports", [])
    )
    graceful_stop_decision_artifact_allowed_stdlib_imports = frozenset(
        scan.get("graceful_stop_decision_artifact_allowed_stdlib_imports", [])
    )
    graceful_stop_decision_artifact_allowed_namespace_symbols = {
        str(namespace): frozenset(symbols)
        for namespace, symbols in scan.get(
            "graceful_stop_decision_artifact_allowed_namespace_symbols", {}
        ).items()
    }
    graceful_stop_decision_artifact_allowed_os_symbols = frozenset(
        scan.get("graceful_stop_decision_artifact_allowed_os_symbols", [])
    )
    graceful_stop_decision_artifact_audited_fs_namespace = str(
        scan.get("graceful_stop_decision_artifact_audited_fs_namespace", "")
    )
    graceful_stop_decision_artifact_allowed_audited_fs_symbols = frozenset(
        scan.get("graceful_stop_decision_artifact_allowed_audited_fs_symbols", [])
    )
    forbidden_graceful_stop_decision_artifact_symbols = frozenset(
        scan.get("forbidden_graceful_stop_decision_artifact_symbols", [])
    )
    clean_stop_terminal_reauthentication_roots = _resolve_roots(
        repository,
        scan.get("clean_stop_terminal_reauthentication_roots", []),
    )
    clean_stop_terminal_reauthentication_allowed_project_imports = frozenset(
        scan.get("clean_stop_terminal_reauthentication_allowed_project_imports", [])
    )
    clean_stop_terminal_reauthentication_allowed_nonproject_imports = frozenset(
        scan.get("clean_stop_terminal_reauthentication_allowed_nonproject_imports", [])
    )
    clean_stop_terminal_reauthentication_allowed_namespace_symbols = {
        str(namespace): frozenset(symbols)
        for namespace, symbols in scan.get(
            "clean_stop_terminal_reauthentication_allowed_namespace_symbols", {}
        ).items()
    }
    clean_stop_terminal_reauthentication_allowed_dynamic_attributes = frozenset(
        scan.get("clean_stop_terminal_reauthentication_allowed_dynamic_attributes", [])
    )
    forbidden_clean_stop_terminal_reauthentication_symbols = frozenset(
        scan.get("forbidden_clean_stop_terminal_reauthentication_symbols", [])
    )
    clean_stop_terminal_reauthentication_provider_class = str(
        scan.get("clean_stop_terminal_reauthentication_provider_class", "")
    )
    clean_stop_terminal_reauthentication_provider_methods = frozenset(
        scan.get("clean_stop_terminal_reauthentication_provider_methods", [])
    )
    clean_stop_terminal_reauthentication_provider_capabilities = frozenset(
        scan.get("clean_stop_terminal_reauthentication_provider_capabilities", [])
    )
    clean_stop_terminal_reauthentication_resources_class = str(
        scan.get("clean_stop_terminal_reauthentication_resources_class", "")
    )
    clean_stop_terminal_reauthentication_repository_capabilities = frozenset(
        scan.get("clean_stop_terminal_reauthentication_repository_capabilities", [])
    )
    clean_stop_terminal_reauthentication_private_reference_roots = _resolve_roots(
        repository,
        scan.get("clean_stop_terminal_reauthentication_private_reference_roots", []),
    )
    clean_stop_terminal_reauthentication_module = str(
        scan.get("clean_stop_terminal_reauthentication_module", "")
    )
    clean_stop_terminal_reauthentication_private_symbols = frozenset(
        scan.get("clean_stop_terminal_reauthentication_private_symbols", [])
    )
    graceful_stop_lifecycle_repository_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_lifecycle_repository_roots", []),
    )
    graceful_stop_lifecycle_repository_allowed_project_imports = frozenset(
        scan.get("graceful_stop_lifecycle_repository_allowed_project_imports", [])
    )
    graceful_stop_lifecycle_repository_allowed_nonproject_imports = frozenset(
        scan.get("graceful_stop_lifecycle_repository_allowed_nonproject_imports", [])
    )
    graceful_stop_lifecycle_repository_allowed_namespace_symbols = {
        str(namespace): frozenset(symbols)
        for namespace, symbols in scan.get(
            "graceful_stop_lifecycle_repository_allowed_namespace_symbols", {}
        ).items()
    }
    graceful_stop_lifecycle_repository_allowed_dynamic_attributes = frozenset(
        scan.get("graceful_stop_lifecycle_repository_allowed_dynamic_attributes", [])
    )
    graceful_stop_lifecycle_repository_ffi_library_factory = str(
        scan.get("graceful_stop_lifecycle_repository_ffi_library_factory", "")
    )
    graceful_stop_lifecycle_repository_ffi_library_binding = str(
        scan.get("graceful_stop_lifecycle_repository_ffi_library_binding", "")
    )
    graceful_stop_lifecycle_repository_ffi_functions = {
        str(binding): str(source)
        for binding, source in scan.get(
            "graceful_stop_lifecycle_repository_ffi_functions", {}
        ).items()
    }
    graceful_stop_lifecycle_repository_descriptor_class = str(
        scan.get("graceful_stop_lifecycle_repository_descriptor_class", "")
    )
    graceful_stop_lifecycle_repository_descriptor_methods = frozenset(
        scan.get("graceful_stop_lifecycle_repository_descriptor_methods", [])
    )
    graceful_stop_lifecycle_repository_class = str(
        scan.get("graceful_stop_lifecycle_repository_class", "")
    )
    graceful_stop_lifecycle_repository_methods = frozenset(
        scan.get("graceful_stop_lifecycle_repository_methods", [])
    )
    graceful_stop_lifecycle_repository_staging_unlink_function = str(
        scan.get("graceful_stop_lifecycle_repository_staging_unlink_function", "")
    )
    graceful_stop_lifecycle_repository_staging_names = frozenset(
        scan.get("graceful_stop_lifecycle_repository_staging_names", [])
    )
    graceful_stop_lifecycle_repository_flock_acquisitions = int(
        scan.get("graceful_stop_lifecycle_repository_flock_acquisitions", -1)
    )
    graceful_stop_lifecycle_repository_flock_unlocks = int(
        scan.get("graceful_stop_lifecycle_repository_flock_unlocks", -1)
    )
    forbidden_graceful_stop_lifecycle_repository_symbols = frozenset(
        scan.get("forbidden_graceful_stop_lifecycle_repository_symbols", [])
    )
    graceful_stop_lifecycle_repository_private_reference_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_lifecycle_repository_private_reference_roots", []),
    )
    graceful_stop_lifecycle_repository_module = str(
        scan.get("graceful_stop_lifecycle_repository_module", "")
    )
    graceful_stop_lifecycle_repository_private_symbols = frozenset(
        scan.get("graceful_stop_lifecycle_repository_private_symbols", [])
    )
    graceful_stop_lifecycle_repository_public_symbols = tuple(
        scan.get("graceful_stop_lifecycle_repository_public_symbols", [])
    )
    graceful_stop_lifecycle_repository_top_level_definitions = tuple(
        scan.get("graceful_stop_lifecycle_repository_top_level_definitions", [])
    )
    graceful_stop_lifecycle_repository_literal_constants = {
        str(name): str(value)
        for name, value in scan.get(
            "graceful_stop_lifecycle_repository_literal_constants", {}
        ).items()
    }
    graceful_stop_lifecycle_repository_enum_members = {
        str(class_name): {str(name): str(value) for name, value in members.items()}
        for class_name, members in scan.get(
            "graceful_stop_lifecycle_repository_enum_members", {}
        ).items()
    }
    graceful_stop_lifecycle_repository_forbidden_unqualified_calls = frozenset(
        scan.get("graceful_stop_lifecycle_repository_forbidden_unqualified_calls", [])
    )
    graceful_stop_lifecycle_repository_forbidden_method_calls = frozenset(
        scan.get("graceful_stop_lifecycle_repository_forbidden_method_calls", [])
    )
    graceful_stop_lifecycle_repository_allowed_qualified_method_calls = frozenset(
        scan.get("graceful_stop_lifecycle_repository_allowed_qualified_method_calls", [])
    )
    graceful_stop_lifecycle_repository_private_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "graceful_stop_lifecycle_repository_private_callsites", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_roots = _resolve_roots(
        repository,
        scan.get("operation_bound_clean_stop_bridge_roots", []),
    )
    operation_bound_clean_stop_bridge_module = str(
        scan.get("operation_bound_clean_stop_bridge_module", "")
    )
    operation_bound_clean_stop_bridge_module_ast_sha256 = str(
        scan.get("operation_bound_clean_stop_bridge_module_ast_sha256", "")
    )
    operation_bound_clean_stop_bridge_allowed_project_imports = frozenset(
        scan.get("operation_bound_clean_stop_bridge_allowed_project_imports", [])
    )
    operation_bound_clean_stop_bridge_allowed_nonproject_imports = frozenset(
        scan.get("operation_bound_clean_stop_bridge_allowed_nonproject_imports", [])
    )
    operation_bound_clean_stop_bridge_allowed_namespace_symbols = {
        str(namespace): frozenset(symbols)
        for namespace, symbols in scan.get(
            "operation_bound_clean_stop_bridge_allowed_namespace_symbols", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_public_symbols = tuple(
        scan.get("operation_bound_clean_stop_bridge_public_symbols", [])
    )
    operation_bound_clean_stop_bridge_private_symbols = frozenset(
        scan.get("operation_bound_clean_stop_bridge_private_symbols", [])
    )
    operation_bound_clean_stop_bridge_closed_fields = frozenset(
        scan.get("operation_bound_clean_stop_bridge_closed_fields", [])
    )
    operation_bound_clean_stop_bridge_true_payload_facts = {
        str(callable_name): frozenset(fields)
        for callable_name, fields in scan.get(
            "operation_bound_clean_stop_bridge_true_payload_facts", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_payload_callable_ast_sha256 = {
        str(callable_name): str(digest)
        for callable_name, digest in scan.get(
            "operation_bound_clean_stop_bridge_payload_callable_ast_sha256", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256 = {
        str(class_name): str(digest)
        for class_name, digest in scan.get(
            "operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_closed_evidence_class = str(
        scan.get("operation_bound_clean_stop_bridge_closed_evidence_class", "")
    )
    operation_bound_clean_stop_bridge_positive_evidence_class = str(
        scan.get("operation_bound_clean_stop_bridge_positive_evidence_class", "")
    )
    operation_bound_clean_stop_bridge_positive_properties = frozenset(
        scan.get("operation_bound_clean_stop_bridge_positive_properties", [])
    )
    operation_bound_clean_stop_bridge_positive_callable_names = frozenset(
        scan.get("operation_bound_clean_stop_bridge_positive_callable_names", [])
    )
    operation_bound_clean_stop_bridge_protected_function_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "operation_bound_clean_stop_bridge_protected_function_callsites", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_protected_closed_field_loads = (
        tuple(
            str(context)
            for context in scan["operation_bound_clean_stop_bridge_protected_closed_field_loads"]
        )
        if "operation_bound_clean_stop_bridge_protected_closed_field_loads" in scan
        else None
    )
    operation_bound_clean_stop_bridge_forbidden_symbols = frozenset(
        scan.get("operation_bound_clean_stop_bridge_forbidden_symbols", [])
    )
    operation_bound_clean_stop_bridge_forbidden_qualified_calls = frozenset(
        scan.get("operation_bound_clean_stop_bridge_forbidden_qualified_calls", [])
    )
    operation_bound_clean_stop_bridge_forbidden_qualified_call_isinstance_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "operation_bound_clean_stop_bridge_forbidden_qualified_call_isinstance_callsites",
            {},
        ).items()
    }
    operation_bound_clean_stop_bridge_allowed_imports = {
        (repository / str(path)).resolve(): frozenset(bindings)
        for path, bindings in scan.get(
            "operation_bound_clean_stop_bridge_allowed_imports", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_clean_stop_owner_roots = _resolve_roots(
        repository,
        scan.get("operation_bound_clean_stop_bridge_clean_stop_owner_roots", []),
    )
    operation_bound_clean_stop_bridge_clean_stop_private_symbols = frozenset(
        scan.get("operation_bound_clean_stop_bridge_clean_stop_private_symbols", [])
    )
    operation_bound_clean_stop_bridge_worker_private_owner_roots = _resolve_roots(
        repository,
        scan.get("operation_bound_clean_stop_bridge_worker_private_owner_roots", []),
    )
    operation_bound_clean_stop_bridge_worker_private_symbols = frozenset(
        scan.get("operation_bound_clean_stop_bridge_worker_private_symbols", [])
    )
    operation_bound_clean_stop_bridge_literal_constants = {
        str(name): str(value)
        for name, value in scan.get(
            "operation_bound_clean_stop_bridge_literal_constants", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_protected_function_bindings = frozenset(
        scan.get("operation_bound_clean_stop_bridge_protected_function_bindings", [])
    )
    operation_bound_clean_stop_bridge_private_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "operation_bound_clean_stop_bridge_private_callsites", {}
        ).items()
    }
    operation_bound_clean_stop_bridge_worker_private_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "operation_bound_clean_stop_bridge_worker_private_callsites", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_supervisor_bridge_roots", []),
    )
    graceful_stop_supervisor_bridge_module = str(
        scan.get("graceful_stop_supervisor_bridge_module", "")
    )
    graceful_stop_supervisor_bridge_module_ast_sha256 = str(
        scan.get("graceful_stop_supervisor_bridge_module_ast_sha256", "")
    )
    graceful_stop_supervisor_bridge_allowed_project_imports = frozenset(
        scan.get("graceful_stop_supervisor_bridge_allowed_project_imports", [])
    )
    graceful_stop_supervisor_bridge_allowed_nonproject_imports = frozenset(
        scan.get("graceful_stop_supervisor_bridge_allowed_nonproject_imports", [])
    )
    graceful_stop_supervisor_bridge_allowed_namespace_symbols = {
        str(namespace): frozenset(symbols)
        for namespace, symbols in scan.get(
            "graceful_stop_supervisor_bridge_allowed_namespace_symbols", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_public_symbols = tuple(
        scan.get("graceful_stop_supervisor_bridge_public_symbols", [])
    )
    graceful_stop_supervisor_bridge_private_symbols = frozenset(
        scan.get("graceful_stop_supervisor_bridge_private_symbols", [])
    )
    graceful_stop_supervisor_bridge_closed_fields = frozenset(
        scan.get("graceful_stop_supervisor_bridge_closed_fields", [])
    )
    graceful_stop_supervisor_bridge_true_payload_facts = {
        str(callable_name): frozenset(fields)
        for callable_name, fields in scan.get(
            "graceful_stop_supervisor_bridge_true_payload_facts", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_payload_callable_ast_sha256 = {
        str(callable_name): str(digest)
        for callable_name, digest in scan.get(
            "graceful_stop_supervisor_bridge_payload_callable_ast_sha256", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_payload_owner_class_ast_sha256 = {
        str(class_name): str(digest)
        for class_name, digest in scan.get(
            "graceful_stop_supervisor_bridge_payload_owner_class_ast_sha256", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_closed_evidence_class = str(
        scan.get("graceful_stop_supervisor_bridge_closed_evidence_class", "")
    )
    graceful_stop_supervisor_bridge_positive_evidence_class = str(
        scan.get("graceful_stop_supervisor_bridge_positive_evidence_class", "")
    )
    graceful_stop_supervisor_bridge_positive_properties = frozenset(
        scan.get("graceful_stop_supervisor_bridge_positive_properties", [])
    )
    graceful_stop_supervisor_bridge_positive_callable_names = frozenset(
        scan.get("graceful_stop_supervisor_bridge_positive_callable_names", [])
    )
    graceful_stop_supervisor_bridge_protected_function_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "graceful_stop_supervisor_bridge_protected_function_callsites", {}
        ).items()
    }
    graceful_stop_supervisor_bridge_protected_closed_field_loads = (
        tuple(
            str(context)
            for context in scan["graceful_stop_supervisor_bridge_protected_closed_field_loads"]
        )
        if "graceful_stop_supervisor_bridge_protected_closed_field_loads" in scan
        else None
    )
    graceful_stop_supervisor_bridge_external_private_symbols = frozenset(
        scan.get("graceful_stop_supervisor_bridge_external_private_symbols", [])
    )
    graceful_stop_supervisor_bridge_forbidden_symbols = frozenset(
        scan.get("graceful_stop_supervisor_bridge_forbidden_symbols", [])
    )
    graceful_stop_supervisor_bridge_forbidden_qualified_calls = frozenset(
        scan.get("graceful_stop_supervisor_bridge_forbidden_qualified_calls", [])
    )
    graceful_stop_supervisor_bridge_forbidden_qualified_call_isinstance_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "graceful_stop_supervisor_bridge_forbidden_qualified_call_isinstance_callsites",
            {},
        ).items()
    }
    graceful_stop_supervisor_bridge_forbidden_path_methods = frozenset(
        scan.get("graceful_stop_supervisor_bridge_forbidden_path_methods", [])
    )
    graceful_stop_supervisor_bridge_dependency_private_owner_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_supervisor_bridge_dependency_private_owner_roots", []),
    )
    graceful_stop_supervisor_bridge_dependency_private_symbols = frozenset(
        scan.get("graceful_stop_supervisor_bridge_dependency_private_symbols", [])
    )
    graceful_stop_supervisor_bridge_lifecycle_owner_roots = _resolve_roots(
        repository,
        scan.get("graceful_stop_supervisor_bridge_lifecycle_owner_roots", []),
    )
    graceful_stop_supervisor_bridge_lifecycle_symbols = frozenset(
        scan.get("graceful_stop_supervisor_bridge_lifecycle_symbols", [])
    )
    graceful_stop_supervisor_bridge_literal_constants = {
        str(name): str(value)
        for name, value in scan.get("graceful_stop_supervisor_bridge_literal_constants", {}).items()
    }
    graceful_stop_supervisor_bridge_protected_function_bindings = frozenset(
        scan.get("graceful_stop_supervisor_bridge_protected_function_bindings", [])
    )
    graceful_stop_supervisor_bridge_private_callsites = {
        str(binding): tuple(str(callsite) for callsite in callsites)
        for binding, callsites in scan.get(
            "graceful_stop_supervisor_bridge_private_callsites", {}
        ).items()
    }

    violations: list[Violation] = []
    if phase3h_policy_keys_present and phase3h_policy_keys_present != phase3h_policy_keys:
        violations.append(
            Violation(
                config_path,
                1,
                "Phase 3H isolated proof policy must be entirely present or absent",
            )
        )
    if (
        trusted_time_v2_policy_keys_present
        and trusted_time_v2_policy_keys_present != trusted_time_v2_policy_keys
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "trusted-time lifecycle-v2 milestone policy must be entirely present or absent",
            )
        )
    native_owned_file_descriptor_captured_call_counts: dict[
        Path,
        dict[str, dict[str, int]],
    ] = {}
    native_owned_file_descriptor_captured_owner_consumers: dict[
        Path,
        dict[str, dict[str, tuple[str, int]]],
    ] = {}
    production_contract_required = (repository / "infra/architecture-boundaries.toml").is_file()
    if production_contract_required:
        violations.extend(
            _architecture_checker_invocation_source_sha256_violations(
                repository,
                config_path,
                architecture_checker_invocation_source_sha256,
            )
        )
        violations.extend(_architecture_checker_invocation_violations(repository))
        expected_bootstrap_paths = (
            ".python-version",
            "pyproject.toml",
            "uv.lock",
            "build_support/build_native_test_launcher.py",
            "build_support/native_build_constraints.txt",
            "build_support/native_image_manifest.py",
            "build_support/native_owned_file_descriptor_hook.py",
            "native/bounded_process.c",
            "native/owned_file_descriptor.c",
            "native/trusted_time_python_launcher.c",
        )
        expected_forbidden_paths = (
            "MANIFEST.in",
            "hatch.toml",
            "setup.cfg",
            "setup.py",
            "uv.toml",
        )
        bootstrap_keys = {key for key in scan if key.startswith("project_build_bootstrap_")}
        bootstrap_config_valid = (
            project_build_bootstrap_manifest_paths == expected_bootstrap_paths
            and project_build_bootstrap_forbidden_paths == expected_forbidden_paths
            and bootstrap_keys
            == {
                "project_build_bootstrap_manifest_paths",
                "project_build_bootstrap_manifest_sha256",
                "project_build_bootstrap_forbidden_paths",
            }
            and re.fullmatch(r"[0-9a-f]{64}", project_build_bootstrap_manifest_sha256) is not None
        )
        if not bootstrap_config_valid:
            violations.append(
                Violation(
                    config_path,
                    1,
                    "project build bootstrap manifest must be mandatory and exact",
                )
            )
        else:
            try:
                observed_bootstrap_sha256 = _project_build_bootstrap_manifest_sha256(
                    repository,
                    project_build_bootstrap_manifest_paths,
                )
            except (OSError, UnicodeError, ValueError) as error:
                violations.append(
                    Violation(
                        config_path,
                        getattr(error, "lineno", 1) or 1,
                        "project build bootstrap manifest cannot be constructed",
                    )
                )
            else:
                if observed_bootstrap_sha256 != project_build_bootstrap_manifest_sha256:
                    violations.append(
                        Violation(
                            config_path,
                            1,
                            "project build bootstrap manifest must match every reviewed input",
                        )
                    )
        for forbidden_path in expected_forbidden_paths:
            candidate = repository / forbidden_path
            if candidate.exists() or candidate.is_symlink():
                violations.append(
                    Violation(
                        Path(forbidden_path),
                        1,
                        "alternate local project build configuration is forbidden",
                    )
                )
        violations.extend(_project_build_bootstrap_configuration_violations(repository))
    operation_bound_bridge_module_config_violations = _module_ast_sha256_config_violations(
        repository=repository,
        config_path=config_path,
        boundary="operation-bound clean-stop bridge",
        roots=operation_bound_clean_stop_bridge_roots,
        module_name=operation_bound_clean_stop_bridge_module,
        expected_sha256=operation_bound_clean_stop_bridge_module_ast_sha256,
        required=production_contract_required,
    )
    host_bridge_module_config_violations = _module_ast_sha256_config_violations(
        repository=repository,
        config_path=config_path,
        boundary="dormant graceful-stop supervisor bridge",
        roots=graceful_stop_supervisor_bridge_roots,
        module_name=graceful_stop_supervisor_bridge_module,
        expected_sha256=graceful_stop_supervisor_bridge_module_ast_sha256,
        required=production_contract_required,
    )
    native_wrapper_module_config_violations = _module_ast_sha256_config_violations(
        repository=repository,
        config_path=config_path,
        boundary="private native owned-file-descriptor wrapper",
        roots=native_owned_file_descriptor_wrapper_roots,
        module_name=native_owned_file_descriptor_wrapper_module,
        expected_sha256=native_owned_file_descriptor_wrapper_module_ast_sha256,
        required=production_contract_required,
    )
    bounded_process_wrapper_module_config_violations = _module_ast_sha256_config_violations(
        repository=repository,
        config_path=config_path,
        boundary="private native bounded-process wrapper",
        roots=native_bounded_process_wrapper_roots,
        module_name=native_bounded_process_wrapper_module,
        expected_sha256=native_bounded_process_wrapper_module_ast_sha256,
        required=production_contract_required,
    )
    violations.extend(operation_bound_bridge_module_config_violations)
    violations.extend(host_bridge_module_config_violations)
    violations.extend(native_wrapper_module_config_violations)
    violations.extend(bounded_process_wrapper_module_config_violations)
    if production_contract_required:
        expected_native_consumer_paths = {
            "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
            "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
            "scripts/trusted_time_post_enrollment_controller_outcome.py",
            "scripts/trusted_time_post_enrollment_execution_admission.py",
            "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py",
            "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
            "scripts/verify_trusted_time_images.py",
        }
        try:
            configured_native_consumer_paths = {
                path.relative_to(repository).as_posix()
                for path in native_owned_file_descriptor_allowed_imports
            }
        except ValueError:
            configured_native_consumer_paths = set()
        configured_native_bindings = frozenset(
            binding
            for bindings in native_owned_file_descriptor_allowed_imports.values()
            for binding in bindings
        )
        if (
            configured_native_consumer_paths != expected_native_consumer_paths
            or not configured_native_bindings
            or not configured_native_bindings.issubset(
                native_owned_file_descriptor_allowed_binding_universe
            )
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native owned-file-descriptor consumer map must be exact",
                )
            )
        expected_native_captured_default_origins = {
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_absences",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_absences",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
                "_open_regular_exact",
            ): "_open_child_regular",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
                "_read_snapshot_exact",
            ): "_read_snapshot",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_open_tmp_context",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_open_tmp_context",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
                "_open_root",
            ): "_open_root_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
                "_open_directory",
            ): "_open_child_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
                "_open_root",
            ): "_open_root_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
                "_open_directory",
            ): "_open_child_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
                "_open_root",
            ): "_open_root_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
                "_open_directory",
            ): "_open_child_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
                "_open_regular_exact",
            ): "_open_child_regular",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
                "_read_snapshot_exact",
            ): "_read_snapshot",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_absences",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_absences",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_tmp_context",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_tmp_context",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
                "_open_root",
            ): "_open_root_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
                "_open_directory",
            ): "_open_child_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
                "_statat_exact",
            ): "_statat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
                "_open_root",
            ): "_open_root_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
                "_open_directory",
            ): "_open_child_directory",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
                "_fstat_exact",
            ): "_fstat",
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
                "_statat_exact",
            ): "_statat",
        }
        expected_native_captured_function_call_counts = {
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_absences",
            ): {"_fstat_exact": 2, "_statat_exact": 1},
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
            ): {
                "_fstat_exact": 4,
                "_statat_exact": 2,
                "_open_regular_exact": 1,
                "_read_snapshot_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_require_open_tmp_context",
            ): {"_fstat_exact": 2, "_statat_exact": 1},
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
            ): {
                "_open_root": 1,
                "_open_directory": 1,
                "_fstat_exact": 2,
                "_statat_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
            ): {
                "_open_root": 1,
                "_open_directory": 1,
                "_fstat_exact": 2,
                "_statat_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
            ): {
                "_open_root": 1,
                "_open_directory": 1,
                "_fstat_exact": 2,
                "_statat_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
            ): {
                "_fstat_exact": 4,
                "_statat_exact": 2,
                "_open_regular_exact": 1,
                "_read_snapshot_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_absences",
            ): {"_fstat_exact": 2, "_statat_exact": 1},
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_require_tmp_context",
            ): {"_fstat_exact": 2, "_statat_exact": 1},
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
            ): {
                "_open_root": 1,
                "_open_directory": 1,
                "_fstat_exact": 2,
                "_statat_exact": 1,
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
            ): {
                "_open_root": 1,
                "_open_directory": 4,
                "_fstat_exact": 10,
                "_statat_exact": 8,
            },
        }
        for (
            relative,
            function,
        ), function_call_counts in expected_native_captured_function_call_counts.items():
            native_owned_file_descriptor_captured_call_counts.setdefault(
                (repository / relative).resolve(), {}
            )[function] = dict(function_call_counts)
        expected_native_captured_owner_helper_consumers = {
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_read_marker",
            ): {"_cleanup": ("_cleanup_native_owners", 2)},
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_staged_barrier_bytes",
            ): {
                "_observe_absences": ("_require_absences", 2),
                "_observe_marker": ("_read_marker", 1),
                "_require_context": ("_require_open_tmp_context", 1),
                "_cleanup": ("_cleanup_native_owners", 2),
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_pre_effect_runtime_absence_bytes",
            ): {
                "_observe_absences": ("_require_absences", 2),
                "_require_context": ("_require_open_tmp_context", 1),
                "_cleanup": ("_cleanup_native_owners", 2),
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
                "_persistent_barrier_bytes",
            ): {
                "_observe_absences": ("_require_absences", 2),
                "_observe_marker": ("_read_marker", 4),
                "_require_context": ("_require_open_tmp_context", 1),
                "_cleanup": ("_cleanup_native_owners", 2),
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_regular_snapshot",
            ): {"_cleanup": ("_cleanup_native_owners", 2)},
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_tmp_snapshot",
            ): {
                "_read_regular": ("_read_regular_snapshot", 1),
                "_observe_absences": ("_require_absences", 2),
                "_require_context": ("_require_tmp_context", 1),
                "_cleanup": ("_cleanup_native_owners", 2),
            },
            (
                "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
                "_read_boot_id_snapshot",
            ): {
                "_read_regular": ("_read_regular_snapshot", 1),
                "_cleanup": ("_cleanup_native_owners", 2),
            },
        }
        for (
            relative,
            function,
        ), helper_consumers in expected_native_captured_owner_helper_consumers.items():
            path = (repository / relative).resolve()
            native_owned_file_descriptor_captured_owner_consumers.setdefault(path, {})[function] = (
                dict(helper_consumers)
            )
        configured_native_captured_defaults: dict[tuple[str, str, str], str] = {}
        try:
            for path, functions in native_owned_file_descriptor_captured_defaults.items():
                relative = path.relative_to(repository).as_posix()
                for function, parameters in functions.items():
                    for parameter, binding in parameters.items():
                        configured_native_captured_defaults[(relative, function, parameter)] = (
                            binding
                        )
        except ValueError:
            configured_native_captured_defaults = {}
        expected_native_captured_defaults = {
            key: f"{native_owned_file_descriptor_wrapper_module}:{origin}"
            for key, origin in expected_native_captured_default_origins.items()
        }
        if configured_native_captured_defaults != expected_native_captured_defaults:
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native owned-file-descriptor captured-default map must be exact",
                )
            )
        expected_native_captured_consumer_modules = {
            "apps/trusted_time_supervisor/post_enrollment_read_probes.py",
            "apps/trusted_time_supervisor/post_enrollment_runtime_state.py",
        }
        try:
            configured_native_captured_consumer_modules = {
                path.relative_to(repository).as_posix(): digest
                for path, digest in (
                    native_owned_file_descriptor_captured_consumer_module_ast_sha256.items()
                )
            }
        except ValueError:
            configured_native_captured_consumer_modules = {}
        if set(
            configured_native_captured_consumer_modules
        ) != expected_native_captured_consumer_modules or any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in configured_native_captured_consumer_modules.values()
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native captured-default consumer module AST map must be exact",
                )
            )
        expected_native_owner_consumer_functions = {
            "apps/trusted_time_supervisor/post_enrollment_read_probes.py": {
                "_cleanup_native_owners",
                "_require_absences",
                "_read_marker",
                "_require_open_tmp_context",
                "_staged_barrier_bytes",
                "_pre_effect_runtime_absence_bytes",
                "_persistent_barrier_bytes",
            },
            "apps/trusted_time_supervisor/post_enrollment_runtime_state.py": {
                "_cleanup_native_owners",
                "_read_regular_snapshot",
                "_require_absences",
                "_require_tmp_context",
                "_read_tmp_snapshot",
                "_read_boot_id_snapshot",
            },
        }
        try:
            configured_native_owner_consumer_functions = {
                path.relative_to(repository).as_posix(): set(functions)
                for path, functions in (
                    native_owned_file_descriptor_owner_consumer_function_ast_sha256.items()
                )
            }
        except ValueError:
            configured_native_owner_consumer_functions = {}
        configured_native_owner_consumer_digests = {
            digest
            for functions in (
                native_owned_file_descriptor_owner_consumer_function_ast_sha256.values()
            )
            for digest in functions.values()
        }
        if (
            configured_native_owner_consumer_functions != expected_native_owner_consumer_functions
            or any(
                re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in configured_native_owner_consumer_digests
            )
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native owner-consumer function AST map must be exact",
                )
            )
        expected_bounded_process_consumer_paths = {"scripts/verify_trusted_time_images.py"}
        try:
            configured_bounded_process_consumer_paths = {
                path.relative_to(repository).as_posix()
                for path in native_bounded_process_allowed_imports
            }
        except ValueError:
            configured_bounded_process_consumer_paths = set()
        configured_bounded_process_bindings = frozenset(
            binding
            for bindings in native_bounded_process_allowed_imports.values()
            for binding in bindings
        )
        if (
            configured_bounded_process_consumer_paths != expected_bounded_process_consumer_paths
            or configured_bounded_process_bindings
            != native_bounded_process_allowed_binding_universe
            or frozenset(native_bounded_process_consumer_function_ast_sha256)
            != frozenset(native_bounded_process_allowed_imports)
            or frozenset(native_bounded_process_consumer_module_ast_sha256)
            != frozenset(native_bounded_process_allowed_imports)
            or any(
                re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in (
                    *native_bounded_process_consumer_function_ast_sha256.values(),
                    *native_bounded_process_consumer_module_ast_sha256.values(),
                )
            )
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native bounded-process consumer map must be exact",
                )
            )
        expected_bounded_process_reader_consumers = {
            "scripts/trusted_time_post_enrollment_execution_admission.py"
        }
        expected_bounded_process_reader_binding = frozenset(
            {"scripts.verify_trusted_time_images:_head_reviewed_operator_authority_object"}
        )
        try:
            configured_bounded_process_reader_consumers = {
                path.relative_to(repository).as_posix()
                for path in native_bounded_process_reader_allowed_imports
            }
        except ValueError:
            configured_bounded_process_reader_consumers = set()
        if (
            configured_bounded_process_reader_consumers != expected_bounded_process_reader_consumers
            or frozenset(native_bounded_process_reader_consumer_module_ast_sha256)
            != frozenset(native_bounded_process_reader_allowed_imports)
            or any(
                bindings != expected_bounded_process_reader_binding
                for bindings in native_bounded_process_reader_allowed_imports.values()
            )
            or any(
                re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in native_bounded_process_reader_consumer_module_ast_sha256.values()
            )
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native bounded-process Git reader consumer map must be exact",
                )
            )
        try:
            configured_reflection_attestations = {
                path.relative_to(repository): attestations
                for path, attestations in native_bounded_process_reflection_attestations.items()
            }
            configured_reflection_module_digests = {
                path.relative_to(repository): digest
                for path, digest in (native_bounded_process_reflection_module_ast_sha256.items())
            }
        except ValueError:
            configured_reflection_attestations = {}
            configured_reflection_module_digests = {}
        if (
            configured_reflection_attestations != _NATIVE_BOUNDED_PROCESS_REFLECTION_ATTESTATIONS
            or configured_reflection_module_digests
            != _NATIVE_BOUNDED_PROCESS_REFLECTION_MODULE_AST_SHA256
        ):
            violations.append(
                Violation(
                    config_path,
                    1,
                    "private native bounded-process reflection attestations must be exact",
                )
            )
    expected_phase3h_proof_module = "packages.domain.fixture_segment_economics"
    expected_phase3h_proof_module_path = Path("packages/domain/fixture_segment_economics.py")
    expected_phase3h_execution_module = "packages.application.fixture_segment_economics"
    expected_phase3h_execution_module_path = Path(
        "packages/application/fixture_segment_economics.py"
    )
    expected_phase3h_proof_consumer_allowed_imports = frozenset(
        {
            f"{expected_phase3h_proof_module}:{symbol}"
            for symbol in {
                "FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS",
                "FIXTURE_ECONOMIC_CHILD_PROCESSES",
                "FIXTURE_ECONOMIC_CPU_SECONDS",
                "FIXTURE_ECONOMIC_FILE_BYTES",
                "FIXTURE_ECONOMIC_OPEN_FILES",
                "FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION",
                "FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS",
                "MAX_FIXTURE_ECONOMIC_REQUEST_BYTES",
                "MAX_FIXTURE_ECONOMIC_STDERR_BYTES",
                "MAX_FIXTURE_ECONOMIC_STDOUT_BYTES",
                "FixtureEconomicPosition",
                "FixtureEconomicProcessEvidence",
                "FixtureEconomicProcessOutcome",
                "FixtureEconomicSegmentError",
                "FixtureEconomicSegmentReceipt",
                "FixtureEconomicSegmentRequest",
                "FixtureEconomicSegmentResult",
                "bind_fixture_economic_request",
                "fixture_economic_isolation_profile_sha256",
            }
        }
    )
    expected_phase3h_isolated_module_ast_sha256 = {
        expected_phase3h_proof_module_path: (
            "89054d8462035a86f3d219caf0ab5dd23ac394c25f0d3a5bbd2c54c94cf7009d"
        ),
        expected_phase3h_execution_module_path: (
            "4f758b154fa063fee92d4f4f1483a1348a5167661e1f30ec03a59eaa1c4c0fe7"
        ),
    }
    expected_phase3h_dynamic_code_exception_module_ast_sha256 = {
        Path("packages/domain/_trusted_time_post_enrollment_projection_bootstrap.py"): (
            "59bfdea9c8740d0df92b00bb74fc619d69b0593196b5e53fb39709ba7cae3df6"
        ),
        Path("scripts/trusted_time_post_enrollment_topology_reader.py"): (
            "a38808e452a92cad0fc63141bb234c579357b07ddb1f17f78bd00b3ca57cef48"
        ),
        Path("scripts/migrate_phase6_trusted_time_head_anchors.py"): (
            "ab1c04fb83c15383970b5e0a23dad1bc0d65ec24fc42c60ef02b0bca3cdedf9c"
        ),
        Path("scripts/migrate_phase6_trusted_time_uncertainty.py"): (
            "a1d6f39be3585af028cc7905e14057d13626f4f92603e3365b16745f39bc2d6d"
        ),
    }
    if production_contract_required and (
        phase3h_proof_module != expected_phase3h_proof_module
        or phase3h_proof_module_path != expected_phase3h_proof_module_path
        or phase3h_execution_module != expected_phase3h_execution_module
        or phase3h_execution_module_path != expected_phase3h_execution_module_path
        or phase3h_proof_consumer_allowed_imports != expected_phase3h_proof_consumer_allowed_imports
        or phase3h_isolated_module_ast_sha256 != expected_phase3h_isolated_module_ast_sha256
        or phase3h_dynamic_code_exception_module_ast_sha256
        != expected_phase3h_dynamic_code_exception_module_ast_sha256
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "Phase 3H isolated proof-module policy must be exact",
            )
        )
    expected_trusted_time_v2_isolated_module_paths = {
        "packages.domain.trusted_time_graceful_stop_v2": Path(
            "packages/domain/trusted_time_graceful_stop_v2.py"
        ),
        "packages.persistence.trusted_time_graceful_stop_v2": Path(
            "packages/persistence/trusted_time_graceful_stop_v2.py"
        ),
        "packages.application.trusted_time_graceful_stop_v2_admission": Path(
            "packages/application/trusted_time_graceful_stop_v2_admission.py"
        ),
        "scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts": Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
        ),
    }
    expected_trusted_time_v2_module_ast_sha256 = {
        Path("packages/domain/trusted_time_graceful_stop_v2.py"): (
            "9e53f33c3655803171ae965ef27393234da1989ba93ef5e25bcfbf33b2980344"
        ),
        Path("packages/persistence/trusted_time_graceful_stop_v2.py"): (
            "8ae95ad12303fb60958392aa9cf58c5d4f609473544af51334e51a685a9bac4b"
        ),
        Path("packages/application/trusted_time_graceful_stop_v2_admission.py"): (
            "50f2b6207fbb0b449e1d3cbcdc40258f74d2fc35ced0cb0a3a9918213019b4b1"
        ),
        Path("scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"): (
            "5625b64548122370b3822cc796cc88cbcfb192dcc92fa6ae99496222c66c17ee"
        ),
    }
    trusted_time_v2_domain_module = "packages.domain.trusted_time_graceful_stop_v2"
    trusted_time_v2_bridge_module = (
        "scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts"
    )
    expected_trusted_time_v2_allowed_imports = {
        Path("packages/persistence/trusted_time_graceful_stop_v2.py"): frozenset(
            f"{trusted_time_v2_domain_module}:{symbol}"
            for symbol in {
                "LIFECYCLE_ROOT_FILE_NAME",
                "LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME",
                "LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION",
                "LIFECYCLE_V2_ROOT_CONTRACT_VERSION",
                "NORMAL_STAGE_BY_ORDINAL",
                "LifecycleV2CleanStopRequestBasis",
                "LifecycleV2Outcome",
                "LifecycleV2OutcomeCommit",
                "LifecycleV2ProgressRecord",
                "LifecycleV2Root",
                "LifecycleV2Stage",
                "LifecycleV2Transcript",
                "LifecycleV2TranscriptEntry",
                "TrustedTimeGracefulStopV2Rejected",
                "UnverifiedLifecycleV2TransportEnvelope",
                "_FakeAuthenticatedLifecycleV2TransportEnvelope",
                "_require_fake_authenticated_lifecycle_v2_transport_envelope",
                "decode_lifecycle_v2_clean_stop_request_basis",
                "decode_lifecycle_v2_outcome",
                "decode_lifecycle_v2_outcome_commit",
                "decode_lifecycle_v2_progress_record",
                "decode_lifecycle_v2_root",
                "decode_lifecycle_v2_transcript",
                "decode_unverified_lifecycle_v2_transport_envelope",
                "lifecycle_v2_progress_file_name",
                "lifecycle_v2_wire_file_name",
            }
        ),
        Path("packages/application/trusted_time_graceful_stop_v2_admission.py"): frozenset(
            f"{trusted_time_v2_bridge_module}:{symbol}"
            for symbol in {
                "LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
                "_ConsumedLoadedDecisionArtifactReceiptV2Snapshot",
                "_LIFECYCLE_V2_BRIDGE_CAPABILITY",
                "_consume_loaded_decision_receipt_for_v2",
                "_reject_loaded_decision_receipt_for_v2_admission_identity",
                "_require_consumed_loaded_decision_artifact_receipt_v2_snapshot",
            }
        ),
        Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"): (
            frozenset(
                f"{trusted_time_v2_bridge_module}:{symbol}"
                for symbol in {
                    "ARTIFACT_RECEIPT_CONTRACT_VERSION",
                    "ARTIFACT_WORKFLOW_SERVICE",
                    "DECISION_CANDIDATE_PREPARED_STATUS",
                    "LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
                    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS",
                    "_ConsumedLoadedDecisionArtifactReceiptSnapshot",
                    "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
                    "_require_consumed_loaded_decision_artifact_receipt_snapshot",
                }
            )
        ),
    }
    expected_trusted_time_v2_reserved_symbols = frozenset(
        {
            "_ADMISSION_IDENTITY_CAPABILITY",
            "_ConsumedLoadedDecisionArtifactReceiptV2Snapshot",
            "_CONSUMED_LOADED_RECEIPT_V2_SNAPSHOT_CAPABILITY",
            "_consume_historical_receipt_for_injected_lifecycle_v2_admission",
            "_consume_loaded_decision_receipt_for_v2",
            "_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY",
            "_FakeAuthenticatedLifecycleV2TransportEnvelope",
            "_LifecycleV2AdmissionIdentity",
            "_LIFECYCLE_V2_BRIDGE_CAPABILITY",
            "_open_injected_lifecycle_v2_repository",
            "_reject_loaded_decision_receipt_for_v2_admission_identity",
            "_require_consumed_loaded_decision_artifact_receipt_v2_snapshot",
            "_require_fake_authenticated_lifecycle_v2_transport_envelope",
            "_retain_progress",
            "_authenticate_lifecycle_v2_transport_envelope_for_fake",
            "_build_injected_lifecycle_v2_admission_identity",
        }
    )
    if production_contract_required and (
        trusted_time_v2_isolated_module_paths != expected_trusted_time_v2_isolated_module_paths
        or trusted_time_v2_module_ast_sha256 != expected_trusted_time_v2_module_ast_sha256
        or trusted_time_v2_allowed_imports != expected_trusted_time_v2_allowed_imports
        or trusted_time_v2_reserved_symbols != expected_trusted_time_v2_reserved_symbols
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "trusted-time lifecycle-v2 milestone isolation policy must be exact",
            )
        )
    expected_exact_private_attribute_callsites = {
        (
            "packages.domain.fixture_segment_economics."
            "FixtureEconomicProcessEvidence._from_supervisor"
        ): ("packages/application/fixture_segment_economics.py:execute_fixture_segment_economics",),
        (
            "packages.domain.fixture_segment_economics."
            "FixtureEconomicSegmentReceipt._from_verified_execution"
        ): ("packages/application/fixture_segment_economics.py:execute_fixture_segment_economics",),
    }
    expected_exact_private_attribute_owner_function_ast_sha256 = {
        "packages/application/fixture_segment_economics.py:execute_fixture_segment_economics": (
            "2949180a4df9d000fd97f4bfb254e5810ab90df7e88c033f35d413815d3457a7"
        ),
    }
    if production_contract_required and (
        exact_private_attribute_callsites != expected_exact_private_attribute_callsites
        or exact_private_attribute_owner_function_ast_sha256
        != expected_exact_private_attribute_owner_function_ast_sha256
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private proof-minting attribute callsite map must be exact",
            )
        )
    production_manifest_required = production_contract_required
    if production_manifest_required:
        manifest_keys = {
            key for key in scan if key.startswith("production_python_source_manifest_")
        }
        manifest_config_valid = (
            production_python_source_manifest_root_values == ("apps", "packages", "scripts")
            and production_python_source_manifest_pruned_values == ("apps/web/node_modules",)
            and manifest_keys
            == {
                "production_python_source_manifest_roots",
                "production_python_source_manifest_pruned_subtrees",
                "production_python_source_manifest_sha256",
            }
            and re.fullmatch(r"[0-9a-f]{64}", production_python_source_manifest_sha256) is not None
        )
        if not manifest_config_valid:
            violations.append(
                Violation(
                    config_path,
                    1,
                    "production Python source manifest must be mandatory and exact",
                )
            )
        else:
            try:
                observed_manifest_sha256 = _production_python_source_manifest_sha256(
                    repository,
                    production_python_source_manifest_roots,
                    production_python_source_manifest_pruned_subtrees,
                )
            except (OSError, SyntaxError, UnicodeError, ValueError) as error:
                violations.append(
                    Violation(
                        config_path,
                        getattr(error, "lineno", 1) or 1,
                        "production Python source manifest cannot be constructed",
                    )
                )
            else:
                if observed_manifest_sha256 != production_python_source_manifest_sha256:
                    violations.append(
                        Violation(
                            config_path,
                            1,
                            "production Python source manifest must match every reviewed source",
                        )
                    )
    builtin_integrity_files = reviewed_python_files(
        builtin_namespace_integrity_roots
    ) - reviewed_python_files(builtin_namespace_integrity_excluded_roots)
    configured_builtin_integrity_files = (
        frozenset(builtin_namespace_integrity_allowed_imports)
        | frozenset(builtin_namespace_integrity_allowed_reads)
        | frozenset(builtin_namespace_integrity_sys_modules_callsites)
    )
    if not configured_builtin_integrity_files.issubset(builtin_integrity_files):
        violations.append(
            Violation(
                config_path,
                1,
                "production builtin namespace integrity config must name scanned files",
            )
        )
    for path in sorted(builtin_integrity_files):
        relative_path = path.relative_to(repository)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
        except (OSError, SyntaxError, UnicodeError) as error:
            violations.append(
                Violation(
                    relative_path,
                    getattr(error, "lineno", 1) or 1,
                    f"cannot parse file: {getattr(error, 'msg', str(error))}",
                )
            )
            continue
        violations.extend(
            _builtin_namespace_integrity_violations(
                tree,
                relative_path=relative_path,
                allowed_imports=builtin_namespace_integrity_allowed_imports.get(path, ()),
                allowed_reads=builtin_namespace_integrity_allowed_reads.get(path, ()),
                allowed_sys_modules_callsites=(
                    builtin_namespace_integrity_sys_modules_callsites.get(path, ())
                ),
            )
        )
    native_capability_files = reviewed_python_files(production_python_source_manifest_roots)
    violations.extend(
        _trusted_time_topology_launch_lock_violations(
            repository=repository,
            config_path=config_path,
            scan=scan,
            production_files=native_capability_files,
        )
    )
    native_captured_functions_by_module = {
        path.relative_to(repository).with_suffix("").as_posix().replace("/", "."): frozenset(
            functions
        )
        for path, functions in native_owned_file_descriptor_captured_defaults.items()
        if path.is_relative_to(repository)
    }
    if not frozenset(native_owned_file_descriptor_allowed_imports).issubset(
        native_capability_files
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private native owned-file-descriptor consumer config must name scanned files",
            )
        )
    if not frozenset(native_owned_file_descriptor_captured_defaults).issubset(
        frozenset(native_owned_file_descriptor_allowed_imports)
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private native owned-file-descriptor captured-default config must name "
                "reviewed consumers",
            )
        )
    if frozenset(native_owned_file_descriptor_captured_consumer_module_ast_sha256) != frozenset(
        native_owned_file_descriptor_captured_defaults
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private native captured-default consumer module AST config must exactly name "
                "captured consumers",
            )
        )
    if not frozenset(native_owned_file_descriptor_owner_consumer_function_ast_sha256).issubset(
        frozenset(native_owned_file_descriptor_captured_defaults)
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private native owner-consumer function AST config must name captured consumers",
            )
        )
    if not frozenset(native_bounded_process_allowed_imports).issubset(native_capability_files):
        violations.append(
            Violation(
                config_path,
                1,
                "private native bounded-process consumer config must name scanned files",
            )
        )
    if not frozenset(native_bounded_process_reader_allowed_imports).issubset(
        native_capability_files
    ):
        violations.append(
            Violation(
                config_path,
                1,
                "private native bounded-process Git reader config must name scanned files",
            )
        )
    native_wrapper_relative_path = (
        Path(*native_owned_file_descriptor_wrapper_module.split(".")).with_suffix(".py")
        if native_owned_file_descriptor_wrapper_module
        else Path("__absent_native_wrapper__.py")
    )
    bounded_process_wrapper_relative_path = (
        Path(*native_bounded_process_wrapper_module.split(".")).with_suffix(".py")
        if native_bounded_process_wrapper_module
        else Path("__absent_bounded_process_wrapper__.py")
    )
    for path in sorted(native_capability_files):
        relative_path = path.relative_to(repository)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
        except (OSError, SyntaxError, UnicodeError) as error:
            violations.append(
                Violation(
                    relative_path,
                    getattr(error, "lineno", 1) or 1,
                    f"cannot parse file: {getattr(error, 'msg', str(error))}",
                )
            )
            continue
        violations.extend(
            _exact_private_attribute_callsite_violations(
                tree,
                relative_path=relative_path,
                boundary="reviewed private proof-minting seam",
                expected=exact_private_attribute_callsites,
                owner_function_ast_sha256=(exact_private_attribute_owner_function_ast_sha256),
            )
        )
        violations.extend(
            _phase3h_proof_boundary_violations(
                tree,
                policy_enabled=phase3h_policy_keys_present == phase3h_policy_keys,
                relative_path=relative_path,
                proof_module=phase3h_proof_module,
                proof_path=phase3h_proof_module_path,
                execution_module=phase3h_execution_module,
                execution_path=phase3h_execution_module_path,
                allowed_proof_imports=phase3h_proof_consumer_allowed_imports,
                module_ast_sha256=phase3h_isolated_module_ast_sha256,
                dynamic_code_exception_module_ast_sha256=(
                    phase3h_dynamic_code_exception_module_ast_sha256
                ),
            )
        )
        violations.extend(
            _isolated_wave5_module_boundary_violations(
                tree,
                boundary="trusted-time lifecycle-v2 milestone-one boundary",
                policy_enabled=(trusted_time_v2_policy_keys_present == trusted_time_v2_policy_keys),
                relative_path=relative_path,
                module_paths=trusted_time_v2_isolated_module_paths,
                allowed_imports=trusted_time_v2_allowed_imports,
                module_ast_sha256=trusted_time_v2_module_ast_sha256,
                reserved_symbols=trusted_time_v2_reserved_symbols,
            )
        )
        expected_process_consumer_module_digest = (
            native_bounded_process_consumer_module_ast_sha256.get(path)
        )
        if (
            expected_process_consumer_module_digest is not None
            and _canonical_ast_sha256(tree) != expected_process_consumer_module_digest
        ):
            violations.append(
                Violation(
                    relative_path,
                    1,
                    "native bounded-process consumer must preserve its exact module AST",
                )
            )
        expected_reader_consumer_module_digest = (
            native_bounded_process_reader_consumer_module_ast_sha256.get(path)
        )
        if (
            expected_reader_consumer_module_digest is not None
            and _canonical_ast_sha256(tree) != expected_reader_consumer_module_digest
        ):
            violations.append(
                Violation(
                    relative_path,
                    1,
                    "native bounded-process Git reader consumer must preserve its exact module AST",
                )
            )
        expected_owner_consumer_digests = (
            native_owned_file_descriptor_owner_consumer_function_ast_sha256.get(path, {})
        )
        expected_captured_consumer_module_digest = (
            native_owned_file_descriptor_captured_consumer_module_ast_sha256.get(path)
        )
        if (
            expected_captured_consumer_module_digest is not None
            and _canonical_ast_sha256(tree) != expected_captured_consumer_module_digest
        ):
            violations.append(
                Violation(
                    relative_path,
                    1,
                    "native captured-default consumer must preserve its exact module AST",
                )
            )
        top_level_functions = {
            node.name: node
            for node in getattr(tree, "body", ())
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for function_name, expected_digest in expected_owner_consumer_digests.items():
            owner_function_node = top_level_functions.get(function_name)
            if (
                owner_function_node is None
                or _canonical_ast_sha256(owner_function_node) != expected_digest
            ):
                violations.append(
                    Violation(
                        relative_path,
                        getattr(owner_function_node, "lineno", 1),
                        "native owner-consuming helper must preserve its exact function AST: "
                        f"'{function_name}'",
                    )
                )
        if relative_path != Path("scripts/trusted_time_post_enrollment_topology_reader.py"):
            violations.extend(
                _exact_origin_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="private native owned-file-descriptor capability",
                    module=native_owned_file_descriptor_wrapper_module,
                    allowed=native_owned_file_descriptor_allowed_imports.get(path, frozenset()),
                )
            )
            violations.extend(
                _native_owned_file_descriptor_usage_violations(
                    tree,
                    relative_path=relative_path,
                    module=native_owned_file_descriptor_wrapper_module,
                    captured_defaults=native_owned_file_descriptor_captured_defaults.get(path, {}),
                    captured_call_counts=(
                        native_owned_file_descriptor_captured_call_counts.get(path, {})
                    ),
                    captured_owner_consumers=(
                        native_owned_file_descriptor_captured_owner_consumers.get(path, {})
                    ),
                )
            )
        violations.extend(
            _native_captured_function_import_violations(
                tree,
                relative_path=relative_path,
                protected_functions=native_captured_functions_by_module,
            )
        )
        if path in native_owned_file_descriptor_captured_defaults:
            violations.extend(
                _native_captured_consumer_reflection_violations(
                    tree,
                    relative_path=relative_path,
                )
            )
        violations.extend(
            _exact_origin_module_import_violations(
                tree,
                relative_path=relative_path,
                boundary="private native bounded-process capability",
                module=native_bounded_process_wrapper_module,
                allowed=native_bounded_process_allowed_imports.get(path, frozenset()),
            )
        )
        violations.extend(
            _native_bounded_process_usage_violations(
                tree,
                relative_path=relative_path,
                module=native_bounded_process_wrapper_module,
                expected_call_count=(3 if path in native_bounded_process_allowed_imports else 0),
                expected_function_ast_sha256=(
                    native_bounded_process_consumer_function_ast_sha256.get(path, "")
                ),
            )
        )
        allowed_reflection_nodes, reflection_attestation_violations = (
            _native_bounded_process_reflection_attestation_nodes(
                tree,
                relative_path=relative_path,
                expected_attestations=native_bounded_process_reflection_attestations.get(path, ()),
                expected_module_ast_sha256=(
                    native_bounded_process_reflection_module_ast_sha256.get(path, "")
                ),
            )
        )
        violations.extend(reflection_attestation_violations)
        if relative_path not in {
            bounded_process_wrapper_relative_path,
            Path("scripts/check_architecture.py"),
        }:
            violations.extend(
                _native_bounded_process_reserved_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    wrapper_module=native_bounded_process_wrapper_module,
                    allowed_consumer=path in native_bounded_process_allowed_imports,
                    allowed_reflection_nodes=allowed_reflection_nodes,
                )
            )
            violations.extend(
                _native_bounded_process_reader_usage_violations(
                    tree,
                    relative_path=relative_path,
                    owner_module="scripts.verify_trusted_time_images",
                    allowed_consumer=path in native_bounded_process_reader_allowed_imports,
                )
            )
        violations.extend(
            _native_executable_loading_violations(
                tree,
                relative_path=relative_path,
                wrapper_path=native_wrapper_relative_path,
                wrapper_module=native_owned_file_descriptor_wrapper_module,
                image_import_root=(
                    bool(relative_path.parts) and relative_path.parts[0] in {"apps", "packages"}
                ),
            )
        )
        if (
            _is_below(path.resolve(), native_owned_file_descriptor_wrapper_roots)
            and native_owned_file_descriptor_wrapper_module_ast_sha256
            and not native_wrapper_module_config_violations
        ):
            violations.extend(
                _exact_module_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="private native owned-file-descriptor wrapper",
                    expected_sha256=(native_owned_file_descriptor_wrapper_module_ast_sha256),
                )
            )
        if (
            _is_below(path.resolve(), native_bounded_process_wrapper_roots)
            and native_bounded_process_wrapper_module_ast_sha256
            and not bounded_process_wrapper_module_config_violations
        ):
            violations.extend(
                _exact_module_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="private native bounded-process wrapper",
                    expected_sha256=native_bounded_process_wrapper_module_ast_sha256,
                )
            )
    python_files = sorted(
        reviewed_python_files(source_roots)
        | reviewed_python_files(offline_public_artifact_roots)
        | reviewed_python_files(shutdown_locator_roots)
        | reviewed_python_files(graceful_stop_structural_bridge_roots)
        | reviewed_python_files(graceful_stop_decision_artifact_roots)
        | reviewed_python_files(clean_stop_terminal_reauthentication_roots)
        | reviewed_python_files(clean_stop_terminal_reauthentication_private_reference_roots)
        | reviewed_python_files(graceful_stop_lifecycle_repository_roots)
        | reviewed_python_files(graceful_stop_lifecycle_repository_private_reference_roots)
        | reviewed_python_files(operation_bound_clean_stop_bridge_roots)
        | frozenset(operation_bound_clean_stop_bridge_allowed_imports)
        | reviewed_python_files(operation_bound_clean_stop_bridge_clean_stop_owner_roots)
        | reviewed_python_files(operation_bound_clean_stop_bridge_worker_private_owner_roots)
        | reviewed_python_files(graceful_stop_supervisor_bridge_roots)
        | reviewed_python_files(graceful_stop_supervisor_bridge_dependency_private_owner_roots)
        | reviewed_python_files(graceful_stop_supervisor_bridge_lifecycle_owner_roots)
    )

    for path in python_files:
        resolved_path = path.resolve()
        relative_path = path.relative_to(repository)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative_path))
        except (OSError, SyntaxError, UnicodeError) as error:
            violations.append(
                Violation(
                    relative_path,
                    getattr(error, "lineno", 1) or 1,
                    f"cannot parse file: {getattr(error, 'msg', str(error))}",
                )
            )
            continue

        is_operation_bound_clean_stop_bridge_root = _is_below(
            resolved_path,
            operation_bound_clean_stop_bridge_roots,
        )
        if is_operation_bound_clean_stop_bridge_root:
            bridge_boundary = "operation-bound clean-stop bridge"
            if (
                operation_bound_clean_stop_bridge_module_ast_sha256
                and not operation_bound_bridge_module_config_violations
            ):
                violations.extend(
                    _exact_module_ast_sha256_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=bridge_boundary,
                        expected_sha256=(operation_bound_clean_stop_bridge_module_ast_sha256),
                    )
                )
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    allowed=operation_bound_clean_stop_bridge_allowed_project_imports,
                )
            )
            violations.extend(
                _exact_nonproject_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    allowed=operation_bound_clean_stop_bridge_allowed_nonproject_imports,
                )
            )
            violations.extend(
                _exact_dunder_all_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    allowed=operation_bound_clean_stop_bridge_public_symbols,
                )
            )
            violations.extend(
                _exact_literal_assignment_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=operation_bound_clean_stop_bridge_literal_constants,
                )
            )
            violations.extend(
                _protected_module_binding_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    protected=frozenset(
                        {
                            "__all__",
                            "_CLOSED_FIELDS",
                            *operation_bound_clean_stop_bridge_literal_constants,
                            *operation_bound_clean_stop_bridge_protected_function_bindings,
                        }
                    ),
                    function_bindings=(
                        operation_bound_clean_stop_bridge_protected_function_bindings
                    ),
                    function_callsites=(
                        operation_bound_clean_stop_bridge_protected_function_callsites
                    ),
                    closed_field_loads=(
                        operation_bound_clean_stop_bridge_protected_closed_field_loads
                    ),
                )
            )
            violations.extend(
                _private_symbol_presence_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=operation_bound_clean_stop_bridge_private_symbols,
                )
            )
            violations.extend(
                _exact_frozenset_assignment_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    name="_CLOSED_FIELDS",
                    expected=operation_bound_clean_stop_bridge_closed_fields,
                )
            )
            violations.extend(
                _exact_closed_payload_builder_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                )
            )
            violations.extend(
                _exact_callable_true_payload_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=operation_bound_clean_stop_bridge_true_payload_facts,
                )
            )
            violations.extend(
                _exact_callable_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=(operation_bound_clean_stop_bridge_payload_callable_ast_sha256),
                )
            )
            violations.extend(
                _exact_ast_owner_class_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=(operation_bound_clean_stop_bridge_payload_callable_ast_sha256),
                )
            )
            violations.extend(
                _exact_class_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=(operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256),
                    required_classes=frozenset(
                        qualified_name.rpartition(".")[0]
                        for qualified_name in (
                            operation_bound_clean_stop_bridge_payload_callable_ast_sha256
                        )
                        if "." in qualified_name
                    ),
                )
            )
            if (
                operation_bound_clean_stop_bridge_closed_evidence_class
                or operation_bound_clean_stop_bridge_positive_evidence_class
                or operation_bound_clean_stop_bridge_positive_properties
                or operation_bound_clean_stop_bridge_positive_callable_names
            ):
                violations.extend(
                    _exact_evidence_property_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=bridge_boundary,
                        closed_class_name=(operation_bound_clean_stop_bridge_closed_evidence_class),
                        closed_fields=operation_bound_clean_stop_bridge_closed_fields,
                        positive_class_name=(
                            operation_bound_clean_stop_bridge_positive_evidence_class
                        ),
                        positive_properties=(operation_bound_clean_stop_bridge_positive_properties),
                        positive_callable_names=(
                            operation_bound_clean_stop_bridge_positive_callable_names
                        ),
                    )
                )
            violations.extend(
                _exact_private_callsite_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    expected=operation_bound_clean_stop_bridge_private_callsites,
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    forbidden=operation_bound_clean_stop_bridge_forbidden_symbols,
                )
            )
            violations.extend(
                _forbidden_qualified_call_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=bridge_boundary,
                    forbidden=(operation_bound_clean_stop_bridge_forbidden_qualified_calls),
                    allowed_isinstance_callsites=(
                        operation_bound_clean_stop_bridge_forbidden_qualified_call_isinstance_callsites
                    ),
                )
            )
            for (
                namespace,
                allowed_symbols,
            ) in operation_bound_clean_stop_bridge_allowed_namespace_symbols.items():
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=bridge_boundary,
                        namespace=namespace,
                        allowed=allowed_symbols,
                        kind="standard-library API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=bridge_boundary,
                        namespace=namespace,
                    )
                )

        is_graceful_stop_supervisor_bridge_root = _is_below(
            resolved_path,
            graceful_stop_supervisor_bridge_roots,
        )
        if is_graceful_stop_supervisor_bridge_root:
            host_bridge_boundary = "dormant graceful-stop supervisor bridge"
            if (
                graceful_stop_supervisor_bridge_module_ast_sha256
                and not host_bridge_module_config_violations
            ):
                violations.extend(
                    _exact_module_ast_sha256_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=host_bridge_boundary,
                        expected_sha256=graceful_stop_supervisor_bridge_module_ast_sha256,
                    )
                )
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    allowed=graceful_stop_supervisor_bridge_allowed_project_imports,
                )
            )
            violations.extend(
                _exact_nonproject_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    allowed=graceful_stop_supervisor_bridge_allowed_nonproject_imports,
                )
            )
            violations.extend(
                _exact_dunder_all_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    allowed=graceful_stop_supervisor_bridge_public_symbols,
                )
            )
            violations.extend(
                _exact_literal_assignment_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_literal_constants,
                )
            )
            violations.extend(
                _protected_module_binding_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    protected=frozenset(
                        {
                            "__all__",
                            "_CLOSED_FIELDS",
                            *graceful_stop_supervisor_bridge_literal_constants,
                            *graceful_stop_supervisor_bridge_protected_function_bindings,
                        }
                    ),
                    function_bindings=(graceful_stop_supervisor_bridge_protected_function_bindings),
                    function_callsites=(
                        graceful_stop_supervisor_bridge_protected_function_callsites
                    ),
                    closed_field_loads=(
                        graceful_stop_supervisor_bridge_protected_closed_field_loads
                    ),
                )
            )
            violations.extend(
                _private_symbol_presence_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_private_symbols,
                )
            )
            violations.extend(
                _exact_frozenset_assignment_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    name="_CLOSED_FIELDS",
                    expected=graceful_stop_supervisor_bridge_closed_fields,
                )
            )
            violations.extend(
                _exact_closed_payload_builder_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                )
            )
            violations.extend(
                _exact_callable_true_payload_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_true_payload_facts,
                )
            )
            violations.extend(
                _exact_callable_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_payload_callable_ast_sha256,
                )
            )
            violations.extend(
                _exact_ast_owner_class_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_payload_callable_ast_sha256,
                )
            )
            violations.extend(
                _exact_class_ast_sha256_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_payload_owner_class_ast_sha256,
                    required_classes=frozenset(
                        qualified_name.rpartition(".")[0]
                        for qualified_name in (
                            graceful_stop_supervisor_bridge_payload_callable_ast_sha256
                        )
                        if "." in qualified_name
                    ),
                )
            )
            if (
                graceful_stop_supervisor_bridge_closed_evidence_class
                or graceful_stop_supervisor_bridge_positive_evidence_class
                or graceful_stop_supervisor_bridge_positive_properties
                or graceful_stop_supervisor_bridge_positive_callable_names
            ):
                violations.extend(
                    _exact_evidence_property_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=host_bridge_boundary,
                        closed_class_name=(graceful_stop_supervisor_bridge_closed_evidence_class),
                        closed_fields=graceful_stop_supervisor_bridge_closed_fields,
                        positive_class_name=(
                            graceful_stop_supervisor_bridge_positive_evidence_class
                        ),
                        positive_properties=(graceful_stop_supervisor_bridge_positive_properties),
                        positive_callable_names=(
                            graceful_stop_supervisor_bridge_positive_callable_names
                        ),
                    )
                )
            violations.extend(
                _exact_private_callsite_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    expected=graceful_stop_supervisor_bridge_private_callsites,
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    forbidden=graceful_stop_supervisor_bridge_forbidden_symbols,
                )
            )
            violations.extend(
                _forbidden_qualified_call_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    forbidden=graceful_stop_supervisor_bridge_forbidden_qualified_calls,
                    allowed_isinstance_callsites=(
                        graceful_stop_supervisor_bridge_forbidden_qualified_call_isinstance_callsites
                    ),
                )
            )
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                    forbidden=graceful_stop_supervisor_bridge_forbidden_path_methods,
                )
            )
            violations.extend(
                _exact_utc_suffix_replace_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=host_bridge_boundary,
                )
            )
            for (
                namespace,
                allowed_symbols,
            ) in graceful_stop_supervisor_bridge_allowed_namespace_symbols.items():
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=host_bridge_boundary,
                        namespace=namespace,
                        allowed=allowed_symbols,
                        kind="standard-library API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=host_bridge_boundary,
                        namespace=namespace,
                    )
                )

        is_clean_stop_terminal_reauthentication_root = _is_below(
            resolved_path,
            clean_stop_terminal_reauthentication_roots,
        )
        if is_clean_stop_terminal_reauthentication_root:
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="clean-stop terminal reauthentication issuer",
                    allowed=(clean_stop_terminal_reauthentication_allowed_project_imports),
                )
            )
            violations.extend(
                _exact_nonproject_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="clean-stop terminal reauthentication issuer",
                    allowed=(clean_stop_terminal_reauthentication_allowed_nonproject_imports),
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="clean-stop terminal reauthentication issuer",
                    forbidden=forbidden_clean_stop_terminal_reauthentication_symbols,
                )
            )
            violations.extend(
                _dynamic_attribute_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="clean-stop terminal reauthentication issuer",
                    allowed=(clean_stop_terminal_reauthentication_allowed_dynamic_attributes),
                )
            )
            for (
                namespace,
                allowed_symbols,
            ) in clean_stop_terminal_reauthentication_allowed_namespace_symbols.items():
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="clean-stop terminal reauthentication issuer",
                        namespace=namespace,
                        allowed=allowed_symbols,
                        kind="namespace API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="clean-stop terminal reauthentication issuer",
                        namespace=namespace,
                    )
                )
            if clean_stop_terminal_reauthentication_provider_class:
                violations.extend(
                    _exact_class_method_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="clean-stop terminal read-only provider",
                        class_name=clean_stop_terminal_reauthentication_provider_class,
                        allowed=clean_stop_terminal_reauthentication_provider_methods,
                    )
                )
                violations.extend(
                    _exact_self_owned_attribute_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="clean-stop terminal read-only provider",
                        class_name=clean_stop_terminal_reauthentication_provider_class,
                        owner_attribute="_provider",
                        allowed=clean_stop_terminal_reauthentication_provider_capabilities,
                    )
                )
            if clean_stop_terminal_reauthentication_resources_class:
                violations.extend(
                    _exact_self_owned_attribute_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="clean-stop terminal SQL observer",
                        class_name=clean_stop_terminal_reauthentication_resources_class,
                        owner_attribute="_repository",
                        allowed=clean_stop_terminal_reauthentication_repository_capabilities,
                    )
                )

        is_graceful_stop_lifecycle_repository_root = _is_below(
            resolved_path,
            graceful_stop_lifecycle_repository_roots,
        )
        if is_graceful_stop_lifecycle_repository_root:
            lifecycle_boundary = "dormant graceful-stop lifecycle repository"
            violations.extend(
                _exact_top_level_definition_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    allowed=graceful_stop_lifecycle_repository_top_level_definitions,
                )
            )
            violations.extend(
                _exact_literal_assignment_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    expected=graceful_stop_lifecycle_repository_literal_constants,
                )
            )
            violations.extend(
                _exact_enum_member_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    expected=graceful_stop_lifecycle_repository_enum_members,
                )
            )
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    allowed=graceful_stop_lifecycle_repository_allowed_project_imports,
                )
            )
            violations.extend(
                _exact_nonproject_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    allowed=graceful_stop_lifecycle_repository_allowed_nonproject_imports,
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    forbidden=forbidden_graceful_stop_lifecycle_repository_symbols,
                )
            )
            violations.extend(
                _dynamic_attribute_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    allowed=graceful_stop_lifecycle_repository_allowed_dynamic_attributes,
                )
            )
            violations.extend(
                _reviewed_filesystem_call_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    forbidden_unqualified=(
                        graceful_stop_lifecycle_repository_forbidden_unqualified_calls
                    ),
                    forbidden_methods=(graceful_stop_lifecycle_repository_forbidden_method_calls),
                    allowed_qualified=(
                        graceful_stop_lifecycle_repository_allowed_qualified_method_calls
                    ),
                )
            )
            for (
                namespace,
                allowed_symbols,
            ) in graceful_stop_lifecycle_repository_allowed_namespace_symbols.items():
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        namespace=namespace,
                        allowed=allowed_symbols,
                        kind="filesystem/FFI API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        namespace=namespace,
                    )
                )
            violations.extend(
                _exact_dunder_all_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    allowed=graceful_stop_lifecycle_repository_public_symbols,
                )
            )
            if (
                graceful_stop_lifecycle_repository_ffi_library_factory
                and graceful_stop_lifecycle_repository_ffi_library_binding
            ):
                violations.extend(
                    _ffi_library_binding_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        factory=graceful_stop_lifecycle_repository_ffi_library_factory,
                        binding=graceful_stop_lifecycle_repository_ffi_library_binding,
                    )
                )
            if graceful_stop_lifecycle_repository_ffi_functions:
                violations.extend(
                    _exact_ffi_function_binding_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        bindings=graceful_stop_lifecycle_repository_ffi_functions,
                    )
                )
            if graceful_stop_lifecycle_repository_descriptor_class:
                violations.extend(
                    _exact_class_method_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        class_name=graceful_stop_lifecycle_repository_descriptor_class,
                        allowed=graceful_stop_lifecycle_repository_descriptor_methods,
                    )
                )
            if graceful_stop_lifecycle_repository_class:
                violations.extend(
                    _exact_class_method_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        class_name=graceful_stop_lifecycle_repository_class,
                        allowed=graceful_stop_lifecycle_repository_methods,
                    )
                )
            if graceful_stop_lifecycle_repository_staging_unlink_function:
                violations.extend(
                    _fixed_staging_unlink_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        publisher=(graceful_stop_lifecycle_repository_staging_unlink_function),
                        staging_names=graceful_stop_lifecycle_repository_staging_names,
                    )
                )
            if (
                graceful_stop_lifecycle_repository_flock_acquisitions >= 0
                and graceful_stop_lifecycle_repository_flock_unlocks >= 0
            ):
                violations.extend(
                    _nonblocking_flock_violations(
                        tree,
                        relative_path=relative_path,
                        boundary=lifecycle_boundary,
                        expected_acquisitions=(
                            graceful_stop_lifecycle_repository_flock_acquisitions
                        ),
                        expected_unlocks=graceful_stop_lifecycle_repository_flock_unlocks,
                    )
                )
            violations.extend(
                _private_symbol_presence_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    expected=graceful_stop_lifecycle_repository_private_symbols,
                )
            )
            violations.extend(
                _exact_private_callsite_violations(
                    tree,
                    relative_path=relative_path,
                    boundary=lifecycle_boundary,
                    expected=graceful_stop_lifecycle_repository_private_callsites,
                )
            )
        if (
            clean_stop_terminal_reauthentication_module
            and not is_clean_stop_terminal_reauthentication_root
            and not is_graceful_stop_supervisor_bridge_root
            and _is_below(
                resolved_path,
                clean_stop_terminal_reauthentication_private_reference_roots,
            )
        ):
            violations.extend(
                _forbidden_project_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    forbidden_module=clean_stop_terminal_reauthentication_module,
                )
            )
            violations.extend(
                _forbidden_module_private_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    module=clean_stop_terminal_reauthentication_module,
                    forbidden=clean_stop_terminal_reauthentication_private_symbols,
                )
            )

        if (
            graceful_stop_lifecycle_repository_module
            and not is_graceful_stop_lifecycle_repository_root
            and not is_graceful_stop_supervisor_bridge_root
            and _is_below(
                resolved_path,
                graceful_stop_lifecycle_repository_private_reference_roots,
            )
        ):
            violations.extend(
                _forbidden_project_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    forbidden_module=graceful_stop_lifecycle_repository_module,
                )
            )
            violations.extend(
                _forbidden_module_private_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    module=graceful_stop_lifecycle_repository_module,
                    forbidden=graceful_stop_lifecycle_repository_private_symbols,
                )
            )

        reviewed_bridge_imports = operation_bound_clean_stop_bridge_allowed_imports.get(
            resolved_path
        )
        if reviewed_bridge_imports is not None:
            violations.extend(
                _exact_origin_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="reviewed operation-bound bridge consumer",
                    module=operation_bound_clean_stop_bridge_module,
                    allowed=reviewed_bridge_imports,
                )
            )
        elif (
            operation_bound_clean_stop_bridge_module
            and not is_operation_bound_clean_stop_bridge_root
        ):
            violations.extend(
                _forbidden_project_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    forbidden_module=operation_bound_clean_stop_bridge_module,
                )
            )

        if (
            not is_operation_bound_clean_stop_bridge_root
            and resolved_path not in operation_bound_clean_stop_bridge_allowed_imports
        ):
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected operation-bound bridge code",
                    forbidden=frozenset(operation_bound_clean_stop_bridge_public_symbols),
                )
            )
        reviewed_private_bridge_consumer = reviewed_bridge_imports is not None and any(
            binding.rpartition(":")[2] in operation_bound_clean_stop_bridge_private_symbols
            for binding in reviewed_bridge_imports
        )
        if not is_operation_bound_clean_stop_bridge_root and not reviewed_private_bridge_consumer:
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected operation-bound bridge code",
                    forbidden=operation_bound_clean_stop_bridge_private_symbols,
                )
            )

        if not _is_below(
            resolved_path,
            operation_bound_clean_stop_bridge_clean_stop_owner_roots,
        ):
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected ADR 0108 bridge code",
                    forbidden=(operation_bound_clean_stop_bridge_clean_stop_private_symbols),
                )
            )
        if not _is_below(
            resolved_path,
            operation_bound_clean_stop_bridge_worker_private_owner_roots,
        ):
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected worker control code",
                    forbidden=operation_bound_clean_stop_bridge_worker_private_symbols,
                )
            )
        else:
            violations.extend(
                _exact_private_callsite_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="operation-bound worker bridge",
                    expected=operation_bound_clean_stop_bridge_worker_private_callsites,
                )
            )

        if graceful_stop_supervisor_bridge_module and not is_graceful_stop_supervisor_bridge_root:
            violations.extend(
                _forbidden_project_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected production code",
                    forbidden_module=graceful_stop_supervisor_bridge_module,
                )
            )
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected graceful-stop supervisor code",
                    forbidden=(
                        frozenset(graceful_stop_supervisor_bridge_public_symbols)
                        | graceful_stop_supervisor_bridge_external_private_symbols
                    ),
                )
            )
        if not _is_below(
            resolved_path,
            graceful_stop_supervisor_bridge_dependency_private_owner_roots,
        ):
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected ADR 0109 composition code",
                    forbidden=graceful_stop_supervisor_bridge_dependency_private_symbols,
                )
            )
        if not _is_below(
            resolved_path,
            graceful_stop_supervisor_bridge_lifecycle_owner_roots,
        ):
            violations.extend(
                _forbidden_seam_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="unconnected ADR 0110 composition code",
                    forbidden=graceful_stop_supervisor_bridge_lifecycle_symbols,
                )
            )
        if _is_below(resolved_path, offline_public_artifact_roots):
            violations.extend(
                _exact_project_module_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="offline public-artifact workflow",
                    allowed=offline_public_artifact_allowed_project_imports.get(
                        resolved_path, frozenset()
                    ),
                )
            )
            violations.extend(
                _forbidden_qualified_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="offline public-artifact workflow",
                    forbidden=forbidden_offline_public_artifact_symbols,
                )
            )
            if offline_public_artifact_allowed_os_symbols:
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="offline public-artifact workflow",
                        namespace="os",
                        allowed=offline_public_artifact_allowed_os_symbols,
                        kind="operating-system API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="offline public-artifact workflow",
                        namespace="os",
                    )
                )
        if _is_below(resolved_path, offline_public_artifact_ffi_roots):
            violations.extend(
                _ffi_library_binding_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="offline public-artifact FFI root",
                    factory=offline_public_artifact_ffi_library_factory,
                    binding=offline_public_artifact_ffi_library_binding,
                )
            )
            violations.extend(
                _unreviewed_namespace_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="offline public-artifact FFI root",
                    namespace="ctypes",
                    allowed=offline_public_artifact_ffi_allowed_symbols,
                )
            )
            violations.extend(
                _unreviewed_namespace_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="offline public-artifact FFI root",
                    namespace="_LIBC",
                    allowed=offline_public_artifact_ffi_allowed_library_symbols,
                )
            )

        if _is_below(resolved_path, shutdown_locator_roots):
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="shutdown locator",
                    allowed=shutdown_locator_allowed_project_imports,
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="shutdown locator",
                    forbidden=forbidden_shutdown_locator_symbols,
                )
            )

        if _is_below(resolved_path, graceful_stop_structural_bridge_roots):
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="graceful-stop structural bridge",
                    allowed=graceful_stop_structural_bridge_allowed_project_imports,
                )
            )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="graceful-stop structural bridge",
                    forbidden=forbidden_graceful_stop_structural_bridge_symbols,
                )
            )

        if _is_below(resolved_path, graceful_stop_decision_artifact_roots):
            violations.extend(
                _exact_project_import_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="graceful-stop decision-artifact binder",
                    allowed=graceful_stop_decision_artifact_allowed_project_imports,
                )
            )
            if graceful_stop_decision_artifact_allowed_stdlib_imports:
                violations.extend(
                    _exact_nonproject_import_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        allowed=graceful_stop_decision_artifact_allowed_stdlib_imports,
                    )
                )
            violations.extend(
                _forbidden_symbol_violations(
                    tree,
                    relative_path=relative_path,
                    boundary="graceful-stop decision-artifact binder",
                    forbidden=forbidden_graceful_stop_decision_artifact_symbols,
                )
            )
            if graceful_stop_decision_artifact_allowed_os_symbols:
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace="os",
                        allowed=graceful_stop_decision_artifact_allowed_os_symbols,
                        kind="operating-system API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace="os",
                    )
                )
            for (
                namespace,
                allowed_symbols,
            ) in graceful_stop_decision_artifact_allowed_namespace_symbols.items():
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace=namespace,
                        allowed=allowed_symbols,
                        kind="standard-library API",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace=namespace,
                    )
                )
            if graceful_stop_decision_artifact_audited_fs_namespace:
                violations.extend(
                    _unreviewed_namespace_symbol_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace=graceful_stop_decision_artifact_audited_fs_namespace,
                        allowed=(graceful_stop_decision_artifact_allowed_audited_fs_symbols),
                        kind="audited filesystem helper",
                    )
                )
                violations.extend(
                    _namespace_alias_violations(
                        tree,
                        relative_path=relative_path,
                        boundary="graceful-stop decision-artifact binder",
                        namespace=graceful_stop_decision_artifact_audited_fs_namespace,
                    )
                )

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
                            getattr(node, "lineno", 1),
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

            is_forbidden_offline_import = _is_below(
                resolved_path, offline_public_artifact_roots
            ) and _matches_namespace(module, forbidden_offline_public_artifact_imports)
            is_reviewed_offline_ffi_import = (
                _is_below(resolved_path, offline_public_artifact_ffi_roots)
                and module in offline_public_artifact_ffi_allowed_imports
            )
            if is_forbidden_offline_import and not is_reviewed_offline_ffi_import:
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        "offline public-artifact workflow cannot import ambient/runtime "
                        f"authority '{module}'",
                    )
                )

            if _is_below(resolved_path, shutdown_locator_roots) and _matches_namespace(
                module, forbidden_shutdown_locator_imports
            ):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        f"shutdown locator cannot import ambient/effect authority '{module}'",
                    )
                )

            if _is_below(
                resolved_path, graceful_stop_structural_bridge_roots
            ) and _matches_namespace(module, forbidden_graceful_stop_structural_bridge_imports):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        "graceful-stop structural bridge cannot import ambient/effect authority "
                        f"'{module}'",
                    )
                )

            if _is_below(
                resolved_path, graceful_stop_decision_artifact_roots
            ) and _matches_namespace(module, forbidden_graceful_stop_decision_artifact_imports):
                violations.append(
                    Violation(
                        relative_path,
                        line,
                        "graceful-stop decision-artifact binder cannot import ambient/effect "
                        f"authority '{module}'",
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
