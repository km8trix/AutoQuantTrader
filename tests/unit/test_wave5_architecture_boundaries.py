from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

from scripts.check_architecture import (
    _EXACT_NATIVE_FFI_MODULE_AST_SHA256,
    Violation,
    _isolated_wave5_module_boundary_violations,
    _native_executable_loading_violations,
    _python_module_identity_collision_violations,
)

REPOSITORY = Path(__file__).resolve().parents[2]

_SCOPE_POISONED_PACKAGE_EXCEPTION_ESCAPE = (
    "from packages.application.durable_trusted_time_monitor import "
    "DurableTrustedTimeMonitorError\n"
    "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
    "import TrustedTimeHeadAnchorCleanStopSupervisorBridgeError\n"
    "import packages.domain.models\n"
    "def poison_import_provenance() -> None:\n"
    "    import math as packages\n"
    "root_package = packages\n"
    "loader = root_package.application.durable_trusted_time_monitor._port_method(\n"
    "    root_package.application.trusted_time_head_anchor_clean_stop_supervisor_bridge."
    "_BUILTINS, import_name\n"
    ")\n"
    "module = loader(module_name, fromlist=('sentinel',))\n"
    "capability = root_package.application.durable_trusted_time_monitor._port_method(\n"
    "    module, attribute_name\n"
    ")"
)

_SCOPE_POISONED_SCRIPT_FFI_ESCAPE = (
    "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
    "import TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected\n"
    "import scripts.check_architecture\n"
    "def poison_import_provenance() -> None:\n"
    "    import cmath as scripts\n"
    "root_scripts = scripts\n"
    "ctypes_owner = "
    "root_scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication\n"
    "library = ctypes_owner.ctypes.pydll.LoadLibrary(None)"
)


def _dynamic_code_exceptions() -> dict[Path, str]:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    return {
        Path(path): digest
        for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
    }


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
        dynamic_code_exception_module_ast_sha256=_dynamic_code_exceptions(),
    )


def _phase4an_policy() -> tuple[
    dict[str, Path],
    dict[Path, frozenset[str]],
    dict[Path, str],
    frozenset[str],
]:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    return (
        {module: Path(path) for module, path in scan["phase4an_isolated_module_paths"].items()},
        {
            Path(path): frozenset(bindings)
            for path, bindings in scan["phase4an_allowed_imports"].items()
        },
        {Path(path): digest for path, digest in scan["phase4an_module_ast_sha256"].items()},
        frozenset(scan["phase4an_reserved_symbols"]),
    )


def _phase4an_violations(source: str, *, relative_path: Path) -> list[Violation]:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _phase4an_policy()
    return _isolated_wave5_module_boundary_violations(
        ast.parse(source),
        boundary="Phase 4AN injected OAuth runtime boundary",
        policy_enabled=True,
        relative_path=relative_path,
        module_paths=module_paths,
        allowed_imports=allowed_imports,
        module_ast_sha256=module_ast_sha256,
        reserved_symbols=reserved_symbols,
        dynamic_code_exception_module_ast_sha256=_dynamic_code_exceptions(),
    )


@pytest.mark.parametrize(
    "source",
    [
        "from packages.domain.trusted_time_graceful_stop_v2 import "
        "_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY",
        "from packages.persistence.trusted_time_graceful_stop_v2 import "
        "_open_injected_lifecycle_v2_repository",
        "from packages.persistence import trusted_time_graceful_stop_v2 as module\n"
        "repository = getattr(module, f\"{'_LifecycleV2'}Repository\")",
        "import packages.application.trusted_time_graceful_stop_v2_admission",
        "from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts "
        "import _LIFECYCLE_V2_BRIDGE_CAPABILITY",
        "name = '_consume_' + 'loaded_decision_receipt_for_v2'",
        "name = '%s%s' % ('_retain_', 'progress')",
        "name = '%(a)s%(b)s' % {'a': '_retain_', 'b': 'progress'}",
        "name = '{}{}'.format('_retain_', 'progress')",
        "name = '{}{}'.format(*('_retain_', 'progress'))",
        "name = '{a}{b}'.format(**{'a': '_retain_', 'b': 'progress'})",
        "name = '{a}{b}'.format_map({'a': '_retain_', 'b': 'progress'})",
        "name = f\"{'_retain_'}progress\"",
        "from uvicorn.importer import import_from_string\n"
        "builder = f\"{'_open_injected_'}lifecycle_v2_repository\"\n"
        "module = f\"packages.persistence.{'trusted_time_graceful_stop_'}v2\"\n"
        "factory = import_from_string(f'{module}:{builder}')",
        "namespace = globals()['%(a)s%(b)s' % {'a': '__built', 'b': 'ins__'}]\n"
        "loader = namespace['%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}]\n"
        "module = loader('%(a)s%(b)s%(c)s' % "
        "{'a': 'packages.persistence.', 'b': 'trusted_time_graceful_stop_', 'c': 'v2'}, "
        "fromlist=('sentinel',))\n"
        "resolved = getattr(module, '%(a)s%(b)s' % "
        "{'a': '_open_injected_', 'b': 'lifecycle_v2_repository'})",
        "namespace = vars()['%(a)s%(b)s' % {'a': '__built', 'b': 'ins__'}]\n"
        "loader = namespace['%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}]\n"
        "module = loader('packages.persistence.trusted_time_graceful_stop_v2', "
        "fromlist=('sentinel',))\n"
        "resolved = getattr(module, '_open_injected_lifecycle_v2_repository')",
        "namespace = locals()['%(a)s%(b)s' % {'a': '__built', 'b': 'ins__'}]\n"
        "loader = namespace['%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}]",
        "import uvicorn.importer as importer\n"
        "loader_name = '%(a)s%(b)s' % {'a': 'import_from_', 'b': 'string'}\n"
        "loader = getattr(importer, loader_name)\n"
        "resolved = loader('packages.persistence.trusted_time_graceful_stop_v2:"
        "_open_injected_lifecycle_v2_repository')",
        "import builtins as runtime_builtins\n"
        "loader_name = '%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}\n"
        "loader = getattr(runtime_builtins, loader_name)",
        "scope_owner = lambda: None\n"
        "scope_prefix = '__global'\n"
        "scope_suffix = 's__'\n"
        "scope = getattr(scope_owner, f'{scope_prefix}{scope_suffix}')\n"
        "builtins_prefix = '__built'\n"
        "builtins_suffix = 'ins__'\n"
        "namespace = scope[f'{builtins_prefix}{builtins_suffix}']\n"
        "import_prefix = '__im'\n"
        "import_suffix = 'port__'\n"
        "loader = namespace[f'{import_prefix}{import_suffix}']",
        "owner = lambda: None\n"
        "a, b = '__glo', 'bals__'\n"
        "scope = getattr(owner, f'{a}{b}')\n"
        "c, d = '__built', 'ins__'\n"
        "namespace = scope[f'{c}{d}']\n"
        "e, f = '__im', 'port__'\n"
        "loader = namespace[f'{e}{f}']",
        "import uvicorn\n"
        "namespace_prefix = 'import'\n"
        "namespace_suffix = 'er'\n"
        "importer = getattr(uvicorn, namespace_prefix + namespace_suffix)\n"
        "loader_prefix = 'import_from_'\n"
        "loader_suffix = 'string'\n"
        "loader = getattr(importer, loader_prefix + loader_suffix)",
        "scope = getattr(lambda: None, '__gloXbals__'.replace('X', ''))\n"
        "namespace = scope['__builXtins__'.replace('X', '')]\n"
        "loader = namespace['__imXport__'.replace('X', '')]",
        "def resolve(module_name, attribute_name):\n"
        "    reflect = getattr\n"
        "    scope = reflect(resolve, '__globals__')\n"
        "    namespace = scope['__builtins__']\n"
        "    loader = namespace['__import__']\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return reflect(module, attribute_name)",
        "def resolve(scope_key, builtins_key, import_key, module_name, attribute_name):\n"
        "    scope = getattr(resolve, scope_key)\n"
        "    namespace = scope[builtins_key]\n"
        "    loader = namespace[import_key]\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return getattr(module, attribute_name)",
        "import string\n"
        "def resolve(module_name, attribute_name):\n"
        "    formatter = string.Formatter()\n"
        "    loader = formatter.get_field(\n"
        "        '0.__globals__[__builtins__][__import__]', (resolve,), {}\n"
        "    )[0]\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return formatter.get_field('0.' + attribute_name, (module,), {})[0]",
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import _BUILTINS\n"
        "from packages.application.durable_trusted_time_monitor import _port_method\n"
        "def resolve(import_name, module_name, attribute_name):\n"
        "    loader = _port_method(_BUILTINS, import_name)\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return _port_method(module, attribute_name)",
        "from packages.application import "
        "trusted_time_head_anchor_clean_stop_supervisor_bridge as builtins_owner\n"
        "from packages.application import durable_trusted_time_monitor as resolver_owner\n"
        "builtins_alias = builtins_owner\n"
        "resolver_alias = resolver_owner\n"
        "loader = resolver_alias._port_method(builtins_alias._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = resolver_alias._port_method(module, attribute_name)",
        "from packages.application import durable_trusted_time_monitor as owner\n"
        "aliases = (owner,)\n"
        "callback(owner)",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import ctypes\n"
        "import _ctypes\n"
        "library = ctypes.pydll.LoadLibrary(None)\n"
        "importer = library['Py' + 'Import_ImportModule']\n"
        "resolver = library['Py' + 'Object_GetAttrString']\n"
        "bridge = _ctypes.PyObj_FromPtr",
        "class Owners:\n"
        "    import packages.application.durable_trusted_time_monitor as resolver\n"
        "    import packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "as builtins\n"
        "loader = Owners.resolver._port_method(Owners.builtins._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = Owners.resolver._port_method(module, attribute_name)",
        "from packages.application.durable_trusted_time_monitor import "
        "DurableTrustedTimeMonitorError\n"
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import TrustedTimeHeadAnchorCleanStopSupervisorBridgeError\n"
        "import packages.domain.models\n"
        "root_package = packages\n"
        "loader = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    root_package.application.trusted_time_head_anchor_clean_stop_supervisor_bridge."
        "_BUILTINS, import_name\n"
        ")\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    module, attribute_name\n"
        ")",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected\n"
        "import scripts.check_architecture\n"
        "root_scripts = scripts\n"
        "ctypes_owner = "
        "root_scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication\n"
        "library = ctypes_owner.ctypes.pydll.LoadLibrary(None)",
        _SCOPE_POISONED_PACKAGE_EXCEPTION_ESCAPE,
        _SCOPE_POISONED_SCRIPT_FFI_ESCAPE,
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
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    dynamic_code_exceptions = {
        Path(path): digest
        for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
    }
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
            dynamic_code_exception_module_ast_sha256=dynamic_code_exceptions,
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


def test_wave5_boundary_rejects_python_package_shadow_of_protected_module() -> None:
    module_paths, _, _, _ = _trusted_time_policy()
    protected_path = module_paths["packages.persistence.trusted_time_graceful_stop_v2"]
    shadow_path = Path("packages/persistence/trusted_time_graceful_stop_v2/__init__.py")

    assert _python_module_identity_collision_violations(
        relative_paths={protected_path, shadow_path},
        protected_module_paths=module_paths,
        boundary="production Python module identity boundary",
    )


def test_wave5_boundary_accepts_unique_protected_python_module_identities() -> None:
    module_paths, _, _, _ = _trusted_time_policy()

    assert not _python_module_identity_collision_violations(
        relative_paths=set(module_paths.values()),
        protected_module_paths=module_paths,
        boundary="production Python module identity boundary",
    )


@pytest.mark.parametrize(
    "source",
    [
        "import packages.application.etrade_oauth_token_runtime",
        "from packages.application import etrade_oauth_token_runtime",
        "from packages.application.etrade_oauth_token_runtime import *",
        "from .etrade_oauth_token_runtime import *",
        "from packages.application.etrade_oauth_token_runtime import "
        "execute_etrade_oauth_injected_token_exchange",
        "from packages.persistence.etrade_oauth_coordinator import "
        "EtradeOAuthTokenRuntimeCurrentnessReservation",
        "reservation = coordinator.issue_token_runtime_currentness_reservation(env, scope)",
        "name = f\"{'_TOKEN_EXCHANGE_'}RECEIPT_ISSUER\"",
        "name = '%s%s' % ('_RAW_TOKEN_', 'RESPONSE_ISSUER')",
        "reservation._claim_snapshot_for_injected_token_runtime()",
        "capability._reserve_unused_for_injected_token_runtime(state=state, verifier=verifier)",
        "request._authorization_header_matches_for_test(header)",
        "request._present_for_injected_exchange()",
        "request._sealed_response_binding_material()",
        "result._matches_test_values_once(token, token_secret)",
        "object.__setattr__(receipt, '_sealed_fields_sha256', digest)",
        "object.__setattr__(result, "
        "'_EtradeOAuthEphemeralTokenExchangeResult__token', bytearray())",
        "from uvicorn.importer import import_from_string\n"
        "module = f\"packages.application.{'etrade_oauth_token_'}runtime\"\n"
        "entry = '{}{}'.format('execute_etrade_oauth_injected_', 'token_exchange')\n"
        "runtime = import_from_string(f'{module}:{entry}')",
        "from uvicorn.importer import import_from_string\n"
        "target = '{mp}{ms}:{ep}{es}'.format_map({"
        "'mp': 'packages.application.etrade_oauth_token_', 'ms': 'runtime', "
        "'ep': 'execute_etrade_oauth_injected_', 'es': 'token_exchange'})\n"
        "runtime = import_from_string(target)",
        "from uvicorn.importer import import_from_string\n"
        "target = '{}{}:{}{}'.format(*('packages.application.etrade_oauth_token_', "
        "'runtime', 'execute_etrade_oauth_injected_', 'token_exchange'))\n"
        "runtime = import_from_string(target)",
        "from uvicorn.importer import import_from_string\n"
        "target = '{mp}{ms}:{ep}{es}'.format(**{"
        "'mp': 'packages.application.etrade_oauth_token_', 'ms': 'runtime', "
        "'ep': 'execute_etrade_oauth_injected_', 'es': 'token_exchange'})\n"
        "runtime = import_from_string(target)",
        "from uvicorn.importer import import_from_string\n"
        "target = '%(mp)s%(ms)s:%(ep)s%(es)s' % {"
        "'mp': 'packages.application.etrade_oauth_token_', 'ms': 'runtime', "
        "'ep': 'execute_etrade_oauth_injected_', 'es': 'token_exchange'}\n"
        "runtime = import_from_string(target)",
        "namespace = vars()['%(a)s%(b)s' % {'a': '__built', 'b': 'ins__'}]\n"
        "loader = namespace['%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}]\n"
        "runtime = loader('packages.application.etrade_oauth_token_runtime', "
        "fromlist=('sentinel',))",
        "import uvicorn.importer as importer\n"
        "loader_name = '%(a)s%(b)s' % {'a': 'import_from_', 'b': 'string'}\n"
        "loader = getattr(importer, loader_name)\n"
        "runtime = loader('packages.application.etrade_oauth_token_runtime:"
        "execute_etrade_oauth_injected_token_exchange')",
        "scope_owner = lambda: None\n"
        "scope_prefix = '__global'\n"
        "scope_suffix = 's__'\n"
        "scope = getattr(scope_owner, scope_prefix + scope_suffix)\n"
        "builtins_prefix = '__built'\n"
        "builtins_suffix = 'ins__'\n"
        "namespace = scope[builtins_prefix + builtins_suffix]",
        "scope = getattr(lambda: None, '__gloXbals__'.replace('X', ''))\n"
        "namespace = scope['__builXtins__'.replace('X', '')]\n"
        "loader = namespace['__imXport__'.replace('X', '')]",
        "def resolve(module_name, attribute_name):\n"
        "    reflect = getattr\n"
        "    scope = reflect(resolve, '__globals__')\n"
        "    namespace = scope['__builtins__']\n"
        "    loader = namespace['__import__']\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return reflect(module, attribute_name)",
        "def resolve(scope_key, builtins_key, import_key, module_name, attribute_name):\n"
        "    scope = getattr(resolve, scope_key)\n"
        "    namespace = scope[builtins_key]\n"
        "    loader = namespace[import_key]\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return getattr(module, attribute_name)",
        "import string\n"
        "def resolve(module_name, attribute_name):\n"
        "    formatter = string.Formatter()\n"
        "    loader = formatter.get_field(\n"
        "        '0.__globals__[__builtins__][__import__]', (resolve,), {}\n"
        "    )[0]\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return formatter.get_field('0.' + attribute_name, (module,), {})[0]",
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import _BUILTINS\n"
        "from packages.application.durable_trusted_time_monitor import _port_method\n"
        "def resolve(import_name, module_name, attribute_name):\n"
        "    loader = _port_method(_BUILTINS, import_name)\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return _port_method(module, attribute_name)",
        "from packages.application import "
        "trusted_time_head_anchor_clean_stop_supervisor_bridge as builtins_owner\n"
        "from packages.application import durable_trusted_time_monitor as resolver_owner\n"
        "builtins_alias = builtins_owner\n"
        "resolver_alias = resolver_owner\n"
        "loader = resolver_alias._port_method(builtins_alias._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = resolver_alias._port_method(module, attribute_name)",
        "from packages.application import durable_trusted_time_monitor as owner\n"
        "aliases = (owner,)\n"
        "callback(owner)",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import ctypes\n"
        "import _ctypes\n"
        "library = ctypes.pydll.LoadLibrary(None)\n"
        "importer = library['Py' + 'Import_ImportModule']\n"
        "resolver = library['Py' + 'Object_GetAttrString']\n"
        "bridge = _ctypes.PyObj_FromPtr",
        "class Owners:\n"
        "    import packages.application.durable_trusted_time_monitor as resolver\n"
        "    import packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "as builtins\n"
        "loader = Owners.resolver._port_method(Owners.builtins._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = Owners.resolver._port_method(module, attribute_name)",
        "from packages.application.durable_trusted_time_monitor import "
        "DurableTrustedTimeMonitorError\n"
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import TrustedTimeHeadAnchorCleanStopSupervisorBridgeError\n"
        "import packages.domain.models\n"
        "root_package = packages\n"
        "loader = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    root_package.application.trusted_time_head_anchor_clean_stop_supervisor_bridge."
        "_BUILTINS, import_name\n"
        ")\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    module, attribute_name\n"
        ")",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected\n"
        "import scripts.check_architecture\n"
        "root_scripts = scripts\n"
        "ctypes_owner = "
        "root_scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication\n"
        "library = ctypes_owner.ctypes.pydll.LoadLibrary(None)",
        _SCOPE_POISONED_PACKAGE_EXCEPTION_ESCAPE,
        _SCOPE_POISONED_SCRIPT_FFI_ESCAPE,
    ],
)
def test_phase4an_boundary_rejects_unreviewed_runtime_reachability(source: str) -> None:
    assert _phase4an_violations(
        source,
        relative_path=Path("packages/application/adversarial_etrade_runtime.py"),
    )


def test_phase4an_boundary_accepts_exact_modules_and_no_production_importers() -> None:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _phase4an_policy()
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    dynamic_code_exceptions = {
        Path(path): digest
        for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
    }
    production_paths = {
        path.relative_to(REPOSITORY)
        for root in ("apps", "packages", "scripts")
        for path in (REPOSITORY / root).rglob("*.py")
        if "node_modules" not in path.parts
    }
    for relative_path in production_paths:
        tree = ast.parse((REPOSITORY / relative_path).read_text(encoding="utf-8"))
        assert not _isolated_wave5_module_boundary_violations(
            tree,
            boundary="Phase 4AN injected OAuth runtime boundary",
            policy_enabled=True,
            relative_path=relative_path,
            module_paths=module_paths,
            allowed_imports=allowed_imports,
            module_ast_sha256=module_ast_sha256,
            reserved_symbols=reserved_symbols,
            dynamic_code_exception_module_ast_sha256=dynamic_code_exceptions,
        )


@pytest.mark.parametrize(
    "source",
    [
        "from packages.application.durable_trusted_time_monitor import "
        "DurableTrustedTimeMonitorError",
        "from packages.application import durable_trusted_time_monitor as owner\n"
        "error_type = owner.DurableTrustedTimeMonitorError",
        "from packages.application.durable_trusted_time_monitor import "
        "DurableTrustedTimeMonitorError as owner\n"
        "def harmless_scope_collision() -> None:\n"
        "    import math as owner\n"
        "error_type = owner",
    ],
)
def test_phase4an_boundary_allows_public_exception_exports(source: str) -> None:
    assert not _phase4an_violations(
        source,
        relative_path=Path("packages/application/benign_exception_consumer.py"),
    )


def test_phase4an_boundary_rejects_protected_module_ast_drift() -> None:
    module_paths, allowed_imports, module_ast_sha256, reserved_symbols = _phase4an_policy()
    relative_path = Path("packages/adapters/broker/etrade_oauth.py")
    source = (REPOSITORY / relative_path).read_text(encoding="utf-8") + "\nDRIFT = True\n"

    assert _isolated_wave5_module_boundary_violations(
        ast.parse(source),
        boundary="Phase 4AN injected OAuth runtime boundary",
        policy_enabled=True,
        relative_path=relative_path,
        module_paths=module_paths,
        allowed_imports=allowed_imports,
        module_ast_sha256=module_ast_sha256,
        reserved_symbols=reserved_symbols,
    )


@pytest.mark.parametrize(
    ("shadow_path"),
    [
        Path("packages/adapters/broker/etrade_oauth/__init__.py"),
        Path("packages/application/etrade_oauth_token_runtime/__init__.py"),
        Path("packages/persistence/etrade_oauth_coordinator/__init__.py"),
    ],
)
def test_phase4an_boundary_rejects_shadow_of_every_pinned_module(shadow_path: Path) -> None:
    module_paths, _, module_ast_sha256, _ = _phase4an_policy()
    protected_module_paths = {
        **module_paths,
        "packages.adapters.broker.etrade_oauth": Path("packages/adapters/broker/etrade_oauth.py"),
        "packages.persistence.etrade_oauth_coordinator": Path(
            "packages/persistence/etrade_oauth_coordinator.py"
        ),
    }
    relative_paths = set(module_ast_sha256)
    relative_paths.add(shadow_path)

    assert _python_module_identity_collision_violations(
        relative_paths=relative_paths,
        protected_module_paths=protected_module_paths,
        boundary="production Python module identity boundary",
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


@pytest.mark.parametrize(
    "source",
    [
        "import ctypes\n"
        "importer = ctypes.pythonapi.PyImport_ImportModule\n"
        "resolver = ctypes.pythonapi.PyObject_GetAttrString",
        "import ctypes\n"
        "library = ctypes.CDLL(None)\n"
        "importer = library.PyImport_ImportModule\n"
        "resolver = library.PyObject_GetAttrString",
        "from ctypes import CDLL\nlibrary = CDLL(None)\nsymbol = getattr(library, symbol_name)",
        "import cffi",
        "import _ctypes",
        "import _imp",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import ctypes\n"
        "library = ctypes.pydll.LoadLibrary(None)\n"
        "bridge = library.PyObj_FromPtr",
    ],
)
def test_native_loader_boundary_rejects_all_production_roots(source: str) -> None:
    assert _native_executable_loading_violations(
        ast.parse(source),
        relative_path=Path("scripts/adversarial_wave5.py"),
        wrapper_path=Path("packages/adapters/trusted_time/native_wrapper.py"),
        wrapper_module="packages.adapters.trusted_time.native_wrapper",
        image_import_root=False,
    )


def test_native_loader_boundary_accepts_only_exact_reviewed_ffi_modules() -> None:
    for relative_path in _EXACT_NATIVE_FFI_MODULE_AST_SHA256:
        tree = ast.parse((REPOSITORY / relative_path).read_text(encoding="utf-8"))
        assert not _native_executable_loading_violations(
            tree,
            relative_path=relative_path,
            wrapper_path=Path("packages/adapters/trusted_time/native_wrapper.py"),
            wrapper_module="packages.adapters.trusted_time.native_wrapper",
            image_import_root=False,
        )


def test_native_loader_boundary_rejects_reviewed_ffi_module_ast_drift() -> None:
    relative_path = next(iter(_EXACT_NATIVE_FFI_MODULE_AST_SHA256))
    source = (REPOSITORY / relative_path).read_text(encoding="utf-8") + "\nDRIFT = True\n"
    assert _native_executable_loading_violations(
        ast.parse(source),
        relative_path=relative_path,
        wrapper_path=Path("packages/adapters/trusted_time/native_wrapper.py"),
        wrapper_module="packages.adapters.trusted_time.native_wrapper",
        image_import_root=False,
    )
