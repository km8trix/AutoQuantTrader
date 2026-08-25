from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import inspect
import json
import marshal
import os
import re
import subprocess
import tomllib
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]

_CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE = (
    "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication"
)
_CLEAN_STOP_TERMINAL_REAUTHENTICATION_PRIVATE_SEAMS = frozenset(
    {
        "_ConsumedPostconditionRegistrySnapshot",
        "_ConfigurationBinding",
        "_DeadlineBoundReadOnlyProvider",
        "_ProductionResources",
        "_build_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_preparer",
        "_capture_configuration_binding",
        "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
        "_create_production_resources",
        "_issue_postcondition",
        "_production_verify_once",
        "_revoke_issued_postcondition",
        "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
    }
)

_MINIMAL_ARCHITECTURE_SCAN_PRELUDE = """\
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
"""

_ARCHITECTURE_BOOTSTRAP_COMMAND = (
    "uv run --isolated --no-project --no-config --offline --no-python-downloads "
    "--python 3.12 python -I -B scripts/check_architecture.py"
)
_ARCHITECTURE_BOOTSTRAP_MAKE_BLOCK = (
    "\t$(UV) run --isolated --no-project --no-config --offline --no-python-downloads \\\n"
    "\t\t--python 3.12 python -I -B scripts/check_architecture.py\n"
)
_ARCHITECTURE_BOOTSTRAP_WORKFLOW_PREFIX = (
    "        run: >-\n"
    "          uv run\n"
    "          --isolated\n"
    "          --no-project\n"
    "          --no-config\n"
    "          --offline\n"
    "          --no-python-downloads\n"
)
_ARCHITECTURE_BOOTSTRAP_WORKFLOW_SUFFIX = (
    "          python\n          -I\n          -B\n          scripts/check_architecture.py\n"
)

_TOPOLOGY_LAUNCH_LOCK_ARCHITECTURE_FIXTURE_PATHS = (
    Path("infra/architecture-boundaries.toml"),
    Path("docs/ARCHITECTURE.md"),
    Path("docs/IMPLEMENTATION_PLAN.md"),
    Path("docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md"),
    Path("docs/runbooks/trusted-time-supervisor.md"),
    Path("scripts/trusted_time_post_enrollment_topology_reader.py"),
    Path("scripts/trusted_time_post_enrollment_host_orchestrator.py"),
    Path("scripts/check_architecture.py"),
    Path("packages/adapters/trusted_time/_owned_file_descriptor.py"),
    Path("packages/adapters/trusted_time/_bounded_process.py"),
    Path("native/owned_file_descriptor.c"),
    Path("native/bounded_process.c"),
    Path("native/trusted_time_python_launcher.c"),
    Path("build_support/build_native_admission_launcher.py"),
    Path("build_support/build_native_test_launcher.py"),
    Path("build_support/install_native_admission_launcher.py"),
    Path("build_support/native_owned_file_descriptor_hook.py"),
)


def _write_topology_launch_lock_architecture_fixture(
    root: Path,
    *,
    full_production: bool = False,
) -> None:
    if full_production:
        for production_root in ("apps", "packages", "scripts"):
            for source in sorted((ROOT / production_root).rglob("*.py")):
                relative_path = source.relative_to(ROOT)
                destination = root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(source, destination)
                except OSError:
                    destination.write_bytes(source.read_bytes())
    for relative_path in _TOPOLOGY_LAUNCH_LOCK_ARCHITECTURE_FIXTURE_PATHS:
        destination = root / relative_path
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative_path).read_bytes())


def _write_detached_topology_fixture_text(path: Path, source: str) -> None:
    path.unlink()
    path.write_text(source, encoding="utf-8")


def _mutate_topology_production_ast_fixture(root: Path, mutation: str) -> None:
    if mutation == "alias_close":
        (root / "apps/topology_alias_escape.py").write_text(
            "def release(issuer):\n"
            "    closer = issuer.close\n"
            "    closer(_scope_is_live=lambda _owner: False)\n",
            encoding="utf-8",
        )
    elif mutation == "slots_escape":
        (root / "apps/topology_slots_escape.py").write_text(
            "def release(issuer):\n"
            "    slot = type(issuer).__slots__[23]\n"
            "    object.__getattribute__(issuer, slot).close()\n",
            encoding="utf-8",
        )
    elif mutation == "raw_allowed_module":
        allowed_path = root / "scripts/trusted_time_post_enrollment_controller_outcome.py"
        _write_detached_topology_fixture_text(
            allowed_path,
            allowed_path.read_text(encoding="utf-8")
            + "\nimport fcntl\nimport io\n"
            + "def _unreviewed_launch_lock(path):\n"
            + "    descriptor = io.FileIO(path)\n"
            + "    fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX)\n",
        )
    elif mutation == "production_added":
        (root / "apps/topology_unreviewed.py").write_text(
            "UNREVIEWED = True\n",
            encoding="utf-8",
        )
    elif mutation == "production_removed":
        (root / "apps/__init__.py").unlink()
    else:
        assert mutation == "production_renamed"
        (root / "packages/__init__.py").rename(root / "packages/topology_renamed.py")


def _architecture_bootstrap_workflow_block(python: str) -> str:
    return (
        _ARCHITECTURE_BOOTSTRAP_WORKFLOW_PREFIX
        + f"          --python {python}\n"
        + _ARCHITECTURE_BOOTSTRAP_WORKFLOW_SUFFIX
    )


def _unchecked_hash_pyc_bytes(source: str, filename: str) -> bytes:
    code = compile(source, filename, "exec")
    return (
        importlib.util.MAGIC_NUMBER + (1).to_bytes(4, "little") + (b"\0" * 8) + marshal.dumps(code)
    )


def _write_adr0111_production_manifest_fixture(
    root: Path,
) -> tuple[Path, Path, Path, str]:
    from scripts.check_architecture import (
        _NATIVE_BOUNDED_PROCESS_REFLECTION_ATTESTATIONS,
        _NATIVE_BOUNDED_PROCESS_REFLECTION_MODULE_AST_SHA256,
        _NATIVE_BUILD_CONSTRAINTS_TEXT,
        _NATIVE_BUILD_REQUIREMENTS,
        _canonical_ast_sha256,
        _production_python_source_manifest_sha256,
        _project_build_bootstrap_manifest_sha256,
    )

    low_relative = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    host_relative = Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    low_source = (
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "__all__ = []\n"
    )
    host_source = (
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "def _utc_text(value):\n"
        '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
        '"+00:00", "Z")\n'
        "__all__ = []\n"
    )
    low_path = root / low_relative
    host_path = root / host_relative
    low_path.parent.mkdir(parents=True)
    host_path.parent.mkdir(parents=True)
    (root / "apps/web/node_modules").mkdir(parents=True)
    low_path.write_text(low_source, encoding="utf-8")
    host_path.write_text(host_source, encoding="utf-8")
    dependency = root / "packages/application/trusted_time_head_anchor.py"
    dependency.write_text("SAFE = True\n", encoding="utf-8")
    native_wrapper_relative = Path("packages/adapters/trusted_time/_owned_file_descriptor.py")
    native_wrapper_source = "__all__ = []\n"
    native_wrapper_path = root / native_wrapper_relative
    native_wrapper_path.parent.mkdir(parents=True)
    native_wrapper_path.write_text(native_wrapper_source, encoding="utf-8")
    bounded_wrapper_relative = Path("packages/adapters/trusted_time/_bounded_process.py")
    bounded_wrapper_source = "__all__ = []\n"
    bounded_wrapper_path = root / bounded_wrapper_relative
    bounded_wrapper_path.write_text(bounded_wrapper_source, encoding="utf-8")
    native_consumer_relatives = (
        Path("apps/trusted_time_supervisor/post_enrollment_read_probes.py"),
        Path("apps/trusted_time_supervisor/post_enrollment_runtime_state.py"),
        Path("scripts/trusted_time_post_enrollment_controller_outcome.py"),
        Path("scripts/trusted_time_post_enrollment_execution_admission.py"),
        Path("scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"),
        Path("scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"),
        Path("scripts/verify_trusted_time_images.py"),
    )
    native_binding = "packages.adapters.trusted_time._owned_file_descriptor:_fstat"
    native_consumer_source = (
        "from packages.adapters.trusted_time._owned_file_descriptor import _fstat\n"
    )
    native_capture_import = (
        "from packages.adapters.trusted_time._owned_file_descriptor import (\n"
        "    _OwnedFileDescriptor, _fstat, _open_child_directory, _open_child_regular,\n"
        "    _open_root_directory, _read_snapshot, _statat,\n"
        ")\n"
    )
    probe_consumer_relative = Path("apps/trusted_time_supervisor/post_enrollment_read_probes.py")
    runtime_consumer_relative = Path(
        "apps/trusted_time_supervisor/post_enrollment_runtime_state.py"
    )
    probe_consumer_source = (
        native_capture_import
        + """\
def _cleanup_native_owners(owners):
    return None

def _require_absences(*, _fstat_exact=_fstat, _statat_exact=_statat):
    _fstat_exact(None)
    _fstat_exact(None)
    _statat_exact(None, "tmp")

def _read_marker(*, _fstat_exact=_fstat, _statat_exact=_statat,
                 _open_regular_exact=_open_child_regular,
                 _read_snapshot_exact=_read_snapshot,
                 _cleanup=_cleanup_native_owners):
    _fstat_exact(None)
    _statat_exact(None, "marker")
    file_owner = _open_regular_exact(None, "marker")
    _fstat_exact(file_owner)
    _read_snapshot_exact(file_owner)
    _fstat_exact(file_owner)
    _statat_exact(None, "marker")
    _fstat_exact(None)
    _cleanup((file_owner,))
    _cleanup((file_owner,))

def _require_open_tmp_context(*, _fstat_exact=_fstat, _statat_exact=_statat):
    _fstat_exact(None)
    _fstat_exact(None)
    _statat_exact(None, "tmp")

def _staged_barrier_bytes(*, _open_root=_open_root_directory,
                          _open_directory=_open_child_directory,
                          _fstat_exact=_fstat, _statat_exact=_statat,
                          _observe_absences=_require_absences,
                          _observe_marker=_read_marker,
                          _require_context=_require_open_tmp_context,
                          _cleanup=_cleanup_native_owners):
    root_owner = _open_root()
    tmp_owner = _open_directory(root_owner, "tmp")
    _fstat_exact(tmp_owner)
    _fstat_exact(root_owner)
    _statat_exact(root_owner, "tmp")
    _observe_absences(tmp_owner)
    _observe_marker(tmp_owner)
    _observe_absences(tmp_owner)
    _require_context(root_owner, tmp_owner)
    _cleanup((tmp_owner, root_owner))
    _cleanup((tmp_owner, root_owner))

def _pre_effect_runtime_absence_bytes(*, _open_root=_open_root_directory,
                                      _open_directory=_open_child_directory,
                                      _fstat_exact=_fstat, _statat_exact=_statat,
                                      _observe_absences=_require_absences,
                                      _require_context=_require_open_tmp_context,
                                      _cleanup=_cleanup_native_owners):
    root_owner = _open_root()
    tmp_owner = _open_directory(root_owner, "tmp")
    _fstat_exact(tmp_owner)
    _fstat_exact(root_owner)
    _statat_exact(root_owner, "tmp")
    _observe_absences(tmp_owner)
    _observe_absences(tmp_owner)
    _require_context(root_owner, tmp_owner)
    _cleanup((tmp_owner, root_owner))
    _cleanup((tmp_owner, root_owner))

def _persistent_barrier_bytes(*, _open_root=_open_root_directory,
                              _open_directory=_open_child_directory,
                              _fstat_exact=_fstat, _statat_exact=_statat,
                              _observe_absences=_require_absences,
                              _observe_marker=_read_marker,
                              _require_context=_require_open_tmp_context,
                              _cleanup=_cleanup_native_owners):
    root_owner = _open_root()
    tmp_owner = _open_directory(root_owner, "tmp")
    _fstat_exact(tmp_owner)
    _fstat_exact(root_owner)
    _statat_exact(root_owner, "tmp")
    _observe_absences(tmp_owner)
    _observe_marker(tmp_owner)
    _observe_marker(tmp_owner)
    _observe_marker(tmp_owner)
    _observe_marker(tmp_owner)
    _observe_absences(tmp_owner)
    _require_context(root_owner, tmp_owner)
    _cleanup((tmp_owner, root_owner))
    _cleanup((tmp_owner, root_owner))
"""
    )
    runtime_consumer_source = (
        native_capture_import
        + """\
def _cleanup_native_owners(owners):
    return None

def _read_regular_snapshot(*, _fstat_exact=_fstat, _statat_exact=_statat,
                           _open_regular_exact=_open_child_regular,
                           _read_snapshot_exact=_read_snapshot,
                           _cleanup=_cleanup_native_owners):
    _fstat_exact(None)
    _statat_exact(None, "marker")
    file_owner = _open_regular_exact(None, "marker")
    _fstat_exact(file_owner)
    _read_snapshot_exact(file_owner)
    _fstat_exact(file_owner)
    _statat_exact(None, "marker")
    _fstat_exact(None)
    _cleanup((file_owner,))
    _cleanup((file_owner,))

def _require_absences(*, _fstat_exact=_fstat, _statat_exact=_statat):
    _fstat_exact(None)
    _fstat_exact(None)
    _statat_exact(None, "tmp")

def _require_tmp_context(*, _fstat_exact=_fstat, _statat_exact=_statat):
    _fstat_exact(None)
    _fstat_exact(None)
    _statat_exact(None, "tmp")

def _read_tmp_snapshot(*, _open_root=_open_root_directory,
                       _open_directory=_open_child_directory,
                       _fstat_exact=_fstat, _statat_exact=_statat,
                       _read_regular=_read_regular_snapshot,
                       _observe_absences=_require_absences,
                       _require_context=_require_tmp_context,
                       _cleanup=_cleanup_native_owners):
    root_owner = _open_root()
    tmp_owner = _open_directory(root_owner, "tmp")
    _fstat_exact(tmp_owner)
    _fstat_exact(root_owner)
    _statat_exact(root_owner, "tmp")
    _read_regular(tmp_owner)
    _observe_absences(tmp_owner)
    _observe_absences(tmp_owner)
    _require_context(root_owner, tmp_owner)
    _cleanup((tmp_owner, root_owner))
    _cleanup((tmp_owner, root_owner))

def _read_boot_id_snapshot(*, _open_root=_open_root_directory,
                           _open_directory=_open_child_directory,
                           _fstat_exact=_fstat, _statat_exact=_statat,
                           _read_regular=_read_regular_snapshot,
                           _cleanup=_cleanup_native_owners):
    root_owner = _open_root()
    proc_owner = _open_directory(root_owner, "proc")
    sys_owner = _open_directory(proc_owner, "sys")
    kernel_owner = _open_directory(sys_owner, "kernel")
    random_owner = _open_directory(kernel_owner, "random")
    _fstat_exact(proc_owner)
    _fstat_exact(root_owner)
    _fstat_exact(proc_owner)
    _fstat_exact(sys_owner)
    _fstat_exact(sys_owner)
    _fstat_exact(kernel_owner)
    _fstat_exact(kernel_owner)
    _fstat_exact(random_owner)
    _fstat_exact(random_owner)
    _fstat_exact(root_owner)
    _statat_exact(root_owner, "proc")
    _statat_exact(root_owner, "proc")
    _statat_exact(proc_owner, "sys")
    _statat_exact(proc_owner, "sys")
    _statat_exact(sys_owner, "kernel")
    _statat_exact(sys_owner, "kernel")
    _statat_exact(kernel_owner, "random")
    _statat_exact(kernel_owner, "random")
    _read_regular(random_owner)
    _cleanup((random_owner, kernel_owner, sys_owner, proc_owner, root_owner))
    _cleanup((random_owner, kernel_owner, sys_owner, proc_owner, root_owner))
"""
    )
    bounded_wrapper_module = "packages.adapters.trusted_time._bounded_process"
    bounded_binding = f"{bounded_wrapper_module}:_run_bounded_process"
    bounded_consumer_relative = Path("scripts/verify_trusted_time_images.py")
    reader_consumer_relative = Path("scripts/trusted_time_post_enrollment_execution_admission.py")
    bounded_consumer_source = (
        native_consumer_source
        + f"from {bounded_wrapper_module} import _run_bounded_process\n"
        + "def _head_reviewed_operator_authority_object():\n"
        + "    def require_native_result(value, *, expected_argv):\n"
        + "        if type(value) is not tuple or len(value) != 4:\n"
        + "            raise ValueError\n"
        + "        argv = tuple.__getitem__(value, 0)\n"
        + "        returncode = tuple.__getitem__(value, 1)\n"
        + "        stdout = tuple.__getitem__(value, 2)\n"
        + "        stderr = tuple.__getitem__(value, 3)\n"
        + "        if argv is not expected_argv:\n"
        + "            raise ValueError\n"
        + "        return returncode, stdout, stderr\n"
        + '    exact_cwd = "/"\n'
        + '    exact_environment = (("LC_ALL", "C"),)\n'
        + '    revision_argv = ("/usr/bin/git", "rev-parse")\n'
        + "    resolved = _run_bounded_process(\n"
        + '        revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000\n'
        + "    )\n"
        + "    require_native_result(resolved, expected_argv=revision_argv)\n"
        + '    tree_argv = ("/usr/bin/git", "ls-tree")\n'
        + "    tree = _run_bounded_process(\n"
        + '        tree_argv, exact_cwd, exact_environment, b"", 1024, 16384, 5000000000\n'
        + "    )\n"
        + "    require_native_result(tree, expected_argv=tree_argv)\n"
        + '    request = b"object\\n"\n'
        + '    blob_argv = ("/usr/bin/git", "cat-file")\n'
        + "    blob = _run_bounded_process(\n"
        + "        blob_argv, exact_cwd, exact_environment, request, 4353, 16384, 5000000000\n"
        + "    )\n"
        + "    return require_native_result(blob, expected_argv=blob_argv)\n"
    )
    reader_consumer_source = (
        native_consumer_source + "from scripts.verify_trusted_time_images import "
        "_head_reviewed_operator_authority_object\n"
        + "def _load_post_enrollment_operator_attested_execution_approval_with_snapshot():\n"
        + '    exact_revision = "a" * 40\n'
        + "    _head_reviewed_operator_authority_object(exact_revision)\n"
        + "    return _head_reviewed_operator_authority_object(exact_revision)\n"
        + "def _load_post_enrollment_operator_attested_execution_approval(**kwargs):\n"
        + "    return kwargs\n"
        + "def load_post_enrollment_operator_attested_execution_approval():\n"
        + "    return _load_post_enrollment_operator_attested_execution_approval(\n"
        + "        git_operator_authority_loader=_head_reviewed_operator_authority_object\n"
        + "    )\n"
    )
    for native_consumer_relative in native_consumer_relatives:
        native_consumer_path = root / native_consumer_relative
        native_consumer_path.parent.mkdir(parents=True, exist_ok=True)
        native_consumer_path.write_text(
            (
                bounded_consumer_source
                if native_consumer_relative == bounded_consumer_relative
                else (
                    reader_consumer_source
                    if native_consumer_relative == reader_consumer_relative
                    else (
                        probe_consumer_source
                        if native_consumer_relative == probe_consumer_relative
                        else (
                            runtime_consumer_source
                            if native_consumer_relative == runtime_consumer_relative
                            else native_consumer_source
                        )
                    )
                )
            ),
            encoding="utf-8",
        )
    native_capture_bindings = tuple(
        f"packages.adapters.trusted_time._owned_file_descriptor:{binding}"
        for binding in (
            "_OwnedFileDescriptor",
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        )
    )
    native_consumer_config = "".join(
        "native_owned_file_descriptor_allowed_imports."
        f'"{relative.as_posix()}" = ['
        + ", ".join(
            f'"{binding}"'
            for binding in (
                native_capture_bindings
                if relative in {probe_consumer_relative, runtime_consumer_relative}
                else (native_binding,)
            )
        )
        + "]\n"
        for relative in native_consumer_relatives
    )
    native_capture_origins = {
        probe_consumer_relative: {
            "_require_absences": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_read_marker": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
                "_open_regular_exact": "_open_child_regular",
                "_read_snapshot_exact": "_read_snapshot",
            },
            "_require_open_tmp_context": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_staged_barrier_bytes": {
                "_open_root": "_open_root_directory",
                "_open_directory": "_open_child_directory",
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_pre_effect_runtime_absence_bytes": {
                "_open_root": "_open_root_directory",
                "_open_directory": "_open_child_directory",
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_persistent_barrier_bytes": {
                "_open_root": "_open_root_directory",
                "_open_directory": "_open_child_directory",
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
        },
        runtime_consumer_relative: {
            "_read_regular_snapshot": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
                "_open_regular_exact": "_open_child_regular",
                "_read_snapshot_exact": "_read_snapshot",
            },
            "_require_absences": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_require_tmp_context": {
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_read_tmp_snapshot": {
                "_open_root": "_open_root_directory",
                "_open_directory": "_open_child_directory",
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
            "_read_boot_id_snapshot": {
                "_open_root": "_open_root_directory",
                "_open_directory": "_open_child_directory",
                "_fstat_exact": "_fstat",
                "_statat_exact": "_statat",
            },
        },
    }
    native_capture_config = "".join(
        "native_owned_file_descriptor_captured_defaults."
        f'"{relative.as_posix()}".{function}.{parameter} = '
        '"packages.adapters.trusted_time._owned_file_descriptor:'
        f'{origin}"\n'
        for relative, functions in native_capture_origins.items()
        for function, parameters in functions.items()
        for parameter, origin in parameters.items()
    )
    native_owner_consumer_functions = {
        probe_consumer_relative: (
            "_cleanup_native_owners",
            "_require_absences",
            "_read_marker",
            "_require_open_tmp_context",
            "_staged_barrier_bytes",
            "_pre_effect_runtime_absence_bytes",
            "_persistent_barrier_bytes",
        ),
        runtime_consumer_relative: (
            "_cleanup_native_owners",
            "_read_regular_snapshot",
            "_require_absences",
            "_require_tmp_context",
            "_read_tmp_snapshot",
            "_read_boot_id_snapshot",
        ),
    }
    native_capture_sources = {
        probe_consumer_relative: probe_consumer_source,
        runtime_consumer_relative: runtime_consumer_source,
    }
    native_capture_module_ast_config = "".join(
        "native_owned_file_descriptor_captured_consumer_module_ast_sha256."
        f'"{relative.as_posix()}" = '
        f'"{_canonical_ast_sha256(ast.parse(source))}"\n'
        for relative, source in native_capture_sources.items()
    )
    native_owner_consumer_ast_config_parts: list[str] = []
    for relative, function_names in native_owner_consumer_functions.items():
        tree = ast.parse(native_capture_sources[relative])
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        native_owner_consumer_ast_config_parts.extend(
            "native_owned_file_descriptor_owner_consumer_function_ast_sha256."
            f'"{relative.as_posix()}".{function_name} = '
            f'"{_canonical_ast_sha256(functions[function_name])}"\n'
            for function_name in function_names
        )
    native_owner_consumer_ast_config = "".join(native_owner_consumer_ast_config_parts)
    bounded_consumer_config = (
        "native_bounded_process_allowed_imports."
        f'"{bounded_consumer_relative.as_posix()}" = ["{bounded_binding}"]\n'
    )
    reader_consumer_config = (
        "native_bounded_process_reader_allowed_imports."
        f'"{reader_consumer_relative.as_posix()}" = '
        '["scripts.verify_trusted_time_images:'
        '_head_reviewed_operator_authority_object"]\n'
    )
    low_module = "packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"
    host_module = "scripts.trusted_time_post_enrollment_graceful_stop_supervisor_bridge"
    native_wrapper_module = "packages.adapters.trusted_time._owned_file_descriptor"
    low_ast_sha256 = _canonical_ast_sha256(ast.parse(low_source))
    host_ast_sha256 = _canonical_ast_sha256(ast.parse(host_source))
    native_wrapper_ast_sha256 = _canonical_ast_sha256(ast.parse(native_wrapper_source))
    bounded_wrapper_ast_sha256 = _canonical_ast_sha256(ast.parse(bounded_wrapper_source))
    bounded_consumer_tree = ast.parse(bounded_consumer_source)
    bounded_consumer_functions = [
        node
        for node in bounded_consumer_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_head_reviewed_operator_authority_object"
    ]
    assert len(bounded_consumer_functions) == 1
    bounded_consumer_function_ast_sha256 = _canonical_ast_sha256(bounded_consumer_functions[0])
    bounded_consumer_function_config = (
        "native_bounded_process_consumer_function_ast_sha256."
        '"scripts/verify_trusted_time_images.py" = '
        f'"{bounded_consumer_function_ast_sha256}"\n'
    )
    bounded_consumer_module_config = (
        "native_bounded_process_consumer_module_ast_sha256."
        '"scripts/verify_trusted_time_images.py" = '
        f'"{_canonical_ast_sha256(bounded_consumer_tree)}"\n'
    )
    bounded_reflection_module_config = "".join(
        "native_bounded_process_reflection_module_ast_sha256."
        f"{json.dumps(relative.as_posix())} = {json.dumps(digest)}\n"
        for relative, digest in _NATIVE_BOUNDED_PROCESS_REFLECTION_MODULE_AST_SHA256.items()
    )
    bounded_reflection_attestations_config = "".join(
        "native_bounded_process_reflection_attestations."
        f"{json.dumps(relative.as_posix())} = "
        f"{json.dumps(list(attestations), separators=(',', ':'))}\n"
        for relative, attestations in _NATIVE_BOUNDED_PROCESS_REFLECTION_ATTESTATIONS.items()
    )
    reader_consumer_module_config = (
        "native_bounded_process_reader_consumer_module_ast_sha256."
        '"scripts/trusted_time_post_enrollment_execution_admission.py" = '
        f'"{_canonical_ast_sha256(ast.parse(reader_consumer_source))}"\n'
    )
    roots = tuple(root / value for value in ("apps", "packages", "scripts"))
    pruned = (root / "apps/web/node_modules",)
    manifest_sha256 = _production_python_source_manifest_sha256(root, roots, pruned)
    bootstrap_paths = (
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
    (root / ".python-version").write_text("3.12\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """\
[build-system]
requires = [
  "hatchling==1.32.0",
  "packaging==26.3",
  "pathspec==1.1.1",
  "pluggy==1.6.0",
  "tomlkit==0.15.1",
  "trove-classifiers==2026.6.1.19",
]
build-backend = "hatchling.build"

[project]
name = "fixture"
version = "0.0.0"
requires-python = ">=3.12,<3.14"

[tool.uv]
build-constraint-dependencies = [
  "hatchling==1.32.0",
  "packaging==26.3",
  "pathspec==1.1.1",
  "pluggy==1.6.0",
  "tomlkit==0.15.1",
  "trove-classifiers==2026.6.1.19",
]

[tool.hatch.build.targets.wheel]
packages = ["apps", "packages"]
exclude = ["packages/adapters/trusted_time/_bounded_process.py"]

[tool.hatch.build.targets.wheel.hooks.custom]
path = "build_support/native_owned_file_descriptor_hook.py"

[tool.hatch.build.targets.sdist]
exclude = ["/.uv-cache", "build_support/build_native_test_launcher.py"]

[tool.hatch.build.targets.sdist.force-include]
"build_support/native_build_constraints.txt" = \
"build_support/native_build_constraints.txt"
"build_support/native_image_manifest.py" = "build_support/native_image_manifest.py"
"build_support/native_owned_file_descriptor_hook.py" = \
"build_support/native_owned_file_descriptor_hook.py"
"native/bounded_process.c" = "native/bounded_process.c"
"native/owned_file_descriptor.c" = "native/owned_file_descriptor.c"
"native/trusted_time_python_launcher.c" = "native/trusted_time_python_launcher.c"
"packages/adapters/trusted_time/_bounded_process.py" = \
"packages/adapters/trusted_time/_bounded_process.py"
""",
        encoding="utf-8",
    )
    assert tuple(_NATIVE_BUILD_REQUIREMENTS) == (
        "hatchling==1.32.0",
        "packaging==26.3",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "tomlkit==0.15.1",
        "trove-classifiers==2026.6.1.19",
    )
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    build_constraints = root / "build_support/native_build_constraints.txt"
    build_constraints.parent.mkdir(parents=True)
    build_constraints.write_text(_NATIVE_BUILD_CONSTRAINTS_TEXT, encoding="utf-8")
    image_helper = root / "build_support/native_image_manifest.py"
    image_helper.write_text("SAFE_IMAGE_MANIFEST = True\n", encoding="utf-8")
    hook = root / "build_support/native_owned_file_descriptor_hook.py"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("SAFE_BUILD_HOOK = True\n", encoding="utf-8")
    test_builder = root / "build_support/build_native_test_launcher.py"
    test_builder.write_text("SAFE_TEST_BUILDER = True\n", encoding="utf-8")
    bounded_source = root / "native/bounded_process.c"
    bounded_source.parent.mkdir(parents=True, exist_ok=True)
    bounded_source.write_text("/* reviewed bounded process fixture */\n", encoding="utf-8")
    native_source = root / "native/owned_file_descriptor.c"
    native_source.parent.mkdir(parents=True, exist_ok=True)
    native_source.write_text("/* reviewed fixture */\n", encoding="utf-8")
    launcher_source = root / "native/trusted_time_python_launcher.c"
    launcher_source.write_text("/* reviewed launcher fixture */\n", encoding="utf-8")
    bootstrap_sha256 = _project_build_bootstrap_manifest_sha256(root, bootstrap_paths)
    config = root / "infra/architecture-boundaries.toml"
    config.parent.mkdir(parents=True)
    (root / "Makefile").write_text(
        "override PYTHONDONTWRITEBYTECODE := 1\n"
        "export PYTHONDONTWRITEBYTECODE\n"
        "check:\n"
        "\t$(MAKE) architecture-check\n"
        "architecture-check:\n" + _ARCHITECTURE_BOOTSTRAP_MAKE_BLOCK,
        encoding="utf-8",
    )
    workflow = root / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n"
        "  architecture:\n"
        "    env:\n"
        '      PYTHONDONTWRITEBYTECODE: "1"\n'
        "    steps:\n"
        + _architecture_bootstrap_workflow_block("3.12")
        + "  backend:\n"
        + "    needs:\n"
        + "      - architecture\n"
        + "    env:\n"
        + '      PYTHONDONTWRITEBYTECODE: "1"\n'
        + "      UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt\n"
        + "    steps:\n"
        + "      - name: Sync\n"
        + "        run: uv sync --all-groups --locked --no-install-project --no-build\n"
        + _architecture_bootstrap_workflow_block("3.12")
        + "      - name: Build\n"
        + "        run: |\n"
        + "          uv build --sdist --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes .\n"
        + "          uv build --wheel --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes dist/project.tar.gz\n"
        + "          uv pip install --python .venv/bin/python --no-deps dist/project.whl\n"
        + _architecture_bootstrap_workflow_block("3.12")
        + "  native-packaging:\n"
        + "    needs:\n"
        + "      - architecture\n"
        + "    env:\n"
        + '      PYTHONDONTWRITEBYTECODE: "1"\n'
        + "      UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt\n"
        + "    steps:\n"
        + "      - name: Sync\n"
        + "        run: uv sync --all-groups --locked --no-install-project --no-build\n"
        + _architecture_bootstrap_workflow_block("${{ matrix.python-version }}")
        + "      - name: Build\n"
        + "        run: |\n"
        + "          uv build --sdist --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes .\n"
        + "          uv build --wheel --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes dist/project.tar.gz\n"
        + "          uv build --wheel --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes dist/project.tar.gz\n"
        + _architecture_bootstrap_workflow_block("${{ matrix.python-version }}")
        + "      - name: Install\n"
        + "        run: |\n"
        + "          uv pip install --python .venv/bin/python --no-deps dist/project.whl\n"
        + "  frontend:\n"
        + "    steps:\n"
        + "      - name: Placeholder\n"
        + "        run: true\n"
        + "  containers:\n"
        + "    needs:\n"
        + "      - architecture\n"
        + "    env:\n"
        + '      PYTHONDONTWRITEBYTECODE: "1"\n'
        + "      UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt\n"
        + "    steps:\n"
        + "      - name: Sync\n"
        + "        run: uv sync --all-groups --locked --no-install-project --no-build\n"
        + _architecture_bootstrap_workflow_block("3.12")
        + "      - name: Build\n"
        + "        run: |\n"
        + "          uv build --sdist --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes .\n"
        + "          uv build --wheel --build-constraints "
        + "build_support/native_build_constraints.txt --require-hashes dist/project.tar.gz\n"
        + "          uv pip install --python .venv/bin/python --no-deps dist/project.whl\n"
        + _architecture_bootstrap_workflow_block("3.12"),
        encoding="utf-8",
    )
    for relative in (
        "docs/ARCHITECTURE.md",
        "docs/IMPLEMENTATION_PLAN.md",
        "docs/adr/0111-dormant-operation-bound-clean-stop-supervisor-bridge.md",
        "docs/runbooks/trusted-time-supervisor.md",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"{_ARCHITECTURE_BOOTSTRAP_COMMAND}\n",
            encoding="utf-8",
        )
    make_sha256 = hashlib.sha256((root / "Makefile").read_bytes()).hexdigest()
    workflow_sha256 = hashlib.sha256(workflow.read_bytes()).hexdigest()
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
production_python_source_manifest_roots = ["apps", "packages", "scripts"]
production_python_source_manifest_pruned_subtrees = ["apps/web/node_modules"]
production_python_source_manifest_sha256 = "{manifest_sha256}"
project_build_bootstrap_manifest_paths = [
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
]
project_build_bootstrap_manifest_sha256 = "{bootstrap_sha256}"
project_build_bootstrap_forbidden_paths = [
  "MANIFEST.in",
  "hatch.toml",
  "setup.cfg",
  "setup.py",
  "uv.toml",
]
architecture_checker_invocation_source_sha256."Makefile" = "{make_sha256}"
architecture_checker_invocation_source_sha256.".github/workflows/ci.yml" = "{workflow_sha256}"
native_owned_file_descriptor_wrapper_roots = ["{native_wrapper_relative.as_posix()}"]
native_owned_file_descriptor_wrapper_module = "{native_wrapper_module}"
native_owned_file_descriptor_wrapper_module_ast_sha256 = "{native_wrapper_ast_sha256}"
native_bounded_process_wrapper_roots = ["{bounded_wrapper_relative.as_posix()}"]
native_bounded_process_wrapper_module = "packages.adapters.trusted_time._bounded_process"
native_bounded_process_wrapper_module_ast_sha256 = "{bounded_wrapper_ast_sha256}"
{bounded_consumer_config}
{bounded_consumer_function_config}
{bounded_consumer_module_config}
{bounded_reflection_module_config}
{bounded_reflection_attestations_config}
{reader_consumer_config}
{reader_consumer_module_config}
{native_consumer_config}
{native_capture_config}
{native_capture_module_ast_config}
{native_owner_consumer_ast_config}
operation_bound_clean_stop_bridge_roots = ["{low_relative.as_posix()}"]
operation_bound_clean_stop_bridge_module = "{low_module}"
operation_bound_clean_stop_bridge_module_ast_sha256 = "{low_ast_sha256}"
operation_bound_clean_stop_bridge_closed_fields = ["closed"]
graceful_stop_supervisor_bridge_roots = ["{host_relative.as_posix()}"]
graceful_stop_supervisor_bridge_module = "{host_module}"
graceful_stop_supervisor_bridge_module_ast_sha256 = "{host_ast_sha256}"
graceful_stop_supervisor_bridge_closed_fields = ["closed"]
''',
        encoding="utf-8",
    )
    return config, low_path, host_path, manifest_sha256


def _production_importers(module: str) -> set[Path]:
    importers: set[Path] = set()
    python_paths = (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").rglob("*.py"),
    )
    for path in python_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path.relative_to(ROOT)))
        for node in ast.walk(tree):
            imports_module = isinstance(node, ast.Import) and any(
                alias.name == module or alias.name.startswith(f"{module}.") for alias in node.names
            )
            if isinstance(node, ast.ImportFrom) and node.module:
                imports_module = (
                    imports_module
                    or node.module == module
                    or any(
                        f"{node.module}.{alias.name}" == module
                        or f"{node.module}.{alias.name}".startswith(f"{module}.")
                        for alias in node.names
                    )
                )
            if imports_module:
                importers.add(path.relative_to(ROOT))
    return importers


def _dotted_ast_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "cast"
        and len(node.args) == 2
    ):
        return _dotted_ast_name(node.args[1])
    if isinstance(node, ast.Attribute):
        parent = _dotted_ast_name(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _production_private_symbol_importers(
    module: str,
    symbol: str,
    *,
    root: Path = ROOT,
    source_directories: tuple[str, ...] = ("apps", "packages", "scripts"),
) -> set[Path]:
    """Find direct, aliased, and module-attribute uses of one private binding."""

    importers: set[Path] = set()
    parent_module, _, module_leaf = module.rpartition(".")
    python_paths = tuple(
        path for directory in source_directories for path in (root / directory).rglob("*.py")
    )
    for path in python_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path.relative_to(root)))
        module_aliases: set[str] = set()
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == module and alias.asname is not None:
                        module_aliases.add(alias.asname)
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == symbol:
                        found = True
                    if node.module == parent_module and alias.name == module_leaf:
                        module_aliases.add(alias.asname or alias.name)
        qualified_symbol = f"{module}.{symbol}"
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                dotted = _dotted_ast_name(node)
                if (
                    node.attr == symbol
                    or dotted == qualified_symbol
                    or any(dotted == f"{module_alias}.{symbol}" for module_alias in module_aliases)
                ):
                    found = True
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == symbol
            ):
                found = True
        if found:
            importers.add(path.relative_to(root))
    return importers


@pytest.mark.parametrize(
    "symbol",
    [
        "_issue_trusted_time_head_anchor_clean_stop_terminal_result",
        "_consume_trusted_time_head_anchor_clean_stop_terminal_result",
    ],
)
@pytest.mark.parametrize(
    "access_style",
    [
        "origin_import_from_alias",
        "origin_module_attribute",
        "reexport_import_from_alias",
        "reexport_module_attribute",
    ],
)
def test_clean_stop_private_result_import_guard_detects_architecture_mutation(
    tmp_path: Path,
    symbol: str,
    access_style: str,
) -> None:
    module = "packages.application.trusted_time_head_anchor_clean_stop"
    authorized_module = (
        "apps.trusted_time_supervisor.head_anchor_attempt"
        if symbol.startswith("_issue_")
        else "packages.application.trusted_time_head_anchor_worker"
    )
    mutated = tmp_path / "apps" / "unreviewed_consumer.py"
    mutated.parent.mkdir(parents=True)
    if access_style == "origin_import_from_alias":
        source = f"from {module} import {symbol} as stolen\nstolen\n"
    elif access_style == "origin_module_attribute":
        source = f"import {module} as terminal_contract\nterminal_contract.{symbol}\n"
    elif access_style == "reexport_import_from_alias":
        source = f"from {authorized_module} import {symbol} as stolen\nstolen\n"
    else:
        source = f"import {authorized_module} as authorized\nauthorized.{symbol}\n"
    mutated.write_text(source, encoding="utf-8")

    assert _production_private_symbol_importers(
        module,
        symbol,
        root=tmp_path,
    ) == {Path("apps/unreviewed_consumer.py")}


@pytest.mark.parametrize(
    "symbol",
    sorted(_CLEAN_STOP_TERMINAL_REAUTHENTICATION_PRIVATE_SEAMS),
)
@pytest.mark.parametrize(
    "access_style",
    [
        "origin_import_from_alias",
        "origin_module_attribute",
        "reexport_import_from_alias",
        "reexport_module_attribute",
    ],
)
def test_clean_stop_terminal_private_seam_guard_detects_architecture_mutation(
    tmp_path: Path,
    symbol: str,
    access_style: str,
) -> None:
    mutated = tmp_path / "apps/unreviewed_terminal_consumer.py"
    mutated.parent.mkdir(parents=True)
    if access_style == "origin_import_from_alias":
        source = (
            f"from {_CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE} "
            f"import {symbol} as stolen\nstolen\n"
        )
    elif access_style == "origin_module_attribute":
        source = (
            f"import {_CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE} as terminal\n"
            f"terminal.{symbol}\n"
        )
    elif access_style == "reexport_import_from_alias":
        source = f"from scripts.unreviewed_reexport import {symbol} as stolen\nstolen\n"
    else:
        source = f"import scripts.unreviewed_reexport as exported\nexported.{symbol}\n"
    mutated.write_text(source, encoding="utf-8")

    assert _production_private_symbol_importers(
        _CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE,
        symbol,
        root=tmp_path,
    ) == {Path("apps/unreviewed_terminal_consumer.py")}


def _first_enrollment_assignments() -> tuple[str, ...]:
    digests = {
        "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256": "b" * 64,
        "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256": "e" * 64,
        "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256": "f" * 64,
        "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256": "1" * 64,
        "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256": "2" * 64,
        "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256": "3" * 64,
        "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256": "4" * 64,
        "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256": "5" * 64,
        "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256": "6" * 64,
        "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256": "7" * 64,
        "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256": "8" * 64,
    }
    return (
        "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/operator/trusted-time-launch.env",
        "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID=123e4567-e89b-42d3-a456-426614174000",
        "TRUSTED_TIME_PRIOR_NEW_OPERATION_ID=223e4567-e89b-42d3-a456-426614174001",
        f"TRUSTED_TIME_PRIOR_NEW_CLAIM_SHA256={'9' * 64}",
        f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
        "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:" + "c" * 64,
        "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID=sha256:" + "d" * 64,
        *(f"{name}={value}" for name, value in digests.items()),
    )


def test_trusted_time_python_launcher_is_isolated_and_cannot_be_overridden() -> None:
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-images",
            "TRUSTED_TIME_PYTHON=python",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert (
        "uv run --isolated --offline --locked --no-env-file "
        "python -I -B -X pycache_prefix=/dev/null"
    ) in completed.stdout
    assert "--no-sync" not in completed.stdout
    assert "--frozen" not in completed.stdout


@pytest.mark.parametrize(
    "forbidden_import",
    [
        "signal",
        "ctypes",
        "concurrent",
        "threading",
        "resource",
        "importlib",
        "builtins",
        "runpy",
        "pkgutil",
        "zipimport",
    ],
)
def test_offline_public_artifact_architecture_boundary_rejects_ambient_import(
    tmp_path: Path,
    forbidden_import: str,
) -> None:
    from scripts.check_architecture import check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text(f"import pathlib\nimport {forbidden_import}\n", encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
forbidden_offline_public_artifact_imports = [
  "signal", "ctypes", "concurrent", "threading", "resource", "importlib",
  "builtins", "runpy", "pkgutil", "zipimport",
]
forbidden_offline_public_artifact_symbols = []
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert len(violations) == 1
    assert violations[0].path == Path("scripts/offline_artifacts.py")
    assert violations[0].line == 2
    assert "offline public-artifact workflow" in violations[0].message
    assert forbidden_import in violations[0].message


@pytest.mark.parametrize(
    "workflow_source",
    [
        "import builtins\nbuiltins.__import__('subprocess')\n",
        "from builtins import __import__ as loader\nloader('subprocess')\n",
    ],
)
def test_offline_public_artifact_architecture_boundary_rejects_builtin_loader(
    tmp_path: Path,
    workflow_source: str,
) -> None:
    from scripts.check_architecture import Violation, check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text(workflow_source, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
forbidden_offline_public_artifact_imports = ["builtins"]
forbidden_offline_public_artifact_symbols = ["__builtins__"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/offline_artifacts.py"),
            line=1,
            message=(
                "offline public-artifact workflow cannot import ambient/runtime authority "
                "'builtins'"
            ),
        )
    ]


def test_offline_public_artifact_architecture_boundary_rejects_builtin_namespace_escape(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import Violation, check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text('__builtins__["__import__"]("subprocess")\n', encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
forbidden_offline_public_artifact_imports = ["builtins"]
forbidden_offline_public_artifact_symbols = ["__builtins__"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/offline_artifacts.py"),
            line=1,
            message=(
                "offline public-artifact workflow cannot reference process/control API "
                "'__builtins__'"
            ),
        )
    ]


@pytest.mark.parametrize(
    "workflow_source",
    [
        "import os\nos.kill(123, 9)\n",
        "import os as operating_system\noperating_system.kill(123, 9)\n",
        "from os import kill as terminate\nterminate(123, 9)\n",
        "import os\ncallback = os.kill\n",
        'import os\ngetattr(os, "kill")(123, 9)\n',
    ],
)
def test_offline_public_artifact_architecture_boundary_rejects_process_control_symbol(
    tmp_path: Path,
    workflow_source: str,
) -> None:
    from scripts.check_architecture import Violation, check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text(workflow_source, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
forbidden_offline_public_artifact_imports = []
forbidden_offline_public_artifact_symbols = ["os.kill"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/offline_artifacts.py"),
            line=2,
            message=(
                "offline public-artifact workflow cannot reference process/control API 'os.kill'"
            ),
        )
    ]


def test_offline_public_artifact_architecture_boundary_rejects_indirect_project_authority(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import Violation, check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text("from scripts import bounded_subprocess\n", encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
forbidden_offline_public_artifact_imports = []
forbidden_offline_public_artifact_symbols = []
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/offline_artifacts.py"),
            line=1,
            message=(
                "offline public-artifact workflow cannot import unreviewed project module "
                "'scripts.bounded_subprocess'"
            ),
        )
    ]


@pytest.mark.parametrize(
    ("workflow_source", "expected_message"),
    [
        (
            "import os\nos.unlink('evidence')\n",
            "offline public-artifact workflow cannot reference unreviewed "
            "operating-system API 'os.unlink'",
        ),
        (
            "import os\nfilesystem = os\nfilesystem.unlink('evidence')\n",
            "offline public-artifact workflow cannot alias imported namespace 'os'",
        ),
    ],
)
def test_offline_public_artifact_architecture_boundary_rejects_unreviewed_os_authority(
    tmp_path: Path,
    workflow_source: str,
    expected_message: str,
) -> None:
    from scripts.check_architecture import Violation, check

    workflow = tmp_path / "scripts/offline_artifacts.py"
    workflow.parent.mkdir()
    workflow.write_text(workflow_source, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/offline_artifacts.py"]
offline_public_artifact_allowed_os_symbols = ["os.fsync"]
forbidden_offline_public_artifact_imports = []
forbidden_offline_public_artifact_symbols = []
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/offline_artifacts.py"),
            line=2,
            message=expected_message,
        )
    ]


def test_offline_public_artifact_ffi_exception_is_exact_to_reviewed_root(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import Violation, check

    reviewed = tmp_path / "scripts/reviewed_ffi.py"
    dependent = tmp_path / "scripts/dependent.py"
    reviewed.parent.mkdir()
    reviewed.write_text(
        "import ctypes\n_LIBC = ctypes.CDLL(None, use_errno=True)\n",
        encoding="utf-8",
    )
    dependent.write_text("import ctypes\nctypes.CDLL(None)\n", encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = [
  "scripts/reviewed_ffi.py",
  "scripts/dependent.py",
]
forbidden_offline_public_artifact_imports = ["ctypes"]
forbidden_offline_public_artifact_symbols = []
offline_public_artifact_ffi_roots = ["scripts/reviewed_ffi.py"]
offline_public_artifact_ffi_allowed_imports = ["ctypes"]
offline_public_artifact_ffi_allowed_symbols = ["ctypes.CDLL"]
offline_public_artifact_ffi_allowed_library_symbols = []
offline_public_artifact_ffi_library_factory = "ctypes.CDLL"
offline_public_artifact_ffi_library_binding = "_LIBC"
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/dependent.py"),
            line=1,
            message=(
                "offline public-artifact workflow cannot import ambient/runtime authority 'ctypes'"
            ),
        )
    ]


@pytest.mark.parametrize(
    ("workflow_source", "forbidden_symbol"),
    [
        (
            "import ctypes\n"
            "_LIBC = ctypes.CDLL(None, use_errno=True)\n"
            "ctypes.POINTER(ctypes.c_int)\n",
            "ctypes.POINTER",
        ),
        (
            "import ctypes\n_LIBC = ctypes.CDLL(None, use_errno=True)\n_EFFECT = _LIBC.system\n",
            "_LIBC.system",
        ),
    ],
)
def test_offline_public_artifact_ffi_exception_rejects_unreviewed_symbols(
    tmp_path: Path,
    workflow_source: str,
    forbidden_symbol: str,
) -> None:
    from scripts.check_architecture import Violation, check

    reviewed = tmp_path / "scripts/reviewed_ffi.py"
    reviewed.parent.mkdir()
    reviewed.write_text(workflow_source, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/reviewed_ffi.py"]
forbidden_offline_public_artifact_imports = ["ctypes"]
forbidden_offline_public_artifact_symbols = []
offline_public_artifact_ffi_roots = ["scripts/reviewed_ffi.py"]
offline_public_artifact_ffi_allowed_imports = ["ctypes"]
offline_public_artifact_ffi_allowed_symbols = ["ctypes.CDLL", "ctypes.c_int"]
offline_public_artifact_ffi_allowed_library_symbols = ["_LIBC.open", "_LIBC.openat"]
offline_public_artifact_ffi_library_factory = "ctypes.CDLL"
offline_public_artifact_ffi_library_binding = "_LIBC"
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    expected_line = 3
    assert violations == [
        Violation(
            path=Path("scripts/reviewed_ffi.py"),
            line=expected_line,
            message=(
                "offline public-artifact FFI root cannot reference unreviewed FFI API "
                f"'{forbidden_symbol}'"
            ),
        )
    ]


def test_offline_public_artifact_ffi_exception_rejects_alternate_library_binding(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import Violation, check

    reviewed = tmp_path / "scripts/reviewed_ffi.py"
    reviewed.parent.mkdir()
    reviewed.write_text(
        "import ctypes\n_OTHER = ctypes.CDLL(None)\n_EFFECT = _OTHER.system\n",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/reviewed_ffi.py"]
forbidden_offline_public_artifact_imports = ["ctypes"]
forbidden_offline_public_artifact_symbols = []
offline_public_artifact_ffi_roots = ["scripts/reviewed_ffi.py"]
offline_public_artifact_ffi_allowed_imports = ["ctypes"]
offline_public_artifact_ffi_allowed_symbols = ["ctypes.CDLL"]
offline_public_artifact_ffi_allowed_library_symbols = ["_LIBC.open", "_LIBC.openat"]
offline_public_artifact_ffi_library_factory = "ctypes.CDLL"
offline_public_artifact_ffi_library_binding = "_LIBC"
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/reviewed_ffi.py"),
            line=2,
            message=(
                "offline public-artifact FFI root must preserve exact FFI library binding "
                "'_LIBC = ctypes.CDLL(None, use_errno=True)'"
            ),
        )
    ]


def test_offline_public_artifact_ffi_exception_rejects_library_binding_alias(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import Violation, check

    reviewed = tmp_path / "scripts/reviewed_ffi.py"
    reviewed.parent.mkdir()
    reviewed.write_text(
        "import ctypes\n"
        "_LIBC = ctypes.CDLL(None, use_errno=True)\n"
        "_OTHER = _LIBC\n"
        "_EFFECT = _OTHER.system\n",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
offline_public_artifact_roots = ["scripts/reviewed_ffi.py"]
forbidden_offline_public_artifact_imports = ["ctypes"]
forbidden_offline_public_artifact_symbols = []
offline_public_artifact_ffi_roots = ["scripts/reviewed_ffi.py"]
offline_public_artifact_ffi_allowed_imports = ["ctypes"]
offline_public_artifact_ffi_allowed_symbols = ["ctypes.CDLL"]
offline_public_artifact_ffi_allowed_library_symbols = ["_LIBC.open", "_LIBC.openat"]
offline_public_artifact_ffi_library_factory = "ctypes.CDLL"
offline_public_artifact_ffi_library_binding = "_LIBC"
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert violations == [
        Violation(
            path=Path("scripts/reviewed_ffi.py"),
            line=3,
            message=("offline public-artifact FFI root cannot alias FFI library binding '_LIBC'"),
        )
    ]


def test_shutdown_locator_architecture_boundary_rejects_effect_import(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    locator = tmp_path / "scripts/shutdown_locator.py"
    locator.parent.mkdir()
    locator.write_text("import hashlib\nimport subprocess\n", encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
shutdown_locator_roots = ["scripts/shutdown_locator.py"]
forbidden_shutdown_locator_imports = ["subprocess"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert len(violations) == 1
    assert violations[0].path == Path("scripts/shutdown_locator.py")
    assert violations[0].line == 2
    assert "shutdown locator" in violations[0].message
    assert "subprocess" in violations[0].message


def test_graceful_stop_bridge_architecture_boundary_rejects_dependency_and_effect_drift(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    bridge = tmp_path / "scripts/graceful_stop.py"
    bridge.parent.mkdir()
    bridge.write_text(
        """from packages.domain.approved import reviewed
from scripts.effecting import run_effect
open("state.json")
""",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
graceful_stop_structural_bridge_roots = ["scripts/graceful_stop.py"]
forbidden_graceful_stop_structural_bridge_imports = []
graceful_stop_structural_bridge_allowed_project_imports = [
  "packages.domain.approved:reviewed",
]
forbidden_graceful_stop_structural_bridge_symbols = ["open"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert len(violations) == 2
    assert {violation.path for violation in violations} == {Path("scripts/graceful_stop.py")}
    assert any(
        violation.line == 2
        and "unreviewed project binding" in violation.message
        and "scripts.effecting:run_effect" in violation.message
        for violation in violations
    )
    assert any(
        violation.line == 3 and "effect API 'open'" in violation.message for violation in violations
    )


def test_graceful_stop_decision_binder_boundary_rejects_capability_drift(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    binder = tmp_path / "scripts/graceful_stop_decision_artifacts.py"
    binder.parent.mkdir()
    binder.write_text(
        """import os
import time
from packages.domain.approved import reviewed
from scripts import audited as _audited_fs
from scripts.effecting import run_effect
os.fspath("candidate")
os.system("stop")
_audited_fs.reviewed_helper()
_audited_fs.effect_helper()
run_effect()
""",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
graceful_stop_decision_artifact_roots = [
  "scripts/graceful_stop_decision_artifacts.py",
]
graceful_stop_decision_artifact_allowed_project_imports = [
  "packages.domain.approved:reviewed",
  "scripts:audited",
]
graceful_stop_decision_artifact_allowed_os_symbols = ["os.fspath"]
graceful_stop_decision_artifact_audited_fs_namespace = "scripts.audited"
graceful_stop_decision_artifact_allowed_audited_fs_symbols = [
  "scripts.audited.reviewed_helper",
]
forbidden_graceful_stop_decision_artifact_imports = ["time"]
forbidden_graceful_stop_decision_artifact_symbols = ["run_effect"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    messages = {violation.message for violation in violations}
    assert any("scripts.effecting:run_effect" in message for message in messages)
    assert any("ambient/effect authority 'time'" in message for message in messages)
    assert any("operating-system API 'os.system'" in message for message in messages)
    assert any(
        "audited filesystem helper 'scripts.audited.effect_helper'" in message
        for message in messages
    )
    assert any("effect API 'run_effect'" in message for message in messages)


def test_graceful_stop_decision_binder_boundary_rejects_direct_filesystem_effects(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    binder = tmp_path / "scripts/graceful_stop_decision_artifacts.py"
    binder.parent.mkdir()
    binder.write_text(
        """import shutil
from pathlib import Path
candidate = Path("candidate.json")
shutil.rmtree("artifact-directory")
open(candidate, "wb")
candidate.write_bytes(b"candidate")
candidate.read_bytes()
candidate.read_text()
candidate.rename("renamed.json")
getattr(candidate, "unlink")()
""",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
graceful_stop_decision_artifact_roots = [
  "scripts/graceful_stop_decision_artifacts.py",
]
graceful_stop_decision_artifact_allowed_project_imports = []
graceful_stop_decision_artifact_allowed_stdlib_imports = ["pathlib:Path"]
forbidden_graceful_stop_decision_artifact_imports = ["shutil"]
forbidden_graceful_stop_decision_artifact_symbols = [
  "open", "read_bytes", "read_text", "rename", "unlink", "write_bytes",
]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    messages = {violation.message for violation in violations}
    assert any("unreviewed non-project binding 'shutil:*'" in message for message in messages)
    assert any("ambient/effect authority 'shutil'" in message for message in messages)
    for forbidden_symbol in (
        "open",
        "read_bytes",
        "read_text",
        "rename",
        "unlink",
        "write_bytes",
    ):
        assert any(f"effect API '{forbidden_symbol}'" in message for message in messages)


def test_clean_stop_terminal_architecture_boundary_rejects_capability_and_consumer_drift(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    issuer = tmp_path / "scripts/terminal.py"
    issuer.parent.mkdir()
    issuer.write_text(
        """from packages.application.reviewed import observe
import ctypes
import os
import subprocess

class _DeadlineBoundReadOnlyProvider:
    def __init__(self):
        self._provider._timeout_seconds
    def _require_guard(self): pass
    def activate(self): pass
    def attest_identity(self): self._provider.attest_identity()
    def deactivate(self): pass
    def download_object(self): self._provider.download_object()
    def list_object_names_page(self): self._provider.list_object_names_page()
    def list_sequence_object_names(self): self._provider.list_sequence_object_names()
    def upload(self): self._provider.upload_object_no_overwrite()

class _ProductionResources:
    def verify(self):
        self._repository.load_head_anchor_startup_snapshot()
        self._repository.discard_head_anchor_snapshot()
        self._repository.commit_trusted_time_head_anchor_intent()

open("outcome.json", "wb")
os.replace("before", "after")
getattr(os, "execv")
stolen_os = os
ctypes.memmove
""",
        encoding="utf-8",
    )
    consumer = tmp_path / "apps/consumer.py"
    consumer.parent.mkdir()
    consumer.write_text(
        """import scripts.terminal as terminal
terminal._issue_postcondition
""",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
clean_stop_terminal_reauthentication_roots = ["scripts/terminal.py"]
clean_stop_terminal_reauthentication_allowed_project_imports = [
  "packages.application.reviewed:observe",
]
clean_stop_terminal_reauthentication_allowed_nonproject_imports = ["ctypes:*", "os:*"]
clean_stop_terminal_reauthentication_allowed_namespace_symbols.ctypes = ["ctypes.CDLL"]
clean_stop_terminal_reauthentication_allowed_namespace_symbols.os = ["os.getpid"]
clean_stop_terminal_reauthentication_allowed_dynamic_attributes = []
clean_stop_terminal_reauthentication_provider_class = "_DeadlineBoundReadOnlyProvider"
clean_stop_terminal_reauthentication_provider_methods = [
  "__init__", "_require_guard", "activate", "attest_identity", "deactivate",
  "download_object", "list_object_names_page", "list_sequence_object_names",
]
clean_stop_terminal_reauthentication_provider_capabilities = [
  "_timeout_seconds", "attest_identity", "download_object",
  "list_object_names_page", "list_sequence_object_names",
]
clean_stop_terminal_reauthentication_resources_class = "_ProductionResources"
clean_stop_terminal_reauthentication_repository_capabilities = [
  "discard_head_anchor_snapshot", "load_head_anchor_startup_snapshot",
]
forbidden_clean_stop_terminal_reauthentication_symbols = [
  "open", "upload_object_no_overwrite", "commit_trusted_time_head_anchor_intent",
]
clean_stop_terminal_reauthentication_private_reference_roots = [
  "apps", "packages", "scripts",
]
clean_stop_terminal_reauthentication_module = "scripts.terminal"
clean_stop_terminal_reauthentication_private_symbols = ["_issue_postcondition"]
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)
    messages = {violation.message for violation in violations}

    assert any("unreviewed non-project binding 'subprocess:*'" in item for item in messages)
    assert any("effect API 'open'" in item for item in messages)
    assert any("namespace API 'os.replace'" in item for item in messages)
    assert any("namespace API 'os.execv'" in item for item in messages)
    assert any("namespace API 'ctypes.memmove'" in item for item in messages)
    assert any("cannot alias imported namespace 'os'" in item for item in messages)
    assert any("unreviewed dynamic attribute dispatch" in item for item in messages)
    assert any(
        "unreviewed method '_DeadlineBoundReadOnlyProvider.upload'" in item for item in messages
    )
    assert any("self._provider.upload_object_no_overwrite" in item for item in messages)
    assert any(
        "self._repository.commit_trusted_time_head_anchor_intent" in item for item in messages
    )
    assert any("cannot import unconnected module 'scripts.terminal'" in item for item in messages)
    assert any("private seam 'scripts.terminal._issue_postcondition'" in item for item in messages)


def test_graceful_stop_lifecycle_boundary_rejects_ffi_filesystem_and_consumer_drift(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    repository = tmp_path / "scripts/lifecycle.py"
    repository.parent.mkdir()
    repository.write_text(
        """import ctypes
import fcntl
import os
import subprocess
from packages.domain.reviewed import evidence

POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS = "success"
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON = "provider_confirmed"

class Phase:
    ATTEMPT_RESERVED = "attempt_reserved"
    SIGNAL_SENT = "signal_sent"

class _OwnedFileDescriptor:
    def __del__(self): pass
    def __index__(self): return 1
    def close(self): pass
    def fileno(self): return 1

_LIBC = ctypes.CDLL(None, use_errno=True)
_OWNED_OPEN = _LIBC.open
_OWNED_OPEN.argtypes = ()
_OWNED_OPEN.restype = _OwnedFileDescriptor
_OWNED_OPENAT = _LIBC.openat
_OWNED_OPENAT.argtypes = ()
_OWNED_OPENAT.restype = _OwnedFileDescriptor
_ALIAS = _OWNED_OPEN

def _invoke():
    _OWNED_OPEN()
    _OWNED_OPENAT()
    ctypes.memmove
    _LIBC.system
    fcntl.flock(1, fcntl.LOCK_EX)
    os.open("raw", os.O_RDONLY)
    os.fork()
    os.rename("before", "after")
    open("artifact")
    target.open()
    target.touch()
    target.mkdir()
    target.chmod(0o600)
    target.hardlink_to("other")
    target.symlink_to("other")
    alias = _register_repository_state

class _Repository:
    def reviewed(self): pass
    def effect(self): pass

def _publish_staged_file(directory_descriptor, *, staging_file_name):
    os.unlink(staging_file_name, dir_fd=directory_descriptor)

def _publish_all(directory_descriptor):
    _publish_staged_file(directory_descriptor, staging_file_name=STAGING_ONE)
    _publish_staged_file(directory_descriptor, staging_file_name=STAGING_TWO)
    _publish_staged_file(directory_descriptor, staging_file_name=STAGING_THREE)
    os.unlink("attempt-root", dir_fd=directory_descriptor)

def _build_repository_state_registry(): pass
def _persist_attempt(): pass
def _register_repository_state(): pass
def _new_success_record(): pass

__all__ = ["safe", "effect"]
""",
        encoding="utf-8",
    )
    consumer = tmp_path / "apps/consumer.py"
    consumer.parent.mkdir()
    consumer.write_text(
        "import scripts.lifecycle as lifecycle\n"
        "from scripts.lifecycle import _persist_attempt\n"
        "lifecycle._build_repository_state_registry\n"
        'getattr(lifecycle, "_register_repository_state")\n',
        encoding="utf-8",
    )
    dynamic_consumer = tmp_path / "apps/dynamic_consumer.py"
    dynamic_consumer.write_text(
        "import importlib\n"
        'lifecycle = importlib.import_module("scripts.lifecycle")\n'
        "lifecycle.safe()\n",
        encoding="utf-8",
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        """[scan]
source_roots = []
package_roots = []
primitive_roots = []
primitive_namespaces = []
composition_namespaces = []
domain_roots = []
forbidden_domain_imports = []
side_effect_free_roots = []
forbidden_side_effect_imports = []
graceful_stop_lifecycle_repository_roots = ["scripts/lifecycle.py"]
graceful_stop_lifecycle_repository_allowed_project_imports = [
  "packages.domain.reviewed:evidence",
]
graceful_stop_lifecycle_repository_allowed_nonproject_imports = [
  "ctypes:*", "fcntl:*", "os:*",
]
graceful_stop_lifecycle_repository_allowed_namespace_symbols.ctypes = ["ctypes.CDLL"]
graceful_stop_lifecycle_repository_allowed_namespace_symbols.fcntl = [
  "fcntl.LOCK_EX", "fcntl.LOCK_NB", "fcntl.LOCK_UN", "fcntl.flock",
]
graceful_stop_lifecycle_repository_allowed_namespace_symbols.os = [
  "os.O_RDONLY", "os.unlink",
]
graceful_stop_lifecycle_repository_allowed_namespace_symbols._LIBC = [
  "_LIBC.open", "_LIBC.openat",
]
graceful_stop_lifecycle_repository_allowed_namespace_symbols._OWNED_OPEN = [
  "_OWNED_OPEN.argtypes", "_OWNED_OPEN.restype",
]
graceful_stop_lifecycle_repository_allowed_namespace_symbols._OWNED_OPENAT = [
  "_OWNED_OPENAT.argtypes", "_OWNED_OPENAT.restype",
]
graceful_stop_lifecycle_repository_allowed_dynamic_attributes = []
graceful_stop_lifecycle_repository_top_level_definitions = [
  "Phase", "_OwnedFileDescriptor", "_Repository", "_build_repository_state_registry",
  "_invoke", "_persist_attempt", "_publish_all", "_publish_staged_file",
  "_register_repository_state",
]
graceful_stop_lifecycle_repository_forbidden_unqualified_calls = ["open"]
graceful_stop_lifecycle_repository_forbidden_method_calls = [
  "chmod", "hardlink_to", "mkdir", "open", "symlink_to", "touch",
]
graceful_stop_lifecycle_repository_allowed_qualified_method_calls = [
  "os.mkdir",
]
graceful_stop_lifecycle_repository_ffi_library_factory = "ctypes.CDLL"
graceful_stop_lifecycle_repository_ffi_library_binding = "_LIBC"
graceful_stop_lifecycle_repository_ffi_functions._OWNED_OPEN = "_LIBC.open"
graceful_stop_lifecycle_repository_ffi_functions._OWNED_OPENAT = "_LIBC.openat"
graceful_stop_lifecycle_repository_descriptor_class = "_OwnedFileDescriptor"
graceful_stop_lifecycle_repository_descriptor_methods = [
  "__del__", "__index__", "close", "fileno",
]
graceful_stop_lifecycle_repository_class = "_Repository"
graceful_stop_lifecycle_repository_methods = ["reviewed"]
graceful_stop_lifecycle_repository_staging_unlink_function = "_publish_staged_file"
graceful_stop_lifecycle_repository_staging_names = [
  "STAGING_ONE", "STAGING_TWO", "STAGING_THREE",
]
graceful_stop_lifecycle_repository_flock_acquisitions = 1
graceful_stop_lifecycle_repository_flock_unlocks = 0
forbidden_graceful_stop_lifecycle_repository_symbols = ["fork", "rename"]
graceful_stop_lifecycle_repository_private_reference_roots = [
  "apps", "packages", "scripts",
]
graceful_stop_lifecycle_repository_module = "scripts.lifecycle"
graceful_stop_lifecycle_repository_private_symbols = [
  "_build_repository_state_registry", "_persist_attempt", "_register_repository_state",
]
graceful_stop_lifecycle_repository_private_callsites._register_repository_state = []
graceful_stop_lifecycle_repository_public_symbols = ["safe"]

[scan.graceful_stop_lifecycle_repository_literal_constants]
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS = "recovery_required"
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON = '''
operation_bound_supervisor_bridge_unavailable'''

[scan.graceful_stop_lifecycle_repository_enum_members.Phase]
ATTEMPT_RESERVED = "attempt_reserved"
""",
        encoding="utf-8",
    )

    violations = check(tmp_path, config)
    messages = {violation.message for violation in violations}

    assert any("unreviewed non-project binding 'subprocess:*'" in item for item in messages)
    assert any("exact reviewed top-level definition surface" in item for item in messages)
    assert any(
        "exact literal constant 'POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS'" in item
        for item in messages
    )
    assert any(
        "exact literal constant 'POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON'" in item
        for item in messages
    )
    assert any("exact enum members for 'Phase'" in item for item in messages)
    for capability in (
        "open",
        "target.chmod",
        "target.hardlink_to",
        "target.mkdir",
        "target.open",
        "target.symlink_to",
        "target.touch",
    ):
        assert any(f"unreviewed filesystem capability '{capability}'" in item for item in messages)
    assert any("filesystem/FFI API 'ctypes.memmove'" in item for item in messages)
    assert any("filesystem/FFI API '_LIBC.system'" in item for item in messages)
    assert any("filesystem/FFI API 'os.open'" in item for item in messages)
    assert any("effect API 'fork'" in item for item in messages)
    assert any("exact nonblocking acquisition or exact unlock" in item for item in messages)
    assert any("cannot alias or re-export FFI binding '_OWNED_OPEN'" in item for item in messages)
    assert any("unreviewed method '_Repository.effect'" in item for item in messages)
    assert any("may unlink only its exact fixed staging file" in item for item in messages)
    assert any("exact reviewed public __all__ surface" in item for item in messages)
    assert any("cannot import unconnected module 'scripts.lifecycle'" in item for item in messages)
    assert any("private seam 'scripts.lifecycle._persist_attempt'" in item for item in messages)
    assert any(
        "private seam 'scripts.lifecycle._build_repository_state_registry'" in item
        for item in messages
    )
    assert any(
        "private seam 'scripts.lifecycle._register_repository_state'" in item for item in messages
    )
    assert any(
        "alias or re-export private callable '_register_repository_state'" in item
        for item in messages
    )
    assert any(
        violation.path == Path("apps/dynamic_consumer.py")
        and "cannot import unconnected module 'scripts.lifecycle'" in violation.message
        for violation in violations
    )


def test_every_supported_trusted_time_python_target_uses_isolated_launcher() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert makefile.count("$(TRUSTED_TIME_PYTHON)") == 19
    for script in (
        "diagnose_trusted_time_runtime.py",
        "enroll_trusted_time_head_anchor.py",
        "inspect_trusted_time_qualification.py",
        "provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        "provision_trusted_time_post_enrollment_operator_authority.py",
        "start_trusted_time_supervisor.py",
        "trusted_time_post_enrollment_graceful_stop_decision_artifacts.py",
        "trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
        "trusted_time_post_enrollment_operator_attestation_artifacts.py",
        "verify_trusted_time_compose.py",
        "verify_trusted_time_images.py",
    ):
        assert script in makefile


def test_post_enrollment_start_is_reachable_only_through_standalone_host_orchestrator() -> None:
    legacy_execution_contracts = (
        "phase6d-post-enrollment-start-execution-approval-v1",
        "phase6d-post-enrollment-start-execution-attempt-v1",
        "phase6d-post-enrollment-start-execution-admission-v1",
        "phase6d-post-enrollment-start-execution-admission-v2",
    )
    legacy_host_orchestrator_contracts = (
        "phase6d-post-enrollment-start-host-orchestrator-v1",
        "phase6d-post-enrollment-start-host-orchestrator-v2",
    )
    execution_admission_api_names = (
        "trusted_time_post_enrollment_execution_admission",
        "phase6d-post-enrollment-start-execution-approval-v2",
        "phase6d-post-enrollment-start-execution-attempt-v2",
        "phase6d-post-enrollment-start-execution-attempt-v3",
        "phase6d-post-enrollment-start-execution-admission-v3",
        ".post-enrollment-start-execution-attempt-slot",
        "HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION",
        "LoadedTrustedTimePostEnrollmentExecutionApproval",
        "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval",
        "TrustedTimePostEnrollmentExecutionAdmission",
        "decode_post_enrollment_execution_approval_bytes",
        "load_post_enrollment_execution_approval",
        "load_post_enrollment_operator_attested_execution_approval",
        "reserve_post_enrollment_execution_attempt",
        "retain_post_enrollment_execution_approval",
        "_consume_post_enrollment_execution_admission",
    )
    image_provenance_api_names = (
        "TrustedTimeImageAdmissionProvenance",
        "load_image_admission_provenance_artifact",
    )
    prepared_creation_api_names = (
        "_TrustedTimePostEnrollmentPreparedReviewedTopologyCreation",
        "_prepare_reviewed_topology_creation",
        "_execute_prepared_reviewed_topology_creation",
    )
    sequence_one_reauthentication_api_names = (
        "trusted_time_post_enrollment_sequence_one_reauthentication",
        "phase6d-post-enrollment-sequence-one-read-only-reauthentication-v1",
        "TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer",
        "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer",
    )
    host_orchestrator_api_names = (
        "trusted_time_post_enrollment_host_orchestrator",
        "POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION",
        "phase6d-post-enrollment-start-host-orchestrator-v3",
        "POST_ENROLLMENT_HOST_ORCHESTRATOR_STATUS",
        "terminal_outcome_retained",
        '"orchestrator_status"',
        "TrustedTimePostEnrollmentHostOrchestratorRejected",
        "run_operator_attested_post_enrollment_start_once",
        "--operator-attested-approval-artifact",
    )
    active_controller_api_names = (
        "trusted_time_post_enrollment_active_controller",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_STATUS",
        "phase6d-post-enrollment-start-active-controller-v1",
        "post_enrollment_start_confirmed",
        "TrustedTimePostEnrollmentStartActiveControllerRejected",
        "TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired",
        "run_post_enrollment_start_active_controller",
    )
    active_controller_admission_api_names = (
        "trusted_time_post_enrollment_active_controller_admission",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS",
        "phase6d-post-enrollment-start-active-controller-admission-v1",
        "active_controller_admission_unqualified",
        "TrustedTimePostEnrollmentStartActiveControllerAdmission",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired",
        "prepare_post_enrollment_start_active_controller_admission",
        "_consume_active_controller_continuation",
        "active_controller_authorized",
        "controller_execution_authorized",
    )
    controller_outcome_api_names = (
        "trusted_time_post_enrollment_controller_outcome",
        "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION",
        "phase6d-post-enrollment-start-retained-controller-outcome-v1",
        "RetainedTrustedTimePostEnrollmentStartControllerOutcome",
        "TrustedTimePostEnrollmentStartControllerOutcomeEvidence",
        "load_retained_post_enrollment_start_controller_outcome",
        "retain_post_enrollment_start_controller_outcome",
        "revalidate_retained_post_enrollment_start_controller_outcome",
        ".post-enrollment-start-controller-outcome-slot",
        ".post-enrollment-start-controller-outcome-staging",
        ".post-enrollment-start-controller-outcome-commit-staging",
        ".post-enrollment-start-controller-outcome-committed",
    )
    persistent_topology_api_names = (
        "trusted_time_post_enrollment_persistent_topology",
        "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION",
        "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS",
        "phase6d-post-enrollment-start-persistent-topology-snapshot-v1",
        "persistent_topology_snapshot_unqualified",
        "TrustedTimePostEnrollmentPersistentTopologySnapshot",
        "validate_post_enrollment_start_persistent_topology",
    )
    sequence_two_verifier_api_names = (
        "trusted_time_post_enrollment_sequence_two_verifier",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS",
        "phase6d-post-enrollment-start-sequence-two-verifier-v1",
        "TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration",
        "TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected",
        "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
        "prepare_trusted_time_post_enrollment_start_sequence_two_verifier",
    )
    action_topology_fence_api_names = (
        "trusted_time_post_enrollment_action_topology_fence",
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-claimed-action-topology-fence-v1",
        "claimed_action_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFence",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired",
        "prepare_post_enrollment_start_leased_claimed_action_topology_fence",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_CONTRACT_VERSION",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_STATUS",
        "phase6d-post-enrollment-final-action-topology-observation-v1",
        "final_action_staged_unreleased_topology_observation_unqualified",
        "TrustedTimePostEnrollmentFinalActionTopologyObservation",
        "_consume_claimed_fence_action_choreography",
        "_consume_claimed_action_fence_controller_choreography",
        "_issue_claimed_final_action_topology_snapshot",
        "_require_armed_recovery_outcome_retention",
        "_require_unbound_recovery_retention_preparation",
        "_recovery_outcome_retention_is_armed",
        "_adopt_registered_confirmed_terminal_outcome",
    )
    recovery_outcome_api_names = (
        "trusted_time_post_enrollment_outcome",
        "phase6d-post-enrollment-start-retained-recovery-outcome-v1",
        '"recovery_required"',
        "retain_post_enrollment_start_recovery_required_outcome",
        "_TrustedTimePostEnrollmentRecoveryClaimBinder",
        "_TrustedTimePostEnrollmentRecoveryRetentionCapability",
        "_issue_recovery_retention_claim_binder",
        "_run_exclusive_choreography_with_recovery_retention",
        "_POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS",
        ".post-enrollment-start-recovery-outcome-staging",
    )
    claimed_fence_api_names = (
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-claimed-pre-release-topology-fence-v1",
        "claimed_pre_release_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        "TrustedTimePostEnrollmentStartClaimedFenceRejected",
        "TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired",
        "prepare_post_enrollment_start_claimed_pre_release_fence",
        "prepare_post_enrollment_start_leased_claimed_pre_release_fence",
    )
    topology_cursor_api_names = (
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_CONTRACT_VERSION",
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_STATUS",
        "phase6d-post-enrollment-topology-observation-cursor-v1",
        "topology_observation_cursor_unqualified",
        "TrustedTimePostEnrollmentTopologyObservationCursor",
        "issue_observation_cursor",
    )
    topology_fence_api_names = (
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-pre-claim-topology-fence-v1",
        "pre_claim_same_session_topology_fence_unqualified",
        "phase6d-post-enrollment-start-pre-release-topology-fence-v1",
        "pre_release_same_session_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartPreClaimTopologyFence",
        "TrustedTimePostEnrollmentStartPreReleaseTopologyFence",
        "TrustedTimePostEnrollmentStartTopologyFenceRejected",
        "bind_post_enrollment_start_pre_claim_topology_fence",
        "bind_post_enrollment_start_pre_release_topology_fence",
    )
    forbidden_names = (
        *legacy_execution_contracts,
        *legacy_host_orchestrator_contracts,
        *execution_admission_api_names,
        *image_provenance_api_names,
        *prepared_creation_api_names,
        *sequence_one_reauthentication_api_names,
        *host_orchestrator_api_names,
        "trusted_time_post_enrollment_topology",
        "validate_post_enrollment_start_created_topology",
        "trusted_time_post_enrollment_staged_topology",
        "validate_post_enrollment_start_staged_unreleased_topology",
        "trusted_time_post_enrollment_topology_reader",
        "phase6d-post-enrollment-topology-observation-reader-v3",
        "TrustedTimePostEnrollmentTopologyObservationIssuer",
        "TrustedTimePostEnrollmentCreatedTopologyObservation",
        "TrustedTimePostEnrollmentStagedTopologyObservation",
        *active_controller_api_names,
        *active_controller_admission_api_names,
        *action_topology_fence_api_names,
        "trusted_time_post_enrollment_claimed_fence",
        *claimed_fence_api_names,
        "_run_exclusive_choreography",
        "choreography_lease",
        "choreography_deadline",
        *recovery_outcome_api_names,
        *controller_outcome_api_names,
        *persistent_topology_api_names,
        *sequence_two_verifier_api_names,
        *topology_cursor_api_names,
        "trusted_time_post_enrollment_topology_fence",
        *topology_fence_api_names,
    )
    supported_surfaces = (
        ROOT / "Makefile",
        ROOT / "apps" / "api" / "main.py",
        ROOT / "apps" / "trader" / "main.py",
        ROOT / "apps" / "worker" / "main.py",
        *sorted((ROOT / "apps" / "trusted_time_supervisor").glob("*.py")),
        ROOT / "infra" / "compose" / "compose.yaml",
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "infra" / "compose" / "trusted-time.defaults.env",
        ROOT / "pyproject.toml",
        ROOT / "scripts" / "diagnose_trusted_time_runtime.py",
        ROOT / "scripts" / "enroll_trusted_time_head_anchor.py",
        ROOT / "scripts" / "generate_trusted_time_anchor_artifacts.py",
        ROOT / "scripts" / "inspect_trusted_time_qualification.py",
        ROOT / "scripts" / "migrate_phase6_trusted_time_head_anchors.py",
        ROOT / "scripts" / "migrate_phase6_trusted_time_uncertainty.py",
        ROOT / "scripts" / "prove_trusted_time_anchor_storage.py",
        ROOT / "scripts" / "provision_trusted_time_anchor_project.py",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
    )

    for path in supported_surfaces:
        payload = path.read_text(encoding="utf-8")
        for forbidden_name in forbidden_names:
            assert forbidden_name not in payload
        assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])600(?:\.0)?(?![0-9A-Za-z])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])605(?:\.0)?(?![0-9A-Za-z])", payload) is None

    network_owned_sources = (
        ROOT / "scripts" / "trusted_time_post_enrollment_topology_reader.py",
        ROOT / "scripts" / "trusted_time_post_enrollment_active_controller.py",
        ROOT / "scripts" / "trusted_time_post_enrollment_persistent_topology.py",
    )
    for path in network_owned_sources:
        payload = path.read_text(encoding="utf-8")
        assert "COMPOSE_NETWORK_NAME" not in payload
        assert "post_enrollment_created_topology_network_name" in payload
    reader_payload = network_owned_sources[0].read_text(encoding="utf-8")
    assert "phase6d-post-enrollment-topology-observation-reader-v3" in reader_payload
    assert "phase6d-post-enrollment-topology-observation-reader-v1" not in reader_payload
    network_contract_docs = (
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "IMPLEMENTATION_PLAN.md",
        ROOT / "docs" / "adr" / "0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs" / "runbooks" / "trusted-time-supervisor.md",
    )
    for path in network_contract_docs:
        payload = path.read_text(encoding="utf-8")
        normalized_payload = " ".join(payload.split())
        assert "issuer-session-derived network name" in normalized_payload
        assert "fixed legacy" in payload
        assert "phase6d-post-enrollment-topology-observation-reader-v1" not in payload
    assert all(
        "phase6d-post-enrollment-topology-observation-reader-v3" in path.read_text(encoding="utf-8")
        for path in network_contract_docs
    )

    staged_input_digest_environment = (
        "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256",
    )
    supervisor_main = (ROOT / "apps" / "trusted_time_supervisor" / "main.py").read_text(
        encoding="utf-8"
    )
    supervisor_configuration = (ROOT / "apps" / "trusted_time_supervisor" / "config.py").read_text(
        encoding="utf-8"
    ) + (ROOT / "apps" / "trusted_time_supervisor" / "head_anchor_config.py").read_text(
        encoding="utf-8"
    )
    supervisor_start = (ROOT / "scripts" / "start_trusted_time_supervisor.py").read_text(
        encoding="utf-8"
    )
    for environment_name in staged_input_digest_environment:
        assert environment_name in supervisor_configuration
    assert "_EXPECTED_STAGED_INPUT_SHA256_ENVIRONMENT" in supervisor_main
    assert "POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT" in supervisor_start
    assert "POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT" in reader_payload
    assert "validate_exact_post_start_exited_supervisor_container" in reader_payload
    assert "_ReviewedCreatedTopologyRegistration" in reader_payload
    normalized_contract_docs = tuple(
        " ".join(path.read_text(encoding="utf-8").split()) for path in network_contract_docs
    )
    for normalized_payload in normalized_contract_docs:
        assert "four private expected SHA-256 bindings" in normalized_payload
        assert "exact bytes" in normalized_payload
        assert "before marker, readiness, or claim" in normalized_payload
        assert "private digests" in normalized_payload

    admission_cli = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert '"scripts/trusted_time_post_enrollment_action_topology_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_action_topology_fence") == 1
    assert '"scripts/trusted_time_post_enrollment_active_controller.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_active_controller") == 2
    assert '"scripts/trusted_time_post_enrollment_active_controller_admission.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_active_controller_admission") == 1
    assert '"scripts/trusted_time_post_enrollment_claimed_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_claimed_fence") == 1
    assert '"scripts/trusted_time_post_enrollment_controller_outcome.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_controller_outcome") == 1
    assert '"scripts/trusted_time_post_enrollment_execution_admission.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_execution_admission") == 1
    assert '"scripts/trusted_time_post_enrollment_host_orchestrator.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_host_orchestrator") == 1
    assert '"scripts/trusted_time_post_enrollment_outcome.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_outcome") == 1
    assert '"scripts/trusted_time_post_enrollment_persistent_topology.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_persistent_topology") == 1
    assert (
        '"scripts/trusted_time_post_enrollment_sequence_one_reauthentication.py"' in admission_cli
    )
    assert admission_cli.count("trusted_time_post_enrollment_sequence_one_reauthentication") == 1
    assert '"scripts/trusted_time_post_enrollment_sequence_two_verifier.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_sequence_two_verifier") == 1
    assert '"scripts/trusted_time_post_enrollment_topology_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_topology_fence") == 1
    for forbidden_name in (
        *legacy_execution_contracts,
        *legacy_host_orchestrator_contracts,
        *execution_admission_api_names[1:],
        *prepared_creation_api_names,
        *sequence_one_reauthentication_api_names[1:],
        *host_orchestrator_api_names[1:],
        *active_controller_api_names[1:],
        *active_controller_admission_api_names[1:],
        *action_topology_fence_api_names[1:],
        *recovery_outcome_api_names[1:],
        *controller_outcome_api_names[1:],
        *persistent_topology_api_names[1:],
        *sequence_two_verifier_api_names[1:],
        *claimed_fence_api_names,
        *topology_cursor_api_names,
        *topology_fence_api_names,
    ):
        assert forbidden_name not in admission_cli
    assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])600(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])605(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None

    orchestrator = (
        ROOT / "scripts" / "trusted_time_post_enrollment_host_orchestrator.py"
    ).read_text(encoding="utf-8")
    for required_name in (
        execution_admission_api_names[0],
        "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval",
        "load_post_enrollment_operator_attested_execution_approval",
        "reserve_post_enrollment_execution_attempt",
        "_consume_post_enrollment_execution_admission",
        "verify_and_write_existing_image_admission",
        "_prepare_reviewed_topology_creation",
        "_execute_prepared_reviewed_topology_creation",
        sequence_one_reauthentication_api_names[0],
        sequence_one_reauthentication_api_names[-1],
        "trusted_time_post_enrollment_topology_reader",
        host_orchestrator_api_names[2],
        active_controller_api_names[0],
        active_controller_admission_api_names[0],
        action_topology_fence_api_names[0],
        claimed_fence_api_names[-1],
        sequence_two_verifier_api_names[0],
        "run_operator_attested_post_enrollment_start_once",
        host_orchestrator_api_names[-1],
        'if __name__ == "__main__"',
    ):
        assert required_name in orchestrator
    assert orchestrator.count("_require_isolated_cli_source_runtime") == 2
    assert "expected_relative_path=Path" in orchestrator
    assert '"scripts/trusted_time_post_enrollment_host_orchestrator.py"' in orchestrator
    assert "sys.flags.isolated != 1" in orchestrator
    assert "sys.flags.dont_write_bytecode != 1" in orchestrator
    assert 'sys.pycache_prefix != "/dev/null"' in orchestrator
    assert '"--approval-artifact"' not in orchestrator
    assert orchestrator.count('"--operator-attested-approval-artifact"') == 1
    assert orchestrator.count('"--runtime-env-file"') == 1
    assert orchestrator.count("_recovery_outcome_retention_is_armed") == 1
    assert orchestrator.count("_adopt_registered_confirmed_terminal_outcome") == 1
    assert "admit_post_enrollment_execution_attempt" not in orchestrator
    for legacy_contract in legacy_host_orchestrator_contracts:
        assert legacy_contract not in orchestrator

    validation_start = orchestrator.index("def _validate_compose(")
    validation_end = orchestrator.index("\ndef _retire_inputs(", validation_start)
    validation_body = orchestrator[validation_start:validation_end]
    assert validation_body.index("render_compose_model(") < validation_body.index(
        "validate_compose_model("
    )
    assert validation_body.index("validate_materialized_database_secret(") < validation_body.index(
        "verify_and_write_existing_image_admission("
    )
    assert validation_body.index(
        "validate_materialized_trusted_time_head_anchor_inputs("
    ) < validation_body.index("verify_and_write_existing_image_admission(")

    execution_start = orchestrator.index("def _execute_under_issuer(")
    execution_end = orchestrator.index(
        "\ndef _run_operator_attested_post_enrollment_start_once_with_dependencies("
    )
    execution_body = orchestrator[execution_start:execution_end]
    assert (
        execution_body.index("_MaterializedRuntimeInputOwner()")
        < execution_body.index("_materialize_runtime_inputs(")
        < execution_body.index("_validate_compose(")
        < execution_body.index("_run_post_enrollment_choreography(")
    )

    run_start = execution_end + 1
    run_end = orchestrator.index("\ndef _safe_terminal_payload(", run_start)
    run_body = orchestrator[run_start:run_end]
    run_order = (
        "load_post_enrollment_operator_attested_execution_approval(",
        "_approved_launch(",
        "_current_git_revision()",
        "_minimal_docker_environment()",
        "qualify_local_docker_daemon(",
        "issuer = allocate_inert_issuer()",
        "activation_result = activate_issuer(",
        "_execute_under_issuer(",
    )
    run_offsets = tuple(run_body.index(marker) for marker in run_order)
    assert run_offsets == tuple(sorted(run_offsets))
    assert len(re.findall(r"(?m)^\s+abort_once\(\)$", run_body)) == 5
    assert run_body.index("def abort_once()") < run_body.index(
        "activation_result = activate_issuer("
    )
    assert "TrustedTimePostEnrollmentTopologyObservationIssuer.open(" not in orchestrator
    topology_reader = (
        ROOT / "scripts" / "trusted_time_post_enrollment_topology_reader.py"
    ).read_text(encoding="utf-8")
    assert "\n    def allocate_inert(" in topology_reader
    assert "\n    def activate(" in topology_reader
    assert "\n    def open(" not in topology_reader
    assert "TrustedTimePostEnrollmentTopologyObservationIssuer.open" not in topology_reader

    choreography_start = orchestrator.index("    def choreography(")
    choreography_end = orchestrator.index(
        "    result = issuer._run_exclusive_choreography_with_recovery_retention(",
        choreography_start,
    )
    choreography_body = orchestrator[choreography_start:choreography_end]
    ordered_late_attempt_markers = (
        "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer(",
        "issuer._prepare_reviewed_topology_creation(",
        "reserve_post_enrollment_execution_attempt(",
        "_consume_post_enrollment_execution_admission(",
        "mutation_may_have_begun = True",
        "issuer._execute_prepared_reviewed_topology_creation(",
    )
    marker_offsets = tuple(
        choreography_body.index(marker) for marker in ordered_late_attempt_markers
    )
    assert marker_offsets == tuple(sorted(marker_offsets))

    execution_admission = (
        ROOT / "scripts" / "trusted_time_post_enrollment_execution_admission.py"
    ).read_text(encoding="utf-8")
    for contract in (
        "phase6d-post-enrollment-start-execution-approval-v2",
        "phase6d-post-enrollment-start-execution-attempt-v2",
        "phase6d-post-enrollment-start-execution-attempt-v3",
        "phase6d-post-enrollment-start-execution-admission-v3",
    ):
        assert contract in execution_admission
    for legacy_contract in legacy_execution_contracts:
        assert legacy_contract not in execution_admission
    reserve_signature = re.search(
        r"    def reserve\(\n(?P<parameters>.*?)\n    \) -> ",
        execution_admission,
        flags=re.DOTALL,
    )
    assert reserve_signature is not None
    reserve_parameters = reserve_signature.group("parameters")
    assert "loaded_attested_approval:" in reserve_parameters
    assert "image_admission:" in reserve_parameters
    assert "approval_artifact:" not in reserve_parameters
    assert "admit_post_enrollment_execution_attempt" not in execution_admission
    assert '"retain_post_enrollment_execution_approval"' in execution_admission

    image_admission = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(
        encoding="utf-8"
    )
    for required_name in image_provenance_api_names:
        assert required_name in image_admission
    active_controller = (
        ROOT / "scripts" / "trusted_time_post_enrollment_active_controller.py"
    ).read_text(encoding="utf-8")
    assert active_controller.count("_adopt_registered_confirmed_terminal_outcome") == 1
    sequence_one = (
        ROOT / "scripts" / "trusted_time_post_enrollment_sequence_one_reauthentication.py"
    ).read_text(encoding="utf-8")
    assert sequence_one.count("_require_unbound_recovery_retention_preparation") == 2


def test_runtime_state_inspector_is_in_container_only_and_not_a_host_controller() -> None:
    command = "autoquant-trusted-time-post-enrollment-runtime-state"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    marker_paths = (
        "/tmp/post-enrollment-start-sequence-two-deadline",
        "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
        "/tmp/post-enrollment-start-release",
        "/tmp/.post-enrollment-start-release-staging",
        "/tmp/post-enrollment-start-sequence-two-ready",
        "/tmp/.post-enrollment-start-sequence-two-ready-staging",
    )

    assert pyproject.count(command) == 1
    for path in (
        ROOT / "Makefile",
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
    ):
        payload = path.read_text(encoding="utf-8")
        assert command not in payload
        for marker_path in marker_paths:
            assert marker_path not in payload


@pytest.mark.parametrize(
    ("target", "assignments", "expected_flags"),
    [
        (
            "trusted-time-prepare-post-enrollment-operator-authority",
            (
                "TRUSTED_TIME_OPERATOR_PUBLIC_KEY_FILE=/private/operator/public-key.raw",
                "TRUSTED_TIME_OPERATOR_CANDIDATE_DIRECTORY=/private/operator/candidates",
            ),
            (
                '--raw-public-key-file "/private/operator/public-key.raw"',
                '--candidate-directory "/private/operator/candidates"',
            ),
        ),
        (
            "trusted-time-install-post-enrollment-operator-authority",
            (
                "TRUSTED_TIME_OPERATOR_CANDIDATE_ARTIFACT=/private/operator/candidate.json",
                f"TRUSTED_TIME_OPERATOR_APPROVED_AUTHORITY_SHA256={'a' * 64}",
                f"TRUSTED_TIME_OPERATOR_APPROVED_PUBLIC_KEY_SHA256={'b' * 64}",
            ),
            (
                '--candidate-artifact "/private/operator/candidate.json"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
            ),
        ),
    ],
)
def test_operator_authority_make_targets_use_exact_two_phase_cli(
    target: str,
    assignments: tuple[str, ...],
    expected_flags: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert "scripts/provision_trusted_time_post_enrollment_operator_authority.py" in (
        completed.stdout
    )
    for expected_flag in expected_flags:
        assert expected_flag in completed.stdout
    assert "--env-file" not in completed.stdout
    assert "docker" not in completed.stdout.lower()
    if target == "trusted-time-prepare-post-enrollment-operator-authority":
        assert " install " not in completed.stdout
        assert "--candidate-artifact" not in completed.stdout
        assert "--expected-authority-sha256" not in completed.stdout
        assert "--expected-public-key-sha256" not in completed.stdout
    else:
        assert " prepare " not in completed.stdout
        assert "--raw-public-key-file" not in completed.stdout
        assert "--candidate-directory" not in completed.stdout


@pytest.mark.parametrize(
    ("target", "assignments", "required_name"),
    [
        (
            "trusted-time-prepare-post-enrollment-operator-authority",
            (),
            "TRUSTED_TIME_OPERATOR_PUBLIC_KEY_FILE",
        ),
        (
            "trusted-time-prepare-post-enrollment-operator-authority",
            ("TRUSTED_TIME_OPERATOR_PUBLIC_KEY_FILE=/private/operator/public-key.raw",),
            "TRUSTED_TIME_OPERATOR_CANDIDATE_DIRECTORY",
        ),
        (
            "trusted-time-install-post-enrollment-operator-authority",
            (),
            "TRUSTED_TIME_OPERATOR_CANDIDATE_ARTIFACT",
        ),
        (
            "trusted-time-install-post-enrollment-operator-authority",
            ("TRUSTED_TIME_OPERATOR_CANDIDATE_ARTIFACT=/private/operator/candidate.json",),
            "TRUSTED_TIME_OPERATOR_APPROVED_AUTHORITY_SHA256",
        ),
        (
            "trusted-time-install-post-enrollment-operator-authority",
            (
                "TRUSTED_TIME_OPERATOR_CANDIDATE_ARTIFACT=/private/operator/candidate.json",
                f"TRUSTED_TIME_OPERATOR_APPROVED_AUTHORITY_SHA256={'a' * 64}",
            ),
            "TRUSTED_TIME_OPERATOR_APPROVED_PUBLIC_KEY_SHA256",
        ),
    ],
)
def test_operator_authority_make_guards_run_before_cli(
    target: str,
    assignments: tuple[str, ...],
    required_name: str,
) -> None:
    completed = subprocess.run(
        ("make", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert required_name in completed.stderr
    assert "scripts/provision_trusted_time_post_enrollment_operator_authority.py" not in (
        completed.stdout
    )


@pytest.mark.parametrize(
    ("target", "assignments", "expected_subcommand", "expected_flags", "forbidden_flags"),
    [
        (
            "trusted-time-prepare-post-enrollment-operator-attestation-statement",
            (
                "TRUSTED_TIME_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT=/private/operator/authority-candidate.json",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_EXECUTION_APPROVAL_V2_ARTIFACT=/private/operator/v2-approval.json",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_STATEMENT_CANDIDATE_DIRECTORY=/private/operator/statement-candidates",
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256={'a' * 64}",
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256={'b' * 64}",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_EXECUTION_APPROVAL_V2_SHA256="
                + "c" * 64,
            ),
            "prepare-statement",
            (
                '--authority-artifact "/private/operator/authority-candidate.json"',
                '--execution-approval-v2-artifact "/private/operator/v2-approval.json"',
                '--statement-candidate-directory "/private/operator/statement-candidates"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
                f'--expected-execution-approval-v2-sha256 "{"c" * 64}"',
            ),
            (
                "--statement-artifact",
                "--detached-signature-file",
                "--envelope-candidate-directory",
                "--expected-statement-sha256",
                "--expected-signature-sha256",
            ),
        ),
        (
            "trusted-time-verify-post-enrollment-operator-attestation-envelope",
            (
                "TRUSTED_TIME_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT=/private/operator/authority-candidate.json",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_EXECUTION_APPROVAL_V2_ARTIFACT=/private/operator/v2-approval.json",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_STATEMENT_ARTIFACT=/private/operator/statement-candidate.json",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_DETACHED_SIGNATURE_FILE=/private/operator/signature.raw",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_ENVELOPE_CANDIDATE_DIRECTORY=/private/operator/envelope-candidates",
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256={'a' * 64}",
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256={'b' * 64}",
                "TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_EXECUTION_APPROVAL_V2_SHA256="
                + "c" * 64,
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_STATEMENT_SHA256={'d' * 64}",
                f"TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_SIGNATURE_SHA256={'e' * 64}",
            ),
            "verify-signature",
            (
                '--authority-artifact "/private/operator/authority-candidate.json"',
                '--execution-approval-v2-artifact "/private/operator/v2-approval.json"',
                '--statement-artifact "/private/operator/statement-candidate.json"',
                '--detached-signature-file "/private/operator/signature.raw"',
                '--envelope-candidate-directory "/private/operator/envelope-candidates"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
                f'--expected-execution-approval-v2-sha256 "{"c" * 64}"',
                f'--expected-statement-sha256 "{"d" * 64}"',
                f'--expected-signature-sha256 "{"e" * 64}"',
            ),
            ("--statement-candidate-directory",),
        ),
    ],
)
def test_operator_attestation_artifact_make_targets_use_exact_offline_cli(
    target: str,
    assignments: tuple[str, ...],
    expected_subcommand: str,
    expected_flags: tuple[str, ...],
    forbidden_flags: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert (
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py" in completed.stdout
    )
    assert f" {expected_subcommand} " in completed.stdout
    for expected_flag in expected_flags:
        assert expected_flag in completed.stdout
    for forbidden_flag in forbidden_flags:
        assert forbidden_flag not in completed.stdout
    forbidden_tokens = (
        "--env-file",
        "--private-key",
        "--signing-key",
        "docker",
        "stdin",
    )
    for forbidden_token in forbidden_tokens:
        assert forbidden_token not in completed.stdout.lower()


@pytest.mark.parametrize(
    ("target", "ordered_assignments"),
    [
        (
            "trusted-time-prepare-post-enrollment-operator-attestation-statement",
            (
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT",
                    "/private/operator/authority-candidate.json",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_EXECUTION_APPROVAL_V2_ARTIFACT",
                    "/private/operator/v2-approval.json",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_STATEMENT_CANDIDATE_DIRECTORY",
                    "/private/operator/statement-candidates",
                ),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256", "a" * 64),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256", "b" * 64),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_EXECUTION_APPROVAL_V2_SHA256",
                    "c" * 64,
                ),
            ),
        ),
        (
            "trusted-time-verify-post-enrollment-operator-attestation-envelope",
            (
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT",
                    "/private/operator/authority-candidate.json",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_EXECUTION_APPROVAL_V2_ARTIFACT",
                    "/private/operator/v2-approval.json",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_STATEMENT_ARTIFACT",
                    "/private/operator/statement-candidate.json",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_DETACHED_SIGNATURE_FILE",
                    "/private/operator/signature.raw",
                ),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_ENVELOPE_CANDIDATE_DIRECTORY",
                    "/private/operator/envelope-candidates",
                ),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256", "a" * 64),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256", "b" * 64),
                (
                    "TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_EXECUTION_APPROVAL_V2_SHA256",
                    "c" * 64,
                ),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_STATEMENT_SHA256", "d" * 64),
                ("TRUSTED_TIME_OPERATOR_ATTESTATION_EXPECTED_SIGNATURE_SHA256", "e" * 64),
            ),
        ),
    ],
)
def test_operator_attestation_artifact_make_guards_run_before_cli(
    target: str,
    ordered_assignments: tuple[tuple[str, str], ...],
) -> None:
    for missing_index, (required_name, _) in enumerate(ordered_assignments):
        supplied = tuple(f"{name}={value}" for name, value in ordered_assignments[:missing_index])
        completed = subprocess.run(
            ("make", target, *supplied),
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": os.defpath},
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert completed.returncode != 0
        assert required_name in completed.stderr
        assert (
            "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
            not in completed.stdout
        )


@pytest.mark.parametrize(
    (
        "target",
        "script",
        "assignments",
        "expected_subcommand",
        "expected_flags",
        "forbidden_flags",
    ),
    [
        (
            "trusted-time-prepare-post-enrollment-graceful-stop-operator-authority",
            "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
            (
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_PUBLIC_KEY_FILE=/private/stop/public-key.raw",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_CANDIDATE_DIRECTORY=/private/stop/authority-candidates",
            ),
            "prepare",
            (
                '--raw-public-key-file "/private/stop/public-key.raw"',
                '--candidate-directory "/private/stop/authority-candidates"',
            ),
            (
                "--candidate-artifact",
                "--expected-authority-sha256",
                "--expected-public-key-sha256",
            ),
        ),
        (
            "trusted-time-install-post-enrollment-graceful-stop-operator-authority",
            "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
            (
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_CANDIDATE_ARTIFACT=/private/stop/authority-candidate.json",
                f"TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_APPROVED_AUTHORITY_SHA256={'a' * 64}",
                f"TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_APPROVED_PUBLIC_KEY_SHA256={'b' * 64}",
            ),
            "install",
            (
                '--candidate-artifact "/private/stop/authority-candidate.json"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
            ),
            ("--raw-public-key-file", "--candidate-directory"),
        ),
        (
            "trusted-time-prepare-post-enrollment-graceful-stop-operator-attestation-statement",
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
            (
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT=/private/stop/authority-candidate.json",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION_V1_ARTIFACT=/private/stop/decision-v1.json",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CANDIDATE_DIRECTORY=/private/stop/statement-candidates",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256="
                + "a" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256="
                + "b" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_DECISION_V1_SHA256="
                + "c" * 64,
            ),
            "prepare-statement",
            (
                '--authority-artifact "/private/stop/authority-candidate.json"',
                '--graceful-stop-decision-v1-artifact "/private/stop/decision-v1.json"',
                '--statement-candidate-directory "/private/stop/statement-candidates"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
                f'--expected-graceful-stop-decision-v1-sha256 "{"c" * 64}"',
            ),
            (
                "--statement-artifact",
                "--detached-signature-file",
                "--envelope-candidate-directory",
                "--expected-statement-sha256",
                "--expected-signature-sha256",
                "--execution-approval-v2-artifact",
            ),
        ),
        (
            "trusted-time-verify-post-enrollment-graceful-stop-operator-attestation-envelope",
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
            (
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT=/private/stop/authority-candidate.json",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION_V1_ARTIFACT=/private/stop/decision-v1.json",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_ARTIFACT=/private/stop/statement-candidate.json",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DETACHED_SIGNATURE_FILE=/private/stop/signature.raw",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_CANDIDATE_DIRECTORY=/private/stop/envelope-candidates",
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256="
                + "a" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256="
                + "b" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_DECISION_V1_SHA256="
                + "c" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_STATEMENT_SHA256="
                + "d" * 64,
                "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_SIGNATURE_SHA256="
                + "e" * 64,
            ),
            "verify-signature",
            (
                '--authority-artifact "/private/stop/authority-candidate.json"',
                '--graceful-stop-decision-v1-artifact "/private/stop/decision-v1.json"',
                '--statement-artifact "/private/stop/statement-candidate.json"',
                '--detached-signature-file "/private/stop/signature.raw"',
                '--envelope-candidate-directory "/private/stop/envelope-candidates"',
                f'--expected-authority-sha256 "{"a" * 64}"',
                f'--expected-public-key-sha256 "{"b" * 64}"',
                f'--expected-graceful-stop-decision-v1-sha256 "{"c" * 64}"',
                f'--expected-statement-sha256 "{"d" * 64}"',
                f'--expected-signature-sha256 "{"e" * 64}"',
            ),
            ("--statement-candidate-directory", "--execution-approval-v2-artifact"),
        ),
    ],
)
def test_graceful_stop_public_artifact_make_targets_use_exact_offline_cli(
    target: str,
    script: str,
    assignments: tuple[str, ...],
    expected_subcommand: str,
    expected_flags: tuple[str, ...],
    forbidden_flags: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert script in completed.stdout
    assert f" {expected_subcommand} " in completed.stdout
    for expected_flag in expected_flags:
        assert expected_flag in completed.stdout
    for forbidden_flag in forbidden_flags:
        assert forbidden_flag not in completed.stdout
    for forbidden_token in (
        "--env-file",
        "--private-key",
        "--signing-key",
        "docker",
        "stdin",
        "active-controller",
        "host-orchestrator",
        "execution-admission",
    ):
        assert forbidden_token not in completed.stdout.lower()


@pytest.mark.parametrize(
    ("target", "script", "ordered_assignments"),
    [
        (
            "trusted-time-prepare-post-enrollment-graceful-stop-operator-authority",
            "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
            (
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_PUBLIC_KEY_FILE",
                    "/private/stop/public-key.raw",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_CANDIDATE_DIRECTORY",
                    "/private/stop/authority-candidates",
                ),
            ),
        ),
        (
            "trusted-time-install-post-enrollment-graceful-stop-operator-authority",
            "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
            (
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_CANDIDATE_ARTIFACT",
                    "/private/stop/authority-candidate.json",
                ),
                ("TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_APPROVED_AUTHORITY_SHA256", "a" * 64),
                ("TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_APPROVED_PUBLIC_KEY_SHA256", "b" * 64),
            ),
        ),
        (
            "trusted-time-prepare-post-enrollment-graceful-stop-operator-attestation-statement",
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
            (
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT",
                    "/private/stop/authority-candidate.json",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION_V1_ARTIFACT",
                    "/private/stop/decision-v1.json",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CANDIDATE_DIRECTORY",
                    "/private/stop/statement-candidates",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256",
                    "a" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256",
                    "b" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_DECISION_V1_SHA256",
                    "c" * 64,
                ),
            ),
        ),
        (
            "trusted-time-verify-post-enrollment-graceful-stop-operator-attestation-envelope",
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
            (
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_AUTHORITY_ARTIFACT",
                    "/private/stop/authority-candidate.json",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION_V1_ARTIFACT",
                    "/private/stop/decision-v1.json",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_ARTIFACT",
                    "/private/stop/statement-candidate.json",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_DETACHED_SIGNATURE_FILE",
                    "/private/stop/signature.raw",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_CANDIDATE_DIRECTORY",
                    "/private/stop/envelope-candidates",
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_AUTHORITY_SHA256",
                    "a" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_PUBLIC_KEY_SHA256",
                    "b" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_DECISION_V1_SHA256",
                    "c" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_STATEMENT_SHA256",
                    "d" * 64,
                ),
                (
                    "TRUSTED_TIME_GRACEFUL_STOP_OPERATOR_ATTESTATION_EXPECTED_SIGNATURE_SHA256",
                    "e" * 64,
                ),
            ),
        ),
    ],
)
def test_graceful_stop_public_artifact_make_guards_run_before_cli(
    target: str,
    script: str,
    ordered_assignments: tuple[tuple[str, str], ...],
) -> None:
    for missing_index, (required_name, _) in enumerate(ordered_assignments):
        supplied = tuple(f"{name}={value}" for name, value in ordered_assignments[:missing_index])
        completed = subprocess.run(
            ("make", target, *supplied),
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": os.defpath},
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert completed.returncode != 0
        assert required_name in completed.stderr
        assert script not in completed.stdout


def test_graceful_stop_decision_make_target_uses_exact_inert_cli() -> None:
    target = "trusted-time-prepare-post-enrollment-graceful-stop-decision"
    script = "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    assignments = (
        "TRUSTED_TIME_GRACEFUL_STOP_OPERATION_ID=123e4567-e89b-42d3-a456-426614174000",
        "TRUSTED_TIME_START_OPERATOR_ATTESTED_APPROVAL_ARTIFACT=/private/start/envelope.json",
        "TRUSTED_TIME_GRACEFUL_STOP_DECISION_CANDIDATE_DIRECTORY=/private/stop/decision-candidates",
        f"TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_CONTROLLER_OUTCOME_SHA256={'a' * 64}",
        f"TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_DURABLE_SHUTDOWN_LOCATOR_SHA256={'b' * 64}",
        f"TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_EXECUTION_ATTEMPT_SLOT_SHA256={'c' * 64}",
        "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_OPERATOR_ATTESTATION_ENVELOPE_SHA256="
        + "d" * 64,
        "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_OPERATION_ID="
        "223e4567-e89b-42d3-a456-426614174001",
        f"TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_APPROVAL_SHA256={'e' * 64}",
    )
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert script in completed.stdout
    assert " prepare-decision " in completed.stdout
    expected_flags = (
        "--graceful-stop-operation-id",
        "--start-operator-attested-approval-artifact",
        "--decision-candidate-directory",
        "--expected-controller-outcome-sha256",
        "--expected-durable-shutdown-locator-sha256",
        "--expected-start-execution-attempt-slot-sha256",
        "--expected-start-operator-attestation-envelope-sha256",
        "--expected-start-operation-id",
        "--expected-start-approval-sha256",
    )
    assert tuple(re.findall(r"(?m)^\s*(--[a-z0-9-]+) ", completed.stdout)) == expected_flags
    for forbidden_token in (
        "--artifact-directory",
        "--ignored-root",
        "--authority-artifact",
        "--private-key",
        "--signing-key",
        "--detached-signature-file",
        "--current-topology",
        "--trusted-head",
        "--stop-attempt-slot",
        "--stop-admission",
        "--stop-effect",
        "docker",
    ):
        assert forbidden_token not in completed.stdout.lower()
    assert "trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py" not in (
        completed.stdout
    )

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    header = re.search(rf"(?m)^{re.escape(target)}:(?P<header>[^\n]*)$", makefile)
    assert header is not None
    assert header.group("header").lstrip().startswith("## ")


def test_graceful_stop_decision_make_guards_all_inputs_before_cli() -> None:
    target = "trusted-time-prepare-post-enrollment-graceful-stop-decision"
    script = "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    ordered_assignments = (
        ("TRUSTED_TIME_GRACEFUL_STOP_OPERATION_ID", "123e4567-e89b-42d3-a456-426614174000"),
        (
            "TRUSTED_TIME_START_OPERATOR_ATTESTED_APPROVAL_ARTIFACT",
            "/private/start/envelope.json",
        ),
        (
            "TRUSTED_TIME_GRACEFUL_STOP_DECISION_CANDIDATE_DIRECTORY",
            "/private/stop/decision-candidates",
        ),
        ("TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_CONTROLLER_OUTCOME_SHA256", "a" * 64),
        (
            "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_DURABLE_SHUTDOWN_LOCATOR_SHA256",
            "b" * 64,
        ),
        (
            "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_EXECUTION_ATTEMPT_SLOT_SHA256",
            "c" * 64,
        ),
        (
            "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_OPERATOR_ATTESTATION_ENVELOPE_SHA256",
            "d" * 64,
        ),
        (
            "TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_OPERATION_ID",
            "223e4567-e89b-42d3-a456-426614174001",
        ),
        ("TRUSTED_TIME_GRACEFUL_STOP_EXPECTED_START_APPROVAL_SHA256", "e" * 64),
    )
    for missing_index, (required_name, _) in enumerate(ordered_assignments):
        supplied = tuple(f"{name}={value}" for name, value in ordered_assignments[:missing_index])
        completed = subprocess.run(
            ("make", target, *supplied),
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": os.defpath},
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert completed.returncode != 0
        assert required_name in completed.stderr
        assert script not in completed.stdout


def test_operator_authority_contract_and_provisioner_remain_public_only() -> None:
    from packages.domain.trusted_time_post_enrollment_operator_authority import (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS,
        TrustedTimePostEnrollmentOperatorAuthorityError,
        require_strict_post_enrollment_operator_public_key,
    )

    assert (
        frozenset(
            {
                "algorithm",
                "contract_version",
                "key_id",
                "public_key_base64",
                "public_key_sha256",
                "replay_domain",
                "service",
                "status",
            }
        )
        == POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS
    )
    assert POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM == "Ed25519"
    assert (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION
        == "phase6d-post-enrollment-operator-attestation-authority-v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID == "aqt-post-enrollment-start-operator-ed25519-v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
        == "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
        "post-enrollment-start/operator-attestation/v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE
        == "trusted-time-post-enrollment-operator-attestation-authority"
    )
    assert POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS == "public_operator_authority_material"

    valid_public_key = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    assert require_strict_post_enrollment_operator_public_key(valid_public_key) is valid_public_key
    ed25519_field_prime = 2**255 - 19
    invalid_public_keys = (
        b"\x01" + b"\x00" * 31,
        b"\x00" * 32,
        (ed25519_field_prime - 1).to_bytes(32, "little"),
        ed25519_field_prime.to_bytes(32, "little"),
        b"\x01" + b"\x00" * 30 + b"\x80",
        b"\x02" + b"\x00" * 31,
        bytes.fromhex("b0bfe83c17bc76a56d48f558b2e481436367d330d13b69733f32aa0ed50b99f3"),
    )
    for invalid_public_key in invalid_public_keys:
        with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
            require_strict_post_enrollment_operator_public_key(invalid_public_key)

    domain_path = ROOT / "packages/domain/trusted_time_post_enrollment_operator_authority.py"
    provisioner_path = ROOT / "scripts/provision_trusted_time_post_enrollment_operator_authority.py"
    provisioning_payload = domain_path.read_text(encoding="utf-8") + provisioner_path.read_text(
        encoding="utf-8"
    )
    forbidden_private_or_ambient_tokens = (
        "Ed25519PrivateKey",
        "from_private_bytes(",
        "private_bytes(",
        ".sign(",
        "--private-key",
        "--signing-key",
        "sys.stdin",
        "os.environ",
        "os.getenv",
        "os.urandom",
        "getenv(",
        "getpass(",
        "input(",
        "uuid4(",
        "import cryptography",
        "from cryptography",
        "import nacl",
        "from nacl",
        "SigningKey",
        "import dotenv",
        "from dotenv",
        "credential_env",
        "import docker",
        "from docker",
        "import aiohttp",
        "from aiohttp",
        "import httpx",
        "from httpx",
        "import http.client",
        "from http",
        "import requests",
        "from requests",
        "import socket",
        "from socket",
        "import ssl",
        "from ssl",
        "import urllib",
        "from urllib",
        "import sqlalchemy",
        "from sqlalchemy",
        "import sqlite3",
        "from sqlite3",
        "import asyncpg",
        "from asyncpg",
        "import psycopg",
        "from psycopg",
        "import supabase",
        "from supabase",
        "import subprocess",
        "from subprocess",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.system(",
        "trusted_time_post_enrollment_active_controller",
        "trusted_time_post_enrollment_execution_admission",
        "trusted_time_post_enrollment_host_orchestrator",
    )
    for forbidden_token in forbidden_private_or_ambient_tokens:
        assert forbidden_token not in provisioning_payload


def test_operator_authority_has_one_git_object_consumer_and_is_excluded_from_images() -> None:
    module_name = "trusted_time_post_enrollment_operator_authority"
    manifest_name = "post-enrollment-operator-attestation-authority.json"
    manifest_path = f"infra/trusted-time/{manifest_name}"
    provisioner_path = f"scripts/provision_{module_name}.py"
    allowed_sources = {
        ROOT / f"packages/domain/{module_name}.py",
        ROOT / "packages/domain/trusted_time_post_enrollment_operator_attestation.py",
        ROOT / "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        ROOT / "packages/adapters/trusted_time/ed25519_operator_attestation.py",
        ROOT / f"scripts/provision_{module_name}.py",
        ROOT / "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        ROOT / "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
        ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py",
    }
    production_python = (
        tuple((ROOT / "apps").rglob("*.py"))
        + tuple((ROOT / "packages").rglob("*.py"))
        + tuple((ROOT / "scripts").glob("*.py"))
    )
    for path in production_python:
        if path not in allowed_sources:
            assert module_name not in path.read_text(encoding="utf-8")

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert dockerignore.count(manifest_path) == 1
    assert dockerignore.count(provisioner_path) == 1
    artifact_workflow_path = (
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
    )
    assert dockerignore.count(artifact_workflow_path) == 1
    trusted_time_dockerignore = (
        ROOT / "infra/docker/trusted-time.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")
    assert manifest_name not in trusted_time_dockerignore
    assert Path(provisioner_path).name not in trusted_time_dockerignore
    assert Path(artifact_workflow_path).name not in trusted_time_dockerignore
    runtime_and_image_surfaces_without_authority = (
        ROOT / "infra/docker/api.Dockerfile",
        ROOT / "infra/docker/trusted-time.Dockerfile",
        ROOT / "infra/compose/compose.yaml",
        ROOT / "infra/compose/trusted-time.compose.yaml",
        ROOT / "scripts/start_trusted_time_supervisor.py",
        ROOT / "scripts/trusted_time_post_enrollment_host_orchestrator.py",
        ROOT / "scripts/verify_trusted_time_compose.py",
    )
    for path in runtime_and_image_surfaces_without_authority:
        payload = path.read_text(encoding="utf-8")
        assert manifest_name not in payload
        assert Path(artifact_workflow_path).name not in payload

    image_verifier_payload = (ROOT / "scripts/verify_trusted_time_images.py").read_text(
        encoding="utf-8"
    )
    execution_admission_payload = (
        ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py"
    ).read_text(encoding="utf-8")
    # One literal fixes the reviewed path contract and the second keeps the
    # native Git argv independent of a rebindable module-global constant.
    assert image_verifier_payload.count(manifest_path) == 2
    assert "def _head_reviewed_operator_authority_object(" in image_verifier_payload
    assert 'fields[0] != b"100644"' in image_verifier_payload
    assert 'fields[1] != b"blob"' in image_verifier_payload
    assert execution_admission_payload.count(manifest_path) == 1
    assert "_head_reviewed_operator_authority_object" in execution_admission_payload
    assert "Path.read_bytes" not in execution_admission_payload
    assert "Path.read_text" not in execution_admission_payload


def test_operator_attestation_codec_and_verifier_have_one_execution_consumer() -> None:
    from packages.adapters.trusted_time.ed25519_operator_attestation import (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    )
    from packages.domain.trusted_time_post_enrollment_operator_attestation import (
        EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS,
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS,
    )

    assert (
        frozenset(
            {
                "algorithm",
                "authority_artifact_sha256",
                "authority_contract_version",
                "contract_version",
                "decision",
                "execution_approval_contract_version",
                "execution_approval_v2_sha256",
                "key_id",
                "public_key_sha256",
                "replay_domain",
                "service",
                "status",
            }
        )
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS
    )
    assert (
        frozenset(
            {
                "contract_version",
                "execution_approval_v2_base64",
                "execution_approval_v2_sha256",
                "operator_attestation_statement",
                "operator_attestation_statement_sha256",
                "service",
                "signature_algorithm",
                "signature_base64",
                "status",
            }
        )
        == POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-operator-attestation-statement-v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE
        == "trusted-time-post-enrollment-start-operator-attestation"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS
        == "exact_one_attempt_execution_approval_statement"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION == "approve_one_post_enrollment_start_attempt"
    )
    assert (
        EXECUTION_APPROVAL_V2_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-approval-v2"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-approval-v3"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE
        == "trusted-time-post-enrollment-start-execution-approval"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS
        == "operator_attested_execution_approval_envelope"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
        == "phase6d-post-enrollment-operator-attestation-verification-v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
        == "trusted-time-post-enrollment-operator-attestation-verification"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
        == "operator_signature_authenticated_unqualified"
    )
    assert (
        frozenset(
            {
                "active_controller_authorized",
                "alert_delivery_authorized",
                "arming_authorized",
                "authority_granted",
                "automatic_rearm_authorized",
                "automatic_resume_authorized",
                "broker_action_authorized",
                "claim_retention_authorized",
                "controller_execution_authorized",
                "database_secret_disclosed",
                "execution_admission_authorized",
                "execution_attempt_reservation_authorized",
                "exposure_authorized",
                "live_trading_authorized",
                "new_exposure_authorized",
                "operational_control_authorized",
                "outcome_retention_authorized",
                "paper_trading_authorized",
                "persistent_start_authorized",
                "readiness_authorized",
                "rearm_authorized",
                "release_authorized",
                "retry_authorized",
                "runtime_start_authorized",
                "sequence_2_authorized",
                "shutdown_authorized",
                "source_start_authorized",
                "success_outcome_retention_authorized",
                "supervisor_start_authorized",
                "topology_mutation_authorized",
            }
        )
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
    )

    domain_module_name = "trusted_time_post_enrollment_operator_attestation"
    adapter_module_name = "ed25519_operator_attestation"
    domain_path = ROOT / f"packages/domain/{domain_module_name}.py"
    adapter_path = ROOT / f"packages/adapters/trusted_time/{adapter_module_name}.py"
    artifact_workflow_path = (
        ROOT / "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
    )
    graceful_stop_artifact_workflow_path = (
        ROOT
        / "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
    )
    execution_admission_path = ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py"
    graceful_stop_decision_binder_path = (
        ROOT / "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    )
    domain_payload = domain_path.read_text(encoding="utf-8")
    adapter_payload = adapter_path.read_text(encoding="utf-8")
    combined_payload = domain_payload + adapter_payload

    required_contract_literals = (
        "phase6d-post-enrollment-start-operator-attestation-statement-v1",
        "trusted-time-post-enrollment-start-operator-attestation",
        "exact_one_attempt_execution_approval_statement",
        "approve_one_post_enrollment_start_attempt",
        "phase6d-post-enrollment-start-execution-approval-v2",
        "phase6d-post-enrollment-start-execution-approval-v3",
        "trusted-time-post-enrollment-start-execution-approval",
        "operator_attested_execution_approval_envelope",
        "phase6d-post-enrollment-operator-attestation-verification-v1",
        "trusted-time-post-enrollment-operator-attestation-verification",
        "operator_signature_authenticated_unqualified",
        "POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION",
        "POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID",
        "POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN",
    )
    for required_literal in required_contract_literals:
        assert required_literal in combined_payload

    strict_adapter_validation_tokens = (
        "_ED25519_FIELD_PRIME",
        "_ED25519_SUBGROUP_ORDER",
        "_require_prime_order_ed25519_public_key",
        "noncanonical, off-curve, torsion, and mixed-subgroup",
    )
    for required_token in strict_adapter_validation_tokens:
        assert required_token in adapter_payload
    assert adapter_payload.count("_require_prime_order_ed25519_public_key(") >= 3

    forbidden_effect_or_signer_tokens = (
        "Ed25519PrivateKey",
        "from_private_bytes(",
        "private_bytes(",
        ".sign(",
        "SigningKey",
        "post-enrollment-operator-attestation-authority.json",
        "pathlib",
        "open(",
        ".read_bytes(",
        ".read_text(",
        "import os",
        "from os",
        "os.environ",
        "os.getenv",
        "sys.stdin",
        "getenv(",
        "getpass(",
        "import random",
        "from random",
        "import secrets",
        "from secrets",
        "import time",
        "from time",
        "import datetime",
        "from datetime",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import docker",
        "from docker",
        "import sqlalchemy",
        "from sqlalchemy",
        "import psycopg",
        "from psycopg",
        "import supabase",
        "from supabase",
        "trusted_time_post_enrollment_active_controller",
        "trusted_time_post_enrollment_execution_admission",
        "trusted_time_post_enrollment_host_orchestrator",
    )
    for forbidden_token in forbidden_effect_or_signer_tokens:
        assert forbidden_token not in combined_payload

    allowed_sources = {
        ROOT / "scripts/check_architecture.py",
        domain_path,
        adapter_path,
        artifact_workflow_path,
        graceful_stop_artifact_workflow_path,
        graceful_stop_decision_binder_path,
        execution_admission_path,
    }
    production_python = (
        tuple((ROOT / "apps").rglob("*.py"))
        + tuple((ROOT / "packages").rglob("*.py"))
        + tuple((ROOT / "scripts").glob("*.py"))
    )
    for path in production_python:
        if path not in allowed_sources:
            payload = path.read_text(encoding="utf-8")
            assert domain_module_name not in payload
            assert adapter_module_name not in payload
            assert "phase6d-post-enrollment-start-execution-approval-v3" not in payload

    unsupported_surfaces = (
        ROOT / "pyproject.toml",
        ROOT / "infra/compose/compose.yaml",
        ROOT / "infra/compose/trusted-time.compose.yaml",
        ROOT / "infra/docker/api.Dockerfile",
        ROOT / "infra/docker/trusted-time.Dockerfile",
    )
    for path in unsupported_surfaces:
        payload = path.read_text(encoding="utf-8")
        assert domain_module_name not in payload
        assert adapter_module_name not in payload
        assert "phase6d-post-enrollment-start-execution-approval-v3" not in payload

    fixed_authority = (
        ROOT / "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
    )
    assert not fixed_authority.exists()
    execution_admission_payload = execution_admission_path.read_text(encoding="utf-8")
    assert domain_module_name in execution_admission_payload
    assert adapter_module_name in execution_admission_payload
    assert "load_post_enrollment_operator_attested_execution_approval" in (
        execution_admission_payload
    )


def test_operator_attested_v3_is_the_only_execution_facing_contract() -> None:
    from scripts import trusted_time_post_enrollment_execution_admission as admission
    from scripts import trusted_time_post_enrollment_host_orchestrator as host

    assert (
        admission.POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-approval-v2"
    )
    assert (
        admission.POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-attempt-v3"
    )
    assert (
        admission.POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-admission-v3"
    )
    assert (
        admission.HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-attempt-v2"
    )
    assert (
        host.POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-host-orchestrator-v3"
    )
    assert (
        admission.POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX
        == "trusted-time-post-enrollment-start-execution-approval-v3-"
    )
    assert (
        admission.POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
        == "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
    )
    assert admission.POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME == (
        ".post-enrollment-start-execution-attempt-slot"
    )
    assert (
        admission.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval.__name__
        == "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval"
    )
    assert admission.load_post_enrollment_operator_attested_execution_approval.__name__ == (
        "load_post_enrollment_operator_attested_execution_approval"
    )
    assert host.run_operator_attested_post_enrollment_start_once.__name__ == (
        "run_operator_attested_post_enrollment_start_once"
    )
    assert not hasattr(admission, "admit_post_enrollment_execution_attempt")
    assert not hasattr(host, "run_approved_post_enrollment_start_once")
    assert not hasattr(host, "load_post_enrollment_execution_approval")

    execution_path = ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py"
    host_path = ROOT / "scripts/trusted_time_post_enrollment_host_orchestrator.py"
    graceful_stop_decision_binder_path = (
        ROOT / "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    )
    execution_payload = execution_path.read_text(encoding="utf-8")
    host_payload = host_path.read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    required_execution_tokens = (
        "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval",
        "load_post_enrollment_operator_attested_execution_approval",
        "_head_reviewed_operator_authority_object",
        "operator_authority_git_blob_object_id",
        'operator_authority_git_mode != "100644"',
        "execution_approval_v2_semantically_authenticated",
        "operator_attestation_envelope_authenticated",
        "operator_attestation_signature_authenticated",
        "operator_authority_git_object_authenticated",
        "_is_complete_historical_attempt_slot_artifact",
    )
    for required_token in required_execution_tokens:
        assert required_token in execution_payload

    assert "loaded_attested_approval:" in execution_payload
    assert "operator_attested_approval_artifact:" in execution_payload
    assert "admit_post_enrollment_execution_attempt" not in execution_payload
    assert "run_approved_post_enrollment_start_once" not in host_payload
    assert 'add_argument("--approval-artifact"' not in host_payload
    assert 'add_argument("--operator-attested-approval-artifact"' in host_payload
    assert "allow_abbrev=False" in host_payload
    assert host_payload.count("run_operator_attested_post_enrollment_start_once(") == 2
    assert "loaded_attested_approval=loaded_attested_approval" in host_payload
    assert "operator_attested_approval_artifact=operator_attested_approval_artifact" in (
        host_payload
    )
    assert (
        host_payload.index("reserve_post_enrollment_execution_attempt(")
        < (host_payload.index("_consume_post_enrollment_execution_admission("))
        < host_payload.index("mutation_may_have_begun = True")
        < host_payload.index("_execute_prepared_reviewed_topology_creation(")
    )

    assert host_path.name not in makefile
    assert "run_operator_attested_post_enrollment_start_once" not in makefile
    assert "--operator-attested-approval-artifact" not in makefile
    assert not (
        ROOT / "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
    ).exists()

    current_contract_docs = (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs/adr/0103-atomic-operator-attested-post-enrollment-execution-admission.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    )
    for path in current_contract_docs:
        payload = path.read_text(encoding="utf-8")
        assert "phase6d-post-enrollment-start-host-orchestrator-v3" in payload
        assert "phase6d-post-enrollment-start-execution-attempt-v3" in payload
        assert "phase6d-post-enrollment-start-execution-admission-v3" in payload
        assert "phase6d-post-enrollment-start-execution-attempt-v2" in payload
        assert "run_operator_attested_post_enrollment_start_once" in payload
        assert "--operator-attested-approval-artifact" in payload
        assert "phase6d-post-enrollment-start-host-orchestrator-v2" not in payload
        assert "phase6d-post-enrollment-start-execution-admission-v2" not in payload

    adr_0103 = current_contract_docs[-2].read_text(encoding="utf-8")
    for required_receipt_binding in (
        "operator_authority_git_revision",
        "operator_authority_git_relative_path",
        "operator_authority_git_mode",
        "operator_authority_git_blob_object_id",
        "operator_authority_artifact_sha256",
        "operator_public_key_sha256",
        "execution_approval_v2_sha256",
        "operator_attestation_statement_sha256",
        "operator_attestation_signature_sha256",
        "operator_attestation_envelope_sha256",
    ):
        assert required_receipt_binding in adr_0103
    assert "fixed authority path is intentionally absent" in adr_0103
    assert "There is deliberately no Make executor" in adr_0103
    assert "No attempt or effect occurred" in adr_0103
    adr_index = (ROOT / "docs/adr/README.md").read_text(encoding="utf-8")
    assert "0103-atomic-operator-attested-post-enrollment-execution-admission.md" in adr_index

    production_python = (
        tuple((ROOT / "apps").rglob("*.py"))
        + tuple((ROOT / "packages").rglob("*.py"))
        + tuple((ROOT / "scripts").glob("*.py"))
    )
    for path in production_python:
        if path == ROOT / "scripts/check_architecture.py":
            continue
        payload = path.read_text(encoding="utf-8")
        if path not in {execution_path, graceful_stop_decision_binder_path, host_path}:
            assert "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval" not in (
                payload
            )
        if path not in {execution_path, host_path}:
            assert "load_post_enrollment_operator_attested_execution_approval" not in payload
        if path != execution_path:
            assert "load_post_enrollment_execution_approval(" not in payload
            assert "LoadedTrustedTimePostEnrollmentExecutionApproval" not in payload
            assert "retain_post_enrollment_execution_approval" not in payload
            assert "post_enrollment_execution_approval_artifact_path" not in payload

    git_helper_consumers = {
        path
        for path in (ROOT / "scripts").glob("*.py")
        if path != ROOT / "scripts/check_architecture.py"
        if "_head_reviewed_operator_authority_object" in path.read_text(encoding="utf-8")
    }
    assert git_helper_consumers == {
        execution_path,
        ROOT / "scripts/verify_trusted_time_images.py",
    }


def test_operator_attestation_artifact_workflow_is_offline_and_non_authorizing() -> None:
    from packages.adapters.trusted_time.ed25519_operator_attestation import (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    )
    from scripts.trusted_time_post_enrollment_operator_attestation_artifacts import (
        ARTIFACT_RECEIPT_CONTRACT_VERSION,
        ARTIFACT_WORKFLOW_SERVICE,
        AUTHORITY_CANDIDATE_FILE_PREFIX,
        ENVELOPE_CANDIDATE_FILE_PREFIX,
        ENVELOPE_CANDIDATE_VERIFIED_STATUS,
        ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS,
        EXECUTION_APPROVAL_V2_FILE_PREFIX,
        EXECUTION_APPROVAL_V2_VALIDATION_STATUS,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS,
        STATEMENT_CANDIDATE_FILE_PREFIX,
        STATEMENT_CANDIDATE_PREPARED_STATUS,
        STATEMENT_SIGNATURE_AUTHENTICATION_STATUS,
        prepare_post_enrollment_operator_attestation_statement_candidate,
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate,
    )

    statement_core_fields = frozenset(
        {
            "artifact_location",
            "authority_artifact_sha256",
            "authority_material_source",
            "contract_version",
            "execution_approval_v2_sha256",
            "execution_approval_v2_semantically_qualified",
            "execution_approval_v2_validation",
            "freshness_qualified",
            "installed_authority_used",
            "key_id",
            "later_atomic_cutover_revalidation_required",
            "operator_attestation_statement_sha256",
            "operator_signature_authentication",
            "public_key_sha256",
            "replay_domain",
            "service",
            "single_use_qualified",
            "status",
            "structural_receipt_only",
            "verification_only",
        }
    )
    assert (
        statement_core_fields | POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
        | {"detached_signature_sha256", "operator_attestation_envelope_sha256"}
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
    )
    assert (
        ARTIFACT_RECEIPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-operator-attestation-artifact-receipt-v1"
    )
    assert (
        ARTIFACT_WORKFLOW_SERVICE == "trusted-time-post-enrollment-operator-attestation-artifacts"
    )
    assert (
        STATEMENT_CANDIDATE_PREPARED_STATUS
        == "operator_attestation_statement_candidate_prepared_unqualified"
    )
    assert (
        ENVELOPE_CANDIDATE_VERIFIED_STATUS == "operator_attestation_envelope_verified_unqualified"
    )
    assert (
        EXECUTION_APPROVAL_V2_VALIDATION_STATUS
        == "canonical_top_level_identity_only_semantics_unqualified"
    )
    assert STATEMENT_SIGNATURE_AUTHENTICATION_STATUS == "not_authenticated"
    assert ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS == "authenticated_unqualified"
    assert (
        AUTHORITY_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-operator-attestation-authority-"
    )
    assert (
        EXECUTION_APPROVAL_V2_FILE_PREFIX
        == "trusted-time-post-enrollment-start-execution-approval-"
    )
    assert (
        STATEMENT_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-operator-attestation-statement-"
    )
    assert (
        ENVELOPE_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-start-execution-approval-v3-"
    )
    assert (
        prepare_post_enrollment_operator_attestation_statement_candidate.__name__
        == "prepare_post_enrollment_operator_attestation_statement_candidate"
    )
    assert (
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate.__name__
        == "verify_and_retain_post_enrollment_operator_attestation_envelope_candidate"
    )

    workflow_path = ROOT / "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
    workflow_payload = workflow_path.read_text(encoding="utf-8")
    required_cli_tokens = (
        'add_parser("prepare-statement"',
        'add_parser("verify-signature"',
        'add_argument("--authority-artifact"',
        'add_argument("--execution-approval-v2-artifact"',
        'add_argument("--statement-candidate-directory"',
        'add_argument("--statement-artifact"',
        'add_argument("--detached-signature-file"',
        'add_argument("--envelope-candidate-directory"',
        'add_argument("--expected-authority-sha256"',
        'add_argument("--expected-public-key-sha256"',
        'add_argument("--expected-execution-approval-v2-sha256"',
        'add_argument("--expected-statement-sha256"',
        'add_argument("--expected-signature-sha256"',
    )
    for required_cli_token in required_cli_tokens:
        assert required_cli_token in workflow_payload

    required_verification_guard_tokens = (
        "type(verification) is not TrustedTimePostEnrollmentOperatorAttestationVerification",
        'verification_payload["verification_only"] is not True',
        "verification.verification_only is not True",
        "verification.authority_artifact_sha256 != observed_authority_sha256",
        "verification.public_key_sha256 != authority.public_key_sha256",
        "verification.execution_approval_v2_sha256 != observed_v2_sha256",
        "verification.operator_attestation_statement_sha256 != reviewed_statement_sha256",
        "verification.operator_attestation_envelope_sha256 != envelope_sha256",
        "verification_payload[field_name] is not False",
        '"execution_approval_v2_semantically_qualified": False',
        '"freshness_qualified": False',
        '"installed_authority_used": False',
        '"later_atomic_cutover_revalidation_required": True',
        '"single_use_qualified": False',
        '"structural_receipt_only": True',
        '"verification_only": True',
        '"not_authenticated"',
        '"authenticated_unqualified"',
    )
    for required_token in required_verification_guard_tokens:
        assert required_token in workflow_payload

    forbidden_private_or_ambient_tokens = (
        "Ed25519PrivateKey",
        "from_private_bytes(",
        "private_bytes(",
        ".sign(",
        "SigningKey",
        "--private-key",
        "--signing-key",
        "sys.stdin",
        "os.environ",
        "os.getenv",
        "getenv(",
        "getpass(",
        "input(",
        "import cryptography",
        "from cryptography",
        "import nacl",
        "from nacl",
        "import dotenv",
        "from dotenv",
        "import docker",
        "from docker",
        "import aiohttp",
        "from aiohttp",
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import socket",
        "from socket",
        "import ssl",
        "from ssl",
        "import urllib",
        "from urllib",
        "import sqlalchemy",
        "from sqlalchemy",
        "import sqlite3",
        "from sqlite3",
        "import asyncpg",
        "from asyncpg",
        "import psycopg",
        "from psycopg",
        "import supabase",
        "from supabase",
        "import subprocess",
        "from subprocess",
        "trusted_time_post_enrollment_active_controller",
        "trusted_time_post_enrollment_execution_admission",
        "trusted_time_post_enrollment_host_orchestrator",
        "infra/trusted-time/post-enrollment-operator-attestation-authority.json",
    )
    for forbidden_token in forbidden_private_or_ambient_tokens:
        assert forbidden_token not in workflow_payload

    workflow_module_name = workflow_path.stem
    graceful_stop_workflow_path = (
        ROOT
        / "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
    )
    graceful_stop_decision_binder_path = (
        ROOT / "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    )
    execution_admission_path = ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py"
    workflow_api_names = (
        "prepare_post_enrollment_operator_attestation_statement_candidate",
        "verify_and_retain_post_enrollment_operator_attestation_envelope_candidate",
    )
    assert _production_importers(f"scripts.{workflow_module_name}") == {
        execution_admission_path.relative_to(ROOT),
        graceful_stop_decision_binder_path.relative_to(ROOT),
        graceful_stop_workflow_path.relative_to(ROOT),
    }
    production_python = (
        tuple((ROOT / "apps").rglob("*.py"))
        + tuple((ROOT / "packages").rglob("*.py"))
        + tuple((ROOT / "scripts").glob("*.py"))
    )
    for path in production_python:
        if path in {
            ROOT / "scripts/check_architecture.py",
            workflow_path,
            graceful_stop_workflow_path,
        }:
            continue
        payload = path.read_text(encoding="utf-8")
        if path not in {execution_admission_path, graceful_stop_decision_binder_path}:
            assert workflow_module_name not in payload
        for workflow_api_name in workflow_api_names:
            assert workflow_api_name not in payload

    execution_payload = execution_admission_path.read_text(encoding="utf-8")
    execution_tree = ast.parse(
        execution_payload,
        filename=str(execution_admission_path.relative_to(ROOT)),
    )
    workflow_module = f"scripts.{workflow_module_name}"
    workflow_imports: list[tuple[str, str | None]] = []
    external_artifact_binding_imports: list[tuple[str, str, str | None]] = []
    for node in ast.walk(execution_tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.partition(".")[0]
                if alias.name == workflow_module:
                    workflow_imports.append((alias.name, alias.asname))
                if local_name == "_external_artifacts":
                    external_artifact_binding_imports.append(("import", alias.name, alias.asname))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if node.module == "scripts" and alias.name == workflow_module_name:
                    workflow_imports.append((workflow_module, alias.asname))
                if local_name == "_external_artifacts":
                    external_artifact_binding_imports.append(
                        (node.module or "", alias.name, alias.asname)
                    )
    assert workflow_imports == [(workflow_module, "_external_artifacts")]
    assert external_artifact_binding_imports == [
        ("scripts", workflow_module_name, "_external_artifacts")
    ]

    rebinding_nodes = [
        node
        for node in ast.walk(execution_tree)
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "_external_artifacts"
        )
        or (isinstance(node, ast.arg) and node.arg == "_external_artifacts")
        or (isinstance(node, ast.ExceptHandler) and node.name == "_external_artifacts")
        or (isinstance(node, (ast.Global, ast.Nonlocal)) and "_external_artifacts" in node.names)
        or (isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == "_external_artifacts")
        or (isinstance(node, ast.MatchMapping) and node.rest == "_external_artifacts")
    ]
    assert rebinding_nodes == []

    expected_external_artifact_calls = sorted(
        (
            "_absolute_path",
            "_absolute_path_components",
            "_absolute_path_components",
            "_absolute_path_components",
            "_external_file_allowed_modes",
            "_external_file_directory_identity",
            "_external_file_encoded",
            "_external_file_file_identity",
            "_external_file_maximum_bytes",
            "_external_file_minimum_bytes",
            "_external_file_path",
            "_external_file_phase",
            "_read_external_binding",
        )
    )
    execution_parents = {
        child: parent
        for parent in ast.walk(execution_tree)
        for child in ast.iter_child_nodes(parent)
    }
    observed_external_artifact_calls: list[str] = []
    for node in ast.walk(execution_tree):
        if not isinstance(node, ast.Name) or node.id != "_external_artifacts":
            continue
        assert isinstance(node.ctx, ast.Load)
        attribute = execution_parents[node]
        assert isinstance(attribute, ast.Attribute)
        assert attribute.value is node
        call = execution_parents[attribute]
        assert isinstance(call, ast.Call)
        assert call.func is attribute
        observed_external_artifact_calls.append(attribute.attr)
    assert sorted(observed_external_artifact_calls) == expected_external_artifact_calls

    with (ROOT / "infra/architecture-boundaries.toml").open("rb") as config_file:
        scan = tomllib.load(config_file)["scan"]
    assert scan["offline_public_artifact_roots"] == [
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
    ]
    expected_forbidden_imports = {
        "aiohttp",
        "asyncio",
        "asyncpg",
        "cryptography",
        "docker",
        "http",
        "httpx",
        "psycopg",
        "random",
        "requests",
        "secrets",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "supabase",
        "tempfile",
        "time",
        "urllib",
    }
    assert expected_forbidden_imports <= set(scan["forbidden_offline_public_artifact_imports"])


def test_runtime_diagnostic_make_target_emits_only_child_output(tmp_path: Path) -> None:
    fake_uv = tmp_path / "fake-uv"
    expected = '{"outcome_code":"test-only","status":"failed"}\n'
    fake_uv.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{expected.rstrip()}'\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o700)
    launch_path = "/private/operator/secret-launch-path.env"

    completed = subprocess.run(
        (
            "make",
            "trusted-time-runtime-diagnostic",
            f"UV={fake_uv}",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_path}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert completed.stdout == expected
    assert launch_path not in completed.stdout
    assert launch_path not in completed.stderr


def test_runtime_diagnostic_make_target_is_pinned_to_v5_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.partition("\ntrusted-time-runtime-diagnostic:")[2].partition("\n\n")[0]
    diagnostic = (ROOT / "scripts" / "diagnose_trusted_time_runtime.py").read_text(encoding="utf-8")

    assert "scripts/diagnose_trusted_time_runtime.py" in target
    assert 'CONTRACT_VERSION = "phase6d-bounded-read-only-runtime-diagnostic-v5"' in diagnostic


def test_container_ci_uses_supported_isolated_trusted_time_entrypoints() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    marker = "\n  containers:\n"
    assert workflow.count(marker) == 1
    container_job = workflow.partition(marker)[2]

    setup = "uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b"
    dependency_sync = "- name: Install locked binary dependencies without project code"
    dependency_recheck = "- name: Recheck architecture boundaries after dependency sync"
    project_build = "- name: Build and install the hash-constrained project wheel"
    project_recheck = "- name: Recheck architecture boundaries after constrained project build"
    compose_admission = "run: make trusted-time-compose-check"
    image_admission = "run: make trusted-time-images"
    architecture_recheck = (
        "run: >-\n"
        "          uv run\n"
        "          --isolated\n"
        "          --no-project\n"
        "          --no-config\n"
        "          --offline\n"
        "          --no-python-downloads\n"
        "          --python 3.12\n"
        "          python\n"
        "          -I\n"
        "          -B\n"
        "          scripts/check_architecture.py"
    )

    assert setup in container_job
    assert 'python-version: "3.12"' in container_job
    assert 'version: "0.11.28"' in container_job
    assert dependency_sync in container_job
    assert "run: uv sync --all-groups --locked --no-install-project --no-build" in container_job
    assert container_job.count(architecture_recheck) == 2
    project_build_source = container_job.partition(project_build)[2].partition(project_recheck)[0]
    assert "uv build --sdist --clear --no-sources" in project_build_source
    assert "uv build --wheel --clear --no-sources" in project_build_source
    assert (
        project_build_source.count("--build-constraints build_support/native_build_constraints.txt")
        == 2
    )
    assert project_build_source.count("--require-hashes") == 2
    assert "uv pip install --python .venv/bin/python --no-deps" in project_build_source
    assert compose_admission in container_job
    assert image_admission in container_job
    assert (
        container_job.index(setup)
        < container_job.index(dependency_sync)
        < container_job.index(dependency_recheck)
        < container_job.index(project_build)
        < container_job.index(project_recheck)
        < container_job.index(compose_admission)
        < container_job.index(image_admission)
    )
    assert "python scripts/verify_trusted_time_compose.py" not in container_job
    assert "python -m scripts.verify_trusted_time_images --build" not in container_job


def test_unenrolled_admission_make_target_passes_exact_approval_tuple() -> None:
    revision = "a" * 40
    artifact_sha256 = "b" * 64
    source_id = "sha256:" + "c" * 64
    supervisor_id = "sha256:" + "d" * 64
    launch_env = "/private/operator/trusted-time-launch.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-admit-unenrolled",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_env}",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={revision}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={artifact_sha256}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--env-file "{launch_env}"' in completed.stdout
    assert f'--approved-git-revision "{revision}"' in completed.stdout
    assert f'--approved-image-admission-sha256 "{artifact_sha256}"' in completed.stdout
    assert f'--approved-source-image-id "{source_id}"' in completed.stdout
    assert f'--approved-supervisor-image-id "{supervisor_id}"' in completed.stdout
    assert "--expect-unenrolled-fail-closed" in completed.stdout
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


def test_persistent_start_make_target_passes_exact_approval_tuple_without_build() -> None:
    revision = "a" * 40
    artifact_sha256 = "b" * 64
    source_id = "sha256:" + "c" * 64
    supervisor_id = "sha256:" + "d" * 64
    launch_env = "/private/operator/trusted-time-launch.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-start",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_env}",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={revision}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={artifact_sha256}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--approved-git-revision "{revision}"' in completed.stdout
    assert f'--approved-image-admission-sha256 "{artifact_sha256}"' in completed.stdout
    assert f'--approved-source-image-id "{source_id}"' in completed.stdout
    assert f'--approved-supervisor-image-id "{supervisor_id}"' in completed.stdout
    assert "--expect-unenrolled-fail-closed" not in completed.stdout
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


def test_existing_image_readmission_target_passes_only_exact_immutable_ids() -> None:
    source_id = "sha256:" + "1" * 64
    supervisor_id = "sha256:" + "2" * 64
    artifact = "/private/operator/image-admission.json"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-readmit-images",
            f"TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT={artifact}",
            f"TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert "scripts/verify_trusted_time_images.py --admit-existing" in completed.stdout
    assert f'--artifact "{artifact}"' in completed.stdout
    assert f'"{source_id}"' in completed.stdout
    assert f'"{supervisor_id}"' in completed.stdout
    assert "--build" not in completed.stdout


@pytest.mark.parametrize(
    ("assignments", "required_name"),
    [
        ((), "TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID"),
        (
            ("TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID=sha256:" + "1" * 64,),
            "TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID",
        ),
    ],
)
def test_existing_image_readmission_guards_reject_incomplete_pair_before_launcher(
    assignments: tuple[str, ...],
    required_name: str,
) -> None:
    completed = subprocess.run(
        ("make", "trusted-time-readmit-images", *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert required_name in completed.stderr
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


@pytest.mark.parametrize(
    ("target", "recovery_expected"),
    [
        ("trusted-time-enroll-first", False),
        ("trusted-time-recover-first-enrollment", True),
    ],
)
def test_first_enrollment_targets_pass_every_exact_binding_and_separate_mode(
    target: str,
    recovery_expected: bool,
) -> None:
    assignments = _first_enrollment_assignments()
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert "scripts/enroll_trusted_time_head_anchor.py" in completed.stdout
    expected_flags = {
        "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID": "--operation-id",
        "TRUSTED_TIME_APPROVED_GIT_REVISION": "--approved-git-revision",
        "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256": ("--approved-image-admission-sha256"),
        "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID": "--approved-source-image-id",
        "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID": ("--approved-supervisor-image-id"),
        "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256": ("--unenrolled-admission-sha256"),
        "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256": ("--anchor-authority-sha256"),
        "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256": ("--deployment-identity-sha256"),
        "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256": (
            "--runtime-database-identity-sha256"
        ),
        "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256": (
            "--anchor-project-identity-sha256"
        ),
        "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256": ("--source-authority-sha256"),
        "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256": ("--signing-public-key-sha256"),
        "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256": "--host-identity-sha256",
        "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256": ("--principal-identity-sha256"),
        "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256": ("--bucket-identity-sha256"),
    }
    assignment_values = dict(item.split("=", 1) for item in assignments)
    for variable, flag in expected_flags.items():
        assert f'{flag} "{assignment_values[variable]}"' in completed.stdout
    assert ("--recover-pending" in completed.stdout) is recovery_expected
    assert ("--prior-new-operation-id" in completed.stdout) is recovery_expected
    assert ("--prior-new-claim-sha256" in completed.stdout) is recovery_expected
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_first_enrollment_guard_rejects_missing_operation_id_before_launcher() -> None:
    completed = subprocess.run(
        (
            "make",
            "trusted-time-enroll-first",
            "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/operator/trusted-time-launch.env",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID" in completed.stderr
    assert "scripts/enroll_trusted_time_head_anchor.py" not in completed.stdout


def test_persistent_start_make_guard_rejects_incomplete_approval_before_launcher() -> None:
    completed = subprocess.run(
        (
            "make",
            "trusted-time-start",
            "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:{'c' * 64}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID" in completed.stderr
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_graceful_stop_operator_authentication_contract_is_distinct_and_unqualified() -> None:
    import packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation as stop_adapter
    from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    )
    from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_FIELDS,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    )
    from packages.domain.trusted_time_post_enrollment_operator_attestation import (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION,
        TrustedTimePostEnrollmentOperatorAttestationEnvelope,
        TrustedTimePostEnrollmentOperatorAttestationStatement,
    )
    from packages.domain.trusted_time_post_enrollment_operator_authority import (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
        POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
        TrustedTimePostEnrollmentOperatorAuthority,
    )
    from scripts.trusted_time_post_enrollment_graceful_stop import (
        POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    )

    authority_fields = frozenset(
        {
            "algorithm",
            "contract_version",
            "key_id",
            "public_key_base64",
            "public_key_sha256",
            "replay_domain",
            "service",
            "status",
        }
    )
    statement_fields = frozenset(
        {
            "algorithm",
            "authority_artifact_sha256",
            "authority_contract_version",
            "contract_version",
            "decision",
            "graceful_stop_decision_contract_version",
            "graceful_stop_decision_v1_sha256",
            "graceful_stop_operation_id",
            "graceful_stop_target_sha256",
            "key_id",
            "public_key_sha256",
            "replay_domain",
            "service",
            "status",
        }
    )
    envelope_fields = frozenset(
        {
            "contract_version",
            "graceful_stop_decision_v1_base64",
            "graceful_stop_decision_v1_sha256",
            "operator_attestation_statement",
            "operator_attestation_statement_sha256",
            "service",
            "signature_algorithm",
            "signature_base64",
            "status",
        }
    )
    false_authority_fields = frozenset(
        {
            "active_controller_authorized",
            "alert_delivery_authorized",
            "arming_authorized",
            "authority_granted",
            "automatic_rearm_authorized",
            "automatic_resume_authorized",
            "broker_action_authorized",
            "claim_retention_authorized",
            "clean_stop_authorized",
            "clean_stop_outcome_retention_authorized",
            "confirmed_start_outcome_authenticated",
            "container_removal_authorized",
            "controller_execution_authorized",
            "current_topology_authenticated",
            "database_secret_disclosed",
            "decision_authenticated",
            "execution_admission_authorized",
            "execution_attempt_reservation_authorized",
            "exposure_authorized",
            "freshness_authenticated",
            "graceful_stop_authorized",
            "live_trading_authorized",
            "network_removal_authorized",
            "new_exposure_authorized",
            "operational_control_authorized",
            "operator_attestation_authenticated",
            "outcome_retention_authorized",
            "paper_trading_authorized",
            "persistent_start_authorized",
            "persistent_topology_authenticated",
            "qualified",
            "readiness_authorized",
            "rearm_authorized",
            "release_authorized",
            "retry_authorized",
            "runtime_start_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
            "shutdown_locator_authenticated",
            "shutdown_outcome_retention_authorized",
            "single_use_authenticated",
            "source_start_authorized",
            "source_stop_authorized",
            "start_execution_attempt_authenticated",
            "stop_attempt_reservation_authorized",
            "stop_decision_authenticated",
            "stop_execution_authorized",
            "success_outcome_retention_authorized",
            "supervisor_signal_authorized",
            "supervisor_start_authorized",
            "supervisor_stop_authorized",
            "target_authenticated",
            "teardown_authorized",
            "topology_mutation_authorized",
            "volume_removal_authorized",
        }
    )

    assert len(authority_fields) == 8
    assert authority_fields == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_FIELDS
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM == "Ed25519"
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-v1"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS
        == "public_graceful_stop_operator_authority_material"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID
        == "aqt-post-enrollment-graceful-stop-operator-ed25519-v1"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN
        == "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
        "post-enrollment-graceful-stop/operator-attestation/v1"
    )

    assert len(statement_fields) == 14
    assert statement_fields == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS
        == "exact_one_attempt_graceful_stop_decision_statement"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION
        == "approve_one_post_enrollment_graceful_stop_attempt"
    )

    assert len(envelope_fields) == 9
    assert envelope_fields == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-decision-v2"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE
        == "trusted-time-post-enrollment-graceful-stop"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS
        == "operator_attested_graceful_stop_decision_envelope"
    )

    assert (
        stop_adapter.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-operator-attestation-verification-v1"
    )
    assert (
        stop_adapter.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation-verification"
    )
    assert (
        stop_adapter.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS
        == "graceful_stop_operator_signature_authenticated_unqualified"
    )
    assert len(false_authority_fields) == 55
    assert false_authority_fields == POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    assert false_authority_fields == (
        stop_adapter.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
    )
    adapter_source = Path(stop_adapter.__file__).read_text(encoding="utf-8")
    attestation_source = (
        ROOT / "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_attestation.py"
    ).read_text(encoding="utf-8")
    assert "def _authority_is_never_granted(_: object) -> bool:\n    return False" in (
        adapter_source
    )
    for field_name in false_authority_fields:
        assert f"{field_name} = property(_authority_is_never_granted)" in adapter_source

    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION
        != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION
    )
    assert (
        TrustedTimePostEnrollmentGracefulStopOperatorAuthority.__module__,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthority.__qualname__,
    ) != (
        TrustedTimePostEnrollmentOperatorAuthority.__module__,
        TrustedTimePostEnrollmentOperatorAuthority.__qualname__,
    )
    assert (
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement.__module__,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement.__qualname__,
    ) != (
        TrustedTimePostEnrollmentOperatorAttestationStatement.__module__,
        TrustedTimePostEnrollmentOperatorAttestationStatement.__qualname__,
    )
    assert (
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope.__module__,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope.__qualname__,
    ) != (
        TrustedTimePostEnrollmentOperatorAttestationEnvelope.__module__,
        TrustedTimePostEnrollmentOperatorAttestationEnvelope.__qualname__,
    )
    normalized_attestation_source = " ".join(attestation_source.split())
    normalized_adapter_source = " ".join(adapter_source.split())
    for exact_type_guard in (
        "type(authority) is not TrustedTimePostEnrollmentGracefulStopOperatorAuthority",
        "type(statement) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement",
        "type(envelope) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope",
    ):
        assert exact_type_guard in normalized_attestation_source + normalized_adapter_source
    assert "TrustedTimePostEnrollmentOperatorAttestation" not in (
        attestation_source + adapter_source
    )


def test_graceful_stop_authority_provisioner_requires_distinct_fixed_start_key() -> None:
    from scripts.provision_trusted_time_post_enrollment_graceful_stop_operator_authority import (
        CANDIDATE_FILE_PREFIX,
        CANDIDATE_FILE_SUFFIX,
        INSTALLED_AUTHORITY_RELATIVE_PATH,
        INSTALLED_STATUS,
        PREPARED_STATUS,
        PROVISIONING_RECEIPT_CONTRACT_VERSION,
        START_AUTHORITY_RELATIVE_PATH,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt,
    )

    expected_stop_path = Path(
        "infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-authority.json"
    )
    expected_start_path = Path(
        "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
    )
    assert expected_stop_path == INSTALLED_AUTHORITY_RELATIVE_PATH
    assert expected_start_path == START_AUTHORITY_RELATIVE_PATH
    assert not (ROOT / expected_stop_path).exists()
    assert (
        PROVISIONING_RECEIPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-"
        "provisioning-receipt-v1"
    )
    assert PREPARED_STATUS == "public_graceful_stop_operator_authority_candidate_prepared"
    assert INSTALLED_STATUS == "public_graceful_stop_operator_authority_installed_for_source_review"
    authority_sha256 = "a" * 64
    prepared = TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
        status=PREPARED_STATUS,
        authority_artifact_sha256=authority_sha256,
        public_key_sha256="b" * 64,
        artifact_location=f"{CANDIDATE_FILE_PREFIX}{authority_sha256}{CANDIDATE_FILE_SUFFIX}",
        distinct_start_key_review_required=True,
    )
    installed = TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
        status=INSTALLED_STATUS,
        authority_artifact_sha256=authority_sha256,
        public_key_sha256="b" * 64,
        artifact_location=expected_stop_path.as_posix(),
        distinct_start_key_review_required=False,
    )
    assert prepared.distinct_start_key_review_required is True
    assert installed.distinct_start_key_review_required is False
    assert set(prepared.public_payload) == {
        "artifact_location",
        "authority_artifact_sha256",
        "authority_granted",
        "contract_version",
        "distinct_start_key_review_required",
        "graceful_stop_authorized",
        "key_id",
        "public_key_sha256",
        "replay_domain",
        "runtime_stop_authorized",
        "service",
        "status",
        "stop_execution_authorized",
        "verification_only",
    }
    for receipt in (prepared, installed):
        assert receipt.public_payload["verification_only"] is True
        for field_name in (
            "authority_granted",
            "graceful_stop_authorized",
            "runtime_stop_authorized",
            "stop_execution_authorized",
        ):
            assert receipt.public_payload[field_name] is False

    provisioner_path = (
        ROOT / "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py"
    )
    provisioner_source = provisioner_path.read_text(encoding="utf-8")
    assert provisioner_source.count(expected_start_path.as_posix()) == 1
    assert provisioner_source.count(expected_stop_path.as_posix()) == 1
    assert "decode_post_enrollment_operator_authority(encoded)" in provisioner_source
    assert "canonical_post_enrollment_operator_authority_bytes(authority) != encoded" in (
        provisioner_source
    )
    assert re.search(
        r"if start_public_key_sha256 == authority\.public_key_sha256:\s+raise ",
        provisioner_source,
    )
    assert '"stop_public_key_not_distinct"' in provisioner_source
    assert "start_encoded=start_encoded" in provisioner_source
    assert "stop_encoded=encoded" in provisioner_source


def test_graceful_stop_authentication_workflow_is_offline_and_runtime_unreachable() -> None:
    from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    )
    from scripts.trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts import (
        ARTIFACT_RECEIPT_CONTRACT_VERSION,
        ARTIFACT_WORKFLOW_SERVICE,
        AUTHORITY_CANDIDATE_FILE_PREFIX,
        ENVELOPE_CANDIDATE_FILE_PREFIX,
        ENVELOPE_CANDIDATE_VERIFIED_STATUS,
        ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS,
        GRACEFUL_STOP_DECISION_V1_FILE_PREFIX,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS,
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS,
        STATEMENT_CANDIDATE_FILE_PREFIX,
        STATEMENT_CANDIDATE_PREPARED_STATUS,
        STATEMENT_SIGNATURE_AUTHENTICATION_STATUS,
        prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
    )

    receipt_core_fields = frozenset(
        {
            "artifact_location",
            "authority_artifact_sha256",
            "authority_material_source",
            "contract_version",
            "currentness_qualified",
            "freshness_qualified",
            "graceful_stop_decision_v1_semantically_qualified",
            "graceful_stop_decision_v1_sha256",
            "graceful_stop_operation_id",
            "graceful_stop_target_sha256",
            "installed_authority_used",
            "key_id",
            "later_atomic_stop_admission_revalidation_required",
            "operator_attestation_statement_sha256",
            "operator_signature_authentication",
            "public_key_sha256",
            "replay_domain",
            "service",
            "single_use_qualified",
            "status",
            "structural_receipt_only",
            "verification_only",
        }
    )
    assert (
        receipt_core_fields
        | POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
        | {"detached_signature_sha256", "operator_attestation_envelope_sha256"}
        == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
    )
    assert (
        ARTIFACT_RECEIPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-operator-attestation-artifact-receipt-v1"
    )
    assert (
        ARTIFACT_WORKFLOW_SERVICE
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation-artifacts"
    )
    assert (
        STATEMENT_CANDIDATE_PREPARED_STATUS
        == "graceful_stop_operator_attestation_statement_candidate_prepared_unqualified"
    )
    assert (
        ENVELOPE_CANDIDATE_VERIFIED_STATUS
        == "graceful_stop_operator_attestation_envelope_verified_unqualified"
    )
    assert STATEMENT_SIGNATURE_AUTHENTICATION_STATUS == "not_authenticated"
    assert ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS == "authenticated_unqualified"
    assert (
        AUTHORITY_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority-"
    )
    assert (
        GRACEFUL_STOP_DECISION_V1_FILE_PREFIX
        == "trusted-time-post-enrollment-graceful-stop-decision-v1-"
    )
    assert (
        STATEMENT_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-graceful-stop-operator-attestation-statement-"
    )
    assert (
        ENVELOPE_CANDIDATE_FILE_PREFIX == "trusted-time-post-enrollment-graceful-stop-decision-v2-"
    )
    assert (
        prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate.__name__
        == "prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate"
    )
    assert (
        verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate.__name__
        == "verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate"
    )
    assert receipt_core_fields.isdisjoint(
        {
            "stop_attempt_id",
            "stop_admission_sha256",
            "current_topology_sha256",
            "trusted_head_sha256",
        }
    )

    authority_module = (
        "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority"
    )
    attestation_module = (
        "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation"
    )
    adapter_module = "packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation"
    start_workflow_module = "scripts.trusted_time_post_enrollment_operator_attestation_artifacts"
    stop_workflow_module = (
        "scripts.trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts"
    )
    stop_workflow_path = Path(
        "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
    )
    decision_binder_path = Path(
        "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    )
    lifecycle_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py")
    assert _production_importers(authority_module) == {
        Path("packages/domain/trusted_time_post_enrollment_graceful_stop_operator_attestation.py"),
        Path("packages/adapters/trusted_time/ed25519_graceful_stop_operator_attestation.py"),
        Path("scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py"),
        stop_workflow_path,
    }
    assert _production_importers(attestation_module) == {
        Path("packages/adapters/trusted_time/ed25519_graceful_stop_operator_attestation.py"),
        lifecycle_path,
        stop_workflow_path,
    }
    assert _production_importers(adapter_module) == {lifecycle_path, stop_workflow_path}
    assert _production_importers(start_workflow_module) == {
        decision_binder_path,
        stop_workflow_path,
        Path("scripts/trusted_time_post_enrollment_execution_admission.py"),
    }
    assert _production_importers(stop_workflow_module) == set()
    stop_workflow_api_names = (
        "prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate",
        "verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate",
    )
    for path in (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
    ):
        if path in {ROOT / decision_binder_path, ROOT / stop_workflow_path}:
            continue
        payload = path.read_text(encoding="utf-8")
        assert stop_workflow_module not in payload
        for api_name in stop_workflow_api_names:
            assert api_name not in payload

    source_paths = (
        ROOT / "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        ROOT / "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_attestation.py",
        ROOT / "packages/adapters/trusted_time/ed25519_graceful_stop_operator_attestation.py",
        ROOT / "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        ROOT / stop_workflow_path,
    )
    sources = {path: path.read_text(encoding="utf-8") for path in source_paths}
    for source in sources.values():
        for forbidden_token in (
            "Ed25519PrivateKey",
            "from_private_bytes(",
            "private_bytes(",
            ".sign(",
            "SigningKey",
            "--private-key",
            "--signing-key",
            "sys.stdin",
            "os.environ",
            "os.getenv",
            "getenv(",
            "getpass(",
            "input(",
            "__import__(",
            "eval(",
            "exec(",
            "uuid.uuid4(",
            "from uuid import uuid4",
            "trusted_time_post_enrollment_active_controller",
            "trusted_time_post_enrollment_controller_outcome",
            "trusted_time_post_enrollment_execution_admission",
            "trusted_time_post_enrollment_host_orchestrator",
            "trusted_time_post_enrollment_topology_reader",
            "start_trusted_time_supervisor",
            "run_post_enrollment_start_active_controller",
            "run_post_enrollment_start_host_orchestrator",
        ):
            assert forbidden_token not in source
    forbidden_script_imports = {
        "aiohttp",
        "asyncio",
        "asyncpg",
        "boto3",
        "botocore",
        "builtins",
        "concurrent",
        "ctypes",
        "docker",
        "http",
        "httpx",
        "importlib",
        "multiprocessing",
        "nacl",
        "pkgutil",
        "psycopg",
        "random",
        "requests",
        "resource",
        "runpy",
        "secrets",
        "signal",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "ssl",
        "subprocess",
        "supabase",
        "tempfile",
        "threading",
        "time",
        "urllib",
        "zipimport",
    }
    forbidden_process_control_symbols = {
        "__builtins__",
        "__import__",
        "compile",
        "eval",
        "exec",
        "globals",
        "locals",
        "os._exit",
        "os.abort",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.fork",
        "os.forkpty",
        "os.kill",
        "os.killpg",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.register_at_fork",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.startfile",
        "os.system",
        "vars",
    }
    for path in source_paths[-2:]:
        tree = ast.parse(sources[path], filename=str(path.relative_to(ROOT)))
        imported_top_levels = {
            alias.name.partition(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.partition(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert imported_top_levels.isdisjoint(forbidden_script_imports)
        for forbidden_symbol in forbidden_process_control_symbols:
            if forbidden_symbol.startswith("os."):
                assert forbidden_symbol not in sources[path]

    workflow_source = sources[ROOT / stop_workflow_path]
    for forbidden_decision_authoring_api in (
        "build_post_enrollment_graceful_stop_target",
        "build_post_enrollment_graceful_stop_decision",
    ):
        assert forbidden_decision_authoring_api not in workflow_source
    for forbidden_fixed_authority_path in (
        "infra/trusted-time/post-enrollment-operator-attestation-authority.json",
        "infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-authority.json",
    ):
        assert forbidden_fixed_authority_path not in workflow_source
    for required_token in (
        'add_parser("prepare-statement"',
        'add_parser("verify-signature"',
        'add_argument("--authority-artifact"',
        'add_argument("--graceful-stop-decision-v1-artifact"',
        'add_argument("--statement-candidate-directory"',
        'add_argument("--statement-artifact"',
        'add_argument("--detached-signature-file"',
        'add_argument("--envelope-candidate-directory"',
        'add_argument("--expected-authority-sha256"',
        'add_argument("--expected-public-key-sha256"',
        'add_argument("--expected-graceful-stop-decision-v1-sha256"',
        'add_argument("--expected-statement-sha256"',
        'add_argument("--expected-signature-sha256"',
        '"currentness_qualified": False',
        '"freshness_qualified": False',
        '"graceful_stop_decision_v1_semantically_qualified": False',
        '"installed_authority_used": False',
        '"later_atomic_stop_admission_revalidation_required": True',
        '"single_use_qualified": False',
        '"structural_receipt_only": True',
        '"verification_only": True',
        "verification_payload[field_name] is not False",
    ):
        assert required_token in workflow_source

    dockerignore_lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    expected_stop_exclusions = {
        "infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-authority.json",
        "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py",
        "scripts/trusted_time_post_enrollment_graceful_stop.py",
        "scripts/trusted_time_post_enrollment_shutdown_locator.py",
    }
    observed_stop_exclusions = {
        line
        for line in dockerignore_lines
        if "graceful_stop" in line or "graceful-stop" in line or "shutdown_locator" in line
    }
    assert observed_stop_exclusions == expected_stop_exclusions
    for exclusion in expected_stop_exclusions:
        assert dockerignore_lines.count(exclusion) == 1

    with (ROOT / "infra/architecture-boundaries.toml").open("rb") as config_file:
        scan = tomllib.load(config_file)["scan"]
    expected_side_effect_free_roots = {
        "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_authority.py",
        "packages/domain/trusted_time_post_enrollment_graceful_stop_operator_attestation.py",
        "packages/adapters/trusted_time/ed25519_graceful_stop_operator_attestation.py",
    }
    assert expected_side_effect_free_roots <= set(scan["side_effect_free_roots"])
    for root in expected_side_effect_free_roots:
        assert scan["side_effect_free_roots"].count(root) == 1
    assert scan["offline_public_artifact_roots"] == [
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
        "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py",
    ]
    assert scan["offline_public_artifact_allowed_project_imports"] == {
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py": [
            "packages.adapters.trusted_time._owned_file_descriptor",
            "packages.adapters.trusted_time.ed25519_operator_attestation",
            "packages.domain.trusted_time_enrollment_evidence",
            "packages.domain.trusted_time_post_enrollment_operator_attestation",
            "packages.domain.trusted_time_post_enrollment_operator_authority",
        ],
        "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py": [
            "packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation",
            "packages.domain.trusted_time_enrollment_evidence",
            "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation",
            "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority",
            "scripts.trusted_time_post_enrollment_graceful_stop",
            "scripts.trusted_time_post_enrollment_operator_attestation_artifacts",
        ],
    }
    assert set(scan["offline_public_artifact_allowed_os_symbols"]) == {
        "os.fsencode",
        "os.fspath",
        "os.geteuid",
        "os.path",
        "os.path.abspath",
        "os.path.basename",
        "os.path.dirname",
        "os.path.isabs",
        "os.path.normpath",
        "os.path.realpath",
        "os.sep",
    }
    assert forbidden_script_imports <= set(scan["forbidden_offline_public_artifact_imports"])
    assert forbidden_process_control_symbols == set(
        scan["forbidden_offline_public_artifact_symbols"]
    )
    assert scan["offline_public_artifact_ffi_roots"] == []
    assert scan["offline_public_artifact_ffi_allowed_imports"] == []
    assert scan["offline_public_artifact_ffi_allowed_symbols"] == []
    assert scan["offline_public_artifact_ffi_allowed_library_symbols"] == []
    assert scan["offline_public_artifact_ffi_library_factory"] == ""
    assert scan["offline_public_artifact_ffi_library_binding"] == ""


def test_graceful_stop_decision_binder_is_historical_exact_and_non_authorizing() -> None:
    from packages.adapters.trusted_time._owned_file_descriptor import (
        _fstat,
        _open_child_directory,
        _open_root_directory,
    )
    from scripts import (
        trusted_time_post_enrollment_graceful_stop_decision_artifacts as binder,
    )
    from scripts.check_architecture import _nonproject_import_bindings, _project_import_bindings
    from scripts.trusted_time_post_enrollment_controller_outcome import (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome,
        _load_retained_post_enrollment_start_controller_outcome_with_snapshot,
        _revalidate_retained_post_enrollment_start_controller_outcome_snapshot,
    )
    from scripts.trusted_time_post_enrollment_execution_admission import (
        HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
        POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
        RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
        _load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot,
        _require_attempt_snapshot_binding,
        _revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot,
    )
    from scripts.trusted_time_post_enrollment_graceful_stop import (
        POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    )
    from scripts.verify_trusted_time_images import _REVIEWED_FIXED_RELATIVE_PATHS

    binder_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py")
    binder_module = "scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts"
    source_path = ROOT / binder_path
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(binder_path))

    assert binder.ARTIFACT_RECEIPT_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1"
    )
    assert (
        binder.ARTIFACT_WORKFLOW_SERVICE
        == "trusted-time-post-enrollment-graceful-stop-decision-artifacts"
    )
    assert (
        binder.DECISION_CANDIDATE_PREPARED_STATUS
        == "graceful_stop_decision_candidate_prepared_unqualified"
    )
    assert (
        binder.DECISION_CANDIDATE_FILE_PREFIX
        == "trusted-time-post-enrollment-graceful-stop-decision-v1-"
    )
    assert binder.ARTIFACT_FILE_SUFFIX == ".json"
    assert binder.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError.__name__ == (
        "TrustedTimePostEnrollmentGracefulStopDecisionArtifactError"
    )
    assert binder.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt.__name__ == (
        "TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt"
    )
    assert binder.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt.__name__ == (
        "LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt"
    )
    assert binder.prepare_post_enrollment_graceful_stop_decision_candidate.__name__ == (
        "prepare_post_enrollment_graceful_stop_decision_candidate"
    )
    assert set(binder.__all__) == {
        "ARTIFACT_FILE_SUFFIX",
        "ARTIFACT_RECEIPT_CONTRACT_VERSION",
        "ARTIFACT_WORKFLOW_SERVICE",
        "DECISION_CANDIDATE_FILE_PREFIX",
        "DECISION_CANDIDATE_PREPARED_STATUS",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS",
        "LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
        "TrustedTimePostEnrollmentGracefulStopDecisionArtifactError",
        "TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
        "authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
        "load_post_enrollment_graceful_stop_decision_artifact_receipt",
        "main",
        "prepare_post_enrollment_graceful_stop_decision_candidate",
        "revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
    }

    identity_fields = {
        "artifact_location",
        "controller_outcome_sha256",
        "durable_shutdown_locator_sha256",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "start_approval_sha256",
        "start_approved_image_provenance_sha256",
        "start_approved_image_provenance_source_revision_sha256",
        "start_execution_attempt_slot_sha256",
        "start_git_revision",
        "start_operation_id",
        "start_operator_attestation_envelope_sha256",
        "start_source_image_id",
        "start_supervisor_image_id",
    }
    true_historical_fields = {
        "committed_confirmed_start_outcome_revalidated",
        "decision_candidate_semantically_bound",
        "durable_shutdown_locator_revalidated",
        "external_stop_attestation_required",
        "historical_evidence_only",
        "historical_start_chain_authenticated",
        "later_atomic_stop_admission_revalidation_required",
        "start_execution_attempt_slot_revalidated",
        "start_operator_attestation_envelope_revalidated",
        "verification_only",
    }
    false_qualification_fields = {
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "stop_admission_qualified",
        "stop_attempt_slot_reserved",
        "stop_effect_authorized",
        "stop_operator_signature_authenticated",
        "stop_outcome_or_recovery_available",
    }
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
        | identity_fields
        | true_historical_fields
        | false_qualification_fields
        | {"contract_version", "service", "status"}
        == binder.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS
    )
    receipt_type = binder.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    for field_name in true_historical_fields:
        assert receipt_type.__dict__[field_name].fget.__name__ == "_validated_receipt_fact"
    for field_name in false_qualification_fields | POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
        assert receipt_type.__dict__[field_name].fget.__name__ == (
            "_validated_receipt_non_authority"
        )
    loaded_type = binder.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    assert tuple(loaded_type.__dataclass_fields__) == (
        "artifact_path",
        "encoded",
        "directory_identity",
        "file_identity",
        "receipt_encoded",
        "receipt_sha256",
        "_sealed_fields",
    )
    for field_name in {
        "decision_artifact_receipt_authenticated",
        "decision_candidate_retention_revalidated",
        "historical_start_chain_authenticated",
        "verification_only",
    }:
        assert loaded_type.__dict__[field_name].fget.__name__ == "_loaded_receipt_fact"
    for field_name in false_qualification_fields | POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
        assert loaded_type.__dict__[field_name].fget.__name__ == ("_loaded_receipt_non_authority")

    signature = inspect.signature(binder.prepare_post_enrollment_graceful_stop_decision_candidate)
    assert tuple(signature.parameters) == (
        "graceful_stop_operation_id",
        "start_operator_attested_approval_artifact",
        "decision_candidate_directory",
        "expected_controller_outcome_sha256",
        "expected_durable_shutdown_locator_sha256",
        "expected_start_execution_attempt_slot_sha256",
        "expected_start_operator_attestation_envelope_sha256",
        "expected_start_operation_id",
        "expected_start_approval_sha256",
        "artifact_directory",
        "ignored_root",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )

    parser = binder._parser()
    assert parser.allow_abbrev is False
    subparser_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparser_action.choices) == {"prepare-decision"}
    prepare_parser = subparser_action.choices["prepare-decision"]
    assert prepare_parser.allow_abbrev is False
    expected_cli_flags = {
        "--graceful-stop-operation-id",
        "--start-operator-attested-approval-artifact",
        "--decision-candidate-directory",
        "--expected-controller-outcome-sha256",
        "--expected-durable-shutdown-locator-sha256",
        "--expected-start-execution-attempt-slot-sha256",
        "--expected-start-operator-attestation-envelope-sha256",
        "--expected-start-operation-id",
        "--expected-start-approval-sha256",
    }
    observed_cli_flags = {
        option
        for action in prepare_parser._actions
        for option in action.option_strings
        if option.startswith("--") and option != "--help"
    }
    assert observed_cli_flags == expected_cli_flags
    assert all(
        action.required
        for action in prepare_parser._actions
        if any(option in expected_cli_flags for option in action.option_strings)
    )

    assert (
        POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-attempt-v3"
    )
    assert (
        HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-attempt-v2"
    )
    assert binder.RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt is (
        RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
    )
    assert binder.RetainedTrustedTimePostEnrollmentStartControllerOutcome is (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    assert binder._load_retained_post_enrollment_start_controller_outcome_with_snapshot is (
        _load_retained_post_enrollment_start_controller_outcome_with_snapshot
    )
    assert binder._revalidate_retained_post_enrollment_start_controller_outcome_snapshot is (
        _revalidate_retained_post_enrollment_start_controller_outcome_snapshot
    )
    assert (
        binder._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot
        is (_load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot)
    )
    assert binder._require_attempt_snapshot_binding is _require_attempt_snapshot_binding
    assert (
        binder._revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot
        is (_revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot)
    )
    assert binder._open_root_directory is _open_root_directory
    assert binder._open_child_directory is _open_child_directory
    assert binder._fstat is _fstat
    assert "HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION" not in source
    assert "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION" not in source
    assert "_decode_slot_payload" not in source
    assert "_ControllerOutcomeSemanticSnapshot" not in source
    assert "_RetainedControllerOutcomeSnapshot" not in source
    assert "_RetainedOperatorAttestedExecutionAttemptSnapshot" not in source

    with (ROOT / "infra/architecture-boundaries.toml").open("rb") as config_file:
        scan = tomllib.load(config_file)["scan"]
    assert scan["graceful_stop_decision_artifact_roots"] == [binder_path.as_posix()]
    observed_bindings = {binding for _, binding in _project_import_bindings(tree)}
    assert observed_bindings == set(scan["graceful_stop_decision_artifact_allowed_project_imports"])
    expected_stdlib_imports = {
        "__future__:annotations",
        "argparse:*",
        "collections.abc:Callable",
        "collections.abc:Iterator",
        "contextlib:contextmanager",
        "dataclasses:dataclass",
        "dataclasses:field",
        "hashlib:*",
        "os:*",
        "pathlib:Path",
        "stat:*",
        "sys:*",
        "threading:*",
        "typing:Any",
        "typing:Never",
        "typing:SupportsIndex",
        "typing:cast",
        "uuid:RFC_4122",
        "uuid:UUID",
        "weakref:*",
    }
    assert set(scan["graceful_stop_decision_artifact_allowed_stdlib_imports"]) == (
        expected_stdlib_imports
    )
    assert {binding for _, binding in _nonproject_import_bindings(tree)} == (
        expected_stdlib_imports
    )
    assert scan["graceful_stop_decision_artifact_allowed_namespace_symbols"] == {
        "argparse": ["argparse.ArgumentParser"],
        "hashlib": ["hashlib.sha256"],
        "stat": ["stat.S_IMODE", "stat.S_ISREG"],
        "sys": [
            "sys.base_prefix",
            "sys.flags",
            "sys.flags.dont_write_bytecode",
            "sys.flags.isolated",
            "sys.path",
            "sys.path.insert",
            "sys.prefix",
            "sys.pycache_prefix",
            "sys.stderr",
            "sys.stdout",
            "sys.stdout.write",
        ],
    }
    assert scan["graceful_stop_decision_artifact_allowed_os_symbols"] == [
        "os.fsencode",
        "os.fspath",
        "os.geteuid",
        "os.getpid",
        "os.path",
        "os.path.abspath",
        "os.path.basename",
        "os.path.dirname",
        "os.path.isabs",
        "os.path.join",
        "os.path.normpath",
        "os.register_at_fork",
        "os.sep",
    ]
    assert set(scan["graceful_stop_decision_artifact_allowed_audited_fs_symbols"]) == {
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts.TrustedTimePostEnrollmentOperatorAttestationArtifactError",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._ExternalFileBinding",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._REPOSITORY_ROOT_STRING",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._absolute_path",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._absolute_path_components",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._external_file_encoded",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._external_file_path",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._publish_candidate",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._read_external_binding",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._repository_identity",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._require_external_directory_metadata",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._require_repository_first_party_sources",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._require_stat_identity",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts._revalidate_external_binding",
    }
    assert {
        "cryptography",
        "datetime",
        "docker",
        "http",
        "httpx",
        "nacl",
        "psycopg",
        "random",
        "requests",
        "secrets",
        "shutil",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "supabase",
        "time",
        "urllib",
    } <= set(scan["forbidden_graceful_stop_decision_artifact_imports"])
    assert {
        "chmod",
        "chown",
        "hardlink_to",
        "lchmod",
        "link_to",
        "mkdir",
        "open",
        "read_bytes",
        "read_text",
        "rename",
        "replace",
        "rmdir",
        "symlink_to",
        "touch",
        "unlink",
        "write_bytes",
        "write_text",
    } <= set(scan["forbidden_graceful_stop_decision_artifact_symbols"])

    forbidden_imported_top_levels = {
        "aiohttp",
        "asyncpg",
        "cryptography",
        "docker",
        "http",
        "httpx",
        "nacl",
        "psycopg",
        "random",
        "requests",
        "secrets",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "supabase",
        "time",
        "urllib",
    }
    imported_top_levels = {
        alias.name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_top_levels.isdisjoint(forbidden_imported_top_levels)
    called_symbols = {
        node.func.id
        if isinstance(node.func, ast.Name)
        else node.func.attr
        if isinstance(node.func, ast.Attribute)
        else ""
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert called_symbols.isdisjoint(
        {
            "admit_post_enrollment_graceful_stop_attempt",
            "execute_post_enrollment_graceful_stop",
            "load_post_enrollment_graceful_stop_operator_authority",
            "qualify_post_enrollment_graceful_stop_currentness",
            "reserve_post_enrollment_execution_attempt",
            "reserve_post_enrollment_graceful_stop_attempt",
            "retain_post_enrollment_graceful_stop_outcome",
            "run_post_enrollment_graceful_stop",
            "sign",
            "uuid4",
            "verify_post_enrollment_graceful_stop_operator_attestation",
        }
    )
    for forbidden_private_or_signer_token in (
        "Ed25519PrivateKey",
        "SigningKey",
        "from_private_bytes(",
        "private_bytes(",
        ".sign(",
        "--private-key",
        "--signing-key",
    ):
        assert forbidden_private_or_signer_token not in source

    assert _production_importers(binder_module) == {
        Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    }
    for path in (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
    ):
        if path in {
            source_path,
            ROOT / "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py",
        }:
            continue
        payload = path.read_text(encoding="utf-8")
        assert binder_module not in payload
        assert "prepare_post_enrollment_graceful_stop_decision_candidate" not in payload
    assert binder_path.as_posix() not in _REVIEWED_FIXED_RELATIVE_PATHS
    assert (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines().count(
        binder_path.as_posix()
    ) == 1
    assert binder_path.as_posix() not in scan["offline_public_artifact_roots"]
    stop_attestation_source = (
        ROOT
        / "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
    ).read_text(encoding="utf-8")
    assert binder_module not in stop_attestation_source
    assert "prepare_post_enrollment_graceful_stop_decision_candidate" not in (
        stop_attestation_source
    )


def test_graceful_stop_evidence_is_reviewed_but_has_no_effecting_surface() -> None:
    from packages.domain.trusted_time_post_enrollment_operator_attestation import (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
    )
    from packages.domain.trusted_time_post_enrollment_operator_authority import (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    )
    from scripts import trusted_time_post_enrollment_graceful_stop as graceful_stop
    from scripts.trusted_time_post_enrollment_controller_outcome import (
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION,
    )
    from scripts.trusted_time_post_enrollment_shutdown_locator import (
        POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION,
        POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS,
    )

    assert (
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-retained-controller-outcome-v2"
    )
    assert (
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-retained-controller-outcome-v1"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-durable-shutdown-locator-v1"
    )
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS
        == "durable_shutdown_locator_unqualified"
    )
    assert (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-target-v1"
    )
    assert (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS
        == "graceful_stop_target_unqualified"
    )
    assert (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION
        == "phase6d-post-enrollment-graceful-stop-decision-v1"
    )
    assert (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS
        == "external_attestation_required"
    )
    assert (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION
        == "approve_one_post_enrollment_graceful_stop_attempt"
    )
    assert graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN != (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    )
    assert graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION != (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION
    )

    locator_module = "scripts.trusted_time_post_enrollment_shutdown_locator"
    graceful_stop_module = "scripts.trusted_time_post_enrollment_graceful_stop"
    lifecycle_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py")
    assert _production_importers(locator_module) == {
        Path("scripts/trusted_time_post_enrollment_controller_outcome.py"),
        Path("scripts/trusted_time_post_enrollment_graceful_stop.py"),
        lifecycle_path,
    }
    assert _production_importers(graceful_stop_module) == {
        Path("scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"),
        Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
        ),
        lifecycle_path,
        Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"),
    }

    graceful_stop_path = ROOT / "scripts" / "trusted_time_post_enrollment_graceful_stop.py"
    graceful_stop_source = graceful_stop_path.read_text(encoding="utf-8")
    graceful_stop_tree = ast.parse(graceful_stop_source, filename=str(graceful_stop_path))
    assert "key_id" not in graceful_stop_source
    assert "private_key" not in graceful_stop_source
    assert 'if __name__ == "__main__"' not in graceful_stop_source
    assert not any(
        token in exported_name.lower()
        for exported_name in graceful_stop.__all__
        for token in ("key", "signer", "loader", "execute", "runtime", "shutdown_authorized")
    )
    forbidden_effect_imports = {
        "argparse",
        "asyncio",
        "cryptography",
        "docker",
        "httpx",
        "os",
        "pathlib",
        "psycopg",
        "requests",
        "socket",
        "sqlalchemy",
        "subprocess",
        "time",
    }
    imported_top_levels = {
        alias.name.partition(".")[0]
        for node in ast.walk(graceful_stop_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(graceful_stop_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_top_levels.isdisjoint(forbidden_effect_imports)

    forbidden_stop_surface_names = (
        graceful_stop_module,
        "TrustedTimePostEnrollmentGracefulStopTarget",
        "TrustedTimePostEnrollmentGracefulStopDecision",
        "build_post_enrollment_graceful_stop_target",
        "build_post_enrollment_graceful_stop_decision",
        "decode_post_enrollment_graceful_stop_target",
        "decode_post_enrollment_graceful_stop_decision",
        "phase6d-post-enrollment-graceful-stop-target-v1",
        "phase6d-post-enrollment-graceful-stop-decision-v1",
    )
    dormant_contract_exceptions = {
        Path("packages/domain/trusted_time_post_enrollment_graceful_stop_operator_authority.py"),
        Path("packages/domain/trusted_time_post_enrollment_graceful_stop_operator_attestation.py"),
        Path("packages/adapters/trusted_time/ed25519_graceful_stop_operator_attestation.py"),
        Path("scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py"),
        Path("scripts/trusted_time_post_enrollment_graceful_stop.py"),
        Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
        ),
        Path("scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"),
        lifecycle_path,
        Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"),
        Path("scripts/verify_trusted_time_images.py"),
    }
    for path in (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").rglob("*.py"),
    ):
        if path.relative_to(ROOT) in dormant_contract_exceptions:
            continue
        payload = path.read_text(encoding="utf-8")
        for forbidden_name in forbidden_stop_surface_names:
            assert forbidden_name not in payload

    reviewed_source = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(
        encoding="utf-8"
    )
    dockerignore_lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for relative_path in (
        "scripts/trusted_time_post_enrollment_shutdown_locator.py",
        "scripts/trusted_time_post_enrollment_graceful_stop.py",
    ):
        assert reviewed_source.count(f'"{relative_path}"') == 1
        assert dockerignore_lines.count(relative_path) == 1

    for path in (
        *(ROOT / "infra" / "compose").rglob("*.yaml"),
        *(ROOT / "infra" / "docker").glob("*Dockerfile*"),
    ):
        payload = path.read_text(encoding="utf-8")
        for forbidden_name in forbidden_stop_surface_names:
            assert forbidden_name not in payload

    architecture_config = tomllib.loads(
        (ROOT / "infra" / "architecture-boundaries.toml").read_text(encoding="utf-8")
    )["scan"]
    assert architecture_config["shutdown_locator_roots"] == [
        "scripts/trusted_time_post_enrollment_shutdown_locator.py"
    ]
    assert architecture_config["graceful_stop_structural_bridge_roots"] == [
        "scripts/trusted_time_post_enrollment_graceful_stop.py"
    ]

    adr = (
        ROOT
        / "docs"
        / "adr"
        / "0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md"
    ).read_text(encoding="utf-8")
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "Historical v1 outcomes remain valid terminal evidence but are locator-unavailable.",
        "This ADR did not choose a key. ADR 0105 now freezes a separate stop authority identity",
        "This ADR itself added no stop authority manifest",
        "ADR 0105 subsequently adds only inert public authority and detached-signature code",
        "`make trusted-time-stop` continues",
    ):
        assert required_statement in normalized_adr
    adr_0105 = (
        ROOT / "docs" / "adr" / "0105-inert-post-enrollment-graceful-stop-operator-attestation.md"
    ).read_text(encoding="utf-8")
    normalized_adr_0105 = " ".join(adr_0105.split())
    for required_statement in (
        "The fixed future source path is "
        "`infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-"
        "authority.json`. It is absent in this slice.",
        "This ADR adds no installed authority",
        "`make trusted-time-stop` remains a no-prerequisite, two-line failure",
        "ADR 0106 now supplies the separate supported `prepare-decision` command.",
    ):
        assert required_statement in normalized_adr_0105
    for path in (
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "IMPLEMENTATION_PLAN.md",
        ROOT / "docs" / "adr" / "0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs" / "runbooks" / "trusted-time-supervisor.md",
    ):
        payload = path.read_text(encoding="utf-8")
        assert "ADR 0104" in payload
        assert "ADR 0105" in payload
        assert "phase6d-post-enrollment-start-retained-controller-outcome-v2" in payload


def test_clean_stop_requires_current_receipt_without_no_new_or_effect_surface() -> None:
    attempt_path = ROOT / "apps" / "trusted_time_supervisor" / "head_anchor_attempt.py"
    worker_path = ROOT / "packages" / "application" / "trusted_time_head_anchor_worker.py"
    attempt_source = attempt_path.read_text(encoding="utf-8")
    worker_source = worker_path.read_text(encoding="utf-8")
    attempt_tree = ast.parse(attempt_source, filename=str(attempt_path.relative_to(ROOT)))
    worker_tree = ast.parse(worker_source, filename=str(worker_path.relative_to(ROOT)))

    run = next(
        node
        for node in ast.walk(attempt_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run"
    )
    clean_stop_guards = [
        node
        for node in ast.walk(run)
        if isinstance(node, ast.If)
        and ast.unparse(node.test)
        == "request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP"
    ]
    assert len(clean_stop_guards) == 1
    clean_stop_guard = clean_stop_guards[0]
    current_receipt_guards = [
        node
        for node in clean_stop_guard.body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "current_receipt is None"
    ]
    assert len(current_receipt_guards) == 1
    current_receipt_guard = current_receipt_guards[0]
    assert any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "TrustedTimeHeadAnchorFatalFailure"
        and any(
            isinstance(argument, ast.Constant)
            and argument.value == "trusted-time anchor clean stop lacks an exact current receipt"
            for argument in node.exc.args
        )
        for node in current_receipt_guard.body
    )
    carried_receipt_assignment = next(
        node
        for node in run.body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "current_receipt is not None"
    )
    assert clean_stop_guard.lineno < carried_receipt_assignment.lineno
    assert "CLEAN_STOP and receipt is None" not in " ".join(attempt_source.split())

    record_success_transition = next(
        node
        for node in ast.walk(worker_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_record_success_transition"
    )
    conflict_guards = [
        node
        for node in ast.walk(record_success_transition)
        if isinstance(node, ast.If)
        and "request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP"
        in ast.unparse(node.test)
        and "result.candidate_remote_readback_sha256 is None" in ast.unparse(node.test)
        and "result.receipt_semantic_sha256 is None" in ast.unparse(node.test)
    ]
    assert len(conflict_guards) == 1
    conflict_guard = conflict_guards[0]
    conflict_test = ast.unparse(conflict_guard.test)
    assert (
        "result.candidate_remote_readback_sha256 is None or result.receipt_semantic_sha256 is None"
    ) in conflict_test
    clean_completion_line = next(
        node.lineno
        for node in ast.walk(record_success_transition)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Attribute) and target.attr == "_clean_shutdown_completed"
            for target in node.targets
        )
    )
    assert conflict_guard.lineno < clean_completion_line

    for payload in (attempt_source, worker_source):
        for forbidden_surface in (
            "TrustedTimeHeadAnchorNoRecordSuccess",
            "TrustedTimeHeadAnchorCleanStopDisposition",
            "clean_stop_no_new_record",
            "unchanged_head_clean_stop",
            "clean_stop_outcome",
            "stop_attempt_slot",
            "stop_admission",
            "stop_signal",
            "stop_effect",
        ):
            assert forbidden_surface not in payload

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^(trusted-time-[a-z0-9-]*stop[a-z0-9-]*):", makefile)) == {
        "trusted-time-install-post-enrollment-graceful-stop-operator-authority",
        "trusted-time-prepare-post-enrollment-graceful-stop-decision",
        "trusted-time-prepare-post-enrollment-graceful-stop-operator-attestation-statement",
        "trusted-time-prepare-post-enrollment-graceful-stop-operator-authority",
        "trusted-time-stop",
        "trusted-time-verify-post-enrollment-graceful-stop-operator-attestation-envelope",
    }

    adr = (ROOT / "docs" / "adr" / "0107-fail-closed-clean-stop-completion-invariant.md").read_text(
        encoding="utf-8"
    )
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "When the exact request reason is `CLEAN_STOP`, that `current_receipt` must be present.",
        "The recovered receipt is durable evidence for that older intent, but it is not a "
        "receipt created by the current `clean_stop` request.",
        "Periodic, on-demand, and other admitted requests may still complete with both paired "
        "fields null",
        "At acceptance, this correction added no public type, serialized field, contract version, "
        "disposition, canonical artifact, loader, writer, CLI, or Make target.",
        "[ADR 0108](0108-sealed-new-record-clean-stop-terminal-result.md) now extends that "
        "historical boundary with one process-local, new-record-only sealed result contract",
        "`make trusted-time-stop` remains the exact no-prerequisite, two-line hard-close target.",
    ):
        assert required_statement in normalized_adr
    for path in (
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "IMPLEMENTATION_PLAN.md",
        ROOT / "docs" / "adr" / "README.md",
        ROOT / "docs" / "adr" / "0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT
        / "docs"
        / "adr"
        / "0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md",
        ROOT / "docs" / "runbooks" / "trusted-time-supervisor.md",
    ):
        assert "ADR 0107" in path.read_text(encoding="utf-8")


def test_sealed_clean_stop_terminal_result_has_exact_non_authorizing_surface() -> None:
    from packages.application import trusted_time_head_anchor_clean_stop as clean_stop

    module = "packages.application.trusted_time_head_anchor_clean_stop"
    module_path = ROOT / "packages/application/trusted_time_head_anchor_clean_stop.py"
    attempt_path = Path("apps/trusted_time_supervisor/head_anchor_attempt.py")
    worker_path = Path("packages/application/trusted_time_head_anchor_worker.py")
    background_path = Path("apps/trusted_time_supervisor/head_anchor_worker.py")
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_path.relative_to(ROOT)))

    assert (
        clean_stop.TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION
        == "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1"
    )
    result_type = clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult
    dataclass_parameters = result_type.__dataclass_params__
    assert dataclass_parameters.init is False
    assert dataclass_parameters.frozen is True
    assert dataclass_parameters.eq is False
    assert set(result_type.__dataclass_fields__) == {
        "request_sequence",
        "request_scheduled_monotonic_ns",
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_transition_count",
        "confirmed_anchor_local_transition_ordinal",
        "predecessor_anchor_sha256",
        "current_host_head_sha256",
        "current_anchor_sha256",
        "current_anchor_semantic_sha256",
        "receipt_observed_at_utc",
        "full_audit_completed",
        "prior_pending_intent_recovered",
        "uploaded_anchor_count",
        "idempotent_duplicate_count",
        "current_anchor_intent_semantic_sha256",
        "current_candidate_remote_readback_sha256",
        "current_receipt_semantic_sha256",
        "_semantic_sha256",
    }
    assert set(result_type.__slots__) == set(result_type.__dataclass_fields__)
    false_properties = {
        "authority_granted",
        "provider_terminal_authenticated",
        "provider_terminal_currentness_authenticated",
        "no_new_record_authenticated",
        "no_new_record_success",
        "durability_authenticated",
        "durable_stop_outcome_authenticated",
        "stop_outcome_retained",
        "slot_authorized",
        "admission_authorized",
        "signal_authorized",
        "graceful_stop_authorized",
        "shutdown_authorized",
        "teardown_authorized",
        "effect_authorized",
        "operational_control_authorized",
        "readiness_authorized",
        "arming_authorized",
        "new_exposure_authorized",
        "broker_action_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "alert_delivery_authorized",
        "exposure_authorized",
        "paper_trading_authorized",
        "live_trading_authorized",
    }
    property_names = {
        name for name, candidate in vars(result_type).items() if isinstance(candidate, property)
    }
    assert property_names == false_properties | {"semantic_sha256"}
    for property_name in false_properties:
        descriptor = vars(result_type)[property_name]
        assert isinstance(descriptor, property)
        assert descriptor.fget is clean_stop._authority_is_never_granted
    assert set(clean_stop.__all__) == {
        "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION",
        "TrustedTimeHeadAnchorCleanStopTerminalResult",
        "TrustedTimeHeadAnchorCleanStopTerminalResultError",
    }
    assert '"status": "exact_current_new_record_clean_stop_completed"' in source

    assert _production_importers(module) == {
        attempt_path,
        worker_path,
        background_path,
        Path("packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"),
    }
    assert _production_private_symbol_importers(
        module,
        "_issue_trusted_time_head_anchor_clean_stop_terminal_result",
    ) == {attempt_path}
    assert _production_private_symbol_importers(
        module,
        "_consume_trusted_time_head_anchor_clean_stop_terminal_result",
    ) == {worker_path}

    top_level_classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert top_level_classes == {
        "TrustedTimeHeadAnchorCleanStopTerminalResult",
        "TrustedTimeHeadAnchorCleanStopTerminalResultError",
    }
    imported_top_levels = {
        alias.name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_top_levels.isdisjoint(
        {
            "argparse",
            "docker",
            "httpx",
            "pathlib",
            "psycopg",
            "requests",
            "signal",
            "socket",
            "sqlalchemy",
            "subprocess",
            "sys",
        }
    )
    called_symbols = {
        node.func.id
        if isinstance(node.func, ast.Name)
        else node.func.attr
        if isinstance(node.func, ast.Attribute)
        else ""
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert called_symbols.isdisjoint(
        {
            "open",
            "print",
            "send_signal",
            "kill",
            "Popen",
            "run",
            "write_bytes",
            "write_text",
            "unlink",
        }
    )

    background_source = (ROOT / background_path).read_text(encoding="utf-8")
    background_tree = ast.parse(background_source, filename=str(background_path))
    accessors = [
        node
        for node in ast.walk(background_tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "close_with_clean_stop_terminal_result"
    ]
    assert len(accessors) == 1
    main_source = (ROOT / "apps/trusted_time_supervisor/main.py").read_text(encoding="utf-8")
    assert "close_with_clean_stop_terminal_result" not in main_source
    assert "TrustedTimeHeadAnchorCleanStopTerminalResult" not in main_source
    accessor_callers = {
        path.relative_to(ROOT)
        for path in (
            *(ROOT / "apps").rglob("*.py"),
            *(ROOT / "packages").rglob("*.py"),
            *(ROOT / "scripts").rglob("*.py"),
        )
        if any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "close_with_clean_stop_terminal_result"
            for node in ast.walk(
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path.relative_to(ROOT)))
            )
        )
    }
    assert accessor_callers == set()
    for persistence_path in (ROOT / "packages/persistence").rglob("*.py"):
        persistence_source = persistence_path.read_text(encoding="utf-8")
        assert "TrustedTimeHeadAnchorCleanStopTerminalResult" not in persistence_source
        assert (
            "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1"
            not in persistence_source
        )

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "close_with_clean_stop_terminal_result" not in makefile
    assert "clean-stop-terminal-result" not in makefile
    assert set(re.findall(r"(?m)^(trusted-time-[a-z0-9-]*stop[a-z0-9-]*):", makefile)) == {
        "trusted-time-install-post-enrollment-graceful-stop-operator-authority",
        "trusted-time-prepare-post-enrollment-graceful-stop-decision",
        "trusted-time-prepare-post-enrollment-graceful-stop-operator-attestation-statement",
        "trusted-time-prepare-post-enrollment-graceful-stop-operator-authority",
        "trusted-time-stop",
        "trusted-time-verify-post-enrollment-graceful-stop-operator-attestation-envelope",
    }

    adr = (ROOT / "docs/adr/0108-sealed-new-record-clean-stop-terminal-result.md").read_text(
        encoding="utf-8"
    )
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "Application contract `phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1` "
        "defines the exact process-local class `TrustedTimeHeadAnchorCleanStopTerminalResult`.",
        "The private issuer "
        "`_issue_trusted_time_head_anchor_clean_stop_terminal_result` has exactly one production "
        "importer: `apps/trusted_time_supervisor/head_anchor_attempt.py`.",
        "The private consumer "
        "`_consume_trusted_time_head_anchor_clean_stop_terminal_result` has exactly one production "
        "importer: `packages/application/trusted_time_head_anchor_worker.py`.",
        "The supervisor main composition continues to use only that boolean and does not call the "
        "new exact-result accessor.",
        "`None` means no sealed current-request result was accepted; it is never a no-new-record "
        "success.",
        "`make trusted-time-stop` remains the exact hard-closed exit-2 target.",
    ):
        assert required_statement in normalized_adr
    for path in (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/README.md",
        ROOT / "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs/adr/0107-fail-closed-clean-stop-completion-invariant.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    ):
        assert "ADR 0108" in path.read_text(encoding="utf-8")


def test_clean_stop_terminal_reauthentication_is_exact_read_only_and_unconnected() -> None:
    from scripts import (
        trusted_time_post_enrollment_clean_stop_terminal_reauthentication as terminal,
    )

    relative_path = Path(
        "scripts/trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py"
    )
    module_path = ROOT / relative_path
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(relative_path))

    def top_level_class(name: str) -> ast.ClassDef:
        matches = [
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name
        ]
        assert len(matches) == 1
        return matches[0]

    def class_methods(name: str) -> set[str]:
        return {
            node.name
            for node in top_level_class(name).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def owned_attributes(class_name: str, owner_attribute: str) -> set[str]:
        return {
            node.attr
            for node in ast.walk(top_level_class(class_name))
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and node.value.attr == owner_attribute
        }

    assert (
        terminal.POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION
        == "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
    )
    assert set(terminal.__all__) == {
        "POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION",
        "TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration",
        "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
        "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
        "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected",
        "prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer",
    }
    assert class_methods("TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration") == {
        "__post_init__",
        "__repr__",
        "configuration_sha256",
    }

    result_type = terminal.TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    result_dataclass = result_type.__dataclass_params__
    assert result_dataclass.init is False
    assert result_dataclass.frozen is True
    assert result_dataclass.eq is False
    assert set(result_type.__dataclass_fields__) == {
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_transition_count",
        "confirmed_anchor_local_transition_ordinal",
        "remote_object_count",
        "predecessor_anchor_sha256",
        "current_host_head_sha256",
        "current_anchor_sha256",
        "current_anchor_semantic_sha256",
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "receipt_semantic_sha256",
        "receipt_observed_at_utc",
        "remote_observation_sha256",
        "anchor_authority_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "source_authority_sha256",
        "signing_public_key_sha256",
        "host_identity_sha256",
        "principal_identity_sha256",
        "bucket_identity_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "deadline_monotonic_ns",
        "issuer_binding_sha256",
        "read_only_configuration_sha256",
        "_semantic_sha256",
    }
    result_false_properties = {
        "authority_granted",
        "database_secret_disclosed",
        "provider_terminal_currentness_authenticated",
        "no_new_record_authenticated",
        "durability_authenticated",
        "durable_stop_outcome_authenticated",
        "slot_authorized",
        "admission_authorized",
        "effect_authorized",
        "active_controller_authorized",
        "claim_retention_authorized",
        "clean_stop_authorized",
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "container_removal_authorized",
        "controller_execution_authorized",
        "current_topology_authenticated",
        "decision_authenticated",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "freshness_authenticated",
        "graceful_stop_authorized",
        "network_removal_authorized",
        "operator_attestation_authenticated",
        "outcome_retention_authorized",
        "persistent_start_authorized",
        "persistent_topology_authenticated",
        "qualified",
        "rearm_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "single_use_authenticated",
        "source_start_authorized",
        "source_stop_authorized",
        "start_execution_attempt_authenticated",
        "stop_attempt_reservation_authorized",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "success_outcome_retention_authorized",
        "supervisor_signal_authorized",
        "supervisor_start_authorized",
        "supervisor_stop_authorized",
        "target_authenticated",
        "topology_mutation_authorized",
        "volume_removal_authorized",
        "currentness_qualified",
        "freshness_qualified",
        "durable",
        "no_new_record_success",
        "stop_outcome_retained",
        "stop_attempt_slot_reserved",
        "stop_admission_qualified",
        "signal_authorized",
        "shutdown_authorized",
        "teardown_authorized",
        "watchdog_authorized",
        "operational_control_authorized",
        "readiness_authorized",
        "arming_authorized",
        "new_exposure_authorized",
        "broker_action_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "alert_delivery_authorized",
        "exposure_authorized",
        "paper_trading_authorized",
        "live_trading_authorized",
    }
    result_property_names = {
        name for name, candidate in vars(result_type).items() if isinstance(candidate, property)
    }
    assert result_property_names == result_false_properties | {
        "contract_version",
        "provider_terminal_observed_under_stable_sql_authenticated",
        "semantic_sha256",
        "status",
    }
    for property_name in result_false_properties:
        descriptor = vars(result_type)[property_name]
        assert isinstance(descriptor, property)
        assert descriptor.fget is terminal._never_authorized
    truth_descriptor = vars(result_type)[
        "provider_terminal_observed_under_stable_sql_authenticated"
    ]
    assert isinstance(truth_descriptor, property)
    assert truth_descriptor.fget is not None
    assert "return True" in inspect.getsource(truth_descriptor.fget)
    assert '"status": _POSTCONDITION_STATUS' in source
    assert (
        '_POSTCONDITION_STATUS = "provider_terminal_observed_under_stable_sql_authenticated"'
        in source
    )
    assert class_methods("TrustedTimePostEnrollmentCleanStopTerminalPostcondition") == {
        "__copy__",
        "__deepcopy__",
        "__new__",
        "__post_init__",
        "__reduce__",
        "__reduce_ex__",
        "contract_version",
        "provider_terminal_observed_under_stable_sql_authenticated",
        "semantic_sha256",
        "status",
    }

    issuer_type = terminal.TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    issuer_false_properties = result_false_properties
    issuer_property_names = {
        name for name, candidate in vars(issuer_type).items() if isinstance(candidate, property)
    }
    assert issuer_property_names == issuer_false_properties | {
        "issuer_binding_sha256",
        "read_only_configuration_sha256",
    }
    for property_name in issuer_false_properties:
        descriptor = vars(issuer_type)[property_name]
        assert isinstance(descriptor, property)
        assert descriptor.fget is terminal._never_authorized
    assert class_methods("TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer") == {
        "__copy__",
        "__deepcopy__",
        "__delattr__",
        "__new__",
        "__reduce__",
        "__reduce_ex__",
        "__setattr__",
        "_dispatch",
        "issuer_binding_sha256",
        "read_only_configuration_sha256",
        "reauthenticate_clean_stop_terminal_once",
    }

    assert set(terminal._Dispatch.__dataclass_fields__) == {
        "binding_digest",
        "configuration_digest",
        "consume_issuance",
        "issuer_reference",
        "reauthenticate",
        "revoke",
    }
    assert tuple(inspect.signature(terminal._issue_postcondition).parameters) == (
        "issuer",
        "issuer_capability",
        "observation",
        "authority",
        "issuer_binding_sha256",
        "configuration_sha256",
        "owner_pid",
        "owner_thread",
    )
    issue_source = inspect.getsource(terminal._issue_postcondition)
    assert (
        issue_source.index("_resolve_issuer_dispatch(issuer, issuer_capability)")
        < issue_source.index("dispatch.consume_issuance(observation)")
        < issue_source.index("object.__new__")
    )
    issue_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_issue_postcondition"
    ]
    assert len(issue_calls) == 1
    assert {keyword.arg for keyword in issue_calls[0].keywords} == {
        "authority",
        "configuration_sha256",
        "issuer",
        "issuer_binding_sha256",
        "issuer_capability",
        "observation",
        "owner_pid",
        "owner_thread",
    }
    assert (
        sum(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "consume_issuance"
            for node in ast.walk(tree)
        )
        == 1
    )
    assert source.count('state["issuance_observation"] = observation') == 1
    assert source.count('state["issuance_observation"] = None') == 2
    assert source.count("state_lock = threading.RLock()") == 1

    assert class_methods("_DeadlineBoundReadOnlyProvider") == {
        "__init__",
        "_require_guard",
        "activate",
        "attest_identity",
        "deactivate",
        "download_object",
        "list_object_names_page",
        "list_sequence_object_names",
    }
    assert owned_attributes("_DeadlineBoundReadOnlyProvider", "_provider") == {
        "_timeout_seconds",
        "attest_identity",
        "download_object",
        "list_object_names_page",
        "list_sequence_object_names",
    }
    assert owned_attributes("_ProductionResources", "_repository") == {
        "discard_head_anchor_snapshot",
        "load_head_anchor_startup_snapshot",
    }
    assert source.count("default_transaction_read_only=on") == 1
    assert source.count("load_head_anchor_startup_snapshot(") == 1
    assert source.count("discard_head_anchor_snapshot") == 1

    forbidden_effect_symbols = {
        "Ed25519PrivateKey",
        "Popen",
        "SigningKey",
        "check_call",
        "check_output",
        "commit_prepared_intent",
        "commit_trusted_time_head_anchor_intent",
        "compact_head_anchor_snapshot",
        "confirm_remote_readback",
        "confirm_remote_readback_from_snapshot",
        "execute_post_enrollment_graceful_stop",
        "kill",
        "killpg",
        "open",
        "prepare_or_read_pending",
        "print",
        "read_bytes",
        "read_pending",
        "read_text",
        "refresh_head_anchor_snapshot",
        "reserve_post_enrollment_graceful_stop_attempt",
        "retain_post_enrollment_graceful_stop_outcome",
        "run_post_enrollment_graceful_stop",
        "send_signal",
        "sign",
        "upload_object_no_overwrite",
        "write_bytes",
        "write_text",
    }
    called_symbols = {
        node.func.id
        if isinstance(node.func, ast.Name)
        else node.func.attr
        if isinstance(node.func, ast.Attribute)
        else ""
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert called_symbols.isdisjoint(forbidden_effect_symbols)
    imported_top_levels = {
        alias.name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_top_levels.isdisjoint(
        {
            "argparse",
            "docker",
            "httpx",
            "json",
            "pathlib",
            "pickle",
            "requests",
            "signal",
            "socket",
            "subprocess",
        }
    )
    assert "__main__" not in source
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_")
        for node in tree.body
    )
    assert (
        sum(
            isinstance(node, ast.Attribute) and _dotted_ast_name(node) == "ctypes.CDLL"
            for node in ast.walk(tree)
        )
        == 1
    )

    supervisor_bridge_path = Path(
        "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
    )
    assert _production_importers(_CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE) == {
        supervisor_bridge_path
    }
    composed_private_seams = {
        "_ConsumedPostconditionRegistrySnapshot",
        "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
        "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
    }
    for private_seam in _CLEAN_STOP_TERMINAL_REAUTHENTICATION_PRIVATE_SEAMS:
        assert _production_private_symbol_importers(
            _CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE,
            private_seam,
        ) == ({supervisor_bridge_path} if private_seam in composed_private_seams else set())
    forbidden_external_api_tokens = {
        "POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION",
        "TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration",
        "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
        "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
        "prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer",
    }
    for path in (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").rglob("*.py"),
    ):
        if path in {module_path, ROOT / supervisor_bridge_path}:
            continue
        candidate_source = path.read_text(encoding="utf-8")
        assert forbidden_external_api_tokens.isdisjoint(candidate_source.split())

    reviewed_relative_path = relative_path.as_posix()
    reviewed_source = (ROOT / "scripts/verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert reviewed_source.count(f'"{reviewed_relative_path}"') == 1
    assert (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines().count(
        reviewed_relative_path
    ) == 1
    assert relative_path.name not in (
        ROOT / "infra/docker/trusted-time.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")

    architecture_config = tomllib.loads(
        (ROOT / "infra/architecture-boundaries.toml").read_text(encoding="utf-8")
    )["scan"]
    assert architecture_config["clean_stop_terminal_reauthentication_roots"] == [
        reviewed_relative_path
    ]
    assert (
        architecture_config["clean_stop_terminal_reauthentication_module"]
        == _CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE
    )
    assert set(architecture_config["clean_stop_terminal_reauthentication_private_symbols"]) == (
        _CLEAN_STOP_TERMINAL_REAUTHENTICATION_PRIVATE_SEAMS
    )
    assert set(
        architecture_config["clean_stop_terminal_reauthentication_provider_capabilities"]
    ) == {
        "_timeout_seconds",
        "attest_identity",
        "download_object",
        "list_object_names_page",
        "list_sequence_object_names",
    }
    assert set(
        architecture_config["clean_stop_terminal_reauthentication_repository_capabilities"]
    ) == {
        "discard_head_anchor_snapshot",
        "load_head_anchor_startup_snapshot",
    }
    assert set(
        architecture_config["clean_stop_terminal_reauthentication_allowed_namespace_symbols"][
            "threading"
        ]
    ) == {
        "threading.Lock",
        "threading.RLock",
        "threading.Thread",
        "threading.current_thread",
    }

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for absent in (
        reviewed_relative_path,
        relative_path.stem,
        "clean-stop-terminal-reauthentication",
        "prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer",
        "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
    ):
        assert absent not in makefile

    adr = (ROOT / "docs/adr/0109-code-only-clean-stop-terminal-reauthentication.md").read_text(
        encoding="utf-8"
    )
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "Its only positive truth property is "
        "`provider_terminal_observed_under_stable_sql_authenticated=true`.",
        "The SQL repository surface used by this module is exactly "
        "`load_head_anchor_startup_snapshot` and `discard_head_anchor_snapshot`.",
        "“Read-only provider” describes this method-narrowed local wrapper, not external IAM.",
        "Its only production importer is ADR 0111's dormant host bridge, which may use only "
        "the exact one-shot consume/consumed-validator snapshot seams.",
        "The minimum safe code-only slice can be implemented without a deployed provider-"
        "terminal watchdog issuer, watchdog process, or durable stop outcome because it has "
        "zero operational consumers and grants zero authority.",
        "`make trusted-time-stop` remains the exact hard-closed exit-2 target.",
    ):
        assert required_statement in normalized_adr
    for path in (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/README.md",
        ROOT / "docs/adr/0095-dormant-provider-neutral-trusted-head-watchdog-state.md",
        ROOT / "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs/adr/0108-sealed-new-record-clean-stop-terminal-result.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    ):
        assert "ADR 0109" in path.read_text(encoding="utf-8")


def test_graceful_stop_lifecycle_repository_is_exact_dormant_and_unconnected() -> None:
    from scripts import trusted_time_post_enrollment_graceful_stop_lifecycle as lifecycle

    relative_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py")
    module_path = ROOT / relative_path
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(relative_path))

    def top_level_class(name: str) -> ast.ClassDef:
        matches = [
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name
        ]
        assert len(matches) == 1
        return matches[0]

    def top_level_function(name: str) -> ast.FunctionDef:
        matches = [
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        assert len(matches) == 1
        return matches[0]

    def class_methods(name: str) -> set[str]:
        return {
            node.name
            for node in top_level_class(name).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-attempt-v1"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-progress-v1"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_TRANSCRIPT_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-progress-transcript-v1"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-retained-outcome-v1"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-outcome-commit-v1"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE == (
        "trusted-time-post-enrollment-graceful-stop-lifecycle"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_STATUS == (
        "graceful_stop_attempt_reserved"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STATUS == (
        "operation_bound_supervisor_bridge_required"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS == ("recovery_required")
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON == (
        "operation_bound_supervisor_bridge_unavailable"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME == (
        ".post-enrollment-graceful-stop-attempt-slot"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME == (
        ".post-enrollment-graceful-stop-progress-staging"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX == (
        "trusted-time-post-enrollment-graceful-stop-progress-01-"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME == (
        ".post-enrollment-graceful-stop-outcome-staging"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_PREFIX == (
        "trusted-time-post-enrollment-graceful-stop-outcome-"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME == (
        ".post-enrollment-graceful-stop-outcome-commit-staging"
    )
    assert lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME == (
        ".post-enrollment-graceful-stop-outcome-committed"
    )
    assert {
        item.value for item in lifecycle.TrustedTimePostEnrollmentGracefulStopProgressPhase
    } == {
        "attempt_reserved",
        "operation_bound_supervisor_bridge_required",
    }
    assert {
        item.value for item in lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus
    } == {
        "recovery_required",
        "retention_unconfirmed",
        "terminal_outcome_retained",
        "unreserved",
    }

    architecture_config = tomllib.loads(
        (ROOT / "infra/architecture-boundaries.toml").read_text(encoding="utf-8")
    )["scan"]
    reviewed_top_level_definitions = tuple(
        architecture_config["graceful_stop_lifecycle_repository_top_level_definitions"]
    )
    observed_top_level_definitions = tuple(
        sorted(
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        )
    )
    assert observed_top_level_definitions == tuple(sorted(reviewed_top_level_definitions))
    assert len(reviewed_top_level_definitions) == len(set(reviewed_top_level_definitions))
    reviewed_public_symbols = tuple(
        architecture_config["graceful_stop_lifecycle_repository_public_symbols"]
    )
    assert len(reviewed_public_symbols) == 49
    assert tuple(lifecycle.__all__) == reviewed_public_symbols
    assert len(lifecycle.__all__) == len(set(lifecycle.__all__))
    assert not any(
        name.startswith(("append_", "reserve_", "retain_", "resume_", "retry_"))
        for name in lifecycle.__all__
    )
    for name, value in architecture_config[
        "graceful_stop_lifecycle_repository_literal_constants"
    ].items():
        assert getattr(lifecycle, name) == value
    for class_name, reviewed_members in architecture_config[
        "graceful_stop_lifecycle_repository_enum_members"
    ].items():
        enum_type = getattr(lifecycle, class_name)
        assert {member.name: member.value for member in enum_type} == reviewed_members

    public_dataclasses = (
        lifecycle.TrustedTimePostEnrollmentGracefulStopAttemptRecord,
        lifecycle.TrustedTimePostEnrollmentGracefulStopProgressRecord,
        lifecycle.TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
        lifecycle.RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
        lifecycle.RetainedTrustedTimePostEnrollmentGracefulStopProgress,
        lifecycle.RetainedTrustedTimePostEnrollmentGracefulStopOutcome,
        lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryState,
    )
    for candidate in public_dataclasses:
        params = candidate.__dataclass_params__
        assert params.init is False
        assert params.frozen is True
        assert params.eq is False
        assert hasattr(candidate, "__slots__")

    recovery_type = lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryState
    assert class_methods("TrustedTimePostEnrollmentGracefulStopRecoveryState") == {
        "__copy__",
        "__deepcopy__",
        "__init__",
        "__post_init__",
        "__reduce__",
        "__reduce_ex__",
        "continuation_authorized",
        "recovery_required",
        "retry_authorized",
        "terminal_outcome_retained",
    }
    for property_name in ("continuation_authorized", "retry_authorized"):
        descriptor = vars(recovery_type)[property_name]
        assert isinstance(descriptor, property)
        assert descriptor.fget is not None
        assert "return False" in inspect.getsource(descriptor.fget)

    repository_class = architecture_config["graceful_stop_lifecycle_repository_class"]
    assert repository_class == ("_TrustedTimePostEnrollmentGracefulStopLifecycleRepository")
    assert class_methods(repository_class) == set(
        architecture_config["graceful_stop_lifecycle_repository_methods"]
    )
    builder = top_level_function("_build_post_enrollment_graceful_stop_lifecycle_repository")
    assert not builder.args.args
    assert [argument.arg for argument in builder.args.kwonlyargs] == ["ignored_root"]
    assert builder.args.kw_defaults == [None]
    assert "_build_post_enrollment_graceful_stop_lifecycle_repository" not in lifecycle.__all__
    assert repository_class not in lifecycle.__all__

    registry_builder = top_level_function("_build_repository_state_registry")
    assert {node.name for node in registry_builder.body if isinstance(node, ast.FunctionDef)} == {
        "burn",
        "cardinality",
        "register",
        "resolve",
        "transition",
    }
    assert "WeakKeyDictionary[object, tuple[object, ...]]" in ast.unparse(registry_builder)
    assert "_REPOSITORY_STATES" not in source
    assert source.count("= _build_repository_state_registry()") == 1
    snapshot = top_level_class("_RepositorySnapshot")
    assert [ast.unparse(base) for base in snapshot.bases] == ["NamedTuple"]
    assert [
        node.target.id
        for node in snapshot.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ] == [
        "ignored_root",
        "owner_pid",
        "owner_thread",
        "owner_thread_id",
        "attempt",
        "progress",
        "outcome",
        "closed",
        "generation",
    ]
    for private_binding in (
        "_burn_repository",
        "_register_repository_state",
        "_registered_repository_state",
        "_replace_repository_state",
    ):
        assert source.count(f"{private_binding} = cast(Any, {private_binding}_untyped)") == 1
        assert private_binding not in lifecycle.__all__
    assert source.count("_repository_state_registry_cardinality = cast(") == 1
    assert "_repository_state_registry_cardinality" not in lifecycle.__all__
    exclusive_create = top_level_class("_ExclusiveCreateAlreadyExists")
    assert [ast.unparse(base) for base in exclusive_create.bases] == ["Exception"]
    assert len(exclusive_create.body) == 1
    assert isinstance(exclusive_create.body[0], ast.Pass)
    assert source.count("_ExclusiveCreateAlreadyExists") == 3

    repository_slots = next(
        node
        for node in top_level_class(repository_class).body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "__slots__"
    )
    assert ast.literal_eval(repository_slots.value) == (
        "__weakref__",
        "_attempt",
        "_closed",
        "_ignored_root",
        "_outcome",
        "_owner_pid",
        "_owner_thread",
        "_owner_thread_id",
        "_progress",
        "_sealed_configuration",
        "_sealed_state",
    )
    for forbidden_introspection in (
        ".__closure__",
        ".__code__",
        ".__globals__",
    ):
        assert forbidden_introspection not in source

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def private_callsites(binding: str) -> list[str]:
        callsites: list[str] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == binding
            ):
                continue
            current: ast.AST = node
            while current in parents:
                current = parents[current]
                if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                owner = parents.get(current)
                callsites.append(
                    f"{owner.name}.{current.name}"
                    if isinstance(owner, ast.ClassDef)
                    else current.name
                )
                break
            else:
                callsites.append("<module>")
        return sorted(callsites)

    for binding, expected_callsites in architecture_config[
        "graceful_stop_lifecycle_repository_private_callsites"
    ].items():
        assert private_callsites(binding) == sorted(expected_callsites)

    os_unlink_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "unlink"
    ]
    assert len(os_unlink_calls) == 1
    assert isinstance(os_unlink_calls[0].args[0], ast.Name)
    assert os_unlink_calls[0].args[0].id == "staging_file_name"
    assert not any(
        isinstance(node, ast.Attribute)
        and node.attr in {"remove", "rename", "replace", "rmdir", "truncate"}
        for node in ast.walk(tree)
    )
    forbidden_object_filesystem_methods = {
        "chmod",
        "hardlink_to",
        "mkdir",
        "open",
        "symlink_to",
        "touch",
    }
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_object_filesystem_methods
        and not (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "mkdir"
        )
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"open", "print"}
        for node in ast.walk(tree)
    )
    assert 'if __name__ == "__main__"' not in source
    assert not any(
        isinstance(node, ast.Attribute)
        and node.attr in {"fork", "forkpty", "posix_spawn", "posix_spawnp", "register_at_fork"}
        for node in ast.walk(tree)
    )

    flock_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "fcntl"
        and node.func.attr == "flock"
    ]
    flock_flags = [ast.unparse(node.args[1]) for node in flock_calls]
    acquisitions = [flags for flags in flock_flags if "LOCK_UN" not in flags]
    unlocks = [flags for flags in flock_flags if "LOCK_UN" in flags]
    assert (
        len(acquisitions)
        == architecture_config["graceful_stop_lifecycle_repository_flock_acquisitions"]
    )
    assert len(unlocks) == architecture_config["graceful_stop_lifecycle_repository_flock_unlocks"]
    assert all("LOCK_NB" in flags for flags in acquisitions)
    assert all(flags == "fcntl.LOCK_UN" for flags in unlocks)

    module_name = architecture_config["graceful_stop_lifecycle_repository_module"]
    assert module_name == "scripts.trusted_time_post_enrollment_graceful_stop_lifecycle"
    assert architecture_config["graceful_stop_lifecycle_repository_roots"] == [
        relative_path.as_posix()
    ]
    assert (
        "weakref:WeakKeyDictionary"
        in architecture_config["graceful_stop_lifecycle_repository_allowed_nonproject_imports"]
    )
    assert (
        "fcntl.LOCK_NB"
        in architecture_config["graceful_stop_lifecycle_repository_allowed_namespace_symbols"][
            "fcntl"
        ]
    )
    assert (
        "os.open"
        not in architecture_config["graceful_stop_lifecycle_repository_allowed_namespace_symbols"][
            "os"
        ]
    )
    assert (
        "os.open"
        not in architecture_config[
            "graceful_stop_lifecycle_repository_allowed_qualified_method_calls"
        ]
    )
    assert _production_importers(module_name) == {
        Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    }
    private_symbols = set(architecture_config["graceful_stop_lifecycle_repository_private_symbols"])
    assert "_RepositorySnapshot" in private_symbols
    assert "_RepositoryState" not in private_symbols
    assert all(name in vars(lifecycle) for name in private_symbols)
    for private_seam in (
        "_ExclusiveCreateAlreadyExists",
        "_TrustedTimePostEnrollmentGracefulStopLifecycleRepository",
        "_build_post_enrollment_graceful_stop_lifecycle_repository",
        "_build_repository_state_registry",
        "_burn_repository",
        "_new_attempt_record",
        "_new_outcome_record",
        "_new_progress_record",
        "_persist_attempt",
        "_persist_outcome",
        "_persist_progress",
        "_rebind_exact_files",
        "_require_secure_open_flags",
        "_register_repository_state",
        "_registered_repository_state",
        "_replace_repository_state",
        "_repository_state_registry_cardinality",
        "_repository_state_registry_cardinality_untyped",
        "_run_cleanup_operations",
    ):
        assert private_seam in private_symbols
    for unique_private_seam in (
        "_TrustedTimePostEnrollmentGracefulStopLifecycleRepository",
        "_build_post_enrollment_graceful_stop_lifecycle_repository",
        "_build_repository_state_registry",
        "_rebind_exact_files",
        "_require_secure_open_flags",
        "_register_repository_state",
    ):
        assert _production_private_symbol_importers(module_name, unique_private_seam) == set()
    assert _production_private_symbol_importers(
        module_name,
        "_build_post_enrollment_graceful_stop_lifecycle_repository",
        source_directories=("tests",),
    ) == {Path("tests/unit/test_trusted_time_post_enrollment_graceful_stop_lifecycle.py")}
    assert _production_private_symbol_importers(
        module_name,
        "_repository_state_registry_cardinality",
        source_directories=("tests",),
    ) == {Path("tests/unit/test_trusted_time_post_enrollment_graceful_stop_lifecycle.py")}

    reviewed_relative_path = relative_path.as_posix()
    reviewed_source = (ROOT / "scripts/verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert reviewed_source.count(f'"{reviewed_relative_path}"') == 1
    assert (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines().count(
        reviewed_relative_path
    ) == 1
    assert relative_path.name not in (
        ROOT / "infra/docker/trusted-time.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for absent in (
        reviewed_relative_path,
        relative_path.stem,
        "graceful-stop-lifecycle",
        "_build_post_enrollment_graceful_stop_lifecycle_repository",
        "inspect_post_enrollment_graceful_stop_recovery_state",
    ):
        assert absent not in makefile
    for path in (
        *(ROOT / "infra/compose").rglob("*.yaml"),
        *(ROOT / "infra/docker").glob("*Dockerfile*"),
    ):
        assert relative_path.stem not in path.read_text(encoding="utf-8")

    adr = (ROOT / "docs/adr/0110-dormant-durable-graceful-stop-lifecycle-repository.md").read_text(
        encoding="utf-8"
    )
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "There is no public reserve, append, retain, retry, continuation, or recovery writer.",
        "This module has no reviewed-Git stop-authority loader",
        "`retention_unconfirmed` withholds every prefix receipt",
        "`make trusted-time-stop` remains the exact no-prerequisite, two-line hard-close target",
        "must not be constructed in a process that can fork",
    ):
        assert required_statement in normalized_adr
    for path in (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/README.md",
        ROOT / "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs/adr/0109-code-only-clean-stop-terminal-reauthentication.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    ):
        assert "ADR 0110" in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("owner", "binding"),
    [
        (
            "worker",
            "_register_trusted_time_head_anchor_operation_bound_clean_stop_request",
        ),
        (
            "worker",
            "_bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request",
        ),
        (
            "worker",
            "_issue_trusted_time_head_anchor_operation_bound_clean_stop_result",
        ),
        (
            "worker",
            "_revoke_trusted_time_head_anchor_operation_bound_clean_stop_request",
        ),
        (
            "worker",
            "_take_trusted_time_head_anchor_operation_bound_clean_stop_result_once",
        ),
        (
            "low",
            "_consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge",
        ),
        ("low", "_result_semantic_sha256"),
        (
            "host",
            "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
        ),
        (
            "host",
            "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
        ),
        (
            "host",
            "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
        ),
        (
            "host",
            "_require_consumed_loaded_decision_artifact_receipt_snapshot",
        ),
        ("host", "inspect_post_enrollment_graceful_stop_recovery_state"),
        ("host", "decode_post_enrollment_graceful_stop_attempt_bytes"),
        ("host", "decode_post_enrollment_graceful_stop_progress_bytes"),
    ],
)
@pytest.mark.parametrize(
    "mutation",
    ["add_main", "move_to_main", "add_generic", "globals_literal", "eval_literal"],
)
def test_adr0111_architecture_checker_rejects_private_callsite_mutation(
    tmp_path: Path,
    owner: str,
    binding: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    relative_paths = {
        "worker": Path("packages/application/trusted_time_head_anchor_worker.py"),
        "low": Path(
            "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
        ),
        "host": Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"),
    }
    root_keys = {
        "worker": "operation_bound_clean_stop_bridge_worker_private_owner_roots",
        "low": "operation_bound_clean_stop_bridge_roots",
        "host": "graceful_stop_supervisor_bridge_roots",
    }
    callsite_keys = {
        "worker": "operation_bound_clean_stop_bridge_worker_private_callsites",
        "low": "operation_bound_clean_stop_bridge_private_callsites",
        "host": "graceful_stop_supervisor_bridge_private_callsites",
    }
    relative_path = relative_paths[owner]
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    scaffold = ""
    config_lines = [
        "[scan]",
        "source_roots = []",
        *_MINIMAL_ARCHITECTURE_SCAN_PRELUDE.splitlines(),
        f'{root_keys[owner]} = ["{relative_path.as_posix()}"]',
        f'{callsite_keys[owner]}.{binding} = ["approved"]',
    ]
    if owner in {"low", "host"}:
        closed_key = (
            "operation_bound_clean_stop_bridge_closed_fields"
            if owner == "low"
            else "graceful_stop_supervisor_bridge_closed_fields"
        )
        config_lines.append(f'{closed_key} = ["closed"]')
        scaffold = (
            '_CLOSED_FIELDS = frozenset({"closed"})\n'
            "def _closed_payload():\n"
            "    return {name: False for name in _CLOSED_FIELDS}\n"
            "__all__ = []\n"
        )
    if owner == "host":
        scaffold += (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
        )
    approved = f"def approved():\n    {binding}()\n"
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text("\n".join(config_lines) + "\n", encoding="utf-8")
    module_path.write_text(scaffold + approved, encoding="utf-8")
    assert check(tmp_path, config) == []

    if mutation == "add_main":
        mutated = scaffold + approved + f"def main():\n    {binding}()\n"
    elif mutation == "move_to_main":
        mutated = scaffold + "def approved():\n    pass\n" + f"def main():\n    {binding}()\n"
    elif mutation == "add_generic":
        mutated = scaffold + approved + f"def request_clean_stop():\n    {binding}()\n"
    elif mutation == "globals_literal":
        mutated = scaffold + approved + f'def hidden():\n    globals()["{binding}"]()\n'
    else:
        mutated = scaffold + approved + f'def hidden():\n    eval("{binding}")()\n'
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "exact private callsites" in item.message
        or "dynamically reference private callable" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'Path("target").write_text("x")',
        'Path("target").read_text()',
        'Path("target").exists()',
        'Path("target").is_junction()',
        'Path("target").replace("other")',
        '"value".replace("v", "V")',
        'getattr(Path("target"), "write_text")("x")',
        'object.__getattribute__(Path("target"), "write_text")("x")',
        'object.__getattribute__(Path("target"), "replace")("other")',
        "datetime.now(UTC)",
        'object.__getattribute__(datetime, "now")(UTC)',
        "threading.Thread()",
        "threading.Thread(target=lambda: None).start()",
        "factory = threading.Thread\nfactory()",
        "from threading import Thread as Factory\nFactory()",
        'getattr(threading, "Thread")()',
        'object.__getattribute__(threading, "Thread")()',
        'object.__getattribute__(threading.current_thread(), "start")()',
        "os.fork()",
        '__import__("os")',
    ],
)
def test_adr0111_architecture_checker_rejects_host_effect_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    baseline = (
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "def _utc_text(value):\n"
        '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
        '"+00:00", "Z")\n'
        "def _composite_payload():\n"
        '    return {"only_fact": True}\n'
        "__all__ = []\n"
    )
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
graceful_stop_supervisor_bridge_roots = ["{relative_path.as_posix()}"]
graceful_stop_supervisor_bridge_closed_fields = ["closed"]
graceful_stop_supervisor_bridge_true_payload_facts._composite_payload = ["only_fact"]
graceful_stop_supervisor_bridge_forbidden_symbols = [
  "__import__", "fork", "join", "now", "run", "start", "today", "utcnow",
]
graceful_stop_supervisor_bridge_forbidden_qualified_calls = ["threading.Thread"]
graceful_stop_supervisor_bridge_forbidden_path_methods = [
  "__dict__", "exists", "is_junction", "read_text", "write_text",
]
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []
    module_path.write_text(f"{baseline}\n{mutation}\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert violations
    assert any(
        "reviewed seam" in item.message
        or "effect API" in item.message
        or "effect callable" in item.message
        or "sole reviewed UTC string replace" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "datetime.utcnow()",
        "threading.Thread()",
        "threading.Thread(target=lambda: None).start()",
        "factory = threading.Thread\nfactory()",
        "from threading import Thread as Factory\nFactory()",
        'getattr(threading, "Thread")()',
        'object.__getattribute__(threading, "Thread")()',
    ],
)
def test_adr0111_architecture_checker_rejects_low_bridge_clock_or_thread_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    baseline = (
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "__all__ = []\n"
    )
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_roots = ["{relative_path.as_posix()}"]
operation_bound_clean_stop_bridge_closed_fields = ["closed"]
operation_bound_clean_stop_bridge_forbidden_symbols = [
  "join", "now", "run", "start", "today", "utcnow",
]
operation_bound_clean_stop_bridge_forbidden_qualified_calls = ["threading.Thread"]
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []
    module_path.write_text(f"{baseline}\n{mutation}\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "effect API" in item.message or "effect callable" in item.message for item in violations
    )


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    [
        ("remove_closed", "exact literal frozenset"),
        ("constant_closed_key", "map every closed field"),
        ("transformed_closed_key", "map every closed field"),
        ("add_true", "exact literal-true payload facts"),
        ("flip_true", "exact literal-true payload facts"),
        ("false_property_true", "closed-false and positive-true properties"),
        ("remove_false_property", "closed-false and positive-true properties"),
        ("add_false_property", "closed-false and positive-true properties"),
        ("true_property_false", "closed-false and positive-true properties"),
        ("true_property_alias", "closed-false and positive-true properties"),
        ("add_true_property", "closed-false and positive-true properties"),
        ("positive_literal_override", "closed-false and positive-true properties"),
        ("positive_method_override", "closed-false and positive-true properties"),
        ("closed_duplicate_method", "closed-false and positive-true properties"),
        ("drop_closed_base", "closed-false and positive-true properties"),
        ("duplicate_closed_class", "closed-false and positive-true properties"),
        ("duplicate_positive_class", "closed-false and positive-true properties"),
        ("custom_getattribute", "closed-false and positive-true properties"),
        ("nested_class_override", "closed-false and positive-true properties"),
        ("tuple_override", "closed-false and positive-true properties"),
        ("walrus_override", "closed-false and positive-true properties"),
        ("import_override", "closed-false and positive-true properties"),
        ("post_class_assignment", "closed-false and positive-true properties"),
        ("post_class_setattr", "closed-false and positive-true properties"),
        ("post_class_type_setattr", "closed-false and positive-true properties"),
        ("post_payload_assignment", "closed-false and positive-true properties"),
    ],
)
def test_adr0111_architecture_checker_rejects_closed_fact_mutation(
    tmp_path: Path,
    mutation: str,
    expected_fragment: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    positive_class_name = "TrustedTimeHeadAnchorOperationBoundCleanStopResult"
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    baseline = (
        '_CLOSED_FIELDS = frozenset({"database_secret_disclosed", '
        '"transport_authenticated"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "class _ClosedBridgeEvidence:\n"
        "    database_secret_disclosed = property(lambda _: False)\n"
        "    transport_authenticated = property(lambda _: False)\n"
        "@dataclass(frozen=True, slots=True, init=False, eq=False)\n"
        "class TrustedTimeHeadAnchorOperationBoundCleanStopResult(_ClosedBridgeEvidence):\n"
        "    def __post_init__(self):\n"
        "        pass\n"
        "    @property\n"
        "    def exact_request_work_result_correlated(self):\n"
        "        self.__post_init__()\n"
        "        return True\n"
        "    def payload(self):\n"
        '        return {"exact_request_work_result_correlated": True}\n'
        "__all__ = []\n"
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_roots = ["{relative_path.as_posix()}"]
operation_bound_clean_stop_bridge_closed_fields = [
  "database_secret_disclosed", "transport_authenticated",
]
operation_bound_clean_stop_bridge_closed_evidence_class = "_ClosedBridgeEvidence"
operation_bound_clean_stop_bridge_positive_evidence_class = "{positive_class_name}"
operation_bound_clean_stop_bridge_positive_properties = [
  "exact_request_work_result_correlated",
]
operation_bound_clean_stop_bridge_positive_callable_names = ["payload"]
[scan.operation_bound_clean_stop_bridge_true_payload_facts]
"TrustedTimeHeadAnchorOperationBoundCleanStopResult.payload" = [
  "exact_request_work_result_correlated",
]
''',
        encoding="utf-8",
    )
    module_path.write_text(baseline, encoding="utf-8")
    assert check(tmp_path, config) == []
    if mutation == "remove_closed":
        mutated = baseline.replace(', "transport_authenticated"', "")
    elif mutation == "constant_closed_key":
        mutated = baseline.replace(
            "{name: False for name in _CLOSED_FIELDS}",
            '{"constant": False for name in _CLOSED_FIELDS}',
        )
    elif mutation == "transformed_closed_key":
        mutated = baseline.replace(
            "{name: False for name in _CLOSED_FIELDS}",
            "{name.upper(): False for name in _CLOSED_FIELDS}",
        )
    elif mutation == "add_true":
        mutated = baseline.replace(
            '"exact_request_work_result_correlated": True',
            '"exact_request_work_result_correlated": True, "effect_authorized": True',
        )
    elif mutation == "flip_true":
        mutated = baseline.replace(
            '"exact_request_work_result_correlated": True',
            '"exact_request_work_result_correlated": False',
        )
    elif mutation == "false_property_true":
        mutated = baseline.replace(
            "transport_authenticated = property(lambda _: False)",
            "transport_authenticated = property(lambda _: True)",
        )
    elif mutation == "remove_false_property":
        mutated = baseline.replace(
            "    transport_authenticated = property(lambda _: False)\n",
            "",
        )
    elif mutation == "add_false_property":
        mutated = baseline.replace(
            "    transport_authenticated = property(lambda _: False)\n",
            "    transport_authenticated = property(lambda _: False)\n"
            "    extra = property(lambda _: False)\n",
        )
    elif mutation == "true_property_false":
        mutated = baseline.replace(
            "        self.__post_init__()\n        return True\n    def payload",
            "        self.__post_init__()\n        return False\n    def payload",
        )
    elif mutation == "true_property_alias":
        mutated = baseline.replace(
            "        self.__post_init__()\n        return True\n    def payload",
            "        self.__post_init__()\n        return _TRUE\n    def payload",
        )
        mutated = f"_TRUE = True\n{mutated}"
    elif mutation == "add_true_property":
        mutated = baseline.replace(
            "    def payload(self):\n",
            "    @property\n"
            "    def effect_authorized(self):\n"
            "        return True\n"
            "    def payload(self):\n",
        )
    elif mutation == "positive_literal_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    transport_authenticated = True\n    def __post_init__(self):\n",
        )
    elif mutation == "positive_method_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    def transport_authenticated(self):\n"
            "        return True\n"
            "    def __post_init__(self):\n",
        )
    elif mutation == "closed_duplicate_method":
        mutated = baseline.replace(
            "    transport_authenticated = property(lambda _: False)\n",
            "    transport_authenticated = property(lambda _: False)\n"
            "    def transport_authenticated(self):\n"
            "        return True\n",
        )
    elif mutation == "drop_closed_base":
        mutated = baseline.replace(
            "TrustedTimeHeadAnchorOperationBoundCleanStopResult(_ClosedBridgeEvidence)",
            "TrustedTimeHeadAnchorOperationBoundCleanStopResult",
        )
    elif mutation == "duplicate_closed_class":
        mutated = f"class _ClosedBridgeEvidence:\n    pass\n{baseline}"
    elif mutation == "duplicate_positive_class":
        mutated = f"class TrustedTimeHeadAnchorOperationBoundCleanStopResult:\n    pass\n{baseline}"
    elif mutation == "custom_getattribute":
        mutated = baseline.replace(
            "    transport_authenticated = property(lambda _: False)\n",
            "    transport_authenticated = property(lambda _: False)\n"
            "    def __getattribute__(self, name):\n"
            "        return True\n",
        )
    elif mutation == "nested_class_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    class transport_authenticated:\n        pass\n    def __post_init__(self):\n",
        )
    elif mutation == "tuple_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    transport_authenticated, other = True, None\n    def __post_init__(self):\n",
        )
    elif mutation == "walrus_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    (transport_authenticated := True)\n    def __post_init__(self):\n",
        )
    elif mutation == "import_override":
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            "    import builtins as transport_authenticated\n    def __post_init__(self):\n",
        )
    elif mutation == "post_class_assignment":
        mutated = (
            f"{baseline}\n"
            "TrustedTimeHeadAnchorOperationBoundCleanStopResult."
            "transport_authenticated = True\n"
        )
    elif mutation == "post_class_setattr":
        mutated = (
            f"{baseline}\n"
            "setattr(TrustedTimeHeadAnchorOperationBoundCleanStopResult, "
            '"transport_authenticated", True)\n'
        )
    elif mutation == "post_class_type_setattr":
        mutated = (
            f"{baseline}\n"
            "type.__setattr__(TrustedTimeHeadAnchorOperationBoundCleanStopResult, "
            '"transport_authenticated", True)\n'
        )
    else:
        mutated = (
            f"{baseline}\n"
            "TrustedTimeHeadAnchorOperationBoundCleanStopResult.payload = lambda self: {}\n"
        )
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(expected_fragment in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "nested_class",
        "tuple_target",
        "walrus",
        "import_alias",
        "direct_assignment",
        "setattr",
        "type_setattr",
        "payload_assignment",
    ],
)
def test_adr0111_architecture_checker_rejects_host_evidence_binding_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    positive_class = "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation"
    baseline = (
        '_CLOSED_FIELDS = frozenset({"currentness_authenticated", '
        '"transport_authenticated"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "def _utc_text(value):\n"
        '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
        '"+00:00", "Z")\n'
        "class _ClosedHostBridgeEvidence:\n"
        "    currentness_authenticated = property(lambda _: False)\n"
        "    transport_authenticated = property(lambda _: False)\n"
        "@dataclass(frozen=True, slots=True, weakref_slot=True, init=False, eq=False)\n"
        f"class {positive_class}(_ClosedHostBridgeEvidence):\n"
        "    def __post_init__(self):\n"
        "        pass\n"
        "    @property\n"
        "    def exact_terminal_projection_cross_bound_unqualified(self):\n"
        "        self.__post_init__()\n"
        "        return True\n"
        "    @property\n"
        "    def provider_terminal_observed_under_stable_sql_authenticated(self):\n"
        "        self.__post_init__()\n"
        "        return True\n"
        "    def payload(self):\n"
        "        return {}\n"
        "__all__ = []\n"
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
graceful_stop_supervisor_bridge_roots = ["{relative_path.as_posix()}"]
graceful_stop_supervisor_bridge_closed_fields = [
  "currentness_authenticated", "transport_authenticated",
]
graceful_stop_supervisor_bridge_closed_evidence_class = "_ClosedHostBridgeEvidence"
graceful_stop_supervisor_bridge_positive_evidence_class = "{positive_class}"
graceful_stop_supervisor_bridge_positive_properties = [
  "exact_terminal_projection_cross_bound_unqualified",
  "provider_terminal_observed_under_stable_sql_authenticated",
]
graceful_stop_supervisor_bridge_positive_callable_names = ["payload"]
''',
        encoding="utf-8",
    )
    module_path.write_text(baseline, encoding="utf-8")
    assert check(tmp_path, config) == []

    insertion = {
        "nested_class": "    class transport_authenticated:\n        pass\n",
        "tuple_target": "    transport_authenticated, other = True, None\n",
        "walrus": "    (transport_authenticated := True)\n",
        "import_alias": "    import builtins as transport_authenticated\n",
    }
    if mutation in insertion:
        mutated = baseline.replace(
            "    def __post_init__(self):\n",
            f"{insertion[mutation]}    def __post_init__(self):\n",
        )
    elif mutation == "direct_assignment":
        mutated = f"{baseline}\n{positive_class}.transport_authenticated = True\n"
    elif mutation == "setattr":
        mutated = f'{baseline}\nsetattr({positive_class}, "transport_authenticated", True)\n'
    elif mutation == "type_setattr":
        mutated = (
            f'{baseline}\ntype.__setattr__({positive_class}, "transport_authenticated", True)\n'
        )
    else:
        mutated = f"{baseline}\n{positive_class}.payload = lambda self: {{}}\n"
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("closed-false and positive-true properties" in item.message for item in violations)


@pytest.mark.parametrize("owner", ["low", "host"])
@pytest.mark.parametrize(
    "mutation",
    [
        "positive_assign",
        "closed_annassign",
        "positive_tuple",
        "closed_walrus",
        "positive_comprehension",
        "closed_import_alias",
        "positive_dynamic_global",
        "positive_alias_mutation",
        "closed_container_alias_mutation",
    ],
)
def test_adr0111_architecture_checker_rejects_evidence_class_rebinding(
    tmp_path: Path,
    owner: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    if owner == "low":
        relative_path = Path(
            "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
        )
        root_key = "operation_bound_clean_stop_bridge_roots"
        closed_key = "operation_bound_clean_stop_bridge_closed_fields"
        closed_class = "_ClosedBridgeEvidence"
        positive_class = "TrustedTimeHeadAnchorOperationBoundCleanStopResult"
        closed_class_key = "operation_bound_clean_stop_bridge_closed_evidence_class"
        positive_class_key = "operation_bound_clean_stop_bridge_positive_evidence_class"
        positive_properties_key = "operation_bound_clean_stop_bridge_positive_properties"
        positive_callables_key = "operation_bound_clean_stop_bridge_positive_callable_names"
        dataclass_options = "frozen=True, slots=True, init=False, eq=False"
        extra = ""
    else:
        relative_path = Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
        )
        root_key = "graceful_stop_supervisor_bridge_roots"
        closed_key = "graceful_stop_supervisor_bridge_closed_fields"
        closed_class = "_ClosedHostBridgeEvidence"
        positive_class = "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation"
        closed_class_key = "graceful_stop_supervisor_bridge_closed_evidence_class"
        positive_class_key = "graceful_stop_supervisor_bridge_positive_evidence_class"
        positive_properties_key = "graceful_stop_supervisor_bridge_positive_properties"
        positive_callables_key = "graceful_stop_supervisor_bridge_positive_callable_names"
        dataclass_options = "frozen=True, slots=True, weakref_slot=True, init=False, eq=False"
        extra = (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
        )
    baseline = (
        '_CLOSED_FIELDS = frozenset({"transport_authenticated"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        f"{extra}"
        f"class {closed_class}:\n"
        "    transport_authenticated = property(lambda _: False)\n"
        f"@dataclass({dataclass_options})\n"
        f"class {positive_class}({closed_class}):\n"
        "    def __post_init__(self):\n"
        "        pass\n"
        "    @property\n"
        "    def exact_fact(self):\n"
        "        self.__post_init__()\n"
        "        return True\n"
        "    def payload(self):\n"
        "        return {}\n"
        "__all__ = []\n"
    )
    mutations = {
        "positive_assign": f"{positive_class} = object",
        "closed_annassign": f"{closed_class}: object = object",
        "positive_tuple": f"{positive_class}, other = object, None",
        "closed_walrus": f"({closed_class} := object)",
        "positive_comprehension": f"[None for {positive_class} in ()]",
        "closed_import_alias": f"import builtins as {closed_class}",
        "positive_dynamic_global": (f'globals().__setitem__("{positive_class}", object)'),
        "positive_alias_mutation": (
            f"Alias = {positive_class}\nAlias.transport_authenticated = True"
        ),
        "closed_container_alias_mutation": (
            f"aliases = [{closed_class}]\naliases[0].transport_authenticated = True"
        ),
    }
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
{root_key} = ["{relative_path.as_posix()}"]
{closed_key} = ["transport_authenticated"]
{closed_class_key} = "{closed_class}"
{positive_class_key} = "{positive_class}"
{positive_properties_key} = ["exact_fact"]
{positive_callables_key} = ["payload"]
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []
    module_path.write_text(f"{baseline}\n{mutations[mutation]}\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("closed-false and positive-true properties" in item.message for item in violations)


def test_adr0111_architecture_callable_ast_digest_is_python_312_313_stable() -> None:
    from scripts.check_architecture import _canonical_ast_sha256

    function = ast.parse(
        "def payload(self):\n"
        "    values = {name: False for name in _CLOSED_FIELDS}\n"
        '    values.update({"exact_fact": True})\n'
        "    return values\n"
    ).body[0]

    assert _canonical_ast_sha256(function) == (
        "ba3793bd0b9e725f9e1483a4f23766e3e2fd8563e35cf44d81eeb247ba1cf677"
    )


@pytest.mark.parametrize("owner", ["low", "host"])
@pytest.mark.parametrize(
    "mutation",
    [
        "direct_class_swap",
        "computed_class_swap",
        "alias_derived_class_swap",
        "direct_class_assignment",
        "split_metaclass_reflection",
        "direct_metaclass_mutation",
        "dynamic_metaclass_mutation",
    ],
)
def test_adr0111_architecture_checker_rejects_bridge_module_reflection_mutation(
    tmp_path: Path,
    owner: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import _canonical_ast_sha256, check

    relative_path = (
        Path("packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py")
        if owner == "low"
        else Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    )
    root_key = (
        "operation_bound_clean_stop_bridge_roots"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_roots"
    )
    module_key = (
        "operation_bound_clean_stop_bridge_module"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_module"
    )
    module_name = (
        "packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"
        if owner == "low"
        else "scripts.trusted_time_post_enrollment_graceful_stop_supervisor_bridge"
    )
    digest_key = (
        "operation_bound_clean_stop_bridge_module_ast_sha256"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_module_ast_sha256"
    )
    closed_key = (
        "operation_bound_clean_stop_bridge_closed_fields"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_closed_fields"
    )
    utc_helper = (
        ""
        if owner == "low"
        else (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
        )
    )
    baseline = (
        '_CLOSED_FIELDS = frozenset({"authority_granted"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        f"{utc_helper}"
        "class Evidence:\n"
        "    @property\n"
        "    def authority_granted(self):\n"
        "        return False\n"
        "def issue():\n"
        "    evidence = Evidence()\n"
        "    return evidence\n"
        "__all__ = []\n"
    )
    digest = _canonical_ast_sha256(ast.parse(baseline))
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
{root_key} = ["{relative_path.as_posix()}"]
{module_key} = "{module_name}"
{digest_key} = "{digest}"
{closed_key} = ["authority_granted"]
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []

    injections = {
        "direct_class_swap": (
            "    class Elevated(Evidence):\n"
            "        authority_granted = property(lambda _: True)\n"
            '    object.__setattr__(evidence, "__class__", Elevated)\n'
        ),
        "computed_class_swap": (
            "    class Elevated(Evidence):\n"
            "        authority_granted = property(lambda _: True)\n"
            '    object.__setattr__(evidence, "__" + "class__", Elevated)\n'
        ),
        "alias_derived_class_swap": (
            "    Base = type(evidence)\n"
            "    class Elevated(Base):\n"
            "        authority_granted = property(lambda _: True)\n"
            '    object.__setattr__(evidence, "__class__", Elevated)\n'
        ),
        "direct_class_assignment": (
            "    class Elevated(Evidence):\n"
            "        authority_granted = property(lambda _: True)\n"
            "    evidence.__class__ = Elevated\n"
        ),
        "split_metaclass_reflection": (
            "    owner_class = type(evidence)\n"
            "    metaclass = type(owner_class)\n"
            '    mutator_name = "__set" + "attr__"\n'
            "    mutator = getattr(metaclass, mutator_name)\n"
            '    field_name = "authority_" + "granted"\n'
            "    mutator(owner_class, field_name, property(lambda _: True))\n"
        ),
        "direct_metaclass_mutation": (
            "    type(type(evidence)).__setattr__(\n"
            "        type(evidence),\n"
            '        "authority_" + "granted",\n'
            "        property(lambda _: True),\n"
            "    )\n"
        ),
        "dynamic_metaclass_mutation": (
            "    type.__getattribute__(\n"
            "        type(type(evidence)),\n"
            '        "__set" + "attr__",\n'
            "    )(\n"
            "        type(evidence),\n"
            '        "authority_" + "granted",\n'
            "        property(lambda _: True),\n"
            "    )\n"
        ),
    }
    module_path.write_text(
        baseline.replace("    return evidence\n", f"{injections[mutation]}    return evidence\n"),
        encoding="utf-8",
    )

    violations = check(tmp_path, config)

    assert any("exact semantic module AST" in item.message for item in violations)


@pytest.mark.parametrize("owner", ["low", "host"])
@pytest.mark.parametrize(
    "mutation",
    [
        "omitted",
        "empty",
        "malformed",
        "wrong_digest",
        "wrong_module",
        "extra_root",
    ],
)
def test_adr0111_architecture_checker_rejects_bridge_module_digest_config_mutation(
    tmp_path: Path,
    owner: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import _canonical_ast_sha256, check

    relative_path = (
        Path("packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py")
        if owner == "low"
        else Path("scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py")
    )
    root_key = (
        "operation_bound_clean_stop_bridge_roots"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_roots"
    )
    module_key = (
        "operation_bound_clean_stop_bridge_module"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_module"
    )
    module_name = (
        "packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"
        if owner == "low"
        else "scripts.trusted_time_post_enrollment_graceful_stop_supervisor_bridge"
    )
    digest_key = (
        "operation_bound_clean_stop_bridge_module_ast_sha256"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_module_ast_sha256"
    )
    closed_key = (
        "operation_bound_clean_stop_bridge_closed_fields"
        if owner == "low"
        else "graceful_stop_supervisor_bridge_closed_fields"
    )
    utc_helper = (
        ""
        if owner == "low"
        else (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
        )
    )
    baseline = (
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        f"{utc_helper}"
        "__all__ = []\n"
    )
    digest = _canonical_ast_sha256(ast.parse(baseline))
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    module_assignment = f'{module_key} = "{module_name}"\n'
    digest_assignment = f'{digest_key} = "{digest}"\n'
    config_source = (
        f"[scan]\n"
        "source_roots = []\n"
        f"{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}"
        f'{root_key} = ["{relative_path.as_posix()}"]\n'
        f"{module_assignment}"
        f"{digest_assignment}"
        f'{closed_key} = ["closed"]\n'
    )
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(config_source, encoding="utf-8")
    assert check(tmp_path, config) == []

    if mutation == "omitted":
        mutated = config_source.replace(digest_assignment, "")
    elif mutation == "empty":
        mutated = config_source.replace(digest_assignment, f'{digest_key} = ""\n')
    elif mutation == "malformed":
        mutated = config_source.replace(digest_assignment, f'{digest_key} = "not-a-sha"\n')
    elif mutation == "wrong_digest":
        mutated = config_source.replace(digest_assignment, f'{digest_key} = "{"0" * 64}"\n')
    elif mutation == "wrong_module":
        mutated = config_source.replace(module_assignment, f'{module_key} = "wrong.module"\n')
    else:
        mutated = config_source.replace(
            f'{root_key} = ["{relative_path.as_posix()}"]\n',
            f'{root_key} = ["{relative_path.as_posix()}", "extra.py"]\n',
        )
    config.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "configure one exact root, dotted module, and semantic AST digest" in item.message
        or "preserve its exact semantic module AST" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_name",
        "getitem",
        "setitem",
        "pop_default",
        "pop_other",
        "extra_contains",
        "config_missing",
    ],
)
@pytest.mark.parametrize(
    ("wrapper_filename", "native_module_name"),
    [
        ("_owned_file_descriptor.py", "_autoquant_native_owned_file_descriptor"),
        ("_bounded_process.py", "_autoquant_native_bounded_process"),
    ],
)
def test_architecture_checker_rejects_private_native_sys_modules_admission_mutation(
    tmp_path: Path,
    mutation: str,
    wrapper_filename: str,
    native_module_name: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path("packages/adapters/trusted_time") / wrapper_filename
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    baseline = (
        "import sys\n"
        f'_NATIVE_MODULE_NAME = "{native_module_name}"\n'
        "if _NATIVE_MODULE_NAME in sys.modules:\n"
        "    raise RuntimeError\n"
        "if _NATIVE_MODULE_NAME in sys.modules:\n"
        "    raise RuntimeError\n"
    )
    allowed_lines = '  "<module>:contains-private-native",\n  "<module>:contains-private-native",\n'
    config_source = (
        "[scan]\n"
        "source_roots = []\n"
        f"{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}"
        'builtin_namespace_integrity_roots = ["packages"]\n'
        f'builtin_namespace_integrity_sys_modules_callsites."{relative_path.as_posix()}" = [\n'
        f"{allowed_lines}]\n"
    )
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(config_source, encoding="utf-8")
    assert check(tmp_path, config) == []

    if mutation == "wrong_name":
        module_path.write_text(
            baseline.replace(
                native_module_name,
                "_autoquant_alternate_native",
            ),
            encoding="utf-8",
        )
    elif mutation == "getitem":
        module_path.write_text(
            f"{baseline}value = sys.modules[_NATIVE_MODULE_NAME]\n", encoding="utf-8"
        )
    elif mutation == "setitem":
        module_path.write_text(
            f"{baseline}sys.modules[_NATIVE_MODULE_NAME] = object()\n", encoding="utf-8"
        )
    elif mutation == "pop_default":
        module_path.write_text(
            f"{baseline}sys.modules.pop(_NATIVE_MODULE_NAME, {{}})\n",
            encoding="utf-8",
        )
    elif mutation == "pop_other":
        module_path.write_text(
            f'{baseline}sys.modules.pop("_autoquant_alternate_native", None)\n',
            encoding="utf-8",
        )
    elif mutation == "extra_contains":
        module_path.write_text(
            f"{baseline}extra = _NATIVE_MODULE_NAME in sys.modules\n", encoding="utf-8"
        )
    else:
        assert mutation == "config_missing"
        config.write_text(
            config_source.replace(
                '  "<module>:contains-private-native",\n',
                "",
                1,
            ),
            encoding="utf-8",
        )

    violations = check(tmp_path, config)

    assert any("sys.modules" in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "direct",
        "module_alias",
        "from_import",
        "setattr",
        "module_dict",
        "dunder_builtins",
        "sys_modules",
        "split_alias",
        "partial_bridge",
        "sys_modules_iteration",
    ],
)
def test_adr0111_architecture_checker_rejects_ambient_builtin_poisoning(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    relative_path = Path("packages/application/trusted_time_head_anchor.py")
    dependency = tmp_path / relative_path
    dependency.parent.mkdir(parents=True)
    dependency.write_text("SAFE = True\n", encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f"""[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
builtin_namespace_integrity_roots = ["packages"]
""",
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []

    mutations = {
        "direct": "import builtins\nbuiltins.property = lambda function: function\n",
        "module_alias": (
            "import builtins as foundation\nfoundation.property = lambda function: function\n"
        ),
        "from_import": (
            "from builtins import property as captured\ncaptured = lambda function: function\n"
        ),
        "setattr": (
            'import builtins\nsetattr(builtins, "pro" + "perty", lambda function: function)\n'
        ),
        "module_dict": (
            'import builtins\nbuiltins.__dict__["property"] = lambda function: function\n'
        ),
        "dunder_builtins": ('__builtins__["property"] = lambda function: function\n'),
        "sys_modules": (
            'import sys\nsys.modules["built" + "ins"].property = lambda function: function\n'
        ),
        "split_alias": (
            "import builtins\n"
            "owner = builtins\n"
            'field = "pro" + "perty"\n'
            "namespace = vars(owner)\n"
            "namespace[field] = lambda function: function\n"
        ),
        "partial_bridge": (
            "import sys\n"
            'bridge = sys.modules["packages.application.'
            'trusted_time_head_anchor_clean_stop_supervisor_bridge"]\n'
            "bridge._EVIDENCE_PROPERTY = lambda function: function\n"
        ),
        "sys_modules_iteration": (
            "import sys\n"
            "for module_name, module in tuple(sys.modules.items()):\n"
            "    module.property = lambda function: function\n"
        ),
    }
    dependency.write_text(f"SAFE = True\n{mutations[mutation]}", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("production builtin namespace integrity" in item.message for item in violations)


def test_adr0111_architecture_checker_invocations_are_isolated_and_bytecode_free() -> None:
    workflow_paths = tuple(
        path for path in (ROOT / ".github/workflows").iterdir() if path.suffix in {".yaml", ".yml"}
    )
    assert workflow_paths == (ROOT / ".github/workflows/ci.yml",)
    make_source = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert make_source.count(_ARCHITECTURE_BOOTSTRAP_MAKE_BLOCK.rstrip("\n")) == 1
    assert make_source.count("scripts/check_architecture.py") == 1
    make_lines = make_source.splitlines()
    assert make_lines.count("override PYTHONDONTWRITEBYTECODE := 1") == 1
    assert make_lines.count("export PYTHONDONTWRITEBYTECODE") == 1
    workflow_source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    python_312_block = _architecture_bootstrap_workflow_block("3.12").rstrip("\n")
    matrix_block = _architecture_bootstrap_workflow_block("${{ matrix.python-version }}").rstrip(
        "\n"
    )
    assert workflow_source.count(python_312_block) == 5
    assert workflow_source.count(matrix_block) == 2
    assert workflow_source.count("scripts/check_architecture.py") == 7
    assert workflow_source.splitlines().count('      PYTHONDONTWRITEBYTECODE: "1"') == 4
    architecture_position = workflow_source.index(python_312_block)
    first_sync_position = workflow_source.index(
        "run: uv sync --all-groups --locked --no-install-project --no-build"
    )
    post_sync_position = workflow_source.index(python_312_block, architecture_position + 1)
    build_position = workflow_source.index("uv build --sdist", post_sync_position)
    post_build_position = workflow_source.index(python_312_block, post_sync_position + 1)
    assert (
        architecture_position
        < first_sync_position
        < post_sync_position
        < build_position
        < post_build_position
    )
    for later in (
        "run: .venv/bin/ruff format --check .",
        "run: .venv/bin/ruff check .",
        "run: .venv/bin/mypy apps packages",
    ):
        assert post_build_position < workflow_source.index(later)
    make_database = subprocess.run(
        ["make", "-pn", "PYTHONDONTWRITEBYTECODE=", "architecture-check"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert re.search(r"^PYTHONDONTWRITEBYTECODE := 1$", make_database, re.MULTILINE)
    parallel_dry_run = subprocess.run(
        [
            "make",
            "-n",
            "-j8",
            "PYTHONDONTWRITEBYTECODE=",
            "UV=echo uv",
            "PNPM=echo pnpm",
            "COMPOSE=echo docker-compose",
            "check",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    architecture_position = parallel_dry_run.index("scripts/check_architecture.py")
    for later in ("ruff format", "mypy apps packages", "pytest", "pnpm --dir"):
        assert architecture_position < parallel_dry_run.index(later)
    for path in (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/0111-dormant-operation-bound-clean-stop-supervisor-bridge.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    ):
        assert path.read_text(encoding="utf-8").count(_ARCHITECTURE_BOOTSTRAP_COMMAND) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "unsafe_make",
        "make_ignore_error",
        "make_or_true",
        "make_relocated",
        "make_bytecode_enabled",
        "make_parallel_check",
        "unsafe_ci",
        "ci_step_if",
        "ci_step_continue",
        "ci_step_shell",
        "ci_step_working_directory",
        "ci_step_env",
        "ci_job_if",
        "ci_job_continue",
        "ci_relocated",
        "ci_bytecode_enabled",
        "ci_sync_installs_project",
        "ci_sync_builds_project",
        "ci_build_without_constraints",
        "ci_build_without_hashes",
        "ci_install_with_dependencies",
        "ci_missing_constraint_environment",
        "extra_workflow",
        "unsafe_documentation",
    ],
)
def test_adr0111_architecture_checker_rejects_invocation_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    if mutation == "unsafe_make":
        path = tmp_path / "Makefile"
        path.write_text(
            path.read_text(encoding="utf-8").replace("--no-project", "--project ."),
            encoding="utf-8",
        )
    elif mutation == "make_ignore_error":
        path = tmp_path / "Makefile"
        path.write_text(
            path.read_text(encoding="utf-8").replace("\t$(UV)", "\t-$(UV)"),
            encoding="utf-8",
        )
    elif mutation == "make_or_true":
        path = tmp_path / "Makefile"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "scripts/check_architecture.py",
                "scripts/check_architecture.py || true",
            ),
            encoding="utf-8",
        )
    elif mutation == "make_relocated":
        path = tmp_path / "Makefile"
        path.write_text(
            "architecture-check:\n\t@true\ndummy:\n" + _ARCHITECTURE_BOOTSTRAP_MAKE_BLOCK,
            encoding="utf-8",
        )
    elif mutation == "make_bytecode_enabled":
        path = tmp_path / "Makefile"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "override PYTHONDONTWRITEBYTECODE := 1\n",
                "",
            ),
            encoding="utf-8",
        )
    elif mutation == "make_parallel_check":
        path = tmp_path / "Makefile"
        path.write_text(
            "override PYTHONDONTWRITEBYTECODE := 1\n"
            "export PYTHONDONTWRITEBYTECODE\n"
            "check: test architecture-check\n"
            "test:\n\tpython -m pytest\n"
            "architecture-check:\n" + _ARCHITECTURE_BOOTSTRAP_MAKE_BLOCK,
            encoding="utf-8",
        )
    elif mutation == "unsafe_ci":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace("--no-project", "--project ."),
            encoding="utf-8",
        )
    elif mutation.startswith("ci_step_"):
        path = tmp_path / ".github/workflows/ci.yml"
        injected = {
            "ci_step_if": "        if: false\n",
            "ci_step_continue": "        continue-on-error: true\n",
            "ci_step_shell": "        shell: bash\n",
            "ci_step_working_directory": "        working-directory: /tmp\n",
            "ci_step_env": "        env:\n          PYTHONPATH: scripts\n",
        }[mutation]
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                _ARCHITECTURE_BOOTSTRAP_WORKFLOW_PREFIX,
                f"{injected}{_ARCHITECTURE_BOOTSTRAP_WORKFLOW_PREFIX}",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation in {"ci_job_if", "ci_job_continue"}:
        path = tmp_path / ".github/workflows/ci.yml"
        injected = "if: false\n" if mutation == "ci_job_if" else "continue-on-error: true\n"
        path.write_text(f"{injected}{path.read_text(encoding='utf-8')}", encoding="utf-8")
    elif mutation == "ci_relocated":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            "jobs:\n"
            "  disabled-job:\n"
            "    if: false\n"
            "    steps:\n"
            "      - name: Architecture\n" + _architecture_bootstrap_workflow_block("3.12"),
            encoding="utf-8",
        )
    elif mutation == "ci_bytecode_enabled":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '  PYTHONDONTWRITEBYTECODE: "1"\n',
                "",
            ),
            encoding="utf-8",
        )
    elif mutation == "ci_sync_installs_project":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(" --no-install-project", "", 1),
            encoding="utf-8",
        )
    elif mutation == "ci_sync_builds_project":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(" --no-build", "", 1),
            encoding="utf-8",
        )
    elif mutation == "ci_build_without_constraints":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "--build-constraints build_support/native_build_constraints.txt ",
                "",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "ci_build_without_hashes":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(" --require-hashes", "", 1),
            encoding="utf-8",
        )
    elif mutation == "ci_install_with_dependencies":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(" --no-deps", "", 1),
            encoding="utf-8",
        )
    elif mutation == "ci_missing_constraint_environment":
        path = tmp_path / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "      UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt\n",
                "",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "extra_workflow":
        (tmp_path / ".github/workflows/extra.yaml").write_text(
            "steps:\n  - run: python scripts/check_architecture.py\n",
            encoding="utf-8",
        )
    else:
        path = tmp_path / "docs/runbooks/trusted-time-supervisor.md"
        path.write_text("python scripts/check_architecture.py\n", encoding="utf-8")

    config = tmp_path / "infra/architecture-boundaries.toml"
    config_source = config.read_text(encoding="utf-8")
    for relative in ("Makefile", ".github/workflows/ci.yml"):
        digest = hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()
        config_source = re.sub(
            r'(?m)^architecture_checker_invocation_source_sha256\."'
            + re.escape(relative)
            + r'" = "[0-9a-f]{64}"$',
            f'architecture_checker_invocation_source_sha256."{relative}" = "{digest}"',
            config_source,
        )
    config.write_text(config_source, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("architecture checker" in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    ["omit", "empty", "wrong", "extra_path", "symlink_make", "symlink_ci", "directory"],
)
def test_adr0111_architecture_checker_rejects_invocation_source_digest_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    source = config.read_text(encoding="utf-8")
    make_digest = hashlib.sha256((tmp_path / "Makefile").read_bytes()).hexdigest()
    assignment = f'architecture_checker_invocation_source_sha256."Makefile" = "{make_digest}"'
    if mutation == "omit":
        config.write_text(source.replace(f"{assignment}\n", ""), encoding="utf-8")
    elif mutation == "empty":
        config.write_text(
            source.replace(assignment, assignment.rsplit('"', 2)[0] + '""'), encoding="utf-8"
        )
    elif mutation == "wrong":
        config.write_text(
            source.replace(assignment, assignment.replace(make_digest, "0" * 64)),
            encoding="utf-8",
        )
    elif mutation == "extra_path":
        extra_assignment = f'architecture_checker_invocation_source_sha256."extra" = "{"0" * 64}"'
        config.write_text(
            source.replace(
                assignment,
                f"{assignment}\n{extra_assignment}",
            ),
            encoding="utf-8",
        )
    elif mutation in {"symlink_make", "symlink_ci"}:
        path = (
            tmp_path / "Makefile"
            if mutation == "symlink_make"
            else tmp_path / ".github/workflows/ci.yml"
        )
        target = path.with_name(f"{path.name}.real")
        path.rename(target)
        path.symlink_to(target)
    else:
        path = tmp_path / "Makefile"
        path.unlink()
        path.mkdir()

    violations = check(tmp_path, config)

    assert any(
        "invocation source" in item.message or "invocation contract" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "omit_path",
        "empty_paths",
        "wrong_path",
        "extra_path",
        "reordered_paths",
        "omit_digest",
        "empty_digest",
        "wrong_digest",
        "extra_key",
        "mutate_python_version",
        "mutate_pyproject",
        "mutate_lock",
        "mutate_test_builder",
        "mutate_build_constraints",
        "mutate_image_helper",
        "mutate_hook",
        "mutate_bounded_source",
        "mutate_native_source",
        "mutate_launcher_source",
        "symlink_input",
        "directory_input",
        "bad_build_backend",
        "bad_build_requirement",
        "bad_build_constraint_requirement",
        "bad_build_constraint_hash",
        "bad_uv_build_constraints",
        "bad_python_range",
        "bad_hook_path",
        "bad_wheel_excludes",
        "bad_sdist_excludes",
        "bad_sdist_sources",
        "bad_python_pin",
    ],
)
def test_adr0111_architecture_checker_rejects_project_build_bootstrap_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    config_source = config.read_text(encoding="utf-8")
    manifest_paths = (
        "project_build_bootstrap_manifest_paths = [\n"
        '  ".python-version",\n'
        '  "pyproject.toml",\n'
        '  "uv.lock",\n'
        '  "build_support/build_native_test_launcher.py",\n'
        '  "build_support/native_build_constraints.txt",\n'
        '  "build_support/native_image_manifest.py",\n'
        '  "build_support/native_owned_file_descriptor_hook.py",\n'
        '  "native/bounded_process.c",\n'
        '  "native/owned_file_descriptor.c",\n'
        '  "native/trusted_time_python_launcher.c",\n'
        "]\n"
    )
    digest_match = re.search(
        r'^project_build_bootstrap_manifest_sha256 = "([0-9a-f]{64})"$',
        config_source,
        re.MULTILINE,
    )
    assert digest_match is not None
    digest_assignment = digest_match.group(0)
    if mutation == "omit_path":
        config.write_text(config_source.replace('  "uv.lock",\n', ""), encoding="utf-8")
    elif mutation == "empty_paths":
        config.write_text(
            config_source.replace(
                manifest_paths,
                "project_build_bootstrap_manifest_paths = []\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_path":
        config.write_text(
            config_source.replace('  "uv.lock",', '  "uv-copy.lock",'),
            encoding="utf-8",
        )
    elif mutation == "extra_path":
        (tmp_path / "extra.bootstrap").write_text("unexpected\n", encoding="utf-8")
        config.write_text(
            config_source.replace(
                '  "native/owned_file_descriptor.c",\n',
                '  "native/owned_file_descriptor.c",\n  "extra.bootstrap",\n',
            ),
            encoding="utf-8",
        )
    elif mutation == "reordered_paths":
        config.write_text(
            config_source.replace(
                '  "pyproject.toml",\n  "uv.lock",',
                '  "uv.lock",\n  "pyproject.toml",',
            ),
            encoding="utf-8",
        )
    elif mutation == "omit_digest":
        config.write_text(config_source.replace(f"{digest_assignment}\n", ""), encoding="utf-8")
    elif mutation == "empty_digest":
        config.write_text(
            config_source.replace(
                digest_assignment, 'project_build_bootstrap_manifest_sha256 = ""'
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_digest":
        config.write_text(
            config_source.replace(digest_assignment, digest_assignment[:-65] + ("0" * 64) + '"'),
            encoding="utf-8",
        )
    elif mutation == "extra_key":
        config.write_text(
            config_source.replace(
                digest_assignment,
                f"{digest_assignment}\nproject_build_bootstrap_unreviewed = true",
            ),
            encoding="utf-8",
        )
    elif mutation.startswith("mutate_"):
        path = {
            "mutate_python_version": tmp_path / ".python-version",
            "mutate_pyproject": tmp_path / "pyproject.toml",
            "mutate_lock": tmp_path / "uv.lock",
            "mutate_test_builder": tmp_path / "build_support/build_native_test_launcher.py",
            "mutate_build_constraints": (tmp_path / "build_support/native_build_constraints.txt"),
            "mutate_image_helper": tmp_path / "build_support/native_image_manifest.py",
            "mutate_hook": tmp_path / "build_support/native_owned_file_descriptor_hook.py",
            "mutate_bounded_source": tmp_path / "native/bounded_process.c",
            "mutate_native_source": tmp_path / "native/owned_file_descriptor.c",
            "mutate_launcher_source": tmp_path / "native/trusted_time_python_launcher.c",
        }[mutation]
        path.write_bytes(path.read_bytes() + b"\n")
    elif mutation == "symlink_input":
        path = tmp_path / "uv.lock"
        target = tmp_path / "uv.lock.real"
        path.rename(target)
        path.symlink_to(target.name)
    elif mutation == "directory_input":
        path = tmp_path / "native/owned_file_descriptor.c"
        path.unlink()
        path.mkdir()
    elif mutation == "bad_build_backend":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'build-backend = "hatchling.build"',
                'build-backend = "setuptools.build_meta"',
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_build_requirement":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '  "hatchling==1.32.0",',
                '  "hatchling>=1.32",',
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_build_constraint_requirement":
        path = tmp_path / "build_support/native_build_constraints.txt"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "hatchling==1.32.0",
                "hatchling==1.31.0",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_build_constraint_hash":
        path = tmp_path / "build_support/native_build_constraints.txt"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "0bdbde4a52b06c37e3eca395f85a762bf0ef06fe374fd8ae429dc6be10230f5f",
                "0" * 64,
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_uv_build_constraints":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "[tool.uv]\nbuild-constraint-dependencies = [",
                "[tool.uv]\nmanaged = false\nbuild-constraint-dependencies = [",
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_python_range":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'requires-python = ">=3.12,<3.14"',
                'requires-python = ">=3.12"',
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_hook_path":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'path = "build_support/native_owned_file_descriptor_hook.py"',
                'path = "build_support/alternate.py"',
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_wheel_excludes":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'exclude = ["packages/adapters/trusted_time/_bounded_process.py"]',
                "exclude = []",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_sdist_excludes":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'exclude = ["/.uv-cache", "build_support/build_native_test_launcher.py"]',
                "exclude = []",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "bad_sdist_sources":
        path = tmp_path / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '"native/owned_file_descriptor.c" = "native/owned_file_descriptor.c"\n',
                "",
            ),
            encoding="utf-8",
        )
    else:
        assert mutation == "bad_python_pin"
        (tmp_path / ".python-version").write_text("3.13\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "project build bootstrap" in item.message
        or "project native" in item.message
        or "project Python" in item.message
        or "alternate local project build" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "forbidden_path",
    ["MANIFEST.in", "hatch.toml", "setup.cfg", "setup.py", "uv.toml"],
)
def test_adr0111_architecture_checker_rejects_alternate_project_build_configuration(
    tmp_path: Path,
    forbidden_path: str,
) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    (tmp_path / forbidden_path).write_text("[unreviewed]\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("alternate local project build" in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "new_consumer",
        "namespace_import",
        "internal_import",
        "dynamic_import",
        "configured_internal_import",
        "wrapper_ast",
        "bounded_wrapper_ast",
        "wrong_wrapper_digest",
        "wrong_bounded_wrapper_digest",
        "missing_consumer_config",
        "missing_probe_consumer_config",
        "operation_alias",
        "operation_container_alias",
        "owner_return",
        "nested_owner_return",
        "reflective_internal_attribute",
        "private_native_name_literal",
        "private_native_sys_modules_literal",
        "alternate_imp_loader",
        "alternate_ctypes_loader",
        "extension_file_loader",
        "raw_descriptor_namespace",
    ],
)
def test_architecture_checker_rejects_native_capability_reachability_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import _production_python_source_manifest_sha256, check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    module = "packages.adapters.trusted_time._owned_file_descriptor"
    binding = f"{module}:_fstat"
    consumer_relative = Path("scripts/trusted_time_post_enrollment_controller_outcome.py")
    consumer = tmp_path / consumer_relative
    config_source = config.read_text(encoding="utf-8")
    consumer_assignment = (
        "native_owned_file_descriptor_allowed_imports."
        f'"{consumer_relative.as_posix()}" = ["{binding}"]'
    )
    if mutation == "new_consumer":
        path = tmp_path / "scripts/unreviewed_native_consumer.py"
        path.write_text(f"from {module} import _fstat\n", encoding="utf-8")
    elif mutation == "namespace_import":
        consumer.write_text(f"import {module} as native\n", encoding="utf-8")
    elif mutation == "internal_import":
        consumer.write_text(f"from {module} import _native_module\n", encoding="utf-8")
    elif mutation == "dynamic_import":
        consumer.write_text(
            f'import importlib\nnative = importlib.import_module("{module}")\n',
            encoding="utf-8",
        )
    elif mutation == "configured_internal_import":
        consumer.write_text(f"from {module} import _native_module\n", encoding="utf-8")
        config.write_text(
            config_source.replace(binding, f"{module}:_native_module"), encoding="utf-8"
        )
    elif mutation == "wrapper_ast":
        path = tmp_path / "packages/adapters/trusted_time/_owned_file_descriptor.py"
        path.write_text(f"{path.read_text(encoding='utf-8')}EXTRA = True\n", encoding="utf-8")
    elif mutation == "bounded_wrapper_ast":
        path = tmp_path / "packages/adapters/trusted_time/_bounded_process.py"
        path.write_text(f"{path.read_text(encoding='utf-8')}EXTRA = True\n", encoding="utf-8")
    elif mutation == "wrong_wrapper_digest":
        config.write_text(
            re.sub(
                r'(?m)^native_owned_file_descriptor_wrapper_module_ast_sha256 = "[0-9a-f]{64}"$',
                f'native_owned_file_descriptor_wrapper_module_ast_sha256 = "{"0" * 64}"',
                config_source,
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_bounded_wrapper_digest":
        config.write_text(
            re.sub(
                r'(?m)^native_bounded_process_wrapper_module_ast_sha256 = "[0-9a-f]{64}"$',
                f'native_bounded_process_wrapper_module_ast_sha256 = "{"0" * 64}"',
                config_source,
            ),
            encoding="utf-8",
        )
    elif mutation == "missing_consumer_config":
        config.write_text(config_source.replace(f"{consumer_assignment}\n", ""), encoding="utf-8")
    elif mutation == "missing_probe_consumer_config":
        config.write_text(
            re.sub(
                r"(?m)^native_owned_file_descriptor_allowed_imports\."
                r'"apps/trusted_time_supervisor/post_enrollment_read_probes\.py" = \[.*\]\n',
                "",
                config_source,
            ),
            encoding="utf-8",
        )
    elif mutation == "operation_alias":
        consumer.write_text(
            f"from {module} import _fstat\nalias = _fstat\n",
            encoding="utf-8",
        )
    elif mutation == "operation_container_alias":
        consumer.write_text(
            f"from {module} import _fstat\nholder = (_fstat,)\n",
            encoding="utf-8",
        )
    elif mutation in {"owner_return", "nested_owner_return"}:
        owner_binding = f"{module}:_open_root_directory"
        consumer.write_text(
            f"from {module} import _fstat, _open_root_directory\n"
            + (
                "def leak():\n    owner = _open_root_directory()\n    return owner\n"
                if mutation == "owner_return"
                else "def leak():\n    return _open_root_directory()\n"
            ),
            encoding="utf-8",
        )
        config.write_text(
            config_source.replace(
                f'["{binding}"]',
                f'["{binding}", "{owner_binding}"]',
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "reflective_internal_attribute":
        consumer.write_text(
            f"from {module} import _fstat\n"
            "class Holder:\n"
            "    pass\n"
            "VALUE = Holder._native_module\n",
            encoding="utf-8",
        )
    elif mutation == "private_native_name_literal":
        consumer.write_text(
            f"from {module} import _fstat\n"
            'VALUE = "packages.adapters.trusted_time._native_" + "owned_file_descriptor"\n',
            encoding="utf-8",
        )
    elif mutation == "private_native_sys_modules_literal":
        consumer.write_text(
            f"from {module} import _fstat\n"
            "import sys\n"
            'VALUE = sys.modules.get("packages.adapters.trusted_time.'
            '_native_owned_file_descriptor")\n',
            encoding="utf-8",
        )
    elif mutation in {
        "alternate_imp_loader",
        "alternate_ctypes_loader",
        "extension_file_loader",
        "raw_descriptor_namespace",
    }:
        path = tmp_path / "packages/unreviewed_native_loader.py"
        source = {
            "alternate_imp_loader": "import _imp\nVALUE = _imp.create_dynamic\n",
            "alternate_ctypes_loader": "import ctypes\nVALUE = ctypes.CDLL\n",
            "extension_file_loader": (
                "from importlib.machinery import ExtensionFileLoader\nVALUE = ExtensionFileLoader\n"
            ),
            "raw_descriptor_namespace": 'VALUE = "/proc/self/fd/3"\n',
        }[mutation]
        path.write_text(source, encoding="utf-8")
    else:
        raise AssertionError(f"unhandled mutation: {mutation}")

    config_source = config.read_text(encoding="utf-8")
    roots = tuple(tmp_path / value for value in ("apps", "packages", "scripts"))
    digest = _production_python_source_manifest_sha256(
        tmp_path,
        roots,
        (tmp_path / "apps/web/node_modules",),
    )
    config_source = re.sub(
        r'(?m)^production_python_source_manifest_sha256 = "[0-9a-f]{64}"$',
        f'production_python_source_manifest_sha256 = "{digest}"',
        config_source,
    )
    config.write_text(config_source, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "native owned-file-descriptor" in item.message
        or "native bounded-process" in item.message
        or "alternate native loader" in item.message
        or "reflective or raw-descriptor native capability" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_function",
        "wrong_parameter",
        "wrong_origin",
        "default_removal",
        "default_alternate",
        "extra_default_alias",
        "extra_import_alias",
        "module_global_rebind",
        "parameter_reassignment",
        "parameter_import_alias",
        "parameter_except_alias",
        "parameter_match_as",
        "parameter_match_star",
        "parameter_match_mapping",
        "parameter_return",
        "parameter_forward",
        "parameter_alias",
        "parameter_closure",
        "direct_origin_reload",
        "wrong_call_count",
        "protected_keyword_override",
        "protected_kwargs_expansion",
        "configured_function_alias",
        "configured_function_rebind",
        "configured_function_decorator",
        "conditional_native_import",
        "external_protected_import",
        "owner_identity_escape",
        "owner_stash_escape",
        "cleanup_bad_default",
        "cleanup_explicit_override",
        "cleanup_local_rebind",
        "observe_marker_default_swap",
        "read_regular_default_swap",
        "globals_native_rebind",
        "globals_helper_rebind",
        "globals_alias_rebind",
        "builtins_globals_alias",
        "computed_reflection",
        "loader_module_rebind",
        "inspect_module_rebind",
        "gc_globals_rebind",
        "pkgutil_module_rebind",
        "operator_modules_rebind",
        "capture_module_ast_drift",
        "wildcard_import",
        "receiver_bound_method_escape",
        "helper_return_escape",
        "helper_global_stash",
        "helper_attribute_stash",
        "helper_container_stash",
        "caller_helper_result_escape",
        "lambda_native_capture",
        "genexpr_native_capture",
        "class_owner_attribute_escape",
        "owner_augassign_escape",
        "owner_for_alias_escape",
        "owner_match_alias_escape",
        "rogue_direct_native_global",
        "factory_nonlocal_store",
    ],
)
def test_architecture_checker_rejects_native_captured_default_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import _production_python_source_manifest_sha256, check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    module = "packages.adapters.trusted_time._owned_file_descriptor"
    probe_relative = Path("apps/trusted_time_supervisor/post_enrollment_read_probes.py")
    probe = tmp_path / probe_relative
    source = probe.read_text(encoding="utf-8")
    runtime = tmp_path / "apps/trusted_time_supervisor/post_enrollment_runtime_state.py"
    runtime_source = runtime.read_text(encoding="utf-8")
    config_source = config.read_text(encoding="utf-8")
    signature = "def _require_absences(*, _fstat_exact=_fstat, _statat_exact=_statat):\n"
    capture_assignment = (
        "native_owned_file_descriptor_captured_defaults."
        f'"{probe_relative.as_posix()}"._require_absences._fstat_exact = '
        f'"{module}:_fstat"'
    )
    if mutation == "wrong_function":
        config_source = config_source.replace(
            capture_assignment,
            capture_assignment.replace("._require_absences.", "._unreviewed."),
        )
    elif mutation == "wrong_parameter":
        config_source = config_source.replace(
            capture_assignment,
            capture_assignment.replace("._fstat_exact =", "._alternate ="),
        )
    elif mutation == "wrong_origin":
        config_source = config_source.replace(
            capture_assignment,
            capture_assignment.replace(':_fstat"', ':_read_snapshot"'),
        )
    elif mutation == "default_removal":
        source = source.replace(
            signature,
            "def _require_absences(*, _fstat_exact, _statat_exact=_statat):\n",
            1,
        )
    elif mutation == "default_alternate":
        source = source.replace("_fstat_exact=_fstat", "_fstat_exact=_statat", 1)
    elif mutation == "extra_default_alias":
        source = source.replace(
            signature,
            "def _require_absences(*, _fstat_exact=_fstat, _statat_exact=_statat, "
            "_extra=_fstat):\n",
            1,
        )
    elif mutation == "extra_import_alias":
        source = f"from {module} import _fstat as extra_fstat\n{source}"
    elif mutation == "module_global_rebind":
        source = source.replace(
            signature,
            "_fstat = lambda value: None\n" + signature,
            1,
        )
    elif mutation in {
        "parameter_reassignment",
        "parameter_import_alias",
        "parameter_except_alias",
        "parameter_match_as",
        "parameter_match_star",
        "parameter_match_mapping",
        "parameter_closure",
    }:
        injected = {
            "parameter_reassignment": "    _fstat_exact = _statat_exact\n",
            "parameter_import_alias": "    from math import ceil as _fstat_exact\n",
            "parameter_except_alias": (
                "    try:\n        pass\n    except Exception as _fstat_exact:\n        pass\n"
            ),
            "parameter_match_as": (
                "    match None:\n        case _fstat_exact:\n            pass\n"
            ),
            "parameter_match_star": (
                "    match ():\n        case (*_fstat_exact,):\n            pass\n"
            ),
            "parameter_match_mapping": (
                "    match {}:\n        case {**_fstat_exact}:\n            pass\n"
            ),
            "parameter_closure": (
                "    def invoke():\n        return _fstat_exact(None)\n    invoke()\n"
            ),
        }[mutation]
        source = source.replace(signature, signature + injected, 1)
    elif mutation == "parameter_return":
        source = source.replace("    _fstat_exact(None)\n", "    return _fstat_exact\n", 1)
    elif mutation == "parameter_forward":
        source = source.replace(
            "    _fstat_exact(None)\n",
            "    _statat_exact(None, _fstat_exact)\n",
            1,
        )
    elif mutation == "parameter_alias":
        source = source.replace("    _fstat_exact(None)\n", "    alias = _fstat_exact\n", 1)
    elif mutation == "direct_origin_reload":
        source = source.replace("    _fstat_exact(None)\n", "    _fstat(None)\n", 1)
    elif mutation == "wrong_call_count":
        source = source.replace(
            signature,
            signature + "    _fstat_exact(None)\n",
            1,
        )
    elif mutation == "protected_keyword_override":
        source += "\n_require_absences(_fstat_exact=lambda value: None)\n"
    elif mutation == "protected_kwargs_expansion":
        source += "\n_require_absences(**{})\n"
    elif mutation == "configured_function_alias":
        source += "\nalias = _require_absences\n"
    elif mutation == "configured_function_rebind":
        source += "\n_require_absences = lambda **kwargs: None\n"
    elif mutation == "configured_function_decorator":
        source = source.replace(signature, "@staticmethod\n" + signature, 1)
    elif mutation == "conditional_native_import":
        source = f"if False:\n    from {module} import _fstat\n{source}"
    elif mutation == "external_protected_import":
        external = tmp_path / "scripts/unreviewed_probe_import.py"
        external.write_text(
            "from apps.trusted_time_supervisor.post_enrollment_read_probes "
            "import _require_absences\n",
            encoding="utf-8",
        )
    elif mutation in {"owner_identity_escape", "owner_stash_escape"}:
        replacement = "    root_owner = _open_root()\n" + (
            "    alias = identity(root_owner)\n    return alias\n"
            if mutation == "owner_identity_escape"
            else "    stash(root_owner)\n"
        )
        source = source.replace("    root_owner = _open_root()\n", replacement, 1)
    elif mutation == "cleanup_bad_default":
        source = source.replace(
            "_cleanup=_cleanup_native_owners",
            "_cleanup=lambda owners: owners",
            1,
        )
    elif mutation == "cleanup_explicit_override":
        source += "\n_read_marker(_cleanup=lambda owners: None)\n"
    elif mutation == "cleanup_local_rebind":
        source = source.replace(
            "_cleanup=_cleanup_native_owners):\n    _fstat_exact(None)",
            "_cleanup=_cleanup_native_owners):\n"
            "    _cleanup = lambda owners: None\n"
            "    _fstat_exact(None)",
            1,
        )
    elif mutation == "observe_marker_default_swap":
        source = source.replace(
            "_observe_marker=_read_marker",
            "_observe_marker=_require_absences",
            1,
        )
    elif mutation == "read_regular_default_swap":
        runtime_source = runtime_source.replace(
            "_read_regular=_read_regular_snapshot",
            "_read_regular=_require_absences",
            1,
        )
    elif mutation in {
        "globals_native_rebind",
        "globals_helper_rebind",
        "globals_alias_rebind",
        "builtins_globals_alias",
        "computed_reflection",
        "loader_module_rebind",
        "inspect_module_rebind",
        "gc_globals_rebind",
        "pkgutil_module_rebind",
        "operator_modules_rebind",
        "wildcard_import",
    }:
        injected = {
            "globals_native_rebind": 'globals()["_fstat"] = lambda value: None\n',
            "globals_helper_rebind": (
                'globals()["_cleanup_native_owners"] = lambda owners: None\n'
            ),
            "globals_alias_rebind": (
                'namespace = globals\nnamespace()["_open_root_directory"] = lambda: object()\n'
            ),
            "builtins_globals_alias": (
                "from builtins import globals as namespace\n"
                'namespace()["_fstat"] = lambda value: None\n'
            ),
            "computed_reflection": (
                'namespace = getattr(__builtins__, "globals")\n'
                'namespace()["_fstat"] = lambda value: None\n'
            ),
            "loader_module_rebind": (
                "this = __loader__.load_module(__name__)\n"
                "this._open_root_directory = lambda: object()\n"
            ),
            "inspect_module_rebind": (
                "import inspect\n"
                "this = inspect.getmodule(lambda: None)\n"
                "this._open_root_directory = lambda: object()\n"
            ),
            "gc_globals_rebind": (
                "import gc\n"
                "namespace = next(\n"
                "    value for value in gc.get_referents(lambda: None)\n"
                '    if type(value) is dict and "__name__" in value\n'
                ")\n"
                'namespace["_open_root_directory"] = lambda: object()\n'
            ),
            "pkgutil_module_rebind": (
                "import pkgutil\n"
                "this = pkgutil.resolve_name(__name__)\n"
                "this._open_root_directory = lambda: object()\n"
            ),
            "operator_modules_rebind": (
                "import operator\n"
                'this = operator.attrgetter("modules")(sys)[__name__]\n'
                "this._open_root_directory = lambda: object()\n"
            ),
            "wildcard_import": "from evil import *\n",
        }[mutation]
        source = source.replace(")\n", ")\n" + injected, 1)
    elif mutation == "receiver_bound_method_escape":
        source = source.replace(
            "    root_owner = _open_root()\n",
            "    root_owner = _open_root()\n"
            '    alias = root_owner.__getattribute__("close")\n'
            "    return alias\n",
            1,
        )
    elif mutation in {
        "helper_return_escape",
        "helper_global_stash",
        "helper_attribute_stash",
        "helper_container_stash",
    }:
        helper_body = {
            "helper_return_escape": "    return owners\n",
            "helper_global_stash": "    global STASH\n    STASH = owners\n    return None\n",
            "helper_attribute_stash": "    holder.value = owners\n    return None\n",
            "helper_container_stash": "    STASH.append(owners)\n    return None\n",
        }[mutation]
        source = source.replace(
            "def _cleanup_native_owners(owners):\n    return None\n",
            "def _cleanup_native_owners(owners):\n" + helper_body,
            1,
        )
    elif mutation == "caller_helper_result_escape":
        source = source.replace(
            "    _cleanup((file_owner,))\n",
            "    escaped = _cleanup((file_owner,))\n    return escaped\n",
            1,
        )
    elif mutation == "lambda_native_capture":
        source = source.replace(
            "    _fstat_exact(None)\n",
            "    deferred = lambda owner: _fstat_exact(owner)\n    deferred(None)\n",
            1,
        )
    elif mutation == "genexpr_native_capture":
        source = source.replace(
            "    _fstat_exact(None)\n",
            "    deferred = (_fstat_exact(owner) for owner in (None,))\n    tuple(deferred)\n",
            1,
        )
    elif mutation == "class_owner_attribute_escape":
        source = source.replace(
            "    root_owner = _open_root()\n",
            "    class Escape:\n        owner = _open_root()\n    return Escape\n",
            1,
        )
    elif mutation in {
        "owner_augassign_escape",
        "owner_for_alias_escape",
        "owner_match_alias_escape",
    }:
        replacement = {
            "owner_augassign_escape": (
                "    global STASH\n    root_owner = _open_root()\n    STASH += (root_owner,)\n"
            ),
            "owner_for_alias_escape": (
                "    root_owner = _open_root()\n"
                "    for alias in (root_owner,):\n"
                "        pass\n"
                "    return alias\n"
            ),
            "owner_match_alias_escape": (
                "    root_owner = _open_root()\n"
                "    match root_owner:\n"
                "        case alias:\n"
                "            pass\n"
                "    return alias\n"
            ),
        }[mutation]
        source = source.replace("    root_owner = _open_root()\n", replacement, 1)
    elif mutation == "rogue_direct_native_global":
        source += "\ndef rogue(owner):\n    return _fstat(owner)\n"
    elif mutation == "capture_module_ast_drift":
        source += "\nMODULE_AST_DRIFT = True\n"
    else:
        assert mutation == "factory_nonlocal_store"
        consumer_relative = Path("scripts/trusted_time_post_enrollment_controller_outcome.py")
        consumer = tmp_path / consumer_relative
        consumer.write_text(
            f"from {module} import _fstat, _open_root_directory\n"
            "def outer():\n"
            "    owner = None\n"
            "    def inner():\n"
            "        nonlocal owner\n"
            "        owner = _open_root_directory()\n"
            "    inner()\n",
            encoding="utf-8",
        )
        config_source = config_source.replace(
            f'"{module}:_fstat"]',
            f'"{module}:_fstat", "{module}:_open_root_directory"]',
            1,
        )
    probe.write_text(source, encoding="utf-8")
    runtime.write_text(runtime_source, encoding="utf-8")
    config.write_text(config_source, encoding="utf-8")
    roots = tuple(tmp_path / value for value in ("apps", "packages", "scripts"))
    digest = _production_python_source_manifest_sha256(
        tmp_path,
        roots,
        (tmp_path / "apps/web/node_modules",),
    )
    config_source = re.sub(
        r'(?m)^production_python_source_manifest_sha256 = "[0-9a-f]{64}"$',
        f'production_python_source_manifest_sha256 = "{digest}"',
        config.read_text(encoding="utf-8"),
    )
    config.write_text(config_source, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "native owned-file-descriptor" in item.message
        or "native captured-default" in item.message
        or "native owner-consuming" in item.message
        for item in violations
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "new_consumer",
        "missing_consumer_config",
        "wrong_configured_binding",
        "namespace_import",
        "import_alias",
        "operation_alias",
        "wrong_caller",
        "extra_call",
        "keyword_argument",
        "wrong_stdout_cap",
        "result_alias",
        "result_attribute",
        "result_subscript",
        "wrong_numeric_slot",
        "binding_function_redefinition",
        "duplicate_reader",
        "reexport_all",
        "result_rebind",
        "result_reflection",
        "transitive_reexport",
        "decoder_rebind",
        "decoder_forged_return",
        "missing_call",
        "six_args",
        "eight_args",
        "starred_args",
        "looped_call",
        "duplicate_direct_import",
        "configured_extra_consumer",
        "operation_match_capture",
        "reader_match_capture",
        "computed_globals_operation",
        "computed_exec_operation",
        "computed_globals_reader",
        "namespace_getattr_operation",
        "owner_dict_import",
        "dynamic_computed_wrapper_import",
        "aliased_dynamic_computed_wrapper_import",
        "reader_globals",
        "reader_kwdefaults",
        "reader_second_hop_namespace",
        "reader_second_hop_dynamic",
        "reader_second_hop_function_globals",
        "module_builtin_shadow",
        "async_duplicate_reader",
    ],
)
def test_architecture_checker_rejects_native_bounded_process_consumer_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import _production_python_source_manifest_sha256, check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    module = "packages.adapters.trusted_time._bounded_process"
    binding = f"{module}:_run_bounded_process"
    consumer_relative = Path("scripts/verify_trusted_time_images.py")
    consumer = tmp_path / consumer_relative
    source = consumer.read_text(encoding="utf-8")
    config_source = config.read_text(encoding="utf-8")
    consumer_assignment = (
        f'native_bounded_process_allowed_imports."{consumer_relative.as_posix()}" = ["{binding}"]'
    )
    if mutation == "new_consumer":
        path = tmp_path / "scripts/unreviewed_bounded_process_consumer.py"
        path.write_text(f"from {module} import _run_bounded_process\n", encoding="utf-8")
    elif mutation == "missing_consumer_config":
        config.write_text(config_source.replace(f"{consumer_assignment}\n", ""), encoding="utf-8")
    elif mutation == "wrong_configured_binding":
        config.write_text(
            config_source.replace(binding, f"{module}:_native_module"), encoding="utf-8"
        )
    elif mutation == "namespace_import":
        consumer.write_text(
            source.replace(
                f"from {module} import _run_bounded_process\n",
                f"import {module} as bounded_process\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "import_alias":
        consumer.write_text(
            source.replace(
                f"from {module} import _run_bounded_process\n",
                f"from {module} import _run_bounded_process as run_process\n",
            ).replace("_run_bounded_process(", "run_process("),
            encoding="utf-8",
        )
    elif mutation == "operation_alias":
        consumer.write_text(f"{source}BOUND_PROCESS = _run_bounded_process\n", encoding="utf-8")
    elif mutation == "binding_function_redefinition":
        consumer.write_text(
            f"{source}def _run_bounded_process(*args):\n    return args\n",
            encoding="utf-8",
        )
    elif mutation == "duplicate_reader":
        consumer.write_text(
            f"{source}def _head_reviewed_operator_authority_object():\n    return None\n",
            encoding="utf-8",
        )
    elif mutation == "async_duplicate_reader":
        consumer.write_text(
            f"{source}async def _head_reviewed_operator_authority_object():\n    return None\n",
            encoding="utf-8",
        )
    elif mutation == "operation_match_capture":
        consumer.write_text(
            f"{source}match object():\n    case _run_bounded_process:\n        pass\n",
            encoding="utf-8",
        )
    elif mutation == "reader_match_capture":
        consumer.write_text(
            f"{source}match object():\n"
            "    case _head_reviewed_operator_authority_object:\n"
            "        pass\n",
            encoding="utf-8",
        )
    elif mutation == "computed_globals_operation":
        consumer.write_text(
            f'{source}globals()["".join(("_run_bounded_", "process"))] = lambda: None\n',
            encoding="utf-8",
        )
    elif mutation == "computed_exec_operation":
        consumer.write_text(
            f'{source}exec("_run_bounded_" + "process = lambda: None")\n',
            encoding="utf-8",
        )
    elif mutation == "computed_globals_reader":
        consumer.write_text(
            f'{source}globals()["".join(("_head_reviewed_operator_", '
            '"authority_object"))] = lambda: None\n',
            encoding="utf-8",
        )
    elif mutation == "module_builtin_shadow":
        consumer.write_text(
            f"{source}tuple = lambda value: value\n"
            "type = lambda value: tuple\n"
            "len = lambda value: 4\n",
            encoding="utf-8",
        )
    elif mutation == "reexport_all":
        consumer.write_text(f'{source}__all__ = ("_run_bounded_process",)\n', encoding="utf-8")
    elif mutation == "decoder_rebind":
        consumer.write_text(
            source.replace(
                '    exact_cwd = "/"\n',
                '    require_native_result = lambda *_args, **_kwargs: (0, b"forged", b"")\n'
                '    exact_cwd = "/"\n',
            ),
            encoding="utf-8",
        )
    elif mutation == "decoder_forged_return":
        consumer.write_text(
            source.replace(
                "        return returncode, stdout, stderr\n",
                '        return 0, b"forged", b""\n',
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_caller":
        consumer.write_text(
            source.replace(
                "def _head_reviewed_operator_authority_object():",
                "def unreviewed_process_caller():",
            ),
            encoding="utf-8",
        )
    elif mutation == "extra_call":
        consumer.write_text(
            source.replace(
                "    return require_native_result(blob, expected_argv=blob_argv)\n",
                "    extra = _run_bounded_process(\n"
                "        blob_argv, exact_cwd, exact_environment, request, 4353, 16384, "
                "5000000000\n"
                "    )\n"
                "    require_native_result(extra, expected_argv=blob_argv)\n"
                "    return require_native_result(blob, expected_argv=blob_argv)\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "keyword_argument":
        consumer.write_text(
            source.replace(
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, '
                "timeout_ns=5000000000",
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_stdout_cap":
        consumer.write_text(
            source.replace(
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
                'revision_argv, exact_cwd, exact_environment, b"", 65, 16384, 5000000000',
            ),
            encoding="utf-8",
        )
    elif mutation == "missing_call":
        consumer.write_text(
            source.replace(
                "    resolved = _run_bounded_process(\n"
                '        revision_argv, exact_cwd, exact_environment, b"", 64, 16384, '
                "5000000000\n"
                "    )\n",
                '    resolved = (revision_argv, 0, b"", b"")\n',
            ),
            encoding="utf-8",
        )
    elif mutation == "six_args":
        consumer.write_text(
            source.replace(
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384',
            ),
            encoding="utf-8",
        )
    elif mutation == "eight_args":
        consumer.write_text(
            source.replace(
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000, 0',
            ),
            encoding="utf-8",
        )
    elif mutation == "starred_args":
        consumer.write_text(
            source.replace(
                'revision_argv, exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
                '* (revision_argv,), exact_cwd, exact_environment, b"", 64, 16384, 5000000000',
            ),
            encoding="utf-8",
        )
    elif mutation == "looped_call":
        consumer.write_text(
            source.replace(
                "    resolved = _run_bounded_process(\n"
                '        revision_argv, exact_cwd, exact_environment, b"", 64, 16384, '
                "5000000000\n"
                "    )\n",
                "    for _index in range(1):\n"
                "        resolved = _run_bounded_process(\n"
                '            revision_argv, exact_cwd, exact_environment, b"", 64, 16384, '
                "5000000000\n"
                "        )\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "duplicate_direct_import":
        consumer.write_text(
            f"{source}from {module} import _run_bounded_process\n", encoding="utf-8"
        )
    elif mutation == "result_alias":
        consumer.write_text(
            source.replace(
                "    require_native_result(resolved, expected_argv=revision_argv)\n",
                "    copied_result = resolved\n"
                "    require_native_result(resolved, expected_argv=revision_argv)\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "result_rebind":
        consumer.write_text(
            source.replace(
                "    require_native_result(resolved, expected_argv=revision_argv)\n",
                '    resolved = (revision_argv, 0, b"", b"")\n'
                "    require_native_result(resolved, expected_argv=revision_argv)\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "result_reflection":
        consumer.write_text(
            source.replace(
                "        return returncode, stdout, stderr\n",
                '        getattr(value, "returncode", returncode)\n'
                "        return returncode, stdout, stderr\n",
            ),
            encoding="utf-8",
        )
    elif mutation == "result_attribute":
        consumer.write_text(
            source.replace(
                "        returncode = tuple.__getitem__(value, 1)",
                "        returncode = value.returncode",
            ),
            encoding="utf-8",
        )
    elif mutation == "result_subscript":
        consumer.write_text(
            source.replace(
                "        returncode = tuple.__getitem__(value, 1)",
                "        returncode = value[1]",
            ),
            encoding="utf-8",
        )
    elif mutation == "wrong_numeric_slot":
        consumer.write_text(
            source.replace(
                "        returncode = tuple.__getitem__(value, 1)",
                "        returncode = tuple.__getitem__(value, 0)",
            ),
            encoding="utf-8",
        )
    elif mutation in {
        "aliased_dynamic_computed_wrapper_import",
        "dynamic_computed_wrapper_import",
        "namespace_getattr_operation",
        "owner_dict_import",
        "reader_globals",
        "reader_kwdefaults",
        "reader_second_hop_dynamic",
        "reader_second_hop_function_globals",
        "reader_second_hop_namespace",
    }:
        path = tmp_path / "scripts/unreviewed_process_reflection.py"
        if mutation == "namespace_getattr_operation":
            reflection_source = (
                "import scripts.verify_trusted_time_images as verifier\n"
                'CAPABILITY = getattr(verifier, "".join(("_run_bounded_", "process")))\n'
            )
        elif mutation == "owner_dict_import":
            reflection_source = (
                "from scripts.verify_trusted_time_images import __dict__ as module_dict\n"
                'CAPABILITY = module_dict["".join(("_run_bounded_", "process"))]\n'
            )
        elif mutation == "dynamic_computed_wrapper_import":
            reflection_source = (
                "import importlib\n"
                'wrapper = importlib.import_module("packages.adapters.trusted_time." '
                '+ "_bounded_process")\n'
                'CAPABILITY = vars(wrapper)["_run_bounded_" + "process"]\n'
            )
        elif mutation == "aliased_dynamic_computed_wrapper_import":
            reflection_source = (
                "from importlib import import_module as load\n"
                'wrapper = load("".join(("packages.adapters.trusted_time.", '
                '"_bounded_process")))\n'
                'CAPABILITY = vars(wrapper)["".join(("_run_bounded_", "process"))]\n'
            )
        elif mutation == "reader_globals":
            reflection_source = (
                "from scripts.verify_trusted_time_images import "
                "_head_reviewed_operator_authority_object as reader\n"
                'CAPABILITY = reader.__globals__["".join(("_run_bounded_", "process"))]\n'
            )
        elif mutation == "reader_kwdefaults":
            reflection_source = (
                "from scripts.verify_trusted_time_images import "
                "_head_reviewed_operator_authority_object as reader\n"
                "CAPABILITY = reader.__kwdefaults__\n"
            )
        elif mutation == "reader_second_hop_namespace":
            reflection_source = (
                "import scripts.trusted_time_post_enrollment_execution_admission as admission\n"
                'CAPABILITY = getattr(admission, "".join(("_head_reviewed_operator_", '
                '"authority_object")))\n'
            )
        elif mutation == "reader_second_hop_dynamic":
            reflection_source = (
                "from importlib import import_module as load\n"
                'admission = load("".join(("scripts.trusted_time_post_enrollment_", '
                '"execution_admission")))\n'
                'CAPABILITY = vars(admission)["".join(("_head_reviewed_operator_", '
                '"authority_object"))]\n'
            )
        else:
            reflection_source = (
                "from scripts.trusted_time_post_enrollment_execution_admission import "
                "load_post_enrollment_operator_attested_execution_approval as loader\n"
                'CAPABILITY = loader.__globals__["".join(("_head_reviewed_operator_", '
                '"authority_object"))]\n'
            )
        path.write_text(reflection_source, encoding="utf-8")
    else:
        assert mutation in {"transitive_reexport", "configured_extra_consumer"}
        path = tmp_path / "scripts/unreviewed_process_reexport.py"
        if mutation == "transitive_reexport":
            path.write_text(
                "from scripts.verify_trusted_time_images import _run_bounded_process\n",
                encoding="utf-8",
            )
        else:
            path.write_text(f"from {module} import _run_bounded_process\n", encoding="utf-8")
            config.write_text(
                config_source + "native_bounded_process_allowed_imports."
                f'"{path.relative_to(tmp_path).as_posix()}" = ["{binding}"]\n'
                + "native_bounded_process_consumer_function_ast_sha256."
                f'"{path.relative_to(tmp_path).as_posix()}" = "{"0" * 64}"\n',
                encoding="utf-8",
            )

    config_source = config.read_text(encoding="utf-8")
    roots = tuple(tmp_path / value for value in ("apps", "packages", "scripts"))
    digest = _production_python_source_manifest_sha256(
        tmp_path,
        roots,
        (tmp_path / "apps/web/node_modules",),
    )
    config_source = re.sub(
        r'(?m)^production_python_source_manifest_sha256 = "[0-9a-f]{64}"$',
        f'production_python_source_manifest_sha256 = "{digest}"',
        config_source,
    )
    config.write_text(config_source, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("native bounded-process" in item.message for item in violations)


@pytest.mark.parametrize("shadow_module", ["argparse", "hashlib"])
def test_adr0111_isolated_checker_bootstrap_rejects_stdlib_shadow(
    tmp_path: Path,
    shadow_module: str,
) -> None:
    from scripts.check_architecture import _production_python_source_manifest_sha256

    config, _, _, initial_digest = _write_adr0111_production_manifest_fixture(tmp_path)
    checker = tmp_path / "scripts/check_architecture.py"
    checker.write_bytes((ROOT / "scripts/check_architecture.py").read_bytes())
    roots = tuple(tmp_path / value for value in ("apps", "packages", "scripts"))
    pruned = (tmp_path / "apps/web/node_modules",)
    checker_digest = _production_python_source_manifest_sha256(tmp_path, roots, pruned)
    config.write_text(
        config.read_text(encoding="utf-8").replace(initial_digest, checker_digest),
        encoding="utf-8",
    )
    (tmp_path / f"scripts/{shadow_module}.py").write_text(
        "import os\nos._exit(0)\n",
        encoding="utf-8",
    )
    environment = {**os.environ, "PYTHONPATH": os.fspath(tmp_path / "scripts")}

    unsafe = subprocess.run(
        [str(ROOT / ".venv/bin/python"), "scripts/check_architecture.py"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    isolated = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            "-I",
            "-B",
            "scripts/check_architecture.py",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert unsafe.returncode == 0
    assert unsafe.stdout == ""
    assert isolated.returncode == 1
    assert "production Python source manifest cannot be constructed" in isolated.stdout


@pytest.mark.parametrize(
    "mutation",
    [
        "omit_roots",
        "empty_roots",
        "extra_root",
        "omit_prune",
        "empty_prune",
        "extra_prune",
        "broaden_prune",
        "omit_digest",
        "empty_digest",
        "wrong_digest",
        "extra_manifest_key",
        "omit_low_module_pin",
    ],
)
def test_adr0111_architecture_checker_requires_exact_production_manifest_config(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    config, _, _, digest = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    source = config.read_text(encoding="utf-8")
    replacements = {
        "omit_roots": (
            'production_python_source_manifest_roots = ["apps", "packages", "scripts"]\n',
            "",
        ),
        "empty_roots": (
            'production_python_source_manifest_roots = ["apps", "packages", "scripts"]',
            "production_python_source_manifest_roots = []",
        ),
        "extra_root": (
            'production_python_source_manifest_roots = ["apps", "packages", "scripts"]',
            'production_python_source_manifest_roots = ["apps", "packages", "scripts", "tests"]',
        ),
        "omit_prune": (
            'production_python_source_manifest_pruned_subtrees = ["apps/web/node_modules"]\n',
            "",
        ),
        "empty_prune": (
            'production_python_source_manifest_pruned_subtrees = ["apps/web/node_modules"]',
            "production_python_source_manifest_pruned_subtrees = []",
        ),
        "extra_prune": (
            'production_python_source_manifest_pruned_subtrees = ["apps/web/node_modules"]',
            "production_python_source_manifest_pruned_subtrees = "
            '["apps/web/node_modules", "packages"]',
        ),
        "broaden_prune": (
            'production_python_source_manifest_pruned_subtrees = ["apps/web/node_modules"]',
            'production_python_source_manifest_pruned_subtrees = ["apps/web"]',
        ),
        "omit_digest": (
            f'production_python_source_manifest_sha256 = "{digest}"\n',
            "",
        ),
        "empty_digest": (
            f'production_python_source_manifest_sha256 = "{digest}"',
            'production_python_source_manifest_sha256 = ""',
        ),
        "wrong_digest": (
            f'production_python_source_manifest_sha256 = "{digest}"',
            f'production_python_source_manifest_sha256 = "{"0" * 64}"',
        ),
        "extra_manifest_key": (
            f'production_python_source_manifest_sha256 = "{digest}"',
            f'production_python_source_manifest_sha256 = "{digest}"\n'
            'production_python_source_manifest_excluded_roots = ["packages"]',
        ),
        "omit_low_module_pin": (
            "operation_bound_clean_stop_bridge_module = "
            '"packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"\n'
            "operation_bound_clean_stop_bridge_module_ast_sha256 = ",
            "operation_bound_clean_stop_bridge_module_ast_sha256 = ",
        ),
    }
    old, new = replacements[mutation]
    config.write_text(source.replace(old, new), encoding="utf-8")

    violations = check(tmp_path, config)

    expected = (
        "configure one exact root, dotted module, and semantic AST digest"
        if mutation == "omit_low_module_pin"
        else "production Python source manifest"
    )
    assert any(expected in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "content",
        "syntax",
        "add",
        "remove",
        "rename",
        "symlink_file",
        "broken_symlink",
        "symlink_directory",
        "symlink_root",
        "symlink_prune",
        "builtin_poison",
        "partial_module_poison",
        "frame_poison",
        "low_native_shadow",
        "host_native_shadow",
        "dependency_native_shadow",
        "native_dylib",
        "native_dll",
        "native_symlink",
        "native_broken_symlink",
        "legacy_pyc",
        "cache_source",
        "cache_native",
        "cache_symlink",
        "cache_nonregular_pyc",
        "cache_pyo",
        "low_cache_pyc_shadow",
        "host_cache_pyc_shadow",
        "dependency_cache_pyc_shadow",
    ],
)
def test_adr0111_architecture_checker_rejects_production_manifest_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    config, low_path, host_path, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    dependency = tmp_path / "packages/application/trusted_time_head_anchor.py"
    outside = tmp_path / "manifest-outside"
    outside.mkdir()
    if mutation == "content":
        low_path.write_text(
            low_path.read_text(encoding="utf-8") + "SAFE = True\n", encoding="utf-8"
        )
    elif mutation == "syntax":
        low_path.write_text(
            low_path.read_text(encoding="utf-8") + "def broken(\n", encoding="utf-8"
        )
    elif mutation == "add":
        (tmp_path / "packages/application/added.py").write_text(
            "SAFE = True\n",
            encoding="utf-8",
        )
    elif mutation == "remove":
        low_path.unlink()
    elif mutation == "rename":
        low_path.rename(low_path.with_name("renamed_bridge.py"))
    elif mutation == "symlink_file":
        target = outside / "hidden.py"
        target.write_text("SAFE = True\n", encoding="utf-8")
        (tmp_path / "packages/hidden.py").symlink_to(target)
    elif mutation == "broken_symlink":
        (tmp_path / "packages/broken.py").symlink_to(outside / "missing.py")
    elif mutation == "symlink_directory":
        target = outside / "hidden-package"
        target.mkdir()
        (target / "hidden.py").write_text("SAFE = True\n", encoding="utf-8")
        (tmp_path / "packages/hidden-package").symlink_to(target, target_is_directory=True)
    elif mutation == "symlink_root":
        apps = tmp_path / "apps"
        moved_apps = tmp_path / "apps-real"
        apps.rename(moved_apps)
        apps.symlink_to(moved_apps, target_is_directory=True)
    elif mutation == "symlink_prune":
        prune = tmp_path / "apps/web/node_modules"
        prune.rmdir()
        prune.symlink_to(outside, target_is_directory=True)
    elif mutation == "builtin_poison":
        dependency.write_text(
            "import builtins\nbuiltins.property = lambda function: property(lambda _: True)\n",
            encoding="utf-8",
        )
    elif mutation == "partial_module_poison":
        dependency.write_text(
            "import sys\n"
            'bridge = sys.modules["packages.application.'
            'trusted_time_head_anchor_clean_stop_supervisor_bridge"]\n'
            "bridge._EVIDENCE_PROPERTY = lambda function: function\n",
            encoding="utf-8",
        )
    elif mutation == "low_native_shadow":
        low_path.with_name(f"{low_path.stem}.cpython-312-darwin.so").write_bytes(b"native")
    elif mutation == "host_native_shadow":
        host_path.with_name(f"{host_path.stem}.pyd").write_bytes(b"native")
    elif mutation == "dependency_native_shadow":
        dependency.with_name(f"{dependency.stem}.abi3.so").write_bytes(b"native")
    elif mutation == "native_dylib":
        (tmp_path / "packages/native.dylib").write_bytes(b"native")
    elif mutation == "native_dll":
        (tmp_path / "scripts/native.dll").write_bytes(b"native")
    elif mutation in {"native_symlink", "native_broken_symlink"}:
        target = outside / "native-target"
        if mutation == "native_symlink":
            target.write_bytes(b"native")
        (tmp_path / "packages/native.so").symlink_to(target)
    elif mutation == "legacy_pyc":
        (tmp_path / "packages/legacy.pyc").write_bytes(b"bytecode")
    elif mutation in {
        "cache_source",
        "cache_native",
        "cache_symlink",
        "cache_nonregular_pyc",
        "cache_pyo",
        "low_cache_pyc_shadow",
        "host_cache_pyc_shadow",
        "dependency_cache_pyc_shadow",
    }:
        shadow_owners = {
            "low_cache_pyc_shadow": low_path,
            "host_cache_pyc_shadow": host_path,
            "dependency_cache_pyc_shadow": dependency,
        }
        owner = shadow_owners.get(mutation)
        cache = (owner.parent if owner is not None else tmp_path / "packages") / "__pycache__"
        cache.mkdir(exist_ok=True)
        if mutation == "cache_source":
            (cache / "shadow.py").write_text("SAFE = False\n", encoding="utf-8")
        elif mutation == "cache_native":
            (cache / "shadow.so").write_bytes(b"native")
        elif mutation == "cache_symlink":
            target = outside / "shadow.pyc"
            target.write_bytes(b"bytecode")
            (cache / "shadow.cpython-312.pyc").symlink_to(target)
        elif mutation == "cache_nonregular_pyc":
            os.mkfifo(cache / "shadow.cpython-312.pyc")
        elif mutation == "cache_pyo":
            (cache / "shadow.pyo").write_bytes(b"legacy-bytecode")
        else:
            assert owner is not None
            (cache / f"{owner.stem}.cpython-312.pyc").write_bytes(
                _unchecked_hash_pyc_bytes("VALUE = 'pwned'\n", os.fspath(owner))
            )
    else:
        dependency.write_text(
            "import sys\n"
            "frame = sys._getframe()\n"
            "while frame.f_back is not None:\n"
            "    frame = frame.f_back\n"
            'frame.f_globals["_EVIDENCE_PROPERTY"] = lambda function: function\n',
            encoding="utf-8",
        )

    violations = check(tmp_path, config)

    assert any("production Python source manifest" in item.message for item in violations)


def test_adr0111_production_manifest_prunes_only_exact_vendor_subtree(tmp_path: Path) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    vendor = tmp_path / "apps/web/node_modules"
    target = tmp_path / "vendor-package"
    target.mkdir()
    (target / "third_party.py").write_text("BROKEN = (\n", encoding="utf-8")
    (vendor / "package").symlink_to(target, target_is_directory=True)

    assert check(tmp_path, config) == []


def test_adr0111_production_manifest_allows_absent_vendor_subtree(tmp_path: Path) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    (tmp_path / "apps/web/node_modules").rmdir()

    assert check(tmp_path, config) == []


def test_adr0111_production_manifest_rejects_transient_cache_bytecode(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import check

    config, _, _, _ = _write_adr0111_production_manifest_fixture(tmp_path)
    assert check(tmp_path, config) == []
    cache = tmp_path / "packages/__pycache__"
    cache.mkdir()
    (cache / "module.cpython-312.pyc").write_bytes(b"transient-bytecode")

    violations = check(tmp_path, config)

    assert any("production Python source manifest" in item.message for item in violations)


def test_adr0111_production_manifest_digest_is_python_312_313_stable() -> None:
    script = (
        "from pathlib import Path; import runpy; "
        "helper=runpy.run_path('scripts/check_architecture.py')"
        "['_production_python_source_manifest_sha256']; "
        "root=Path('.').resolve(); "
        "print(helper("
        "root, tuple(root / value for value in ('apps','packages','scripts')), "
        "(root / 'apps/web/node_modules',)))"
    )
    interpreters = (ROOT / ".venv/bin/python", Path("/usr/bin/env"))
    commands = (
        [str(interpreters[0]), "-I", "-B", "-c", script],
        [str(interpreters[1]), "python3", "-I", "-B", "-c", script],
    )
    observed = {
        subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for command in commands
    }
    configured = tomllib.loads(
        (ROOT / "infra/architecture-boundaries.toml").read_text(encoding="utf-8")
    )["scan"]["production_python_source_manifest_sha256"]

    assert observed == {configured}


@pytest.mark.parametrize(
    "mutation",
    [
        "request_dynamic_true",
        "request_closed_overwrite",
        "validator_inert",
        "validator_decoy",
    ],
)
def test_adr0111_architecture_checker_rejects_request_or_closed_validator_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import _canonical_ast_sha256, check

    relative_path = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    baseline = (
        '_CLOSED_FIELDS = frozenset({"effect_authorized", "transport_authenticated"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "def _require_closed(payload):\n"
        "    if any(payload.get(name) is not False for name in _CLOSED_FIELDS):\n"
        "        raise ValueError\n"
        "class Request:\n"
        "    def payload(self):\n"
        "        payload = _closed_payload()\n"
        "        return payload\n"
        "def decode(payload):\n"
        "    _require_closed(payload)\n"
        "__all__ = []\n"
    )
    tree = ast.parse(baseline)
    request_class = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Request"
    )
    request_payload = next(
        node
        for node in request_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "payload"
    )
    require_closed = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_require_closed"
    )
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_roots = ["{relative_path.as_posix()}"]
operation_bound_clean_stop_bridge_closed_fields = [
  "effect_authorized", "transport_authenticated",
]
operation_bound_clean_stop_bridge_protected_function_bindings = [
  "_closed_payload", "_require_closed",
]
operation_bound_clean_stop_bridge_protected_closed_field_loads = [
  "comprehension:_closed_payload", "comprehension:_require_closed",
]
[scan.operation_bound_clean_stop_bridge_protected_function_callsites]
_closed_payload = ["Request.payload"]
_require_closed = ["decode"]
[scan.operation_bound_clean_stop_bridge_payload_callable_ast_sha256]
"Request.payload" = "{_canonical_ast_sha256(request_payload)}"
_require_closed = "{_canonical_ast_sha256(require_closed)}"
[scan.operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256]
Request = "{_canonical_ast_sha256(request_class)}"
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []

    if mutation == "request_dynamic_true":
        mutated = baseline.replace(
            "        return payload\n",
            '        payload["effect_authorized"] = bool(1)\n        return payload\n',
        )
    elif mutation == "request_closed_overwrite":
        mutated = baseline.replace(
            "        return payload\n",
            '        payload["transport_authenticated"] = True\n        return payload\n',
        )
    elif mutation == "validator_inert":
        mutated = baseline.replace(
            "if any(payload.get(name) is not False for name in _CLOSED_FIELDS):",
            "if any(False for name in _CLOSED_FIELDS):",
        )
    else:
        mutated = baseline.replace(
            "    if any(payload.get(name) is not False for name in _CLOSED_FIELDS):\n"
            "        raise ValueError\n",
            "    decoy = any(\n"
            "        payload.get(name) is not False for name in _CLOSED_FIELDS\n"
            "    )\n"
            "    return None\n",
        )
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("exact payload-builder AST" in item.message for item in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "assignment",
        "annassign",
        "tuple",
        "walrus",
        "comprehension",
        "import_alias",
        "global_rebind",
        "container_alias",
        "subclass_rebind",
        "payload_assignment",
        "payload_setattr",
        "payload_type_setattr",
        "property_override",
        "method_override",
        "tuple_override",
        "walrus_override",
        "import_override",
        "extra_base",
        "drop_base",
        "custom_getattr",
        "constructor_derived_dynamic_mutation",
        "constructor_derived_type_setattr",
        "constructor_derived_dynamic_type_setattr",
    ],
)
def test_adr0111_architecture_checker_rejects_pinned_request_owner_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import _canonical_ast_sha256, check

    relative_path = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    baseline = (
        '_CLOSED_FIELDS = frozenset({"authority_granted"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        "class ClosedEvidence:\n"
        "    pass\n"
        "@dataclass(frozen=True, slots=True, init=False, eq=False)\n"
        "class Request(ClosedEvidence):\n"
        "    @property\n"
        "    def authority_granted(self):\n"
        "        return False\n"
        "    def payload(self):\n"
        "        return _closed_payload()\n"
        "__all__ = []\n"
    )
    tree = ast.parse(baseline)
    request_class = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Request"
    )
    request_payload = next(
        node
        for node in request_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "payload"
    )
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_roots = ["{relative_path.as_posix()}"]
operation_bound_clean_stop_bridge_closed_fields = ["authority_granted"]
[scan.operation_bound_clean_stop_bridge_payload_callable_ast_sha256]
"Request.payload" = "{_canonical_ast_sha256(request_payload)}"
[scan.operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256]
Request = "{_canonical_ast_sha256(request_class)}"
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []

    mutations = {
        "assignment": "Request = object",
        "annassign": "Request: object = object",
        "tuple": "Request, other = object, None",
        "walrus": "(Request := object)",
        "comprehension": "[None for Request in ()]",
        "import_alias": "import builtins as Request",
        "global_rebind": ("def rebind():\n    global Request\n    Request = object\n"),
        "container_alias": "aliases = [Request]",
        "subclass_rebind": (
            "OriginalRequest = Request\n"
            "class ForgedRequest(OriginalRequest):\n"
            "    @property\n"
            "    def authority_granted(self):\n"
            "        return True\n"
            "    def payload(self):\n"
            "        payload = super().payload()\n"
            '        payload["authority_granted"] = True\n'
            "        return payload\n"
            "Request = ForgedRequest\n"
        ),
        "payload_assignment": "Request.payload = lambda self: {}",
        "payload_setattr": 'setattr(Request, "payload", lambda self: {})',
        "payload_type_setattr": ('type.__setattr__(Request, "payload", lambda self: {})'),
        "constructor_derived_dynamic_mutation": (
            'Alias = type(Request())\nsetattr(Alias, "authority_" + "granted", True)'
        ),
        "constructor_derived_type_setattr": (
            "type(type(Request())).__setattr__(\n"
            "    type(Request()),\n"
            '    "authority_" + "granted",\n'
            "    property(lambda _: True),\n"
            ")"
        ),
        "constructor_derived_dynamic_type_setattr": (
            'getattr(type(type(Request())), "__set" + "attr__")(\n'
            "    type(Request()),\n"
            '    "authority_" + "granted",\n'
            "    property(lambda _: True),\n"
            ")"
        ),
    }
    class_insertion = {
        "property_override": "    authority_granted = property(lambda _: True)\n",
        "method_override": ("    def authority_granted(self):\n        return True\n"),
        "tuple_override": "    authority_granted, other = True, None\n",
        "walrus_override": "    (authority_granted := True)\n",
        "import_override": "    import builtins as authority_granted\n",
        "custom_getattr": ("    def __getattr__(self, name):\n        return True\n"),
    }
    if mutation in class_insertion:
        mutated = baseline.replace(
            "    @property\n    def authority_granted(self):\n",
            f"{class_insertion[mutation]}    @property\n    def authority_granted(self):\n",
        )
    elif mutation == "extra_base":
        request_with_extra_base = baseline.replace(
            "class Request(ClosedEvidence):",
            "class Request(ClosedEvidence, ExtraBase):",
        )
        mutated = f"class ExtraBase:\n    pass\n{request_with_extra_base}"
    elif mutation == "drop_base":
        mutated = baseline.replace("class Request(ClosedEvidence):", "class Request:")
    else:
        mutated = f"{baseline}\n{mutations[mutation]}\n"
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert any(
        "sole-bound AST-pinned callable owner classes" in item.message
        or "exact evidence-class AST" in item.message
        for item in violations
    )


@pytest.mark.parametrize("owner", ["low", "host"])
@pytest.mark.parametrize(
    "mutation",
    ["dynamic_true", "expected_overwrite", "decoy_alternate_return", "alias_mutation"],
)
def test_adr0111_architecture_checker_rejects_payload_dataflow_mutation(
    tmp_path: Path,
    owner: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import _canonical_ast_sha256, check

    if owner == "low":
        relative_path = Path(
            "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
        )
        callable_name = "Result.payload"
        body = (
            "class Result:\n"
            "    def payload(self):\n"
            "        payload = _closed_payload()\n"
            '        payload.update({"only_fact": True})\n'
            "        return payload\n"
        )
        root_key = "operation_bound_clean_stop_bridge_roots"
        closed_key = "operation_bound_clean_stop_bridge_closed_fields"
        true_key = "operation_bound_clean_stop_bridge_true_payload_facts"
        digest_key = "operation_bound_clean_stop_bridge_payload_callable_ast_sha256"
        indent = "        "
    else:
        relative_path = Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
        )
        callable_name = "_composite_payload"
        body = (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
            "def _composite_payload():\n"
            "    payload = _closed_payload()\n"
            '    payload.update({"only_fact": True})\n'
            "    return payload\n"
        )
        root_key = "graceful_stop_supervisor_bridge_roots"
        closed_key = "graceful_stop_supervisor_bridge_closed_fields"
        true_key = "graceful_stop_supervisor_bridge_true_payload_facts"
        digest_key = "graceful_stop_supervisor_bridge_payload_callable_ast_sha256"
        indent = "    "
    baseline = (
        '_CLOSED_FIELDS = frozenset({"effect_authorized"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        f"{body}"
        "__all__ = []\n"
    )
    tree = ast.parse(baseline)
    candidates: tuple[ast.AST, ...] = tuple(tree.body)
    owner_class_config = ""
    if "." in callable_name:
        class_name, _, method_name = callable_name.partition(".")
        owner_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        candidates = tuple(owner_class.body)
        owner_class_config = (
            "[scan.operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256]\n"
            f'{class_name} = "{_canonical_ast_sha256(owner_class)}"\n'
        )
    else:
        method_name = callable_name
    function = next(
        node
        for node in candidates
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name
    )
    digest = _canonical_ast_sha256(function)
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
{root_key} = ["{relative_path.as_posix()}"]
{closed_key} = ["effect_authorized"]
[scan.{true_key}]
"{callable_name}" = ["only_fact"]
[scan.{digest_key}]
"{callable_name}" = "{digest}"
{owner_class_config}
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []

    return_line = f"{indent}return payload"
    if mutation == "dynamic_true":
        replacement = f'{indent}payload["effect_authorized"] = bool(1)\n{return_line}'
    elif mutation == "expected_overwrite":
        replacement = f'{indent}payload["only_fact"] = False\n{return_line}'
    elif mutation == "decoy_alternate_return":
        replacement = f'{indent}decoy = payload\n{indent}return {{"only_fact": False}}'
    else:
        replacement = (
            f'{indent}alias = payload\n{indent}alias["effect_authorized"] = bool(1)\n{return_line}'
        )
    module_path.write_text(baseline.replace(return_line, replacement), encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("exact payload-builder AST" in item.message for item in violations)


@pytest.mark.parametrize("owner", ["low", "host"])
@pytest.mark.parametrize(
    "mutation",
    [
        'CONTRACT_VERSION: str = "changed"',
        '_CLOSED_FIELDS |= frozenset({"effect_authorized"})',
        "(__all__ := [])",
        "__all__, other = [], None",
        '__all__.append("_private")',
        "exported = __all__\nexported.append('_private')",
        'globals()["__all__"].append("_private")',
        'getattr(__all__, "append")("_private")',
        'list.append(__all__, "_private")',
        '[(__all__ := ["_private"]) for _ in [0]]',
        'globals().update(__all__=["_private"])',
        'locals().update({"__all__": ["_private"]})',
        'exports, = (__all__,)\nexports.append("_private")',
        'holder = [__all__]\nholder[0].append("_private")',
        '_closed_payload = lambda: {"closed": True}',
    ],
)
def test_adr0111_architecture_checker_rejects_protected_binding_mutation(
    tmp_path: Path,
    owner: str,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    if owner == "low":
        relative_path = Path(
            "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
        )
        root_key = "operation_bound_clean_stop_bridge_roots"
        closed_key = "operation_bound_clean_stop_bridge_closed_fields"
        constant_key = "operation_bound_clean_stop_bridge_literal_constants"
        function_key = "operation_bound_clean_stop_bridge_protected_function_bindings"
        function_callsites_key = "operation_bound_clean_stop_bridge_protected_function_callsites"
        extra = ""
    else:
        relative_path = Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
        )
        root_key = "graceful_stop_supervisor_bridge_roots"
        closed_key = "graceful_stop_supervisor_bridge_closed_fields"
        constant_key = "graceful_stop_supervisor_bridge_literal_constants"
        function_key = "graceful_stop_supervisor_bridge_protected_function_bindings"
        function_callsites_key = "graceful_stop_supervisor_bridge_protected_function_callsites"
        extra = (
            "def _utc_text(value):\n"
            '    return value.astimezone(UTC).isoformat(timespec="microseconds").replace('
            '"+00:00", "Z")\n'
        )
    baseline = (
        'CONTRACT_VERSION = "v1"\n'
        '_CLOSED_FIELDS = frozenset({"closed"})\n'
        "def _closed_payload():\n"
        "    return {name: False for name in _CLOSED_FIELDS}\n"
        f"{extra}"
        "__all__ = []\n"
    )
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    module_path.write_text(baseline, encoding="utf-8")
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(
        f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
{root_key} = ["{relative_path.as_posix()}"]
{closed_key} = ["closed"]
{constant_key}.CONTRACT_VERSION = "v1"
{function_key} = ["_closed_payload"]
{function_callsites_key}._closed_payload = []
''',
        encoding="utf-8",
    )
    assert check(tmp_path, config) == []
    module_path.write_text(f"{baseline}\n{mutation}\n", encoding="utf-8")

    violations = check(tmp_path, config)

    assert any("exact protected module bindings" in item.message for item in violations)


@pytest.mark.parametrize("mutation", ["unreviewed", "extra", "missing"])
def test_adr0111_architecture_checker_rejects_importer_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import check

    module = "packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"
    if mutation == "unreviewed":
        relative_path = Path("apps/unreviewed.py")
        baseline = "VALUE = 1\n"
        mutated = f"from {module} import TrustedTimeHeadAnchorOperationBoundCleanStopRequest\n"
        config_source = f'''[scan]
source_roots = ["apps"]
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_module = "{module}"
operation_bound_clean_stop_bridge_public_symbols = [
  "TrustedTimeHeadAnchorOperationBoundCleanStopRequest",
]
'''
    else:
        relative_path = Path("packages/application/reviewed.py")
        expected = f"{module}:TrustedTimeHeadAnchorOperationBoundCleanStopRequest"
        baseline = f"from {module} import TrustedTimeHeadAnchorOperationBoundCleanStopRequest\n"
        mutated = (
            f"from {module} import (\n"
            "    TrustedTimeHeadAnchorOperationBoundCleanStopRequest,\n"
            "    TrustedTimeHeadAnchorOperationBoundCleanStopResult,\n"
            ")\n"
            if mutation == "extra"
            else "VALUE = 1\n"
        )
        config_source = f'''[scan]
source_roots = []
{_MINIMAL_ARCHITECTURE_SCAN_PRELUDE}
operation_bound_clean_stop_bridge_module = "{module}"
operation_bound_clean_stop_bridge_allowed_imports."{relative_path.as_posix()}" = [
  "{expected}",
]
'''
    module_path = tmp_path / relative_path
    module_path.parent.mkdir(parents=True)
    config = tmp_path / "architecture-boundaries.toml"
    config.write_text(config_source, encoding="utf-8")
    module_path.write_text(baseline, encoding="utf-8")
    assert check(tmp_path, config) == []
    module_path.write_text(mutated, encoding="utf-8")

    violations = check(tmp_path, config)

    assert violations
    assert any(
        "unconnected module" in item.message
        or "reviewed binding" in item.message
        or "reviewed seam" in item.message
        for item in violations
    )


def test_adr0111_operation_bound_supervisor_bridge_is_exact_dormant_and_unconnected() -> None:
    from scripts.check_architecture import (
        _canonical_ast_sha256,
        _production_python_source_manifest_sha256,
        _project_build_bootstrap_manifest_sha256,
    )

    low_relative_path = Path(
        "packages/application/trusted_time_head_anchor_clean_stop_supervisor_bridge.py"
    )
    worker_relative_path = Path("packages/application/trusted_time_head_anchor_worker.py")
    host_relative_path = Path(
        "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
    )
    decision_artifact_relative_path = Path(
        "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
    )
    low_module = "packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge"
    host_module = "scripts.trusted_time_post_enrollment_graceful_stop_supervisor_bridge"
    decision_artifact_module = (
        "scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts"
    )
    lifecycle_module = "scripts.trusted_time_post_enrollment_graceful_stop_lifecycle"
    architecture_config = tomllib.loads(
        (ROOT / "infra/architecture-boundaries.toml").read_text(encoding="utf-8")
    )["scan"]

    assert architecture_config["production_python_source_manifest_roots"] == [
        "apps",
        "packages",
        "scripts",
    ]
    assert architecture_config["production_python_source_manifest_pruned_subtrees"] == [
        "apps/web/node_modules"
    ]
    assert architecture_config["production_python_source_manifest_sha256"] == (
        "b44e1d6197cba2ca3f8f3dd4098fe891259900d85b851c98b3acccab6ded5e80"
    )
    assert (
        _production_python_source_manifest_sha256(
            ROOT,
            tuple(ROOT / value for value in ("apps", "packages", "scripts")),
            (ROOT / "apps/web/node_modules",),
        )
        == architecture_config["production_python_source_manifest_sha256"]
    )
    tracked_vendor_python = subprocess.run(
        [
            "git",
            "ls-files",
            "apps/web/node_modules/*.py",
            "apps/web/node_modules/**/*.py",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked_vendor_python == []
    tracked_production_paths = subprocess.run(
        ["git", "ls-files", "--", "apps", "packages", "scripts"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert not any(
        path.lower().endswith((".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll"))
        or ".so." in path.lower()
        or ".dylib." in path.lower()
        for path in tracked_production_paths
    )
    assert "__pycache__/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore_lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "**/__pycache__" in dockerignore_lines
    assert "**/*.pyc" in dockerignore_lines
    expected_bootstrap_paths = [
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
    ]
    assert architecture_config["project_build_bootstrap_manifest_paths"] == (
        expected_bootstrap_paths
    )
    assert architecture_config["project_build_bootstrap_forbidden_paths"] == [
        "MANIFEST.in",
        "hatch.toml",
        "setup.cfg",
        "setup.py",
        "uv.toml",
    ]
    assert (
        _project_build_bootstrap_manifest_sha256(
            ROOT,
            tuple(expected_bootstrap_paths),
        )
        == architecture_config["project_build_bootstrap_manifest_sha256"]
    )
    expected_invocation_source_sha256 = {
        "Makefile": "189b041060855fbb6218fdc9d8425c25f534d1885d1207725b8022a84e7de758",
        ".github/workflows/ci.yml": (
            "8da27296e12d3e7a8bed8559ca0e849e919ec5dee4423b824c98c5fbf68a05a5"
        ),
    }
    assert architecture_config["architecture_checker_invocation_source_sha256"] == (
        expected_invocation_source_sha256
    )
    assert {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in expected_invocation_source_sha256
    } == expected_invocation_source_sha256
    assert architecture_config["builtin_namespace_integrity_roots"] == [
        "apps",
        "packages",
        "scripts",
    ]
    assert architecture_config["builtin_namespace_integrity_excluded_roots"] == [
        "scripts/check_architecture.py"
    ]
    assert architecture_config["builtin_namespace_integrity_allowed_imports"] == {
        "packages/adapters/market_data/recorded.py": ["builtins:*"],
        low_relative_path.as_posix(): ["builtins:*", "builtins:property"],
        host_relative_path.as_posix(): ["builtins:*", "builtins:property"],
    }
    assert architecture_config["builtin_namespace_integrity_allowed_reads"] == {
        "packages/adapters/market_data/recorded.py": ["builtins.bytes@annotation"],
        low_relative_path.as_posix(): ["builtins.property@identity"],
        host_relative_path.as_posix(): ["builtins.property@identity"],
    }
    expected_sys_modules_callsites = {
        relative_path: ["_require_repository_first_party_sources"]
        for relative_path in (
            "scripts/diagnose_trusted_time_runtime.py",
            "scripts/enroll_trusted_time_head_anchor.py",
            "scripts/inspect_trusted_time_qualification.py",
            "scripts/provision_trusted_time_post_enrollment_operator_authority.py",
            "scripts/start_trusted_time_supervisor.py",
            "scripts/trusted_time_post_enrollment_host_orchestrator.py",
            "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py",
            "scripts/verify_trusted_time_compose.py",
            "scripts/verify_trusted_time_images.py",
        )
    }
    expected_sys_modules_callsites["packages/adapters/trusted_time/_owned_file_descriptor.py"] = [
        "<module>:contains-private-native",
        "<module>:contains-private-native",
    ]
    expected_sys_modules_callsites["packages/adapters/trusted_time/_bounded_process.py"] = [
        "<module>:contains-private-native",
        "<module>:contains-private-native",
    ]
    expected_sys_modules_callsites[
        "packages/domain/_trusted_time_post_enrollment_projection_bootstrap.py"
    ] = ["_build_start_projection_bootstrap:capture-private-module-map"]
    expected_sys_modules_callsites["scripts/trusted_time_post_enrollment_topology_reader.py"] = [
        "_build_observation_sealer:capture-private-module-map"
    ]
    assert architecture_config["builtin_namespace_integrity_sys_modules_callsites"] == (
        expected_sys_modules_callsites
    )
    native_wrapper_relative = Path("packages/adapters/trusted_time/_owned_file_descriptor.py")
    native_wrapper_module = "packages.adapters.trusted_time._owned_file_descriptor"
    native_wrapper_tree = ast.parse(
        (ROOT / native_wrapper_relative).read_text(encoding="utf-8"),
        filename=native_wrapper_relative.as_posix(),
    )
    assert architecture_config["native_owned_file_descriptor_wrapper_roots"] == [
        native_wrapper_relative.as_posix()
    ]
    assert architecture_config["native_owned_file_descriptor_wrapper_module"] == (
        native_wrapper_module
    )
    assert architecture_config["native_owned_file_descriptor_wrapper_module_ast_sha256"] == (
        _canonical_ast_sha256(native_wrapper_tree)
    )
    native_wrapper_all = [
        node
        for node in native_wrapper_tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "__all__"
    ]
    assert len(native_wrapper_all) == 1
    assert ast.literal_eval(native_wrapper_all[0].value) == ()
    bounded_wrapper_relative = Path("packages/adapters/trusted_time/_bounded_process.py")
    bounded_wrapper_module = "packages.adapters.trusted_time._bounded_process"
    bounded_wrapper_tree = ast.parse(
        (ROOT / bounded_wrapper_relative).read_text(encoding="utf-8"),
        filename=bounded_wrapper_relative.as_posix(),
    )
    assert architecture_config["native_bounded_process_wrapper_roots"] == [
        bounded_wrapper_relative.as_posix()
    ]
    assert architecture_config["native_bounded_process_wrapper_module"] == (bounded_wrapper_module)
    assert architecture_config["native_bounded_process_wrapper_module_ast_sha256"] == (
        _canonical_ast_sha256(bounded_wrapper_tree)
    )
    bounded_wrapper_all = [
        node
        for node in bounded_wrapper_tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "__all__"
    ]
    assert len(bounded_wrapper_all) == 1
    assert ast.literal_eval(bounded_wrapper_all[0].value) == ()
    assert architecture_config["native_bounded_process_allowed_imports"] == {
        "scripts/verify_trusted_time_images.py": [f"{bounded_wrapper_module}:_run_bounded_process"]
    }
    verifier_tree = ast.parse(
        (ROOT / "scripts/verify_trusted_time_images.py").read_text(encoding="utf-8")
    )
    verifier_process_readers = [
        node
        for node in verifier_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_head_reviewed_operator_authority_object"
    ]
    assert len(verifier_process_readers) == 1
    assert architecture_config["native_bounded_process_consumer_function_ast_sha256"] == {
        "scripts/verify_trusted_time_images.py": _canonical_ast_sha256(verifier_process_readers[0])
    }
    assert architecture_config["native_bounded_process_consumer_module_ast_sha256"] == {
        "scripts/verify_trusted_time_images.py": _canonical_ast_sha256(verifier_tree)
    }
    assert architecture_config["native_bounded_process_reader_allowed_imports"] == {
        "scripts/trusted_time_post_enrollment_execution_admission.py": [
            "scripts.verify_trusted_time_images:_head_reviewed_operator_authority_object"
        ]
    }
    execution_admission_tree = ast.parse(
        (ROOT / "scripts/trusted_time_post_enrollment_execution_admission.py").read_text(
            encoding="utf-8"
        )
    )
    assert architecture_config["native_bounded_process_reader_consumer_module_ast_sha256"] == {
        "scripts/trusted_time_post_enrollment_execution_admission.py": _canonical_ast_sha256(
            execution_admission_tree
        )
    }
    expected_native_imports = {
        "apps/trusted_time_supervisor/post_enrollment_read_probes.py": {
            "_OwnedFileDescriptor",
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        },
        "apps/trusted_time_supervisor/post_enrollment_runtime_state.py": {
            "_OwnedFileDescriptor",
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        },
        "scripts/trusted_time_post_enrollment_controller_outcome.py": {
            "_OwnedFileDescriptor",
            "_flock",
            "_fstat",
            "_list_snapshot",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        },
        "scripts/trusted_time_post_enrollment_execution_admission.py": {
            "_OwnedFileDescriptor",
            "_flock",
            "_fstat",
            "_fsync",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        },
        "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py": {
            "_fstat",
            "_open_child_directory",
            "_open_root_directory",
        },
        "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py": {
            "_OwnedFileDescriptor",
            "_create_child_regular_exclusive",
            "_fchmod_0600",
            "_flock",
            "_fstat",
            "_fsync",
            "_ftruncate",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
            "_write_all",
        },
        "scripts/verify_trusted_time_images.py": {
            "_OwnedFileDescriptor",
            "_fstat",
            "_list_snapshot",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        },
    }
    assert architecture_config["native_owned_file_descriptor_allowed_imports"] == {
        path: sorted(f"{native_wrapper_module}:{binding}" for binding in bindings)
        for path, bindings in expected_native_imports.items()
    }
    expected_native_capture_parameters = {
        "apps/trusted_time_supervisor/post_enrollment_read_probes.py": {
            "_require_absences": {"_fstat_exact", "_statat_exact"},
            "_read_marker": {
                "_fstat_exact",
                "_statat_exact",
                "_open_regular_exact",
                "_read_snapshot_exact",
            },
            "_require_open_tmp_context": {"_fstat_exact", "_statat_exact"},
            "_staged_barrier_bytes": {
                "_open_root",
                "_open_directory",
                "_fstat_exact",
                "_statat_exact",
            },
            "_pre_effect_runtime_absence_bytes": {
                "_open_root",
                "_open_directory",
                "_fstat_exact",
                "_statat_exact",
            },
            "_persistent_barrier_bytes": {
                "_open_root",
                "_open_directory",
                "_fstat_exact",
                "_statat_exact",
            },
        },
        "apps/trusted_time_supervisor/post_enrollment_runtime_state.py": {
            "_read_regular_snapshot": {
                "_fstat_exact",
                "_statat_exact",
                "_open_regular_exact",
                "_read_snapshot_exact",
            },
            "_require_absences": {"_fstat_exact", "_statat_exact"},
            "_require_tmp_context": {"_fstat_exact", "_statat_exact"},
            "_read_tmp_snapshot": {
                "_open_root",
                "_open_directory",
                "_fstat_exact",
                "_statat_exact",
            },
            "_read_boot_id_snapshot": {
                "_open_root",
                "_open_directory",
                "_fstat_exact",
                "_statat_exact",
            },
        },
    }
    captured_defaults = architecture_config["native_owned_file_descriptor_captured_defaults"]
    assert {
        path: {function: set(parameters) for function, parameters in functions.items()}
        for path, functions in captured_defaults.items()
    } == expected_native_capture_parameters
    for path, expected_functions in expected_native_capture_parameters.items():
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        for function_name, parameters in expected_functions.items():
            function = functions[function_name]
            defaults = {
                argument.arg: default
                for argument, default in zip(
                    function.args.kwonlyargs,
                    function.args.kw_defaults,
                    strict=True,
                )
            }
            for parameter in parameters:
                default = defaults[parameter]
                assert isinstance(default, ast.Name)
                assert captured_defaults[path][function_name][parameter] == (
                    f"{native_wrapper_module}:{default.id}"
                )
    assert architecture_config[
        "native_owned_file_descriptor_captured_consumer_module_ast_sha256"
    ] == {
        path: _canonical_ast_sha256(
            ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
        )
        for path in expected_native_capture_parameters
    }
    expected_owner_consumer_functions = {
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
    owner_consumer_digests = architecture_config[
        "native_owned_file_descriptor_owner_consumer_function_ast_sha256"
    ]
    assert {
        capture_path: set(functions) for capture_path, functions in owner_consumer_digests.items()
    } == expected_owner_consumer_functions
    for capture_path, expected_functions in expected_owner_consumer_functions.items():
        tree = ast.parse(
            (ROOT / capture_path).read_text(encoding="utf-8"),
            filename=capture_path,
        )
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert owner_consumer_digests[capture_path] == {
            function_name: _canonical_ast_sha256(functions[function_name])
            for function_name in expected_functions
        }

    low_tree = ast.parse(
        (ROOT / low_relative_path).read_text(encoding="utf-8"),
        filename=str(low_relative_path),
    )
    worker_tree = ast.parse(
        (ROOT / worker_relative_path).read_text(encoding="utf-8"),
        filename=str(worker_relative_path),
    )
    host_tree = ast.parse(
        (ROOT / host_relative_path).read_text(encoding="utf-8"),
        filename=str(host_relative_path),
    )

    def require_evidence_before_project_imports(
        tree: ast.Module,
        class_names: frozenset[str],
    ) -> None:
        project_import_lines = [
            node.lineno
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.partition(".")[0] in {"apps", "packages", "scripts"}
        ]
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name in class_names
        ]
        assert {node.name for node in classes} == class_names
        assert project_import_lines
        assert max(cast(int, node.end_lineno) for node in classes) < min(project_import_lines)

    require_evidence_before_project_imports(
        low_tree,
        frozenset(
            {
                "_ClosedBridgeEvidence",
                "TrustedTimeHeadAnchorOperationBoundCleanStopRequest",
                "TrustedTimeHeadAnchorOperationBoundCleanStopResult",
            }
        ),
    )
    require_evidence_before_project_imports(
        host_tree,
        frozenset(
            {
                "_ClosedHostBridgeEvidence",
                "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation",
            }
        ),
    )

    def literal_all(tree: ast.Module) -> tuple[str, ...]:
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
        ]
        assert len(assignments) == 1
        return tuple(ast.literal_eval(assignments[0].value))

    def private_callsites(tree: ast.Module, binding: str) -> list[str]:
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        callsites: list[str] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == binding
            ):
                continue
            current: ast.AST = node
            while current in parents:
                current = parents[current]
                if not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                owner = parents.get(current)
                callsites.append(
                    f"{owner.name}.{current.name}"
                    if isinstance(owner, ast.ClassDef)
                    else current.name
                )
                break
            else:
                callsites.append("<module>")
        return sorted(callsites)

    assert architecture_config["operation_bound_clean_stop_bridge_roots"] == [
        low_relative_path.as_posix()
    ]
    assert architecture_config["operation_bound_clean_stop_bridge_module"] == low_module
    assert architecture_config["operation_bound_clean_stop_bridge_module_ast_sha256"] == (
        "203f68a0bb1a0e4441455c1ca4bc0ebbbf5847650b8d7ba35587f8f811b2eb38"
    )
    assert (
        _canonical_ast_sha256(low_tree)
        == architecture_config["operation_bound_clean_stop_bridge_module_ast_sha256"]
    )
    assert literal_all(low_tree) == tuple(
        architecture_config["operation_bound_clean_stop_bridge_public_symbols"]
    )
    assert literal_all(host_tree) == tuple(
        architecture_config["graceful_stop_supervisor_bridge_public_symbols"]
    )
    assert architecture_config["graceful_stop_supervisor_bridge_roots"] == [
        host_relative_path.as_posix()
    ]
    assert architecture_config["graceful_stop_supervisor_bridge_module"] == host_module
    assert architecture_config["graceful_stop_supervisor_bridge_module_ast_sha256"] == (
        "b3c35a7086eb2de22a7ea8dec929c179f59660901de53a00fdfb5f0fddfaa14d"
    )
    assert (
        _canonical_ast_sha256(host_tree)
        == architecture_config["graceful_stop_supervisor_bridge_module_ast_sha256"]
    )
    assert architecture_config["operation_bound_clean_stop_bridge_true_payload_facts"] == {
        "TrustedTimeHeadAnchorOperationBoundCleanStopResult.payload": [
            "exact_request_work_result_correlated"
        ]
    }
    assert architecture_config["operation_bound_clean_stop_bridge_payload_callable_ast_sha256"] == {
        "TrustedTimeHeadAnchorOperationBoundCleanStopRequest.payload": (
            "e0ac801370c35ab94e297bf7cb0fbe3702f3cfc322c0d74664349de856284d9c"
        ),
        "TrustedTimeHeadAnchorOperationBoundCleanStopResult.payload": (
            "3e24cdc2e0a27fa6e3d9dcb1a75eacab910a3731b0f300d496ec32693f958a5c"
        ),
        "_closed_payload": "b19d97b327484a1e7e243247cae22f8ec8a03702f8667f5757a2605f09c3d060",
        "_require_closed": "d23f341752021dcb885111c63d4e1f031a970db4755143935519437b194a9acd",
    }
    assert architecture_config[
        "operation_bound_clean_stop_bridge_payload_owner_class_ast_sha256"
    ] == {
        "TrustedTimeHeadAnchorOperationBoundCleanStopRequest": (
            "c82bfc6c5fc359e3303ac423318e0a6b6e4912de457147b8d7186776b1697a6f"
        ),
        "TrustedTimeHeadAnchorOperationBoundCleanStopResult": (
            "0f719871fdd1b8f79a5dfed281bd1d586a99cfca9492fce90a4798795a9244bd"
        ),
    }
    assert architecture_config["graceful_stop_supervisor_bridge_true_payload_facts"] == {
        "_composite_payload": [
            "decision_artifact_receipt_authenticated",
            "exact_terminal_projection_cross_bound_unqualified",
            "historical_start_chain_authenticated",
            "provider_terminal_observed_under_stable_sql_authenticated",
        ]
    }
    assert architecture_config["graceful_stop_supervisor_bridge_payload_callable_ast_sha256"] == {
        "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation.payload": (
            "76addf99df33bc51783ba1e881aa97c28b69e3f9563b030319af1b3bb69d8bd4"
        ),
        "_closed_payload": "46dd541bcb118173905eeaf669e897fb4bde09e46842a8c86dc573d390cbd68d",
        "_composite_payload": "39c364056997f0edb0ba7ba29af178b0ab706a4557b244c9c415326847663da8",
    }
    assert architecture_config[
        "graceful_stop_supervisor_bridge_payload_owner_class_ast_sha256"
    ] == {
        "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation": (
            "de8a78e38934b9af30d7c17f556bfe95113d3b7d8ec15ea8979ddab6576d662c"
        )
    }
    assert architecture_config["operation_bound_clean_stop_bridge_closed_evidence_class"] == (
        "_ClosedBridgeEvidence"
    )
    assert architecture_config["operation_bound_clean_stop_bridge_positive_evidence_class"] == (
        "TrustedTimeHeadAnchorOperationBoundCleanStopResult"
    )
    assert architecture_config["operation_bound_clean_stop_bridge_positive_properties"] == [
        "exact_request_work_result_correlated"
    ]
    assert architecture_config["operation_bound_clean_stop_bridge_positive_callable_names"] == [
        "payload"
    ]
    assert architecture_config["operation_bound_clean_stop_bridge_protected_function_bindings"] == [
        "_closed_payload",
        "_require_closed",
    ]
    assert architecture_config[
        "operation_bound_clean_stop_bridge_protected_function_callsites"
    ] == {
        "_closed_payload": [
            "TrustedTimeHeadAnchorOperationBoundCleanStopRequest.payload",
            "TrustedTimeHeadAnchorOperationBoundCleanStopResult.payload",
        ],
        "_require_closed": [
            "decode_trusted_time_head_anchor_operation_bound_clean_stop_request",
            "decode_trusted_time_head_anchor_operation_bound_clean_stop_result",
        ],
    }
    assert architecture_config[
        "operation_bound_clean_stop_bridge_protected_closed_field_loads"
    ] == [
        "comprehension:_closed_payload",
        "comprehension:_require_closed",
        "frozenset-assignment:_REQUEST_FIELDS",
        "frozenset-assignment:_RESULT_FIELDS",
    ]
    assert architecture_config["graceful_stop_supervisor_bridge_closed_evidence_class"] == (
        "_ClosedHostBridgeEvidence"
    )
    assert architecture_config["graceful_stop_supervisor_bridge_positive_evidence_class"] == (
        "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation"
    )
    assert architecture_config["graceful_stop_supervisor_bridge_positive_properties"] == [
        "decision_artifact_receipt_authenticated",
        "exact_terminal_projection_cross_bound_unqualified",
        "historical_start_chain_authenticated",
        "provider_terminal_observed_under_stable_sql_authenticated",
    ]
    assert architecture_config["graceful_stop_supervisor_bridge_positive_callable_names"] == [
        "payload"
    ]
    assert architecture_config["graceful_stop_supervisor_bridge_protected_function_bindings"] == [
        "_closed_payload",
        "_composite_payload",
    ]
    assert architecture_config["graceful_stop_supervisor_bridge_protected_function_callsites"] == {
        "_closed_payload": ["_composite_payload"],
        "_composite_payload": [
            "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation.payload",
            "_issue_composite",
            "_validate_registered_composite",
        ],
    }
    assert architecture_config["graceful_stop_supervisor_bridge_protected_closed_field_loads"] == [
        "comprehension:_closed_payload"
    ]
    assert architecture_config["operation_bound_clean_stop_bridge_forbidden_qualified_calls"] == [
        "threading.Thread"
    ]
    assert architecture_config[
        "operation_bound_clean_stop_bridge_forbidden_qualified_call_isinstance_callsites"
    ] == {
        "threading.Thread": [
            "_bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request"
        ]
    }
    assert architecture_config["graceful_stop_supervisor_bridge_forbidden_qualified_calls"] == [
        "threading.Thread"
    ]
    assert len(architecture_config["operation_bound_clean_stop_bridge_closed_fields"]) == 76
    assert len(architecture_config["graceful_stop_supervisor_bridge_closed_fields"]) == 81
    assert {
        "decision_artifact_receipt_authenticated",
        "historical_start_chain_authenticated",
    }.isdisjoint(architecture_config["graceful_stop_supervisor_bridge_closed_fields"])
    assert {
        "database_secret_disclosed",
        "transport_authenticated",
        "transport_origin_authenticated",
    }.issubset(architecture_config["graceful_stop_supervisor_bridge_closed_fields"])

    for binding, expected in architecture_config[
        "operation_bound_clean_stop_bridge_private_callsites"
    ].items():
        assert private_callsites(low_tree, binding) == sorted(expected)
    for binding, expected in architecture_config[
        "operation_bound_clean_stop_bridge_worker_private_callsites"
    ].items():
        assert private_callsites(worker_tree, binding) == sorted(expected)
    for binding, expected in architecture_config[
        "graceful_stop_supervisor_bridge_private_callsites"
    ].items():
        assert private_callsites(host_tree, binding) == sorted(expected)

    assert _production_importers(low_module) == {worker_relative_path, host_relative_path}
    assert _production_importers(host_module) == set()
    decision_artifact_private_seams = {
        "_ConsumedLoadedDecisionArtifactReceiptSnapshot",
        "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
        "_require_consumed_loaded_decision_artifact_receipt_snapshot",
    }
    terminal_reauthentication_private_seams = {
        "_ConsumedPostconditionRegistrySnapshot",
        "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
        "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
    }
    assert (
        set(architecture_config["graceful_stop_supervisor_bridge_dependency_private_symbols"])
        == decision_artifact_private_seams | terminal_reauthentication_private_seams
    )
    assert architecture_config[
        "graceful_stop_supervisor_bridge_dependency_private_owner_roots"
    ] == [
        "scripts/trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py",
        decision_artifact_relative_path.as_posix(),
        host_relative_path.as_posix(),
    ]
    reviewed_symbols = {
        low_module: set(architecture_config["operation_bound_clean_stop_bridge_private_symbols"]),
        "packages.application.trusted_time_head_anchor_clean_stop": set(
            architecture_config["operation_bound_clean_stop_bridge_clean_stop_private_symbols"]
        ),
        "packages.application.trusted_time_head_anchor_worker": set(
            architecture_config["operation_bound_clean_stop_bridge_worker_private_symbols"]
        ),
        _CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE: (terminal_reauthentication_private_seams),
        decision_artifact_module: decision_artifact_private_seams,
        lifecycle_module: set(
            architecture_config["graceful_stop_supervisor_bridge_lifecycle_symbols"]
        ),
    }
    observed_importers = {
        module: {symbol: set() for symbol in symbols}
        for module, symbols in reviewed_symbols.items()
    }
    for path in (
        *(ROOT / "apps").rglob("*.py"),
        *(ROOT / "packages").rglob("*.py"),
        *(ROOT / "scripts").rglob("*.py"),
    ):
        candidate = ast.parse(
            path.read_text(encoding="utf-8"),
            filename=str(path.relative_to(ROOT)),
        )
        for node in ast.walk(candidate):
            if not isinstance(node, ast.ImportFrom) or node.module not in reviewed_symbols:
                continue
            for alias in node.names:
                if alias.name in reviewed_symbols[node.module]:
                    observed_importers[node.module][alias.name].add(path.relative_to(ROOT))
    for private_seam in architecture_config["operation_bound_clean_stop_bridge_private_symbols"]:
        expected_importers = (
            {worker_relative_path}
            if private_seam
            in {
                "_bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request",
                "_issue_trusted_time_head_anchor_operation_bound_clean_stop_result",
                "_register_trusted_time_head_anchor_operation_bound_clean_stop_request",
                "_revoke_trusted_time_head_anchor_operation_bound_clean_stop_request",
                "_take_trusted_time_head_anchor_operation_bound_clean_stop_result_once",
            }
            else set()
        )
        assert observed_importers[low_module][private_seam] == expected_importers
    for private_seam in architecture_config[
        "operation_bound_clean_stop_bridge_clean_stop_private_symbols"
    ]:
        assert observed_importers["packages.application.trusted_time_head_anchor_clean_stop"][
            private_seam
        ] == {low_relative_path}
    for private_method in architecture_config[
        "operation_bound_clean_stop_bridge_worker_private_symbols"
    ]:
        assert (
            observed_importers["packages.application.trusted_time_head_anchor_worker"][
                private_method
            ]
            == set()
        )
    for private_seam in terminal_reauthentication_private_seams:
        assert observed_importers[_CLEAN_STOP_TERMINAL_REAUTHENTICATION_MODULE][private_seam] == {
            host_relative_path
        }
    for private_seam in decision_artifact_private_seams:
        assert observed_importers[decision_artifact_module][private_seam] == {host_relative_path}
    for lifecycle_symbol in architecture_config[
        "graceful_stop_supervisor_bridge_lifecycle_symbols"
    ]:
        assert observed_importers[lifecycle_module][lifecycle_symbol] == {host_relative_path}

    reviewed_source = (ROOT / "scripts/verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert reviewed_source.count(f'"{host_relative_path.as_posix()}"') == 1
    assert (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines().count(
        host_relative_path.as_posix()
    ) == 1
    assert host_relative_path.name not in (
        ROOT / "infra/docker/trusted-time.Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert host_relative_path.as_posix() not in makefile
    assert host_relative_path.stem not in makefile
    for path in (
        *(ROOT / "infra/compose").rglob("*.yaml"),
        *(ROOT / "infra/docker").glob("*Dockerfile*"),
    ):
        assert host_relative_path.stem not in path.read_text(encoding="utf-8")

    adr = (
        ROOT / "docs/adr/0111-dormant-operation-bound-clean-stop-supervisor-bridge.md"
    ).read_text(encoding="utf-8")
    normalized_adr = " ".join(adr.split())
    for required_statement in (
        "An unseen exact decoded request may be the first registered object",
        "exact thirteen terminal fields shared by the structural ADR-0108 result",
        "no production caller of the host bridge",
        "an authenticated, bounded, replay-safe host-to-supervisor request/result transport",
        "same-lock current topology, stop-authority, and operation admission",
        "a separately versioned lifecycle successor to ADR-0110 v1",
        "explicit at-fork invalidation and inherited-lock cleanup",
        "`apps/web/node_modules` is the sole lexical prune",
        "required-check branch protection remain external trusted controls",
        "legacy sourceless bytecode",
        "`make trusted-time-stop` remains the exact hard-closed target that exits 2",
    ):
        assert required_statement in normalized_adr
    for path in (
        ROOT / "docs/ARCHITECTURE.md",
        ROOT / "docs/IMPLEMENTATION_PLAN.md",
        ROOT / "docs/adr/README.md",
        ROOT / "docs/adr/0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs/adr/0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md",
        ROOT / "docs/adr/0105-inert-post-enrollment-graceful-stop-operator-attestation.md",
        ROOT
        / "docs/adr/0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md",
        ROOT / "docs/adr/0107-fail-closed-clean-stop-completion-invariant.md",
        ROOT / "docs/adr/0108-sealed-new-record-clean-stop-terminal-result.md",
        ROOT / "docs/adr/0109-code-only-clean-stop-terminal-reauthentication.md",
        ROOT / "docs/adr/0110-dormant-durable-graceful-stop-lifecycle-repository.md",
        ROOT / "docs/runbooks/trusted-time-supervisor.md",
    ):
        assert "ADR 0111" in path.read_text(encoding="utf-8")


def test_stop_make_target_fails_closed_without_live_compose_files() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = re.search(
        r"(?m)^trusted-time-stop:(?P<header>[^\n]*)\n"
        r"(?P<recipe>(?:\t[^\n]*\n)+)",
        makefile,
    )
    assert target is not None
    assert target.group("header").strip().startswith("## Fail closed")
    assert target.group("recipe").splitlines() == [
        '\t@echo "trusted-time-stop is approval-blocked: '
        'no effecting approved shutdown operator is implemented" >&2',
        "\t@exit 2",
    ]

    completed = subprocess.run(
        ("make", "trusted-time-stop"),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "approval-blocked" in completed.stderr
    assert "docker compose" not in completed.stdout


def test_inspection_make_target_uses_separate_database_only_environment() -> None:
    inspect_env = "/private/operator/trusted-time-inspect.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-inspect",
            f"TRUSTED_TIME_INSPECT_ENV_FILE={inspect_env}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--env-file "{inspect_env}"' in completed.stdout
    assert "TRUSTED_TIME_LAUNCH_ENV_FILE" not in completed.stdout


@pytest.mark.parametrize(
    ("assignments", "required_name"),
    [
        ((), "TRUSTED_TIME_LAUNCH_ENV_FILE"),
        (
            ("TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",),
            "TRUSTED_TIME_APPROVED_GIT_REVISION",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
            ),
            "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
                f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
            ),
            "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
                f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
                f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:{'c' * 64}",
            ),
            "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID",
        ),
    ],
)
def test_unenrolled_admission_make_guards_execute_before_launcher(
    assignments: tuple[str, ...],
    required_name: str,
) -> None:
    completed = subprocess.run(
        ("make", "trusted-time-admit-unenrolled", *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert required_name in completed.stderr
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_inspection_make_guard_executes_before_inspector() -> None:
    completed = subprocess.run(
        ("make", "trusted-time-inspect"),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_INSPECT_ENV_FILE" in completed.stderr
    assert "scripts/inspect_trusted_time_qualification.py" not in completed.stdout


def test_topology_launch_lock_architecture_policy_accepts_exact_frozen_surface(
    tmp_path: Path,
) -> None:
    from scripts.check_architecture import (
        _load_config,
        _python_files,
        _trusted_time_topology_launch_lock_violations,
    )

    _write_topology_launch_lock_architecture_fixture(tmp_path, full_production=True)
    config_path = tmp_path / "infra/architecture-boundaries.toml"
    scan = _load_config(config_path)
    production_files = _python_files(
        tuple(tmp_path / root for root in ("apps", "packages", "scripts")),
        pruned_subtrees=(tmp_path / "apps/web/node_modules",),
    )

    assert not _trusted_time_topology_launch_lock_violations(
        repository=tmp_path,
        config_path=config_path,
        scan=scan,
        production_files=production_files,
    )


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    [
        ("config", "configuration must remain mandatory and exact"),
        ("foreign_import", "native lease imports are reserved"),
        ("reader_reexport", "reader authority exports are private"),
        ("private_binding_import", "reader authority exports are private"),
        ("heap_escape", "reader authority cannot escape through attributes"),
        ("protected_override", "protected defaults cannot be overridden"),
        ("legacy_import", "cannot reach the legacy Python launch-lock API"),
        ("raw_reconstruction", "cannot reconstruct the raw launch-lock path"),
        ("reflection", "cannot be reached by reflection"),
        ("reader_ast", "preserve the exact reader module AST"),
        ("issuer_slots", "preserve exact issuer slots"),
        ("host_ast", "preserve the exact host module AST"),
        ("protected_default", "preserve protected default"),
        ("call_count", "preserve exact call count"),
        ("raw_lock_graph", "cannot restore the legacy Python/raw-descriptor lock graph"),
        ("yielded_authority", "cannot publish held authority through a generator"),
        ("production_aggregate", "preserve the exact production path/module AST aggregate"),
        ("documentation_claim", "documentation claim must remain exact and singular"),
        ("documentation_blocker", "activation-blocker claim must remain exact and singular"),
        ("frozen_native", "preserve frozen native/build source bytes"),
    ],
)
def test_topology_launch_lock_architecture_policy_rejects_mutation(
    tmp_path: Path,
    mutation: str,
    expected_fragment: str,
) -> None:
    from scripts.check_architecture import (
        _load_config,
        _python_files,
        _trusted_time_topology_launch_lock_violations,
    )

    _write_topology_launch_lock_architecture_fixture(tmp_path)
    config_path = tmp_path / "infra/architecture-boundaries.toml"
    scan = _load_config(config_path)
    reader_path = tmp_path / "scripts/trusted_time_post_enrollment_topology_reader.py"
    host_path = tmp_path / "scripts/trusted_time_post_enrollment_host_orchestrator.py"
    if mutation == "config":
        scan["trusted_time_topology_launch_lock_allowed_imports"] = []
    elif mutation == "foreign_import":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            "from packages.adapters.trusted_time._owned_file_descriptor import "
            "_TrustedTimeLaunchLockLease\n",
            encoding="utf-8",
        )
    elif mutation == "reader_reexport":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            "from scripts.trusted_time_post_enrollment_topology_reader import "
            "_TrustedTimeLaunchLockLease as EscapedLease\n",
            encoding="utf-8",
        )
    elif mutation == "private_binding_import":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            "from scripts.trusted_time_post_enrollment_topology_reader import "
            "_validated_authenticated_issuer_launch_lock_binding\n",
            encoding="utf-8",
        )
    elif mutation == "heap_escape":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            "def release(issuer):\n    issuer._launch_lock_lease.close()\n",
            encoding="utf-8",
        )
    elif mutation == "protected_override":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            "def release(issuer):\n    issuer.close(_validate_launch_lock=lambda _lease: None)\n",
            encoding="utf-8",
        )
    elif mutation in {"legacy_import", "raw_reconstruction"}:
        foreign = tmp_path / "scripts/topology_lock_foreign.py"
        if mutation == "legacy_import":
            foreign.write_text(
                "from scripts.start_trusted_time_supervisor import "
                "_acquire_trusted_time_launch_lock\n",
                encoding="utf-8",
            )
        else:
            foreign.write_text(
                'import fcntl\nLOCK_NAME = "trusted-time-launch.lock"\n',
                encoding="utf-8",
            )
        _write_detached_topology_fixture_text(
            host_path,
            host_path.read_text(encoding="utf-8") + "\nimport scripts.topology_lock_foreign\n",
        )
    elif mutation == "reflection":
        foreign = tmp_path / "apps/foreign.py"
        foreign.parent.mkdir(parents=True, exist_ok=True)
        foreign.write_text(
            'getattr(object(), "_TrustedTimeLaunchLockLease")\n',
            encoding="utf-8",
        )
    elif mutation == "reader_ast":
        _write_detached_topology_fixture_text(
            reader_path,
            reader_path.read_text(encoding="utf-8") + "\n_UNREVIEWED = True\n",
        )
    elif mutation == "issuer_slots":
        source = reader_path.read_text(encoding="utf-8")
        _write_detached_topology_fixture_text(
            reader_path,
            source.replace('        "_launch_lock_lease",\n', "", 1),
        )
    elif mutation == "host_ast":
        _write_detached_topology_fixture_text(
            host_path,
            host_path.read_text(encoding="utf-8") + "\n_UNREVIEWED = True\n",
        )
    elif mutation == "protected_default":
        source = reader_path.read_text(encoding="utf-8")
        _write_detached_topology_fixture_text(
            reader_path,
            source.replace(
                "    _restore: Callable[[object, int], BaseException | None] = "
                "_restore_rlock_depth,\n",
                "    _restore: Callable[[object, int], BaseException | None] = "
                "lambda _lock, _depth: None,\n",
                1,
            ),
        )
    elif mutation == "call_count":
        source = reader_path.read_text(encoding="utf-8")
        _write_detached_topology_fixture_text(
            reader_path,
            source.replace(
                "                _validate_launch_lock(cast(_TrustedTimeLaunchLockLease, "
                "bound_lease))\n",
                "                bool(cast(_TrustedTimeLaunchLockLease, bound_lease))\n",
                1,
            ),
        )
    elif mutation == "raw_lock_graph":
        _write_detached_topology_fixture_text(
            reader_path,
            reader_path.read_text(encoding="utf-8") + "\nFileIO = object()\n",
        )
    elif mutation == "yielded_authority":
        _write_detached_topology_fixture_text(
            reader_path,
            reader_path.read_text(encoding="utf-8")
            + "\ndef _unreviewed_lock_context():\n    yield object()\n",
        )
    elif mutation == "production_aggregate":
        pass
    elif mutation == "documentation_claim":
        documentation_path = tmp_path / "docs/ARCHITECTURE.md"
        documentation_path.write_text(
            documentation_path.read_text(encoding="utf-8").replace(
                "No held lock or opaque-lease authority crosses a function `RETURN`, "
                "generator `yield`, or context-manager handoff.",
                "No authority claim is reviewed here.",
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "documentation_blocker":
        documentation_path = tmp_path / "docs/ARCHITECTURE.md"
        documentation_path.write_text(
            documentation_path.read_text(encoding="utf-8").replace(
                "a separate production-activation blocker outside",
                "within the reviewed production activation surface of",
                1,
            ),
            encoding="utf-8",
        )
    else:
        assert mutation == "frozen_native"
        native_path = tmp_path / "native/owned_file_descriptor.c"
        native_path.write_bytes(native_path.read_bytes() + b"\n/* unreviewed */\n")

    production_files = _python_files(
        tuple(tmp_path / root for root in ("apps", "packages", "scripts")),
        pruned_subtrees=(tmp_path / "apps/web/node_modules",),
    )
    violations = _trusted_time_topology_launch_lock_violations(
        repository=tmp_path,
        config_path=config_path,
        scan=scan,
        production_files=production_files,
    )

    assert any(expected_fragment in violation.message for violation in violations)


@pytest.mark.parametrize(
    "mutation",
    [
        "alias_close",
        "slots_escape",
        "raw_allowed_module",
        "production_added",
        "production_removed",
        "production_renamed",
    ],
)
def test_topology_launch_lock_production_ast_aggregate_rejects_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    from scripts.check_architecture import (
        _load_config,
        _python_files,
        _trusted_time_topology_production_ast_sha256,
    )

    _write_topology_launch_lock_architecture_fixture(tmp_path, full_production=True)
    config_path = tmp_path / "infra/architecture-boundaries.toml"
    expected = _load_config(config_path)["trusted_time_topology_launch_lock_production_ast_sha256"]
    roots = tuple(tmp_path / root for root in ("apps", "packages", "scripts"))
    assert (
        _trusted_time_topology_production_ast_sha256(
            tmp_path,
            _python_files(
                roots,
                pruned_subtrees=(tmp_path / "apps/web/node_modules",),
            ),
        )
        == expected
    )

    _mutate_topology_production_ast_fixture(tmp_path, mutation)

    assert (
        _trusted_time_topology_production_ast_sha256(
            tmp_path,
            _python_files(
                roots,
                pruned_subtrees=(tmp_path / "apps/web/node_modules",),
            ),
        )
        != expected
    )
