from __future__ import annotations

import importlib.util
import os
import platform
import re
import shlex
import shutil
import subprocess
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
BUILD_HELPER = ROOT / "build_support" / "build_trusted_time_v2_endpoint_test.py"
SOCKET_PATH = (
    "/run/autoquant/trusted-time/graceful-stop-v2/transport/supervisor.sock"
)

HOST_METHODS = {
    "aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python",
    "aqt_trusted_time_graceful_stop_v2_host_connector_create",
    "aqt_trusted_time_graceful_stop_v2_host_send_hello",
    "aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello",
    "aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation",
    "aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request",
    "aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error",
    "aqt_trusted_time_graceful_stop_v2_host_close",
}
SUPERVISOR_METHODS = {
    "aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python",
    "aqt_trusted_time_graceful_stop_v2_supervisor_listener_create",
    "aqt_trusted_time_graceful_stop_v2_supervisor_accept_once",
    "aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello",
    "aqt_trusted_time_graceful_stop_v2_supervisor_send_hello",
    "aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation",
    "aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request",
    "aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error",
    "aqt_trusted_time_graceful_stop_v2_supervisor_close",
}
HOST_RESOURCE_METHODS = {
    "aqt_trusted_time_v2_host_transport_resources_prepare",
    "aqt_trusted_time_v2_host_transport_resources_bind_connected_peer",
    "aqt_trusted_time_v2_host_transport_resources_revalidate",
    "aqt_trusted_time_v2_host_transport_resources_close",
}
SUPERVISOR_RESOURCE_METHODS = {
    "aqt_trusted_time_v2_supervisor_transport_resources_prepare",
    "aqt_trusted_time_v2_supervisor_transport_resources_bind_listener",
    "aqt_trusted_time_v2_supervisor_transport_resources_bind_accepted_peer",
    "aqt_trusted_time_v2_supervisor_transport_resources_revalidate",
    "aqt_trusted_time_v2_supervisor_transport_resources_close",
}


def _load_build_helper():
    specification = importlib.util.spec_from_file_location(
        "build_trusted_time_v2_endpoint_test", BUILD_HELPER
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _compiler() -> str:
    configured = os.environ.get("CC") or sysconfig.get_config_var("CC") or "cc"
    words = shlex.split(configured)
    compiler = shutil.which(words[0]) if words else None
    if compiler is None:
        pytest.skip("a C11 compiler is required")
    return compiler


def _strict_flags() -> list[str]:
    return [
        "-std=c11",
        "-O2",
        "-fno-lto",
        "-fPIE",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror",
        "-pthread",
        f"-I{NATIVE}",
    ]


def _symbols(path: Path, undefined: bool) -> set[str]:
    nm = shutil.which("nm")
    if nm is None:
        pytest.skip("nm is required for native role-surface audit")
    command = [nm, "-u" if undefined else "-g", str(path)]
    output = subprocess.run(
        command, cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout
    symbols: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        symbol = fields[-1]
        if symbol.startswith("_") and platform.system() == "Darwin":
            symbol = symbol[1:]
        if undefined or any(marker in fields for marker in ("T", "D", "B", "S")):
            symbols.add(symbol)
    return symbols


@pytest.fixture(scope="module")
def production_objects(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    directory = tmp_path_factory.mktemp("trusted-time-v2-endpoint-objects")
    compiler = _compiler()
    outputs: dict[str, Path] = {}
    for role in ("host", "supervisor"):
        definition = f"-DAQT_TRUSTED_TIME_V2_{role.upper()}_PROFILE"
        for component in ("endpoint", "resources"):
            source = (
                NATIVE
                / f"trusted_time_graceful_stop_v2_{component}.c"
            )
            output = directory / f"{role}-{component}.o"
            subprocess.run(
                [
                    compiler,
                    *_strict_flags(),
                    definition,
                    "-c",
                    str(source),
                    "-o",
                    str(output),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )
            outputs[f"{role}-{component}"] = output
    return outputs


def test_adversarial_native_harness(tmp_path: Path) -> None:
    executable = tmp_path / "trusted-time-v2-endpoint-resources"
    helper = _load_build_helper()
    assert helper.build(executable) == executable
    completed = subprocess.run(
        [executable], cwd=ROOT, check=True, text=True, capture_output=True
    )
    expected = (
        "all checks passed"
        if platform.system() == "Linux"
        else "portable compile passed"
    )
    assert expected in completed.stdout


def test_production_role_symbols_are_closed(
    production_objects: dict[str, Path],
) -> None:
    host_defined = _symbols(production_objects["host-endpoint"], undefined=False)
    supervisor_defined = _symbols(
        production_objects["supervisor-endpoint"], undefined=False
    )
    host_resource_defined = _symbols(
        production_objects["host-resources"], undefined=False
    )
    supervisor_resource_defined = _symbols(
        production_objects["supervisor-resources"], undefined=False
    )
    assert host_defined == HOST_METHODS
    assert supervisor_defined == SUPERVISOR_METHODS
    assert host_resource_defined == HOST_RESOURCE_METHODS
    assert supervisor_resource_defined == SUPERVISOR_RESOURCE_METHODS
    assert not any("for_test" in symbol for symbol in host_defined | supervisor_defined)
    assert not any(
        symbol.startswith("aqt_trusted_time_graceful_stop_v2_supervisor_")
        for symbol in host_defined
    )
    assert not any(
        symbol.startswith("aqt_trusted_time_graceful_stop_v2_host_")
        for symbol in supervisor_defined
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux syscall audit")
def test_linux_role_syscalls_are_asymmetric(
    production_objects: dict[str, Path],
) -> None:
    host_undefined = _symbols(production_objects["host-endpoint"], undefined=True)
    supervisor_undefined = _symbols(
        production_objects["supervisor-endpoint"], undefined=True
    )
    assert {"socket", "connect", "sendmsg", "recvmsg", "ppoll"} <= host_undefined
    assert not {"bind", "listen", "accept", "accept4"} & host_undefined
    assert {"socket", "bind", "listen", "accept4", "sendmsg", "recvmsg", "ppoll"} <= (
        supervisor_undefined
    )
    assert "connect" not in supervisor_undefined


def test_header_has_only_role_narrow_production_surface() -> None:
    header = (
        NATIVE / "trusted_time_graceful_stop_v2_endpoint.h"
    ).read_text(encoding="utf-8")
    source = (
        NATIVE / "trusted_time_graceful_stop_v2_endpoint.c"
    ).read_text(encoding="utf-8")
    declarations = set(
        re.findall(
            r"\b(aqt_trusted_time_graceful_stop_v2_[a-z0-9_]+)\s*\(",
            header,
        )
    )
    assert declarations >= HOST_METHODS | SUPERVISOR_METHODS
    assert "aqt_trusted_time_graceful_stop_v2_send" not in declarations
    assert "aqt_trusted_time_graceful_stop_v2_receive" not in declarations
    assert "getenv(" not in source
    assert "SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK" in source
    assert "MSG_TRUNC | MSG_CTRUNC" in source
    assert "SO_COOKIE" in source
    assert "SO_SNDBUF" in source
    assert "SO_RCVBUF" in source
    assert "atomic_compare_exchange_strong_explicit" in source
    assert "(void)umask(0177);" in source
    assert "previous_umask" not in source
    assert "shutdown(" not in source
    assert "aqt_trusted_time_v2_fork_guard_close_fd(" in source
    bind_call = source.index("result = bind(")
    bind_resource = source.index(
        "supervisor_transport_resources_bind_listener", bind_call
    )
    listen_call = source.index("if (listen(", bind_resource)
    assert bind_call < bind_resource < listen_call
    resource_header = (
        NATIVE / "trusted_time_graceful_stop_v2_resources.h"
    ).read_text(encoding="utf-8")
    assert header.count("uintptr_t interpreter_instance_identity") >= 16
    assert resource_header.count("uintptr_t interpreter_instance_identity") == 9
    assert SOCKET_PATH.rsplit("/", 1)[0] in resource_header
    assert SOCKET_PATH.rsplit("/", 1)[1] in resource_header


def test_resource_admission_is_literal_and_stable() -> None:
    source = (
        NATIVE / "trusted_time_graceful_stop_v2_resources.c"
    ).read_text(encoding="utf-8")
    assert '"/proc/self/mountinfo"' not in source
    assert '"mountinfo"' in source
    assert '"/proc"' in source
    assert '"ns/pid"' in source
    assert '"NSpid:"' in source
    assert '"cgroup"' in source
    assert "O_NOFOLLOW" in source
    assert "aqt_open_numeric_proc_directory" in source
    assert "aqt_openat_correlated_directory" in source
    assert "PROC_SUPER_MAGIC" in source
    assert "bytes[length - 1U]" in source
    assert "aqt_guarded_fd_adopt(" in source
    assert "aqt_validate_literal_directory_binding" in source
    assert "process_directory_identity" in source
    assert "aqt_process_identity_equal" in source
    assert "aqt_trusted_time_v2_fork_guard_close_fd(" in source
    assert not any(
        forbidden in source
        for forbidden in (
            "getenv(",
            "DOCKER_HOST",
            "/var/run/docker.sock",
            "system(",
            "popen(",
        )
    )
