"""Build the standalone Wave 7 role/profile evidence matrix.

This helper uses only test stubs and writes only to an explicit new output
directory.  It neither installs a candidate nor authorizes activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Never

_ROOT = Path(__file__).resolve(strict=True).parents[1]
_NATIVE = _ROOT / "native"
_MONOCYPHER = _ROOT / "third_party/monocypher/4.0.3/src"
_MONOCYPHER_OPTIONAL = _MONOCYPHER / "optional"
_STUBS = _ROOT / "tests/fixtures/native/trusted-time-v2"
_ROLE_SOURCE = _NATIVE / "trusted_time_v2_role_launcher.c"
_PROVISIONER_SOURCE = _NATIVE / "trusted_time_v2_provisioner.c"
_SECCOMP_SOURCE = _NATIVE / "trusted_time_v2_seccomp.c"
_DESCRIPTOR_BASELINE_SOURCE = _NATIVE / "trusted_time_v2_descriptor_baseline.c"
_MONOCYPHER_SOURCE = _MONOCYPHER / "monocypher.c"
_MONOCYPHER_ED25519_SOURCE = _MONOCYPHER_OPTIONAL / "monocypher-ed25519.c"
_STUB_SOURCE = _STUBS / "profile_stubs.c"
_HARNESS_SOURCE = _STUBS / "provisioner_contract_harness.c"
_FORBIDDEN_RECOVERY_STRINGS = (
    "host-ed25519.raw",
    "supervisor-ed25519.raw",
    "host-secrets",
    "supervisor-secrets",
    "supervisor.sock",
    "/run/autoquant/trusted-time/graceful-stop-v2/transport",
    "/var/run/docker.sock",
    "/v1.45",
    "stop?t=30",
    "v=false&force=false&link=false",
    "autoquant-trusted-time-graceful-stop-v2-host-provision",
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision",
    "autoquant_trusted_time_v2_host_entry",
    "autoquant_trusted_time_v2_supervisor_entry",
    "trusted_time_graceful_stop_v2_endpoint",
    "lib-dynload",
)
_FORBIDDEN_RECOVERY_UNDEFINED = (
    "accept",
    "accept4",
    "bind",
    "clone",
    "clone3",
    "connect",
    "dlopen",
    "dlsym",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execveat",
    "execvp",
    "execvpe",
    "fork",
    "listen",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "send",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "shutdown",
    "socket",
    "socketpair",
    "system",
    "vfork",
)


class ProfileBuildError(RuntimeError):
    """The standalone role/profile evidence build failed closed."""


@dataclass(frozen=True, slots=True)
class _Role:
    name: str
    macro: str
    signer_macro: str
    executable: str
    provisioner_macro: str
    provisioner: str


_ROLES = (
    _Role(
        "host",
        "AQT_TRUSTED_TIME_V2_HOST_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-host",
        "AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-host-provision",
    ),
    _Role(
        "supervisor",
        "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-supervisor",
        "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-supervisor-provision",
    ),
    _Role(
        "recovery",
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-recovery",
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-recovery-provision",
    ),
)


def _fail(message: str) -> Never:
    raise ProfileBuildError(message)


def _tool(name: str) -> Path:
    located = shutil.which(name)
    if located is None:
        _fail(f"required native profile tool is unavailable: {name}")
    path = Path(located).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _fail(f"native profile tool is not admitted: {path}")
    return path


def _compiler() -> Path:
    configured = sysconfig.get_config_var("CC")
    if type(configured) is not str or not configured:
        _fail("Python did not declare a C compiler")
    words = shlex.split(configured)
    if not words:
        _fail("Python declared an empty C compiler")
    return _tool(words[0])


def _run(command: tuple[str, ...]) -> bytes:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": os.environ.get("TMPDIR", "/private/tmp"),
        },
        check=False,
    )
    if completed.returncode != 0:
        output = completed.stdout.decode("utf-8", errors="replace")
        _fail(f"native profile command failed ({completed.returncode}):\n{output}")
    if len(completed.stdout) > 16 * 1024 * 1024:
        _fail("native profile command output exceeded its bound")
    return completed.stdout


def _run_expect_status(command: tuple[str, ...], expected_status: int) -> bytes:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": os.environ.get("TMPDIR", "/private/tmp"),
        },
        check=False,
    )
    if completed.returncode != expected_status:
        output = completed.stdout.decode("utf-8", errors="replace")
        _fail(
            "native profile command returned "
            f"{completed.returncode}, expected {expected_status}:\n{output}"
        )
    return completed.stdout


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _common(compiler: Path) -> tuple[str, ...]:
    return (
        str(compiler),
        "-std=c11",
        "-O2",
        f"-ffile-prefix-map={_ROOT}=.",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror",
        f"-I{_STUBS}",
        f"-I{_NATIVE}",
        f"-I{_MONOCYPHER}",
        f"-I{_MONOCYPHER_OPTIONAL}",
    )


def _python_build_flags() -> tuple[tuple[str, ...], tuple[str, ...]]:
    configured_include = sysconfig.get_config_var("INCLUDEPY")
    configured_libdir = sysconfig.get_config_var("LIBDIR")
    configured_library = sysconfig.get_config_var("LDLIBRARY")
    configured_framework = sysconfig.get_config_var("PYTHONFRAMEWORK")
    configured_framework_prefix = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")
    if type(configured_include) is not str:
        _fail("Python did not declare its include root")
    include = Path(configured_include).resolve(strict=True)
    compile_flags = (f"-I{include}",)
    link_flags: list[str] = []
    if type(configured_framework) is str and configured_framework:
        if type(configured_framework_prefix) is not str:
            _fail("framework Python did not declare its framework root")
        framework_prefix = Path(configured_framework_prefix).resolve(strict=True)
        link_flags.extend((f"-F{framework_prefix}", "-framework", configured_framework))
    else:
        if type(configured_libdir) is not str or type(configured_library) is not str:
            _fail("Python did not declare its embed library")
        library_name = configured_library
        if not library_name.startswith("lib"):
            _fail("Python embed library has an unknown name")
        library_name = library_name[3:]
        for marker in (".so", ".dylib", ".a"):
            if marker in library_name:
                library_name = library_name.split(marker, 1)[0]
                break
        library_root = Path(configured_libdir).resolve(strict=True)
        link_flags.extend((f"-L{library_root}", f"-Wl,-rpath,{library_root}", f"-l{library_name}"))
    link_variables = ("LIBS", "SYSLIBS")
    if not (type(configured_framework) is str and configured_framework):
        link_variables += ("LINKFORSHARED",)
    for variable in link_variables:
        configured = sysconfig.get_config_var(variable)
        if type(configured) is str and configured:
            link_flags.extend(shlex.split(configured))
    return compile_flags, tuple(link_flags)


def _quoted_definition(name: str, value: Path | str) -> str:
    payload = str(value)
    if not payload or any(character in payload for character in ('"', "\\", "\n", "\r")):
        _fail(f"the {name} C string is not representable")
    return f'-D{name}="{payload}"'


def _role_python_definitions(role: _Role) -> tuple[str, ...]:
    python_home = Path(sys.base_prefix).resolve(strict=True)
    standard_library = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    import_root = (_STUBS / "import-roots" / role.name).resolve(strict=True)
    definitions = [
        "-DAQT_TRUSTED_TIME_V2_CANDIDATE_CLOSED_RUNTIME=1",
        _quoted_definition("AQT_TRUSTED_TIME_V2_TEST_ROLE_IMPORT_ROOT", import_root),
        _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_HOME", python_home),
        _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_STDLIB", standard_library),
    ]
    if role.name != "recovery":
        configured_dynload = sysconfig.get_config_var("DESTSHARED")
        if type(configured_dynload) is not str:
            _fail("Python did not declare its dynamic-extension root")
        dynamic_extensions = Path(configured_dynload).resolve(strict=True)
        definitions.append(
            _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_DYNLOAD", dynamic_extensions)
        )
    return tuple(definitions)


def _child_identity() -> tuple[Path, str]:
    candidate = Path("/usr/bin/true").resolve(strict=True)
    if not candidate.is_file():
        _fail("the fixed test child is unavailable")
    return candidate, _sha256(candidate)


def _build_role(
    compiler: Path,
    role: _Role,
    output: Path,
    *,
    python_compile_flags: tuple[str, ...],
    python_link_flags: tuple[str, ...],
) -> None:
    _run(
        (
            *_common(compiler),
            *python_compile_flags,
            f"-D{role.macro}=1",
            f"-D{role.signer_macro}=1",
            "-DAQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE=1",
            *_role_python_definitions(role),
            str(_ROLE_SOURCE),
            str(_DESCRIPTOR_BASELINE_SOURCE),
            str(_SECCOMP_SOURCE),
            str(_STUB_SOURCE),
            "-o",
            str(output),
            *python_link_flags,
        )
    )
    output.chmod(0o755)
    _run((str(output),))


def _provisioner_definitions(role: _Role, child: Path, digest: str) -> tuple[str, ...]:
    return (
        f"-D{role.provisioner_macro}=1",
        "-DAQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD=1",
        f'-DAQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256="{digest}"',
        f'-DAQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH="{child}"',
    )


def _build_provisioner(
    compiler: Path,
    role: _Role,
    output: Path,
    *,
    child: Path,
    child_sha256: str,
) -> None:
    _run(
        (
            *_common(compiler),
            *_provisioner_definitions(role, child, child_sha256),
            str(_PROVISIONER_SOURCE),
            str(_SECCOMP_SOURCE),
            str(_MONOCYPHER_SOURCE),
            str(_MONOCYPHER_ED25519_SOURCE),
            str(_STUB_SOURCE),
            "-o",
            str(output),
        )
    )
    output.chmod(0o755)
    _run_expect_status((str(output),), 191)


def _build_harness(
    compiler: Path,
    role: _Role,
    output: Path,
    *,
    child: Path,
    child_sha256: str,
) -> None:
    _run(
        (
            *_common(compiler),
            *_provisioner_definitions(role, child, child_sha256),
            "-DAQT_TRUSTED_TIME_V2_PROVISIONER_TEST_API=1",
            "-DAQT_TRUSTED_TIME_V2_NO_MAIN=1",
            str(_PROVISIONER_SOURCE),
            str(_SECCOMP_SOURCE),
            str(_MONOCYPHER_SOURCE),
            str(_MONOCYPHER_ED25519_SOURCE),
            str(_STUB_SOURCE),
            str(_HARNESS_SOURCE),
            "-o",
            str(output),
        )
    )
    output.chmod(0o755)
    _run((str(output),))


def _preprocess_recovery(
    compiler: Path,
    source: Path,
    macro: str,
    *,
    python_compile_flags: tuple[str, ...],
) -> str:
    payload = _run(
        (
            *_common(compiler),
            *python_compile_flags,
            f"-D{macro}=1",
            "-DAQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE=1",
            "-DAQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE=1",
            "-DAQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD=1",
            '-DAQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256="' + ("0" * 64) + '"',
            '-DAQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH="/usr/bin/true"',
            *_role_python_definitions(_ROLES[2]),
            "-E",
            "-P",
            str(source),
        )
    )
    return payload.decode("utf-8", errors="strict")


def _audit_recovery(
    compiler: Path,
    role_binary: Path,
    provisioner_binary: Path,
    *,
    python_compile_flags: tuple[str, ...],
) -> None:
    role_source = _preprocess_recovery(
        compiler,
        _ROLE_SOURCE,
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE",
        python_compile_flags=python_compile_flags,
    )
    provisioner_source = _preprocess_recovery(
        compiler,
        _PROVISIONER_SOURCE,
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE",
        python_compile_flags=python_compile_flags,
    )
    for label, payload in (
        ("recovery preprocessed role source", role_source),
        ("recovery preprocessed provisioner source", provisioner_source),
    ):
        found = [value for value in _FORBIDDEN_RECOVERY_STRINGS if value in payload]
        if found:
            _fail(f"{label} contains forbidden normal-role strings: {found}")

    strings = _tool("strings")
    for binary in (role_binary, provisioner_binary):
        payload = _run((str(strings), "-a", str(binary))).decode("utf-8", errors="strict")
        found = [value for value in _FORBIDDEN_RECOVERY_STRINGS if value in payload]
        if found:
            _fail(f"recovery binary contains forbidden normal-role strings: {found}")

    nm = _tool("nm")
    undefined = _run((str(nm), "-u", str(role_binary))).decode("utf-8", errors="strict")
    undefined_symbols = {
        line.split()[-1].partition("@")[0]
        for line in undefined.splitlines()
        if line.split()
    }
    found_symbols = sorted(undefined_symbols & set(_FORBIDDEN_RECOVERY_UNDEFINED))
    if found_symbols:
        _fail(f"recovery role has forbidden undefined capabilities: {found_symbols}")


def build(output_directory: Path) -> dict[str, object]:
    if output_directory.exists() or not output_directory.is_absolute():
        _fail("output directory must be one absent absolute path")
    output_directory.mkdir(mode=0o700)
    compiler = _compiler()
    python_compile_flags, python_link_flags = _python_build_flags()
    child, child_sha256 = _child_identity()
    records: list[dict[str, object]] = []
    role_outputs: dict[str, Path] = {}
    provisioner_outputs: dict[str, Path] = {}

    for role in _ROLES:
        role_output = output_directory / role.executable
        provisioner_output = output_directory / role.provisioner
        harness_output = output_directory / f"{role.provisioner}-contract-test"
        _build_role(
            compiler,
            role,
            role_output,
            python_compile_flags=python_compile_flags,
            python_link_flags=python_link_flags,
        )
        _build_provisioner(
            compiler,
            role,
            provisioner_output,
            child=child,
            child_sha256=child_sha256,
        )
        _build_harness(
            compiler,
            role,
            harness_output,
            child=child,
            child_sha256=child_sha256,
        )
        role_outputs[role.name] = role_output
        provisioner_outputs[role.name] = provisioner_output
        for kind, path in (
            ("role", role_output),
            ("provisioner", provisioner_output),
            ("contract_test", harness_output),
        ):
            records.append(
                {
                    "basename": path.name,
                    "kind": kind,
                    "role": role.name,
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                }
            )

    _audit_recovery(
        compiler,
        role_outputs["recovery"],
        provisioner_outputs["recovery"],
        python_compile_flags=python_compile_flags,
    )
    result: dict[str, object] = {
        "activation_authorized": False,
        "artifacts": sorted(records, key=lambda record: str(record["basename"])),
        "compiler": str(compiler),
        "schema": "autoquant-trusted-time-v2-profile-test-build-v1",
        "status": "candidate_unactivated",
    }
    receipt = output_directory / "profile-test-build.json"
    receipt.write_text(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    receipt.chmod(0o444)
    return result


def main(argument_values: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-directory", required=True)
    arguments = parser.parse_args(argument_values)
    output = Path(arguments.output_directory)
    result = build(output)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
