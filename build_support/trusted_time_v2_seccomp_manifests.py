"""Build and verify the canonical Wave 7 seccomp manifests.

The manifests bind the exact x86_64 classic-BPF bytes compiled into each
candidate profile.  They are build evidence only: this module never installs a
filter, installs a candidate, or authorizes activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Never

ROOT = Path(__file__).resolve(strict=True).parents[1]
NATIVE = ROOT / "native"
SECCOMP_SOURCE = NATIVE / "trusted_time_v2_seccomp.c"
SECCOMP_HEADER = NATIVE / "trusted_time_v2_seccomp.h"
HARNESS = ROOT / "tests/native/trusted_time_v2_seccomp_manifest_harness.c"
MANIFEST_ROOT = ROOT / "infra/trusted-time/graceful-stop-v2/seccomp"

FORMAT = "autoquant-trusted-time-graceful-stop-v2-seccomp-manifest-v1"
POLICY_MODEL = "ordered-default-deny-allowlist-v1"
AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO_EPERM = 0x00050001
SECCOMP_RET_ALLOW = 0x7FFF0000
ARCH_SET_FS = 0x1002

PROFILE_MACROS = {
    "host": "AQT_TRUSTED_TIME_V2_HOST_PROFILE",
    "supervisor": "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE",
    "recovery": "AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE",
    "provisioner": "AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE",
}

CAPABILITY_TUPLES: dict[str, object] = {
    "host": [
        "fork_guard",
        "host_signer",
        "unix_seqpacket_connector",
        "host_resource_admission",
        "owner_cleanup",
        "host_seccomp",
    ],
    "supervisor": [
        "fork_guard",
        "supervisor_signer",
        "unix_seqpacket_listener",
        "supervisor_resource_admission",
        "owner_cleanup",
        "supervisor_seccomp",
    ],
    "recovery": [
        "fork_guard",
        "recovery_classification_signer",
        "owner_cleanup",
        "recovery_seccomp",
    ],
    "provisioner": {
        role: [
            "authenticated_generation_seal",
            f"{role}_secret_tmpfs_writer",
            "one_pinned_systemd_creds_child",
            "pre_child_seccomp",
            "child_exec_seccomp",
            "post_child_seccomp",
        ]
        for role in ("host", "supervisor", "recovery")
    },
}


class SeccompManifestError(RuntimeError):
    """The canonical seccomp evidence failed closed."""


def _fail(message: str) -> Never:
    raise SeccompManifestError(message)


def _allow(syscall: str, arguments: str = "any") -> dict[str, object]:
    return {"action": "allow", "arguments": arguments, "syscall": syscall}


_BASE_RUNTIME = (
    _allow("read"),
    _allow("close"),
    _allow("lseek"),
    _allow("munmap"),
    _allow("brk"),
    _allow("rt_sigaction"),
    _allow("rt_sigprocmask"),
    _allow("rt_sigreturn"),
    _allow("pread64"),
    _allow("madvise"),
    _allow("geteuid"),
    _allow("getpid"),
    _allow("futex"),
    _allow("clock_gettime"),
    _allow("exit"),
    _allow("exit_group"),
    _allow("newfstatat"),
    _allow("fstat"),
    _allow("getdents64"),
    _allow("getrandom"),
    _allow("mlock"),
    _allow("munlock"),
    _allow("readlinkat"),
    _allow("sysinfo"),
)

_PORTABLE_LINUX_RUNTIME = (
    _allow("faccessat2"),
    _allow("gettid"),
    _allow("prlimit64"),
    _allow("rseq"),
)

_WRITE = _allow("write", "fd is exactly stdout or stderr")
_READ_ONLY_OPENAT = _allow(
    "openat",
    "flags contain none of O_ACCMODE|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|O_TMPFILE",
)
_PROVISIONER_OPENAT = _allow(
    "openat",
    "read-only, or exact O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_CREAT|O_EXCL mode 0600",
)
_FCNTL = _allow(
    "fcntl",
    "command is F_GETFD, F_GETFL, or F_SETFD with argument FD_CLOEXEC",
)
_TCGETS_IOCTL = _allow("ioctl", "request is exactly TCGETS")
_ENDPOINT_IOCTL = _allow("ioctl", "request is exactly TCGETS or FIONREAD")
_NONEXEC_MMAP = _allow("mmap", "protection excludes PROT_EXEC")
_NONEXEC_MPROTECT = _allow("mprotect", "protection excludes PROT_EXEC")
_UNLINKAT = _allow("unlinkat", "flags are exactly zero")
_ARCH_SET_FS = _allow(
    "arch_prctl",
    "operation is exactly ARCH_SET_FS with a zero high word; TLS base address is unconstrained",
)


def _normal_prefix(*, endpoint: bool) -> tuple[dict[str, object], ...]:
    return (
        _WRITE,
        _READ_ONLY_OPENAT,
        _FCNTL,
        _ENDPOINT_IOCTL if endpoint else _TCGETS_IOCTL,
        _NONEXEC_MMAP,
        _NONEXEC_MPROTECT,
        *_BASE_RUNTIME,
        _allow("readlink"),
        _allow("stat"),
        *_PORTABLE_LINUX_RUNTIME,
    )


_ENDPOINT_SHARED = (
    _allow("getegid"),
    _allow(
        "socket",
        "domain AF_UNIX, type SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, protocol 0",
    ),
    _allow(
        "setsockopt",
        "level SOL_SOCKET, option SO_SNDBUF or SO_RCVBUF, optlen sizeof(int)",
    ),
    _allow("ppoll"),
    _allow("sendmsg", "flags are exactly MSG_DONTWAIT|MSG_NOSIGNAL"),
    _allow("recvmsg", "flags are exactly MSG_DONTWAIT|MSG_CMSG_CLOEXEC"),
    _UNLINKAT,
    _allow("fstatfs"),
)


def _policies(profile: str) -> tuple[tuple[str, int, tuple[dict[str, object], ...]], ...]:
    if profile == "host":
        return (
            (
                "initial",
                0,
                (
                    *_normal_prefix(endpoint=True),
                    *_ENDPOINT_SHARED,
                    _allow(
                        "getsockopt",
                        "SOL_SOCKET option in "
                        "SO_TYPE|SO_PEERCRED|SO_ERROR|SO_COOKIE|SO_SNDBUF|SO_RCVBUF",
                    ),
                    _allow("connect"),
                    _allow("getsockname"),
                ),
            ),
        )
    if profile == "supervisor":
        return (
            (
                "initial",
                0,
                (
                    *_normal_prefix(endpoint=True),
                    *_ENDPOINT_SHARED,
                    _allow(
                        "getsockopt",
                        "SOL_SOCKET option in SO_TYPE|SO_PEERCRED|SO_COOKIE|SO_SNDBUF|SO_RCVBUF",
                    ),
                    _allow("accept4", "flags are exactly SOCK_CLOEXEC|SOCK_NONBLOCK"),
                    _allow("listen", "backlog is exactly one"),
                    _allow("bind"),
                    _allow("getsockname"),
                    _allow("umask", "mask is exactly 0177"),
                ),
            ),
        )
    if profile == "recovery":
        return (
            (
                "initial",
                0,
                (*_normal_prefix(endpoint=False), _UNLINKAT),
            ),
        )
    if profile != "provisioner":
        _fail(f"unknown seccomp profile: {profile}")
    initial = (
        _WRITE,
        _PROVISIONER_OPENAT,
        _FCNTL,
        _TCGETS_IOCTL,
        _allow("mmap"),
        _allow("mprotect"),
        *_BASE_RUNTIME,
        _allow("readlink"),
        *_PORTABLE_LINUX_RUNTIME,
        _allow(
            "dup3",
            "normalizes only fixed fds 64|65|66 with O_CLOEXEC or maps "
            "65->0 and 66->1 with flags 0",
        ),
        _allow("clone", "exact fork-like flags and null stack/parent-tid/TLS"),
        _allow("kill", "signal is exactly SIGKILL"),
        _allow("execveat", "fd is exactly 64 and flags are exactly AT_EMPTY_PATH"),
        _ARCH_SET_FS,
        _allow("prctl", "exact PR_SET_NO_NEW_PRIVS(1,0,0,0)"),
        _allow("seccomp", "exact SET_MODE_FILTER with TSYNC and nonnull program"),
        _allow("wait4"),
        _allow("nanosleep"),
        _UNLINKAT,
        _allow("fchmod"),
        _allow("fchown"),
        _allow("fstatfs"),
        _allow("getegid"),
    )
    child_exec = (
        _WRITE,
        _READ_ONLY_OPENAT,
        _FCNTL,
        _TCGETS_IOCTL,
        _allow("mmap"),
        _allow("mprotect"),
        *_BASE_RUNTIME,
        _allow("execveat", "fd is exactly 64 and flags are exactly AT_EMPTY_PATH"),
        _allow("access"),
        _ARCH_SET_FS,
        _allow("faccessat2"),
        _allow("getegid"),
        _allow("getgid"),
        _allow("gettid"),
        _allow("getuid"),
        _allow("prlimit64"),
        _allow("readlink"),
        _allow("rseq"),
        _allow("set_robust_list"),
        _allow("set_tid_address"),
        _allow("statx"),
        _allow("uname"),
    )
    post_child = (
        _WRITE,
        _READ_ONLY_OPENAT,
        _allow("fcntl", "command is exactly F_GETFD"),
        _NONEXEC_MMAP,
        _allow("read"),
        _allow("close"),
        _allow("lseek"),
        _allow("munmap"),
        _allow("rt_sigaction"),
        _allow("rt_sigreturn"),
        _allow("pread64"),
        _allow("madvise"),
        _allow("geteuid"),
        _allow("getegid"),
        _allow("getpid"),
        _allow("exit"),
        _allow("exit_group"),
        _allow("newfstatat"),
        _allow("fstat"),
        _allow("fstatfs"),
        _allow("mlock"),
        _allow("munlock"),
        _allow("gettid"),
        _UNLINKAT,
    )
    return (
        ("initial", 0, initial),
        ("child_exec", 2, child_exec),
        ("post_child", 1, post_child),
    )


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _compiler() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        _fail("a C compiler is required to build canonical seccomp evidence")
    return compiler


def _run(command: Sequence[str]) -> bytes:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        _fail(
            f"seccomp evidence command failed ({completed.returncode}):\n"
            + completed.stdout.decode(errors="replace")
        )
    return completed.stdout


def _syscall_names() -> tuple[str, ...]:
    names = {
        str(rule["syscall"])
        for profile in PROFILE_MACROS
        for _phase, _number, rules in _policies(profile)
        for rule in rules
    }
    names.update(("clone3", "execve", "fork", "setns", "socketpair", "unshare", "vfork"))
    return tuple(sorted(names))


def _syscall_numbers(build: Path) -> dict[str, int]:
    source = build / "syscall_numbers.c"
    executable = build / "syscall_numbers"
    lines = ["#include <stdio.h>", "#include <sys/syscall.h>", "int main(void) {"]
    for name in _syscall_names():
        lines.append(f'  printf("{name}=%ld\\n", (long)__NR_{name});')
    lines.extend(("  return 0;", "}"))
    source.write_text("\n".join(lines) + "\n", encoding="ascii")
    _run(
        (
            _compiler(),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(executable),
        )
    )
    result: dict[str, int] = {}
    for line in _run((str(executable),)).decode("ascii").splitlines():
        name, value = line.split("=", 1)
        result[name] = int(value)
    if tuple(sorted(result)) != _syscall_names() or len(set(result.values())) != len(result):
        _fail("the x86_64 syscall-number map is incomplete or aliased")
    return result


def _compiled_filters(build: Path, profile: str) -> dict[str, bytes]:
    executable = build / f"seccomp-{profile}"
    _run(
        (
            _compiler(),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-Wshadow",
            "-Wpedantic",
            "-Werror",
            f"-D{PROFILE_MACROS[profile]}=1",
            f"-I{NATIVE}",
            str(SECCOMP_SOURCE),
            str(HARNESS),
            "-o",
            str(executable),
        )
    )
    return {
        phase: _run((str(executable), str(number))) for phase, number, _rules in _policies(profile)
    }


def _syscall_selectors(payload: bytes) -> tuple[int, ...]:
    if not payload or len(payload) % 8:
        _fail("compiled classic-BPF bytes are malformed")
    instructions = tuple(struct.iter_unpack("<HBBI", payload))
    origins: dict[int, set[str]] = {0: {"unknown"}}
    pending = [0]
    while pending:
        index = pending.pop()
        if index >= len(instructions):
            _fail("classic-BPF control flow exits the instruction array")
        code, jump_true, jump_false, constant = instructions[index]
        incoming = origins[index]
        targets: tuple[int, ...]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            outgoing = {"nr" if constant == 0 else "arch" if constant == 4 else "argument"}
            targets = (index + 1,)
        elif code in (0x15, 0x45):  # BPF_JEQ/JSET | BPF_K
            outgoing = incoming
            targets = (index + 1 + jump_true, index + 1 + jump_false)
        elif code == 0x06:  # BPF_RET | BPF_K
            continue
        else:
            _fail(f"unsupported classic-BPF instruction 0x{code:04x}")
        for target in targets:
            if target >= len(instructions):
                _fail("classic-BPF jump exits the instruction array")
            previous = origins.setdefault(target, set())
            update = outgoing - previous
            if update:
                previous.update(update)
                pending.append(target)
    selectors = []
    for index, (code, _jump_true, _jump_false, constant) in enumerate(instructions):
        if code == 0x15 and "nr" in origins.get(index, set()):
            selectors.append(constant)
    return tuple(selectors)


def evaluate_classic_bpf(
    payload: bytes,
    *,
    architecture: int,
    syscall_number: int,
    arguments: Sequence[int] = (0, 0, 0, 0, 0, 0),
) -> int:
    """Interpret the small verified classic-BPF subset used by these filters."""

    if len(arguments) != 6 or any(value < 0 or value > 0xFFFFFFFFFFFFFFFF for value in arguments):
        _fail("seccomp interpreter arguments must be six unsigned 64-bit integers")
    if syscall_number < -(1 << 31) or syscall_number >= (1 << 32):
        _fail("seccomp interpreter syscall number is outside the 32-bit field")
    encoded_number = syscall_number & 0xFFFFFFFF
    seccomp_data = struct.pack(
        "<IIQ6Q",
        encoded_number,
        architecture & 0xFFFFFFFF,
        0,
        *arguments,
    )
    instructions = tuple(struct.iter_unpack("<HBBI", payload))
    accumulator = 0
    program_counter = 0
    for _step in range(len(instructions) + 1):
        if program_counter >= len(instructions):
            _fail("classic-BPF interpreter escaped the filter")
        code, jump_true, jump_false, constant = instructions[program_counter]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            if constant + 4 > len(seccomp_data):
                _fail("classic-BPF absolute load exceeds seccomp_data")
            accumulator = int.from_bytes(seccomp_data[constant : constant + 4], "little")
            program_counter += 1
        elif code == 0x15:  # BPF_JMP | BPF_JEQ | BPF_K
            program_counter += 1 + (jump_true if accumulator == constant else jump_false)
        elif code == 0x45:  # BPF_JMP | BPF_JSET | BPF_K
            program_counter += 1 + (jump_true if accumulator & constant else jump_false)
        elif code == 0x06:  # BPF_RET | BPF_K
            return int(constant)
        else:
            _fail(f"unsupported classic-BPF instruction 0x{code:04x}")
    _fail("classic-BPF interpreter exceeded the acyclic instruction bound")


def _phase_document(
    name: str,
    payload: bytes,
    rules: Iterable[dict[str, object]],
    syscall_numbers: dict[str, int],
) -> dict[str, object]:
    numbered_rules = []
    expected_numbers = []
    for rule in rules:
        numbered = dict(rule)
        number = syscall_numbers[str(rule["syscall"])]
        numbered["number"] = number
        numbered_rules.append(numbered)
        expected_numbers.append(number)
    actual_numbers = _syscall_selectors(payload)
    if actual_numbers != tuple(expected_numbers):
        _fail(
            f"{name} compiled syscall selectors differ from the ordered policy: "
            f"{actual_numbers!r} != {tuple(expected_numbers)!r}"
        )
    if (
        evaluate_classic_bpf(
            payload,
            architecture=0,
            syscall_number=syscall_numbers["read"],
        )
        != SECCOMP_RET_KILL_PROCESS
        or evaluate_classic_bpf(
            payload,
            architecture=AUDIT_ARCH_X86_64,
            syscall_number=0x40000000 | syscall_numbers["read"],
        )
        != SECCOMP_RET_KILL_PROCESS
    ):
        _fail(f"{name} does not kill architecture or x32 namespace mismatches")
    declared = set(expected_numbers)
    for syscall_number in range(1024):
        if syscall_number not in declared and (
            evaluate_classic_bpf(
                payload,
                architecture=AUDIT_ARCH_X86_64,
                syscall_number=syscall_number,
            )
            != SECCOMP_RET_ERRNO_EPERM
        ):
            _fail(f"{name} unexpectedly permits syscall number {syscall_number}")
    return {
        "bpf_instruction_count": len(payload) // 8,
        "bpf_sha256": _sha256(payload),
        "bpf_size": len(payload),
        "default_action": "errno:EPERM",
        "ordered_syscall_policy": numbered_rules,
        "phase": name,
    }


def build_documents() -> dict[str, bytes]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        _fail("canonical seccomp BPF may be built only on Linux x86_64")
    source_bytes = SECCOMP_SOURCE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="aqt-wave7-seccomp-") as temporary:
        build = Path(temporary)
        syscall_numbers = _syscall_numbers(build)
        documents: dict[str, bytes] = {}
        for profile in PROFILE_MACROS:
            compiled = _compiled_filters(build, profile)
            phases = [
                _phase_document(name, compiled[name], rules, syscall_numbers)
                for name, _number, rules in _policies(profile)
            ]
            document: dict[str, object] = {
                "activation_authorized": False,
                "architecture": {
                    "audit_arch": "AUDIT_ARCH_X86_64",
                    "audit_arch_value": AUDIT_ARCH_X86_64,
                    "elf_machine": "EM_X86_64",
                    "endianness": "little",
                    "linux_machine": "x86_64",
                },
                "capability_tuple": CAPABILITY_TUPLES[profile],
                "format": FORMAT,
                "phases": phases,
                "policy_model": POLICY_MODEL,
                "profile": profile,
                "seccomp_source": {
                    "path": "native/trusted_time_v2_seccomp.c",
                    "sha256": _sha256(source_bytes),
                },
            }
            if profile == "provisioner":
                initial = compiled["initial"]
                child_exec = compiled["child_exec"]
                post_child = compiled["post_child"]
                if (
                    evaluate_classic_bpf(
                        initial,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["clone"],
                        arguments=(0x01200011, 0, 0, 0, 0, 0),
                    )
                    != SECCOMP_RET_ALLOW
                    or evaluate_classic_bpf(
                        initial,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["clone"],
                    )
                    != SECCOMP_RET_ERRNO_EPERM
                    or evaluate_classic_bpf(
                        initial,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["clone"],
                        arguments=(0x0000000101200011, 0, 0, 0, 0, 0),
                    )
                    != SECCOMP_RET_ERRNO_EPERM
                    or evaluate_classic_bpf(
                        child_exec,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["execveat"],
                        arguments=(64, 0, 0, 0, 0x1000, 0),
                    )
                    != SECCOMP_RET_ALLOW
                    or any(
                        evaluate_classic_bpf(
                            payload,
                            architecture=AUDIT_ARCH_X86_64,
                            syscall_number=syscall_numbers["arch_prctl"],
                            arguments=(ARCH_SET_FS, 0x7F0012345000, 0, 0, 0, 0),
                        )
                        != SECCOMP_RET_ALLOW
                        for payload in (initial, child_exec)
                    )
                    or any(
                        evaluate_classic_bpf(
                            payload,
                            architecture=AUDIT_ARCH_X86_64,
                            syscall_number=syscall_numbers["arch_prctl"],
                            arguments=(0x1001, 0x7F0012345000, 0, 0, 0, 0),
                        )
                        != SECCOMP_RET_ERRNO_EPERM
                        for payload in (initial, child_exec)
                    )
                    or any(
                        evaluate_classic_bpf(
                            payload,
                            architecture=AUDIT_ARCH_X86_64,
                            syscall_number=syscall_numbers["arch_prctl"],
                            arguments=(0x0000000100001002, 0x7F0012345000, 0, 0, 0, 0),
                        )
                        != SECCOMP_RET_ERRNO_EPERM
                        for payload in (initial, child_exec)
                    )
                    or evaluate_classic_bpf(
                        post_child,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["clone"],
                    )
                    != SECCOMP_RET_ERRNO_EPERM
                    or evaluate_classic_bpf(
                        post_child,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["execveat"],
                    )
                    != SECCOMP_RET_ERRNO_EPERM
                    or evaluate_classic_bpf(
                        post_child,
                        architecture=AUDIT_ARCH_X86_64,
                        syscall_number=syscall_numbers["arch_prctl"],
                        arguments=(ARCH_SET_FS, 0x7F0012345000, 0, 0, 0, 0),
                    )
                    != SECCOMP_RET_ERRNO_EPERM
                ):
                    _fail("the provisioner phase filters misstate process authority")
                document["process_authority"] = {
                    "child_exec_phase_exec_authority": ("exact-fd64-execveat-at-empty-path"),
                    "initial_phase_process_creation_denied": False,
                    "one_pinned_systemd_creds_child": True,
                    "post_child_phase_process_creation_denied": True,
                }
            else:
                document["process_authority"] = {
                    "initial_phase_process_creation_denied": True,
                    "one_pinned_systemd_creds_child": False,
                }
            documents[profile] = _canonical(document)
    return documents


def verify_static_documents() -> None:
    source_sha256 = _sha256(SECCOMP_SOURCE.read_bytes())
    expected_paths = {f"{profile}.json" for profile in PROFILE_MACROS}
    actual_paths = {path.name for path in MANIFEST_ROOT.glob("*.json")}
    if actual_paths != expected_paths:
        _fail(f"canonical seccomp manifest paths differ: {actual_paths!r}")
    for profile in PROFILE_MACROS:
        path = MANIFEST_ROOT / f"{profile}.json"
        payload = path.read_bytes()
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SeccompManifestError(f"{path} is not canonical JSON") from error
        if payload != _canonical(document):
            _fail(f"{path} is not encoded as canonical JSON")
        if document.get("format") != FORMAT or document.get("profile") != profile:
            _fail(f"{path} has the wrong format or profile")
        if document.get("activation_authorized") is not False:
            _fail(f"{path} must remain non-authorizing")
        source = document.get("seccomp_source")
        if source != {
            "path": "native/trusted_time_v2_seccomp.c",
            "sha256": source_sha256,
        }:
            _fail(f"{path} does not bind the exact seccomp source")
        if document.get("capability_tuple") != CAPABILITY_TUPLES[profile]:
            _fail(f"{path} does not contain the exact role capability tuple")


def verify_compiled_documents() -> None:
    expected = build_documents()
    for profile, payload in expected.items():
        path = MANIFEST_ROOT / f"{profile}.json"
        if path.read_bytes() != payload:
            _fail(f"{path} differs from the compiled x86_64 BPF evidence")


def write_documents() -> None:
    documents = build_documents()
    MANIFEST_ROOT.mkdir(parents=True, exist_ok=True)
    for profile, payload in documents.items():
        (MANIFEST_ROOT / f"{profile}.json").write_bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.write:
        write_documents()
    else:
        verify_static_documents()
        if platform.system() == "Linux" and platform.machine() == "x86_64":
            verify_compiled_documents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
