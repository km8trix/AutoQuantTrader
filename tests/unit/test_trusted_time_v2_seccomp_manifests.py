from __future__ import annotations

import json
import platform
import tempfile
from pathlib import Path

import pytest

from build_support import trusted_time_v2_seccomp_manifests as manifests


def test_canonical_manifests_are_exact_non_authorizing_source_bound_documents() -> None:
    manifests.verify_static_documents()
    for profile in manifests.PROFILE_MACROS:
        path = manifests.MANIFEST_ROOT / f"{profile}.json"
        document = json.loads(path.read_bytes())
        assert document["activation_authorized"] is False
        assert document["architecture"] == {
            "audit_arch": "AUDIT_ARCH_X86_64",
            "audit_arch_value": manifests.AUDIT_ARCH_X86_64,
            "elf_machine": "EM_X86_64",
            "endianness": "little",
            "linux_machine": "x86_64",
        }
        assert document["policy_model"] == manifests.POLICY_MODEL
        assert all(phase["default_action"] == "errno:EPERM" for phase in document["phases"])


def test_provisioner_manifest_truthfully_separates_process_authority_phases() -> None:
    document = json.loads((manifests.MANIFEST_ROOT / "provisioner.json").read_bytes())
    assert document["process_authority"] == {
        "child_exec_phase_exec_authority": "exact-fd64-execveat-at-empty-path",
        "initial_phase_process_creation_denied": False,
        "one_pinned_systemd_creds_child": True,
        "post_child_phase_process_creation_denied": True,
    }
    assert [phase["phase"] for phase in document["phases"]] == [
        "initial",
        "child_exec",
        "post_child",
    ]


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "x86_64",
    reason="canonical BPF is qualified on Linux x86_64",
)
def test_compiled_bpf_is_reproducible_and_matches_every_canonical_manifest() -> None:
    first = manifests.build_documents()
    second = manifests.build_documents()
    assert first == second
    assert first == {
        profile: (manifests.MANIFEST_ROOT / f"{profile}.json").read_bytes()
        for profile in manifests.PROFILE_MACROS
    }


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "x86_64",
    reason="canonical BPF is qualified on Linux x86_64",
)
def test_compiled_bpf_has_no_hidden_syscall_or_process_authority() -> None:
    with tempfile.TemporaryDirectory(prefix="aqt-wave7-seccomp-test-") as temporary:
        build = Path(temporary)
        numbers = manifests._syscall_numbers(build)
        compiled = {
            profile: manifests._compiled_filters(build, profile)
            for profile in manifests.PROFILE_MACROS
        }

    documents = {
        profile: json.loads((manifests.MANIFEST_ROOT / f"{profile}.json").read_bytes())
        for profile in manifests.PROFILE_MACROS
    }
    for profile, phases in compiled.items():
        for phase_name, payload in phases.items():
            phase = next(
                item for item in documents[profile]["phases"] if item["phase"] == phase_name
            )
            declared = tuple(rule["number"] for rule in phase["ordered_syscall_policy"])
            assert manifests._syscall_selectors(payload) == declared
            assert (
                manifests.evaluate_classic_bpf(
                    payload,
                    architecture=0,
                    syscall_number=numbers["read"],
                )
                == manifests.SECCOMP_RET_KILL_PROCESS
            )
            assert (
                manifests.evaluate_classic_bpf(
                    payload,
                    architecture=manifests.AUDIT_ARCH_X86_64,
                    syscall_number=0x40000000 | numbers["read"],
                )
                == manifests.SECCOMP_RET_KILL_PROCESS
            )
            declared_set = set(declared)
            for syscall_number in range(1024):
                if syscall_number not in declared_set:
                    assert (
                        manifests.evaluate_classic_bpf(
                            payload,
                            architecture=manifests.AUDIT_ARCH_X86_64,
                            syscall_number=syscall_number,
                        )
                        == manifests.SECCOMP_RET_ERRNO_EPERM
                    )

    forbidden_process = ("fork", "vfork", "clone3", "execve", "unshare", "setns")
    for profile in ("host", "supervisor", "recovery"):
        payload = compiled[profile]["initial"]
        for syscall in forbidden_process:
            assert (
                manifests.evaluate_classic_bpf(
                    payload,
                    architecture=manifests.AUDIT_ARCH_X86_64,
                    syscall_number=numbers[syscall],
                )
                == manifests.SECCOMP_RET_ERRNO_EPERM
            )

    recovery = compiled["recovery"]["initial"]
    for syscall in ("socket", "socketpair", "connect", "bind", "sendmsg", "recvmsg"):
        assert (
            manifests.evaluate_classic_bpf(
                recovery,
                architecture=manifests.AUDIT_ARCH_X86_64,
                syscall_number=numbers[syscall],
            )
            == manifests.SECCOMP_RET_ERRNO_EPERM
        )

    initial = compiled["provisioner"]["initial"]
    assert (
        manifests.evaluate_classic_bpf(
            initial,
            architecture=manifests.AUDIT_ARCH_X86_64,
            syscall_number=numbers["clone"],
            arguments=(0x01200011, 0, 0, 0, 0, 0),
        )
        == manifests.SECCOMP_RET_ALLOW
    )
    assert (
        manifests.evaluate_classic_bpf(
            initial,
            architecture=manifests.AUDIT_ARCH_X86_64,
            syscall_number=numbers["clone"],
        )
        == manifests.SECCOMP_RET_ERRNO_EPERM
    )
    assert (
        manifests.evaluate_classic_bpf(
            initial,
            architecture=manifests.AUDIT_ARCH_X86_64,
            syscall_number=numbers["clone"],
            arguments=(0x0000000101200011, 0, 0, 0, 0, 0),
        )
        == manifests.SECCOMP_RET_ERRNO_EPERM
    )
    child_exec = compiled["provisioner"]["child_exec"]
    assert (
        manifests.evaluate_classic_bpf(
            child_exec,
            architecture=manifests.AUDIT_ARCH_X86_64,
            syscall_number=numbers["execveat"],
            arguments=(64, 0, 0, 0, 0x1000, 0),
        )
        == manifests.SECCOMP_RET_ALLOW
    )
    post_child = compiled["provisioner"]["post_child"]
    for syscall in (*forbidden_process, "execveat", "clone"):
        assert (
            manifests.evaluate_classic_bpf(
                post_child,
                architecture=manifests.AUDIT_ARCH_X86_64,
                syscall_number=numbers[syscall],
            )
            == manifests.SECCOMP_RET_ERRNO_EPERM
        )
