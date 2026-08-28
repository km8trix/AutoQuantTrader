from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
VENDOR = ROOT / "third_party" / "monocypher" / "4.0.3"
HARNESS = ROOT / "tests" / "native" / "trusted_time_v2_guard_signer_harness.c"

ROLE_METHODS = {
    "host": {
        "aqt_trusted_time_v2_signer_sign_host_hello",
        "aqt_trusted_time_v2_signer_sign_host_channel_confirmation",
        "aqt_trusted_time_v2_signer_sign_clean_stop_request",
    },
    "supervisor": {
        "aqt_trusted_time_v2_signer_sign_supervisor_hello",
        "aqt_trusted_time_v2_signer_sign_clean_stop_result",
        "aqt_trusted_time_v2_signer_sign_clean_stop_error",
        "aqt_trusted_time_v2_signer_sign_supervisor_cleanup_commitment",
    },
    "recovery": {
        "aqt_trusted_time_v2_signer_sign_recovery_classification",
    },
}
ROLE_CREDENTIALS = {
    "host": (
        "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets",
        "host-ed25519.raw",
    ),
    "supervisor": (
        "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets",
        "supervisor-ed25519.raw",
    ),
    "recovery": (
        "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets",
        "recovery-ed25519.raw",
    ),
}
ALL_ROLE_METHODS = set().union(*ROLE_METHODS.values())
EXPECTED_CRYPTO_REFERENCES = {
    "crypto_ed25519_check",
    "crypto_ed25519_key_pair",
    "crypto_ed25519_sign",
    "crypto_wipe",
}


def _compiler() -> str:
    compiler = os.environ.get("CC") or shutil.which("cc")
    if not compiler:
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
        "-Werror=implicit-function-declaration",
        "-Werror=return-type",
        "-pthread",
        f"-I{NATIVE}",
        f"-I{VENDOR / 'src'}",
        f"-I{VENDOR / 'src' / 'optional'}",
    ]


def _role_definition(role: str) -> str:
    return f"-DAQT_TRUSTED_TIME_V2_SIGNER_{role.upper()}_PROFILE"


@pytest.fixture(scope="module")
def compiled_native_lane(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    build_directory = tmp_path_factory.mktemp("trusted-time-v2-native")
    compiler = _compiler()
    outputs: dict[str, Path] = {}
    for role in ROLE_METHODS:
        executable = build_directory / f"{role}-harness"
        command = [
            compiler,
            *_strict_flags(),
            _role_definition(role),
            "-DAQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE",
            "-DAQT_TRUSTED_TIME_V2_SIGNER_TESTING",
            "-DAQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING",
            str(NATIVE / "trusted_time_v2_fork_guard.c"),
            str(NATIVE / "trusted_time_graceful_stop_v2_signer.c"),
            str(HARNESS),
            str(VENDOR / "src" / "monocypher.c"),
            str(VENDOR / "src" / "optional" / "monocypher-ed25519.c"),
            "-o",
            str(executable),
        ]
        subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
        outputs[role] = executable

        signer_object = build_directory / f"{role}-signer.o"
        subprocess.run(
            [
                compiler,
                *_strict_flags(),
                _role_definition(role),
                "-c",
                str(NATIVE / "trusted_time_graceful_stop_v2_signer.c"),
                "-o",
                str(signer_object),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        outputs[f"{role}-object"] = signer_object
    return outputs


def test_vendored_monocypher_manifest_is_exact() -> None:
    manifest = json.loads((VENDOR / "VENDORING.json").read_text(encoding="utf-8"))
    assert manifest == {
        **manifest,
        "schema": "autoquant-vendored-native-source-v1",
        "tag": "4.0.3",
        "commit": "ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f",
        "license_expression": "BSD-2-Clause OR CC0-1.0",
        "patches": [],
    }
    assert manifest["archive"] == {
        "name": "monocypher-4.0.3.tar.gz",
        "url": "https://monocypher.org/download/monocypher-4.0.3.tar.gz",
        "sha512": (
            "40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d5402"
            "51ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965"
        ),
    }
    recorded_files = {entry["path"]: entry for entry in manifest["files"]}
    assert set(recorded_files) == {
        "LICENCE.md",
        "src/monocypher.c",
        "src/monocypher.h",
        "src/optional/monocypher-ed25519.c",
        "src/optional/monocypher-ed25519.h",
    }
    for relative_path, entry in recorded_files.items():
        contents = (VENDOR / relative_path).read_bytes()
        assert len(contents) == entry["size"]
        assert hashlib.sha256(contents).hexdigest() == entry["sha256"]


def test_rfc8032_basic_vectors(compiled_native_lane: dict[str, Path]) -> None:
    subprocess.run(
        [compiled_native_lane["host"], "rfc8032"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


@pytest.mark.parametrize("role", tuple(ROLE_METHODS))
def test_role_signer_lifecycle(compiled_native_lane: dict[str, Path], role: str) -> None:
    subprocess.run(
        [compiled_native_lane[role], "signer"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def test_fork_during_odd_table_generation_poisons_parent_and_child(
    compiled_native_lane: dict[str, Path],
) -> None:
    subprocess.run(
        [compiled_native_lane["host"], "guard-race"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def test_prepare_then_guarded_close_cannot_leak_descriptor_to_child(
    compiled_native_lane: dict[str, Path],
) -> None:
    subprocess.run(
        [compiled_native_lane["host"], "guard-prepare-close-race"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def test_concurrent_fork_prepares_poison_every_process(
    compiled_native_lane: dict[str, Path],
) -> None:
    subprocess.run(
        [compiled_native_lane["host"], "guard-concurrent-prepares"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def test_native_signatures_match_existing_python_signature_inputs(
    compiled_native_lane: dict[str, Path], tmp_path: Path
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from packages.adapters.trusted_time import graceful_stop_v2_ed25519 as ed25519_adapter
    from tests.unit import test_trusted_time_graceful_stop_v2_transport_contracts as vectors

    manifest = vectors._manifest()
    host_hello = vectors._host_hello(manifest)
    root = vectors._root(manifest)
    intent = vectors._intent(root)
    envelope = vectors._envelope(root, intent, frame_type="clean_stop_request")
    transcript = vectors._classified_transcript(root, intent)
    recovery = vectors._recovery_envelope(root, transcript, manifest)

    envelope_signature_input = ed25519_adapter._transport_envelope_signature_input(envelope)
    envelope_unsigned = envelope_signature_input.split(b"\0", 1)[1]
    cross_vectors = (
        ("host", "host-hello", host_hello.unsigned_encoded, host_hello.signature_input),
        ("host", "clean-stop-request", envelope_unsigned, envelope_signature_input),
        (
            "recovery",
            "recovery-classification",
            recovery.unsigned_encoded,
            recovery.signature_input,
        ),
    )
    public_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    ).public_key()

    for role, operation, unsigned_encoded, signature_input in cross_vectors:
        assert unsigned_encoded.endswith(b"}\n")
        assert signature_input.endswith(unsigned_encoded)
        message_path = tmp_path / f"{operation}.json"
        message_path.write_bytes(unsigned_encoded)
        completed = subprocess.run(
            [compiled_native_lane[role], "python-cross", operation, message_path],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        signature = bytes.fromhex(completed.stdout.strip())
        assert len(signature) == 64
        public_key.verify(signature, signature_input)


@pytest.mark.parametrize("role", tuple(ROLE_METHODS))
def test_production_role_object_has_closed_symbol_surface(
    compiled_native_lane: dict[str, Path], role: str
) -> None:
    nm = shutil.which("nm")
    if not nm:
        pytest.skip("nm is required for the native symbol audit")
    output = subprocess.run(
        [nm, "-g", compiled_native_lane[f"{role}-object"]],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    for method in ROLE_METHODS[role]:
        assert method in output
    for method in ALL_ROLE_METHODS - ROLE_METHODS[role]:
        assert method not in output
    assert not re.search(r"_?aqt_trusted_time_v2_signer_sign(?:\s|$)", output)
    crypto_references = set(re.findall(r"\b_?(crypto_[A-Za-z0-9_]+)\b", output))
    assert crypto_references == EXPECTED_CRYPTO_REFERENCES
    assert all(forbidden not in output for forbidden in ("dlopen", "dlsym", "EVP_", "sodium"))
    assert "aqt_trusted_time_v2_signer_initialize_before_python" in output
    assert "aqt_trusted_time_v2_signer_owner_open" in output
    assert "aqt_trusted_time_v2_signer_owner_open_preopened" not in output
    assert "aqt_trusted_time_v2_signer_test_" not in output

    strings = shutil.which("strings")
    if strings:
        literals = subprocess.run(
            [strings, compiled_native_lane[f"{role}-object"]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        for candidate_role, credential_literals in ROLE_CREDENTIALS.items():
            for literal in credential_literals:
                assert (literal in literals) is (candidate_role == role)
        assert "credential.raw" not in literals


@pytest.mark.parametrize("role", tuple(ROLE_METHODS))
def test_native_harness_adds_no_crypto_shared_library_dependency(
    compiled_native_lane: dict[str, Path], role: str
) -> None:
    if platform.system() == "Darwin":
        command = ["otool", "-L", compiled_native_lane[role]]
    elif platform.system() == "Linux":
        command = ["ldd", compiled_native_lane[role]]
    else:
        pytest.skip("shared-library audit is supported on Linux and macOS")
    output = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.lower()
    assert all(name not in output for name in ("libcrypto", "libssl", "libsodium", "monocypher"))
