from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sysconfig
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from packages.adapters.trusted_time.graceful_stop_v2_ed25519 import (
    LifecycleV2TransportAuthenticationError,
    authenticate_lifecycle_v2_transport_authority,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
VENDOR = ROOT / "third_party" / "monocypher" / "4.0.3" / "src"
OPTIONAL = VENDOR / "optional"
HARNESS = ROOT / "tests" / "native" / "trusted_time_v2_authority_harness.c"
NO_PIN_HARNESS = ROOT / "tests" / "native" / "trusted_time_v2_authority_no_pin_harness.c"
AUTHORITY = NATIVE / "trusted_time_v2_authority.c"
FORK_GUARD = NATIVE / "trusted_time_v2_fork_guard.c"
SECRET_MOUNT_ADMISSION = NATIVE / "trusted_time_v2_secret_mount_admission.c"
MONOCYPHER = VENDOR / "monocypher.c"
MONOCYPHER_ED25519 = OPTIONAL / "monocypher-ed25519.c"

ROOT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ROOT_KEY_ID = "trusted-time-transport-root-ed25519-v1"
ENVIRONMENT = "test"
MANIFEST_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/transport-authority/v1"
SELECTION_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/transport-authority-selection/v1"


def _compiler() -> str:
    configured = sysconfig.get_config_var("CC")
    assert type(configured) is str and configured
    executable = shutil.which(configured.split()[0])
    assert executable is not None
    return executable


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def _canonical(fields: dict[str, object]) -> bytes:
    return (
        json.dumps(
            fields,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _signed(
    fields: dict[str, object],
    domain: str,
    *,
    signer: Ed25519PrivateKey = ROOT_PRIVATE_KEY,
) -> bytes:
    signature = signer.sign(domain.encode("ascii") + b"\0" + _canonical(fields))
    return _canonical(
        {**fields, "signature_ed25519_base64": base64.b64encode(signature).decode("ascii")}
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class AuthorityFixture:
    path: Path
    manifest_bytes: tuple[bytes, ...]
    manifest_sha256: tuple[str, ...]
    role_public_keys: tuple[tuple[bytes, bytes, bytes], ...]
    selection_bytes: tuple[bytes, ...]
    selection_sha256: tuple[str, ...]

    def make_mutable(self) -> None:
        self.path.chmod(0o700)
        for child in self.path.iterdir():
            if not child.is_symlink():
                child.chmod(0o600)

    def freeze(self) -> None:
        for child in self.path.iterdir():
            if not child.is_symlink():
                child.chmod(0o400)
        self.path.chmod(0o500)


def _build_authority(
    path: Path,
    *,
    bad_manifest_signature: bool = False,
    noncanonical_last_manifest: bool = False,
    reuse_role_key: bool = False,
    terminal_denial: bool = False,
    recovery_generation: int | None = 2,
    wrong_environment: bool = False,
    wrong_root_id: bool = False,
    bad_base64: bool = False,
    extra_manifest_field: bool = False,
    bad_manifest_predecessor: bool = False,
    bad_selection_signature: bool = False,
    bad_selection_predecessor: bool = False,
) -> AuthorityFixture:
    path.mkdir(mode=0o700)
    root_public_key = _public_key(ROOT_PRIVATE_KEY)
    (path / "root-ed25519.pub").write_bytes(root_public_key)
    manifest_bytes: list[bytes] = []
    manifest_sha256: list[str] = []
    role_public_keys: list[tuple[bytes, bytes, bytes]] = []
    predecessor: str | None = None
    first_role_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey] | None = None
    for generation in (1, 2):
        role_keys = tuple(
            _key(f"{role}-g{generation}") for role in ("host", "supervisor", "recovery")
        )
        if first_role_keys is None:
            first_role_keys = role_keys
        if reuse_role_key and generation == 2:
            role_keys = (first_role_keys[0], role_keys[1], role_keys[2])
        public_keys = tuple(_public_key(key) for key in role_keys)
        fields: dict[str, object] = {
            "contract_version": "phase6d-trusted-time-graceful-stop-transport-authority-v1",
            "service": "trusted-time-graceful-stop-transport-v2",
            "status": "transport_authority_manifest_issued",
            "environment": "wrong" if wrong_environment and generation == 2 else ENVIRONMENT,
            "generation": generation,
            "root_key_id": "wrong-root-id" if wrong_root_id and generation == 2 else ROOT_KEY_ID,
            "predecessor_manifest_sha256": (
                "f" * 64 if bad_manifest_predecessor and generation == 2 else predecessor
            ),
            "host_key_id": f"host-transport-g{generation}",
            "host_public_key_base64": base64.b64encode(public_keys[0]).decode("ascii"),
            "supervisor_key_id": f"supervisor-transport-g{generation}",
            "supervisor_public_key_base64": base64.b64encode(public_keys[1]).decode("ascii"),
            "recovery_key_id": f"recovery-transport-g{generation}",
            "recovery_public_key_base64": base64.b64encode(public_keys[2]).decode("ascii"),
        }
        if bad_base64 and generation == 2:
            fields["host_public_key_base64"] = "!" * 44
        if extra_manifest_field and generation == 2:
            fields["unexpected"] = "field"
        signer = (
            _key("wrong-root") if bad_manifest_signature and generation == 2 else ROOT_PRIVATE_KEY
        )
        encoded = _signed(fields, MANIFEST_DOMAIN, signer=signer)
        if noncanonical_last_manifest and generation == 2:
            encoded = encoded[:-1] + b" \n"
        digest = _sha256(encoded)
        name = f"transport-authority-manifest-g{generation:08d}-{digest}.json"
        (path / name).write_bytes(encoded)
        manifest_bytes.append(encoded)
        manifest_sha256.append(digest)
        role_public_keys.append(public_keys)
        predecessor = digest

    selection_bytes: list[bytes] = []
    selection_sha256: list[str] = []
    predecessor = None
    for sequence, generation in ((1, 1), (2, 2)):
        fields = {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-transport-authority-selection-v1"
            ),
            "service": "trusted-time-graceful-stop-transport-v2",
            "status": "transport_authority_selection_recorded",
            "environment": ENVIRONMENT,
            "selection_sequence": sequence,
            "disposition": "generation_selected",
            "selected_manifest_sha256": manifest_sha256[generation - 1],
            "selected_generation": generation,
            "recovery_manifest_sha256": manifest_sha256[generation - 1],
            "predecessor_selection_sha256": (
                "e" * 64 if bad_selection_predecessor and sequence == 2 else predecessor
            ),
            "reason_code": "initial" if sequence == 1 else "rotation",
        }
        selection_signer = (
            _key("wrong-selection-root")
            if bad_selection_signature and sequence == 2
            else ROOT_PRIVATE_KEY
        )
        encoded = _signed(fields, SELECTION_DOMAIN, signer=selection_signer)
        digest = _sha256(encoded)
        name = f"transport-authority-selection-s{sequence:08d}-{digest}.json"
        (path / name).write_bytes(encoded)
        selection_bytes.append(encoded)
        selection_sha256.append(digest)
        predecessor = digest

    if terminal_denial:
        fields = {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-transport-authority-selection-v1"
            ),
            "service": "trusted-time-graceful-stop-transport-v2",
            "status": "transport_authority_selection_recorded",
            "environment": ENVIRONMENT,
            "selection_sequence": 3,
            "disposition": "new_roots_denied",
            "selected_manifest_sha256": None,
            "selected_generation": None,
            "recovery_manifest_sha256": (
                manifest_sha256[recovery_generation - 1]
                if recovery_generation is not None
                else None
            ),
            "predecessor_selection_sha256": predecessor,
            "reason_code": "administrative_hold",
        }
        encoded = _signed(fields, SELECTION_DOMAIN)
        digest = _sha256(encoded)
        (path / f"transport-authority-selection-s00000003-{digest}.json").write_bytes(encoded)
        selection_bytes.append(encoded)
        selection_sha256.append(digest)

    (path / "selection.json").write_bytes(selection_bytes[-1])
    result = AuthorityFixture(
        path=path,
        manifest_bytes=tuple(manifest_bytes),
        manifest_sha256=tuple(manifest_sha256),
        role_public_keys=tuple(role_public_keys),
        selection_bytes=tuple(selection_bytes),
        selection_sha256=tuple(selection_sha256),
    )
    result.freeze()
    return result


@pytest.fixture(scope="module")
def authority_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("native-authority-build") / "authority-harness"
    command = [
        _compiler(),
        "-std=c11",
        "-O2",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror",
        "-DAQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE=1",
        "-DAQT_TRUSTED_TIME_V2_AUTHORITY_TESTING=1",
        "-DAQT_TRUSTED_TIME_V2_AUTHORITY_TEST_ROOT_PIN=1",
        f"-I{NATIVE}",
        f"-I{VENDOR}",
        f"-I{OPTIONAL}",
        str(HARNESS),
        str(AUTHORITY),
        str(FORK_GUARD),
        str(MONOCYPHER),
        str(MONOCYPHER_ED25519),
        "-o",
        str(output),
    ]
    subprocess.run(command, check=True, capture_output=True)
    return output


def _run(
    harness: Path,
    fixture: AuthorityFixture,
    role: str,
    *,
    action: str = "consume",
    recovery_generation: int | None = None,
    recovery_manifest_sha256: str | None = None,
    extra: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    command = [str(harness), action, role, str(fixture.path)]
    if role == "recovery":
        command.extend(
            (
                str(recovery_generation if recovery_generation is not None else 2),
                recovery_manifest_sha256 or fixture.manifest_sha256[-1],
            )
        )
    command.extend(extra)
    return subprocess.run(command, text=True, capture_output=True, check=False)


def _python_authenticate(fixture: AuthorityFixture) -> object:
    return authenticate_lifecycle_v2_transport_authority(
        fixture.manifest_bytes,
        fixture.selection_bytes,
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )


@pytest.mark.parametrize("role,key_index", [("host", 0), ("supervisor", 1), ("recovery", 2)])
def test_complete_signed_chain_projects_only_the_exact_role_generation(
    tmp_path: Path,
    authority_harness: Path,
    role: str,
    key_index: int,
) -> None:
    fixture = _build_authority(tmp_path / role)
    completed = _run(authority_harness, fixture, role)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "owners=0" in completed.stdout
    assert "generation=2" in completed.stdout
    assert fixture.role_public_keys[1][key_index].hex() in completed.stdout
    authority = _python_authenticate(fixture)
    assert authority.resolution.selected_manifest is not None
    assert authority.resolution.selected_manifest.generation == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "bad_signature",
        "noncanonical",
        "reused_role_key",
        "wrong_environment",
        "wrong_root_id",
        "bad_base64",
        "extra_field",
        "bad_manifest_predecessor",
        "bad_selection_signature",
        "bad_selection_predecessor",
        "rollback_head",
        "unknown_entry",
        "hard_link",
        "symlink_head",
        "wrong_root_file",
        "head_bytes_differ",
        "missing_manifest",
        "writable_file",
        "writable_directory",
    ],
)
def test_authority_tamper_path_reuse_and_head_vectors_fail_closed(
    tmp_path: Path,
    authority_harness: Path,
    mutation: str,
) -> None:
    fixture = _build_authority(
        tmp_path / mutation,
        bad_manifest_signature=mutation == "bad_signature",
        noncanonical_last_manifest=mutation == "noncanonical",
        reuse_role_key=mutation == "reused_role_key",
        wrong_environment=mutation == "wrong_environment",
        wrong_root_id=mutation == "wrong_root_id",
        bad_base64=mutation == "bad_base64",
        extra_manifest_field=mutation == "extra_field",
        bad_manifest_predecessor=mutation == "bad_manifest_predecessor",
        bad_selection_signature=mutation == "bad_selection_signature",
        bad_selection_predecessor=mutation == "bad_selection_predecessor",
    )
    if mutation in {
        "rollback_head",
        "unknown_entry",
        "hard_link",
        "symlink_head",
        "wrong_root_file",
        "head_bytes_differ",
        "missing_manifest",
        "writable_file",
        "writable_directory",
    }:
        fixture.make_mutable()
        if mutation == "rollback_head":
            (fixture.path / "selection.json").write_bytes(fixture.selection_bytes[0])
        elif mutation == "hard_link":
            manifest = next(fixture.path.glob("transport-authority-manifest-g00000002-*.json"))
            os.link(manifest, fixture.path / "extra-hard-link")
        elif mutation == "symlink_head":
            (fixture.path / "selection.json").unlink()
            (fixture.path / "selection.json").symlink_to(
                next(fixture.path.glob("transport-authority-selection-s00000002-*.json")).name
            )
        elif mutation == "wrong_root_file":
            (fixture.path / "root-ed25519.pub").write_bytes(b"x" * 32)
        elif mutation == "head_bytes_differ":
            head = fixture.path / "selection.json"
            head.write_bytes(head.read_bytes()[:-1] + b" \n")
        elif mutation == "missing_manifest":
            next(fixture.path.glob("transport-authority-manifest-g00000002-*.json")).unlink()
        elif mutation == "writable_file":
            (fixture.path / "root-ed25519.pub").chmod(0o600)
        elif mutation == "writable_directory":
            pass
        if mutation == "unknown_entry":
            unknown = fixture.path / (
                "transport-authority-selection-s99999999-" + "f" * 64 + ".json"
            )
            unknown.write_bytes(b"{}\n")
        if mutation == "writable_file":
            for child in fixture.path.iterdir():
                if child.name != "root-ed25519.pub" and not child.is_symlink():
                    child.chmod(0o400)
            fixture.path.chmod(0o500)
        elif mutation == "writable_directory":
            for child in fixture.path.iterdir():
                if not child.is_symlink():
                    child.chmod(0o400)
        elif mutation != "writable_directory":
            fixture.freeze()
    completed = _run(authority_harness, fixture, "host")

    assert completed.returncode != 0
    assert "generation=0" in completed.stdout
    if mutation in {
        "bad_signature",
        "noncanonical",
        "reused_role_key",
        "wrong_environment",
        "wrong_root_id",
        "bad_base64",
        "extra_field",
        "bad_manifest_predecessor",
        "bad_selection_signature",
        "bad_selection_predecessor",
    }:
        with pytest.raises(LifecycleV2TransportAuthenticationError):
            _python_authenticate(fixture)


def test_signed_denial_withholds_normal_generation_but_can_pin_recovery(
    tmp_path: Path,
    authority_harness: Path,
) -> None:
    fixture = _build_authority(tmp_path / "denial", terminal_denial=True)

    assert _run(authority_harness, fixture, "host").returncode != 0
    recovery = _run(authority_harness, fixture, "recovery")
    assert recovery.returncode == 0
    assert fixture.role_public_keys[1][2].hex() in recovery.stdout


def test_recovery_requires_exact_injected_root_generation_and_manifest(
    tmp_path: Path,
    authority_harness: Path,
) -> None:
    fixture = _build_authority(tmp_path / "recovery")

    assert (
        _run(
            authority_harness,
            fixture,
            "recovery",
            recovery_generation=1,
            recovery_manifest_sha256=fixture.manifest_sha256[1],
        ).returncode
        != 0
    )
    assert (
        _run(
            authority_harness,
            fixture,
            "recovery",
            recovery_generation=2,
            recovery_manifest_sha256="f" * 64,
        ).returncode
        != 0
    )
    null_recovery = _build_authority(
        tmp_path / "null-recovery",
        terminal_denial=True,
        recovery_generation=None,
    )
    assert _run(authority_harness, null_recovery, "recovery").returncode != 0


def test_fork_child_and_stable_read_race_are_denied(
    tmp_path: Path,
    authority_harness: Path,
) -> None:
    fork_fixture = _build_authority(tmp_path / "fork")
    assert _run(authority_harness, fork_fixture, "host", action="fork").returncode == 0

    race_fixture = _build_authority(tmp_path / "race")
    victim = race_fixture.path / "root-ed25519.pub"
    replacement = tmp_path / "replacement-root-ed25519.pub"
    replacement.write_bytes(b"x" * 32)
    replacement.chmod(0o400)
    raced = _run(
        authority_harness,
        race_fixture,
        "host",
        action="race",
        extra=(str(victim), str(replacement)),
    )
    assert raced.returncode != 0
    assert "generation=0" in raced.stdout


@pytest.mark.parametrize(
    "action",
    ["wrong-pid", "wrong-thread", "wrong-interpreter", "wrong-epoch"],
)
def test_one_use_generation_seal_rejects_every_identity_dimension(
    tmp_path: Path,
    authority_harness: Path,
    action: str,
) -> None:
    fixture = _build_authority(tmp_path / action)
    completed = _run(authority_harness, fixture, "host", action=action)

    assert completed.returncode != 0
    assert "owners=0" in completed.stdout
    assert "generation=0" in completed.stdout


def test_authenticated_generation_can_be_consumed_only_once(
    tmp_path: Path,
    authority_harness: Path,
) -> None:
    fixture = _build_authority(tmp_path / "double")
    completed = _run(authority_harness, fixture, "host", action="double")

    assert completed.returncode == 0
    assert "owners=0" in completed.stdout
    assert "generation=0" in completed.stdout


@pytest.mark.parametrize("role", ["HOST", "SUPERVISOR", "RECOVERY"])
def test_all_production_role_provisioners_link_without_a_release_root_pin(
    tmp_path: Path,
    role: str,
) -> None:
    output = tmp_path / f"provisioner-{role.lower()}"
    subprocess.run(
        [
            _compiler(),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-Wshadow",
            "-Wpedantic",
            "-Werror",
            f"-DAQT_TRUSTED_TIME_V2_{role}_PROVISIONER_PROFILE=1",
            ('-DAQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256="' + "0" * 64 + '"'),
            f"-I{NATIVE}",
            f"-I{VENDOR}",
            f"-I{OPTIONAL}",
            str(NATIVE / "trusted_time_v2_provisioner.c"),
            str(AUTHORITY),
            str(FORK_GUARD),
            str(SECRET_MOUNT_ADMISSION),
            str(NATIVE / "trusted_time_v2_descriptor_baseline.c"),
            str(NATIVE / "trusted_time_v2_seccomp.c"),
            str(MONOCYPHER),
            str(MONOCYPHER_ED25519),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    assert output.is_file()
    assert subprocess.run([output], check=False, capture_output=True).returncode == 191


@pytest.mark.parametrize("role", ["HOST", "SUPERVISOR", "RECOVERY"])
def test_all_production_authority_consumers_deny_without_a_release_pin(
    tmp_path: Path,
    role: str,
) -> None:
    output = tmp_path / f"no-pin-{role.lower()}"
    subprocess.run(
        [
            _compiler(),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-Wshadow",
            "-Wpedantic",
            "-Werror",
            f"-DAQT_TRUSTED_TIME_V2_{role}_PROVISIONER_PROFILE=1",
            f"-I{NATIVE}",
            f"-I{VENDOR}",
            f"-I{OPTIONAL}",
            str(NO_PIN_HARNESS),
            str(AUTHORITY),
            str(FORK_GUARD),
            str(MONOCYPHER),
            str(MONOCYPHER_ED25519),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    assert subprocess.run([output], check=False, capture_output=True).returncode == 0


def test_production_boundary_has_no_path_generation_environment_or_root_seam() -> None:
    source = AUTHORITY.read_text(encoding="utf-8")
    header = (NATIVE / "trusted_time_v2_authority.h").read_text(encoding="utf-8")

    assert '"/opt/autoquant/trusted-time/authorities/graceful-stop-v2"' in source
    assert '"root-ed25519.pub"' in source
    assert '"selection.json"' in source
    assert "#if !AQT_AUTHORITY_ROOT_PIN_AVAILABLE" in source
    assert "return ENOKEY;" in source
    assert "AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_ROOT_PIN" in source
    assert "release-root-pin-absent" in source
    assert "release-environment-pin-absent" in source
    assert "AQT_AUTHORITY_MAXIMUM_CHAIN_FILES 256U" in source
    assert "AQT_AUTHORITY_MAXIMUM_AGGREGATE_BYTES" in source
    assert "aqt_native_interpreter_instance_capability" in source
    production_open = source[source.index("aqt_open_production_authority_directory(") :]
    assert '"graceful-stop-v2",\n            O_RDONLY | O_DIRECTORY,' in production_open
    assert "aqt_open_tracked_at(" in production_open
    assert "aqt_production_ancestor_valid(&metadata)" in production_open
    assert "fstatat(" in production_open
    assert "getenv(" not in source
    assert "argv" not in source
    assert "AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING" in header
    assert "injected_root_manifest_sha256" in header
    assert "injected_root_generation" in header
    assert ".post-enrollment-graceful-stop-attempt-slot" not in source
    production_header = header.split("#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING", 1)[0]
    assert "authority_directory_fd" not in production_header
    assert "injected_root" not in production_header


def test_provisioner_consumes_authority_before_any_blob_or_fork_work() -> None:
    source = (NATIVE / "trusted_time_v2_provisioner.c").read_text(encoding="utf-8")
    main = source[source.index("aqt_trusted_time_v2_provisioner_main(") :]

    consume = main.index("aqt_consume_authenticated_generation(&generation)")
    blob = main.index("aqt_capture_blob_identity(blob_path, &blob_identity)")
    empty = main.index("aqt_trusted_time_v2_fork_guard_require_owner_table_empty()")
    child = main.index("aqt_run_child(")
    assert consume < blob
    assert consume < empty
    assert consume < child
    cleanup = main[main.index("cleanup:") :]
    assert "if (!success && target_descriptor >= 0)" in cleanup
    unlink_condition = cleanup[: cleanup.index("aqt_unlink_exact_target(")]
    assert "aqt_child_state" not in unlink_condition
