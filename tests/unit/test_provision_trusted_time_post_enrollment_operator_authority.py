from __future__ import annotations

import dis
import fcntl
import gc
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from packages.domain.trusted_time_post_enrollment_operator_authority import (
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
)
from scripts import provision_trusted_time_post_enrollment_operator_authority as provisioning
from scripts.provision_trusted_time_post_enrollment_operator_authority import (
    CANDIDATE_FILE_PREFIX,
    INSTALLED_AUTHORITY_RELATIVE_PATH,
    INSTALLED_STATUS,
    PREPARED_STATUS,
    TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
    TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt,
    _install_post_enrollment_operator_authority,
    install_post_enrollment_operator_authority,
    main,
    prepare_post_enrollment_operator_authority_candidate,
)

PUBLIC_KEY_BYTES = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


def _owner_only_directory(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def _external_inputs(tmp_path: Path) -> tuple[Path, Path]:
    key_directory = _owner_only_directory(tmp_path / "external-key")
    candidate_directory = _owner_only_directory(tmp_path / "review-candidates")
    public_key_file = key_directory / "operator-public-key.raw"
    public_key_file.write_bytes(PUBLIC_KEY_BYTES)
    public_key_file.chmod(0o600)
    return public_key_file, candidate_directory


def _prepare(
    tmp_path: Path,
) -> tuple[TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt, Path, bytes]:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    receipt = prepare_post_enrollment_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )
    candidate = candidate_directory / receipt.artifact_location
    return receipt, candidate, candidate.read_bytes()


def _repository(tmp_path: Path) -> Path:
    repository = _owner_only_directory(tmp_path / "source-checkout")
    infra = _owner_only_directory(repository / "infra")
    _owner_only_directory(infra / "trusted-time")
    return repository


def _interrupt_instruction(target: Any, instruction_offset: int, action: Any) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise KeyboardInterrupt

    sys.monitoring.use_tool_id(tool_id, "operator-authority-instruction-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        action()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)


def _open_descriptor_names() -> set[str]:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        descriptor_root = Path("/dev/fd")
    return {entry.name for entry in descriptor_root.iterdir()}


def test_prepare_retains_exact_final_form_content_addressed_public_bytes(
    tmp_path: Path,
) -> None:
    receipt, candidate, encoded = _prepare(tmp_path)
    authority = decode_post_enrollment_operator_authority(encoded)
    metadata = candidate.stat()

    assert receipt.status == PREPARED_STATUS
    assert receipt.authority_artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    assert receipt.public_key_sha256 == hashlib.sha256(PUBLIC_KEY_BYTES).hexdigest()
    assert receipt.artifact_location == (
        f"{CANDIDATE_FILE_PREFIX}{receipt.authority_artifact_sha256}.json"
    )
    assert authority.public_key_bytes == PUBLIC_KEY_BYTES
    assert canonical_post_enrollment_operator_authority_bytes(authority) == encoded
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    rendered = json.dumps(receipt.public_payload, sort_keys=True)
    assert PUBLIC_KEY_BYTES.hex() not in rendered
    assert receipt.public_payload["verification_only"] is True
    assert receipt.public_payload["authority_granted"] is False
    assert receipt.public_payload["controller_execution_authorized"] is False
    assert receipt.public_payload["runtime_start_authorized"] is False
    assert receipt.public_payload["key_id"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID
    assert (
        receipt.public_payload["replay_domain"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    )


def test_prepare_exact_retry_refsyncs_and_preserves_one_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt, candidate, _ = _prepare(tmp_path)
    identity = (candidate.stat().st_dev, candidate.stat().st_ino)
    public_key_file = tmp_path / "external-key" / "operator-public-key.raw"
    candidate_directory = tmp_path / "review-candidates"
    real_fsync = os.fsync
    fsync_kinds: list[str] = []

    def observing_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(
        "scripts.provision_trusted_time_post_enrollment_operator_authority.os.fsync",
        observing_fsync,
    )
    retried = prepare_post_enrollment_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )

    assert retried == receipt
    assert (candidate.stat().st_dev, candidate.stat().st_ino) == identity
    assert fsync_kinds == ["file", "directory", "file", "directory"]


@pytest.mark.parametrize(
    ("payload", "mode"),
    [
        (PUBLIC_KEY_BYTES[:-1], 0o600),
        (PUBLIC_KEY_BYTES + b"x", 0o600),
        (PUBLIC_KEY_BYTES, 0o644),
    ],
)
def test_prepare_rejects_wrong_public_key_size_or_mode(
    tmp_path: Path,
    payload: bytes,
    mode: int,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    public_key_file.write_bytes(payload)
    public_key_file.chmod(mode)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    assert not tuple(candidate_directory.iterdir())


def test_prepare_rejects_relative_symlink_hardlink_and_non_owner_only_paths(
    tmp_path: Path,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    alias = public_key_file.with_name("public-key-alias")
    os.link(public_key_file, alias)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    alias.unlink()

    symlink = public_key_file.with_name("public-key-symlink")
    symlink.symlink_to(public_key_file)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=symlink,
            candidate_directory=candidate_directory,
        )

    candidate_directory.chmod(0o755)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    candidate_directory.chmod(0o700)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=Path("relative-public-key"),
            candidate_directory=candidate_directory,
        )


def test_prepare_rejects_any_candidate_directory_below_repository_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _owner_only_directory(tmp_path / "repository")
    candidate_directory = _owner_only_directory(repository / "candidates")
    key_directory = _owner_only_directory(tmp_path / "external-key")
    public_key_file = key_directory / "public.raw"
    public_key_file.write_bytes(PUBLIC_KEY_BYTES)
    public_key_file.chmod(0o600)
    monkeypatch.setattr(provisioning, "REPOSITORY_ROOT", repository)

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="external_directory_unavailable",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )


def test_prepare_validates_candidate_directory_before_path_composition(tmp_path: Path) -> None:
    public_key_file, _ = _external_inputs(tmp_path)

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_directory_invalid",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory="not-a-path",  # type: ignore[arg-type]
        )


def test_install_copies_identical_reviewed_bytes_to_only_fixed_source_path(
    tmp_path: Path,
) -> None:
    prepared, candidate, encoded = _prepare(tmp_path)
    repository = _repository(tmp_path)

    installed = _install_post_enrollment_operator_authority(
        candidate_artifact=candidate,
        expected_authority_sha256=prepared.authority_artifact_sha256,
        expected_public_key_sha256=prepared.public_key_sha256,
        repository_root=repository,
    )
    installed_path = repository / INSTALLED_AUTHORITY_RELATIVE_PATH
    metadata = installed_path.stat()

    assert installed.status == INSTALLED_STATUS
    assert installed.authority_artifact_sha256 == prepared.authority_artifact_sha256
    assert installed.public_key_sha256 == prepared.public_key_sha256
    assert installed.artifact_location == INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix()
    assert installed_path.read_bytes() == encoded == candidate.read_bytes()
    assert stat.S_IMODE(metadata.st_mode) == 0o644
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert not tuple(
        path for path in repository.rglob("*") if path.is_file() and path != installed_path
    )


@pytest.mark.parametrize("changed_digest", ["authority", "public_key"])
def test_install_requires_both_explicit_reviewed_digests_before_creation(
    tmp_path: Path,
    changed_digest: str,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository = _repository(tmp_path)
    authority_sha256 = prepared.authority_artifact_sha256
    public_key_sha256 = prepared.public_key_sha256
    if changed_digest == "authority":
        authority_sha256 = "0" * 64
    else:
        public_key_sha256 = "0" * 64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
        _install_post_enrollment_operator_authority(
            candidate_artifact=candidate,
            expected_authority_sha256=authority_sha256,
            expected_public_key_sha256=public_key_sha256,
            repository_root=repository,
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_rejects_wrong_content_addressed_name_and_noncanonical_candidate(
    tmp_path: Path,
) -> None:
    prepared, candidate, encoded = _prepare(tmp_path)
    repository = _repository(tmp_path)
    wrong_name = candidate.with_name("reviewed-candidate.json")
    candidate.rename(wrong_name)

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="authority_candidate_differs_from_review",
    ):
        _install_post_enrollment_operator_authority(
            candidate_artifact=wrong_name,
            expected_authority_sha256=prepared.authority_artifact_sha256,
            expected_public_key_sha256=prepared.public_key_sha256,
            repository_root=repository,
        )

    changed = json.dumps(json.loads(encoded), indent=2, sort_keys=True).encode("ascii")
    changed_path = wrong_name.with_name(
        f"{CANDIDATE_FILE_PREFIX}{hashlib.sha256(changed).hexdigest()}.json"
    )
    changed_path.write_bytes(changed)
    changed_path.chmod(0o600)
    wrong_name.unlink()
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="authority_candidate_invalid",
    ):
        _install_post_enrollment_operator_authority(
            candidate_artifact=changed_path,
            expected_authority_sha256=hashlib.sha256(changed).hexdigest(),
            expected_public_key_sha256=prepared.public_key_sha256,
            repository_root=repository,
        )


def test_install_is_exactly_idempotent_and_conflicting_target_never_overwrites(
    tmp_path: Path,
) -> None:
    prepared, candidate, encoded = _prepare(tmp_path)
    repository = _repository(tmp_path)
    kwargs: dict[str, Any] = {
        "candidate_artifact": candidate,
        "expected_authority_sha256": prepared.authority_artifact_sha256,
        "expected_public_key_sha256": prepared.public_key_sha256,
        "repository_root": repository,
    }
    first = _install_post_enrollment_operator_authority(**kwargs)
    target = repository / INSTALLED_AUTHORITY_RELATIVE_PATH
    identity = (target.stat().st_dev, target.stat().st_ino)
    second = _install_post_enrollment_operator_authority(**kwargs)

    assert first == second
    assert target.read_bytes() == encoded
    assert (target.stat().st_dev, target.stat().st_ino) == identity

    target.write_bytes(b"conflict")
    target.chmod(0o644)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="install_retention_unconfirmed",
    ):
        _install_post_enrollment_operator_authority(**kwargs)
    assert target.read_bytes() == b"conflict"


def test_candidate_partial_write_is_unconfirmed_and_never_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    authority = build_post_enrollment_operator_authority(PUBLIC_KEY_BYTES)
    encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    candidate = candidate_directory / (
        f"{CANDIDATE_FILE_PREFIX}{hashlib.sha256(encoded).hexdigest()}.json"
    )
    real_write = os.write
    interrupted = False

    def partial_write(descriptor: int, payload: Any) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            real_write(descriptor, bytes(payload[:1]))
            raise KeyboardInterrupt
        return real_write(descriptor, payload)

    monkeypatch.setattr(
        "scripts.provision_trusted_time_post_enrollment_operator_authority.os.write",
        partial_write,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ) as captured:
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    assert isinstance(captured.value.__cause__, KeyboardInterrupt)
    assert candidate.read_bytes() == encoded[:1]

    monkeypatch.setattr(
        "scripts.provision_trusted_time_post_enrollment_operator_authority.os.write",
        real_write,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    assert candidate.read_bytes() == encoded[:1]


def test_lost_o_excl_return_closes_descriptor_and_leaves_blocking_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    authority = build_post_enrollment_operator_authority(PUBLIC_KEY_BYTES)
    encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    candidate = candidate_directory / (
        f"{CANDIDATE_FILE_PREFIX}{hashlib.sha256(encoded).hexdigest()}.json"
    )
    real_open = provisioning._open_relative_file
    lost_descriptor: int | None = None

    def interrupt_after_open(
        directory_descriptor: int,
        file_name: str,
        *,
        exclusive: bool,
    ) -> object:
        nonlocal lost_descriptor
        owner = real_open(
            directory_descriptor,
            file_name,
            exclusive=exclusive,
        )
        if exclusive:
            lost_descriptor = owner.fileno()
            raise KeyboardInterrupt
        return owner

    monkeypatch.setattr(provisioning, "_open_relative_file", interrupt_after_open)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )

    assert lost_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(lost_descriptor)
    assert candidate.exists()
    assert candidate.read_bytes() == b""


def test_directory_fsync_ambiguity_retries_only_exact_existing_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    real_fsync = os.fsync
    failed = False

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not failed:
            failed = True
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        "scripts.provision_trusted_time_post_enrollment_operator_authority.os.fsync",
        fail_directory_fsync,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    candidate = next(candidate_directory.iterdir())
    identity = (candidate.stat().st_dev, candidate.stat().st_ino)

    monkeypatch.setattr(
        "scripts.provision_trusted_time_post_enrollment_operator_authority.os.fsync",
        real_fsync,
    )
    prepare_post_enrollment_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )
    assert (candidate.stat().st_dev, candidate.stat().st_ino) == identity


@pytest.mark.parametrize("phase", ["candidate", "install"])
def test_final_receipt_rebind_rejects_named_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository = _repository(tmp_path)
    candidate_directory = candidate.parent
    install_directory = (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).parent
    replaced = False
    real_retain = provisioning._retain_exact_file

    def retain_then_replace(*args: Any, **kwargs: Any) -> tuple[int, ...]:
        nonlocal replaced
        result = real_retain(*args, **kwargs)
        if kwargs["phase"] == phase and not replaced:
            replaced = True
            directory = candidate_directory if phase == "candidate" else install_directory
            displaced = directory.with_name(directory.name + "-displaced")
            directory.rename(displaced)
            directory.mkdir()
            directory.chmod(0o700)
        return result

    monkeypatch.setattr(provisioning, "_retain_exact_file", retain_then_replace)
    if phase == "candidate":
        public_key_file = tmp_path / "external-key" / "operator-public-key.raw"
        with pytest.raises(
            TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
            match="candidate_path_revalidation_failed",
        ):
            prepare_post_enrollment_operator_authority_candidate(
                raw_public_key_file=public_key_file,
                candidate_directory=candidate_directory,
            )
    else:
        with pytest.raises(
            TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
            match="install_path_revalidation_failed",
        ):
            _install_post_enrollment_operator_authority(
                candidate_artifact=candidate,
                expected_authority_sha256=prepared.authority_artifact_sha256,
                expected_public_key_sha256=prepared.public_key_sha256,
                repository_root=repository,
            )
    assert replaced is True


def test_final_receipt_rechecks_external_directory_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    real_retain = provisioning._retain_exact_file

    def retain_then_open_permissions(*args: Any, **kwargs: Any) -> tuple[int, ...]:
        result = real_retain(*args, **kwargs)
        candidate_directory.chmod(0o777)
        return result

    monkeypatch.setattr(provisioning, "_retain_exact_file", retain_then_open_permissions)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAuthorityProvisioningError,
        match="candidate_path_revalidation_failed",
    ):
        prepare_post_enrollment_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )


def test_install_public_surface_has_fixed_repository_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository = _repository(tmp_path)
    monkeypatch.setattr(provisioning, "REPOSITORY_ROOT", repository)

    installed = install_post_enrollment_operator_authority(
        candidate_artifact=candidate,
        expected_authority_sha256=prepared.authority_artifact_sha256,
        expected_public_key_sha256=prepared.public_key_sha256,
    )

    assert installed.status == INSTALLED_STATUS
    assert (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).is_file()


def test_cli_emits_only_sanitized_receipts_and_rejects_unrecognized_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    result = main(
        [
            "prepare",
            "--raw-public-key-file",
            str(public_key_file),
            "--candidate-directory",
            str(candidate_directory),
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert result == 0
    assert captured.err == ""
    assert payload["status"] == PREPARED_STATUS
    assert payload["verification_only"] is True
    assert PUBLIC_KEY_BYTES.hex() not in captured.out

    result = main(["prepare", "--raw-public-key-file", str(public_key_file), "--force"])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "command_arguments_invalid\n"

    repository = _repository(tmp_path)
    monkeypatch.setattr(provisioning, "REPOSITORY_ROOT", repository)
    candidate = next(candidate_directory.iterdir())
    result = main(
        [
            "install",
            "--candidate-artifact",
            str(candidate),
            "--expected-authority-sha256",
            payload["authority_artifact_sha256"],
            "--expected-public-key-sha256",
            payload["public_key_sha256"],
        ]
    )
    captured = capsys.readouterr()
    installed_payload = json.loads(captured.out)
    assert result == 0
    assert captured.err == ""
    assert installed_payload["status"] == INSTALLED_STATUS


def test_cli_rejects_long_option_abbreviations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)

    result = main(
        [
            "prepare",
            "--raw-public-key-f",
            str(public_key_file),
            "--candidate-d",
            str(candidate_directory),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "command_arguments_invalid\n"


def test_exclusive_raw_open_sets_close_on_exec(tmp_path: Path) -> None:
    directory = _owner_only_directory(tmp_path / "cloexec")
    directory_owner = provisioning._open_directory_chain(directory)
    try:
        file_owner = provisioning._open_relative_file(
            directory_owner.fileno(),
            "candidate.json",
            exclusive=True,
        )
        try:
            assert fcntl.fcntl(file_owner.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        finally:
            file_owner.close()
    finally:
        directory_owner.close()


def test_owned_descriptor_and_directory_chain_close_exactly_once(tmp_path: Path) -> None:
    directory = _owner_only_directory(tmp_path / "descriptors")
    owner = provisioning._open_directory_chain(directory)
    descriptor = owner.fileno()
    owner.close()
    owner.close()
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("relative", [False, True])
def test_owned_descriptor_call_store_interruption_closes_native_result(
    tmp_path: Path,
    relative: bool,
) -> None:
    target = provisioning._open_owned_descriptor
    stores = [
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST" and instruction.argval == "owner"
    ]
    parent_owner = provisioning._open_owned_descriptor(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    before = _open_descriptor_names()
    try:
        with pytest.raises(KeyboardInterrupt):
            _interrupt_instruction(
                target,
                stores[1 if relative else 0],
                lambda: target(
                    "." if relative else tmp_path,
                    flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    directory_descriptor=parent_owner.fileno() if relative else None,
                ),
            )
        gc.collect()
        assert _open_descriptor_names() == before
    finally:
        parent_owner.close()


def test_owned_descriptor_close_retries_async_interruption_after_retirement(
    tmp_path: Path,
) -> None:
    owner = provisioning._open_owned_descriptor(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    descriptor = owner.fileno()
    target = provisioning._OwnedFileDescriptor.close
    instructions = list(dis.get_instructions(target))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "value"
    )
    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            instructions[store_index + 1].offset,
            owner.close,
        )

    assert owner.value == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_isolated_cli_attestation_rejects_an_ordinary_runtime() -> None:
    with pytest.raises(RuntimeError, match="CLI runtime attestation failed"):
        provisioning._require_isolated_cli_source_runtime(
            expected_relative_path=Path(
                "scripts/provision_trusted_time_post_enrollment_operator_authority.py"
            )
        )
