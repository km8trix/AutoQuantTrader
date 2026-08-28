from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    build_post_enrollment_graceful_stop_operator_authority,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
    decode_post_enrollment_graceful_stop_operator_authority,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
)
from scripts import (
    provision_trusted_time_post_enrollment_graceful_stop_operator_authority as provisioning,
)
from scripts import (
    provision_trusted_time_post_enrollment_operator_authority as start_provisioning,
)
from scripts.provision_trusted_time_post_enrollment_graceful_stop_operator_authority import (
    CANDIDATE_FILE_PREFIX,
    INSTALLED_AUTHORITY_RELATIVE_PATH,
    INSTALLED_STATUS,
    PREPARED_STATUS,
    START_AUTHORITY_RELATIVE_PATH,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt,
    _install_post_enrollment_graceful_stop_operator_authority,
    install_post_enrollment_graceful_stop_operator_authority,
    main,
    prepare_post_enrollment_graceful_stop_operator_authority_candidate,
)

START_PUBLIC_KEY_BYTES = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
STOP_PUBLIC_KEY_BYTES = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
OTHER_START_PUBLIC_KEY_BYTES = bytes.fromhex(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)


def _owner_only_directory(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def _external_inputs(
    tmp_path: Path,
    *,
    public_key_bytes: bytes = STOP_PUBLIC_KEY_BYTES,
) -> tuple[Path, Path]:
    key_directory = _owner_only_directory(tmp_path / "external-stop-key")
    candidate_directory = _owner_only_directory(tmp_path / "stop-review-candidates")
    public_key_file = key_directory / "graceful-stop-operator-public-key.raw"
    public_key_file.write_bytes(public_key_bytes)
    public_key_file.chmod(0o600)
    return public_key_file, candidate_directory


def _prepare(
    tmp_path: Path,
) -> tuple[
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt,
    Path,
    bytes,
]:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    receipt = prepare_post_enrollment_graceful_stop_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )
    candidate = candidate_directory / receipt.artifact_location
    return receipt, candidate, candidate.read_bytes()


def _repository(
    tmp_path: Path,
    *,
    start_public_key_bytes: bytes | None = START_PUBLIC_KEY_BYTES,
) -> tuple[Path, Path | None]:
    repository = _owner_only_directory(tmp_path / "source-checkout")
    infra = _owner_only_directory(repository / "infra")
    _owner_only_directory(infra / "trusted-time")
    if start_public_key_bytes is None:
        return repository, None
    start_authority = build_post_enrollment_operator_authority(start_public_key_bytes)
    start_encoded = canonical_post_enrollment_operator_authority_bytes(start_authority)
    start_path = repository / START_AUTHORITY_RELATIVE_PATH
    start_path.write_bytes(start_encoded)
    start_path.chmod(0o644)
    return repository, start_path


def _install_kwargs(
    prepared: TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt,
    candidate: Path,
    repository: Path,
) -> dict[str, Any]:
    return {
        "candidate_artifact": candidate,
        "expected_authority_sha256": prepared.authority_artifact_sha256,
        "expected_public_key_sha256": prepared.public_key_sha256,
        "repository_root": repository,
    }


def test_prepare_retains_exact_stop_specific_public_bytes_without_start_manifest(
    tmp_path: Path,
) -> None:
    receipt, candidate, encoded = _prepare(tmp_path)
    authority = decode_post_enrollment_graceful_stop_operator_authority(encoded)
    metadata = candidate.stat()

    assert receipt.status == PREPARED_STATUS
    assert receipt.authority_artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    assert receipt.public_key_sha256 == hashlib.sha256(STOP_PUBLIC_KEY_BYTES).hexdigest()
    assert receipt.artifact_location == (
        f"{CANDIDATE_FILE_PREFIX}{receipt.authority_artifact_sha256}.json"
    )
    assert receipt.distinct_start_key_review_required is True
    assert authority.public_key_bytes == STOP_PUBLIC_KEY_BYTES
    assert canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority) == encoded
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert receipt.public_payload == {
        "artifact_location": receipt.artifact_location,
        "authority_artifact_sha256": receipt.authority_artifact_sha256,
        "authority_granted": False,
        "contract_version": (
            "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-"
            "provisioning-receipt-v1"
        ),
        "distinct_start_key_review_required": True,
        "graceful_stop_authorized": False,
        "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
        "public_key_sha256": receipt.public_key_sha256,
        "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
        "runtime_stop_authorized": False,
        "service": "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority",
        "status": PREPARED_STATUS,
        "stop_execution_authorized": False,
        "verification_only": True,
    }
    assert STOP_PUBLIC_KEY_BYTES.hex() not in json.dumps(receipt.public_payload)
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES == (
        POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES
    )


def test_stop_candidate_is_cross_protocol_isolated_from_start_authority(
    tmp_path: Path,
) -> None:
    _, _, encoded = _prepare(tmp_path)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError):
        decode_post_enrollment_operator_authority(encoded)


@pytest.mark.parametrize(
    ("payload", "mode"),
    [
        (STOP_PUBLIC_KEY_BYTES[:-1], 0o600),
        (STOP_PUBLIC_KEY_BYTES + b"x", 0o600),
        (STOP_PUBLIC_KEY_BYTES, 0o644),
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

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="raw_public_key_unavailable",
    ):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    assert not tuple(candidate_directory.iterdir())


def test_prepare_rejects_relative_symlink_hardlink_and_repository_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    hardlink = public_key_file.with_name("hardlink.raw")
    os.link(public_key_file, hardlink)
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    hardlink.unlink()

    symlink = public_key_file.with_name("symlink.raw")
    symlink.symlink_to(public_key_file)
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=symlink,
            candidate_directory=candidate_directory,
        )
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=Path("relative.raw"),
            candidate_directory=candidate_directory,
        )

    repository, _ = _repository(tmp_path, start_public_key_bytes=None)
    inside_repository = _owner_only_directory(repository / "candidates")
    monkeypatch.setattr(provisioning, "REPOSITORY_ROOT", repository)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="external_directory_unavailable",
    ):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=inside_repository,
        )


@pytest.mark.parametrize("directory", ["key", "candidate"])
def test_prepare_requires_every_external_parent_to_be_owner_only(
    tmp_path: Path,
    directory: str,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    (public_key_file.parent if directory == "key" else candidate_directory).chmod(0o755)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="external_directory_unavailable",
    ):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    assert not tuple(candidate_directory.iterdir())


def test_prepare_accepts_read_only_owner_public_key_file(tmp_path: Path) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    public_key_file.chmod(0o400)

    receipt = prepare_post_enrollment_graceful_stop_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )

    assert (candidate_directory / receipt.artifact_location).is_file()


def test_prepare_exact_retry_refsyncs_and_preserves_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt, candidate, _ = _prepare(tmp_path)
    identity = (candidate.stat().st_dev, candidate.stat().st_ino)
    real_fsync = os.fsync
    fsync_kinds: list[str] = []

    def observing_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", observing_fsync)
    retried = prepare_post_enrollment_graceful_stop_operator_authority_candidate(
        raw_public_key_file=tmp_path
        / "external-stop-key"
        / "graceful-stop-operator-public-key.raw",
        candidate_directory=tmp_path / "stop-review-candidates",
    )

    assert retried == receipt
    assert (candidate.stat().st_dev, candidate.stat().st_ino) == identity
    assert fsync_kinds == ["file", "directory", "file", "directory"]


def test_install_requires_existing_exact_start_authority_before_stop_creation(
    tmp_path: Path,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, _ = _repository(tmp_path, start_public_key_bytes=None)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="start_authority_unavailable",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            **_install_kwargs(prepared, candidate, repository)
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_rejects_same_start_and_stop_public_key_before_stop_creation(
    tmp_path: Path,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, _ = _repository(tmp_path, start_public_key_bytes=STOP_PUBLIC_KEY_BYTES)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="stop_public_key_not_distinct",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            **_install_kwargs(prepared, candidate, repository)
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


@pytest.mark.parametrize("mutation", ["noncanonical", "mode", "hardlink", "symlink"])
def test_install_rejects_unsafe_or_invalid_start_authority_before_stop_creation(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, start_path = _repository(tmp_path)
    assert start_path is not None
    if mutation == "noncanonical":
        start_path.write_bytes(b"{}\n")
    elif mutation == "mode":
        start_path.chmod(0o600)
    elif mutation == "hardlink":
        os.link(start_path, start_path.with_name("start-hardlink.json"))
    else:
        encoded = start_path.read_bytes()
        start_path.unlink()
        target = start_path.with_name("start-target.json")
        target.write_bytes(encoded)
        target.chmod(0o644)
        start_path.symlink_to(target.name)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="start_authority_unavailable",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            **_install_kwargs(prepared, candidate, repository)
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_copies_exact_distinct_bytes_and_closes_review_requirement(
    tmp_path: Path,
) -> None:
    prepared, candidate, encoded = _prepare(tmp_path)
    repository, start_path = _repository(tmp_path)
    assert start_path is not None

    installed = _install_post_enrollment_graceful_stop_operator_authority(
        **_install_kwargs(prepared, candidate, repository)
    )
    installed_path = repository / INSTALLED_AUTHORITY_RELATIVE_PATH
    metadata = installed_path.stat()

    assert installed.status == INSTALLED_STATUS
    assert installed.authority_artifact_sha256 == prepared.authority_artifact_sha256
    assert installed.public_key_sha256 == prepared.public_key_sha256
    assert installed.artifact_location == INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix()
    assert installed.distinct_start_key_review_required is False
    assert installed.public_payload["distinct_start_key_review_required"] is False
    assert installed_path.read_bytes() == encoded == candidate.read_bytes()
    assert stat.S_IMODE(metadata.st_mode) == 0o644
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    start = decode_post_enrollment_operator_authority(start_path.read_bytes())
    stop = decode_post_enrollment_graceful_stop_operator_authority(installed_path.read_bytes())
    assert start.public_key_sha256 != stop.public_key_sha256


@pytest.mark.parametrize("changed_digest", ["authority", "public_key"])
def test_install_requires_both_reviewed_digests_before_creation(
    tmp_path: Path,
    changed_digest: str,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, _ = _repository(tmp_path)
    kwargs = _install_kwargs(prepared, candidate, repository)
    key = (
        "expected_authority_sha256"
        if changed_digest == "authority"
        else "expected_public_key_sha256"
    )
    kwargs[key] = "0" * 64

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError):
        _install_post_enrollment_graceful_stop_operator_authority(**kwargs)
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_rejects_start_protocol_candidate_even_with_matching_digests(
    tmp_path: Path,
) -> None:
    _, candidate_directory = _external_inputs(tmp_path)
    start_authority = build_post_enrollment_operator_authority(STOP_PUBLIC_KEY_BYTES)
    encoded = canonical_post_enrollment_operator_authority_bytes(start_authority)
    digest = hashlib.sha256(encoded).hexdigest()
    candidate = candidate_directory / f"{CANDIDATE_FILE_PREFIX}{digest}.json"
    candidate.write_bytes(encoded)
    candidate.chmod(0o600)
    repository, _ = _repository(tmp_path)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="authority_candidate_invalid",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            candidate_artifact=candidate,
            expected_authority_sha256=digest,
            expected_public_key_sha256=start_authority.public_key_sha256,
            repository_root=repository,
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_rejects_candidate_below_target_repository(
    tmp_path: Path,
) -> None:
    authority = build_post_enrollment_graceful_stop_operator_authority(STOP_PUBLIC_KEY_BYTES)
    encoded = canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
    digest = hashlib.sha256(encoded).hexdigest()
    repository, _ = _repository(tmp_path)
    candidate_directory = _owner_only_directory(repository / "review-candidate")
    candidate = candidate_directory / f"{CANDIDATE_FILE_PREFIX}{digest}.json"
    candidate.write_bytes(encoded)
    candidate.chmod(0o600)

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="external_directory_unavailable",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            candidate_artifact=candidate,
            expected_authority_sha256=digest,
            expected_public_key_sha256=authority.public_key_sha256,
            repository_root=repository,
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_rejects_open_candidate_mode_and_writable_source_parent(
    tmp_path: Path,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, _ = _repository(tmp_path)
    candidate.chmod(0o644)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="authority_candidate_unavailable",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            **_install_kwargs(prepared, candidate, repository)
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()

    candidate.chmod(0o600)
    (repository / "infra").chmod(0o777)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="install_directory_unavailable",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(
            **_install_kwargs(prepared, candidate, repository)
        )
    assert not (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).exists()


def test_install_is_exactly_idempotent_and_never_overwrites_conflict(
    tmp_path: Path,
) -> None:
    prepared, candidate, encoded = _prepare(tmp_path)
    repository, _ = _repository(tmp_path)
    kwargs = _install_kwargs(prepared, candidate, repository)
    first = _install_post_enrollment_graceful_stop_operator_authority(**kwargs)
    target = repository / INSTALLED_AUTHORITY_RELATIVE_PATH
    identity = (target.stat().st_dev, target.stat().st_ino)
    second = _install_post_enrollment_graceful_stop_operator_authority(**kwargs)

    assert first == second
    assert target.read_bytes() == encoded
    assert (target.stat().st_dev, target.stat().st_ino) == identity

    target.write_bytes(b"conflict")
    target.chmod(0o644)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="install_retention_unconfirmed",
    ):
        _install_post_enrollment_graceful_stop_operator_authority(**kwargs)
    assert target.read_bytes() == b"conflict"


@pytest.mark.parametrize("phase", ["candidate", "install"])
def test_partial_write_is_unconfirmed_and_leaves_permanent_blocking_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "candidate":
        public_key_file, candidate_directory = _external_inputs(tmp_path)
        action = partial(
            prepare_post_enrollment_graceful_stop_operator_authority_candidate,
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
        target_directory = candidate_directory
    else:
        prepared, candidate, _ = _prepare(tmp_path)
        repository, _ = _repository(tmp_path)
        action = partial(
            _install_post_enrollment_graceful_stop_operator_authority,
            **_install_kwargs(prepared, candidate, repository),
        )
        target_directory = (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).parent

    real_write = os.write
    interrupted = False

    def partial_write(descriptor: int, payload: Any) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            real_write(descriptor, bytes(payload[:1]))
            raise KeyboardInterrupt
        return real_write(descriptor, payload)

    monkeypatch.setattr(os, "write", partial_write)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match=f"{phase}_retention_unconfirmed",
    ) as captured:
        action()
    assert isinstance(captured.value.__cause__, KeyboardInterrupt)
    partial_path = (
        next(target_directory.iterdir())
        if phase == "candidate"
        else target_directory / INSTALLED_AUTHORITY_RELATIVE_PATH.name
    )
    assert partial_path.read_bytes()
    assert len(partial_path.read_bytes()) == 1

    monkeypatch.setattr(os, "write", real_write)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match=f"{phase}_retention_unconfirmed",
    ):
        action()
    assert len(partial_path.read_bytes()) == 1


def test_lost_o_excl_return_closes_descriptor_and_leaves_blocking_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_file, candidate_directory = _external_inputs(tmp_path)
    real_open = start_provisioning._open_relative_file
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

    monkeypatch.setattr(start_provisioning, "_open_relative_file", interrupt_after_open)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )

    assert lost_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(lost_descriptor)
    candidate = next(candidate_directory.iterdir())
    assert candidate.read_bytes() == b""


def test_directory_fsync_ambiguity_allows_only_exact_idempotent_retry(
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

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="candidate_retention_unconfirmed",
    ):
        prepare_post_enrollment_graceful_stop_operator_authority_candidate(
            raw_public_key_file=public_key_file,
            candidate_directory=candidate_directory,
        )
    candidate = next(candidate_directory.iterdir())
    identity = (candidate.stat().st_dev, candidate.stat().st_ino)

    monkeypatch.setattr(os, "fsync", real_fsync)
    prepare_post_enrollment_graceful_stop_operator_authority_candidate(
        raw_public_key_file=public_key_file,
        candidate_directory=candidate_directory,
    )
    assert (candidate.stat().st_dev, candidate.stat().st_ino) == identity


@pytest.mark.parametrize("phase", ["candidate", "install_directory", "start_authority"])
def test_final_named_rebind_rejects_path_or_start_manifest_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, start_path = _repository(tmp_path)
    assert start_path is not None
    real_retain = provisioning._retain_exact_file
    replaced = False

    def retain_then_replace(*args: Any, **kwargs: Any) -> tuple[int, ...]:
        nonlocal replaced
        result = real_retain(*args, **kwargs)
        if replaced or kwargs["phase"] != ("candidate" if phase == "candidate" else "install"):
            return result
        replaced = True
        if phase == "candidate":
            directory = candidate.parent
            displaced = directory.with_name(directory.name + "-displaced")
            directory.rename(displaced)
            _owner_only_directory(directory)
        elif phase == "install_directory":
            directory = (repository / INSTALLED_AUTHORITY_RELATIVE_PATH).parent
            displaced = directory.with_name(directory.name + "-displaced")
            directory.rename(displaced)
            _owner_only_directory(directory)
        else:
            replacement = build_post_enrollment_operator_authority(OTHER_START_PUBLIC_KEY_BYTES)
            start_path.write_bytes(canonical_post_enrollment_operator_authority_bytes(replacement))
            start_path.chmod(0o644)
        return result

    monkeypatch.setattr(provisioning, "_retain_exact_file", retain_then_replace)
    if phase == "candidate":
        public_key_file = tmp_path / "external-stop-key" / "graceful-stop-operator-public-key.raw"
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
            match="candidate_path_revalidation_failed",
        ):
            prepare_post_enrollment_graceful_stop_operator_authority_candidate(
                raw_public_key_file=public_key_file,
                candidate_directory=candidate.parent,
            )
    else:
        expected_reason = (
            "install_path_revalidation_failed"
            if phase == "install_directory"
            else "start_authority_revalidation_failed"
        )
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
            match=expected_reason,
        ):
            _install_post_enrollment_graceful_stop_operator_authority(
                **_install_kwargs(prepared, candidate, repository)
            )
    assert replaced is True


def test_public_install_surface_has_only_fixed_repository_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, candidate, _ = _prepare(tmp_path)
    repository, _ = _repository(tmp_path)
    monkeypatch.setattr(provisioning, "REPOSITORY_ROOT", repository)

    installed = install_post_enrollment_graceful_stop_operator_authority(
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
    assert payload["distinct_start_key_review_required"] is True
    assert payload["verification_only"] is True
    assert STOP_PUBLIC_KEY_BYTES.hex() not in captured.out

    result = main(["prepare", "--raw-public-key-file", str(public_key_file), "--force"])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "command_arguments_invalid\n"

    repository, _ = _repository(tmp_path)
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
    assert installed_payload["distinct_start_key_review_required"] is False


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


def test_receipt_rejects_false_prepare_or_unreviewed_install_claim() -> None:
    common: dict[str, Any] = {
        "authority_artifact_sha256": "a" * 64,
        "public_key_sha256": "b" * 64,
    }
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="provisioning_receipt_invalid",
    ):
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
            status=PREPARED_STATUS,
            artifact_location=f"{CANDIDATE_FILE_PREFIX}{'a' * 64}.json",
            distinct_start_key_review_required=False,
            **common,
        )
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        match="provisioning_receipt_invalid",
    ):
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
            status=INSTALLED_STATUS,
            artifact_location=INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix(),
            distinct_start_key_review_required=True,
            **common,
        )


def test_module_has_no_private_signer_environment_stdin_or_mutating_escape_hatch() -> None:
    source = Path(provisioning.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } | {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert imported_modules.isdisjoint(
        {
            "asyncio",
            "cryptography",
            "docker",
            "httpx",
            "requests",
            "secrets",
            "socket",
            "sqlalchemy",
            "subprocess",
        }
    )
    assert called_names.isdisjoint(
        {
            "input",
            "mkdir",
            "remove",
            "rename",
            "replace",
            "rmdir",
            "sign",
            "unlink",
        }
    )
    assert "Ed25519PrivateKey" not in source
    assert "SigningKey" not in source
    assert "private_key" not in source
    assert "os.environ" not in source
    assert "sys.stdin" not in source
    assert "--force" not in source
    assert "--overwrite" not in source


def test_isolated_cli_attestation_rejects_an_ordinary_runtime() -> None:
    script = Path(provisioning.__file__).resolve(strict=True)
    base_python = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    ).resolve(strict=True)
    completed = subprocess.run(
        (
            os.fspath(base_python),
            "-I",
            "-B",
            "-X",
            "pycache_prefix=/dev/null",
            os.fspath(script),
        ),
        cwd=script.parents[1],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert (
        "RuntimeError: graceful-stop authority CLI runtime attestation failed" in completed.stderr
    )
