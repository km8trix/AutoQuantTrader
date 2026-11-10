"""Prepare and explicitly install one public operator-attestation authority.

This two-phase command accepts only an externally exported raw 32-byte
Ed25519 public key.  ``prepare`` retains canonical, content-addressed review
bytes in a caller-selected owner-only directory outside this repository.
``install`` requires both reviewed SHA-256 identities and copies those exact
bytes to one fixed source path without overwriting a conflicting entry.

The module has no signer, credential, network, database, container, admission,
or controller capability.  Installation is source material for a later review
and commit; it grants no execution or runtime authority.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Never, cast


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Require canonical source in a disposable isolated Python runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(os.path.abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("operator authority CLI runtime attestation failed") from None
    if (
        repository_root != canonical_root
        or expected_source != canonical_source
        or actual_source != expected_source
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
        or runtime_prefix in (base_prefix, reusable_repository_venv)
        or runtime_prefix.is_relative_to(reusable_repository_venv)
    ):
        raise RuntimeError("operator authority CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("operator authority CLI runtime attestation failed") from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("operator authority CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path(
            "scripts/provision_trusted_time_post_enrollment_operator_authority.py"
        )
    )
    if __name__ == "__main__"
    else None
)

from packages.domain.trusted_time_post_enrollment_operator_authority import (  # noqa: E402
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
    TrustedTimePostEnrollmentOperatorAuthority,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
)

PROVISIONING_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-operator-attestation-authority-provisioning-receipt-v1"
)
PREPARED_STATUS = "public_operator_authority_candidate_prepared"
INSTALLED_STATUS = "public_operator_authority_installed_for_source_review"
CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-operator-attestation-authority-"
CANDIDATE_FILE_SUFFIX = ".json"
INSTALLED_AUTHORITY_RELATIVE_PATH = Path(
    "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RAW_PUBLIC_KEY_BYTES = 32
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


class TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(RuntimeError):
    """One sanitized provisioning failure reason."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt:
    """Public digest-only result of one completed provisioning phase."""

    status: str
    authority_artifact_sha256: str
    public_key_sha256: str
    artifact_location: str

    def __post_init__(self) -> None:
        if (
            self.status not in {PREPARED_STATUS, INSTALLED_STATUS}
            or not _is_sha256(self.authority_artifact_sha256)
            or not _is_sha256(self.public_key_sha256)
            or type(self.artifact_location) is not str
            or not self.artifact_location
            or "\x00" in self.artifact_location
        ):
            raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                "provisioning_receipt_invalid"
            )
        if self.status == PREPARED_STATUS:
            if self.artifact_location != _candidate_file_name(self.authority_artifact_sha256):
                raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                    "provisioning_receipt_invalid"
                )
        elif self.artifact_location != INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix():
            raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                "provisioning_receipt_invalid"
            )

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "artifact_location": self.artifact_location,
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "authority_granted": False,
            "contract_version": PROVISIONING_RECEIPT_CONTRACT_VERSION,
            "controller_execution_authorized": False,
            "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "runtime_start_authorized": False,
            "service": POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
            "status": self.status,
            "verification_only": True,
        }


class _OwnedFileDescriptor(ctypes.c_int):
    """Own one descriptor before the Python CALL can return."""

    def __index__(self) -> int:
        return self.fileno()

    def fileno(self) -> int:
        descriptor = self.value
        if descriptor < 0:
            raise OSError
        return descriptor

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        try:
            self.value = -1
            os.close(descriptor)
        except OSError:
            raise
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


_LIBC = ctypes.CDLL(None, use_errno=True)
_OWNED_OPEN = _LIBC.open
_OWNED_OPEN.argtypes = (ctypes.c_char_p, ctypes.c_int)
_OWNED_OPEN.restype = _OwnedFileDescriptor
_OWNED_OPENAT = _LIBC.openat
_OWNED_OPENAT.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
_OWNED_OPENAT.restype = _OwnedFileDescriptor


def _open_owned_descriptor(
    path: str | Path,
    *,
    flags: int,
    mode: int = 0,
    directory_descriptor: int | None = None,
) -> _OwnedFileDescriptor:
    ctypes.set_errno(0)
    if directory_descriptor is None:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPEN(os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    else:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPENAT(
                directory_descriptor,
                os.fsencode(path),
                flags,
                ctypes.c_int(mode),
            ),
        )
    if owner.value >= 0:
        return owner
    error_number = ctypes.get_errno() or errno.EIO
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), os.fspath(path))
    if error_number == errno.ENOENT:
        raise FileNotFoundError(error_number, os.strerror(error_number), os.fspath(path))
    raise OSError(error_number, os.strerror(error_number), os.fspath(path))


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _absolute_path(value: object, *, reason_code: str) -> Path:
    if type(value) is not type(Path()) or not value.is_absolute() or value.name in {"", ".", ".."}:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(reason_code)
    try:
        absolute = Path(os.path.abspath(value))
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(reason_code) from None
    if absolute != value or "\x00" in os.fspath(absolute):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(reason_code)
    return absolute


def _open_directory_chain(
    path: Path,
    *,
    rejected_identity: tuple[int, int] | None = None,
) -> _OwnedFileDescriptor:
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_owned_descriptor(path.anchor, flags=_DIRECTORY_FLAGS)
        metadata = os.fstat(directory_owner.fileno())
        if rejected_identity == (metadata.st_dev, metadata.st_ino):
            raise OSError
        for part in path.parts[1:]:
            next_owner = _open_owned_descriptor(
                part,
                flags=_DIRECTORY_FLAGS,
                directory_descriptor=directory_owner.fileno(),
            )
            try:
                metadata = os.fstat(next_owner.fileno())
                if rejected_identity == (metadata.st_dev, metadata.st_ino):
                    raise OSError
            except BaseException:
                next_owner.close()
                raise
            directory_owner.close()
            directory_owner = next_owner
        return directory_owner
    except BaseException:
        if directory_owner is not None:
            directory_owner.close()
        raise


def _repository_identity() -> tuple[int, int]:
    repository_owner: _OwnedFileDescriptor | None = None
    try:
        repository_owner = _open_directory_chain(REPOSITORY_ROOT)
        metadata = os.fstat(repository_owner.fileno())
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        return metadata.st_dev, metadata.st_ino
    except BaseException:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "repository_identity_unavailable"
        ) from None
    finally:
        if repository_owner is not None:
            with suppress(OSError):
                repository_owner.close()


def _open_external_owner_only_directory(path: Path) -> _OwnedFileDescriptor:
    try:
        owner = _open_directory_chain(path, rejected_identity=_repository_identity())
        metadata = os.fstat(owner.fileno())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError
        return owner
    except BaseException as error:
        if isinstance(error, TrustedTimePostEnrollmentOperatorAuthorityProvisioningError):
            raise
        with suppress(UnboundLocalError, OSError):
            owner.close()
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "external_directory_unavailable"
        ) from None


def _open_install_directory(repository_root: Path) -> _OwnedFileDescriptor:
    root_owner: _OwnedFileDescriptor | None = None
    try:
        root_owner = _open_directory_chain(repository_root)
        root_metadata = os.fstat(root_owner.fileno())
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise OSError
        for part in INSTALLED_AUTHORITY_RELATIVE_PATH.parts[:-1]:
            next_owner = _open_owned_descriptor(
                part,
                flags=_DIRECTORY_FLAGS,
                directory_descriptor=root_owner.fileno(),
            )
            try:
                metadata = os.fstat(next_owner.fileno())
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise OSError
            except BaseException:
                next_owner.close()
                raise
            root_owner.close()
            root_owner = next_owner
        return root_owner
    except BaseException:
        if root_owner is not None:
            with suppress(OSError):
                root_owner.close()
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "install_directory_unavailable"
        ) from None


def _open_relative_file(
    directory_descriptor: int,
    file_name: str,
    *,
    exclusive: bool,
) -> _OwnedFileDescriptor:
    if (
        type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > 255
    ):
        raise OSError
    flags = (
        ((os.O_RDWR | os.O_CREAT | os.O_EXCL) if exclusive else _READ_FILE_FLAGS)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return _open_owned_descriptor(
        file_name,
        flags=flags,
        mode=0o600,
        directory_descriptor=directory_descriptor,
    )


def _read_relative_file(
    directory_descriptor: int,
    *,
    file_name: str,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    file_owner: _OwnedFileDescriptor | None = None
    try:
        directory_before = os.fstat(directory_descriptor)
        file_owner = _open_relative_file(
            directory_descriptor,
            file_name,
            exclusive=False,
        )
        descriptor = file_owner.fileno()
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) not in allowed_modes
            or before.st_nlink != 1
            or before.st_size < minimum_bytes
            or before.st_size > maximum_bytes
        ):
            raise OSError
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(65_536, maximum_bytes + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        directory_after = os.fstat(directory_descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > maximum_bytes
            or _stable_identity(before) != _stable_identity(after)
            or _stable_identity(after) != _stable_identity(named)
            or _stable_identity(directory_before) != _stable_identity(directory_after)
        ):
            raise OSError
        return bytes(payload), _stable_identity(after)
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


def _read_external_file(
    path: Path,
    *,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    exact_path = _absolute_path(path, reason_code=reason_code)
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_external_owner_only_directory(exact_path.parent)
        encoded, _ = _read_relative_file(
            directory_owner.fileno(),
            file_name=exact_path.name,
            allowed_modes=allowed_modes,
            minimum_bytes=minimum_bytes,
            maximum_bytes=maximum_bytes,
        )
        return encoded
    except TrustedTimePostEnrollmentOperatorAuthorityProvisioningError:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(reason_code) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError
        view = view[written:]


def _confirm_durable_exact_file(
    directory_descriptor: int,
    *,
    file_name: str,
    encoded: bytes,
    required_mode: int,
) -> tuple[int, ...]:
    file_owner: _OwnedFileDescriptor | None = None
    try:
        directory_before = os.fstat(directory_descriptor)
        file_owner = _open_relative_file(
            directory_descriptor,
            file_name,
            exclusive=False,
        )
        descriptor = file_owner.fileno()
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != required_mode
            or before.st_nlink != 1
            or before.st_size != len(encoded)
        ):
            raise OSError
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= len(encoded):
            chunk = os.read(descriptor, min(65_536, len(encoded) + 1 - len(observed)))
            if not chunk:
                break
            observed.extend(chunk)
        after_read = os.fstat(descriptor)
        named = os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            bytes(observed) != encoded
            or _stable_identity(before) != _stable_identity(after_read)
            or _stable_identity(after_read) != _stable_identity(named)
        ):
            raise OSError
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        final_payload = bytearray()
        while len(final_payload) <= len(encoded):
            chunk = os.read(
                descriptor,
                min(65_536, len(encoded) + 1 - len(final_payload)),
            )
            if not chunk:
                break
            final_payload.extend(chunk)
        final = os.fstat(descriptor)
        named_final = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        directory_final = os.fstat(directory_descriptor)
        if (
            bytes(final_payload) != encoded
            or _stable_identity(before) != _stable_identity(final)
            or _stable_identity(final) != _stable_identity(named_final)
            or _stable_identity(directory_before) != _stable_identity(directory_final)
        ):
            raise OSError
        return _stable_identity(final)
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


def _retain_exact_file(
    directory_descriptor: int,
    *,
    file_name: str,
    encoded: bytes,
    required_mode: int,
    phase: str,
) -> tuple[int, ...]:
    file_owner: _OwnedFileDescriptor | None = None
    creation_call_started = False
    try:
        try:
            creation_call_started = True
            file_owner = _open_relative_file(
                directory_descriptor,
                file_name,
                exclusive=True,
            )
        except FileExistsError:
            creation_call_started = False
            try:
                existing, _ = _read_relative_file(
                    directory_descriptor,
                    file_name=file_name,
                    allowed_modes=frozenset({required_mode}),
                    minimum_bytes=1,
                    maximum_bytes=POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
                )
            except BaseException:
                raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                    f"{phase}_retention_unconfirmed"
                ) from None
            if existing != encoded:
                raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                    f"{phase}_retention_unconfirmed"
                ) from None
            try:
                return _confirm_durable_exact_file(
                    directory_descriptor,
                    file_name=file_name,
                    encoded=encoded,
                    required_mode=required_mode,
                )
            except BaseException:
                raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                    f"{phase}_retention_unconfirmed"
                ) from None
        descriptor = file_owner.fileno()
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _write_all(descriptor, encoded)
        os.ftruncate(descriptor, len(encoded))
        os.fchmod(descriptor, required_mode)
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
    except TrustedTimePostEnrollmentOperatorAuthorityProvisioningError:
        raise
    except BaseException as error:
        if creation_call_started:
            raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                f"{phase}_retention_unconfirmed"
            ) from error
        raise
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()
    try:
        identity = _confirm_durable_exact_file(
            directory_descriptor,
            file_name=file_name,
            encoded=encoded,
            required_mode=required_mode,
        )
    except BaseException as error:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            f"{phase}_retention_unconfirmed"
        ) from error
    creation_call_started = False
    return identity


def _revalidate_external_published_file(
    *,
    directory_path: Path,
    expected_directory_identity: tuple[int, int],
    file_name: str,
    encoded: bytes,
    required_mode: int,
    phase: str,
) -> tuple[int, ...]:
    """Rebind a publication to its named external directory at receipt time."""

    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_external_owner_only_directory(directory_path)
        metadata = os.fstat(directory_owner.fileno())
        if (metadata.st_dev, metadata.st_ino) != expected_directory_identity:
            raise OSError
        return _confirm_durable_exact_file(
            directory_owner.fileno(),
            file_name=file_name,
            encoded=encoded,
            required_mode=required_mode,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            f"{phase}_path_revalidation_failed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _revalidate_installed_file(
    *,
    repository_root: Path,
    expected_directory_identity: tuple[int, int],
    encoded: bytes,
) -> tuple[int, ...]:
    """Rebind an install to the fixed source directory at receipt time."""

    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_install_directory(repository_root)
        metadata = os.fstat(directory_owner.fileno())
        if (metadata.st_dev, metadata.st_ino) != expected_directory_identity:
            raise OSError
        return _confirm_durable_exact_file(
            directory_owner.fileno(),
            file_name=INSTALLED_AUTHORITY_RELATIVE_PATH.name,
            encoded=encoded,
            required_mode=0o644,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "install_path_revalidation_failed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _candidate_file_name(authority_sha256: str) -> str:
    if not _is_sha256(authority_sha256):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "authority_sha256_invalid"
        )
    return f"{CANDIDATE_FILE_PREFIX}{authority_sha256}{CANDIDATE_FILE_SUFFIX}"


def _decode_exact_authority(encoded: bytes) -> TrustedTimePostEnrollmentOperatorAuthority:
    try:
        authority = decode_post_enrollment_operator_authority(encoded)
        if canonical_post_enrollment_operator_authority_bytes(authority) != encoded:
            raise ValueError
        return authority
    except (TrustedTimePostEnrollmentOperatorAuthorityError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "authority_candidate_invalid"
        ) from None


def prepare_post_enrollment_operator_authority_candidate(
    *,
    raw_public_key_file: Path,
    candidate_directory: Path,
) -> TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt:
    """Retain final-form public authority bytes for external review."""

    public_key_bytes = _read_external_file(
        raw_public_key_file,
        allowed_modes=frozenset({0o400, 0o600}),
        minimum_bytes=_RAW_PUBLIC_KEY_BYTES,
        maximum_bytes=_RAW_PUBLIC_KEY_BYTES,
        reason_code="raw_public_key_unavailable",
    )
    try:
        authority = build_post_enrollment_operator_authority(public_key_bytes)
        encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    except TrustedTimePostEnrollmentOperatorAuthorityError:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "raw_public_key_invalid"
        ) from None
    authority_sha256 = hashlib.sha256(encoded).hexdigest()
    candidate_name = _candidate_file_name(authority_sha256)
    exact_directory = _absolute_path(
        candidate_directory,
        reason_code="candidate_directory_invalid",
    )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_identity: tuple[int, int] | None = None
    try:
        directory_owner = _open_external_owner_only_directory(exact_directory)
        directory_metadata = os.fstat(directory_owner.fileno())
        directory_identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        _retain_exact_file(
            directory_owner.fileno(),
            file_name=candidate_name,
            encoded=encoded,
            required_mode=0o600,
            phase="candidate",
        )
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
    if directory_identity is None:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "candidate_path_revalidation_failed"
        )
    _revalidate_external_published_file(
        directory_path=exact_directory,
        expected_directory_identity=directory_identity,
        file_name=candidate_name,
        encoded=encoded,
        required_mode=0o600,
        phase="candidate",
    )
    return TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt(
        status=PREPARED_STATUS,
        authority_artifact_sha256=authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        artifact_location=candidate_name,
    )


def _install_post_enrollment_operator_authority(
    *,
    candidate_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    repository_root: Path,
) -> TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt:
    if not _is_sha256(expected_authority_sha256):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "expected_authority_sha256_invalid"
        )
    if not _is_sha256(expected_public_key_sha256):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "expected_public_key_sha256_invalid"
        )
    encoded = _read_external_file(
        candidate_artifact,
        allowed_modes=frozenset({0o400, 0o600}),
        minimum_bytes=1,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
        reason_code="authority_candidate_unavailable",
    )
    authority = _decode_exact_authority(encoded)
    observed_authority_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        candidate_artifact.name != _candidate_file_name(observed_authority_sha256)
        or observed_authority_sha256 != expected_authority_sha256
    ):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "authority_candidate_differs_from_review"
        )
    if authority.public_key_sha256 != expected_public_key_sha256:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "public_key_differs_from_review"
        )
    if (
        type(repository_root) is not type(Path())
        or not repository_root.is_absolute()
        or repository_root != Path(os.path.abspath(repository_root))
    ):
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "repository_identity_unavailable"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_identity: tuple[int, int] | None = None
    try:
        directory_owner = _open_install_directory(repository_root)
        directory_metadata = os.fstat(directory_owner.fileno())
        directory_identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        _retain_exact_file(
            directory_owner.fileno(),
            file_name=INSTALLED_AUTHORITY_RELATIVE_PATH.name,
            encoded=encoded,
            required_mode=0o644,
            phase="install",
        )
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
    if directory_identity is None:
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "install_path_revalidation_failed"
        )
    _revalidate_installed_file(
        repository_root=repository_root,
        expected_directory_identity=directory_identity,
        encoded=encoded,
    )
    return TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt(
        status=INSTALLED_STATUS,
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        artifact_location=INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix(),
    )


def install_post_enrollment_operator_authority(
    *,
    candidate_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
) -> TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt:
    """Install reviewed bytes at the one fixed source path without overwrite."""

    return _install_post_enrollment_operator_authority(
        candidate_artifact=candidate_artifact,
        expected_authority_sha256=expected_authority_sha256,
        expected_public_key_sha256=expected_public_key_sha256,
        repository_root=REPOSITORY_ROOT,
    )


def _require_repository_first_party_sources(repository_root: Path) -> None:
    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("operator authority first-party source attestation failed")
        module_path = repository_root.joinpath(*module_name.split("."))
        expected_sources = {
            module_path.with_suffix(".py"),
            module_path / "__init__.py",
        }
        try:
            lexical_origin = Path(os.path.abspath(origin))
            canonical_origin = lexical_origin.resolve(strict=True)
            source_metadata = lexical_origin.lstat()
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("operator authority first-party source attestation failed") from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("operator authority first-party source attestation failed")


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
            "command_arguments_invalid"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description="Prepare or install verification-only operator public authority material.",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(
        dest="operation",
        required=True,
        parser_class=_SafeArgumentParser,
    )
    prepare = subparsers.add_parser("prepare", allow_abbrev=False)
    prepare.add_argument("--raw-public-key-file", type=Path, required=True)
    prepare.add_argument("--candidate-directory", type=Path, required=True)
    install = subparsers.add_parser("install", allow_abbrev=False)
    install.add_argument("--candidate-artifact", type=Path, required=True)
    install.add_argument("--expected-authority-sha256", required=True)
    install.add_argument("--expected-public-key-sha256", required=True)
    return parser


def _canonical_receipt_bytes(
    receipt: TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt,
) -> bytes:
    return json.dumps(
        receipt.public_payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def main(argv: list[str] | None = None) -> int:
    """Run one public-only phase and emit only its digest receipt."""

    try:
        if _CLI_REPOSITORY_ROOT is not None:
            _require_repository_first_party_sources(_CLI_REPOSITORY_ROOT)
        arguments = _parser().parse_args(argv)
        if arguments.operation == "prepare":
            receipt = prepare_post_enrollment_operator_authority_candidate(
                raw_public_key_file=arguments.raw_public_key_file,
                candidate_directory=arguments.candidate_directory,
            )
        elif arguments.operation == "install":
            receipt = install_post_enrollment_operator_authority(
                candidate_artifact=arguments.candidate_artifact,
                expected_authority_sha256=arguments.expected_authority_sha256,
                expected_public_key_sha256=arguments.expected_public_key_sha256,
            )
        else:  # pragma: no cover - argparse enforces the closed operation set.
            raise TrustedTimePostEnrollmentOperatorAuthorityProvisioningError(
                "command_arguments_invalid"
            )
    except TrustedTimePostEnrollmentOperatorAuthorityProvisioningError as error:
        print(error.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_receipt_bytes(receipt).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main/subprocess tests.
    raise SystemExit(main())


__all__ = [
    "CANDIDATE_FILE_PREFIX",
    "CANDIDATE_FILE_SUFFIX",
    "INSTALLED_AUTHORITY_RELATIVE_PATH",
    "INSTALLED_STATUS",
    "PREPARED_STATUS",
    "PROVISIONING_RECEIPT_CONTRACT_VERSION",
    "TrustedTimePostEnrollmentOperatorAuthorityProvisioningError",
    "TrustedTimePostEnrollmentOperatorAuthorityProvisioningReceipt",
    "install_post_enrollment_operator_authority",
    "main",
    "prepare_post_enrollment_operator_authority_candidate",
]
