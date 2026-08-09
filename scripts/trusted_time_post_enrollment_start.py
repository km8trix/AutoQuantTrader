"""Durable, non-authorizing claim persistence for a future trusted-time start."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartClaim,
)

ROOT = Path(__file__).resolve().parents[1]
IGNORED_ARTIFACT_ROOT = ROOT / "artifacts"

POST_ENROLLMENT_START_RETAINED_CLAIM_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-retained-claim-v1"
)
POST_ENROLLMENT_START_RETAINED_CLAIM_SERVICE = "trusted-time-post-enrollment-start-host-launcher"
POST_ENROLLMENT_START_CLAIM_FILE_PREFIX = "trusted-time-post-enrollment-start-claim-"
POST_ENROLLMENT_START_CLAIM_FILE_SUFFIX = ".json"
MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES = 32_768
DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY = IGNORED_ARTIFACT_ROOT / "trusted-time"

_FILE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_CLOSED_LIFECYCLE_FIELDS = (
    "authority_granted",
    "database_secret_disclosed",
    "persistent_start_authorized",
    "release_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
)


class TrustedTimePostEnrollmentStartClaimPersistenceError(ValueError):
    """A start claim cannot be durably and unambiguously represented."""


class TrustedTimePostEnrollmentStartClaimConsumed(RuntimeError):
    """The exact operation identity already has a retained claim inode."""


class TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed(RuntimeError):
    """Claim creation may have occurred, but durable retention is unconfirmed."""


@dataclass(frozen=True, slots=True)
class RetainedTrustedTimePostEnrollmentStartClaim:
    """Exact bytes observed after one durable exclusive claim creation."""

    claim: TrustedTimePostEnrollmentStartClaim
    operation_id: str
    claim_projection_sha256: str
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.claim) is not TrustedTimePostEnrollmentStartClaim
            or not _is_uuid4(self.operation_id)
            or type(self.claim_projection_sha256) is not str
            or len(self.claim_projection_sha256) != 64
            or type(self.artifact_sha256) is not str
            or len(self.artifact_sha256) != 64
            or not isinstance(self.artifact_path, Path)
            or not self.artifact_path.is_absolute()
            or self.artifact_path != Path(os.path.abspath(self.artifact_path))
            or type(self.encoded) is not bytes
            or not self.encoded
            or len(self.encoded) > MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES
            or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
            or type(self.file_identity) is not tuple
            or len(self.file_identity) != 9
            or any(type(value) is not int for value in self.file_identity)
            or not stat.S_ISREG(self.file_identity[2])
            or stat.S_IMODE(self.file_identity[2]) != 0o600
            or self.file_identity[3] != os.geteuid()
            or self.file_identity[5] != 1
            or self.file_identity[6] != len(self.encoded)
            or any(
                character not in "0123456789abcdef"
                for value in (self.claim_projection_sha256, self.artifact_sha256)
                for character in value
            )
        ):
            raise TrustedTimePostEnrollmentStartClaimPersistenceError(
                "trusted-time post-enrollment retained start claim is invalid"
            )
        try:
            self.claim.__post_init__()
            expected_encoded = retained_post_enrollment_start_claim_bytes(self.claim)
        except Exception:
            raise TrustedTimePostEnrollmentStartClaimPersistenceError(
                "trusted-time post-enrollment retained start claim is invalid"
            ) from None
        if (
            self.operation_id != self.claim.operation_id
            or self.claim_projection_sha256 != self.claim.claim_sha256
            or self.encoded != expected_encoded
        ):
            raise TrustedTimePostEnrollmentStartClaimPersistenceError(
                "trusted-time post-enrollment retained start claim is invalid"
            )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _retained_claim_payload(
    claim: TrustedTimePostEnrollmentStartClaim,
) -> dict[str, object]:
    if type(claim) is not TrustedTimePostEnrollmentStartClaim:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim persistence payload is invalid"
        )
    try:
        claim.__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim persistence payload is invalid"
        ) from None
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update({field_name: False for field_name in _CLOSED_LIFECYCLE_FIELDS})
    payload.update(
        {
            "claim": claim.payload(),
            "claim_projection_sha256": claim.claim_sha256,
            "contract_version": POST_ENROLLMENT_START_RETAINED_CLAIM_CONTRACT_VERSION,
            "operation_id": claim.operation_id,
            "service": POST_ENROLLMENT_START_RETAINED_CLAIM_SERVICE,
            "status": "claim_persistence_payload",
        }
    )
    return payload


def retained_post_enrollment_start_claim_bytes(
    claim: TrustedTimePostEnrollmentStartClaim,
) -> bytes:
    """Encode the exact bounded payload that may be retained by the host."""

    try:
        encoded = canonical_first_enrollment_json_bytes(_retained_claim_payload(claim))
    except Exception:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim persistence payload is invalid"
        ) from None
    if not encoded or len(encoded) > MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim persistence payload is invalid"
        )
    return encoded


def _claim_file_name(operation_id: str) -> str:
    if not _is_uuid4(operation_id):
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim artifact binding is invalid"
        )
    file_name = (
        f"{POST_ENROLLMENT_START_CLAIM_FILE_PREFIX}{operation_id}"
        f"{POST_ENROLLMENT_START_CLAIM_FILE_SUFFIX}"
    )
    if (
        len(os.fsencode(file_name)) > 255
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
    ):
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim artifact binding is invalid"
        )
    return file_name


def _artifact_directory(
    artifact_directory: Path,
    *,
    ignored_root: Path,
) -> Path:
    try:
        canonical_root = Path(os.path.abspath(ignored_root))
        expected = canonical_root / "trusted-time"
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is invalid"
        ) from None
    if (
        not isinstance(artifact_directory, Path)
        or not isinstance(ignored_root, Path)
        or not artifact_directory.is_absolute()
        or artifact_directory != Path(os.path.abspath(artifact_directory))
        or ignored_root != canonical_root
        or artifact_directory != expected
    ):
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is invalid"
        )
    return expected


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
    create: bool,
) -> int:
    """Open one canonical owner-only directory without following path links."""

    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if (
        absolute != path
        or root != ignored_root
        or (absolute != root and not absolute.is_relative_to(root))
    ):
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is unavailable"
        )
    try:
        descriptor = os.open(
            absolute.anchor,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is unavailable"
        ) from None
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            protected = current == root or current.is_relative_to(root)
            if protected and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    created = False
            else:
                created = False
            next_descriptor: int | None = None
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                metadata = os.fstat(next_descriptor)
                if created:
                    os.fchmod(next_descriptor, 0o700)
                    metadata = os.fstat(next_descriptor)
                if protected and (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise OSError
                if created:
                    os.fsync(next_descriptor)
                    os.fsync(descriptor)
                os.close(descriptor)
            except OSError:
                if next_descriptor is not None:
                    with suppress(OSError):
                        os.close(next_descriptor)
                raise
            if next_descriptor is None:
                raise OSError
            descriptor = next_descriptor
        return descriptor
    except OSError:
        with suppress(OSError):
            os.close(descriptor)
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is unavailable"
        ) from None


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _read_retained_claim(
    directory_descriptor: int,
    *,
    file_name: str,
) -> tuple[bytes, tuple[int, ...]]:
    descriptor: int | None = None
    try:
        directory_before = os.fstat(directory_descriptor)
        descriptor = os.open(file_name, _FILE_READ_FLAGS, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        directory_after = os.fstat(directory_descriptor)
        if (
            _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(named)
            or _stable_file_identity(directory_before) != _stable_file_identity(directory_after)
            or len(retained) != before.st_size
            or len(retained) > MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES
        ):
            raise OSError
        return bytes(retained), _stable_file_identity(before)
    except OSError:
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment retained start claim is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def retain_post_enrollment_start_claim(
    claim: TrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    """Durably create one operation claim without granting release authority."""

    absolute_directory = _artifact_directory(
        artifact_directory,
        ignored_root=ignored_root,
    )
    encoded = retained_post_enrollment_start_claim_bytes(claim)
    operation_id = claim.operation_id
    file_name = _claim_file_name(operation_id)
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    created_file_identity: tuple[int, ...] | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=True,
        )
        file_descriptor = os.open(
            file_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(encoded)
        ):
            raise OSError
        created_file_identity = _stable_file_identity(metadata)
        os.fsync(directory_descriptor)
    except FileExistsError:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartClaimConsumed(
            "trusted-time post-enrollment start approval was already consumed"
        ) from None
    except TrustedTimePostEnrollmentStartClaimPersistenceError:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartClaimPersistenceError(
            "trusted-time post-enrollment start claim directory is unavailable"
        ) from None
    except OSError:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed(
            "trusted-time post-enrollment start claim retention is unconfirmed"
        ) from None
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                if directory_descriptor is not None:
                    with suppress(OSError):
                        os.close(directory_descriptor)
                    directory_descriptor = None
                raise TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed(
                    "trusted-time post-enrollment start claim retention is unconfirmed"
                ) from None
    try:
        if directory_descriptor is None:
            raise OSError
        retained, observed_file_identity = _read_retained_claim(
            directory_descriptor,
            file_name=file_name,
        )
        if (
            created_file_identity is None
            or observed_file_identity != created_file_identity
            or retained != encoded
            or hashlib.sha256(retained).hexdigest() != artifact_sha256
        ):
            raise OSError
    except (OSError, TrustedTimePostEnrollmentStartClaimPersistenceError):
        raise TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed(
            "trusted-time post-enrollment start claim retention is unconfirmed"
        ) from None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
    return RetainedTrustedTimePostEnrollmentStartClaim(
        claim=claim,
        operation_id=operation_id,
        claim_projection_sha256=claim.claim_sha256,
        artifact_sha256=artifact_sha256,
        artifact_path=absolute_directory / file_name,
        encoded=encoded,
        file_identity=created_file_identity,
    )


def revalidate_retained_post_enrollment_start_claim(
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    """Return true only while the exact retained inode and bytes remain stable."""

    if type(retained) is not RetainedTrustedTimePostEnrollmentStartClaim:
        return False
    try:
        retained.__post_init__()
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        file_name = _claim_file_name(retained.operation_id)
        if retained.artifact_path != absolute_directory / file_name:
            return False
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
    except Exception:
        return False
    try:
        observed, observed_file_identity = _read_retained_claim(
            directory_descriptor,
            file_name=file_name,
        )
        return (
            observed_file_identity == retained.file_identity
            and observed == retained.encoded
            and hashlib.sha256(observed).hexdigest() == retained.artifact_sha256
        )
    except Exception:
        return False
    finally:
        with suppress(OSError):
            os.close(directory_descriptor)


__all__ = [
    "DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY",
    "MAXIMUM_POST_ENROLLMENT_START_CLAIM_BYTES",
    "POST_ENROLLMENT_START_CLAIM_FILE_PREFIX",
    "POST_ENROLLMENT_START_CLAIM_FILE_SUFFIX",
    "POST_ENROLLMENT_START_RETAINED_CLAIM_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_RETAINED_CLAIM_SERVICE",
    "RetainedTrustedTimePostEnrollmentStartClaim",
    "TrustedTimePostEnrollmentStartClaimConsumed",
    "TrustedTimePostEnrollmentStartClaimPersistenceError",
    "TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed",
    "retain_post_enrollment_start_claim",
    "retained_post_enrollment_start_claim_bytes",
    "revalidate_retained_post_enrollment_start_claim",
]
