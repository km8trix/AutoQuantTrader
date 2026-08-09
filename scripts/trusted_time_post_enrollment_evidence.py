"""Owner-only loading for exact trusted-time post-enrollment evidence."""

from __future__ import annotations

import os
import re
import stat
import uuid
from contextlib import suppress
from pathlib import Path

from packages.domain.trusted_time_enrollment_evidence import (
    MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeEnrollmentEvidenceError,
    decode_confirmed_first_enrollment,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY = ROOT / "artifacts" / "trusted-time"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_MAXIMUM_ARTIFACT_DIRECTORY_ENTRIES = 4_096
_MAXIMUM_ARTIFACT_NAME_BYTES = 255
_CLAIM_PREFIX = "trusted-time-first-enrollment-claim-"
_OUTCOME_PREFIX = "trusted-time-first-enrollment-outcome-"


class TrustedTimeRetainedEnrollmentEvidenceError(ValueError):
    """Exact owner-only enrollment evidence is unavailable or ambiguous."""


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


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _open_owner_only_directory(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact directory is invalid"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
        for part in path.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError
        return descriptor
    except (OSError, ValueError):
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact directory is unavailable"
        ) from None


def _read_owner_only_relative(
    directory_descriptor: int,
    *,
    file_name: str,
) -> bytes:
    if (
        type(directory_descriptor) is not int
        or directory_descriptor < 0
        or type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
    ):
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact binding is invalid"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(file_name, _FILE_FLAGS, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(descriptor)
        if (
            _stable_identity(before) != _stable_identity(after)
            or len(retained) != before.st_size
            or len(retained) > MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES
        ):
            raise OSError
        return bytes(retained)
    except OSError:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def _require_exact_inventory(
    entries: object,
    *,
    expected_claim_name: str,
    expected_outcome_name: str,
) -> None:
    if (
        type(entries) is not list
        or len(entries) > _MAXIMUM_ARTIFACT_DIRECTORY_ENTRIES
        or any(
            type(entry) is not str
            or not entry
            or len(os.fsencode(entry)) > _MAXIMUM_ARTIFACT_NAME_BYTES
            for entry in entries
        )
    ):
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact inventory is invalid"
        )
    claims = {
        entry for entry in entries if entry.startswith(_CLAIM_PREFIX) and entry.endswith(".json")
    }
    outcomes = {
        entry for entry in entries if entry.startswith(_OUTCOME_PREFIX) and entry.endswith(".json")
    }
    if claims != {expected_claim_name} or outcomes != {expected_outcome_name}:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact inventory is ambiguous"
        )


def _read_bounded_inventory(directory_descriptor: int) -> list[str]:
    entries: list[str] = []
    try:
        with os.scandir(directory_descriptor) as iterator:
            for entry in iterator:
                name = entry.name
                if (
                    type(name) is not str
                    or not name
                    or len(os.fsencode(name)) > _MAXIMUM_ARTIFACT_NAME_BYTES
                    or len(entries) == _MAXIMUM_ARTIFACT_DIRECTORY_ENTRIES
                ):
                    raise TrustedTimeRetainedEnrollmentEvidenceError(
                        "trusted-time enrollment artifact inventory is invalid"
                    )
                entries.append(name)
    except OSError:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact inventory is unavailable"
        ) from None
    return sorted(entries)


def load_confirmed_first_enrollment_evidence(
    *,
    operation_id: str,
    claim_sha256: str,
    outcome_sha256: str,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
) -> TrustedTimeConfirmedFirstEnrollment:
    """Load one unambiguous owner-only claim/outcome pair by exact public hashes."""

    if (
        not _is_uuid4(operation_id)
        or type(claim_sha256) is not str
        or _SHA256_PATTERN.fullmatch(claim_sha256) is None
        or type(outcome_sha256) is not str
        or _SHA256_PATTERN.fullmatch(outcome_sha256) is None
    ):
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact binding is invalid"
        )
    claim_name = f"{_CLAIM_PREFIX}{operation_id}.json"
    outcome_name = f"{_OUTCOME_PREFIX}{outcome_sha256}.json"
    directory_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_directory(artifact_directory)
        before = os.fstat(directory_descriptor)
        entries_before = _read_bounded_inventory(directory_descriptor)
        _require_exact_inventory(
            entries_before,
            expected_claim_name=claim_name,
            expected_outcome_name=outcome_name,
        )
        claim_encoded = _read_owner_only_relative(
            directory_descriptor,
            file_name=claim_name,
        )
        outcome_encoded = _read_owner_only_relative(
            directory_descriptor,
            file_name=outcome_name,
        )
        entries_after = _read_bounded_inventory(directory_descriptor)
        after = os.fstat(directory_descriptor)
        if entries_after != entries_before or _stable_identity(before) != _stable_identity(after):
            raise TrustedTimeRetainedEnrollmentEvidenceError(
                "trusted-time enrollment artifact inventory changed"
            )
        return decode_confirmed_first_enrollment(
            claim_encoded=claim_encoded,
            outcome_encoded=outcome_encoded,
            expected_operation_id=operation_id,
            expected_claim_sha256=claim_sha256,
            expected_outcome_sha256=outcome_sha256,
        )
    except TrustedTimeEnrollmentEvidenceError:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time confirmed enrollment artifacts are invalid"
        ) from None
    except OSError:
        raise TrustedTimeRetainedEnrollmentEvidenceError(
            "trusted-time enrollment artifact inventory is unavailable"
        ) from None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


__all__ = [
    "DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY",
    "TrustedTimeRetainedEnrollmentEvidenceError",
    "load_confirmed_first_enrollment_evidence",
]
