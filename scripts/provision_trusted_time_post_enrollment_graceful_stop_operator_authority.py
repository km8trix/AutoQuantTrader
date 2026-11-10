"""Prepare and explicitly install one graceful-stop public operator authority.

This two-phase command accepts only an externally exported raw 32-byte
Ed25519 public key. ``prepare`` retains canonical, content-addressed review
bytes in a caller-selected owner-only directory outside this repository.
``install`` requires both reviewed SHA-256 identities, requires an already
installed canonical start authority with a distinct public key, and copies the
exact stop bytes to one fixed source path without overwriting a conflict.

The module has no signer, private key, credential, network, database,
container, admission, shutdown, or controller capability. Installation is
public source material for later review and commit; it grants no runtime or
graceful-stop authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Never


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
        raise RuntimeError("graceful-stop authority CLI runtime attestation failed") from None
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
        raise RuntimeError("graceful-stop authority CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("graceful-stop authority CLI runtime attestation failed") from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("graceful-stop authority CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path(
            "scripts/provision_trusted_time_post_enrollment_graceful_stop_operator_authority.py"
        )
    )
    if __name__ == "__main__"
    else None
)

from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
    build_post_enrollment_graceful_stop_operator_authority,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
    decode_post_enrollment_graceful_stop_operator_authority,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (  # noqa: E402
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
)
from scripts import (  # noqa: E402
    provision_trusted_time_post_enrollment_operator_authority as _filesystem,
)

PROVISIONING_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-provisioning-receipt-v1"
)
PREPARED_STATUS = "public_graceful_stop_operator_authority_candidate_prepared"
INSTALLED_STATUS = "public_graceful_stop_operator_authority_installed_for_source_review"
CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority-"
CANDIDATE_FILE_SUFFIX = ".json"
INSTALLED_AUTHORITY_RELATIVE_PATH = Path(
    "infra/trusted-time/post-enrollment-graceful-stop-operator-attestation-authority.json"
)
START_AUTHORITY_RELATIVE_PATH = Path(
    "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RAW_PUBLIC_KEY_BYTES = 32
_SHA256_CHARACTERS = frozenset("0123456789abcdef")

_OwnedFileDescriptor = _filesystem._OwnedFileDescriptor
_open_owned_descriptor = _filesystem._open_owned_descriptor
_open_directory_chain = _filesystem._open_directory_chain
_open_relative_file = _filesystem._open_relative_file
_read_relative_file = _filesystem._read_relative_file
_confirm_durable_exact_file = _filesystem._confirm_durable_exact_file


class TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(RuntimeError):
    """One sanitized graceful-stop authority provisioning failure reason."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt:
    """Public digest-only result of one completed provisioning phase."""

    status: str
    authority_artifact_sha256: str
    public_key_sha256: str
    artifact_location: str
    distinct_start_key_review_required: bool

    def __post_init__(self) -> None:
        if (
            self.status not in {PREPARED_STATUS, INSTALLED_STATUS}
            or not _is_sha256(self.authority_artifact_sha256)
            or not _is_sha256(self.public_key_sha256)
            or type(self.artifact_location) is not str
            or not self.artifact_location
            or "\x00" in self.artifact_location
            or type(self.distinct_start_key_review_required) is not bool
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "provisioning_receipt_invalid"
            )
        if self.status == PREPARED_STATUS:
            if (
                self.artifact_location != _candidate_file_name(self.authority_artifact_sha256)
                or self.distinct_start_key_review_required is not True
            ):
                raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                    "provisioning_receipt_invalid"
                )
        elif (
            self.artifact_location != INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix()
            or self.distinct_start_key_review_required is not False
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "provisioning_receipt_invalid"
            )

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "artifact_location": self.artifact_location,
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "authority_granted": False,
            "contract_version": PROVISIONING_RECEIPT_CONTRACT_VERSION,
            "distinct_start_key_review_required": self.distinct_start_key_review_required,
            "graceful_stop_authorized": False,
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "runtime_stop_authorized": False,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE,
            "status": self.status,
            "stop_execution_authorized": False,
            "verification_only": True,
        }


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _absolute_path(value: object, *, reason_code: str) -> Path:
    try:
        return _filesystem._absolute_path(value, reason_code=reason_code)
    except _filesystem.TrustedTimePostEnrollmentOperatorAuthorityProvisioningError as error:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            error.reason_code
        ) from None


def _repository_identity(repository_root: Path) -> tuple[int, int]:
    repository_owner: _OwnedFileDescriptor | None = None
    try:
        repository_owner = _open_directory_chain(repository_root)
        metadata = os.fstat(repository_owner.fileno())
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        return metadata.st_dev, metadata.st_ino
    except BaseException:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "repository_identity_unavailable"
        ) from None
    finally:
        if repository_owner is not None:
            with suppress(OSError):
                repository_owner.close()


def _open_external_owner_only_directory(
    path: Path,
    *,
    rejected_repository_root: Path,
) -> _OwnedFileDescriptor:
    owner: _OwnedFileDescriptor | None = None
    try:
        owner = _open_directory_chain(
            path,
            rejected_identity=_repository_identity(rejected_repository_root),
        )
        metadata = os.fstat(owner.fileno())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError
        return owner
    except BaseException as error:
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError,
        ):
            raise
        if owner is not None:
            with suppress(OSError):
                owner.close()
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
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
            next_owner = _filesystem._open_owned_descriptor(
                part,
                flags=_filesystem._DIRECTORY_FLAGS,
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
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "install_directory_unavailable"
        ) from None


def _read_external_file(
    path: Path,
    *,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    reason_code: str,
    rejected_repository_root: Path,
) -> bytes:
    exact_path = _absolute_path(path, reason_code=reason_code)
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_external_owner_only_directory(
            exact_path.parent,
            rejected_repository_root=rejected_repository_root,
        )
        encoded, _ = _read_relative_file(
            directory_owner.fileno(),
            file_name=exact_path.name,
            allowed_modes=allowed_modes,
            minimum_bytes=minimum_bytes,
            maximum_bytes=maximum_bytes,
        )
        return encoded
    except TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            reason_code
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _retain_exact_file(
    directory_descriptor: int,
    *,
    file_name: str,
    encoded: bytes,
    required_mode: int,
    phase: str,
) -> tuple[int, ...]:
    """Reuse the descriptor-owned CALL/STORE engine with stop error identity."""

    reason_code: str | None = None
    asynchronous_cause: KeyboardInterrupt | SystemExit | None = None
    try:
        return _filesystem._retain_exact_file(
            directory_descriptor,
            file_name=file_name,
            encoded=encoded,
            required_mode=required_mode,
            phase=phase,
        )
    except _filesystem.TrustedTimePostEnrollmentOperatorAuthorityProvisioningError as error:
        reason_code = error.reason_code
        if isinstance(error.__cause__, KeyboardInterrupt):
            # Do not retain the interrupted callee traceback: it may own the
            # native descriptor whose return was lost before Python STORE.
            asynchronous_cause = KeyboardInterrupt()
        elif isinstance(error.__cause__, SystemExit):
            asynchronous_cause = SystemExit()
    if reason_code is None:  # pragma: no cover - the caught type always has a reason.
        raise RuntimeError
    translated = TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
        reason_code
    )
    if asynchronous_cause is not None:
        raise translated from asynchronous_cause
    raise translated from None


def _revalidate_external_published_file(
    *,
    directory_path: Path,
    expected_directory_identity: tuple[int, int],
    file_name: str,
    encoded: bytes,
    required_mode: int,
    phase: str,
    rejected_repository_root: Path,
) -> tuple[int, ...]:
    """Rebind a publication to its named external directory at receipt time."""

    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_external_owner_only_directory(
            directory_path,
            rejected_repository_root=rejected_repository_root,
        )
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
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            f"{phase}_path_revalidation_failed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _candidate_file_name(authority_sha256: str) -> str:
    if not _is_sha256(authority_sha256):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "authority_sha256_invalid"
        )
    return f"{CANDIDATE_FILE_PREFIX}{authority_sha256}{CANDIDATE_FILE_SUFFIX}"


def _decode_exact_authority(
    encoded: bytes,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    try:
        authority = decode_post_enrollment_graceful_stop_operator_authority(encoded)
        if canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority) != encoded:
            raise ValueError
        return authority
    except (
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
        TypeError,
        ValueError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "authority_candidate_invalid"
        ) from None


def _load_exact_start_authority(
    directory_descriptor: int,
) -> tuple[bytes, str]:
    try:
        encoded, _ = _read_relative_file(
            directory_descriptor,
            file_name=START_AUTHORITY_RELATIVE_PATH.name,
            allowed_modes=frozenset({0o644}),
            minimum_bytes=1,
            maximum_bytes=POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
        )
        authority = decode_post_enrollment_operator_authority(encoded)
        if canonical_post_enrollment_operator_authority_bytes(authority) != encoded:
            raise ValueError
        return encoded, authority.public_key_sha256
    except (
        TrustedTimePostEnrollmentOperatorAuthorityError,
        OSError,
        TypeError,
        ValueError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "start_authority_unavailable"
        ) from None


def _revalidate_installed_authorities(
    *,
    repository_root: Path,
    expected_directory_identity: tuple[int, int],
    start_encoded: bytes,
    stop_encoded: bytes,
) -> None:
    """Rebind both distinct authorities to the final named source directory."""

    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_install_directory(repository_root)
        metadata = os.fstat(directory_owner.fileno())
        if (metadata.st_dev, metadata.st_ino) != expected_directory_identity:
            raise OSError
        try:
            _confirm_durable_exact_file(
                directory_owner.fileno(),
                file_name=START_AUTHORITY_RELATIVE_PATH.name,
                encoded=start_encoded,
                required_mode=0o644,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "start_authority_revalidation_failed"
            ) from None
        try:
            _confirm_durable_exact_file(
                directory_owner.fileno(),
                file_name=INSTALLED_AUTHORITY_RELATIVE_PATH.name,
                encoded=stop_encoded,
                required_mode=0o644,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "install_path_revalidation_failed"
            ) from None
    except TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "install_path_revalidation_failed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def prepare_post_enrollment_graceful_stop_operator_authority_candidate(
    *,
    raw_public_key_file: Path,
    candidate_directory: Path,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt:
    """Retain final-form stop public-authority bytes for external review."""

    public_key_bytes = _read_external_file(
        raw_public_key_file,
        allowed_modes=frozenset({0o400, 0o600}),
        minimum_bytes=_RAW_PUBLIC_KEY_BYTES,
        maximum_bytes=_RAW_PUBLIC_KEY_BYTES,
        reason_code="raw_public_key_unavailable",
        rejected_repository_root=REPOSITORY_ROOT,
    )
    try:
        authority = build_post_enrollment_graceful_stop_operator_authority(public_key_bytes)
        encoded = canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
    except TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
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
        directory_owner = _open_external_owner_only_directory(
            exact_directory,
            rejected_repository_root=REPOSITORY_ROOT,
        )
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
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "candidate_path_revalidation_failed"
        )
    _revalidate_external_published_file(
        directory_path=exact_directory,
        expected_directory_identity=directory_identity,
        file_name=candidate_name,
        encoded=encoded,
        required_mode=0o600,
        phase="candidate",
        rejected_repository_root=REPOSITORY_ROOT,
    )
    return TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
        status=PREPARED_STATUS,
        authority_artifact_sha256=authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        artifact_location=candidate_name,
        distinct_start_key_review_required=True,
    )


def _install_post_enrollment_graceful_stop_operator_authority(
    *,
    candidate_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    repository_root: Path,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt:
    if not _is_sha256(expected_authority_sha256):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "expected_authority_sha256_invalid"
        )
    if not _is_sha256(expected_public_key_sha256):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "expected_public_key_sha256_invalid"
        )
    if (
        type(repository_root) is not type(Path())
        or not repository_root.is_absolute()
        or repository_root != Path(os.path.abspath(repository_root))
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "repository_identity_unavailable"
        )
    encoded = _read_external_file(
        candidate_artifact,
        allowed_modes=frozenset({0o400, 0o600}),
        minimum_bytes=1,
        maximum_bytes=(POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES),
        reason_code="authority_candidate_unavailable",
        rejected_repository_root=repository_root,
    )
    authority = _decode_exact_authority(encoded)
    observed_authority_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        candidate_artifact.name != _candidate_file_name(observed_authority_sha256)
        or observed_authority_sha256 != expected_authority_sha256
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "authority_candidate_differs_from_review"
        )
    if authority.public_key_sha256 != expected_public_key_sha256:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "public_key_differs_from_review"
        )

    directory_owner: _OwnedFileDescriptor | None = None
    directory_identity: tuple[int, int] | None = None
    start_encoded: bytes | None = None
    try:
        directory_owner = _open_install_directory(repository_root)
        directory_metadata = os.fstat(directory_owner.fileno())
        directory_identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        start_encoded, start_public_key_sha256 = _load_exact_start_authority(
            directory_owner.fileno()
        )
        if start_public_key_sha256 == authority.public_key_sha256:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "stop_public_key_not_distinct"
            )
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
    if directory_identity is None or start_encoded is None:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "install_path_revalidation_failed"
        )
    _revalidate_installed_authorities(
        repository_root=repository_root,
        expected_directory_identity=directory_identity,
        start_encoded=start_encoded,
        stop_encoded=encoded,
    )
    return TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt(
        status=INSTALLED_STATUS,
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        artifact_location=INSTALLED_AUTHORITY_RELATIVE_PATH.as_posix(),
        distinct_start_key_review_required=False,
    )


def install_post_enrollment_graceful_stop_operator_authority(
    *,
    candidate_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt:
    """Install reviewed stop bytes only after exact distinct-start-key proof."""

    return _install_post_enrollment_graceful_stop_operator_authority(
        candidate_artifact=candidate_artifact,
        expected_authority_sha256=expected_authority_sha256,
        expected_public_key_sha256=expected_public_key_sha256,
        repository_root=REPOSITORY_ROOT,
    )


def _require_repository_first_party_sources(repository_root: Path) -> None:
    _filesystem._require_repository_first_party_sources(repository_root)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
            "command_arguments_invalid"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description=(
            "Prepare or install verification-only graceful-stop operator public authority material."
        ),
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
    receipt: TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt,
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
            receipt = prepare_post_enrollment_graceful_stop_operator_authority_candidate(
                raw_public_key_file=arguments.raw_public_key_file,
                candidate_directory=arguments.candidate_directory,
            )
        elif arguments.operation == "install":
            receipt = install_post_enrollment_graceful_stop_operator_authority(
                candidate_artifact=arguments.candidate_artifact,
                expected_authority_sha256=arguments.expected_authority_sha256,
                expected_public_key_sha256=arguments.expected_public_key_sha256,
            )
        else:  # pragma: no cover - argparse enforces the closed operation set.
            raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError(
                "command_arguments_invalid"
            )
    except TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError as error:
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
    "START_AUTHORITY_RELATIVE_PATH",
    "TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningError",
    "TrustedTimePostEnrollmentGracefulStopOperatorAuthorityProvisioningReceipt",
    "install_post_enrollment_graceful_stop_operator_authority",
    "main",
    "prepare_post_enrollment_graceful_stop_operator_authority_candidate",
]
