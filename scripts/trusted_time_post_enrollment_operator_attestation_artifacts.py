"""Prepare and verify inert detached operator-attestation artifacts.

``prepare-statement`` binds one explicit, reviewed public-authority candidate to
one explicit v2 execution-approval artifact and retains the exact bytes that an
external custody process may sign.  ``verify-signature`` independently reloads
all reviewed inputs, authenticates one externally produced raw Ed25519
signature, and retains a content-addressed public v3 envelope candidate.

The v2 check in this module is deliberately structural: exact canonical JSON,
the frozen top-level contract/service/status identity, content address, and
cross-bindings are checked.  The receipts remain semantically unqualified and
require a later atomic cutover to reload and fully validate v2 semantics.  This
module has no key generation, signer, private key, standard-input, environment,
network, database, container, admission, host, controller, or runtime surface.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast


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
        raise RuntimeError("operator-attestation artifact CLI runtime attestation failed") from None
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
        raise RuntimeError("operator-attestation artifact CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError(
                "operator-attestation artifact CLI runtime attestation failed"
            ) from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("operator-attestation artifact CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path(
            "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
        )
    )
    if __name__ == "__main__"
    else None
)

from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _create_child_regular_exclusive,
    _fchmod_0600,
    _flock,
    _fstat,
    _fsync,
    _ftruncate,
    _open_child_directory,
    _open_child_regular,
    _open_root_directory,
    _OwnedFileDescriptor,
    _read_snapshot,
    _statat,
    _write_all,
)
from packages.adapters.trusted_time.ed25519_operator_attestation import (  # noqa: E402
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    Ed25519PostEnrollmentOperatorAttestationVerifier,
    TrustedTimePostEnrollmentOperatorAttestationVerification,
    TrustedTimePostEnrollmentOperatorAttestationVerificationError,
)
from packages.domain.trusted_time_enrollment_evidence import (  # noqa: E402
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (  # noqa: E402
    EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
    EXECUTION_APPROVAL_V2_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
    TrustedTimePostEnrollmentOperatorAttestationError,
    build_post_enrollment_operator_attestation_envelope,
    build_post_enrollment_operator_attestation_statement,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    canonical_post_enrollment_operator_attestation_statement_bytes,
    decode_post_enrollment_operator_attestation_envelope,
    decode_post_enrollment_operator_attestation_statement,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (  # noqa: E402
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    TrustedTimePostEnrollmentOperatorAuthority,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
)

ARTIFACT_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-operator-attestation-artifact-receipt-v1"
)
ARTIFACT_WORKFLOW_SERVICE = "trusted-time-post-enrollment-operator-attestation-artifacts"
STATEMENT_CANDIDATE_PREPARED_STATUS = (
    "operator_attestation_statement_candidate_prepared_unqualified"
)
ENVELOPE_CANDIDATE_VERIFIED_STATUS = "operator_attestation_envelope_verified_unqualified"
EXECUTION_APPROVAL_V2_VALIDATION_STATUS = "canonical_top_level_identity_only_semantics_unqualified"
STATEMENT_SIGNATURE_AUTHENTICATION_STATUS = "not_authenticated"
ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS = "authenticated_unqualified"

AUTHORITY_CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-operator-attestation-authority-"
EXECUTION_APPROVAL_V2_FILE_PREFIX = "trusted-time-post-enrollment-start-execution-approval-"
STATEMENT_CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-operator-attestation-statement-"
ENVELOPE_CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-start-execution-approval-v3-"
ARTIFACT_FILE_SUFFIX = ".json"

_STATEMENT_RECEIPT_CORE_FIELDS = frozenset(
    {
        "artifact_location",
        "authority_artifact_sha256",
        "authority_material_source",
        "contract_version",
        "execution_approval_v2_sha256",
        "execution_approval_v2_semantically_qualified",
        "execution_approval_v2_validation",
        "freshness_qualified",
        "installed_authority_used",
        "key_id",
        "later_atomic_cutover_revalidation_required",
        "operator_attestation_statement_sha256",
        "operator_signature_authentication",
        "public_key_sha256",
        "replay_domain",
        "service",
        "single_use_qualified",
        "status",
        "structural_receipt_only",
        "verification_only",
    }
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS = frozenset(
    {
        *_STATEMENT_RECEIPT_CORE_FIELDS,
        *POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    }
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS,
        "detached_signature_sha256",
        "operator_attestation_envelope_sha256",
    }
)

_REPOSITORY_ROOT_STRING = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REPOSITORY_ROOT = Path(_REPOSITORY_ROOT_STRING)
_RAW_ED25519_SIGNATURE_BYTES = 64
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_INPUT_MODES = frozenset({0o400, 0o600})
_OUTPUT_MODE = 0o600
_RECEIPT_CONSTRUCTION_CAPABILITY = object()


class TrustedTimePostEnrollmentOperatorAttestationArtifactError(RuntimeError):
    """One sanitized detached-artifact workflow failure reason."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _authority_is_never_granted(_: object) -> bool:
    return False


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentOperatorAttestationStatementReceipt:
    """Sealed digest-only receipt for an unqualified statement candidate."""

    authority_artifact_sha256: str
    public_key_sha256: str
    execution_approval_v2_sha256: str
    operator_attestation_statement_sha256: str
    artifact_location: str
    _sealed_fields: tuple[str, str, str, str, str] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        execution_approval_v2_sha256: str,
        operator_attestation_statement_sha256: str,
        artifact_location: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentOperatorAttestationStatementReceipt
            or _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )
        values = (
            authority_artifact_sha256,
            public_key_sha256,
            execution_approval_v2_sha256,
            operator_attestation_statement_sha256,
            artifact_location,
        )
        object.__setattr__(self, "authority_artifact_sha256", authority_artifact_sha256)
        object.__setattr__(self, "public_key_sha256", public_key_sha256)
        object.__setattr__(self, "execution_approval_v2_sha256", execution_approval_v2_sha256)
        object.__setattr__(
            self,
            "operator_attestation_statement_sha256",
            operator_attestation_statement_sha256,
        )
        object.__setattr__(self, "artifact_location", artifact_location)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        values = (
            self.authority_artifact_sha256,
            self.public_key_sha256,
            self.execution_approval_v2_sha256,
            self.operator_attestation_statement_sha256,
            self.artifact_location,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentOperatorAttestationStatementReceipt
            or values != getattr(self, "_sealed_fields", None)
            or not all(_is_sha256(value) for value in values[:4])
            or self.artifact_location
            != _statement_candidate_file_name(self.operator_attestation_statement_sha256)
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return STATEMENT_CANDIDATE_PREPARED_STATUS

    @property
    def public_payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_authority_payload()
        payload.update(
            {
                "artifact_location": self.artifact_location,
                "authority_artifact_sha256": self.authority_artifact_sha256,
                "authority_material_source": (
                    "explicit_external_adr0100_content_addressed_candidate"
                ),
                "contract_version": ARTIFACT_RECEIPT_CONTRACT_VERSION,
                "execution_approval_v2_sha256": self.execution_approval_v2_sha256,
                "execution_approval_v2_semantically_qualified": False,
                "execution_approval_v2_validation": EXECUTION_APPROVAL_V2_VALIDATION_STATUS,
                "freshness_qualified": False,
                "installed_authority_used": False,
                "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
                "later_atomic_cutover_revalidation_required": True,
                "operator_attestation_statement_sha256": (
                    self.operator_attestation_statement_sha256
                ),
                "operator_signature_authentication": (STATEMENT_SIGNATURE_AUTHENTICATION_STATUS),
                "public_key_sha256": self.public_key_sha256,
                "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
                "service": ARTIFACT_WORKFLOW_SERVICE,
                "single_use_qualified": False,
                "status": self.status,
                "structural_receipt_only": True,
                "verification_only": True,
            }
        )
        if set(payload) != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS:
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_serialized"
        )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt:
    """Sealed digest-only receipt for an authenticated unqualified envelope."""

    authority_artifact_sha256: str
    public_key_sha256: str
    execution_approval_v2_sha256: str
    operator_attestation_statement_sha256: str
    detached_signature_sha256: str
    operator_attestation_envelope_sha256: str
    artifact_location: str
    _sealed_fields: tuple[str, str, str, str, str, str, str] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        execution_approval_v2_sha256: str,
        operator_attestation_statement_sha256: str,
        detached_signature_sha256: str,
        operator_attestation_envelope_sha256: str,
        artifact_location: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt
            or _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )
        values = (
            authority_artifact_sha256,
            public_key_sha256,
            execution_approval_v2_sha256,
            operator_attestation_statement_sha256,
            detached_signature_sha256,
            operator_attestation_envelope_sha256,
            artifact_location,
        )
        object.__setattr__(self, "authority_artifact_sha256", authority_artifact_sha256)
        object.__setattr__(self, "public_key_sha256", public_key_sha256)
        object.__setattr__(self, "execution_approval_v2_sha256", execution_approval_v2_sha256)
        object.__setattr__(
            self,
            "operator_attestation_statement_sha256",
            operator_attestation_statement_sha256,
        )
        object.__setattr__(self, "detached_signature_sha256", detached_signature_sha256)
        object.__setattr__(
            self,
            "operator_attestation_envelope_sha256",
            operator_attestation_envelope_sha256,
        )
        object.__setattr__(self, "artifact_location", artifact_location)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        values = (
            self.authority_artifact_sha256,
            self.public_key_sha256,
            self.execution_approval_v2_sha256,
            self.operator_attestation_statement_sha256,
            self.detached_signature_sha256,
            self.operator_attestation_envelope_sha256,
            self.artifact_location,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt
            or values != getattr(self, "_sealed_fields", None)
            or not all(_is_sha256(value) for value in values[:6])
            or self.artifact_location
            != _envelope_candidate_file_name(self.operator_attestation_envelope_sha256)
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return ENVELOPE_CANDIDATE_VERIFIED_STATUS

    @property
    def public_payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_authority_payload()
        payload.update(
            {
                "artifact_location": self.artifact_location,
                "authority_artifact_sha256": self.authority_artifact_sha256,
                "authority_material_source": (
                    "explicit_external_adr0100_content_addressed_candidate"
                ),
                "contract_version": ARTIFACT_RECEIPT_CONTRACT_VERSION,
                "detached_signature_sha256": self.detached_signature_sha256,
                "execution_approval_v2_sha256": self.execution_approval_v2_sha256,
                "execution_approval_v2_semantically_qualified": False,
                "execution_approval_v2_validation": EXECUTION_APPROVAL_V2_VALIDATION_STATUS,
                "freshness_qualified": False,
                "installed_authority_used": False,
                "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
                "later_atomic_cutover_revalidation_required": True,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "operator_attestation_statement_sha256": (
                    self.operator_attestation_statement_sha256
                ),
                "operator_signature_authentication": (ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS),
                "public_key_sha256": self.public_key_sha256,
                "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
                "service": ARTIFACT_WORKFLOW_SERVICE,
                "single_use_qualified": False,
                "status": self.status,
                "structural_receipt_only": True,
                "verification_only": True,
            }
        )
        if set(payload) != POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS:
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "artifact_receipt_invalid"
            )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "artifact_receipt_cannot_be_serialized"
        )


for _authority_field in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS:
    setattr(
        TrustedTimePostEnrollmentOperatorAttestationStatementReceipt,
        _authority_field,
        property(_authority_is_never_granted),
    )
    setattr(
        TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt,
        _authority_field,
        property(_authority_is_never_granted),
    )


def _closed_authority_payload() -> dict[str, object]:
    return {
        field_name: False
        for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
    }


def _preferred_cleanup_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_cleanup_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_cleanup_exception(preferred, error)
    return preferred


def _cleanup_owned_descriptors(
    owners: tuple[_OwnedFileDescriptor | None, ...],
) -> BaseException | None:
    """Attempt every close and report the preferred cleanup failure."""

    first_error: BaseException | None = None
    for owner in owners:
        if owner is None:
            continue
        for _ in range(2):
            try:
                if owner.closed:
                    break
                owner.close()
            except BaseException as error:
                first_error = _preferred_cleanup_exception(first_error, error)
        try:
            if not owner.closed:
                first_error = _preferred_cleanup_exception(
                    first_error,
                    RuntimeError("owned file descriptor could not be closed"),
                )
        except BaseException as error:
            first_error = _preferred_cleanup_exception(first_error, error)
    return first_error


_StatIdentity = tuple[int, int, int, int, int, int, int, int, int]


def _require_stat_identity(value: object) -> _StatIdentity:
    if (
        type(value) is not tuple
        or len(value) != 9
        or any(type(field) is not int for field in value)
    ):
        raise OSError
    return cast(_StatIdentity, value)


type _ExternalFileBinding = tuple[
    str,
    str,
    bytes,
    tuple[int, int],
    _StatIdentity,
    frozenset[int],
    int,
    int,
    str,
]


def _make_external_file_binding(
    *,
    path: str,
    encoded: bytes,
    directory_identity: tuple[int, int],
    file_identity: _StatIdentity,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    phase: str,
) -> _ExternalFileBinding:
    return (
        "operator-attestation-external-file-binding-v1",
        path,
        encoded,
        directory_identity,
        file_identity,
        allowed_modes,
        minimum_bytes,
        maximum_bytes,
        phase,
    )


def _require_external_file_binding(value: object) -> _ExternalFileBinding:
    if type(value) is not tuple or len(value) != 9:
        raise OSError
    tag = tuple.__getitem__(value, 0)
    path = tuple.__getitem__(value, 1)
    encoded = tuple.__getitem__(value, 2)
    directory_identity = tuple.__getitem__(value, 3)
    file_identity = tuple.__getitem__(value, 4)
    allowed_modes = tuple.__getitem__(value, 5)
    minimum_bytes = tuple.__getitem__(value, 6)
    maximum_bytes = tuple.__getitem__(value, 7)
    phase = tuple.__getitem__(value, 8)
    if (
        tag != "operator-attestation-external-file-binding-v1"
        or type(tag) is not str
        or type(path) is not str
        or type(encoded) is not bytes
        or type(directory_identity) is not tuple
        or len(directory_identity) != 2
        or any(type(item) is not int for item in directory_identity)
        or type(file_identity) is not tuple
        or len(file_identity) != 9
        or any(type(item) is not int for item in file_identity)
        or type(allowed_modes) is not frozenset
        or not allowed_modes
        or any(type(item) is not int for item in allowed_modes)
        or type(minimum_bytes) is not int
        or type(maximum_bytes) is not int
        or minimum_bytes < 0
        or maximum_bytes < minimum_bytes
        or len(encoded) < minimum_bytes
        or len(encoded) > maximum_bytes
        or type(phase) is not str
        or not phase
    ):
        raise OSError
    return cast(_ExternalFileBinding, value)


def _external_file_path(binding: object) -> str:
    return cast(str, tuple.__getitem__(_require_external_file_binding(binding), 1))


def _external_file_encoded(binding: object) -> bytes:
    return cast(bytes, tuple.__getitem__(_require_external_file_binding(binding), 2))


def _external_file_directory_identity(binding: object) -> tuple[int, int]:
    return cast(
        tuple[int, int],
        tuple.__getitem__(_require_external_file_binding(binding), 3),
    )


def _external_file_file_identity(binding: object) -> _StatIdentity:
    return cast(
        _StatIdentity,
        tuple.__getitem__(_require_external_file_binding(binding), 4),
    )


def _external_file_allowed_modes(binding: object) -> frozenset[int]:
    return cast(
        frozenset[int],
        tuple.__getitem__(_require_external_file_binding(binding), 5),
    )


def _external_file_minimum_bytes(binding: object) -> int:
    return cast(
        int,
        tuple.__getitem__(_require_external_file_binding(binding), 6),
    )


def _external_file_maximum_bytes(binding: object) -> int:
    return cast(
        int,
        tuple.__getitem__(_require_external_file_binding(binding), 7),
    )


def _external_file_phase(binding: object) -> str:
    return cast(str, tuple.__getitem__(_require_external_file_binding(binding), 8))


def _absolute_path(value: object, *, reason_code: str) -> str:
    if type(value) is not type(Path()):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(reason_code)
    try:
        raw = os.fspath(value)
        absolute = os.path.abspath(raw)
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(reason_code) from None
    if (
        type(raw) is not str
        or not os.path.isabs(raw)
        or os.path.basename(raw) in {"", ".", ".."}
        or absolute != raw
        or os.path.normpath(raw) != raw
        or "\x00" in raw
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(reason_code)
    return absolute


def _absolute_path_components(path: str) -> tuple[str, ...]:
    if (
        type(path) is not str
        or not os.path.isabs(path)
        or os.path.abspath(path) != path
        or os.path.normpath(path) != path
        or "\x00" in path
    ):
        raise OSError
    components = tuple(path.split(os.sep))[1:]
    if any(
        not component
        or component in {".", ".."}
        or os.sep in component
        or "\x00" in component
        or len(os.fsencode(component)) > 255
        for component in components
    ):
        raise OSError
    return components


def _require_external_directory_metadata(
    metadata: tuple[int, ...],
    *,
    rejected_identity: tuple[int, int],
) -> tuple[int, int]:
    exact = _require_stat_identity(metadata)
    if (
        (exact[0], exact[1]) == rejected_identity
        or not stat.S_ISDIR(exact[2])
        or exact[3] != os.geteuid()
        or stat.S_IMODE(exact[2]) != 0o700
    ):
        raise OSError
    return exact[0], exact[1]


def _repository_identity() -> tuple[int, int]:
    repository_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    result: tuple[int, int] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            repository_owner = _open_root_directory()
            for component in _absolute_path_components(_REPOSITORY_ROOT_STRING):
                next_owner = _open_child_directory(repository_owner, component)
                intermediate_error = _cleanup_owned_descriptors((repository_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                repository_owner = next_owner
                next_owner = None
            metadata = _require_stat_identity(_fstat(repository_owner))
            if not stat.S_ISDIR(metadata[2]):
                raise OSError
            result = metadata[0], metadata[1]
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((next_owner, repository_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((next_owner, repository_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "repository_identity_unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "repository_identity_unavailable"
        )
    return result


def _require_file_component(file_name: object) -> str:
    if (
        type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or os.sep in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > 255
    ):
        raise OSError
    return file_name


def _read_relative_file(
    directory_owner: _OwnedFileDescriptor,
    *,
    file_name: str,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
) -> tuple[bytes, _StatIdentity]:
    file_owner: _OwnedFileDescriptor | None = None
    result: tuple[bytes, _StatIdentity] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            exact_file_name = _require_file_component(file_name)
            directory_before = _require_stat_identity(_fstat(directory_owner))
            file_owner = _open_child_regular(directory_owner, exact_file_name)
            payload, before, after = _read_snapshot(file_owner, maximum_bytes)
            before = _require_stat_identity(before)
            after = _require_stat_identity(after)
            if (
                not stat.S_ISREG(before[2])
                or before[3] != os.geteuid()
                or stat.S_IMODE(before[2]) not in allowed_modes
                or before[5] != 1
                or before[6] < minimum_bytes
                or before[6] > maximum_bytes
            ):
                raise OSError
            named = _require_stat_identity(_statat(directory_owner, exact_file_name))
            directory_after = _require_stat_identity(_fstat(directory_owner))
            if (
                len(payload) != before[6]
                or len(payload) > maximum_bytes
                or before != after
                or after != named
                or directory_before != directory_after
            ):
                raise OSError
            result = payload, after
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((file_owner,))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((file_owner,))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise RuntimeError("relative file read did not produce a result")
    return result


def _read_external_binding(
    path: Path,
    *,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    phase: str,
) -> _ExternalFileBinding:
    exact_path = _absolute_path(path, reason_code=f"{phase}_path_invalid")
    directory_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    result: _ExternalFileBinding | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            directory_path = os.path.dirname(exact_path)
            file_name = _require_file_component(os.path.basename(exact_path))
            repository_identity = _repository_identity()
            directory_owner = _open_root_directory()
            root_metadata = _require_stat_identity(_fstat(directory_owner))
            if (root_metadata[0], root_metadata[1]) == repository_identity:
                raise OSError
            for component in _absolute_path_components(directory_path):
                next_owner = _open_child_directory(directory_owner, component)
                next_metadata = _require_stat_identity(_fstat(next_owner))
                if (next_metadata[0], next_metadata[1]) == repository_identity:
                    raise OSError
                intermediate_error = _cleanup_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_owner
                next_owner = None
            directory_identity = _require_external_directory_metadata(
                _fstat(directory_owner),
                rejected_identity=repository_identity,
            )
            encoded, file_identity = _read_relative_file(
                directory_owner,
                file_name=file_name,
                allowed_modes=allowed_modes,
                minimum_bytes=minimum_bytes,
                maximum_bytes=maximum_bytes,
            )
            result = _make_external_file_binding(
                path=exact_path,
                encoded=encoded,
                directory_identity=directory_identity,
                file_identity=file_identity,
                allowed_modes=allowed_modes,
                minimum_bytes=minimum_bytes,
                maximum_bytes=maximum_bytes,
                phase=phase,
            )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        if isinstance(
            terminal,
            TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        ) and terminal.reason_code.endswith("_path_invalid"):
            raise terminal
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(f"{phase}_unavailable")
    return result


def _revalidate_external_binding(binding: _ExternalFileBinding) -> None:
    directory_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    phase = "external_artifact"
    try:
        try:
            exact_binding = _require_external_file_binding(binding)
            path = cast(
                str,
                tuple.__getitem__(exact_binding, 1),
            )
            encoded_expected = cast(
                bytes,
                tuple.__getitem__(exact_binding, 2),
            )
            directory_identity_expected = cast(
                tuple[int, int],
                tuple.__getitem__(
                    exact_binding,
                    3,
                ),
            )
            file_identity_expected = cast(
                _StatIdentity,
                tuple.__getitem__(exact_binding, 4),
            )
            allowed_modes = cast(
                frozenset[int],
                tuple.__getitem__(exact_binding, 5),
            )
            minimum_bytes = cast(
                int,
                tuple.__getitem__(exact_binding, 6),
            )
            maximum_bytes = cast(
                int,
                tuple.__getitem__(exact_binding, 7),
            )
            phase = cast(
                str,
                tuple.__getitem__(exact_binding, 8),
            )
            directory_path = os.path.dirname(path)
            file_name = _require_file_component(os.path.basename(path))
            repository_identity = _repository_identity()
            directory_owner = _open_root_directory()
            root_metadata = _require_stat_identity(_fstat(directory_owner))
            if (root_metadata[0], root_metadata[1]) == repository_identity:
                raise OSError
            for component in _absolute_path_components(directory_path):
                next_owner = _open_child_directory(directory_owner, component)
                next_metadata = _require_stat_identity(_fstat(next_owner))
                if (next_metadata[0], next_metadata[1]) == repository_identity:
                    raise OSError
                intermediate_error = _cleanup_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_owner
                next_owner = None
            directory_identity = _require_external_directory_metadata(
                _fstat(directory_owner),
                rejected_identity=repository_identity,
            )
            if directory_identity != directory_identity_expected:
                raise OSError
            encoded, identity = _read_relative_file(
                directory_owner,
                file_name=file_name,
                allowed_modes=allowed_modes,
                minimum_bytes=minimum_bytes,
                maximum_bytes=maximum_bytes,
            )
            if encoded != encoded_expected or identity != file_identity_expected:
                raise OSError
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_path_revalidation_failed"
        ) from None


def _confirm_durable_exact_file(
    directory_owner: _OwnedFileDescriptor,
    *,
    file_name: str,
    encoded: bytes,
    required_mode: int,
) -> _StatIdentity:
    file_owner: _OwnedFileDescriptor | None = None
    result: _StatIdentity | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            exact_file_name = _require_file_component(file_name)
            directory_before = _require_stat_identity(_fstat(directory_owner))
            file_owner = _open_child_regular(directory_owner, exact_file_name)
            _flock(file_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observed, before, after_read = _read_snapshot(file_owner, len(encoded))
            before = _require_stat_identity(before)
            after_read = _require_stat_identity(after_read)
            if (
                not stat.S_ISREG(before[2])
                or before[3] != os.geteuid()
                or stat.S_IMODE(before[2]) != required_mode
                or before[5] != 1
                or before[6] != len(encoded)
            ):
                raise OSError
            named = _require_stat_identity(_statat(directory_owner, exact_file_name))
            if observed != encoded or before != after_read or after_read != named:
                raise OSError
            _fsync(file_owner)
            _fsync(directory_owner)
            final_payload, final_before, final = _read_snapshot(
                file_owner,
                len(encoded),
            )
            final_before = _require_stat_identity(final_before)
            final = _require_stat_identity(final)
            named_final = _require_stat_identity(_statat(directory_owner, exact_file_name))
            directory_final = _require_stat_identity(_fstat(directory_owner))
            if (
                final_payload != encoded
                or before != final_before
                or final_before != final
                or final != named_final
                or directory_before != directory_final
            ):
                raise OSError
            result = final
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((file_owner,))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((file_owner,))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise RuntimeError("durable file confirmation did not produce an identity")
    return result


def _retain_exact_file(
    directory_owner: _OwnedFileDescriptor,
    *,
    file_name: str,
    encoded: bytes,
    maximum_bytes: int,
    phase: str,
) -> _StatIdentity:
    file_owner: _OwnedFileDescriptor | None = None
    creation_call_started = False
    confirmation_required = False
    result: _StatIdentity | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            try:
                creation_call_started = True
                exact_file_name = _require_file_component(file_name)
                file_owner = _create_child_regular_exclusive(
                    directory_owner,
                    exact_file_name,
                )
            except FileExistsError:
                creation_call_started = False
                try:
                    existing, _ = _read_relative_file(
                        directory_owner,
                        file_name=exact_file_name,
                        allowed_modes=frozenset({_OUTPUT_MODE}),
                        minimum_bytes=1,
                        maximum_bytes=maximum_bytes,
                    )
                    if existing != encoded:
                        raise OSError
                    result = _confirm_durable_exact_file(
                        directory_owner,
                        file_name=exact_file_name,
                        encoded=encoded,
                        required_mode=_OUTPUT_MODE,
                    )
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                        f"{phase}_retention_unconfirmed"
                    ) from None
            else:
                _flock(file_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                _write_all(file_owner, encoded)
                _ftruncate(file_owner, len(encoded))
                _fchmod_0600(file_owner)
                _fsync(file_owner)
                _fsync(directory_owner)
                confirmation_required = True
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((file_owner,))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((file_owner,))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        if isinstance(
            terminal,
            TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        ):
            raise terminal
        if creation_call_started:
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                f"{phase}_retention_unconfirmed"
            ) from terminal
        raise terminal
    if confirmation_required:
        try:
            result = _confirm_durable_exact_file(
                directory_owner,
                file_name=exact_file_name,
                encoded=encoded,
                required_mode=_OUTPUT_MODE,
            )
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                f"{phase}_retention_unconfirmed"
            ) from error
    if result is None:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_retention_unconfirmed"
        )
    return result


def _revalidate_external_published_file(
    *,
    directory_path: str,
    expected_directory_identity: tuple[int, int],
    file_name: str,
    encoded: bytes,
    phase: str,
) -> _StatIdentity:
    directory_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    result: _StatIdentity | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            if type(directory_path) is not str:
                raise OSError
            repository_identity = _repository_identity()
            directory_owner = _open_root_directory()
            root_metadata = _require_stat_identity(_fstat(directory_owner))
            if (root_metadata[0], root_metadata[1]) == repository_identity:
                raise OSError
            for component in _absolute_path_components(directory_path):
                next_owner = _open_child_directory(directory_owner, component)
                next_metadata = _require_stat_identity(_fstat(next_owner))
                if (next_metadata[0], next_metadata[1]) == repository_identity:
                    raise OSError
                intermediate_error = _cleanup_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_owner
                next_owner = None
            directory_identity = _require_external_directory_metadata(
                _fstat(directory_owner),
                rejected_identity=repository_identity,
            )
            if directory_identity != expected_directory_identity:
                raise OSError
            result = _confirm_durable_exact_file(
                directory_owner,
                file_name=file_name,
                encoded=encoded,
                required_mode=_OUTPUT_MODE,
            )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_path_revalidation_failed"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_path_revalidation_failed"
        )
    return result


def _content_addressed_file_name(*, prefix: str, artifact_sha256: str) -> str:
    if not _is_sha256(artifact_sha256):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError("artifact_sha256_invalid")
    file_name = f"{prefix}{artifact_sha256}{ARTIFACT_FILE_SUFFIX}"
    if (
        file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > 255
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError("artifact_sha256_invalid")
    return file_name


def _authority_candidate_file_name(authority_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=AUTHORITY_CANDIDATE_FILE_PREFIX,
        artifact_sha256=authority_sha256,
    )


def _execution_approval_v2_file_name(execution_approval_v2_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=EXECUTION_APPROVAL_V2_FILE_PREFIX,
        artifact_sha256=execution_approval_v2_sha256,
    )


def _statement_candidate_file_name(statement_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=STATEMENT_CANDIDATE_FILE_PREFIX,
        artifact_sha256=statement_sha256,
    )


def _envelope_candidate_file_name(envelope_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=ENVELOPE_CANDIDATE_FILE_PREFIX,
        artifact_sha256=envelope_sha256,
    )


def _require_expected_sha256(value: object, *, field_name: str) -> str:
    if not _is_sha256(value):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"expected_{field_name}_sha256_invalid"
        )
    return cast(str, value)


class _DuplicateJsonField(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJsonField
        payload[key] = value
    return payload


def _reject_json_constant(_: str) -> Never:
    raise ValueError


def _validate_structural_execution_approval_v2(encoded: bytes) -> None:
    """Validate only canonical JSON and the frozen top-level v2 identity."""

    try:
        payload = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if type(payload) is not dict:
            raise ValueError
        canonical = canonical_first_enrollment_json_bytes(payload)
        if canonical != encoded:
            raise ValueError
        exact_identity = {
            "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
            "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
            "status": EXECUTION_APPROVAL_V2_STATUS,
        }
        if any(
            type(payload.get(field_name)) is not str or payload.get(field_name) != expected_value
            for field_name, expected_value in exact_identity.items()
        ):
            raise ValueError
    except (
        TypeError,
        UnicodeError,
        ValueError,
        RecursionError,
        TrustedTimeEnrollmentEvidenceError,
        _DuplicateJsonField,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "execution_approval_v2_artifact_invalid"
        ) from None


def _load_authority_candidate(
    *,
    authority_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
) -> tuple[
    _ExternalFileBinding,
    TrustedTimePostEnrollmentOperatorAuthority,
    str,
]:
    binding = _read_external_binding(
        authority_artifact,
        allowed_modes=_INPUT_MODES,
        minimum_bytes=1,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
        phase="authority_artifact",
    )
    try:
        binding_encoded = _external_file_encoded(binding)
        authority = decode_post_enrollment_operator_authority(binding_encoded)
        if canonical_post_enrollment_operator_authority_bytes(authority) != binding_encoded:
            raise ValueError
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentOperatorAuthorityError,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "authority_artifact_invalid"
        ) from None
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        os.path.basename(_external_file_path(binding))
        != _authority_candidate_file_name(observed_sha256)
        or observed_sha256 != expected_authority_sha256
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "authority_artifact_differs_from_review"
        )
    if authority.public_key_sha256 != expected_public_key_sha256:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "public_key_differs_from_review"
        )
    return binding, authority, observed_sha256


def _load_execution_approval_v2(
    *,
    execution_approval_v2_artifact: Path,
    expected_execution_approval_v2_sha256: str,
) -> tuple[_ExternalFileBinding, str]:
    binding = _read_external_binding(
        execution_approval_v2_artifact,
        allowed_modes=_INPUT_MODES,
        minimum_bytes=1,
        maximum_bytes=(POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES),
        phase="execution_approval_v2_artifact",
    )
    binding_encoded = _external_file_encoded(binding)
    _validate_structural_execution_approval_v2(binding_encoded)
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        os.path.basename(_external_file_path(binding))
        != _execution_approval_v2_file_name(observed_sha256)
        or observed_sha256 != expected_execution_approval_v2_sha256
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "execution_approval_v2_artifact_differs_from_review"
        )
    return binding, observed_sha256


def _publish_candidate(
    *,
    directory: Path,
    file_name: str,
    encoded: bytes,
    maximum_bytes: int,
    phase: str,
    expected_directory_identity: tuple[int, int] | None = None,
) -> _StatIdentity:
    if expected_directory_identity is not None and (
        type(expected_directory_identity) is not tuple
        or len(expected_directory_identity) != 2
        or any(type(value) is not int for value in expected_directory_identity)
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_directory_unavailable"
        )
    exact_directory = _absolute_path(
        directory,
        reason_code=f"{phase}_directory_path_invalid",
    )
    directory_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    publication_attempted = False
    directory_identity: tuple[int, int] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            repository_identity = _repository_identity()
            directory_owner = _open_root_directory()
            root_metadata = _require_stat_identity(_fstat(directory_owner))
            if (root_metadata[0], root_metadata[1]) == repository_identity:
                raise OSError
            for component in _absolute_path_components(exact_directory):
                next_owner = _open_child_directory(directory_owner, component)
                next_metadata = _require_stat_identity(_fstat(next_owner))
                if (next_metadata[0], next_metadata[1]) == repository_identity:
                    raise OSError
                intermediate_error = _cleanup_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_owner
                next_owner = None
            directory_identity = _require_external_directory_metadata(
                _fstat(directory_owner),
                rejected_identity=repository_identity,
            )
            if (
                expected_directory_identity is not None
                and directory_identity != expected_directory_identity
            ):
                raise OSError
            publication_attempted = True
            _retain_exact_file(
                directory_owner,
                file_name=file_name,
                encoded=encoded,
                maximum_bytes=maximum_bytes,
                phase=phase,
            )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_owned_descriptors((next_owner, directory_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        if (
            isinstance(
                terminal,
                TrustedTimePostEnrollmentOperatorAttestationArtifactError,
            )
            and terminal.reason_code == f"{phase}_directory_path_invalid"
        ):
            raise terminal
        if publication_attempted:
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                f"{phase}_retention_unconfirmed"
            ) from terminal
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_directory_unavailable"
        ) from None
    if directory_identity is None:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_directory_unavailable"
        )
    try:
        return _revalidate_external_published_file(
            directory_path=exact_directory,
            expected_directory_identity=directory_identity,
            file_name=file_name,
            encoded=encoded,
            phase=phase,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            f"{phase}_retention_unconfirmed"
        ) from error


def prepare_post_enrollment_operator_attestation_statement_candidate(
    *,
    authority_artifact: Path,
    execution_approval_v2_artifact: Path,
    statement_candidate_directory: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    expected_execution_approval_v2_sha256: str,
) -> TrustedTimePostEnrollmentOperatorAttestationStatementReceipt:
    """Retain the exact unqualified statement bytes for external signing."""

    reviewed_authority_sha256 = _require_expected_sha256(
        expected_authority_sha256,
        field_name="authority",
    )
    reviewed_public_key_sha256 = _require_expected_sha256(
        expected_public_key_sha256,
        field_name="public_key",
    )
    reviewed_v2_sha256 = _require_expected_sha256(
        expected_execution_approval_v2_sha256,
        field_name="execution_approval_v2",
    )
    authority_binding, authority, observed_authority_sha256 = _load_authority_candidate(
        authority_artifact=authority_artifact,
        expected_authority_sha256=reviewed_authority_sha256,
        expected_public_key_sha256=reviewed_public_key_sha256,
    )
    v2_binding, observed_v2_sha256 = _load_execution_approval_v2(
        execution_approval_v2_artifact=execution_approval_v2_artifact,
        expected_execution_approval_v2_sha256=reviewed_v2_sha256,
    )
    try:
        statement = build_post_enrollment_operator_attestation_statement(
            authority=authority,
            execution_approval_v2_sha256=observed_v2_sha256,
        )
        statement_encoded = canonical_post_enrollment_operator_attestation_statement_bytes(
            statement
        )
        if decode_post_enrollment_operator_attestation_statement(statement_encoded) != statement:
            raise ValueError
    except (TypeError, ValueError, TrustedTimePostEnrollmentOperatorAttestationError):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "operator_attestation_statement_invalid"
        ) from None
    statement_sha256 = hashlib.sha256(statement_encoded).hexdigest()
    statement_file_name = _statement_candidate_file_name(statement_sha256)
    _revalidate_external_binding(authority_binding)
    _revalidate_external_binding(v2_binding)
    _publication_identity = _publish_candidate(
        directory=statement_candidate_directory,
        file_name=statement_file_name,
        encoded=statement_encoded,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
        phase="statement_candidate",
    )
    return TrustedTimePostEnrollmentOperatorAttestationStatementReceipt(
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        execution_approval_v2_sha256=observed_v2_sha256,
        operator_attestation_statement_sha256=statement_sha256,
        artifact_location=statement_file_name,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _load_statement_candidate(
    *,
    statement_artifact: Path,
    expected_statement_sha256: str,
    expected_statement_encoded: bytes,
) -> _ExternalFileBinding:
    binding = _read_external_binding(
        statement_artifact,
        allowed_modes=_INPUT_MODES,
        minimum_bytes=1,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
        phase="statement_artifact",
    )
    try:
        binding_encoded = _external_file_encoded(binding)
        statement = decode_post_enrollment_operator_attestation_statement(binding_encoded)
        if (
            canonical_post_enrollment_operator_attestation_statement_bytes(statement)
            != binding_encoded
        ):
            raise ValueError
    except (TypeError, ValueError, TrustedTimePostEnrollmentOperatorAttestationError):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "statement_artifact_invalid"
        ) from None
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        os.path.basename(_external_file_path(binding))
        != _statement_candidate_file_name(observed_sha256)
        or observed_sha256 != expected_statement_sha256
        or binding_encoded != expected_statement_encoded
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "statement_artifact_differs_from_review"
        )
    return binding


def _load_detached_signature(
    *,
    detached_signature_file: Path,
    expected_signature_sha256: str,
) -> tuple[_ExternalFileBinding, str]:
    binding = _read_external_binding(
        detached_signature_file,
        allowed_modes=_INPUT_MODES,
        minimum_bytes=_RAW_ED25519_SIGNATURE_BYTES,
        maximum_bytes=_RAW_ED25519_SIGNATURE_BYTES,
        phase="detached_signature",
    )
    observed_sha256 = hashlib.sha256(_external_file_encoded(binding)).hexdigest()
    if observed_sha256 != expected_signature_sha256:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "detached_signature_differs_from_review"
        )
    return binding, observed_sha256


def verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
    *,
    authority_artifact: Path,
    execution_approval_v2_artifact: Path,
    statement_artifact: Path,
    detached_signature_file: Path,
    envelope_candidate_directory: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    expected_execution_approval_v2_sha256: str,
    expected_statement_sha256: str,
    expected_signature_sha256: str,
) -> TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt:
    """Authenticate and retain an unqualified public v3 envelope candidate."""

    reviewed_authority_sha256 = _require_expected_sha256(
        expected_authority_sha256,
        field_name="authority",
    )
    reviewed_public_key_sha256 = _require_expected_sha256(
        expected_public_key_sha256,
        field_name="public_key",
    )
    reviewed_v2_sha256 = _require_expected_sha256(
        expected_execution_approval_v2_sha256,
        field_name="execution_approval_v2",
    )
    reviewed_statement_sha256 = _require_expected_sha256(
        expected_statement_sha256,
        field_name="statement",
    )
    reviewed_signature_sha256 = _require_expected_sha256(
        expected_signature_sha256,
        field_name="signature",
    )
    authority_binding, authority, observed_authority_sha256 = _load_authority_candidate(
        authority_artifact=authority_artifact,
        expected_authority_sha256=reviewed_authority_sha256,
        expected_public_key_sha256=reviewed_public_key_sha256,
    )
    v2_binding, observed_v2_sha256 = _load_execution_approval_v2(
        execution_approval_v2_artifact=execution_approval_v2_artifact,
        expected_execution_approval_v2_sha256=reviewed_v2_sha256,
    )
    try:
        expected_statement = build_post_enrollment_operator_attestation_statement(
            authority=authority,
            execution_approval_v2_sha256=observed_v2_sha256,
        )
        expected_statement_encoded = canonical_post_enrollment_operator_attestation_statement_bytes(
            expected_statement
        )
    except TrustedTimePostEnrollmentOperatorAttestationError:
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "operator_attestation_statement_invalid"
        ) from None
    statement_binding = _load_statement_candidate(
        statement_artifact=statement_artifact,
        expected_statement_sha256=reviewed_statement_sha256,
        expected_statement_encoded=expected_statement_encoded,
    )
    signature_binding, observed_signature_sha256 = _load_detached_signature(
        detached_signature_file=detached_signature_file,
        expected_signature_sha256=reviewed_signature_sha256,
    )
    try:
        statement = decode_post_enrollment_operator_attestation_statement(
            _external_file_encoded(statement_binding)
        )
        envelope = build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=_external_file_encoded(v2_binding),
            statement=statement,
            signature_ed25519=_external_file_encoded(signature_binding),
        )
        envelope_encoded = canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
        snapshot = decode_post_enrollment_operator_attestation_envelope(envelope_encoded)
        if (
            canonical_post_enrollment_operator_attestation_envelope_bytes(snapshot)
            != envelope_encoded
        ):
            raise ValueError
        verifier = Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)
        verification = verifier.verify(snapshot)
        envelope_sha256 = hashlib.sha256(envelope_encoded).hexdigest()
        verification_payload = verification.payload()
        expected_verification_fields = frozenset(
            {
                *POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
                "authority_artifact_sha256",
                "contract_version",
                "execution_approval_v2_sha256",
                "operator_attestation_envelope_sha256",
                "operator_attestation_statement_sha256",
                "public_key_sha256",
                "service",
                "status",
                "verification_only",
            }
        )
        if (
            type(verification) is not TrustedTimePostEnrollmentOperatorAttestationVerification
            or set(verification_payload) != expected_verification_fields
            or verification_payload["contract_version"]
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
            or verification_payload["service"]
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
            or verification_payload["status"]
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
            or verification_payload["verification_only"] is not True
            or verification.verification_only is not True
            or verification.authority_artifact_sha256 != observed_authority_sha256
            or verification.public_key_sha256 != authority.public_key_sha256
            or verification.execution_approval_v2_sha256 != observed_v2_sha256
            or verification.operator_attestation_statement_sha256 != reviewed_statement_sha256
            or verification.operator_attestation_envelope_sha256 != envelope_sha256
            or verification_payload["authority_artifact_sha256"] != observed_authority_sha256
            or verification_payload["public_key_sha256"] != authority.public_key_sha256
            or verification_payload["execution_approval_v2_sha256"] != observed_v2_sha256
            or verification_payload["operator_attestation_statement_sha256"]
            != reviewed_statement_sha256
            or verification_payload["operator_attestation_envelope_sha256"] != envelope_sha256
            or any(
                verification_payload[field_name] is not False
                for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
            )
        ):
            raise ValueError
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
            "operator_attestation_signature_verification_failed"
        ) from None
    envelope_file_name = _envelope_candidate_file_name(envelope_sha256)
    for binding in (
        authority_binding,
        v2_binding,
        statement_binding,
        signature_binding,
    ):
        _revalidate_external_binding(binding)
    _publication_identity = _publish_candidate(
        directory=envelope_candidate_directory,
        file_name=envelope_file_name,
        encoded=envelope_encoded,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
        phase="envelope_candidate",
    )
    return TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt(
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        execution_approval_v2_sha256=observed_v2_sha256,
        operator_attestation_statement_sha256=reviewed_statement_sha256,
        detached_signature_sha256=observed_signature_sha256,
        operator_attestation_envelope_sha256=envelope_sha256,
        artifact_location=envelope_file_name,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _require_repository_first_party_sources(repository_root: Path) -> None:
    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("operator-attestation first-party source attestation failed")
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
            raise RuntimeError(
                "operator-attestation first-party source attestation failed"
            ) from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("operator-attestation first-party source attestation failed")


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise TrustedTimePostEnrollmentOperatorAttestationArtifactError("command_arguments_invalid")


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-artifact", type=Path, required=True)
    parser.add_argument("--execution-approval-v2-artifact", type=Path, required=True)
    parser.add_argument("--expected-authority-sha256", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--expected-execution-approval-v2-sha256", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description=(
            "Prepare or authenticate unqualified detached operator-attestation artifacts."
        ),
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(
        dest="operation",
        required=True,
        parser_class=_SafeArgumentParser,
    )
    prepare = subparsers.add_parser("prepare-statement", allow_abbrev=False)
    _add_shared_arguments(prepare)
    prepare.add_argument("--statement-candidate-directory", type=Path, required=True)
    verify = subparsers.add_parser("verify-signature", allow_abbrev=False)
    _add_shared_arguments(verify)
    verify.add_argument("--statement-artifact", type=Path, required=True)
    verify.add_argument("--detached-signature-file", type=Path, required=True)
    verify.add_argument("--expected-statement-sha256", required=True)
    verify.add_argument("--expected-signature-sha256", required=True)
    verify.add_argument("--envelope-candidate-directory", type=Path, required=True)
    return parser


def _canonical_receipt_bytes(
    receipt: (
        TrustedTimePostEnrollmentOperatorAttestationStatementReceipt
        | TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt
    ),
) -> bytes:
    return canonical_first_enrollment_json_bytes(receipt.public_payload)


def main(argv: list[str] | None = None) -> int:
    """Run one verification-only phase and emit only its digest receipt."""

    try:
        if _CLI_REPOSITORY_ROOT is not None:
            _require_repository_first_party_sources(_CLI_REPOSITORY_ROOT)
        arguments = _parser().parse_args(argv)
        receipt: (
            TrustedTimePostEnrollmentOperatorAttestationStatementReceipt
            | TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt
        )
        if arguments.operation == "prepare-statement":
            receipt = prepare_post_enrollment_operator_attestation_statement_candidate(
                authority_artifact=arguments.authority_artifact,
                execution_approval_v2_artifact=arguments.execution_approval_v2_artifact,
                statement_candidate_directory=arguments.statement_candidate_directory,
                expected_authority_sha256=arguments.expected_authority_sha256,
                expected_public_key_sha256=arguments.expected_public_key_sha256,
                expected_execution_approval_v2_sha256=(
                    arguments.expected_execution_approval_v2_sha256
                ),
            )
        elif arguments.operation == "verify-signature":
            receipt = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
                authority_artifact=arguments.authority_artifact,
                execution_approval_v2_artifact=arguments.execution_approval_v2_artifact,
                statement_artifact=arguments.statement_artifact,
                detached_signature_file=arguments.detached_signature_file,
                envelope_candidate_directory=arguments.envelope_candidate_directory,
                expected_authority_sha256=arguments.expected_authority_sha256,
                expected_public_key_sha256=arguments.expected_public_key_sha256,
                expected_execution_approval_v2_sha256=(
                    arguments.expected_execution_approval_v2_sha256
                ),
                expected_statement_sha256=arguments.expected_statement_sha256,
                expected_signature_sha256=arguments.expected_signature_sha256,
            )
        else:  # pragma: no cover - argparse enforces the closed operation set.
            raise TrustedTimePostEnrollmentOperatorAttestationArtifactError(
                "command_arguments_invalid"
            )
    except TrustedTimePostEnrollmentOperatorAttestationArtifactError as error:
        print(error.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_receipt_bytes(receipt).decode("ascii"))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through isolated subprocess tests.
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_FILE_SUFFIX",
    "ARTIFACT_RECEIPT_CONTRACT_VERSION",
    "ARTIFACT_WORKFLOW_SERVICE",
    "AUTHORITY_CANDIDATE_FILE_PREFIX",
    "ENVELOPE_CANDIDATE_FILE_PREFIX",
    "ENVELOPE_CANDIDATE_VERIFIED_STATUS",
    "ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS",
    "EXECUTION_APPROVAL_V2_FILE_PREFIX",
    "EXECUTION_APPROVAL_V2_VALIDATION_STATUS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS",
    "STATEMENT_CANDIDATE_FILE_PREFIX",
    "STATEMENT_CANDIDATE_PREPARED_STATUS",
    "STATEMENT_SIGNATURE_AUTHENTICATION_STATUS",
    "TrustedTimePostEnrollmentOperatorAttestationArtifactError",
    "TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt",
    "TrustedTimePostEnrollmentOperatorAttestationStatementReceipt",
    "main",
    "prepare_post_enrollment_operator_attestation_statement_candidate",
    "verify_and_retain_post_enrollment_operator_attestation_envelope_candidate",
]
