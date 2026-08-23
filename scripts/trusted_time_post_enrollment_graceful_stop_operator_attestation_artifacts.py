"""Prepare and verify inert graceful-stop detached-attestation artifacts.

The two operations in this module accept only explicit external public inputs.
They retain exact statement or envelope candidates without discovering an
installed authority, handling a private key, admitting a stop, or reaching any
runtime, container, database, network, or trading surface.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Never, Protocol, SupportsIndex, cast
from uuid import RFC_4122, UUID


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
        raise RuntimeError(
            "graceful-stop operator-attestation artifact CLI runtime attestation failed"
        ) from None
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
        raise RuntimeError(
            "graceful-stop operator-attestation artifact CLI runtime attestation failed"
        )
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError(
                "graceful-stop operator-attestation artifact CLI runtime attestation failed"
            ) from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError(
                "graceful-stop operator-attestation artifact CLI runtime attestation failed"
            )
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
        )
    )
    if __name__ == "__main__"
    else None
)

from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
)
from packages.domain.trusted_time_enrollment_evidence import (  # noqa: E402
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
    build_post_enrollment_graceful_stop_operator_attestation_envelope,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
    canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes,
    canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
    decode_post_enrollment_graceful_stop_operator_attestation_statement,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
    decode_post_enrollment_graceful_stop_operator_authority,
)
from scripts import (  # noqa: E402
    trusted_time_post_enrollment_operator_attestation_artifacts as _audited_fs,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (  # noqa: E402
    TrustedTimePostEnrollmentGracefulStopDecision,
    TrustedTimePostEnrollmentGracefulStopRejected,
    canonical_post_enrollment_graceful_stop_decision_bytes,
    decode_post_enrollment_graceful_stop_decision,
)

ARTIFACT_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-operator-attestation-artifact-receipt-v1"
)
ARTIFACT_WORKFLOW_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation-artifacts"
)
STATEMENT_CANDIDATE_PREPARED_STATUS = (
    "graceful_stop_operator_attestation_statement_candidate_prepared_unqualified"
)
ENVELOPE_CANDIDATE_VERIFIED_STATUS = (
    "graceful_stop_operator_attestation_envelope_verified_unqualified"
)
STATEMENT_SIGNATURE_AUTHENTICATION_STATUS = "not_authenticated"
ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS = "authenticated_unqualified"

AUTHORITY_CANDIDATE_FILE_PREFIX = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority-"
)
GRACEFUL_STOP_DECISION_V1_FILE_PREFIX = "trusted-time-post-enrollment-graceful-stop-decision-v1-"
STATEMENT_CANDIDATE_FILE_PREFIX = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation-statement-"
)
ENVELOPE_CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-graceful-stop-decision-v2-"
ARTIFACT_FILE_SUFFIX = ".json"

_INPUT_MODES = frozenset({0o400, 0o600})
_RAW_ED25519_SIGNATURE_BYTES = 64
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_RECEIPT_CONSTRUCTION_CAPABILITY = object()
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

_STATEMENT_RECEIPT_CORE_FIELDS = frozenset(
    {
        "artifact_location",
        "authority_artifact_sha256",
        "authority_material_source",
        "contract_version",
        "currentness_qualified",
        "freshness_qualified",
        "graceful_stop_decision_v1_semantically_qualified",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "installed_authority_used",
        "key_id",
        "later_atomic_stop_admission_revalidation_required",
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
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS = frozenset(
    {
        *_STATEMENT_RECEIPT_CORE_FIELDS,
        *POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    }
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS = frozenset(
    {
        *_STATEMENT_RECEIPT_CORE_FIELDS,
        *POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
        "detached_signature_sha256",
        "operator_attestation_envelope_sha256",
    }
)


class TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(RuntimeError):
    """One sanitized offline graceful-stop artifact-workflow failure."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 4 and parsed.variant == RFC_4122 and str(parsed) == value


def _authority_is_never_granted(_: object) -> bool:
    return False


def _require_digest(value: object, *, field_name: str) -> str:
    if not _is_sha256(value):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            f"expected_{field_name}_sha256_invalid"
        )
    return cast(str, value)


class _ReceiptCore(Protocol):
    @property
    def authority_artifact_sha256(self) -> str: ...

    @property
    def public_key_sha256(self) -> str: ...

    @property
    def graceful_stop_decision_v1_sha256(self) -> str: ...

    @property
    def graceful_stop_operation_id(self) -> str: ...

    @property
    def graceful_stop_target_sha256(self) -> str: ...

    @property
    def operator_attestation_statement_sha256(self) -> str: ...

    @property
    def artifact_location(self) -> str: ...


def _receipt_core_is_valid(value: _ReceiptCore) -> bool:
    return (
        _is_sha256(value.authority_artifact_sha256)
        and _is_sha256(value.public_key_sha256)
        and _is_sha256(value.graceful_stop_decision_v1_sha256)
        and _is_uuid4(value.graceful_stop_operation_id)
        and _is_sha256(value.graceful_stop_target_sha256)
        and _is_sha256(value.operator_attestation_statement_sha256)
        and type(value.artifact_location) is str
        and bool(value.artifact_location)
        and "/" not in value.artifact_location
        and "\x00" not in value.artifact_location
    )


def _statement_receipt_seal(value: _ReceiptCore) -> tuple[object, ...]:
    return (
        value.authority_artifact_sha256,
        value.public_key_sha256,
        value.graceful_stop_decision_v1_sha256,
        value.graceful_stop_operation_id,
        value.graceful_stop_target_sha256,
        value.operator_attestation_statement_sha256,
        value.artifact_location,
    )


def _common_receipt_payload(
    value: _ReceiptCore,
    *,
    status: str,
    signature_status: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False
        for field_name in (
            POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        )
    }
    payload.update(
        {
            "artifact_location": value.artifact_location,
            "authority_artifact_sha256": value.authority_artifact_sha256,
            "authority_material_source": "explicit_external_candidate",
            "contract_version": ARTIFACT_RECEIPT_CONTRACT_VERSION,
            "currentness_qualified": False,
            "freshness_qualified": False,
            "graceful_stop_decision_v1_semantically_qualified": False,
            "graceful_stop_decision_v1_sha256": value.graceful_stop_decision_v1_sha256,
            "graceful_stop_operation_id": value.graceful_stop_operation_id,
            "graceful_stop_target_sha256": value.graceful_stop_target_sha256,
            "installed_authority_used": False,
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "later_atomic_stop_admission_revalidation_required": True,
            "operator_attestation_statement_sha256": (value.operator_attestation_statement_sha256),
            "operator_signature_authentication": signature_status,
            "public_key_sha256": value.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": ARTIFACT_WORKFLOW_SERVICE,
            "single_use_qualified": False,
            "status": status,
            "structural_receipt_only": True,
            "verification_only": True,
        }
    )
    return payload


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt:
    """Sealed public digest receipt for one prepared statement candidate."""

    authority_artifact_sha256: str
    public_key_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    operator_attestation_statement_sha256: str
    artifact_location: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        operator_attestation_statement_sha256: str,
        artifact_location: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt
            or _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "statement_receipt_invalid"
            )
        for name, value in (
            ("authority_artifact_sha256", authority_artifact_sha256),
            ("public_key_sha256", public_key_sha256),
            ("graceful_stop_decision_v1_sha256", graceful_stop_decision_v1_sha256),
            ("graceful_stop_operation_id", graceful_stop_operation_id),
            ("graceful_stop_target_sha256", graceful_stop_target_sha256),
            ("operator_attestation_statement_sha256", operator_attestation_statement_sha256),
            ("artifact_location", artifact_location),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", _statement_receipt_seal(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt
            or not _receipt_core_is_valid(self)
            or self.artifact_location
            != _statement_candidate_file_name(self.operator_attestation_statement_sha256)
            or _statement_receipt_seal(self) != getattr(self, "_sealed_fields", None)
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "statement_receipt_invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return STATEMENT_CANDIDATE_PREPARED_STATUS

    @property
    def public_payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _common_receipt_payload(
            self,
            status=self.status,
            signature_status=STATEMENT_SIGNATURE_AUTHENTICATION_STATUS,
        )
        if (
            set(payload)
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "statement_receipt_invalid"
            )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_receipt_invalid"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_receipt_invalid"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_receipt_invalid"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_receipt_invalid"
        )


def _envelope_receipt_seal(
    value: TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt,
) -> tuple[object, ...]:
    return (
        *_statement_receipt_seal(value),
        value.detached_signature_sha256,
        value.operator_attestation_envelope_sha256,
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt:
    """Sealed public digest receipt for one verified envelope candidate."""

    authority_artifact_sha256: str
    public_key_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    operator_attestation_statement_sha256: str
    detached_signature_sha256: str
    operator_attestation_envelope_sha256: str
    artifact_location: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        operator_attestation_statement_sha256: str,
        detached_signature_sha256: str,
        operator_attestation_envelope_sha256: str,
        artifact_location: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt
            or _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "envelope_receipt_invalid"
            )
        for name, value in (
            ("authority_artifact_sha256", authority_artifact_sha256),
            ("public_key_sha256", public_key_sha256),
            ("graceful_stop_decision_v1_sha256", graceful_stop_decision_v1_sha256),
            ("graceful_stop_operation_id", graceful_stop_operation_id),
            ("graceful_stop_target_sha256", graceful_stop_target_sha256),
            ("operator_attestation_statement_sha256", operator_attestation_statement_sha256),
            ("detached_signature_sha256", detached_signature_sha256),
            ("operator_attestation_envelope_sha256", operator_attestation_envelope_sha256),
            ("artifact_location", artifact_location),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", _envelope_receipt_seal(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt
            or not _receipt_core_is_valid(self)
            or not _is_sha256(self.detached_signature_sha256)
            or not _is_sha256(self.operator_attestation_envelope_sha256)
            or self.artifact_location
            != _envelope_candidate_file_name(self.operator_attestation_envelope_sha256)
            or _envelope_receipt_seal(self) != getattr(self, "_sealed_fields", None)
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "envelope_receipt_invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return ENVELOPE_CANDIDATE_VERIFIED_STATUS

    @property
    def public_payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _common_receipt_payload(
            self,
            status=self.status,
            signature_status=ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS,
        )
        payload.update(
            {
                "detached_signature_sha256": self.detached_signature_sha256,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
            }
        )
        if (
            set(payload)
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "envelope_receipt_invalid"
            )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "envelope_receipt_invalid"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "envelope_receipt_invalid"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "envelope_receipt_invalid"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "envelope_receipt_invalid"
        )


for (
    _authority_field
) in POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS:
    setattr(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt,
        _authority_field,
        property(_authority_is_never_granted),
    )
    setattr(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt,
        _authority_field,
        property(_authority_is_never_granted),
    )


def _translate_engine_error(error: BaseException) -> Never:
    if isinstance(error, _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            error.reason_code
        ) from None
    raise error


def _read_external_binding(
    path: Path,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    phase: str,
) -> _audited_fs._ExternalFileBinding:
    try:
        return _audited_fs._read_external_binding(
            path,
            allowed_modes=_INPUT_MODES,
            minimum_bytes=minimum_bytes,
            maximum_bytes=maximum_bytes,
            phase=phase,
        )
    except BaseException as error:
        _translate_engine_error(error)


def _revalidate_external_binding(
    binding: _audited_fs._ExternalFileBinding,
) -> None:
    try:
        _audited_fs._revalidate_external_binding(binding)
    except BaseException as error:
        _translate_engine_error(error)


def _publish_candidate(
    *,
    directory: Path,
    file_name: str,
    encoded: bytes,
    maximum_bytes: int,
    phase: str,
) -> tuple[int, ...]:
    try:
        return _audited_fs._publish_candidate(
            directory=directory,
            file_name=file_name,
            encoded=encoded,
            maximum_bytes=maximum_bytes,
            phase=phase,
        )
    except BaseException as error:
        _translate_engine_error(error)


def _content_addressed_file_name(*, prefix: str, artifact_sha256: str) -> str:
    if not _is_sha256(artifact_sha256):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "artifact_sha256_invalid"
        )
    file_name = f"{prefix}{artifact_sha256}{ARTIFACT_FILE_SUFFIX}"
    if (
        file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > 255
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "artifact_sha256_invalid"
        )
    return file_name


def _authority_candidate_file_name(authority_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=AUTHORITY_CANDIDATE_FILE_PREFIX,
        artifact_sha256=authority_sha256,
    )


def _decision_v1_file_name(decision_sha256: str) -> str:
    return _content_addressed_file_name(
        prefix=GRACEFUL_STOP_DECISION_V1_FILE_PREFIX,
        artifact_sha256=decision_sha256,
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


def _load_authority_candidate(
    *,
    authority_artifact: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
) -> tuple[
    _audited_fs._ExternalFileBinding,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    str,
]:
    binding = _read_external_binding(
        authority_artifact,
        minimum_bytes=1,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
        phase="authority_artifact",
    )
    try:
        binding_encoded = _audited_fs._external_file_encoded(binding)
        authority = decode_post_enrollment_graceful_stop_operator_authority(binding_encoded)
        if (
            canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
            != binding_encoded
        ):
            raise ValueError
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "authority_artifact_invalid"
        ) from None
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        Path(_audited_fs._external_file_path(binding)).name
        != _authority_candidate_file_name(observed_sha256)
        or observed_sha256 != expected_authority_sha256
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "authority_artifact_differs_from_review"
        )
    if authority.public_key_sha256 != expected_public_key_sha256:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "public_key_differs_from_review"
        )
    return binding, authority, observed_sha256


def _load_decision_v1(
    *,
    graceful_stop_decision_v1_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
) -> tuple[
    _audited_fs._ExternalFileBinding,
    TrustedTimePostEnrollmentGracefulStopDecision,
    str,
    str,
    str,
]:
    binding = _read_external_binding(
        graceful_stop_decision_v1_artifact,
        minimum_bytes=1,
        maximum_bytes=(
            POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES
        ),
        phase="graceful_stop_decision_v1_artifact",
    )
    try:
        binding_encoded = _audited_fs._external_file_encoded(binding)
        decision = decode_post_enrollment_graceful_stop_decision(binding_encoded)
        if canonical_post_enrollment_graceful_stop_decision_bytes(decision) != binding_encoded:
            raise ValueError
        operation_id = decision.operation_id
        target_sha256 = decision.target.target_sha256
    except (TypeError, ValueError, TrustedTimePostEnrollmentGracefulStopRejected):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "graceful_stop_decision_v1_artifact_invalid"
        ) from None
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        Path(_audited_fs._external_file_path(binding)).name
        != _decision_v1_file_name(observed_sha256)
        or observed_sha256 != expected_graceful_stop_decision_v1_sha256
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "graceful_stop_decision_v1_artifact_differs_from_review"
        )
    return binding, decision, observed_sha256, operation_id, target_sha256


def _load_statement_candidate(
    *,
    statement_artifact: Path,
    expected_statement_sha256: str,
    expected_statement_encoded: bytes,
) -> _audited_fs._ExternalFileBinding:
    binding = _read_external_binding(
        statement_artifact,
        minimum_bytes=1,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
        phase="statement_artifact",
    )
    try:
        binding_encoded = _audited_fs._external_file_encoded(binding)
        statement = decode_post_enrollment_graceful_stop_operator_attestation_statement(
            binding_encoded
        )
        if (
            canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
            != binding_encoded
        ):
            raise ValueError
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_artifact_invalid"
        ) from None
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if (
        Path(_audited_fs._external_file_path(binding)).name
        != _statement_candidate_file_name(observed_sha256)
        or observed_sha256 != expected_statement_sha256
        or binding_encoded != expected_statement_encoded
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "statement_artifact_differs_from_review"
        )
    return binding


def _load_detached_signature(
    *,
    detached_signature_file: Path,
    expected_signature_sha256: str,
) -> tuple[_audited_fs._ExternalFileBinding, str]:
    binding = _read_external_binding(
        detached_signature_file,
        minimum_bytes=_RAW_ED25519_SIGNATURE_BYTES,
        maximum_bytes=_RAW_ED25519_SIGNATURE_BYTES,
        phase="detached_signature",
    )
    binding_encoded = _audited_fs._external_file_encoded(binding)
    observed_sha256 = hashlib.sha256(binding_encoded).hexdigest()
    if observed_sha256 != expected_signature_sha256:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "detached_signature_differs_from_review"
        )
    return binding, observed_sha256


def prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate(
    *,
    authority_artifact: Path,
    graceful_stop_decision_v1_artifact: Path,
    statement_candidate_directory: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    expected_graceful_stop_decision_v1_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt:
    """Retain exact unqualified stop statement bytes for external signing."""

    reviewed_authority_sha256 = _require_digest(
        expected_authority_sha256,
        field_name="authority",
    )
    reviewed_public_key_sha256 = _require_digest(
        expected_public_key_sha256,
        field_name="public_key",
    )
    reviewed_decision_sha256 = _require_digest(
        expected_graceful_stop_decision_v1_sha256,
        field_name="graceful_stop_decision_v1",
    )
    authority_binding, authority, observed_authority_sha256 = _load_authority_candidate(
        authority_artifact=authority_artifact,
        expected_authority_sha256=reviewed_authority_sha256,
        expected_public_key_sha256=reviewed_public_key_sha256,
    )
    decision_binding, _, observed_decision_sha256, operation_id, target_sha256 = _load_decision_v1(
        graceful_stop_decision_v1_artifact=graceful_stop_decision_v1_artifact,
        expected_graceful_stop_decision_v1_sha256=reviewed_decision_sha256,
    )
    try:
        statement = build_post_enrollment_graceful_stop_operator_attestation_statement(
            authority=authority,
            graceful_stop_decision_v1_sha256=observed_decision_sha256,
            graceful_stop_operation_id=operation_id,
            graceful_stop_target_sha256=target_sha256,
        )
        statement_encoded = (
            canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
        )
        if (
            decode_post_enrollment_graceful_stop_operator_attestation_statement(statement_encoded)
            != statement
        ):
            raise ValueError
    except (TypeError, ValueError, TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "operator_attestation_statement_invalid"
        ) from None
    statement_sha256 = hashlib.sha256(statement_encoded).hexdigest()
    statement_file_name = _statement_candidate_file_name(statement_sha256)
    _revalidate_external_binding(authority_binding)
    _revalidate_external_binding(decision_binding)
    _publish_candidate(
        directory=statement_candidate_directory,
        file_name=statement_file_name,
        encoded=statement_encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
        phase="statement_candidate",
    )
    return TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt(
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        graceful_stop_decision_v1_sha256=observed_decision_sha256,
        graceful_stop_operation_id=operation_id,
        graceful_stop_target_sha256=target_sha256,
        operator_attestation_statement_sha256=statement_sha256,
        artifact_location=statement_file_name,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate(
    *,
    authority_artifact: Path,
    graceful_stop_decision_v1_artifact: Path,
    statement_artifact: Path,
    detached_signature_file: Path,
    envelope_candidate_directory: Path,
    expected_authority_sha256: str,
    expected_public_key_sha256: str,
    expected_graceful_stop_decision_v1_sha256: str,
    expected_statement_sha256: str,
    expected_signature_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt:
    """Authenticate and retain one unqualified stop envelope candidate."""

    reviewed_authority_sha256 = _require_digest(
        expected_authority_sha256,
        field_name="authority",
    )
    reviewed_public_key_sha256 = _require_digest(
        expected_public_key_sha256,
        field_name="public_key",
    )
    reviewed_decision_sha256 = _require_digest(
        expected_graceful_stop_decision_v1_sha256,
        field_name="graceful_stop_decision_v1",
    )
    reviewed_statement_sha256 = _require_digest(
        expected_statement_sha256,
        field_name="statement",
    )
    reviewed_signature_sha256 = _require_digest(
        expected_signature_sha256,
        field_name="signature",
    )
    authority_binding, authority, observed_authority_sha256 = _load_authority_candidate(
        authority_artifact=authority_artifact,
        expected_authority_sha256=reviewed_authority_sha256,
        expected_public_key_sha256=reviewed_public_key_sha256,
    )
    decision_binding, _, observed_decision_sha256, operation_id, target_sha256 = _load_decision_v1(
        graceful_stop_decision_v1_artifact=graceful_stop_decision_v1_artifact,
        expected_graceful_stop_decision_v1_sha256=reviewed_decision_sha256,
    )
    try:
        expected_statement = build_post_enrollment_graceful_stop_operator_attestation_statement(
            authority=authority,
            graceful_stop_decision_v1_sha256=observed_decision_sha256,
            graceful_stop_operation_id=operation_id,
            graceful_stop_target_sha256=target_sha256,
        )
        expected_statement_encoded = (
            canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(
                expected_statement
            )
        )
    except TrustedTimePostEnrollmentGracefulStopOperatorAttestationError:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
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
        statement = decode_post_enrollment_graceful_stop_operator_attestation_statement(
            _audited_fs._external_file_encoded(statement_binding)
        )
        envelope = build_post_enrollment_graceful_stop_operator_attestation_envelope(
            graceful_stop_decision_v1=_audited_fs._external_file_encoded(decision_binding),
            statement=statement,
            signature_ed25519=_audited_fs._external_file_encoded(signature_binding),
        )
        envelope_encoded = (
            canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(envelope)
        )
        snapshot = decode_post_enrollment_graceful_stop_operator_attestation_envelope(
            envelope_encoded
        )
        if (
            canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(snapshot)
            != envelope_encoded
        ):
            raise ValueError
        verifier = Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority(
            authority
        )
        verification = verifier.verify(snapshot)
        if (
            type(verification)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification
        ):
            raise ValueError
        envelope_sha256 = hashlib.sha256(envelope_encoded).hexdigest()
        verification_payload = verification.payload()
        expected_verification_fields = frozenset(
            {
                *POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
                "authority_artifact_sha256",
                "contract_version",
                "graceful_stop_decision_v1_sha256",
                "graceful_stop_operation_id",
                "graceful_stop_target_sha256",
                "operator_attestation_envelope_sha256",
                "operator_attestation_signature_sha256",
                "operator_attestation_statement_sha256",
                "public_key_sha256",
                "service",
                "status",
                "verification_only",
            }
        )
        if (
            set(verification_payload) != expected_verification_fields
            or verification_payload["contract_version"]
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
            or verification_payload["service"]
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
            or verification_payload["status"]
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS
            or verification_payload["verification_only"] is not True
            or verification.verification_only is not True
            or verification.authority_artifact_sha256 != observed_authority_sha256
            or verification.public_key_sha256 != authority.public_key_sha256
            or verification.graceful_stop_decision_v1_sha256 != observed_decision_sha256
            or verification.graceful_stop_operation_id != operation_id
            or verification.graceful_stop_target_sha256 != target_sha256
            or verification.operator_attestation_statement_sha256 != reviewed_statement_sha256
            or verification.operator_attestation_signature_sha256 != observed_signature_sha256
            or verification.operator_attestation_envelope_sha256 != envelope_sha256
            or any(
                verification_payload[field_name] is not False
                for field_name in (
                    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
                )
            )
        ):
            raise ValueError
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "operator_attestation_signature_verification_failed"
        ) from None
    for binding in (
        authority_binding,
        decision_binding,
        statement_binding,
        signature_binding,
    ):
        _revalidate_external_binding(binding)
    _publish_candidate(
        directory=envelope_candidate_directory,
        file_name=_envelope_candidate_file_name(envelope_sha256),
        encoded=envelope_encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
        phase="envelope_candidate",
    )
    return TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt(
        authority_artifact_sha256=observed_authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        graceful_stop_decision_v1_sha256=observed_decision_sha256,
        graceful_stop_operation_id=operation_id,
        graceful_stop_target_sha256=target_sha256,
        operator_attestation_statement_sha256=reviewed_statement_sha256,
        detached_signature_sha256=observed_signature_sha256,
        operator_attestation_envelope_sha256=envelope_sha256,
        artifact_location=_envelope_candidate_file_name(envelope_sha256),
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _require_repository_first_party_sources(repository_root: Path) -> None:
    try:
        _audited_fs._require_repository_first_party_sources(repository_root)
    except RuntimeError:
        raise RuntimeError(
            "graceful-stop operator-attestation first-party source attestation failed"
        ) from None


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
            "command_arguments_invalid"
        )


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-artifact", type=Path, required=True)
    parser.add_argument("--graceful-stop-decision-v1-artifact", type=Path, required=True)
    parser.add_argument("--expected-authority-sha256", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--expected-graceful-stop-decision-v1-sha256", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description=(
            "Prepare or authenticate unqualified graceful-stop detached-attestation artifacts."
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
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt
        | TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt
    ),
) -> bytes:
    return canonical_first_enrollment_json_bytes(receipt.public_payload)


def main(argv: list[str] | None = None) -> int:
    """Run one verification-only phase and emit only its public digest receipt."""

    try:
        if _CLI_REPOSITORY_ROOT is not None:
            _require_repository_first_party_sources(_CLI_REPOSITORY_ROOT)
        arguments = _parser().parse_args(argv)
        receipt: (
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt
            | TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt
        )
        if arguments.operation == "prepare-statement":
            receipt = (
                prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate(
                    authority_artifact=arguments.authority_artifact,
                    graceful_stop_decision_v1_artifact=arguments.graceful_stop_decision_v1_artifact,
                    statement_candidate_directory=arguments.statement_candidate_directory,
                    expected_authority_sha256=arguments.expected_authority_sha256,
                    expected_public_key_sha256=arguments.expected_public_key_sha256,
                    expected_graceful_stop_decision_v1_sha256=(
                        arguments.expected_graceful_stop_decision_v1_sha256
                    ),
                )
            )
        elif arguments.operation == "verify-signature":
            verify_operation = verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate  # noqa: E501
            receipt = verify_operation(
                authority_artifact=arguments.authority_artifact,
                graceful_stop_decision_v1_artifact=arguments.graceful_stop_decision_v1_artifact,
                statement_artifact=arguments.statement_artifact,
                detached_signature_file=arguments.detached_signature_file,
                envelope_candidate_directory=arguments.envelope_candidate_directory,
                expected_authority_sha256=arguments.expected_authority_sha256,
                expected_public_key_sha256=arguments.expected_public_key_sha256,
                expected_graceful_stop_decision_v1_sha256=(
                    arguments.expected_graceful_stop_decision_v1_sha256
                ),
                expected_statement_sha256=arguments.expected_statement_sha256,
                expected_signature_sha256=arguments.expected_signature_sha256,
            )
        else:  # pragma: no cover - argparse enforces the closed set.
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError(
                "command_arguments_invalid"
            )
    except TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError as error:
        print(error.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_receipt_bytes(receipt).decode("ascii"))
    return 0


if __name__ == "__main__":  # pragma: no cover - isolated subprocess coverage.
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_FILE_SUFFIX",
    "ARTIFACT_RECEIPT_CONTRACT_VERSION",
    "ARTIFACT_WORKFLOW_SERVICE",
    "AUTHORITY_CANDIDATE_FILE_PREFIX",
    "ENVELOPE_CANDIDATE_FILE_PREFIX",
    "ENVELOPE_CANDIDATE_VERIFIED_STATUS",
    "ENVELOPE_SIGNATURE_AUTHENTICATION_STATUS",
    "GRACEFUL_STOP_DECISION_V1_FILE_PREFIX",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS",
    "STATEMENT_CANDIDATE_FILE_PREFIX",
    "STATEMENT_CANDIDATE_PREPARED_STATUS",
    "STATEMENT_SIGNATURE_AUTHENTICATION_STATUS",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt",
    "main",
    "prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate",
    "verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate",
]
