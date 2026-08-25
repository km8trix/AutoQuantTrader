"""Bind one inert graceful-stop decision to authenticated historical start evidence.

This workflow loads and revalidates the exact committed confirmed start outcome,
the permanent operator-attested v3 start-attempt slot, and the exact external
start-attestation envelope.  It publishes only a content-addressed public
decision candidate for later external stop attestation.  It owns no stop key,
clock, currentness, replay, admission, Docker, database, provider, signal, or
shutdown authority.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast
from uuid import RFC_4122, UUID


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
    _abspath: Callable[[str], str] = os.path.abspath,
    _fspath: Callable[[Any], Any] = os.fspath,
) -> Path:
    """Require canonical source in a disposable isolated Python runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(_abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError(
            "graceful-stop decision artifact CLI runtime attestation failed"
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
        raise RuntimeError("graceful-stop decision artifact CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError(
                "graceful-stop decision artifact CLI runtime attestation failed"
            ) from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("graceful-stop decision artifact CLI runtime attestation failed")
    sys.path.insert(0, _fspath(canonical_root))
    return canonical_root


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path(
            "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
        )
    )
    if __name__ == "__main__"
    else None
)

from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _fstat,
    _open_child_directory,
    _open_root_directory,
)
from scripts import (  # noqa: E402
    trusted_time_post_enrollment_operator_attestation_artifacts as _audited_fs,
)
from scripts.trusted_time_post_enrollment_controller_outcome import (  # noqa: E402
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    _load_retained_post_enrollment_start_controller_outcome_with_snapshot,
    _revalidate_retained_post_enrollment_start_controller_outcome_snapshot,
)
from scripts.trusted_time_post_enrollment_execution_admission import (  # noqa: E402
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
    _load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot,
    _require_attempt_snapshot_binding,
    _revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    TrustedTimePostEnrollmentGracefulStopDecision,
    canonical_post_enrollment_graceful_stop_decision_bytes,
    decode_post_enrollment_graceful_stop_decision,
)
from scripts.verify_trusted_time_images import (  # noqa: E402
    IGNORED_ARTIFACT_ROOT,
)

ARTIFACT_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1"
)
ARTIFACT_WORKFLOW_SERVICE = "trusted-time-post-enrollment-graceful-stop-decision-artifacts"
DECISION_CANDIDATE_PREPARED_STATUS = "graceful_stop_decision_candidate_prepared_unqualified"
DECISION_CANDIDATE_FILE_PREFIX = "trusted-time-post-enrollment-graceful-stop-decision-v1-"
ARTIFACT_FILE_SUFFIX = ".json"

_TRUE_HISTORICAL_FACT_FIELDS = frozenset(
    {
        "committed_confirmed_start_outcome_revalidated",
        "decision_candidate_semantically_bound",
        "durable_shutdown_locator_revalidated",
        "external_stop_attestation_required",
        "historical_evidence_only",
        "historical_start_chain_authenticated",
        "later_atomic_stop_admission_revalidation_required",
        "start_execution_attempt_slot_revalidated",
        "start_operator_attestation_envelope_revalidated",
        "verification_only",
    }
)
_FALSE_QUALIFICATION_FIELDS = frozenset(
    {
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "stop_admission_qualified",
        "stop_attempt_slot_reserved",
        "stop_effect_authorized",
        "stop_operator_signature_authenticated",
        "stop_outcome_or_recovery_available",
    }
)
_RECEIPT_IDENTITY_FIELDS = frozenset(
    {
        "artifact_location",
        "controller_outcome_sha256",
        "durable_shutdown_locator_sha256",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "start_approval_sha256",
        "start_approved_image_provenance_sha256",
        "start_approved_image_provenance_source_revision_sha256",
        "start_execution_attempt_slot_sha256",
        "start_git_revision",
        "start_operation_id",
        "start_operator_attestation_envelope_sha256",
        "start_source_image_id",
        "start_supervisor_image_id",
    }
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        *_TRUE_HISTORICAL_FACT_FIELDS,
        *_FALSE_QUALIFICATION_FIELDS,
        *_RECEIPT_IDENTITY_FIELDS,
        "contract_version",
        "service",
        "status",
    }
)

_RECEIPT_CONSTRUCTION_CAPABILITY = object()
_LOADED_RECEIPT_CONSTRUCTION_CAPABILITY = object()
_CONSUMED_LOADED_RECEIPT_SNAPSHOT_CAPABILITY = object()
_PUBLIC_REVALIDATION_CONSUMER_IDENTITY = object()
_StatIdentity = tuple[int, int, int, int, int, int, int, int, int]
type _ExternalBinding = tuple[
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
_RetainedStartExecutionAttempt = RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
_LOADED_RECEIPT_ORIGIN_PID = os.getpid()
_LOADED_RECEIPT_REGISTRY_LOCK = threading.RLock()


def _registry_process_matches_origin(
    _getpid: Callable[[], int] = os.getpid,
    _origin_pid: int = _LOADED_RECEIPT_ORIGIN_PID,
) -> bool:
    return _getpid() == _origin_pid


def _registry_origin_pid(
    _origin_pid: int = _LOADED_RECEIPT_ORIGIN_PID,
) -> int:
    return _origin_pid


def _registry_current_thread(
    _current_thread: Callable[[], threading.Thread] = threading.current_thread,
) -> threading.Thread:
    return _current_thread()


def _is_exact_registry_thread(
    value: object,
    _thread_type: type[Any] = threading.Thread,
) -> bool:
    return isinstance(value, _thread_type)


def _is_exact_registry_reference(
    value: object,
    _reference_type: type[Any] = weakref.ReferenceType,
) -> bool:
    return type(value) is _reference_type


def _new_exact_registry_reference(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    callback: Callable[[weakref.ReferenceType[Any]], None],
    _reference_factory: Callable[..., weakref.ReferenceType[Any]] = weakref.ref,
) -> weakref.ReferenceType[Any]:
    reference = _reference_factory(value, callback)
    if not _is_exact_registry_reference(reference):
        raise ValueError
    return reference


class TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(RuntimeError):
    """One sanitized inert decision-candidate workflow failure."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _reset_loaded_receipt_registry_lock_after_fork() -> None:
    global _LOADED_RECEIPT_REGISTRY_LOCK

    _LOADED_RECEIPT_REGISTRY_LOCK = threading.RLock()


os.register_at_fork(after_in_child=_reset_loaded_receipt_registry_lock_after_fork)


def _preferred_registry_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_registry_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_registry_exception(preferred, error)
    return preferred


def _loaded_receipt_registry_lock_depth() -> int:
    counter = getattr(_LOADED_RECEIPT_REGISTRY_LOCK, "_recursion_count", None)
    if not callable(counter):
        raise RuntimeError("loaded receipt registry lock is unavailable")
    depth = cast(Callable[[], int], counter)()
    if type(depth) is not int or depth < 0:
        raise RuntimeError("loaded receipt registry lock is unavailable")
    return depth


def _release_loaded_receipt_registry_lock_to_depth(
    expected_depth: int,
) -> BaseException | None:
    first_error: BaseException | None = None
    for _ in range(3):
        try:
            if _loaded_receipt_registry_lock_depth() <= expected_depth:
                break
            _LOADED_RECEIPT_REGISTRY_LOCK.release()
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
    try:
        if _loaded_receipt_registry_lock_depth() > expected_depth:
            return first_error or RuntimeError("loaded receipt registry lock could not be released")
    except BaseException as error:
        return _preferred_registry_exception(first_error, error)
    return first_error


@contextmanager
def _held_loaded_receipt_registry_lock() -> Iterator[None]:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    initial_depth = _loaded_receipt_registry_lock_depth()
    try:
        with _LOADED_RECEIPT_REGISTRY_LOCK:
            yield
    except BaseException as error:
        cleanup_error = _release_loaded_receipt_registry_lock_to_depth(initial_depth)
        terminal = _preferred_registry_exception(error, cleanup_error)
        if terminal is error or terminal is None:
            raise
        raise terminal from error


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _captured_sha256_hexdigest(
    encoded: bytes,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> str:
    if type(encoded) is not bytes:
        raise ValueError
    result: object = _sha256(encoded).hexdigest()
    if not _is_sha256(result):
        raise ValueError
    return cast(str, result)


def _captured_path_string(
    value: object,
    _fspath: Callable[[Any], Any] = os.fspath,
) -> str:
    """Capture one exact path string without a later mutable module lookup."""

    result: object = _fspath(value)
    if type(result) is not str:
        raise ValueError
    return result


def _captured_path_abspath(
    path: str,
    _abspath: Callable[[str], str] = os.path.abspath,
) -> str:
    if type(path) is not str:
        raise ValueError
    result: object = _abspath(path)
    if type(result) is not str:
        raise ValueError
    return result


def _captured_path_basename(
    path: str,
    _basename: Callable[[str], str] = os.path.basename,
) -> str:
    if type(path) is not str:
        raise ValueError
    result: object = _basename(path)
    if type(result) is not str:
        raise ValueError
    return result


def _captured_path_isabs(
    path: str,
    _isabs: Callable[[str], bool] = os.path.isabs,
) -> bool:
    if type(path) is not str:
        raise ValueError
    result: object = _isabs(path)
    if type(result) is not bool:
        raise ValueError
    return result


def _captured_path_join(
    left: str,
    right: str,
    _join: Callable[..., str] = os.path.join,
) -> str:
    if type(left) is not str or type(right) is not str:
        raise ValueError
    result: object = _join(left, right)
    if type(result) is not str:
        raise ValueError
    return result


def _captured_path_normpath(
    path: str,
    _normpath: Callable[[str], str] = os.path.normpath,
) -> str:
    if type(path) is not str:
        raise ValueError
    result: object = _normpath(path)
    if type(result) is not str:
        raise ValueError
    return result


def _is_git_revision(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_image_id(value: object) -> bool:
    return type(value) is str and value.startswith("sha256:") and _is_sha256(value[7:])


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 4 and parsed.variant == RFC_4122 and str(parsed) == value


def _decision_candidate_file_name(
    decision_sha256: str,
    _fsencode: Callable[[str], bytes] = os.fsencode,
) -> str:
    if not _is_sha256(decision_sha256):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_sha256_invalid"
        )
    file_name = f"trusted-time-post-enrollment-graceful-stop-decision-v1-{decision_sha256}.json"
    if (
        file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(_fsencode(file_name)) > 255
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_sha256_invalid"
        )
    return file_name


def _captured_decision_candidate_file_name(
    decision_sha256: str,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
) -> str:
    result: object = _candidate_file_name(decision_sha256)
    if type(result) is not str:
        raise ValueError
    return result


def _receipt_seal_values(value: Any) -> tuple[object, ...]:
    return (
        value.artifact_location,
        value.controller_outcome_sha256,
        value.durable_shutdown_locator_sha256,
        value.graceful_stop_decision_v1_sha256,
        value.graceful_stop_operation_id,
        value.graceful_stop_target_sha256,
        value.start_approval_sha256,
        value.start_approved_image_provenance_sha256,
        value.start_approved_image_provenance_source_revision_sha256,
        value.start_execution_attempt_slot_sha256,
        value.start_git_revision,
        value.start_operation_id,
        value.start_operator_attestation_envelope_sha256,
        value.start_source_image_id,
        value.start_supervisor_image_id,
    )


def _validated_receipt_fact(value: object) -> bool:
    if type(value) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_invalid"
        )
    value.__post_init__()
    return True


def _validated_receipt_non_authority(value: object) -> bool:
    if type(value) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_invalid"
        )
    value.__post_init__()
    return False


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    """Non-authorizing public view of one historical decision receipt."""

    artifact_location: str
    controller_outcome_sha256: str
    durable_shutdown_locator_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    start_approval_sha256: str
    start_approved_image_provenance_sha256: str
    start_approved_image_provenance_source_revision_sha256: str
    start_execution_attempt_slot_sha256: str
    start_git_revision: str
    start_operation_id: str
    start_operator_attestation_envelope_sha256: str
    start_source_image_id: str
    start_supervisor_image_id: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        artifact_location: str,
        controller_outcome_sha256: str,
        durable_shutdown_locator_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        start_approval_sha256: str,
        start_approved_image_provenance_sha256: str,
        start_approved_image_provenance_source_revision_sha256: str,
        start_execution_attempt_slot_sha256: str,
        start_git_revision: str,
        start_operation_id: str,
        start_operator_attestation_envelope_sha256: str,
        start_source_image_id: str,
        start_supervisor_image_id: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "decision_artifact_receipt_invalid"
            )
        values = {
            "artifact_location": artifact_location,
            "controller_outcome_sha256": controller_outcome_sha256,
            "durable_shutdown_locator_sha256": durable_shutdown_locator_sha256,
            "graceful_stop_decision_v1_sha256": graceful_stop_decision_v1_sha256,
            "graceful_stop_operation_id": graceful_stop_operation_id,
            "graceful_stop_target_sha256": graceful_stop_target_sha256,
            "start_approval_sha256": start_approval_sha256,
            "start_approved_image_provenance_sha256": (start_approved_image_provenance_sha256),
            "start_approved_image_provenance_source_revision_sha256": (
                start_approved_image_provenance_source_revision_sha256
            ),
            "start_execution_attempt_slot_sha256": start_execution_attempt_slot_sha256,
            "start_git_revision": start_git_revision,
            "start_operation_id": start_operation_id,
            "start_operator_attestation_envelope_sha256": (
                start_operator_attestation_envelope_sha256
            ),
            "start_source_image_id": start_source_image_id,
            "start_supervisor_image_id": start_supervisor_image_id,
        }
        for name, item in values.items():
            object.__setattr__(self, name, item)
        object.__setattr__(self, "_sealed_fields", _receipt_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        digests = (
            self.controller_outcome_sha256,
            self.durable_shutdown_locator_sha256,
            self.graceful_stop_decision_v1_sha256,
            self.graceful_stop_target_sha256,
            self.start_approval_sha256,
            self.start_approved_image_provenance_sha256,
            self.start_approved_image_provenance_source_revision_sha256,
            self.start_execution_attempt_slot_sha256,
            self.start_operator_attestation_envelope_sha256,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or _receipt_seal_values(self) != getattr(self, "_sealed_fields", None)
            or not all(_is_sha256(value) for value in digests)
            or not _is_uuid4(self.graceful_stop_operation_id)
            or not _is_uuid4(self.start_operation_id)
            or self.graceful_stop_operation_id == self.start_operation_id
            or not _is_git_revision(self.start_git_revision)
            or not _is_image_id(self.start_source_image_id)
            or not _is_image_id(self.start_supervisor_image_id)
            or self.artifact_location
            != _captured_decision_candidate_file_name(self.graceful_stop_decision_v1_sha256)
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "decision_artifact_receipt_invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return DECISION_CANDIDATE_PREPARED_STATUS

    @property
    def contract_version(self) -> str:
        self.__post_init__()
        return ARTIFACT_RECEIPT_CONTRACT_VERSION

    @property
    def service(self) -> str:
        self.__post_init__()
        return ARTIFACT_WORKFLOW_SERVICE

    @property
    def public_payload(self) -> dict[str, object]:
        self.__post_init__()
        payload: dict[str, object] = {
            name: False for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
        }
        payload.update({name: True for name in _TRUE_HISTORICAL_FACT_FIELDS})
        payload.update({name: False for name in _FALSE_QUALIFICATION_FIELDS})
        payload.update(
            {
                "artifact_location": self.artifact_location,
                "contract_version": self.contract_version,
                "controller_outcome_sha256": self.controller_outcome_sha256,
                "durable_shutdown_locator_sha256": self.durable_shutdown_locator_sha256,
                "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
                "graceful_stop_operation_id": self.graceful_stop_operation_id,
                "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
                "service": self.service,
                "start_approval_sha256": self.start_approval_sha256,
                "start_approved_image_provenance_sha256": (
                    self.start_approved_image_provenance_sha256
                ),
                "start_approved_image_provenance_source_revision_sha256": (
                    self.start_approved_image_provenance_source_revision_sha256
                ),
                "start_execution_attempt_slot_sha256": (self.start_execution_attempt_slot_sha256),
                "start_git_revision": self.start_git_revision,
                "start_operation_id": self.start_operation_id,
                "start_operator_attestation_envelope_sha256": (
                    self.start_operator_attestation_envelope_sha256
                ),
                "start_source_image_id": self.start_source_image_id,
                "start_supervisor_image_id": self.start_supervisor_image_id,
                "status": self.status,
            }
        )
        if set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS:
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "decision_artifact_receipt_invalid"
            )
        return payload

    committed_confirmed_start_outcome_revalidated = property(_validated_receipt_fact)
    decision_candidate_semantically_bound = property(_validated_receipt_fact)
    durable_shutdown_locator_revalidated = property(_validated_receipt_fact)
    external_stop_attestation_required = property(_validated_receipt_fact)
    historical_evidence_only = property(_validated_receipt_fact)
    historical_start_chain_authenticated = property(_validated_receipt_fact)
    later_atomic_stop_admission_revalidation_required = property(_validated_receipt_fact)
    start_execution_attempt_slot_revalidated = property(_validated_receipt_fact)
    start_operator_attestation_envelope_revalidated = property(_validated_receipt_fact)
    verification_only = property(_validated_receipt_fact)
    currentness_qualified = property(_validated_receipt_non_authority)
    freshness_qualified = property(_validated_receipt_non_authority)
    single_use_qualified = property(_validated_receipt_non_authority)
    stop_admission_qualified = property(_validated_receipt_non_authority)
    stop_attempt_slot_reserved = property(_validated_receipt_non_authority)
    stop_effect_authorized = property(_validated_receipt_non_authority)
    stop_operator_signature_authenticated = property(_validated_receipt_non_authority)
    stop_outcome_or_recovery_available = property(_validated_receipt_non_authority)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_cannot_be_copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_cannot_be_copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_cannot_be_serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_cannot_be_serialized"
        )


for _authority_field in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
    setattr(
        TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        _authority_field,
        property(_validated_receipt_non_authority),
    )


def _canonical_receipt_bytes_from_identity_values(
    identity_values: tuple[str, ...],
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
) -> bytes:
    """Derive receipt bytes without consulting a mutable receipt projection."""

    try:
        if (
            type(identity_values) is not tuple
            or len(identity_values) != 15
            or any(type(value) is not str for value in identity_values)
            or tuple.__getitem__(identity_values, 0)
            != _candidate_file_name(tuple.__getitem__(identity_values, 3))
            or any(
                not _is_sha256(tuple.__getitem__(identity_values, index))
                for index in (1, 2, 3, 5, 6, 7, 8, 9, 12)
            )
            or not _is_uuid4(tuple.__getitem__(identity_values, 4))
            or not _is_uuid4(tuple.__getitem__(identity_values, 11))
            or tuple.__getitem__(identity_values, 4) == tuple.__getitem__(identity_values, 11)
            or not _is_git_revision(tuple.__getitem__(identity_values, 10))
            or not _is_image_id(tuple.__getitem__(identity_values, 13))
            or not _is_image_id(tuple.__getitem__(identity_values, 14))
        ):
            raise ValueError
        receipt_items = tuple(
            sorted(
                (
                    ("active_controller_authorized", False),
                    ("alert_delivery_authorized", False),
                    ("arming_authorized", False),
                    ("authority_granted", False),
                    ("automatic_rearm_authorized", False),
                    ("automatic_resume_authorized", False),
                    ("broker_action_authorized", False),
                    ("claim_retention_authorized", False),
                    ("clean_stop_authorized", False),
                    ("clean_stop_outcome_retention_authorized", False),
                    ("confirmed_start_outcome_authenticated", False),
                    ("container_removal_authorized", False),
                    ("controller_execution_authorized", False),
                    ("current_topology_authenticated", False),
                    ("database_secret_disclosed", False),
                    ("decision_authenticated", False),
                    ("execution_admission_authorized", False),
                    ("execution_attempt_reservation_authorized", False),
                    ("exposure_authorized", False),
                    ("freshness_authenticated", False),
                    ("graceful_stop_authorized", False),
                    ("live_trading_authorized", False),
                    ("network_removal_authorized", False),
                    ("new_exposure_authorized", False),
                    ("operational_control_authorized", False),
                    ("operator_attestation_authenticated", False),
                    ("outcome_retention_authorized", False),
                    ("paper_trading_authorized", False),
                    ("persistent_start_authorized", False),
                    ("persistent_topology_authenticated", False),
                    ("qualified", False),
                    ("readiness_authorized", False),
                    ("rearm_authorized", False),
                    ("release_authorized", False),
                    ("retry_authorized", False),
                    ("runtime_start_authorized", False),
                    ("sequence_2_authorized", False),
                    ("shutdown_authorized", False),
                    ("shutdown_locator_authenticated", False),
                    ("shutdown_outcome_retention_authorized", False),
                    ("single_use_authenticated", False),
                    ("source_start_authorized", False),
                    ("source_stop_authorized", False),
                    ("start_execution_attempt_authenticated", False),
                    ("stop_attempt_reservation_authorized", False),
                    ("stop_decision_authenticated", False),
                    ("stop_execution_authorized", False),
                    ("success_outcome_retention_authorized", False),
                    ("supervisor_signal_authorized", False),
                    ("supervisor_start_authorized", False),
                    ("supervisor_stop_authorized", False),
                    ("target_authenticated", False),
                    ("teardown_authorized", False),
                    ("topology_mutation_authorized", False),
                    ("volume_removal_authorized", False),
                    ("committed_confirmed_start_outcome_revalidated", True),
                    ("decision_candidate_semantically_bound", True),
                    ("durable_shutdown_locator_revalidated", True),
                    ("external_stop_attestation_required", True),
                    ("historical_evidence_only", True),
                    ("historical_start_chain_authenticated", True),
                    ("later_atomic_stop_admission_revalidation_required", True),
                    ("start_execution_attempt_slot_revalidated", True),
                    ("start_operator_attestation_envelope_revalidated", True),
                    ("verification_only", True),
                    ("currentness_qualified", False),
                    ("freshness_qualified", False),
                    ("single_use_qualified", False),
                    ("stop_admission_qualified", False),
                    ("stop_attempt_slot_reserved", False),
                    ("stop_effect_authorized", False),
                    ("stop_operator_signature_authenticated", False),
                    ("stop_outcome_or_recovery_available", False),
                    ("artifact_location", tuple.__getitem__(identity_values, 0)),
                    ("controller_outcome_sha256", tuple.__getitem__(identity_values, 1)),
                    (
                        "durable_shutdown_locator_sha256",
                        tuple.__getitem__(identity_values, 2),
                    ),
                    (
                        "graceful_stop_decision_v1_sha256",
                        tuple.__getitem__(identity_values, 3),
                    ),
                    ("graceful_stop_operation_id", tuple.__getitem__(identity_values, 4)),
                    (
                        "graceful_stop_target_sha256",
                        tuple.__getitem__(identity_values, 5),
                    ),
                    ("start_approval_sha256", tuple.__getitem__(identity_values, 6)),
                    (
                        "start_approved_image_provenance_sha256",
                        tuple.__getitem__(identity_values, 7),
                    ),
                    (
                        "start_approved_image_provenance_source_revision_sha256",
                        tuple.__getitem__(identity_values, 8),
                    ),
                    (
                        "start_execution_attempt_slot_sha256",
                        tuple.__getitem__(identity_values, 9),
                    ),
                    ("start_git_revision", tuple.__getitem__(identity_values, 10)),
                    ("start_operation_id", tuple.__getitem__(identity_values, 11)),
                    (
                        "start_operator_attestation_envelope_sha256",
                        tuple.__getitem__(identity_values, 12),
                    ),
                    ("start_source_image_id", tuple.__getitem__(identity_values, 13)),
                    ("start_supervisor_image_id", tuple.__getitem__(identity_values, 14)),
                    (
                        "contract_version",
                        "phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1",
                    ),
                    (
                        "service",
                        "trusted-time-post-enrollment-graceful-stop-decision-artifacts",
                    ),
                    ("status", "graceful_stop_decision_candidate_prepared_unqualified"),
                ),
                key=lambda item: item[0],
            )
        )
        receipt_names = tuple(name for name, _ in receipt_items)
        if (
            len(receipt_items) != 91
            or len(frozenset(receipt_names)) != 91
            or receipt_names != tuple(sorted(receipt_names))
        ):
            raise ValueError

        def exact_ascii_json_string(value: object) -> bytes:
            if (
                type(value) is not str
                or not value
                or not value.isascii()
                or any(ord(character) < 0x20 or character in '"\\' for character in value)
            ):
                raise ValueError
            return b'"' + value.encode("ascii") + b'"'

        def exact_receipt_item(item: object) -> bytes:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError
            name = tuple.__getitem__(item, 0)
            value = tuple.__getitem__(item, 1)
            encoded_value: bytes
            if type(value) is bool:
                encoded_value = b"true" if value else b"false"
            elif type(value) is str:
                encoded_value = exact_ascii_json_string(value)
            else:
                raise ValueError
            return exact_ascii_json_string(name) + b":" + encoded_value

        encoded = b"{" + b",".join(exact_receipt_item(item) for item in receipt_items) + b"}\n"
        if not encoded or len(encoded) > 128 * 1_024:
            raise ValueError
        return encoded
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_invalid"
        ) from None


def _captured_receipt_bytes(
    identity_values: tuple[str, ...],
    _receipt_bytes: Callable[[tuple[str, ...]], bytes] = (
        _canonical_receipt_bytes_from_identity_values
    ),
) -> bytes:
    result: object = _receipt_bytes(identity_values)
    if type(result) is not bytes:
        raise ValueError
    return result


type _HistoricalStartChain = tuple[
    str,
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
]
type _HistoricalStartFileSnapshot = tuple[
    str,
    tuple[object, ...],
    tuple[object, ...],
]
type _LoadedReceiptSourceSnapshot = tuple[
    str,
    str,
    bytes,
    tuple[int, int],
    _StatIdentity,
    str,
    bytes,
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    str,
    bytes,
    tuple[int, int],
    tuple[int, ...],
    str,
    bytes,
    tuple[int, int],
    tuple[int, ...],
    bytes,
    tuple[str, ...],
    bytes,
    str,
]
type _ExpectedDecisionCandidateSnapshot = tuple[
    str,
    bytes,
    bytes,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
]


def _exact_int_tuple(value: object, *, length: int) -> bool:
    return (
        type(value) is tuple and len(value) == length and all(type(item) is int for item in value)
    )


def _exact_str_tuple(value: object, *, length: int) -> bool:
    return (
        type(value) is tuple and len(value) == length and all(type(item) is str for item in value)
    )


def _exact_int_frozenset(value: object) -> bool:
    return type(value) is frozenset and bool(value) and all(type(item) is int for item in value)


def _external_binding_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 9
        or tuple.__getitem__(value, 0) != "operator-attestation-external-file-binding-v1"
        or type(tuple.__getitem__(value, 1)) is not str
        or type(tuple.__getitem__(value, 2)) is not bytes
        or not _exact_int_tuple(tuple.__getitem__(value, 3), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 4), length=9)
        or not _exact_int_frozenset(tuple.__getitem__(value, 5))
        or type(tuple.__getitem__(value, 6)) is not int
        or type(tuple.__getitem__(value, 7)) is not int
        or tuple.__getitem__(value, 6) < 0
        or tuple.__getitem__(value, 7) < tuple.__getitem__(value, 6)
        or len(tuple.__getitem__(value, 2)) < tuple.__getitem__(value, 6)
        or len(tuple.__getitem__(value, 2)) > tuple.__getitem__(value, 7)
        or type(tuple.__getitem__(value, 8)) is not str
        or not tuple.__getitem__(value, 8)
        or type(index) is not int
        or index < 1
        or index >= 9
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _make_external_binding(
    *,
    path: str,
    encoded: bytes,
    directory_identity: tuple[int, int],
    file_identity: _StatIdentity,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    phase: str,
) -> _ExternalBinding:
    value: _ExternalBinding = (
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
    _external_binding_value(value, 1)
    return value


def _chain_slot(value: _HistoricalStartChain, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 3
        or tuple.__getitem__(value, 0) != "historical-start-chain-v1"
        or type(tuple.__getitem__(value, 1))
        is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
        or type(tuple.__getitem__(value, 2))
        is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
        or type(index) is not int
        or index < 1
        or index >= 3
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _controller_semantic_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 12
        or tuple.__getitem__(value, 0) != "controller-outcome-semantic-snapshot-v1"
        or any(type(tuple.__getitem__(value, slot)) is not str for slot in range(1, 9))
        or type(tuple.__getitem__(value, 9)) not in (bytes, type(None))
        or type(tuple.__getitem__(value, 10)) not in (str, type(None))
        or (
            tuple.__getitem__(value, 11) is not None
            and not _exact_str_tuple(tuple.__getitem__(value, 11), length=10)
        )
        or type(index) is not int
        or index < 1
        or index >= 12
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _controller_snapshot_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 14
        or tuple.__getitem__(value, 0) != "retained-controller-outcome-snapshot-v1"
        or type(tuple.__getitem__(value, 1)) is not str
        or type(tuple.__getitem__(value, 2)) is not str
        or not _exact_int_tuple(tuple.__getitem__(value, 3), length=9)
        or type(tuple.__getitem__(value, 4)) is not bool
        or not _exact_str_tuple(tuple.__getitem__(value, 5), length=1)
        or not tuple.__getitem__(tuple.__getitem__(value, 5), 0)
        or type(tuple.__getitem__(value, 6)) is not str
        or type(tuple.__getitem__(value, 7)) is not bytes
        or type(tuple.__getitem__(value, 10)) is not bytes
        or type(tuple.__getitem__(value, 12)) is not bytes
        or not _exact_int_tuple(tuple.__getitem__(value, 9), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 11), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 13), length=9)
        or type(index) is not int
        or index < 1
        or index >= 14
    ):
        raise ValueError
    _controller_semantic_value(tuple.__getitem__(value, 8), 1)
    return tuple.__getitem__(value, index)


def _provenance_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 14
        or tuple.__getitem__(value, 0) != "trusted-time-image-admission-provenance-snapshot-v1"
        or any(type(tuple.__getitem__(value, slot)) is not str for slot in range(1, 10))
        or type(tuple.__getitem__(value, 10)) is not int
        or type(tuple.__getitem__(value, 11)) is not bytes
        or not _exact_int_tuple(tuple.__getitem__(value, 12), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 13), length=9)
        or type(index) is not int
        or index < 1
        or index >= 14
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _loaded_approval_snapshot_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 31
        or tuple.__getitem__(value, 0) != "loaded-operator-attested-approval-snapshot-v1"
        or any(
            type(tuple.__getitem__(value, slot)) is not str
            for slot in (
                1,
                2,
                3,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                22,
                23,
                24,
                25,
                26,
                27,
            )
        )
        or any(type(tuple.__getitem__(value, slot)) is not bytes for slot in (4, 7, 8, 21, 28))
        or not _exact_int_tuple(tuple.__getitem__(value, 5), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 6), length=9)
        or type(tuple.__getitem__(value, 30)) is not tuple
        or type(index) is not int
        or index < 1
        or index >= 31
    ):
        raise ValueError
    _provenance_value(tuple.__getitem__(value, 29), 1)
    return tuple.__getitem__(value, index)


def _attempt_snapshot_value(value: object, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 10
        or tuple.__getitem__(value, 0) != "retained-operator-attested-execution-attempt-snapshot-v1"
        or any(type(tuple.__getitem__(value, slot)) is not str for slot in (1, 2, 3, 5))
        or type(tuple.__getitem__(value, 4)) is not bytes
        or not _exact_int_tuple(tuple.__getitem__(value, 6), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 7), length=9)
        or type(tuple.__getitem__(value, 9)) is not tuple
        or type(index) is not int
        or index < 1
        or index >= 10
    ):
        raise ValueError
    _loaded_approval_snapshot_value(tuple.__getitem__(value, 8), 1)
    return tuple.__getitem__(value, index)


def _historical_slot(value: _HistoricalStartFileSnapshot, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 3
        or tuple.__getitem__(value, 0) != "historical-start-file-snapshot-v1"
        or type(index) is not int
        or index < 1
        or index >= 3
    ):
        raise ValueError
    _controller_snapshot_value(tuple.__getitem__(value, 1), 7)
    _attempt_snapshot_value(tuple.__getitem__(value, 2), 4)
    return tuple.__getitem__(value, index)


def _source_slot(value: _LoadedReceiptSourceSnapshot, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 22
        or tuple.__getitem__(value, 0) != "loaded-receipt-source-snapshot-v1"
    ):
        raise ValueError
    strings = (1, 5, 10, 14, 21)
    byte_strings = (2, 6, 11, 15, 18, 20)
    if (
        any(type(tuple.__getitem__(value, slot)) is not str for slot in strings)
        or any(type(tuple.__getitem__(value, slot)) is not bytes for slot in byte_strings)
        or not _exact_int_tuple(tuple.__getitem__(value, 3), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 4), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 7), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 8), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 9), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 12), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 13), length=9)
        or not _exact_int_tuple(tuple.__getitem__(value, 16), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 17), length=9)
        or not _exact_str_tuple(
            tuple.__getitem__(value, 19),
            length=15,
        )
        or not _is_sha256(tuple.__getitem__(value, 21))
        or type(index) is not int
        or index < 1
        or index >= 22
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _expected_slot(value: _ExpectedDecisionCandidateSnapshot, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 10
        or tuple.__getitem__(value, 0) != "expected-decision-candidate-snapshot-v1"
        or type(tuple.__getitem__(value, 1)) is not bytes
        or type(tuple.__getitem__(value, 2)) is not bytes
        or any(type(tuple.__getitem__(value, slot)) is not str for slot in range(3, 10))
        or any(
            not _is_sha256(tuple.__getitem__(value, slot))
            for slot in (
                3,
                4,
                5,
                6,
                7,
                9,
            )
        )
        or not _is_uuid4(tuple.__getitem__(value, 8))
        or type(index) is not int
        or index < 1
        or index >= 10
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _require_expected_sha256(value: object, *, field_name: str) -> str:
    if not _is_sha256(value):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            f"expected_{field_name}_sha256_invalid"
        )
    return cast(str, value)


def _require_expected_uuid4(value: object, *, field_name: str) -> str:
    if not _is_uuid4(value):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            f"expected_{field_name}_invalid"
        )
    return cast(str, value)


def _require_graceful_stop_operation_id(value: object) -> str:
    if not _is_uuid4(value):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "graceful_stop_operation_id_invalid"
        )
    return cast(str, value)


def _new_exact_immutable_json_serializer() -> Callable[[object], bytes]:
    """Create a closure-local serializer with no imported byte-authority seam."""

    def encode_string(value: object) -> bytes:
        if type(value) is not str:
            raise ValueError
        result = b'"'
        for character in value:
            ordinal = ord(character)
            if character == '"':
                result += b'\\"'
            elif character == "\\":
                result += b"\\\\"
            elif character == "\b":
                result += b"\\b"
            elif character == "\f":
                result += b"\\f"
            elif character == "\n":
                result += b"\\n"
            elif character == "\r":
                result += b"\\r"
            elif character == "\t":
                result += b"\\t"
            elif ordinal < 0x20:
                result += f"\\u{ordinal:04x}".encode("ascii")
            elif 0xD800 <= ordinal <= 0xDFFF:
                raise ValueError
            else:
                result += character.encode("utf-8")
        return result + b'"'

    def encode(value: object) -> bytes:
        if value is None:
            return b"null"
        if type(value) is bool:
            return b"true" if value else b"false"
        if type(value) is int:
            return str(value).encode("ascii")
        if type(value) is str:
            return encode_string(value)
        if (
            type(value) is tuple
            and len(value) == 2
            and type(tuple.__getitem__(value, 0)) is int
            and tuple.__getitem__(value, 0) == 1
            and type(tuple.__getitem__(value, 1)) is tuple
        ):
            items = tuple.__getitem__(value, 1)
            return b"[" + b",".join(encode(item) for item in items) + b"]"
        if (
            type(value) is tuple
            and len(value) == 2
            and type(tuple.__getitem__(value, 0)) is int
            and tuple.__getitem__(value, 0) == 0
            and type(tuple.__getitem__(value, 1)) is tuple
        ):
            items = tuple.__getitem__(value, 1)
            previous_key: str | None = None
            encoded_items: tuple[bytes, ...] = ()
            for item in items:
                if (
                    type(item) is not tuple
                    or len(item) != 2
                    or type(tuple.__getitem__(item, 0)) is not str
                ):
                    raise ValueError
                key = tuple.__getitem__(item, 0)
                if previous_key is not None and previous_key >= key:
                    raise ValueError
                encoded_items += (encode_string(key) + b":" + encode(tuple.__getitem__(item, 1)),)
                previous_key = key
            return b"{" + b",".join(encoded_items) + b"}"
        raise ValueError

    return encode


_EXACT_IMMUTABLE_JSON_SERIALIZER = _new_exact_immutable_json_serializer()


def _decode_immutable_json_object(
    encoded: object,
    *,
    maximum_bytes: int,
    _canonical_json: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
) -> tuple[object, ...]:
    """Parse bytes directly into bounded immutable tuples without parser hooks."""

    if (
        type(encoded) is not bytes
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
        or not encoded
        or len(encoded) > maximum_bytes
    ):
        raise ValueError
    try:
        text = encoded.decode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError from None
    length = len(text)

    def fail() -> Never:
        raise ValueError

    def skip_whitespace(index: int) -> int:
        while index < length and text[index] in " \t\r\n":
            index += 1
        return index

    def hexadecimal_value(index: int) -> int:
        token = text[index : index + 4]
        if len(token) != 4 or any(character not in "0123456789abcdefABCDEF" for character in token):
            fail()
        return int(token, 16)

    def parse_string(index: int) -> tuple[str, int]:
        if index >= length or text[index] != '"':
            fail()
        index += 1
        result = ""
        segment_start = index
        while index < length:
            character = text[index]
            ordinal = ord(character)
            if character == '"':
                segment = text[segment_start:index]
                if any(0xD800 <= ord(item) <= 0xDFFF for item in segment):
                    fail()
                return result + segment, index + 1
            if ordinal < 0x20 or 0xD800 <= ordinal <= 0xDFFF:
                fail()
            if character != "\\":
                index += 1
                continue
            result += text[segment_start:index]
            index += 1
            if index >= length:
                fail()
            escaped = text[index]
            if escaped == '"':
                result += '"'
            elif escaped == "/":
                result += "/"
            elif escaped == "\\":
                result += "\\"
            elif escaped == "b":
                result += "\b"
            elif escaped == "f":
                result += "\f"
            elif escaped == "n":
                result += "\n"
            elif escaped == "r":
                result += "\r"
            elif escaped == "t":
                result += "\t"
            elif escaped == "u":
                code_point = hexadecimal_value(index + 1)
                index += 4
                if 0xD800 <= code_point <= 0xDBFF:
                    if index + 6 > length or text[index + 1 : index + 3] != "\\u":
                        fail()
                    low_surrogate = hexadecimal_value(index + 3)
                    if not 0xDC00 <= low_surrogate <= 0xDFFF:
                        fail()
                    code_point = 0x10000 + ((code_point - 0xD800) << 10) + (low_surrogate - 0xDC00)
                    index += 6
                elif 0xDC00 <= code_point <= 0xDFFF:
                    fail()
                result += chr(code_point)
            else:
                fail()
            index += 1
            segment_start = index
        fail()

    def parse_value(
        index: int,
        *,
        depth: int,
        remaining_nodes: int,
    ) -> tuple[object, int, int]:
        if depth > 24 or remaining_nodes <= 0:
            fail()
        index = skip_whitespace(index)
        if index >= length:
            fail()
        character = text[index]
        if character == '"':
            value, final_index = parse_string(index)
            return value, final_index, 1
        if text.startswith("true", index):
            return True, index + 4, 1
        if text.startswith("false", index):
            return False, index + 5, 1
        if text.startswith("null", index):
            return None, index + 4, 1
        if character == "[":
            array_items: tuple[object, ...] = ()
            used_nodes = 1
            index = skip_whitespace(index + 1)
            if index < length and text[index] == "]":
                return (1, array_items), index + 1, used_nodes
            while True:
                item, index, child_nodes = parse_value(
                    index,
                    depth=depth + 1,
                    remaining_nodes=remaining_nodes - used_nodes,
                )
                array_items += (item,)
                used_nodes += child_nodes
                index = skip_whitespace(index)
                if index >= length:
                    fail()
                if text[index] == "]":
                    return (1, array_items), index + 1, used_nodes
                if text[index] != ",":
                    fail()
                index = skip_whitespace(index + 1)
        if character == "{":
            object_items: tuple[tuple[str, object], ...] = ()
            used_nodes = 1
            index = skip_whitespace(index + 1)
            if index < length and text[index] == "}":
                return (0, object_items), index + 1, used_nodes
            while True:
                key, index = parse_string(index)
                if any(existing == key for existing, _ in object_items):
                    fail()
                used_nodes += 1
                if used_nodes >= remaining_nodes:
                    fail()
                index = skip_whitespace(index)
                if index >= length or text[index] != ":":
                    fail()
                parsed_value, index, child_nodes = parse_value(
                    index + 1,
                    depth=depth + 1,
                    remaining_nodes=remaining_nodes - used_nodes,
                )
                object_items += ((key, parsed_value),)
                used_nodes += child_nodes
                index = skip_whitespace(index)
                if index >= length:
                    fail()
                if text[index] == "}":
                    return (0, object_items), index + 1, used_nodes
                if text[index] != ",":
                    fail()
                index = skip_whitespace(index + 1)
        number_start = index
        if character == "-":
            index += 1
            if index >= length:
                fail()
        if index < length and text[index] == "0":
            index += 1
            if index < length and text[index].isdigit():
                fail()
        elif index < length and "1" <= text[index] <= "9":
            index += 1
            while index < length and text[index].isdigit():
                index += 1
        else:
            fail()
        if index < length and text[index] in ".eE":
            fail()
        token = text[number_start:index]
        if len(token) > 78:
            fail()
        integer_value = int(token)
        if integer_value.bit_length() > 256:
            fail()
        return integer_value, index, 1

    try:
        payload, final_index, used_nodes = parse_value(
            0,
            depth=0,
            remaining_nodes=4_096,
        )
        if (
            used_nodes > 4_096
            or skip_whitespace(final_index) != length
            or _canonical_json(payload) + b"\n" != encoded
            or type(payload) is not tuple
            or len(payload) != 2
            or tuple.__getitem__(payload, 0) != 0
        ):
            raise ValueError
        return payload
    except (TypeError, UnicodeError, ValueError, RecursionError, OverflowError):
        raise ValueError from None


def _historical_start_approval_artifact_path(
    historical: _HistoricalStartFileSnapshot,
) -> str:
    attempt = cast(
        tuple[object, ...],
        _historical_slot(historical, 2),
    )
    approval = cast(
        tuple[object, ...],
        _attempt_snapshot_value(attempt, 8),
    )
    return cast(
        str,
        _loaded_approval_snapshot_value(approval, 3),
    )


def _historical_invocation_binding_matches(
    historical: _HistoricalStartFileSnapshot,
    *,
    start_artifact: object,
    artifact_directory: object,
    ignored_root: object,
    _abspath: Callable[[str], str] = os.path.abspath,
    _dirname: Callable[[str], str] = os.path.dirname,
    _isabs: Callable[[str], bool] = os.path.isabs,
    _join: Callable[..., str] = os.path.join,
    _normpath: Callable[[str], str] = os.path.normpath,
) -> bool:
    """Bind one immutable historical snapshot to its exact invocation strings."""

    try:
        if (
            type(start_artifact) is not str
            or type(artifact_directory) is not str
            or type(ignored_root) is not str
            or not _isabs(start_artifact)
            or _abspath(start_artifact) != start_artifact
            or _normpath(start_artifact) != start_artifact
            or "\x00" in start_artifact
            or not _isabs(artifact_directory)
            or _abspath(artifact_directory) != artifact_directory
            or _normpath(artifact_directory) != artifact_directory
            or "\x00" in artifact_directory
            or not _isabs(ignored_root)
            or _abspath(ignored_root) != ignored_root
            or _normpath(ignored_root) != ignored_root
            or "\x00" in ignored_root
            or artifact_directory != _join(ignored_root, "trusted-time")
        ):
            return False
        outcome_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 1),
        )
        attempt_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 2),
        )
        approval_snapshot = cast(
            tuple[object, ...],
            _attempt_snapshot_value(attempt_snapshot, 8),
        )
        provenance_snapshot = cast(
            tuple[object, ...],
            _loaded_approval_snapshot_value(approval_snapshot, 29),
        )
        outcome_path = _controller_snapshot_value(outcome_snapshot, 6)
        attempt_path = _attempt_snapshot_value(attempt_snapshot, 3)
        approval_path = _loaded_approval_snapshot_value(approval_snapshot, 3)
        provenance_path = _provenance_value(provenance_snapshot, 1)
        return not (
            _controller_snapshot_value(outcome_snapshot, 1) != artifact_directory
            or _controller_snapshot_value(outcome_snapshot, 2) != ignored_root
            or _attempt_snapshot_value(attempt_snapshot, 1) != artifact_directory
            or _attempt_snapshot_value(attempt_snapshot, 2) != ignored_root
            or _loaded_approval_snapshot_value(approval_snapshot, 1) != artifact_directory
            or _loaded_approval_snapshot_value(approval_snapshot, 2) != ignored_root
            or approval_path != start_artifact
            or type(outcome_path) is not str
            or _dirname(outcome_path) != artifact_directory
            or type(attempt_path) is not str
            or _dirname(attempt_path) != artifact_directory
            or type(provenance_path) is not str
            or _dirname(provenance_path) != artifact_directory
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _load_historical_start_chain(
    *,
    start_operator_attested_approval_artifact: str,
    artifact_directory: str,
    ignored_root: str,
) -> tuple[_HistoricalStartChain, _HistoricalStartFileSnapshot]:
    try:
        if any(
            type(value) is not str
            for value in (
                start_operator_attested_approval_artifact,
                artifact_directory,
                ignored_root,
            )
        ):
            raise ValueError
        outcome, outcome_snapshot = (
            _load_retained_post_enrollment_start_controller_outcome_with_snapshot(
                artifact_directory=Path(artifact_directory),
                ignored_root=Path(ignored_root),
            )
        )
        attempt, attempt_snapshot = (
            _load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
                start_operator_attested_approval_artifact=Path(
                    start_operator_attested_approval_artifact
                ),
                artifact_directory=Path(artifact_directory),
                ignored_root=Path(ignored_root),
            )
        )
        if (
            type(outcome) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
            or type(attempt)
            is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
        ):
            raise ValueError
        chain: _HistoricalStartChain = (
            "historical-start-chain-v1",
            outcome,
            attempt,
        )
        return chain, _capture_historical_file_snapshot(
            chain,
            outcome_snapshot=outcome_snapshot,
            attempt_snapshot=attempt_snapshot,
        )
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_chain_unavailable"
        ) from None


def _require_historical_start_chain(
    snapshot: _HistoricalStartFileSnapshot,
    *,
    expected_controller_outcome_sha256: str,
    expected_durable_shutdown_locator_sha256: str,
    expected_start_execution_attempt_slot_sha256: str,
    expected_start_operator_attestation_envelope_sha256: str,
    expected_start_operation_id: str,
    expected_start_approval_sha256: str,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> None:
    try:
        outcome = cast(
            tuple[object, ...],
            _historical_slot(snapshot, 1),
        )
        attempt = cast(
            tuple[object, ...],
            _historical_slot(snapshot, 2),
        )
        semantic = cast(
            tuple[object, ...],
            _controller_snapshot_value(outcome, 8),
        )
        approval = cast(
            tuple[object, ...],
            _attempt_snapshot_value(attempt, 8),
        )
        provenance = cast(
            tuple[object, ...],
            _loaded_approval_snapshot_value(approval, 29),
        )
        _loaded_approval_snapshot_value(approval, 1)
        _provenance_value(provenance, 1)
        attempt_encoded = cast(
            bytes,
            _attempt_snapshot_value(attempt, 4),
        )
        _require_attempt_snapshot_binding(attempt_encoded, approval)
        outcome_encoded = cast(bytes, _controller_snapshot_value(outcome, 7))
        locator_encoded = _controller_semantic_value(semantic, 9)
        locator_sha256 = _controller_semantic_value(semantic, 10)
        topology = _controller_semantic_value(
            semantic,
            11,
        )
        semantic_contract_version = _controller_semantic_value(semantic, 1)
        semantic_status = _controller_semantic_value(semantic, 2)
        semantic_reason = _controller_semantic_value(semantic, 3)
        semantic_operation_id = _controller_semantic_value(semantic, 4)
        semantic_approval_sha256 = _controller_semantic_value(semantic, 5)
        semantic_claim_sha256 = _controller_semantic_value(semantic, 6)
        semantic_retained_claim_sha256 = _controller_semantic_value(
            semantic,
            7,
        )
        semantic_active_admission_sha256 = _controller_semantic_value(
            semantic,
            8,
        )
        reviewed_values = (
            _sha256(outcome_encoded).hexdigest() == expected_controller_outcome_sha256,
            locator_sha256 == expected_durable_shutdown_locator_sha256,
            _attempt_snapshot_value(attempt, 5) == expected_start_execution_attempt_slot_sha256,
            _loaded_approval_snapshot_value(approval, 27)
            == expected_start_operator_attestation_envelope_sha256,
            _loaded_approval_snapshot_value(approval, 12) == expected_start_operation_id,
            _loaded_approval_snapshot_value(approval, 9) == expected_start_approval_sha256,
        )
        if not all(reviewed_values):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "historical_start_chain_differs_from_review"
            )
        if (
            semantic_contract_version
            != "phase6d-post-enrollment-start-retained-controller-outcome-v2"
            or semantic_status != "post_enrollment_start_confirmed"
            or semantic_reason != "post_enrollment_start_confirmed"
            or type(locator_encoded) is not bytes
            or not locator_encoded
            or _sha256(locator_encoded).hexdigest() != locator_sha256
            or type(topology) is not tuple
            or len(topology) != 10
            or any(type(value) is not str for value in topology)
            or topology
            != (
                semantic_operation_id,
                semantic_approval_sha256,
                semantic_claim_sha256,
                semantic_retained_claim_sha256,
                semantic_active_admission_sha256,
                topology[5],
                _loaded_approval_snapshot_value(approval, 13),
                _loaded_approval_snapshot_value(approval, 14),
                _loaded_approval_snapshot_value(approval, 15),
                _loaded_approval_snapshot_value(approval, 16),
            )
            or semantic_operation_id != _loaded_approval_snapshot_value(approval, 12)
            or semantic_approval_sha256 != _loaded_approval_snapshot_value(approval, 9)
            or _provenance_value(provenance, 8) != _loaded_approval_snapshot_value(approval, 16)
        ):
            raise ValueError
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_chain_invalid"
        ) from None


def _revalidate_historical_start_chain(
    chain: _HistoricalStartChain,
    snapshot: _HistoricalStartFileSnapshot,
    *,
    artifact_directory: str,
    ignored_root: str,
) -> None:
    try:
        if type(artifact_directory) is not str or type(ignored_root) is not str:
            raise ValueError
        if (
            not _revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
                cast(
                    tuple[object, ...],
                    _historical_slot(snapshot, 1),
                ),
                artifact_directory=Path(artifact_directory),
                ignored_root=Path(ignored_root),
            )
            or not (
                _revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot(
                    cast(
                        tuple[object, ...],
                        _historical_slot(snapshot, 2),
                    ),
                    artifact_directory=Path(artifact_directory),
                    ignored_root=Path(ignored_root),
                )
            )
            or not _historical_chain_matches_snapshot(chain, snapshot)
        ):
            raise ValueError
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_chain_revalidation_failed"
        ) from None


def _exact_artifact_roots(
    artifact_directory: object,
    *,
    ignored_root: object,
    _abspath: Callable[[str], str] = os.path.abspath,
    _isabs: Callable[[str], bool] = os.path.isabs,
    _join: Callable[..., str] = os.path.join,
    _normpath: Callable[[str], str] = os.path.normpath,
) -> tuple[str, str]:
    if type(artifact_directory) is not type(Path()) or type(ignored_root) is not type(Path()):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_artifact_root_invalid"
        )
    try:
        captured_directory = _captured_path_string(artifact_directory)
        captured_root = _captured_path_string(ignored_root)
        exact_directory_string = _abspath(captured_directory)
        exact_root_string = _abspath(captured_root)
        if type(exact_directory_string) is not str or type(exact_root_string) is not str:
            raise ValueError
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_artifact_root_invalid"
        ) from None
    if (
        type(_isabs(captured_directory)) is not bool
        or not _isabs(captured_directory)
        or exact_directory_string != captured_directory
        or _normpath(captured_directory) != captured_directory
        or "\x00" in captured_directory
        or type(_isabs(captured_root)) is not bool
        or not _isabs(captured_root)
        or exact_root_string != captured_root
        or _normpath(captured_root) != captured_root
        or "\x00" in captured_root
        or exact_directory_string != _join(exact_root_string, "trusted-time")
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_artifact_root_invalid"
        )
    return exact_directory_string, exact_root_string


def _cleanup_external_directory_owners(
    owners: tuple[Any | None, ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner in owners:
        if owner is None or owner.closed:
            continue
        try:
            owner.close()
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
    return first_error


def _path_is_same_or_beneath(path: str, root: str, _separator: str = os.sep) -> bool:
    boundary = root if root.endswith(_separator) else root + _separator
    return path == root or path.startswith(boundary)


def _external_directory_identity(
    path: str,
    *,
    repository_identity: tuple[int, int],
) -> tuple[int, int]:
    directory_owner: Any | None = None
    next_owner: Any | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    result: tuple[int, int] | None = None
    try:
        try:
            directory_owner = _open_root_directory()
            root_metadata = _audited_fs._require_stat_identity(_fstat(directory_owner))
            if (root_metadata[0], root_metadata[1]) == repository_identity:
                raise OSError
            for component in _audited_fs._absolute_path_components(path):
                next_owner = _open_child_directory(
                    directory_owner,
                    component,
                )
                next_metadata = _audited_fs._require_stat_identity(_fstat(next_owner))
                if (next_metadata[0], next_metadata[1]) == repository_identity:
                    raise OSError
                intermediate_error = _cleanup_external_directory_owners((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_owner
                next_owner = None
            result = _audited_fs._require_external_directory_metadata(
                _fstat(directory_owner),
                rejected_identity=repository_identity,
            )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_external_directory_owners((next_owner, directory_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_external_directory_owners((next_owner, directory_owner))
    terminal = _preferred_registry_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise OSError
    return result


def _require_external_candidate_directory(
    directory: str,
    *,
    artifact_directory: str,
    ignored_root: str,
    _is_same_or_beneath: Callable[[str, str], bool] = _path_is_same_or_beneath,
    _repository_root_string: str = _audited_fs._REPOSITORY_ROOT_STRING,
) -> tuple[str, tuple[int, int]]:
    try:
        if (
            type(directory) is not str
            or type(artifact_directory) is not str
            or type(ignored_root) is not str
        ):
            raise ValueError
        exact = _audited_fs._absolute_path(
            Path(directory),
            reason_code="decision_candidate_directory_path_invalid",
        )
        if exact != directory:
            raise ValueError
    except _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError as error:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            error.reason_code
        ) from None
    if type(_repository_root_string) is not str:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_directory_unavailable"
        )
    if any(
        _is_same_or_beneath(exact, rejected_root)
        for rejected_root in (
            artifact_directory,
            ignored_root,
            _repository_root_string,
        )
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_directory_unavailable"
        )
    try:
        repository_identity = _audited_fs._repository_identity()
        identity = _external_directory_identity(
            exact,
            repository_identity=repository_identity,
        )
        artifact_identity = _external_directory_identity(
            artifact_directory,
            repository_identity=repository_identity,
        )
        ignored_identity = _external_directory_identity(
            ignored_root,
            repository_identity=repository_identity,
        )
        if identity in (artifact_identity, ignored_identity):
            raise OSError
        return exact, identity
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_directory_unavailable"
        ) from None


def _read_decision_candidate_binding(
    *,
    graceful_stop_decision_v1_artifact: str,
    expected_graceful_stop_decision_v1_sha256: str,
    artifact_directory: str,
    ignored_root: str,
    _basename: Callable[[str], str] = os.path.basename,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
    _dirname: Callable[[str], str] = os.path.dirname,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> tuple[
    _ExternalBinding,
    TrustedTimePostEnrollmentGracefulStopDecision,
]:
    try:
        if (
            type(graceful_stop_decision_v1_artifact) is not str
            or type(artifact_directory) is not str
            or type(ignored_root) is not str
        ):
            raise ValueError
        exact_path = _audited_fs._absolute_path(
            Path(graceful_stop_decision_v1_artifact),
            reason_code="decision_candidate_path_invalid",
        )
        if exact_path != graceful_stop_decision_v1_artifact:
            raise ValueError
        exact_directory, expected_directory_identity = _require_external_candidate_directory(
            _dirname(exact_path),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        binding = _audited_fs._read_external_binding(
            Path(exact_path),
            allowed_modes=frozenset((0o600,)),
            minimum_bytes=1,
            maximum_bytes=128 * 1_024,
            phase="decision_candidate",
        )
        binding_path = cast(str, _external_binding_value(binding, 1))
        binding_encoded = cast(bytes, _external_binding_value(binding, 2))
        binding_directory_identity = cast(tuple[int, int], _external_binding_value(binding, 3))
        if (
            binding_path != exact_path
            or _dirname(binding_path) != exact_directory
            or binding_directory_identity != expected_directory_identity
        ):
            raise ValueError
        decision = decode_post_enrollment_graceful_stop_decision(binding_encoded)
        if canonical_post_enrollment_graceful_stop_decision_bytes(decision) != binding_encoded:
            raise ValueError
        observed_sha256 = _sha256(binding_encoded).hexdigest()
        if (
            _basename(binding_path) != _candidate_file_name(observed_sha256)
            or observed_sha256 != expected_graceful_stop_decision_v1_sha256
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "decision_candidate_differs_from_review"
            )
        return binding, decision
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError as error:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            error.reason_code
        ) from None
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_invalid"
        ) from None


def _revalidate_decision_candidate_binding(
    binding: _ExternalBinding,
) -> None:
    try:
        _audited_fs._revalidate_external_binding(binding)
    except _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError as error:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            error.reason_code
        ) from None
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_revalidation_failed"
        ) from None


def _historical_chain_matches_snapshot(
    chain: _HistoricalStartChain,
    snapshot: _HistoricalStartFileSnapshot,
) -> bool:
    """Require exact inert view holders and exact immutable descriptor snapshots."""

    try:
        _chain_slot(chain, 1)
        _chain_slot(chain, 2)
        _historical_slot(snapshot, 1)
        _historical_slot(snapshot, 2)
        return True
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _capture_historical_file_snapshot(
    chain: _HistoricalStartChain,
    *,
    outcome_snapshot: tuple[object, ...],
    attempt_snapshot: tuple[object, ...],
) -> _HistoricalStartFileSnapshot:
    try:
        snapshot: _HistoricalStartFileSnapshot = (
            "historical-start-file-snapshot-v1",
            outcome_snapshot,
            attempt_snapshot,
        )
        if not _historical_chain_matches_snapshot(chain, snapshot):
            raise ValueError
        return snapshot
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_chain_invalid"
        ) from None


def _expected_decision_candidate_snapshot(
    historical: _HistoricalStartFileSnapshot,
    *,
    decision_operation_id: str,
    _abspath: Callable[[str], str] = os.path.abspath,
    _canonical_json: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
    _decode_json: Callable[..., tuple[object, ...]] = _decode_immutable_json_object,
    _join: Callable[..., str] = os.path.join,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> _ExpectedDecisionCandidateSnapshot:
    """Build exact candidate bytes solely from primitive retained snapshots."""

    try:
        authority_field_names = (
            "active_controller_authorized",
            "alert_delivery_authorized",
            "arming_authorized",
            "authority_granted",
            "automatic_rearm_authorized",
            "automatic_resume_authorized",
            "broker_action_authorized",
            "claim_retention_authorized",
            "clean_stop_authorized",
            "clean_stop_outcome_retention_authorized",
            "confirmed_start_outcome_authenticated",
            "container_removal_authorized",
            "controller_execution_authorized",
            "current_topology_authenticated",
            "database_secret_disclosed",
            "decision_authenticated",
            "execution_admission_authorized",
            "execution_attempt_reservation_authorized",
            "exposure_authorized",
            "freshness_authenticated",
            "graceful_stop_authorized",
            "live_trading_authorized",
            "network_removal_authorized",
            "new_exposure_authorized",
            "operational_control_authorized",
            "operator_attestation_authenticated",
            "outcome_retention_authorized",
            "paper_trading_authorized",
            "persistent_start_authorized",
            "persistent_topology_authenticated",
            "qualified",
            "readiness_authorized",
            "rearm_authorized",
            "release_authorized",
            "retry_authorized",
            "runtime_start_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
            "shutdown_locator_authenticated",
            "shutdown_outcome_retention_authorized",
            "single_use_authenticated",
            "source_start_authorized",
            "source_stop_authorized",
            "start_execution_attempt_authenticated",
            "stop_attempt_reservation_authorized",
            "stop_decision_authenticated",
            "stop_execution_authorized",
            "success_outcome_retention_authorized",
            "supervisor_signal_authorized",
            "supervisor_start_authorized",
            "supervisor_stop_authorized",
            "target_authenticated",
            "teardown_authorized",
            "topology_mutation_authorized",
            "volume_removal_authorized",
        )
        if (
            len(authority_field_names) != 55
            or len(frozenset(authority_field_names)) != 55
            or authority_field_names != tuple(sorted(authority_field_names))
        ):
            raise ValueError

        def exact_immutable_object(
            items: tuple[tuple[str, object], ...],
        ) -> tuple[object, ...]:
            ordered: tuple[tuple[str, object], ...] = ()
            for item in items:
                raw_name = tuple.__getitem__(item, 0) if type(item) is tuple else None
                if type(item) is not tuple or len(item) != 2 or type(raw_name) is not str:
                    raise ValueError
                name = raw_name
                index = 0
                while index < len(ordered) and ordered[index][0] < name:
                    index += 1
                if index < len(ordered) and ordered[index][0] == name:
                    raise ValueError
                ordered = (*ordered[:index], item, *ordered[index:])
            return (0, ordered)

        outcome_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 1),
        )
        attempt_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 2),
        )
        outcome_encoded = cast(
            bytes,
            _controller_snapshot_value(outcome_snapshot, 7),
        )
        attempt_encoded = cast(
            bytes,
            _attempt_snapshot_value(attempt_snapshot, 4),
        )
        approval_snapshot = cast(
            tuple[object, ...],
            _attempt_snapshot_value(attempt_snapshot, 8),
        )
        approval_encoded = cast(
            bytes,
            _loaded_approval_snapshot_value(approval_snapshot, 4),
        )
        provenance_snapshot = cast(
            tuple[object, ...],
            _loaded_approval_snapshot_value(approval_snapshot, 29),
        )
        _loaded_approval_snapshot_value(approval_snapshot, 1)
        _provenance_value(provenance_snapshot, 1)
        semantic = cast(
            tuple[object, ...],
            _controller_snapshot_value(outcome_snapshot, 8),
        )
        _require_attempt_snapshot_binding(attempt_encoded, approval_snapshot)
        locator_encoded = _controller_semantic_value(semantic, 9)
        locator_sha256 = _controller_semantic_value(semantic, 10)
        topology_values = _controller_semantic_value(
            semantic,
            11,
        )
        if (
            type(locator_encoded) is not bytes
            or not _is_sha256(locator_sha256)
            or type(topology_values) is not tuple
            or len(topology_values) != 10
            or any(type(value) is not str for value in topology_values)
        ):
            raise ValueError
        locator = _decode_json(
            locator_encoded,
            maximum_bytes=64 * 1_024,
        )
        exact_locator_sha256 = cast(str, locator_sha256)
        if _sha256(locator_encoded).hexdigest() != exact_locator_sha256:
            raise ValueError
        (
            topology_operation_id,
            topology_approval_sha256,
            topology_claim_sha256,
            topology_retained_claim_sha256,
            topology_active_admission_sha256,
            topology_successor_sha256,
            topology_source_image_id,
            topology_supervisor_image_id,
            topology_git_revision,
            topology_image_admission_sha256,
        ) = topology_values
        outcome_sha256 = _sha256(outcome_encoded).hexdigest()
        attempt_sha256 = _sha256(attempt_encoded).hexdigest()
        approval_sha256 = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 9),
        )
        start_operation_id = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 12),
        )
        envelope_sha256 = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 27),
        )
        source_image_id = _loaded_approval_snapshot_value(
            approval_snapshot,
            13,
        )
        supervisor_image_id = _loaded_approval_snapshot_value(
            approval_snapshot,
            14,
        )
        git_revision = _loaded_approval_snapshot_value(
            approval_snapshot,
            15,
        )
        image_admission_sha256 = _loaded_approval_snapshot_value(
            approval_snapshot,
            16,
        )
        source_revision_sha256 = _provenance_value(
            provenance_snapshot,
            6,
        )
        semantic_contract_version = _controller_semantic_value(semantic, 1)
        semantic_status = _controller_semantic_value(semantic, 2)
        semantic_reason = _controller_semantic_value(semantic, 3)
        semantic_operation_id = _controller_semantic_value(semantic, 4)
        semantic_approval_sha256 = _controller_semantic_value(semantic, 5)
        semantic_claim_sha256 = _controller_semantic_value(semantic, 6)
        semantic_retained_claim_sha256 = _controller_semantic_value(
            semantic,
            7,
        )
        semantic_active_admission_sha256 = _controller_semantic_value(
            semantic,
            8,
        )
        if (
            semantic_contract_version
            != "phase6d-post-enrollment-start-retained-controller-outcome-v2"
            or semantic_status != "post_enrollment_start_confirmed"
            or semantic_reason != "post_enrollment_start_confirmed"
            or semantic_operation_id != start_operation_id
            or semantic_approval_sha256 != approval_sha256
            or locator_sha256 != exact_locator_sha256
            or topology_operation_id != semantic_operation_id
            or topology_approval_sha256 != semantic_approval_sha256
            or topology_claim_sha256 != semantic_claim_sha256
            or topology_retained_claim_sha256 != semantic_retained_claim_sha256
            or topology_active_admission_sha256 != semantic_active_admission_sha256
            or not _is_sha256(topology_successor_sha256)
            or topology_source_image_id != source_image_id
            or topology_supervisor_image_id != supervisor_image_id
            or topology_git_revision != git_revision
            or topology_image_admission_sha256 != image_admission_sha256
            or _abspath(cast(str, _controller_snapshot_value(outcome_snapshot, 1)))
            != _controller_snapshot_value(outcome_snapshot, 1)
            or _abspath(cast(str, _controller_snapshot_value(outcome_snapshot, 6)))
            != _controller_snapshot_value(outcome_snapshot, 6)
            or _controller_snapshot_value(outcome_snapshot, 6)
            != _join(
                cast(str, _controller_snapshot_value(outcome_snapshot, 1)),
                tuple.__getitem__(
                    cast(
                        tuple[str, ...],
                        _controller_snapshot_value(outcome_snapshot, 5),
                    ),
                    0,
                ),
            )
            or attempt_sha256 != _attempt_snapshot_value(attempt_snapshot, 5)
            or _sha256(approval_encoded).hexdigest() != envelope_sha256
            or any(
                not _is_sha256(value)
                for value in (
                    outcome_sha256,
                    attempt_sha256,
                    approval_sha256,
                    envelope_sha256,
                    semantic_claim_sha256,
                    semantic_retained_claim_sha256,
                    semantic_active_admission_sha256,
                    image_admission_sha256,
                    source_revision_sha256,
                )
            )
            or not _is_uuid4(start_operation_id)
            or not _is_uuid4(decision_operation_id)
            or decision_operation_id == start_operation_id
            or not _is_git_revision(git_revision)
            or not _is_image_id(source_image_id)
            or not _is_image_id(supervisor_image_id)
        ):
            raise ValueError
        target_items = (
            *((name, False) for name in authority_field_names),
            (
                "contract_version",
                "phase6d-post-enrollment-graceful-stop-target-v1",
            ),
            ("controller_outcome_contract_version", semantic_contract_version),
            ("controller_outcome_reason", semantic_reason),
            ("controller_outcome_sha256", outcome_sha256),
            ("controller_outcome_status", semantic_status),
            ("durable_shutdown_locator", locator),
            ("durable_shutdown_locator_sha256", exact_locator_sha256),
            ("service", "trusted-time-post-enrollment-graceful-stop"),
            ("start_approval_sha256", approval_sha256),
            ("start_execution_attempt_slot_sha256", attempt_sha256),
            ("start_operation_id", start_operation_id),
            ("start_operator_attestation_envelope_sha256", envelope_sha256),
            ("status", "graceful_stop_target_unqualified"),
        )
        if len(target_items) != 68 or len(frozenset(name for name, _ in target_items)) != 68:
            raise ValueError
        target = exact_immutable_object(target_items)
        target_encoded = _canonical_json(target) + b"\n"
        target_sha256 = _sha256(target_encoded).hexdigest()
        decision_items = (
            *((name, False) for name in authority_field_names),
            (
                "contract_version",
                "phase6d-post-enrollment-graceful-stop-decision-v1",
            ),
            ("decision", "approve_one_post_enrollment_graceful_stop_attempt"),
            ("graceful_stop_target", target),
            ("graceful_stop_target_sha256", target_sha256),
            ("operation_id", decision_operation_id),
            (
                "replay_domain",
                "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
                "post-enrollment-graceful-stop/operator-attestation/v1",
            ),
            ("service", "trusted-time-post-enrollment-graceful-stop"),
            ("status", "external_attestation_required"),
        )
        if len(decision_items) != 63 or len(frozenset(name for name, _ in decision_items)) != 63:
            raise ValueError
        decision = exact_immutable_object(decision_items)
        expected: _ExpectedDecisionCandidateSnapshot = (
            "expected-decision-candidate-snapshot-v1",
            _canonical_json(decision) + b"\n",
            target_encoded,
            target_sha256,
            outcome_sha256,
            exact_locator_sha256,
            attempt_sha256,
            approval_sha256,
            start_operation_id,
            envelope_sha256,
        )
        _expected_slot(expected, 1)
        return expected
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        ) from None


def _build_loaded_receipt_source_snapshot(
    *,
    binding: _ExternalBinding,
    historical: _HistoricalStartFileSnapshot,
    _abspath: Callable[[str], str] = os.path.abspath,
    _basename: Callable[[str], str] = os.path.basename,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
    _canonical_json: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
    _decode_json: Callable[..., tuple[object, ...]] = _decode_immutable_json_object,
    _join: Callable[..., str] = os.path.join,
    _receipt_bytes: Callable[[tuple[str, ...]], bytes] = (
        _canonical_receipt_bytes_from_identity_values
    ),
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> _LoadedReceiptSourceSnapshot:
    try:
        authority_field_names = (
            "active_controller_authorized",
            "alert_delivery_authorized",
            "arming_authorized",
            "authority_granted",
            "automatic_rearm_authorized",
            "automatic_resume_authorized",
            "broker_action_authorized",
            "claim_retention_authorized",
            "clean_stop_authorized",
            "clean_stop_outcome_retention_authorized",
            "confirmed_start_outcome_authenticated",
            "container_removal_authorized",
            "controller_execution_authorized",
            "current_topology_authenticated",
            "database_secret_disclosed",
            "decision_authenticated",
            "execution_admission_authorized",
            "execution_attempt_reservation_authorized",
            "exposure_authorized",
            "freshness_authenticated",
            "graceful_stop_authorized",
            "live_trading_authorized",
            "network_removal_authorized",
            "new_exposure_authorized",
            "operational_control_authorized",
            "operator_attestation_authenticated",
            "outcome_retention_authorized",
            "paper_trading_authorized",
            "persistent_start_authorized",
            "persistent_topology_authenticated",
            "qualified",
            "readiness_authorized",
            "rearm_authorized",
            "release_authorized",
            "retry_authorized",
            "runtime_start_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
            "shutdown_locator_authenticated",
            "shutdown_outcome_retention_authorized",
            "single_use_authenticated",
            "source_start_authorized",
            "source_stop_authorized",
            "start_execution_attempt_authenticated",
            "stop_attempt_reservation_authorized",
            "stop_decision_authenticated",
            "stop_execution_authorized",
            "success_outcome_retention_authorized",
            "supervisor_signal_authorized",
            "supervisor_start_authorized",
            "supervisor_stop_authorized",
            "target_authenticated",
            "teardown_authorized",
            "topology_mutation_authorized",
            "volume_removal_authorized",
        )
        if (
            len(authority_field_names) != 55
            or len(frozenset(authority_field_names)) != 55
            or authority_field_names != tuple(sorted(authority_field_names))
        ):
            raise ValueError

        def exact_immutable_object(
            items: tuple[tuple[str, object], ...],
        ) -> tuple[object, ...]:
            ordered: tuple[tuple[str, object], ...] = ()
            for item in items:
                raw_name = tuple.__getitem__(item, 0) if type(item) is tuple else None
                if type(item) is not tuple or len(item) != 2 or type(raw_name) is not str:
                    raise ValueError
                name = raw_name
                index = 0
                while index < len(ordered) and ordered[index][0] < name:
                    index += 1
                if index < len(ordered) and ordered[index][0] == name:
                    raise ValueError
                ordered = (*ordered[:index], item, *ordered[index:])
            return (0, ordered)

        def exact_object_value(value: object, name: str) -> object:
            if (
                type(value) is not tuple
                or len(value) != 2
                or tuple.__getitem__(value, 0) != 0
                or type(tuple.__getitem__(value, 1)) is not tuple
                or type(name) is not str
            ):
                raise ValueError
            matches: tuple[object, ...] = ()
            for item in tuple.__getitem__(value, 1):
                if (
                    type(item) is not tuple
                    or len(item) != 2
                    or type(tuple.__getitem__(item, 0)) is not str
                ):
                    raise ValueError
                if tuple.__getitem__(item, 0) == name:
                    matches += (tuple.__getitem__(item, 1),)
            if len(matches) != 1:
                raise ValueError
            return tuple.__getitem__(matches, 0)

        candidate_path = cast(str, _external_binding_value(binding, 1))
        candidate_encoded = cast(bytes, _external_binding_value(binding, 2))
        candidate_directory_identity = cast(tuple[int, int], _external_binding_value(binding, 3))
        candidate_file_identity = cast(_StatIdentity, _external_binding_value(binding, 4))
        outcome_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 1),
        )
        attempt_snapshot = cast(
            tuple[object, ...],
            _historical_slot(historical, 2),
        )
        outcome_encoded = cast(
            bytes,
            _controller_snapshot_value(outcome_snapshot, 7),
        )
        attempt_encoded = cast(
            bytes,
            _attempt_snapshot_value(attempt_snapshot, 4),
        )
        approval_snapshot = cast(
            tuple[object, ...],
            _attempt_snapshot_value(attempt_snapshot, 8),
        )
        approval_encoded = cast(
            bytes,
            _loaded_approval_snapshot_value(approval_snapshot, 4),
        )
        provenance_snapshot = cast(
            tuple[object, ...],
            _loaded_approval_snapshot_value(approval_snapshot, 29),
        )
        _loaded_approval_snapshot_value(approval_snapshot, 1)
        _provenance_value(provenance_snapshot, 1)
        semantic = cast(
            tuple[object, ...],
            _controller_snapshot_value(outcome_snapshot, 8),
        )
        _require_attempt_snapshot_binding(
            attempt_encoded,
            approval_snapshot,
        )
        locator_encoded = _controller_semantic_value(semantic, 9)
        locator_sha256 = _controller_semantic_value(semantic, 10)
        topology_values = _controller_semantic_value(
            semantic,
            11,
        )
        if (
            type(locator_encoded) is not bytes
            or not _is_sha256(locator_sha256)
            or type(topology_values) is not tuple
            or len(topology_values) != 10
            or any(type(value) is not str for value in topology_values)
        ):
            raise ValueError
        locator = _decode_json(
            locator_encoded,
            maximum_bytes=64 * 1_024,
        )
        exact_locator_sha256 = cast(str, locator_sha256)
        if _sha256(locator_encoded).hexdigest() != exact_locator_sha256:
            raise ValueError
        (
            topology_operation_id,
            topology_approval_sha256,
            topology_claim_sha256,
            topology_retained_claim_sha256,
            topology_active_admission_sha256,
            topology_successor_sha256,
            topology_source_image_id,
            topology_supervisor_image_id,
            topology_git_revision,
            topology_image_admission_sha256,
        ) = topology_values
        outcome_sha256 = _sha256(outcome_encoded).hexdigest()
        attempt_sha256 = _sha256(attempt_encoded).hexdigest()
        approval_sha256 = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 9),
        )
        start_operation_id = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 12),
        )
        envelope_sha256 = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 27),
        )
        source_image_id = _loaded_approval_snapshot_value(
            approval_snapshot,
            13,
        )
        supervisor_image_id = _loaded_approval_snapshot_value(
            approval_snapshot,
            14,
        )
        git_revision = _loaded_approval_snapshot_value(approval_snapshot, 15)
        image_admission_sha256 = _loaded_approval_snapshot_value(
            approval_snapshot,
            16,
        )
        source_revision_sha256 = _provenance_value(
            provenance_snapshot,
            6,
        )
        semantic_contract_version = _controller_semantic_value(semantic, 1)
        semantic_status = _controller_semantic_value(semantic, 2)
        semantic_reason = _controller_semantic_value(semantic, 3)
        semantic_operation_id = _controller_semantic_value(semantic, 4)
        semantic_approval_sha256 = _controller_semantic_value(semantic, 5)
        semantic_claim_sha256 = _controller_semantic_value(semantic, 6)
        semantic_retained_claim_sha256 = _controller_semantic_value(
            semantic,
            7,
        )
        semantic_active_admission_sha256 = _controller_semantic_value(
            semantic,
            8,
        )
        if (
            semantic_contract_version
            != "phase6d-post-enrollment-start-retained-controller-outcome-v2"
            or semantic_status != "post_enrollment_start_confirmed"
            or semantic_reason != "post_enrollment_start_confirmed"
            or semantic_operation_id != start_operation_id
            or semantic_approval_sha256 != approval_sha256
            or locator_sha256 != exact_locator_sha256
            or topology_operation_id != semantic_operation_id
            or topology_approval_sha256 != semantic_approval_sha256
            or topology_claim_sha256 != semantic_claim_sha256
            or topology_retained_claim_sha256 != semantic_retained_claim_sha256
            or topology_active_admission_sha256 != semantic_active_admission_sha256
            or not _is_sha256(topology_successor_sha256)
            or topology_source_image_id != source_image_id
            or topology_supervisor_image_id != supervisor_image_id
            or topology_git_revision != git_revision
            or topology_image_admission_sha256 != image_admission_sha256
            or _abspath(cast(str, _controller_snapshot_value(outcome_snapshot, 1)))
            != _controller_snapshot_value(outcome_snapshot, 1)
            or _abspath(cast(str, _controller_snapshot_value(outcome_snapshot, 6)))
            != _controller_snapshot_value(outcome_snapshot, 6)
            or _controller_snapshot_value(outcome_snapshot, 6)
            != _join(
                cast(str, _controller_snapshot_value(outcome_snapshot, 1)),
                tuple.__getitem__(
                    cast(
                        tuple[str, ...],
                        _controller_snapshot_value(outcome_snapshot, 5),
                    ),
                    0,
                ),
            )
            or attempt_sha256 != _attempt_snapshot_value(attempt_snapshot, 5)
            or _sha256(approval_encoded).hexdigest() != envelope_sha256
            or any(
                not _is_sha256(value)
                for value in (
                    outcome_sha256,
                    attempt_sha256,
                    approval_sha256,
                    envelope_sha256,
                    semantic_claim_sha256,
                    semantic_retained_claim_sha256,
                    semantic_active_admission_sha256,
                    image_admission_sha256,
                    source_revision_sha256,
                )
            )
            or not _is_uuid4(start_operation_id)
            or not _is_git_revision(git_revision)
            or not _is_image_id(source_image_id)
            or not _is_image_id(supervisor_image_id)
        ):
            raise ValueError
        target_items = (
            *((name, False) for name in authority_field_names),
            (
                "contract_version",
                "phase6d-post-enrollment-graceful-stop-target-v1",
            ),
            ("controller_outcome_contract_version", semantic_contract_version),
            ("controller_outcome_reason", semantic_reason),
            ("controller_outcome_sha256", outcome_sha256),
            ("controller_outcome_status", semantic_status),
            ("durable_shutdown_locator", locator),
            ("durable_shutdown_locator_sha256", exact_locator_sha256),
            ("service", "trusted-time-post-enrollment-graceful-stop"),
            ("start_approval_sha256", approval_sha256),
            ("start_execution_attempt_slot_sha256", attempt_sha256),
            ("start_operation_id", start_operation_id),
            ("start_operator_attestation_envelope_sha256", envelope_sha256),
            ("status", "graceful_stop_target_unqualified"),
        )
        if len(target_items) != 68 or len(frozenset(name for name, _ in target_items)) != 68:
            raise ValueError
        target = exact_immutable_object(target_items)
        target_encoded = _canonical_json(target) + b"\n"
        target_sha256 = _sha256(target_encoded).hexdigest()
        decision = _decode_json(
            candidate_encoded,
            maximum_bytes=128 * 1_024,
        )
        decision_operation_id = exact_object_value(decision, "operation_id")
        if not _is_uuid4(decision_operation_id) or decision_operation_id == start_operation_id:
            raise ValueError
        expected_decision_items = (
            *((name, False) for name in authority_field_names),
            (
                "contract_version",
                "phase6d-post-enrollment-graceful-stop-decision-v1",
            ),
            ("decision", "approve_one_post_enrollment_graceful_stop_attempt"),
            ("graceful_stop_target", target),
            ("graceful_stop_target_sha256", target_sha256),
            ("operation_id", decision_operation_id),
            (
                "replay_domain",
                "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
                "post-enrollment-graceful-stop/operator-attestation/v1",
            ),
            ("service", "trusted-time-post-enrollment-graceful-stop"),
            ("status", "external_attestation_required"),
        )
        if (
            len(expected_decision_items) != 63
            or len(frozenset(name for name, _ in expected_decision_items)) != 63
        ):
            raise ValueError
        expected_decision = exact_immutable_object(expected_decision_items)
        if (
            decision != expected_decision
            or _canonical_json(expected_decision) + b"\n" != candidate_encoded
        ):
            raise ValueError
        decision_sha256 = _sha256(candidate_encoded).hexdigest()
        candidate_file_name = _basename(candidate_path)
        if candidate_file_name != _candidate_file_name(decision_sha256):
            raise ValueError
        receipt_identity_values = (
            candidate_file_name,
            outcome_sha256,
            exact_locator_sha256,
            decision_sha256,
            cast(str, decision_operation_id),
            target_sha256,
            approval_sha256,
            cast(str, image_admission_sha256),
            cast(str, source_revision_sha256),
            attempt_sha256,
            cast(str, git_revision),
            start_operation_id,
            envelope_sha256,
            cast(str, source_image_id),
            cast(str, supervisor_image_id),
        )
        if any(type(value) is not str for value in receipt_identity_values):
            raise ValueError
        receipt_encoded = _receipt_bytes(receipt_identity_values)
        attempt_path = cast(
            str,
            _attempt_snapshot_value(attempt_snapshot, 3),
        )
        attempt_directory_identity = cast(
            tuple[int, int],
            _attempt_snapshot_value(
                attempt_snapshot,
                6,
            ),
        )
        attempt_file_identity = cast(
            tuple[int, ...],
            _attempt_snapshot_value(
                attempt_snapshot,
                7,
            ),
        )
        approval_path = cast(
            str,
            _loaded_approval_snapshot_value(approval_snapshot, 3),
        )
        approval_directory_identity = cast(
            tuple[int, int],
            _loaded_approval_snapshot_value(
                approval_snapshot,
                5,
            ),
        )
        approval_file_identity = cast(
            tuple[int, ...],
            _loaded_approval_snapshot_value(
                approval_snapshot,
                6,
            ),
        )
        source_snapshot: _LoadedReceiptSourceSnapshot = (
            "loaded-receipt-source-snapshot-v1",
            candidate_path,
            candidate_encoded,
            candidate_directory_identity,
            candidate_file_identity,
            cast(str, _controller_snapshot_value(outcome_snapshot, 6)),
            outcome_encoded,
            cast(
                tuple[int, ...],
                _controller_snapshot_value(outcome_snapshot, 9),
            ),
            cast(
                tuple[int, ...],
                _controller_snapshot_value(outcome_snapshot, 11),
            ),
            cast(
                tuple[int, ...],
                _controller_snapshot_value(outcome_snapshot, 13),
            ),
            attempt_path,
            attempt_encoded,
            attempt_directory_identity,
            attempt_file_identity,
            approval_path,
            approval_encoded,
            approval_directory_identity,
            approval_file_identity,
            target_encoded,
            receipt_identity_values,
            receipt_encoded,
            _sha256(receipt_encoded).hexdigest(),
        )
        _source_slot(source_snapshot, 1)
        return source_snapshot
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        ) from None


def _receipt_from_identity_values(
    identity_values: tuple[str, ...],
) -> TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    try:
        if (
            type(identity_values) is not tuple
            or len(identity_values) != 15
            or any(type(value) is not str for value in identity_values)
        ):
            raise ValueError
        receipt = TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
            artifact_location=tuple.__getitem__(identity_values, 0),
            controller_outcome_sha256=tuple.__getitem__(identity_values, 1),
            durable_shutdown_locator_sha256=tuple.__getitem__(identity_values, 2),
            graceful_stop_decision_v1_sha256=tuple.__getitem__(identity_values, 3),
            graceful_stop_operation_id=tuple.__getitem__(identity_values, 4),
            graceful_stop_target_sha256=tuple.__getitem__(identity_values, 5),
            start_approval_sha256=tuple.__getitem__(identity_values, 6),
            start_approved_image_provenance_sha256=tuple.__getitem__(identity_values, 7),
            start_approved_image_provenance_source_revision_sha256=(
                tuple.__getitem__(identity_values, 8)
            ),
            start_execution_attempt_slot_sha256=tuple.__getitem__(identity_values, 9),
            start_git_revision=tuple.__getitem__(identity_values, 10),
            start_operation_id=tuple.__getitem__(identity_values, 11),
            start_operator_attestation_envelope_sha256=tuple.__getitem__(identity_values, 12),
            start_source_image_id=tuple.__getitem__(identity_values, 13),
            start_supervisor_image_id=tuple.__getitem__(identity_values, 14),
            _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
        )
        if type(receipt) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
            raise ValueError
        return receipt
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_invalid"
        ) from None


def _loaded_receipt_seal_values(
    value: Any,
    _fspath: Callable[[Any], Any] = os.fspath,
) -> tuple[object, ...]:
    return (
        _fspath(value.artifact_path),
        value.encoded,
        value.directory_identity,
        value.file_identity,
        value.receipt_encoded,
        value.receipt_sha256,
    )


def _source_view_values(
    snapshot: _LoadedReceiptSourceSnapshot,
) -> tuple[object, ...]:
    """Return the immutable view projection without consulting the heap view."""

    return (
        "loaded-receipt-view-values-v1",
        _source_slot(snapshot, 1),
        _source_slot(snapshot, 2),
        _source_slot(snapshot, 3),
        _source_slot(snapshot, 4),
        _source_slot(snapshot, 20),
        _source_slot(snapshot, 21),
    )


def _registration_comparison_values(
    *,
    historical: _HistoricalStartFileSnapshot,
    source: _LoadedReceiptSourceSnapshot,
    artifact_directory: str,
    ignored_root: str,
    allowed_modes: frozenset[int],
    minimum_bytes: int,
    maximum_bytes: int,
    phase: str,
) -> tuple[object, ...]:
    """Return only primitive/snapshot values used to compare registrations."""

    _historical_slot(historical, 1)
    _source_slot(source, 1)
    if (
        type(artifact_directory) is not str
        or type(ignored_root) is not str
        or not _exact_int_frozenset(allowed_modes)
        or type(minimum_bytes) is not int
        or type(maximum_bytes) is not int
        or minimum_bytes < 0
        or maximum_bytes < minimum_bytes
        or type(phase) is not str
        or not phase
    ):
        raise ValueError
    return (
        "loaded-receipt-comparison-values-v1",
        historical,
        source,
        artifact_directory,
        ignored_root,
        allowed_modes,
        minimum_bytes,
        maximum_bytes,
        phase,
    )


def _registry_source_binding_matches(
    *,
    historical: _HistoricalStartFileSnapshot,
    source: _LoadedReceiptSourceSnapshot,
    start_artifact: object,
    expected_decision_sha256: object,
    artifact_directory: object,
    ignored_root: object,
    _abspath: Callable[[str], str] = os.path.abspath,
    _basename: Callable[[str], str] = os.path.basename,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
    _is_same_or_beneath: Callable[[str, str], bool] = _path_is_same_or_beneath,
    _receipt_bytes: Callable[[tuple[str, ...]], bytes] = (
        _canonical_receipt_bytes_from_identity_values
    ),
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> bool:
    """Validate every primitive binding carried by a registry record."""

    try:
        _historical_slot(historical, 1)
        _source_slot(source, 1)
        candidate_path = cast(str, _source_slot(source, 1))
        candidate_encoded = cast(bytes, _source_slot(source, 2))
        receipt_identity_values = cast(tuple[str, ...], _source_slot(source, 19))
        receipt_encoded = cast(bytes, _source_slot(source, 20))
        receipt_sha256 = cast(str, _source_slot(source, 21))
        receipt_artifact_location = tuple.__getitem__(receipt_identity_values, 0)
        receipt_decision_sha256 = tuple.__getitem__(receipt_identity_values, 3)
        return not (
            type(start_artifact) is not str
            or type(expected_decision_sha256) is not str
            or type(artifact_directory) is not str
            or type(ignored_root) is not str
            or not _is_sha256(expected_decision_sha256)
            or not _historical_invocation_binding_matches(
                historical,
                start_artifact=start_artifact,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            or _abspath(candidate_path) != candidate_path
            or _is_same_or_beneath(candidate_path, ignored_root)
            or _sha256(candidate_encoded).hexdigest() != expected_decision_sha256
            or _basename(candidate_path) != _candidate_file_name(expected_decision_sha256)
            or receipt_artifact_location != _basename(candidate_path)
            or receipt_decision_sha256 != expected_decision_sha256
            or _receipt_bytes(receipt_identity_values) != receipt_encoded
            or _sha256(receipt_encoded).hexdigest() != receipt_sha256
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


type _LoadedReceiptRegistration = tuple[
    str,
    weakref.ReferenceType[LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt],
    int,
    threading.Thread,
    _HistoricalStartFileSnapshot,
    _LoadedReceiptSourceSnapshot,
    tuple[object, ...],
    tuple[object, ...],
    str,
    bytes,
    tuple[int, int],
    _StatIdentity,
    str,
    str,
    tuple[str, ...],
    bytes,
    str,
    str,
    str,
    frozenset[int],
    int,
    int,
    str,
]
type _PendingLoadedReceiptRegistration = tuple[
    str,
    weakref.ReferenceType[LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt],
    int,
    threading.Thread,
    _HistoricalStartFileSnapshot,
    _LoadedReceiptSourceSnapshot,
    tuple[object, ...],
    str,
    str,
    str,
    str,
]


def _registration_slot(value: _LoadedReceiptRegistration, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 23
        or tuple.__getitem__(value, 0) != "loaded-receipt-registration-v1"
        or not _is_exact_registry_reference(tuple.__getitem__(value, 1))
        or type(tuple.__getitem__(value, 2)) is not int
        or not _is_exact_registry_thread(tuple.__getitem__(value, 3))
        or type(tuple.__getitem__(value, 6)) is not tuple
        or type(tuple.__getitem__(value, 7)) is not tuple
        or any(
            type(tuple.__getitem__(value, slot)) is not str for slot in (8, 12, 13, 16, 17, 18, 22)
        )
        or type(tuple.__getitem__(value, 9)) is not bytes
        or type(tuple.__getitem__(value, 15)) is not bytes
        or not _exact_int_tuple(tuple.__getitem__(value, 10), length=2)
        or not _exact_int_tuple(tuple.__getitem__(value, 11), length=9)
        or not _exact_str_tuple(
            tuple.__getitem__(value, 14),
            length=15,
        )
        or not _exact_int_frozenset(tuple.__getitem__(value, 19))
        or type(tuple.__getitem__(value, 20)) is not int
        or type(tuple.__getitem__(value, 21)) is not int
        or not _is_sha256(tuple.__getitem__(value, 13))
        or not _is_sha256(tuple.__getitem__(value, 16))
        or type(index) is not int
        or index < 1
        or index >= 23
    ):
        raise ValueError
    historical = cast(
        _HistoricalStartFileSnapshot,
        tuple.__getitem__(value, 4),
    )
    source = cast(
        _LoadedReceiptSourceSnapshot,
        tuple.__getitem__(value, 5),
    )
    _historical_slot(historical, 1)
    _source_slot(source, 1)
    if (
        tuple.__getitem__(value, 6) != _source_view_values(source)
        or tuple.__getitem__(value, 7)
        != _registration_comparison_values(
            historical=historical,
            source=source,
            artifact_directory=cast(str, tuple.__getitem__(value, 17)),
            ignored_root=cast(str, tuple.__getitem__(value, 18)),
            allowed_modes=cast(frozenset[int], tuple.__getitem__(value, 19)),
            minimum_bytes=cast(int, tuple.__getitem__(value, 20)),
            maximum_bytes=cast(int, tuple.__getitem__(value, 21)),
            phase=cast(str, tuple.__getitem__(value, 22)),
        )
        or tuple.__getitem__(value, 8) != _source_slot(source, 1)
        or tuple.__getitem__(value, 9) != _source_slot(source, 2)
        or tuple.__getitem__(value, 10) != _source_slot(source, 3)
        or tuple.__getitem__(value, 11) != _source_slot(source, 4)
        or tuple.__getitem__(value, 14) != _source_slot(source, 19)
        or tuple.__getitem__(value, 15) != _source_slot(source, 20)
        or tuple.__getitem__(value, 16) != _source_slot(source, 21)
        or tuple.__getitem__(value, 19) != frozenset((0o600,))
        or tuple.__getitem__(value, 20) != 1
        or tuple.__getitem__(value, 21) != 128 * 1_024
        or tuple.__getitem__(value, 22) != "decision_candidate"
        or not _registry_source_binding_matches(
            historical=historical,
            source=source,
            start_artifact=tuple.__getitem__(value, 12),
            expected_decision_sha256=tuple.__getitem__(value, 13),
            artifact_directory=tuple.__getitem__(value, 17),
            ignored_root=tuple.__getitem__(value, 18),
        )
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _pending_slot(value: _PendingLoadedReceiptRegistration, index: int) -> object:
    if (
        type(value) is not tuple
        or len(value) != 11
        or tuple.__getitem__(value, 0) != "pending-loaded-receipt-registration-v1"
        or not _is_exact_registry_reference(tuple.__getitem__(value, 1))
        or type(tuple.__getitem__(value, 2)) is not int
        or not _is_exact_registry_thread(tuple.__getitem__(value, 3))
        or type(tuple.__getitem__(value, 6)) is not tuple
        or any(type(tuple.__getitem__(value, slot)) is not str for slot in (7, 8, 9, 10))
        or not _is_sha256(tuple.__getitem__(value, 8))
        or type(index) is not int
        or index < 1
        or index >= 11
    ):
        raise ValueError
    historical = cast(
        _HistoricalStartFileSnapshot,
        tuple.__getitem__(value, 4),
    )
    source = cast(
        _LoadedReceiptSourceSnapshot,
        tuple.__getitem__(value, 5),
    )
    _historical_slot(historical, 1)
    _source_slot(source, 1)
    if tuple.__getitem__(value, 6) != _source_view_values(
        source
    ) or not _registry_source_binding_matches(
        historical=historical,
        source=source,
        start_artifact=tuple.__getitem__(value, 7),
        expected_decision_sha256=tuple.__getitem__(value, 8),
        artifact_directory=tuple.__getitem__(value, 9),
        ignored_root=tuple.__getitem__(value, 10),
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


_LOADED_RECEIPT_REGISTRY: dict[int, _LoadedReceiptRegistration] = {}
_PENDING_LOADED_RECEIPT_REGISTRY: dict[int, _PendingLoadedReceiptRegistration] = {}
_LOADED_RECEIPT_REGISTRY_BURN_ATTEMPTS = 16


def _lost_registry_reference_matches(
    current: object | None,
    *,
    tag: str,
    length: int,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ],
) -> bool:
    return (
        type(current) is tuple
        and len(current) == length
        and tuple.__getitem__(current, 0) == tag
        and tuple.__getitem__(current, 1) is reference
    )


def _discard_lost_registry_reference(
    registry: dict[int, Any],
    candidate_id: int,
    *,
    tag: str,
    length: int,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ],
) -> BaseException | None:
    """Best-effort exact weakref cleanup without re-entering the traced lock helper."""

    first_error: BaseException | None = None
    try:
        initial_depth = _loaded_receipt_registry_lock_depth()
    except BaseException as error:
        return error
    for _ in range(16):
        absent = False
        try:
            with _LOADED_RECEIPT_REGISTRY_LOCK:
                current = cast(object | None, registry.get(candidate_id))
                if _lost_registry_reference_matches(
                    current,
                    tag=tag,
                    length=length,
                    reference=reference,
                ):
                    registry.pop(candidate_id, None)
                remaining = cast(object | None, registry.get(candidate_id))
                absent = not _lost_registry_reference_matches(
                    remaining,
                    tag=tag,
                    length=length,
                    reference=reference,
                )
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
        finally:
            cleanup_error = _release_loaded_receipt_registry_lock_to_depth(initial_depth)
            first_error = _preferred_registry_exception(first_error, cleanup_error)
        if absent:
            return first_error
    return _preferred_registry_exception(
        first_error,
        RuntimeError("lost loaded receipt registry reference could not be discarded"),
    )


def _registry_entry_matches(
    current: object | None,
    *,
    registration: object | None,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ]
    | None,
) -> bool:
    if current is None:
        return False
    if registration is not None:
        return current is registration
    if reference is not None:
        try:
            current_reference = _registration_slot(
                cast(_LoadedReceiptRegistration, current),
                1,
            )
        except (TypeError, ValueError):
            return True
        if not _is_exact_registry_reference(current_reference):
            return True
        return current_reference is reference
    return True


def _burn_loaded_receipt_registry_entry(
    candidate_id: int,
    *,
    registration: object | None = None,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ]
    | None = None,
) -> BaseException | None:
    """Remove one exact registration despite an interrupt at a mutation boundary."""

    first_error: BaseException | None = None
    for _ in range(16):
        absent = False
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(object | None, _LOADED_RECEIPT_REGISTRY.get(candidate_id))
                if _registry_entry_matches(
                    current,
                    registration=registration,
                    reference=reference,
                ):
                    _LOADED_RECEIPT_REGISTRY.pop(candidate_id, None)
                remaining = cast(
                    object | None,
                    _LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
                absent = not _registry_entry_matches(
                    remaining,
                    registration=registration,
                    reference=reference,
                )
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
        if absent:
            return first_error
    return _preferred_registry_exception(
        first_error,
        RuntimeError("loaded receipt registry entry could not be revoked"),
    )


def _raise_preferred_registry_exception(
    primary: BaseException,
    cleanup: BaseException | None,
) -> Never:
    terminal = _preferred_registry_exception(primary, cleanup)
    if terminal is None or terminal is primary:
        raise primary
    raise terminal from primary


def _propagate_async_registry_exception(
    primary: BaseException,
    cleanup: BaseException | None,
) -> None:
    terminal = _preferred_registry_exception(primary, cleanup)
    if terminal is None or isinstance(terminal, Exception):
        return
    if terminal is primary:
        raise primary.with_traceback(primary.__traceback__)
    raise terminal from primary


def _pending_registry_entry_matches(
    current: object | None,
    *,
    registration: object | None,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ]
    | None,
) -> bool:
    if current is None:
        return False
    if registration is not None:
        return current is registration
    if reference is not None:
        try:
            current_reference = _pending_slot(
                cast(_PendingLoadedReceiptRegistration, current),
                1,
            )
        except (TypeError, ValueError):
            return True
        if not _is_exact_registry_reference(current_reference):
            return True
        return current_reference is reference
    return True


def _burn_pending_loaded_receipt_registry_entry(
    candidate_id: int,
    *,
    registration: object | None = None,
    reference: weakref.ReferenceType[
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ]
    | None = None,
) -> BaseException | None:
    first_error: BaseException | None = None
    for _ in range(16):
        absent = False
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _PENDING_LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
                if _pending_registry_entry_matches(
                    current,
                    registration=registration,
                    reference=reference,
                ):
                    _PENDING_LOADED_RECEIPT_REGISTRY.pop(candidate_id, None)
                remaining = cast(
                    object | None,
                    _PENDING_LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
                absent = not _pending_registry_entry_matches(
                    remaining,
                    registration=registration,
                    reference=reference,
                )
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
        if absent:
            return first_error
    return _preferred_registry_exception(
        first_error,
        RuntimeError("pending loaded receipt registry entry could not be revoked"),
    )


def _revoke_pending_loaded_receipt_if_registered(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> BaseException | None:
    if not _registry_process_matches_origin():
        return None
    candidate_id = id(value)
    first_error: BaseException | None = None
    for _ in range(16):
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _PENDING_LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
            continue
        if current is None:
            return first_error
        cleanup_error = _burn_pending_loaded_receipt_registry_entry(candidate_id)
        first_error = _preferred_registry_exception(first_error, cleanup_error)
        try:
            with _held_loaded_receipt_registry_lock():
                remaining = cast(
                    object | None,
                    _PENDING_LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
                if remaining is None:
                    return first_error
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
    return _preferred_registry_exception(
        first_error,
        RuntimeError("pending loaded receipt registry entry could not be revoked"),
    )


def _pending_loaded_receipt_matches_live(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    registration: _PendingLoadedReceiptRegistration,
) -> bool:
    try:
        reference = _pending_slot(registration, 1)
        owner_pid = _pending_slot(registration, 2)
        owner_thread = _pending_slot(registration, 3)
        historical = cast(
            _HistoricalStartFileSnapshot,
            _pending_slot(registration, 4),
        )
        snapshot = cast(
            _LoadedReceiptSourceSnapshot,
            _pending_slot(registration, 5),
        )
        source_view_values = cast(
            tuple[object, ...],
            _pending_slot(registration, 6),
        )
        candidate_path = cast(str, _source_slot(snapshot, 1))
        candidate_encoded = cast(bytes, _source_slot(snapshot, 2))
        candidate_directory_identity = cast(
            tuple[int, int],
            _source_slot(snapshot, 3),
        )
        candidate_file_identity = cast(
            _StatIdentity,
            _source_slot(snapshot, 4),
        )
        return not (
            not _registry_process_matches_origin()
            or owner_pid != _registry_origin_pid()
            or owner_thread is not _registry_current_thread()
            or cast(weakref.ReferenceType[object], reference)() is not value
            or source_view_values != _source_view_values(snapshot)
            or _build_loaded_receipt_source_snapshot(
                binding=_make_external_binding(
                    path=candidate_path,
                    encoded=candidate_encoded,
                    directory_identity=candidate_directory_identity,
                    file_identity=candidate_file_identity,
                    allowed_modes=frozenset((0o600,)),
                    minimum_bytes=1,
                    maximum_bytes=128 * 1_024,
                    phase="decision_candidate",
                ),
                historical=historical,
            )
            != snapshot
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _burn_pending_loaded_receipt_targets(
    targets: tuple[
        tuple[
            LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
            _PendingLoadedReceiptRegistration | None,
        ],
        ...,
    ],
) -> BaseException | None:
    first_error: BaseException | None = None
    for value, _registration in targets:
        try:
            observed = _revoke_pending_loaded_receipt_if_registered(value)
        except BaseException as error:
            observed = error
        first_error = _preferred_registry_exception(first_error, observed)
    return first_error


def _register_pending_loaded_receipt(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    *,
    artifact_directory: str,
    ignored_root: str,
    start_operator_attested_approval_artifact: str,
    expected_graceful_stop_decision_v1_sha256: str,
    historical_snapshot: _HistoricalStartFileSnapshot,
    source_snapshot: _LoadedReceiptSourceSnapshot,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> _PendingLoadedReceiptRegistration:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    owner_pid = _registry_origin_pid()
    owner_thread = _registry_current_thread()
    candidate_path = cast(
        str,
        _source_slot(source_snapshot, 1),
    )
    candidate_encoded = cast(
        bytes,
        _source_slot(source_snapshot, 2),
    )
    candidate_directory_identity = cast(
        tuple[int, int],
        _source_slot(source_snapshot, 3),
    )
    candidate_file_identity = cast(
        _StatIdentity,
        _source_slot(source_snapshot, 4),
    )
    if (
        type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or _sha256(candidate_encoded).hexdigest() != expected_graceful_stop_decision_v1_sha256
        or type(start_operator_attested_approval_artifact) is not str
        or start_operator_attested_approval_artifact
        != _historical_start_approval_artifact_path(historical_snapshot)
        or _build_loaded_receipt_source_snapshot(
            binding=_make_external_binding(
                path=candidate_path,
                encoded=candidate_encoded,
                directory_identity=candidate_directory_identity,
                file_identity=candidate_file_identity,
                allowed_modes=frozenset((0o600,)),
                minimum_bytes=1,
                maximum_bytes=128 * 1_024,
                phase="decision_candidate",
            ),
            historical=historical_snapshot,
        )
        != source_snapshot
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    candidate_id = id(value)

    def candidate_lost(
        reference: weakref.ReferenceType[
            LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        ],
    ) -> None:
        if not _registry_process_matches_origin():
            return
        cleanup_error: BaseException | None = None
        transition_error: BaseException | None = None
        retry_error: BaseException | None = None
        try:
            try:
                cleanup_error = _discard_lost_registry_reference(
                    cast(dict[int, Any], _PENDING_LOADED_RECEIPT_REGISTRY),
                    candidate_id,
                    tag="pending-loaded-receipt-registration-v1",
                    length=11,
                    reference=reference,
                )
            except BaseException as error:
                transition_error = error
        finally:
            try:
                retry_error = _discard_lost_registry_reference(
                    cast(dict[int, Any], _PENDING_LOADED_RECEIPT_REGISTRY),
                    candidate_id,
                    tag="pending-loaded-receipt-registration-v1",
                    length=11,
                    reference=reference,
                )
            except BaseException as error:
                retry_error = error
        terminal = _preferred_registry_exceptions(
            transition_error,
            cleanup_error,
            retry_error,
        )
        if terminal is not None and reference() is not None:
            raise terminal

    reference = _new_exact_registry_reference(value, candidate_lost)
    registration: _PendingLoadedReceiptRegistration = (
        "pending-loaded-receipt-registration-v1",
        reference,
        owner_pid,
        owner_thread,
        historical_snapshot,
        source_snapshot,
        _source_view_values(source_snapshot),
        start_operator_attested_approval_artifact,
        expected_graceful_stop_decision_v1_sha256,
        artifact_directory,
        ignored_root,
    )
    _pending_slot(registration, 1)
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    insertion_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            with _held_loaded_receipt_registry_lock():
                if (
                    candidate_id in _PENDING_LOADED_RECEIPT_REGISTRY
                    or candidate_id in _LOADED_RECEIPT_REGISTRY
                ):
                    raise ValueError
                _PENDING_LOADED_RECEIPT_REGISTRY[candidate_id] = registration
        except BaseException as error:
            insertion_error = error
        finally:
            if insertion_error is not None:
                cleanup_error = _burn_pending_loaded_receipt_targets(((value, registration),))
    except BaseException as error:
        transition_error = error
    finally:
        if insertion_error is not None or transition_error is not None:
            retry_error = _burn_pending_loaded_receipt_targets(((value, registration),))
    terminal = _preferred_registry_exceptions(
        insertion_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if not _pending_loaded_receipt_matches_live(value, registration):
        cleanup_error = _burn_pending_loaded_receipt_targets(((value, registration),))
        if cleanup_error is not None:
            raise cleanup_error
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    return registration


def _consume_pending_loaded_receipt(
    value: object,
) -> _PendingLoadedReceiptRegistration:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    owner_pid = _registry_origin_pid()
    owner_thread = _registry_current_thread()
    if type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    exact = value
    registration: _PendingLoadedReceiptRegistration | None = None
    valid = False
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _PENDING_LOADED_RECEIPT_REGISTRY.get(id(exact)),
                )
                try:
                    typed_current = cast(_PendingLoadedReceiptRegistration, current)
                    current_reference = _pending_slot(typed_current, 1)
                    current_owner_pid = _pending_slot(typed_current, 2)
                    current_owner_thread = _pending_slot(
                        typed_current,
                        3,
                    )
                    valid = (
                        _is_exact_registry_reference(current_reference)
                        and cast(weakref.ReferenceType[object], current_reference)() is exact
                        and current_owner_pid == owner_pid
                        and current_owner_thread is owner_thread
                    )
                except (TypeError, ValueError):
                    valid = False
                if valid:
                    registration = typed_current
                if current is not None:
                    _PENDING_LOADED_RECEIPT_REGISTRY.pop(id(exact), None)
                    if _PENDING_LOADED_RECEIPT_REGISTRY.get(id(exact)) is not None:
                        raise RuntimeError(
                            "pending loaded receipt registry entry could not be consumed"
                        )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _burn_pending_loaded_receipt_targets(((exact, None),))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _burn_pending_loaded_receipt_targets(((exact, None),))
    terminal = _preferred_registry_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if (
        not valid
        or registration is None
        or not _pending_loaded_receipt_matches_live(exact, registration)
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    return registration


def _register_loaded_receipt(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    *,
    artifact_directory: str,
    ignored_root: str,
    start_operator_attested_approval_artifact: str,
    expected_graceful_stop_decision_v1_sha256: str,
    historical_snapshot: _HistoricalStartFileSnapshot,
    source_snapshot: _LoadedReceiptSourceSnapshot,
    _basename: Callable[[str], str] = os.path.basename,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> _LoadedReceiptRegistration:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    owner_pid = _registry_origin_pid()
    owner_thread = _registry_current_thread()
    candidate_path = cast(str, _source_slot(source_snapshot, 1))
    candidate_encoded = cast(bytes, _source_slot(source_snapshot, 2))
    candidate_directory_identity = cast(
        tuple[int, int],
        _source_slot(source_snapshot, 3),
    )
    candidate_file_identity = cast(
        _StatIdentity,
        _source_slot(source_snapshot, 4),
    )
    receipt_identity_values = cast(
        tuple[str, ...],
        _source_slot(source_snapshot, 19),
    )
    receipt_encoded = cast(bytes, _source_slot(source_snapshot, 20))
    receipt_sha256 = cast(str, _source_slot(source_snapshot, 21))
    receipt_decision_sha256 = tuple.__getitem__(receipt_identity_values, 3)
    if (
        type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or _build_loaded_receipt_source_snapshot(
            binding=_make_external_binding(
                path=candidate_path,
                encoded=candidate_encoded,
                directory_identity=candidate_directory_identity,
                file_identity=candidate_file_identity,
                allowed_modes=frozenset((0o600,)),
                minimum_bytes=1,
                maximum_bytes=128 * 1_024,
                phase="decision_candidate",
            ),
            historical=historical_snapshot,
        )
        != source_snapshot
        or _basename(candidate_path)
        != _candidate_file_name(expected_graceful_stop_decision_v1_sha256)
        or _sha256(candidate_encoded).hexdigest() != expected_graceful_stop_decision_v1_sha256
        or receipt_decision_sha256 != expected_graceful_stop_decision_v1_sha256
        or type(start_operator_attested_approval_artifact) is not str
        or start_operator_attested_approval_artifact
        != _historical_start_approval_artifact_path(historical_snapshot)
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    source_view_values = _source_view_values(source_snapshot)
    comparison_values = _registration_comparison_values(
        historical=historical_snapshot,
        source=source_snapshot,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        allowed_modes=frozenset((0o600,)),
        minimum_bytes=1,
        maximum_bytes=128 * 1_024,
        phase="decision_candidate",
    )
    candidate_id = id(value)

    def candidate_lost(
        reference: weakref.ReferenceType[
            LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        ],
    ) -> None:
        if not _registry_process_matches_origin():
            return
        cleanup_error: BaseException | None = None
        transition_error: BaseException | None = None
        retry_error: BaseException | None = None
        try:
            try:
                cleanup_error = _discard_lost_registry_reference(
                    cast(dict[int, Any], _LOADED_RECEIPT_REGISTRY),
                    candidate_id,
                    tag="loaded-receipt-registration-v1",
                    length=23,
                    reference=reference,
                )
            except BaseException as error:
                transition_error = error
        finally:
            try:
                retry_error = _discard_lost_registry_reference(
                    cast(dict[int, Any], _LOADED_RECEIPT_REGISTRY),
                    candidate_id,
                    tag="loaded-receipt-registration-v1",
                    length=23,
                    reference=reference,
                )
            except BaseException as error:
                retry_error = error
        terminal = _preferred_registry_exceptions(
            transition_error,
            cleanup_error,
            retry_error,
        )
        if terminal is not None and reference() is not None:
            raise terminal

    reference = _new_exact_registry_reference(value, candidate_lost)
    registration: _LoadedReceiptRegistration = (
        "loaded-receipt-registration-v1",
        reference,
        owner_pid,
        owner_thread,
        historical_snapshot,
        source_snapshot,
        source_view_values,
        comparison_values,
        candidate_path,
        candidate_encoded,
        candidate_directory_identity,
        candidate_file_identity,
        start_operator_attested_approval_artifact,
        expected_graceful_stop_decision_v1_sha256,
        receipt_identity_values,
        receipt_encoded,
        receipt_sha256,
        artifact_directory,
        ignored_root,
        frozenset((0o600,)),
        1,
        128 * 1_024,
        "decision_candidate",
    )
    _registration_slot(registration, 1)
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    insertion_error: BaseException | None = None
    insertion_transition_error: BaseException | None = None
    insertion_cleanup_error: BaseException | None = None
    insertion_retry_error: BaseException | None = None
    try:
        try:
            with _held_loaded_receipt_registry_lock():
                if candidate_id in _LOADED_RECEIPT_REGISTRY:
                    raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                        "loaded_decision_artifact_receipt_invalid"
                    )
                _LOADED_RECEIPT_REGISTRY[candidate_id] = registration
        except BaseException as error:
            insertion_error = error
        finally:
            if insertion_error is not None:
                insertion_cleanup_error = _burn_loaded_receipt_registry_entry(
                    candidate_id,
                    registration=registration,
                )
    except BaseException as error:
        insertion_transition_error = error
    finally:
        if insertion_error is not None or insertion_transition_error is not None:
            insertion_retry_error = _burn_loaded_receipt_registry_entry(
                candidate_id,
                registration=registration,
            )
    insertion_terminal = _preferred_registry_exceptions(
        insertion_error,
        insertion_transition_error,
        insertion_cleanup_error,
        insertion_retry_error,
    )
    if insertion_terminal is not None:
        raise insertion_terminal

    validation_error: BaseException | None = None
    validation_transition_error: BaseException | None = None
    validation_cleanup_error: BaseException | None = None
    validation_retry_error: BaseException | None = None
    try:
        try:
            if not _registration_matches_live(value, registration):
                raise ValueError
        except BaseException as error:
            validation_error = error
        finally:
            if validation_error is not None:
                validation_cleanup_error = _burn_loaded_receipt_targets(((value, registration),))
    except BaseException as error:
        validation_transition_error = error
    finally:
        if validation_error is not None or validation_transition_error is not None:
            validation_retry_error = _burn_loaded_receipt_targets(((value, registration),))
    validation_terminal = _preferred_registry_exceptions(
        validation_error,
        validation_transition_error,
        validation_cleanup_error,
        validation_retry_error,
    )
    if validation_terminal is not None:
        raise validation_terminal
    return registration


def _revoke_loaded_receipt(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    registration: _LoadedReceiptRegistration,
) -> BaseException | None:
    if not _registry_process_matches_origin():
        return None
    del registration
    return _burn_loaded_receipt_registry_entry(id(value))


def _revoke_loaded_receipt_if_registered(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> BaseException | None:
    if not _registry_process_matches_origin():
        return None
    candidate_id = id(value)
    first_error: BaseException | None = None
    for _ in range(16):
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
            continue
        if current is None:
            return first_error
        cleanup_error = _burn_loaded_receipt_registry_entry(candidate_id)
        first_error = _preferred_registry_exception(first_error, cleanup_error)
        try:
            with _held_loaded_receipt_registry_lock():
                remaining = cast(
                    object | None,
                    _LOADED_RECEIPT_REGISTRY.get(candidate_id),
                )
                if remaining is None:
                    return first_error
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
    return _preferred_registry_exception(
        first_error,
        RuntimeError("loaded receipt registry entry could not be revoked"),
    )


def _burn_loaded_receipt_targets(
    targets: tuple[
        tuple[
            LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
            _LoadedReceiptRegistration | None,
        ],
        ...,
    ],
) -> BaseException | None:
    """Best-effort exact burn for every target while preserving async priority."""

    first_error: BaseException | None = None
    for value, registration in targets:
        try:
            observed = (
                _revoke_loaded_receipt(value, registration)
                if registration is not None
                else _revoke_loaded_receipt_if_registered(value)
            )
        except BaseException as error:
            observed = error
        first_error = _preferred_registry_exception(first_error, observed)
    return first_error


def _require_loaded_receipt_registration(
    value: object,
) -> _LoadedReceiptRegistration:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    owner_pid = _registry_origin_pid()
    owner_thread = _registry_current_thread()
    if type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    registration: _LoadedReceiptRegistration | None = None
    valid = False
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _LOADED_RECEIPT_REGISTRY.get(id(value)),
                )
                try:
                    typed_current = cast(_LoadedReceiptRegistration, current)
                    current_reference = _registration_slot(
                        typed_current,
                        1,
                    )
                    current_owner_pid = _registration_slot(
                        typed_current,
                        2,
                    )
                    current_owner_thread = _registration_slot(
                        typed_current,
                        3,
                    )
                    valid = (
                        _is_exact_registry_reference(current_reference)
                        and cast(weakref.ReferenceType[object], current_reference)() is value
                        and current_owner_pid == owner_pid
                        and current_owner_thread is owner_thread
                    )
                except (TypeError, ValueError):
                    valid = False
                if valid:
                    registration = typed_current
                elif current is not None:
                    _LOADED_RECEIPT_REGISTRY.pop(id(value), None)
                    if _LOADED_RECEIPT_REGISTRY.get(id(value)) is not None:
                        raise RuntimeError("loaded receipt registry entry could not be revoked")
        except BaseException as error:
            body_error = error
        finally:
            if body_error is not None or not valid:
                cleanup_error = _burn_loaded_receipt_targets(((value, None),))
    except BaseException as error:
        transition_error = error
    finally:
        if body_error is not None or transition_error is not None or not valid:
            retry_error = _burn_loaded_receipt_targets(((value, None),))
    terminal = _preferred_registry_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if not valid or registration is None:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    return registration


def _consume_loaded_receipt_registration(
    value: object,
) -> _LoadedReceiptRegistration:
    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    owner_pid = _registry_origin_pid()
    owner_thread = _registry_current_thread()
    if type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    exact = value
    registration: _LoadedReceiptRegistration | None = None
    valid = False
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            with _held_loaded_receipt_registry_lock():
                current = cast(
                    object | None,
                    _LOADED_RECEIPT_REGISTRY.get(id(exact)),
                )
                try:
                    typed_current = cast(_LoadedReceiptRegistration, current)
                    current_reference = _registration_slot(typed_current, 1)
                    current_owner_pid = _registration_slot(typed_current, 2)
                    current_owner_thread = _registration_slot(typed_current, 3)
                    valid = (
                        _is_exact_registry_reference(current_reference)
                        and cast(weakref.ReferenceType[object], current_reference)() is exact
                        and current_owner_pid == owner_pid
                        and current_owner_thread is owner_thread
                    )
                except (TypeError, ValueError):
                    valid = False
                if valid:
                    registration = typed_current
                if current is not None:
                    _LOADED_RECEIPT_REGISTRY.pop(id(exact), None)
                    if _LOADED_RECEIPT_REGISTRY.get(id(exact)) is not None:
                        raise RuntimeError("loaded receipt registry entry could not be consumed")
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _burn_loaded_receipt_targets(((exact, None),))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _burn_loaded_receipt_targets(((exact, None),))
    terminal = _preferred_registry_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if not valid or registration is None or not _registration_matches_live(exact, registration):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    return registration


def _registration_matches_live(
    value: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    registration: _LoadedReceiptRegistration,
) -> bool:
    try:
        reference = _registration_slot(registration, 1)
        owner_pid = _registration_slot(registration, 2)
        owner_thread = _registration_slot(registration, 3)
        historical = cast(
            _HistoricalStartFileSnapshot,
            _registration_slot(registration, 4),
        )
        snapshot = cast(
            _LoadedReceiptSourceSnapshot,
            _registration_slot(registration, 5),
        )
        candidate_path = cast(str, _source_slot(snapshot, 1))
        candidate_encoded = cast(bytes, _source_slot(snapshot, 2))
        candidate_directory_identity = cast(
            tuple[int, int],
            _source_slot(snapshot, 3),
        )
        candidate_file_identity = cast(
            _StatIdentity,
            _source_slot(snapshot, 4),
        )
        source_view_values = cast(
            tuple[object, ...],
            _registration_slot(registration, 6),
        )
        candidate_allowed_modes = cast(
            frozenset[int],
            _registration_slot(registration, 19),
        )
        candidate_minimum_bytes = cast(
            int,
            _registration_slot(registration, 20),
        )
        candidate_maximum_bytes = cast(
            int,
            _registration_slot(registration, 21),
        )
        candidate_phase = cast(
            str,
            _registration_slot(registration, 22),
        )
        return not (
            type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or not _registry_process_matches_origin()
            or owner_pid != _registry_origin_pid()
            or owner_thread is not _registry_current_thread()
            or cast(weakref.ReferenceType[object], reference)() is not value
            or source_view_values != _source_view_values(snapshot)
            or _build_loaded_receipt_source_snapshot(
                binding=_make_external_binding(
                    path=candidate_path,
                    encoded=candidate_encoded,
                    directory_identity=candidate_directory_identity,
                    file_identity=candidate_file_identity,
                    allowed_modes=candidate_allowed_modes,
                    minimum_bytes=candidate_minimum_bytes,
                    maximum_bytes=candidate_maximum_bytes,
                    phase=candidate_phase,
                ),
                historical=historical,
            )
            != snapshot
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _loaded_receipt_fact(value: object) -> bool:
    if type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    value.__post_init__()
    return True


def _loaded_receipt_non_authority(value: object) -> bool:
    if type(value) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    value.__post_init__()
    return False


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False, eq=False)
class LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    """Non-authorizing view; exact source authority remains in private snapshots."""

    artifact_path: Path
    encoded: bytes = field(repr=False)
    directory_identity: tuple[int, int] = field(repr=False)
    file_identity: _StatIdentity = field(repr=False)
    receipt_encoded: bytes = field(repr=False)
    receipt_sha256: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        artifact_path: Path,
        encoded: bytes,
        directory_identity: tuple[int, int],
        file_identity: _StatIdentity,
        receipt_encoded: bytes,
        receipt_sha256: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or _construction_capability is not _LOADED_RECEIPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "loaded_decision_artifact_receipt_invalid"
            )
        values = {
            "artifact_path": artifact_path,
            "encoded": encoded,
            "directory_identity": directory_identity,
            "file_identity": file_identity,
            "receipt_encoded": receipt_encoded,
            "receipt_sha256": receipt_sha256,
        }
        for name, item in values.items():
            object.__setattr__(self, name, item)
        try:
            sealed_fields = _loaded_receipt_seal_values(self)
            object.__setattr__(self, "_sealed_fields", sealed_fields)
            if _loaded_receipt_seal_values(self) != sealed_fields:
                raise ValueError
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "loaded_decision_artifact_receipt_invalid"
            ) from None

    def __post_init__(self) -> None:
        registration: _LoadedReceiptRegistration | None = None
        body_error: BaseException | None = None
        transition_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        retry_error: BaseException | None = None
        try:
            try:
                registration = _require_loaded_receipt_registration(self)
                if not _registration_matches_live(self, registration):
                    raise ValueError
                snapshot = cast(
                    _LoadedReceiptSourceSnapshot,
                    _registration_slot(registration, 5),
                )
                historical = cast(
                    _HistoricalStartFileSnapshot,
                    _registration_slot(registration, 4),
                )
                registration_artifact_path = cast(
                    str,
                    _registration_slot(registration, 8),
                )
                registration_encoded = cast(
                    bytes,
                    _registration_slot(registration, 9),
                )
                registration_directory_identity = cast(
                    tuple[int, int],
                    _registration_slot(registration, 10),
                )
                registration_file_identity = cast(
                    _StatIdentity,
                    _registration_slot(registration, 11),
                )
                expected_decision_sha256 = cast(
                    str,
                    _registration_slot(registration, 13),
                )
                receipt_identity_values = cast(
                    tuple[str, ...],
                    _registration_slot(registration, 14),
                )
                registration_receipt_encoded = cast(
                    bytes,
                    _registration_slot(registration, 15),
                )
                registration_receipt_sha256 = cast(
                    str,
                    _registration_slot(registration, 16),
                )
                artifact_directory_string = cast(
                    str,
                    _registration_slot(registration, 17),
                )
                ignored_root_string = cast(
                    str,
                    _registration_slot(registration, 18),
                )
                candidate_allowed_modes = cast(
                    frozenset[int],
                    _registration_slot(registration, 19),
                )
                candidate_minimum_bytes = cast(
                    int,
                    _registration_slot(registration, 20),
                )
                candidate_maximum_bytes = cast(
                    int,
                    _registration_slot(registration, 21),
                )
                candidate_phase = cast(
                    str,
                    _registration_slot(registration, 22),
                )
                candidate_path = cast(str, _source_slot(snapshot, 1))
                candidate_encoded = cast(
                    bytes,
                    _source_slot(snapshot, 2),
                )
                candidate_directory_identity = cast(
                    tuple[int, int],
                    _source_slot(snapshot, 3),
                )
                candidate_file_identity = cast(
                    _StatIdentity,
                    _source_slot(snapshot, 4),
                )
                source_receipt_encoded = cast(
                    bytes,
                    _source_slot(snapshot, 20),
                )
                source_receipt_sha256 = cast(
                    str,
                    _source_slot(snapshot, 21),
                )
                source_receipt_identity_values = cast(
                    tuple[str, ...],
                    _source_slot(snapshot, 19),
                )
                if (
                    _loaded_receipt_seal_values(self) != getattr(self, "_sealed_fields", None)
                    or _captured_path_string(self.artifact_path) != registration_artifact_path
                    or self.encoded != registration_encoded
                    or self.directory_identity != registration_directory_identity
                    or self.file_identity != registration_file_identity
                    or self.receipt_encoded != registration_receipt_encoded
                    or self.receipt_sha256 != registration_receipt_sha256
                    or type(registration_artifact_path) is not str
                    or not _captured_path_isabs(registration_artifact_path)
                    or _captured_path_abspath(registration_artifact_path)
                    != registration_artifact_path
                    or _captured_path_normpath(registration_artifact_path)
                    != registration_artifact_path
                    or _captured_path_basename(registration_artifact_path)
                    != _captured_decision_candidate_file_name(expected_decision_sha256)
                    or type(registration_encoded) is not bytes
                    or not registration_encoded
                    or len(registration_encoded) > 128 * 1_024
                    or _captured_sha256_hexdigest(registration_encoded) != expected_decision_sha256
                    or registration_artifact_path != candidate_path
                    or registration_encoded != candidate_encoded
                    or registration_directory_identity != candidate_directory_identity
                    or registration_file_identity != candidate_file_identity
                    or not _captured_path_isabs(artifact_directory_string)
                    or _captured_path_abspath(artifact_directory_string)
                    != artifact_directory_string
                    or _captured_path_normpath(artifact_directory_string)
                    != artifact_directory_string
                    or not _captured_path_isabs(ignored_root_string)
                    or _captured_path_abspath(ignored_root_string) != ignored_root_string
                    or _captured_path_normpath(ignored_root_string) != ignored_root_string
                    or artifact_directory_string
                    != _captured_path_join(ignored_root_string, "trusted-time")
                    or candidate_allowed_modes != frozenset((0o600,))
                    or candidate_minimum_bytes != 1
                    or candidate_maximum_bytes != 128 * 1_024
                    or candidate_phase != "decision_candidate"
                    or not _exact_int_tuple(registration_directory_identity, length=2)
                    or not _exact_int_tuple(registration_file_identity, length=9)
                    or not stat.S_ISREG(registration_file_identity[2])
                    or stat.S_IMODE(registration_file_identity[2]) != 0o600
                    or registration_file_identity[3] != os.geteuid()
                    or registration_file_identity[5] != 1
                    or registration_file_identity[6] != len(registration_encoded)
                    or type(registration_receipt_encoded) is not bytes
                    or registration_receipt_encoded != source_receipt_encoded
                    or registration_receipt_sha256 != source_receipt_sha256
                    or receipt_identity_values != source_receipt_identity_values
                    or _captured_receipt_bytes(receipt_identity_values)
                    != registration_receipt_encoded
                    or not _is_sha256(registration_receipt_sha256)
                    or _captured_sha256_hexdigest(registration_receipt_encoded)
                    != registration_receipt_sha256
                ):
                    raise ValueError
                rebuilt_snapshot = _build_loaded_receipt_source_snapshot(
                    binding=_make_external_binding(
                        path=candidate_path,
                        encoded=candidate_encoded,
                        directory_identity=candidate_directory_identity,
                        file_identity=candidate_file_identity,
                        allowed_modes=candidate_allowed_modes,
                        minimum_bytes=candidate_minimum_bytes,
                        maximum_bytes=candidate_maximum_bytes,
                        phase=candidate_phase,
                    ),
                    historical=historical,
                )
                if (
                    rebuilt_snapshot != snapshot
                    or _captured_receipt_bytes(
                        cast(
                            tuple[str, ...],
                            _source_slot(
                                rebuilt_snapshot,
                                19,
                            ),
                        )
                    )
                    != registration_receipt_encoded
                    or _require_loaded_receipt_registration(self) is not registration
                    or not _registration_matches_live(self, registration)
                ):
                    raise ValueError
            except BaseException as error:
                body_error = error
            finally:
                if body_error is not None:
                    cleanup_error = _burn_loaded_receipt_targets(((self, registration),))
        except BaseException as error:
            transition_error = error
        finally:
            if body_error is not None or transition_error is not None:
                retry_error = _burn_loaded_receipt_targets(((self, registration),))
        terminal = _preferred_registry_exceptions(
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
                TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
            ):
                raise terminal
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "loaded_decision_artifact_receipt_invalid"
            ) from None

    decision_artifact_receipt_authenticated = property(_loaded_receipt_fact)
    decision_candidate_retention_revalidated = property(_loaded_receipt_fact)
    historical_start_chain_authenticated = property(_loaded_receipt_fact)
    verification_only = property(_loaded_receipt_fact)
    currentness_qualified = property(_loaded_receipt_non_authority)
    freshness_qualified = property(_loaded_receipt_non_authority)
    single_use_qualified = property(_loaded_receipt_non_authority)
    stop_admission_qualified = property(_loaded_receipt_non_authority)
    stop_attempt_slot_reserved = property(_loaded_receipt_non_authority)
    stop_effect_authorized = property(_loaded_receipt_non_authority)
    stop_operator_signature_authenticated = property(_loaded_receipt_non_authority)
    stop_outcome_or_recovery_available = property(_loaded_receipt_non_authority)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_cannot_be_copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_cannot_be_copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_cannot_be_serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_cannot_be_serialized"
        )


for _authority_field in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
    setattr(
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        _authority_field,
        property(_loaded_receipt_non_authority),
    )


@dataclass(frozen=True, slots=True, eq=False)
class _ConsumedLoadedDecisionArtifactReceiptSnapshot:
    """Private source-derived handoff from one consuming revalidation."""

    loaded_identity: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    consumer_identity: object
    owner_pid: int
    owner_thread: threading.Thread
    historical_snapshot: _HistoricalStartFileSnapshot
    source_snapshot: _LoadedReceiptSourceSnapshot
    artifact_directory: str
    ignored_root: str
    receipt_identity_values: tuple[str, ...]
    receipt_encoded: bytes
    receipt_sha256: str
    _construction_capability: object = field(repr=False, compare=False)


def _require_consumed_loaded_decision_artifact_receipt_snapshot(
    value: object,
    *,
    loaded_identity: object,
    consumer_identity: object,
) -> _ConsumedLoadedDecisionArtifactReceiptSnapshot:
    """Validate one exact private handoff without reading the loaded heap view."""

    try:
        if (
            type(value) is not _ConsumedLoadedDecisionArtifactReceiptSnapshot
            or type(loaded_identity)
            is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or value.loaded_identity is not loaded_identity
            or value.consumer_identity is not consumer_identity
            or consumer_identity is None
            or value._construction_capability is not _CONSUMED_LOADED_RECEIPT_SNAPSHOT_CAPABILITY
            or not _registry_process_matches_origin()
            or value.owner_pid != _registry_origin_pid()
            or value.owner_thread is not _registry_current_thread()
            or type(value.artifact_directory) is not str
            or type(value.ignored_root) is not str
            or value.artifact_directory != _captured_path_join(value.ignored_root, "trusted-time")
            or type(value.receipt_identity_values) is not tuple
            or len(value.receipt_identity_values) != 15
            or any(type(item) is not str for item in value.receipt_identity_values)
            or type(value.receipt_encoded) is not bytes
            or not _is_sha256(value.receipt_sha256)
        ):
            raise ValueError
        _historical_slot(value.historical_snapshot, 1)
        _source_slot(value.source_snapshot, 1)
        if (
            value.receipt_identity_values != _source_slot(value.source_snapshot, 19)
            or value.receipt_encoded != _source_slot(value.source_snapshot, 20)
            or value.receipt_sha256 != _source_slot(value.source_snapshot, 21)
            or _captured_receipt_bytes(value.receipt_identity_values) != value.receipt_encoded
            or _captured_sha256_hexdigest(value.receipt_encoded) != value.receipt_sha256
        ):
            raise ValueError
        return value
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        ) from None


def _same_loaded_receipt(
    left: object,
    right: object,
) -> bool:
    if (
        type(left) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(right) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ):
        return False
    left_registration: _LoadedReceiptRegistration | None = None
    right_registration: _LoadedReceiptRegistration | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    same = False
    burn_on_completion = False
    try:
        try:
            left_registration = _require_loaded_receipt_registration(left)
            right_registration = _require_loaded_receipt_registration(right)
            same = (
                _registration_matches_live(left, left_registration)
                and _registration_matches_live(right, right_registration)
                and _registration_slot(left_registration, 7)
                == _registration_slot(right_registration, 7)
                and _registration_slot(
                    left_registration,
                    14,
                )
                == _registration_slot(
                    right_registration,
                    14,
                )
                and _registration_slot(left_registration, 15)
                == _registration_slot(right_registration, 15)
                and _registration_slot(left_registration, 16)
                == _registration_slot(right_registration, 16)
            )
            burn_on_completion = not same
        except BaseException as error:
            body_error = error
        finally:
            if body_error is not None or burn_on_completion:
                cleanup_error = _burn_loaded_receipt_targets(
                    (
                        (left, left_registration),
                        (right, right_registration),
                    )
                )
    except BaseException as error:
        transition_error = error
    finally:
        if body_error is not None or transition_error is not None or burn_on_completion:
            retry_error = _burn_loaded_receipt_targets(
                (
                    (left, left_registration),
                    (right, right_registration),
                )
            )
    terminal = _preferred_registry_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        return False
    return same


def load_post_enrollment_graceful_stop_decision_artifact_receipt(
    *,
    graceful_stop_decision_v1_artifact: Path,
    start_operator_attested_approval_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
    artifact_directory: Path,
    ignored_root: Path,
) -> LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    """Return an exact but inert receipt pending explicit authentication."""

    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        )
    try:
        if type(graceful_stop_decision_v1_artifact) is not type(Path()) or type(
            start_operator_attested_approval_artifact
        ) is not type(Path()):
            raise ValueError
        captured_candidate_path = _captured_path_string(graceful_stop_decision_v1_artifact)
        captured_start_artifact = _captured_path_string(start_operator_attested_approval_artifact)
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        ) from None
    reviewed_decision_sha256 = _require_expected_sha256(
        expected_graceful_stop_decision_v1_sha256,
        field_name="graceful_stop_decision_v1",
    )
    exact_artifact_directory, exact_ignored_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    loaded: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt | None = None
    pending_registration: _PendingLoadedReceiptRegistration | None = None
    cleanup_error: BaseException | None = None
    cleanup_transition_error: BaseException | None = None
    cleanup_retry_error: BaseException | None = None
    try:
        exact_start_artifact = _audited_fs._absolute_path(
            Path(captured_start_artifact),
            reason_code="start_operator_attested_approval_artifact_path_invalid",
        )
        if exact_start_artifact != captured_start_artifact:
            raise ValueError
        binding, _ = _read_decision_candidate_binding(
            graceful_stop_decision_v1_artifact=captured_candidate_path,
            expected_graceful_stop_decision_v1_sha256=reviewed_decision_sha256,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        if cast(str, _external_binding_value(binding, 1)) != captured_candidate_path:
            raise ValueError
        chain, historical_snapshot = _load_historical_start_chain(
            start_operator_attested_approval_artifact=exact_start_artifact,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        if not _historical_invocation_binding_matches(
            historical_snapshot,
            start_artifact=exact_start_artifact,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        ):
            raise ValueError
        source_snapshot = _build_loaded_receipt_source_snapshot(
            binding=binding,
            historical=historical_snapshot,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if (
            _build_loaded_receipt_source_snapshot(
                binding=binding,
                historical=historical_snapshot,
            )
            != source_snapshot
        ):
            raise ValueError
        source_receipt_encoded = cast(
            bytes,
            _source_slot(source_snapshot, 20),
        )
        source_receipt_sha256 = cast(
            str,
            _source_slot(source_snapshot, 21),
        )
        source_candidate_path = cast(
            str,
            _source_slot(source_snapshot, 1),
        )
        source_candidate_encoded = cast(
            bytes,
            _source_slot(source_snapshot, 2),
        )
        source_candidate_directory_identity = cast(
            tuple[int, int],
            _source_slot(source_snapshot, 3),
        )
        source_candidate_file_identity = cast(
            _StatIdentity,
            _source_slot(source_snapshot, 4),
        )
        loaded = LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
            artifact_path=Path(source_candidate_path),
            encoded=source_candidate_encoded,
            directory_identity=source_candidate_directory_identity,
            file_identity=source_candidate_file_identity,
            receipt_encoded=source_receipt_encoded,
            receipt_sha256=source_receipt_sha256,
            _construction_capability=_LOADED_RECEIPT_CONSTRUCTION_CAPABILITY,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if (
            _build_loaded_receipt_source_snapshot(
                binding=binding,
                historical=historical_snapshot,
            )
            != source_snapshot
        ):
            raise ValueError
        pending_registration = _register_pending_loaded_receipt(
            loaded,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
            start_operator_attested_approval_artifact=exact_start_artifact,
            expected_graceful_stop_decision_v1_sha256=reviewed_decision_sha256,
            historical_snapshot=historical_snapshot,
            source_snapshot=source_snapshot,
        )
        return loaded
    except BaseException as error:
        if loaded is not None:
            try:
                try:
                    cleanup_error = _burn_pending_loaded_receipt_targets(
                        ((loaded, pending_registration),)
                    )
                except BaseException as observed_cleanup_error:
                    cleanup_transition_error = observed_cleanup_error
            finally:
                try:
                    cleanup_retry_error = _burn_pending_loaded_receipt_targets(
                        ((loaded, pending_registration),)
                    )
                except BaseException as observed_retry_error:
                    cleanup_retry_error = observed_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            cleanup_error,
            cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
        ):
            raise
        if isinstance(
            error,
            _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                error.reason_code
            ) from None
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        ) from None


def authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
    loaded: object,
    *,
    start_operator_attested_approval_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    """Freshly authenticate and activate an already-owned inert receipt wrapper."""

    if not _registry_process_matches_origin():
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        )
    if type(loaded) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    pending = _consume_pending_loaded_receipt(loaded)
    try:
        if type(start_operator_attested_approval_artifact) is not type(Path()):
            raise ValueError
        captured_start_artifact = _captured_path_string(start_operator_attested_approval_artifact)
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        ) from None
    reviewed_decision_sha256 = _require_expected_sha256(
        expected_graceful_stop_decision_v1_sha256,
        field_name="graceful_stop_decision_v1",
    )
    exact_artifact_directory, exact_ignored_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    exact_start_argument = _audited_fs._absolute_path(
        Path(captured_start_artifact),
        reason_code="start_operator_attested_approval_artifact_path_invalid",
    )
    if exact_start_argument != captured_start_artifact:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    pending_expected_decision_sha256 = cast(
        str,
        _pending_slot(pending, 8),
    )
    pending_artifact_directory = cast(
        str,
        _pending_slot(pending, 9),
    )
    pending_ignored_root = cast(str, _pending_slot(pending, 10))
    pending_start_artifact = cast(
        str,
        _pending_slot(pending, 7),
    )
    pending_historical = cast(
        _HistoricalStartFileSnapshot,
        _pending_slot(pending, 4),
    )
    pending_source = cast(
        _LoadedReceiptSourceSnapshot,
        _pending_slot(pending, 5),
    )
    pending_candidate_path = cast(
        str,
        _source_slot(pending_source, 1),
    )
    if (
        reviewed_decision_sha256 != pending_expected_decision_sha256
        or exact_artifact_directory != pending_artifact_directory
        or exact_ignored_root != pending_ignored_root
        or exact_start_argument != pending_start_artifact
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    bound_artifact_directory = pending_artifact_directory
    bound_ignored_root = pending_ignored_root
    bound_start_artifact = pending_start_artifact
    bound_decision_sha256 = pending_expected_decision_sha256
    registration: _LoadedReceiptRegistration | None = None
    cleanup_error: BaseException | None = None
    cleanup_transition_error: BaseException | None = None
    cleanup_retry_error: BaseException | None = None
    try:
        binding, _ = _read_decision_candidate_binding(
            graceful_stop_decision_v1_artifact=pending_candidate_path,
            expected_graceful_stop_decision_v1_sha256=bound_decision_sha256,
            artifact_directory=bound_artifact_directory,
            ignored_root=bound_ignored_root,
        )
        chain, historical_snapshot = _load_historical_start_chain(
            start_operator_attested_approval_artifact=bound_start_artifact,
            artifact_directory=bound_artifact_directory,
            ignored_root=bound_ignored_root,
        )
        if not _historical_invocation_binding_matches(
            historical_snapshot,
            start_artifact=bound_start_artifact,
            artifact_directory=bound_artifact_directory,
            ignored_root=bound_ignored_root,
        ):
            raise ValueError
        source_snapshot = _build_loaded_receipt_source_snapshot(
            binding=binding,
            historical=historical_snapshot,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=bound_artifact_directory,
            ignored_root=bound_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if (
            _build_loaded_receipt_source_snapshot(
                binding=binding,
                historical=historical_snapshot,
            )
            != source_snapshot
            or historical_snapshot != pending_historical
            or source_snapshot != pending_source
            or not _pending_loaded_receipt_matches_live(loaded, pending)
        ):
            raise ValueError
        registration = _register_loaded_receipt(
            loaded,
            artifact_directory=pending_artifact_directory,
            ignored_root=pending_ignored_root,
            start_operator_attested_approval_artifact=bound_start_artifact,
            expected_graceful_stop_decision_v1_sha256=bound_decision_sha256,
            historical_snapshot=historical_snapshot,
            source_snapshot=source_snapshot,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=bound_artifact_directory,
            ignored_root=bound_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if _require_loaded_receipt_registration(
            loaded
        ) is not registration or not _registration_matches_live(loaded, registration):
            raise ValueError
        return None
    except BaseException as error:
        try:
            try:
                cleanup_error = _burn_loaded_receipt_targets(((loaded, registration),))
            except BaseException as observed_cleanup_error:
                cleanup_transition_error = observed_cleanup_error
        finally:
            try:
                cleanup_retry_error = _burn_loaded_receipt_targets(((loaded, registration),))
            except BaseException as observed_retry_error:
                cleanup_retry_error = observed_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            cleanup_error,
            cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
        ):
            raise
        if isinstance(
            error,
            _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                error.reason_code
            ) from None
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        ) from None


def _consume_revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
    loaded: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
    consumer_identity: object,
) -> _ConsumedLoadedDecisionArtifactReceiptSnapshot:
    """Consume, revalidate, and return only a private immutable source snapshot."""

    if (
        type(loaded) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or consumer_identity is None
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    registration: _LoadedReceiptRegistration | None = None
    cleanup_error: BaseException | None = None
    cleanup_transition_error: BaseException | None = None
    cleanup_retry_error: BaseException | None = None
    try:
        registration = _consume_loaded_receipt_registration(loaded)
        exact_artifact_directory, exact_ignored_root = _exact_artifact_roots(
            artifact_directory,
            ignored_root=ignored_root,
        )
        registration_artifact_directory = cast(
            str,
            _registration_slot(registration, 17),
        )
        registration_ignored_root = cast(
            str,
            _registration_slot(registration, 18),
        )
        registration_artifact_path = cast(
            str,
            _registration_slot(registration, 8),
        )
        registration_expected_decision_sha256 = cast(
            str,
            _registration_slot(registration, 13),
        )
        registration_start_artifact = cast(
            str,
            _registration_slot(registration, 12),
        )
        registration_historical = cast(
            _HistoricalStartFileSnapshot,
            _registration_slot(registration, 4),
        )
        registration_source = cast(
            _LoadedReceiptSourceSnapshot,
            _registration_slot(registration, 5),
        )
        registration_encoded = cast(
            bytes,
            _registration_slot(registration, 9),
        )
        registration_directory_identity = cast(
            tuple[int, int],
            _registration_slot(registration, 10),
        )
        registration_file_identity = cast(
            _StatIdentity,
            _registration_slot(registration, 11),
        )
        registration_receipt_encoded = cast(
            bytes,
            _registration_slot(registration, 15),
        )
        registration_receipt_sha256 = cast(
            str,
            _registration_slot(registration, 16),
        )
        if (
            exact_artifact_directory != registration_artifact_directory
            or exact_ignored_root != registration_ignored_root
        ):
            raise ValueError
        binding, _ = _read_decision_candidate_binding(
            graceful_stop_decision_v1_artifact=registration_artifact_path,
            expected_graceful_stop_decision_v1_sha256=(registration_expected_decision_sha256),
            artifact_directory=registration_artifact_directory,
            ignored_root=registration_ignored_root,
        )
        chain, historical_snapshot = _load_historical_start_chain(
            start_operator_attested_approval_artifact=registration_start_artifact,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        if not _historical_invocation_binding_matches(
            historical_snapshot,
            start_artifact=registration_start_artifact,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        ):
            raise ValueError
        source_snapshot = _build_loaded_receipt_source_snapshot(
            binding=binding,
            historical=historical_snapshot,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if (
            historical_snapshot != registration_historical
            or source_snapshot != registration_source
            or cast(str, _external_binding_value(binding, 1)) != registration_artifact_path
            or cast(bytes, _external_binding_value(binding, 2)) != registration_encoded
            or cast(tuple[int, int], _external_binding_value(binding, 3))
            != registration_directory_identity
            or cast(_StatIdentity, _external_binding_value(binding, 4))
            != registration_file_identity
            or _captured_receipt_bytes(
                cast(
                    tuple[str, ...],
                    _source_slot(source_snapshot, 19),
                )
            )
            != registration_receipt_encoded
            or _source_slot(source_snapshot, 21) != registration_receipt_sha256
        ):
            raise ValueError
        receipt_identity_values = cast(
            tuple[str, ...],
            _source_slot(source_snapshot, 19),
        )
        receipt_encoded = cast(bytes, _source_slot(source_snapshot, 20))
        receipt_sha256 = cast(str, _source_slot(source_snapshot, 21))
        snapshot = _ConsumedLoadedDecisionArtifactReceiptSnapshot(
            loaded_identity=loaded,
            consumer_identity=consumer_identity,
            owner_pid=_registry_origin_pid(),
            owner_thread=_registry_current_thread(),
            historical_snapshot=historical_snapshot,
            source_snapshot=source_snapshot,
            artifact_directory=registration_artifact_directory,
            ignored_root=registration_ignored_root,
            receipt_identity_values=receipt_identity_values,
            receipt_encoded=receipt_encoded,
            receipt_sha256=receipt_sha256,
            _construction_capability=_CONSUMED_LOADED_RECEIPT_SNAPSHOT_CAPABILITY,
        )
        return _require_consumed_loaded_decision_artifact_receipt_snapshot(
            snapshot,
            loaded_identity=loaded,
            consumer_identity=consumer_identity,
        )
    except BaseException as error:
        try:
            try:
                cleanup_error = _burn_loaded_receipt_targets(((loaded, registration),))
            except BaseException as observed_cleanup_error:
                cleanup_transition_error = observed_cleanup_error
        finally:
            try:
                cleanup_retry_error = _burn_loaded_receipt_targets(((loaded, registration),))
            except BaseException as observed_retry_error:
                cleanup_retry_error = observed_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            cleanup_error,
            cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
        ):
            raise
        if isinstance(
            error,
            _audited_fs.TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        ):
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                error.reason_code
            ) from None
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        ) from None


def _authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge(  # noqa: E501
    loaded: object,
    *,
    start_operator_attested_approval_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
    artifact_directory: Path,
    ignored_root: Path,
    consumer_identity: object,
) -> _ConsumedLoadedDecisionArtifactReceiptSnapshot:
    """Own the pending-authentication and active-consumption bridge interval."""

    if (
        type(loaded) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or consumer_identity is None
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "loaded_decision_artifact_receipt_invalid"
        )
    pending_cleanup_error: BaseException | None = None
    active_cleanup_error: BaseException | None = None
    cleanup_transition_error: BaseException | None = None
    pending_retry_error: BaseException | None = None
    active_retry_error: BaseException | None = None
    try:
        authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
            expected_graceful_stop_decision_v1_sha256=(expected_graceful_stop_decision_v1_sha256),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return _consume_revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            consumer_identity=consumer_identity,
        )
    except BaseException as error:
        try:
            try:
                pending_cleanup_error = _burn_pending_loaded_receipt_targets(((loaded, None),))
                active_cleanup_error = _burn_loaded_receipt_targets(((loaded, None),))
            except BaseException as observed_cleanup_error:
                cleanup_transition_error = observed_cleanup_error
        finally:
            try:
                pending_retry_error = _burn_pending_loaded_receipt_targets(((loaded, None),))
            except BaseException as observed_pending_retry_error:
                pending_retry_error = observed_pending_retry_error
            try:
                active_retry_error = _burn_loaded_receipt_targets(((loaded, None),))
            except BaseException as observed_active_retry_error:
                active_retry_error = observed_active_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            pending_cleanup_error,
            active_cleanup_error,
            pending_retry_error,
            active_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
        ):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_artifact_receipt_unavailable"
        ) from None


def revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
    loaded: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    """Reload and compare the exact candidate, inode, and full historical chain."""

    if type(loaded) is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        return False
    exact_loaded = loaded
    cleanup_error: BaseException | None = None
    cleanup_transition_error: BaseException | None = None
    cleanup_retry_error: BaseException | None = None
    try:
        consumed_snapshot = (
            _consume_revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                exact_loaded,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
                consumer_identity=_PUBLIC_REVALIDATION_CONSUMER_IDENTITY,
            )
        )
        if type(consumed_snapshot) is not _ConsumedLoadedDecisionArtifactReceiptSnapshot:
            raise ValueError
        return True
    except BaseException as error:
        try:
            try:
                cleanup_error = _burn_loaded_receipt_targets(((exact_loaded, None),))
            except BaseException as observed_cleanup_error:
                cleanup_transition_error = observed_cleanup_error
        finally:
            try:
                cleanup_retry_error = _burn_loaded_receipt_targets(((exact_loaded, None),))
            except BaseException as observed_retry_error:
                cleanup_retry_error = observed_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            cleanup_error,
            cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        return False


def _prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot(
    *,
    graceful_stop_operation_id: str,
    start_operator_attested_approval_artifact: Path,
    decision_candidate_directory: Path,
    expected_controller_outcome_sha256: str,
    expected_durable_shutdown_locator_sha256: str,
    expected_start_execution_attempt_slot_sha256: str,
    expected_start_operator_attestation_envelope_sha256: str,
    expected_start_operation_id: str,
    expected_start_approval_sha256: str,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    _candidate_file_name: Callable[[str], str] = _decision_candidate_file_name,
    _join: Callable[..., str] = os.path.join,
    _receipt_bytes: Callable[[tuple[str, ...]], bytes] = (
        _canonical_receipt_bytes_from_identity_values
    ),
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> tuple[
    TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    tuple[str, ...],
    bytes,
]:
    """Publish one unqualified decision bound to exact historical start evidence."""

    try:
        if type(start_operator_attested_approval_artifact) is not type(Path()) or type(
            decision_candidate_directory
        ) is not type(Path()):
            raise ValueError
        captured_start_artifact = _captured_path_string(start_operator_attested_approval_artifact)
        captured_candidate_directory = _captured_path_string(decision_candidate_directory)
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_invalid"
        ) from None
    stop_operation_id = _require_graceful_stop_operation_id(graceful_stop_operation_id)
    start_operation_id = _require_expected_uuid4(
        expected_start_operation_id,
        field_name="start_operation_id",
    )
    if stop_operation_id == start_operation_id:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "graceful_stop_operation_id_conflicts_with_start"
        )
    reviewed_controller_outcome_sha256 = _require_expected_sha256(
        expected_controller_outcome_sha256,
        field_name="controller_outcome",
    )
    reviewed_locator_sha256 = _require_expected_sha256(
        expected_durable_shutdown_locator_sha256,
        field_name="durable_shutdown_locator",
    )
    reviewed_attempt_sha256 = _require_expected_sha256(
        expected_start_execution_attempt_slot_sha256,
        field_name="start_execution_attempt_slot",
    )
    reviewed_envelope_sha256 = _require_expected_sha256(
        expected_start_operator_attestation_envelope_sha256,
        field_name="start_operator_attestation_envelope",
    )
    reviewed_start_approval_sha256 = _require_expected_sha256(
        expected_start_approval_sha256,
        field_name="start_approval",
    )
    exact_artifact_directory, exact_ignored_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    exact_candidate_directory, candidate_directory_identity = _require_external_candidate_directory(
        captured_candidate_directory,
        artifact_directory=exact_artifact_directory,
        ignored_root=exact_ignored_root,
    )
    if exact_candidate_directory != captured_candidate_directory:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_directory_path_invalid"
        )
    exact_start_artifact = _audited_fs._absolute_path(
        Path(captured_start_artifact),
        reason_code="start_operator_attested_approval_artifact_path_invalid",
    )
    if exact_start_artifact != captured_start_artifact:
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "start_operator_attested_approval_artifact_path_invalid"
        )
    chain, historical_snapshot = _load_historical_start_chain(
        start_operator_attested_approval_artifact=exact_start_artifact,
        artifact_directory=exact_artifact_directory,
        ignored_root=exact_ignored_root,
    )
    if not _historical_invocation_binding_matches(
        historical_snapshot,
        start_artifact=exact_start_artifact,
        artifact_directory=exact_artifact_directory,
        ignored_root=exact_ignored_root,
    ):
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "historical_start_chain_invalid"
        )
    _require_historical_start_chain(
        historical_snapshot,
        expected_controller_outcome_sha256=reviewed_controller_outcome_sha256,
        expected_durable_shutdown_locator_sha256=reviewed_locator_sha256,
        expected_start_execution_attempt_slot_sha256=reviewed_attempt_sha256,
        expected_start_operator_attestation_envelope_sha256=reviewed_envelope_sha256,
        expected_start_operation_id=start_operation_id,
        expected_start_approval_sha256=reviewed_start_approval_sha256,
    )
    _revalidate_historical_start_chain(
        chain,
        historical_snapshot,
        artifact_directory=exact_artifact_directory,
        ignored_root=exact_ignored_root,
    )
    try:
        expected_candidate = _expected_decision_candidate_snapshot(
            historical_snapshot,
            decision_operation_id=stop_operation_id,
        )
        if (
            _expected_slot(expected_candidate, 4) != reviewed_controller_outcome_sha256
            or _expected_slot(expected_candidate, 5) != reviewed_locator_sha256
            or _expected_slot(expected_candidate, 6) != reviewed_attempt_sha256
            or _expected_slot(expected_candidate, 9) != reviewed_envelope_sha256
            or _expected_slot(expected_candidate, 8) != start_operation_id
            or _expected_slot(expected_candidate, 7) != reviewed_start_approval_sha256
        ):
            raise ValueError
        encoded = cast(
            bytes,
            _expected_slot(expected_candidate, 1),
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_invalid"
        ) from None
    decision_sha256 = _sha256(encoded).hexdigest()
    file_name = _candidate_file_name(decision_sha256)
    _revalidate_historical_start_chain(
        chain,
        historical_snapshot,
        artifact_directory=exact_artifact_directory,
        ignored_root=exact_ignored_root,
    )
    try:
        published_identity = _audited_fs._publish_candidate(
            directory=Path(exact_candidate_directory),
            file_name=file_name,
            encoded=encoded,
            maximum_bytes=128 * 1_024,
            phase="decision_candidate",
            expected_directory_identity=candidate_directory_identity,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_retention_unconfirmed"
        ) from error
    try:
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        binding, _ = _read_decision_candidate_binding(
            graceful_stop_decision_v1_artifact=_join(
                exact_candidate_directory,
                file_name,
            ),
            expected_graceful_stop_decision_v1_sha256=decision_sha256,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        source_snapshot = _build_loaded_receipt_source_snapshot(
            binding=binding,
            historical=historical_snapshot,
        )
        _revalidate_historical_start_chain(
            chain,
            historical_snapshot,
            artifact_directory=exact_artifact_directory,
            ignored_root=exact_ignored_root,
        )
        _revalidate_decision_candidate_binding(binding)
        if (
            cast(str, _external_binding_value(binding, 1))
            != _join(exact_candidate_directory, file_name)
            or cast(bytes, _external_binding_value(binding, 2)) != encoded
            or cast(tuple[int, int], _external_binding_value(binding, 3))
            != candidate_directory_identity
            or cast(_StatIdentity, _external_binding_value(binding, 4)) != published_identity
            or _source_slot(source_snapshot, 1) != cast(str, _external_binding_value(binding, 1))
            or _source_slot(source_snapshot, 2) != encoded
            or _source_slot(source_snapshot, 3) != candidate_directory_identity
            or _source_slot(source_snapshot, 4) != published_identity
            or _source_slot(source_snapshot, 18) != _expected_slot(expected_candidate, 2)
            or tuple.__getitem__(
                cast(
                    tuple[str, ...],
                    _source_slot(source_snapshot, 19),
                ),
                5,
            )
            != _expected_slot(expected_candidate, 3)
            or _build_loaded_receipt_source_snapshot(
                binding=binding,
                historical=historical_snapshot,
            )
            != source_snapshot
        ):
            raise ValueError
        source_receipt_identity_values = cast(
            tuple[str, ...],
            _source_slot(source_snapshot, 19),
        )
        source_receipt_encoded = cast(
            bytes,
            _source_slot(source_snapshot, 20),
        )
        if _receipt_bytes(source_receipt_identity_values) != source_receipt_encoded:
            raise ValueError
        receipt = _receipt_from_identity_values(source_receipt_identity_values)
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "decision_candidate_retention_unconfirmed"
        ) from error
    return (
        receipt,
        source_receipt_identity_values,
        source_receipt_encoded,
    )


def prepare_post_enrollment_graceful_stop_decision_candidate(
    *,
    graceful_stop_operation_id: str,
    start_operator_attested_approval_artifact: Path,
    decision_candidate_directory: Path,
    expected_controller_outcome_sha256: str,
    expected_durable_shutdown_locator_sha256: str,
    expected_start_execution_attempt_slot_sha256: str,
    expected_start_operator_attestation_envelope_sha256: str,
    expected_start_operation_id: str,
    expected_start_approval_sha256: str,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    """Publish one unqualified decision bound to exact historical start evidence."""

    receipt, _, _ = _prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot(
        graceful_stop_operation_id=graceful_stop_operation_id,
        start_operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
        decision_candidate_directory=decision_candidate_directory,
        expected_controller_outcome_sha256=expected_controller_outcome_sha256,
        expected_durable_shutdown_locator_sha256=(expected_durable_shutdown_locator_sha256),
        expected_start_execution_attempt_slot_sha256=(expected_start_execution_attempt_slot_sha256),
        expected_start_operator_attestation_envelope_sha256=(
            expected_start_operator_attestation_envelope_sha256
        ),
        expected_start_operation_id=expected_start_operation_id,
        expected_start_approval_sha256=expected_start_approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return receipt


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
            "command_arguments_invalid"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description="Prepare one unqualified historical graceful-stop decision candidate.",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(
        dest="operation",
        required=True,
        parser_class=_SafeArgumentParser,
    )
    prepare = subparsers.add_parser("prepare-decision", allow_abbrev=False)
    prepare.add_argument("--graceful-stop-operation-id", required=True)
    prepare.add_argument(
        "--start-operator-attested-approval-artifact",
        type=Path,
        required=True,
    )
    prepare.add_argument("--decision-candidate-directory", type=Path, required=True)
    prepare.add_argument("--expected-controller-outcome-sha256", required=True)
    prepare.add_argument("--expected-durable-shutdown-locator-sha256", required=True)
    prepare.add_argument("--expected-start-execution-attempt-slot-sha256", required=True)
    prepare.add_argument(
        "--expected-start-operator-attestation-envelope-sha256",
        required=True,
    )
    prepare.add_argument("--expected-start-operation-id", required=True)
    prepare.add_argument("--expected-start-approval-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the isolated binder and emit only one canonical public receipt."""

    try:
        if _CLI_REPOSITORY_ROOT is not None:
            try:
                _audited_fs._require_repository_first_party_sources(_CLI_REPOSITORY_ROOT)
            except RuntimeError:
                raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                    "first_party_source_attestation_failed"
                ) from None
        arguments = _parser().parse_args(argv)
        if arguments.operation != "prepare-decision":  # pragma: no cover
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "command_arguments_invalid"
            )
        _receipt, receipt_identity_values, receipt_encoded = (
            _prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot(
                graceful_stop_operation_id=arguments.graceful_stop_operation_id,
                start_operator_attested_approval_artifact=(
                    arguments.start_operator_attested_approval_artifact
                ),
                decision_candidate_directory=arguments.decision_candidate_directory,
                expected_controller_outcome_sha256=arguments.expected_controller_outcome_sha256,
                expected_durable_shutdown_locator_sha256=(
                    arguments.expected_durable_shutdown_locator_sha256
                ),
                expected_start_execution_attempt_slot_sha256=(
                    arguments.expected_start_execution_attempt_slot_sha256
                ),
                expected_start_operator_attestation_envelope_sha256=(
                    arguments.expected_start_operator_attestation_envelope_sha256
                ),
                expected_start_operation_id=arguments.expected_start_operation_id,
                expected_start_approval_sha256=arguments.expected_start_approval_sha256,
            )
        )
        if _captured_receipt_bytes(receipt_identity_values) != receipt_encoded:
            raise TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "decision_artifact_receipt_invalid"
            )
    except TrustedTimePostEnrollmentGracefulStopDecisionArtifactError as error:
        print(error.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(receipt_encoded.decode("ascii"))
    return 0


if __name__ == "__main__":  # pragma: no cover - isolated subprocess coverage.
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_FILE_SUFFIX",
    "ARTIFACT_RECEIPT_CONTRACT_VERSION",
    "ARTIFACT_WORKFLOW_SERVICE",
    "DECISION_CANDIDATE_FILE_PREFIX",
    "DECISION_CANDIDATE_PREPARED_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS",
    "LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
    "TrustedTimePostEnrollmentGracefulStopDecisionArtifactError",
    "TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt",
    "authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
    "load_post_enrollment_graceful_stop_decision_artifact_receipt",
    "main",
    "prepare_post_enrollment_graceful_stop_decision_candidate",
    "revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
]
