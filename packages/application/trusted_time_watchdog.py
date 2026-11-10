"""Pure, dormant state contract for an independent trusted-head watchdog.

The watchdog authenticates canonical remote checkpoint candidates and records
their process-local observation order.  It owns no provider client, database,
scheduler, process supervision, alert delivery, operational control, or trading
authority.  Raw candidate bytes can establish neither provider-terminal proof
nor current/stale runtime state, even when multiple signed successors are valid.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Never, SupportsIndex
from uuid import UUID

from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorEd25519Verifier,
    TrustedTimeHeadAnchorRecord,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.trusted_time import TRUSTED_TIME_POLICY

TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION = "phase6e-provider-neutral-trusted-head-watchdog-state-v1"
# Reserved in the authority identity for the later real provider-terminal
# observation adapter.  Dormant v1 never applies this threshold to caller-
# supplied candidate observation times.
TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS = 360_000_000_000

_MAX_MONOTONIC_NS = 9_223_372_036_854_775_807
_PROJECT_REF = re.compile(r"[a-z0-9]{20}\Z", re.ASCII)


class TrustedTimeWatchdogError(RuntimeError):
    """The preparatory watchdog contract was used incorrectly."""


class TrustedTimeWatchdogFatalError(TrustedTimeWatchdogError):
    """Authenticated watchdog state failed closed and is permanently fatal."""


class TrustedTimeWatchdogStatus(StrEnum):
    UNAVAILABLE = "unavailable"
    FATAL = "fatal"


class TrustedTimeWatchdogReason(StrEnum):
    STARTUP_NO_BASELINE = "startup_no_baseline"
    BASELINE_ONLY = "baseline_only"
    PROVIDER_TERMINAL_PROOF_ABSENT = "provider_terminal_proof_absent"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INVALID_CHECKPOINT = "invalid_checkpoint"
    SIGNATURE_INVALID = "signature_invalid"
    AUTHORITY_MISMATCH = "authority_mismatch"
    CHAIN_MISMATCH = "chain_mismatch"
    SEQUENCE_GAP = "sequence_gap"
    ROLLBACK = "rollback"
    FORK = "fork"
    MONOTONIC_REGRESSION = "monotonic_regression"


def _authority_is_never_granted(_: object) -> bool:
    return False


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedTimeWatchdogError(f"trusted-time watchdog {field_name} is invalid")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeWatchdogError(f"trusted-time watchdog {field_name} is invalid")
    return value


def _require_monotonic_ns(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_MONOTONIC_NS:
        raise TrustedTimeWatchdogError(f"trusted-time watchdog {field_name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class TrustedTimeWatchdogAuthority:
    """Exact nonsecret identities admitted by the dormant candidate evaluator."""

    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    signing_key_id: str
    signing_public_key_sha256: str
    host_id: str
    source_id: str
    source_authority_sha256: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.anchor_authority_sha256, "anchor-authority SHA-256"),
            (self.deployment_identity_sha256, "deployment-identity SHA-256"),
            (self.runtime_database_identity_sha256, "runtime-database identity SHA-256"),
            (self.anchor_project_identity_sha256, "anchor-project identity SHA-256"),
            (self.signing_public_key_sha256, "signing public-key SHA-256"),
            (self.source_authority_sha256, "source-authority SHA-256"),
        ):
            _require_sha256(value, field_name)
        if (
            type(self.anchor_project_ref) is not str
            or _PROJECT_REF.fullmatch(self.anchor_project_ref) is None
        ):
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog anchor-project reference is invalid"
            )
        if self.bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog bucket differs from the trusted-head contract"
            )
        try:
            principal = UUID(self.principal_id)
        except (TypeError, ValueError, AttributeError):
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog principal identity is invalid"
            ) from None
        if principal.int == 0 or str(principal) != self.principal_id:
            raise TrustedTimeWatchdogError("trusted-time watchdog principal identity is invalid")
        for value, field_name in (
            (self.signing_key_id, "signing-key identity"),
            (self.host_id, "host identity"),
            (self.source_id, "source identity"),
        ):
            _require_text(value, field_name)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION,
            "trusted_time_watchdog_authority",
            self.anchor_authority_sha256,
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.anchor_project_ref,
            self.bucket_name,
            self.principal_id,
            self.signing_key_id,
            self.signing_public_key_sha256,
            self.host_id,
            self.source_id,
            self.source_authority_sha256,
            TRUSTED_TIME_POLICY.semantic_sha256,
            TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
            TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
            TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS,
            "raw_checkpoint_candidates_never_establish_provider_terminal_proof",
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


_WATCHDOG_EVIDENCE_SEAL = object()
_FATAL_REASONS = frozenset(
    {
        TrustedTimeWatchdogReason.INVALID_CHECKPOINT,
        TrustedTimeWatchdogReason.SIGNATURE_INVALID,
        TrustedTimeWatchdogReason.AUTHORITY_MISMATCH,
        TrustedTimeWatchdogReason.CHAIN_MISMATCH,
        TrustedTimeWatchdogReason.SEQUENCE_GAP,
        TrustedTimeWatchdogReason.ROLLBACK,
        TrustedTimeWatchdogReason.FORK,
        TrustedTimeWatchdogReason.MONOTONIC_REGRESSION,
    }
)


def _watchdog_evidence_material(
    *,
    contract_version: str,
    authority_semantic_sha256: str,
    status: TrustedTimeWatchdogStatus,
    reason: TrustedTimeWatchdogReason,
    observed_at_monotonic_ns: int,
    anchor_sequence: int | None,
    anchor_sha256: str | None,
    current_host_head_sha256: str | None,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None,
    last_candidate_successor_observed_at_monotonic_ns: int | None,
    candidate_successor_observed: bool,
    provider_unavailable_latched: bool,
    fatal_error_latched: bool,
) -> tuple[object, ...]:
    return (
        contract_version,
        "trusted_time_watchdog_evidence",
        authority_semantic_sha256,
        status.value,
        reason.value,
        observed_at_monotonic_ns,
        anchor_sequence,
        anchor_sha256,
        current_host_head_sha256,
        None if checkpoint_reason is None else checkpoint_reason.value,
        last_candidate_successor_observed_at_monotonic_ns,
        candidate_successor_observed,
        provider_unavailable_latched,
        fatal_error_latched,
        "provider_terminal_proof_absent",
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimeWatchdogEvidence:
    """Factory-issued, non-authorizing projection of candidate observations.

    Raw signed records prove only candidate consistency.  A later real provider
    terminal-observation adapter must issue its own opaque proof before a future
    contract can define ``CURRENT`` semantics; this dormant contract deliberately
    contains no substitute issuer.
    """

    contract_version: str
    authority_semantic_sha256: str
    status: TrustedTimeWatchdogStatus
    reason: TrustedTimeWatchdogReason
    observed_at_monotonic_ns: int
    anchor_sequence: int | None
    anchor_sha256: str | None
    current_host_head_sha256: str | None
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None
    last_candidate_successor_observed_at_monotonic_ns: int | None
    candidate_successor_observed: bool
    provider_unavailable_latched: bool
    fatal_error_latched: bool
    semantic_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError("TrustedTimeWatchdogEvidence is issued by the watchdog core")

    def __post_init__(self) -> None:
        if self._seal is not _WATCHDOG_EVIDENCE_SEAL:
            raise TrustedTimeWatchdogError("trusted-time watchdog evidence is not factory-issued")
        if self.contract_version != TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION:
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog evidence contract version is invalid"
            )
        _require_sha256(
            self.authority_semantic_sha256,
            "evidence authority semantic SHA-256",
        )
        if type(self.status) is not TrustedTimeWatchdogStatus:
            raise TrustedTimeWatchdogError("trusted-time watchdog status is invalid")
        if type(self.reason) is not TrustedTimeWatchdogReason:
            raise TrustedTimeWatchdogError("trusted-time watchdog reason is invalid")
        observed = _require_monotonic_ns(
            self.observed_at_monotonic_ns,
            "evidence observation instant",
        )
        anchor_fields = (
            self.anchor_sequence,
            self.anchor_sha256,
            self.current_host_head_sha256,
            self.checkpoint_reason,
        )
        if self.anchor_sequence is None:
            if any(value is not None for value in anchor_fields):
                raise TrustedTimeWatchdogError(
                    "trusted-time watchdog evidence has a partial candidate baseline"
                )
        else:
            if type(self.anchor_sequence) is not int or self.anchor_sequence <= 0:
                raise TrustedTimeWatchdogError("trusted-time watchdog anchor sequence is invalid")
            _require_sha256(self.anchor_sha256, "anchor SHA-256")
            _require_sha256(self.current_host_head_sha256, "host-head SHA-256")
            if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
                raise TrustedTimeWatchdogError("trusted-time watchdog checkpoint reason is invalid")
        candidate_successor = self.last_candidate_successor_observed_at_monotonic_ns
        if candidate_successor is not None:
            exact_candidate_successor = _require_monotonic_ns(
                candidate_successor,
                "last candidate-successor observation instant",
            )
            if exact_candidate_successor > observed or self.anchor_sequence is None:
                raise TrustedTimeWatchdogError(
                    "trusted-time watchdog candidate-successor projection is invalid"
                )
        if type(
            self.candidate_successor_observed
        ) is not bool or self.candidate_successor_observed != (candidate_successor is not None):
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog candidate-successor projection is inconsistent"
            )
        for flag in (
            self.provider_unavailable_latched,
            self.fatal_error_latched,
        ):
            if type(flag) is not bool:
                raise TrustedTimeWatchdogError("trusted-time watchdog evidence flag is invalid")
        if self.fatal_error_latched:
            if (
                self.status is not TrustedTimeWatchdogStatus.FATAL
                or self.reason not in _FATAL_REASONS
            ):
                raise TrustedTimeWatchdogError(
                    "trusted-time watchdog fatal projection is inconsistent"
                )
        else:
            if self.status is not TrustedTimeWatchdogStatus.UNAVAILABLE:
                raise TrustedTimeWatchdogError(
                    "trusted-time watchdog candidate evidence must remain unavailable"
                )
            if self.provider_unavailable_latched:
                expected_reason = TrustedTimeWatchdogReason.PROVIDER_UNAVAILABLE
            elif self.anchor_sequence is None:
                expected_reason = TrustedTimeWatchdogReason.STARTUP_NO_BASELINE
            elif candidate_successor is None:
                expected_reason = TrustedTimeWatchdogReason.BASELINE_ONLY
            else:
                expected_reason = TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
            if self.reason is not expected_reason:
                raise TrustedTimeWatchdogError(
                    "trusted-time watchdog unavailable projection is inconsistent"
                )
        material = _watchdog_evidence_material(
            contract_version=self.contract_version,
            authority_semantic_sha256=self.authority_semantic_sha256,
            status=self.status,
            reason=self.reason,
            observed_at_monotonic_ns=self.observed_at_monotonic_ns,
            anchor_sequence=self.anchor_sequence,
            anchor_sha256=self.anchor_sha256,
            current_host_head_sha256=self.current_host_head_sha256,
            checkpoint_reason=self.checkpoint_reason,
            last_candidate_successor_observed_at_monotonic_ns=(
                self.last_candidate_successor_observed_at_monotonic_ns
            ),
            candidate_successor_observed=self.candidate_successor_observed,
            provider_unavailable_latched=self.provider_unavailable_latched,
            fatal_error_latched=self.fatal_error_latched,
        )
        _require_sha256(self.semantic_sha256, "evidence semantic SHA-256")
        if self.semantic_sha256 != _sha256(material):
            raise TrustedTimeWatchdogError(
                "trusted-time watchdog evidence semantic seal is invalid"
            )

    def __copy__(self) -> TrustedTimeWatchdogEvidence:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> TrustedTimeWatchdogEvidence:
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("trusted-time watchdog evidence cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[object, ...]:
        del protocol
        return self.__reduce__()

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


def _new_trusted_time_watchdog_evidence(
    *,
    authority_semantic_sha256: str,
    status: TrustedTimeWatchdogStatus,
    reason: TrustedTimeWatchdogReason,
    observed_at_monotonic_ns: int,
    anchor_sequence: int | None,
    anchor_sha256: str | None,
    current_host_head_sha256: str | None,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None,
    last_candidate_successor_observed_at_monotonic_ns: int | None,
    candidate_successor_observed: bool,
    provider_unavailable_latched: bool,
    fatal_error_latched: bool,
) -> TrustedTimeWatchdogEvidence:
    material = _watchdog_evidence_material(
        contract_version=TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION,
        authority_semantic_sha256=authority_semantic_sha256,
        status=status,
        reason=reason,
        observed_at_monotonic_ns=observed_at_monotonic_ns,
        anchor_sequence=anchor_sequence,
        anchor_sha256=anchor_sha256,
        current_host_head_sha256=current_host_head_sha256,
        checkpoint_reason=checkpoint_reason,
        last_candidate_successor_observed_at_monotonic_ns=(
            last_candidate_successor_observed_at_monotonic_ns
        ),
        candidate_successor_observed=candidate_successor_observed,
        provider_unavailable_latched=provider_unavailable_latched,
        fatal_error_latched=fatal_error_latched,
    )
    evidence = object.__new__(TrustedTimeWatchdogEvidence)
    for field_name, value in (
        ("contract_version", TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION),
        ("authority_semantic_sha256", authority_semantic_sha256),
        ("status", status),
        ("reason", reason),
        ("observed_at_monotonic_ns", observed_at_monotonic_ns),
        ("anchor_sequence", anchor_sequence),
        ("anchor_sha256", anchor_sha256),
        ("current_host_head_sha256", current_host_head_sha256),
        ("checkpoint_reason", checkpoint_reason),
        (
            "last_candidate_successor_observed_at_monotonic_ns",
            last_candidate_successor_observed_at_monotonic_ns,
        ),
        ("candidate_successor_observed", candidate_successor_observed),
        ("provider_unavailable_latched", provider_unavailable_latched),
        ("fatal_error_latched", fatal_error_latched),
        ("semantic_sha256", _sha256(material)),
        ("_seal", _WATCHDOG_EVIDENCE_SEAL),
    ):
        object.__setattr__(evidence, field_name, value)
    evidence.__post_init__()
    return evidence


class TrustedTimeWatchdogCore:
    """Authenticate raw remote candidates without qualifying provider state."""

    __slots__ = (
        "_authority",
        "_fatal",
        "_fatal_reason",
        "_last_candidate_successor_monotonic_ns",
        "_last_observed_monotonic_ns",
        "_provider_unavailable_latched",
        "_record",
        "_verifier",
    )

    def __init__(
        self,
        *,
        authority: TrustedTimeWatchdogAuthority,
        verifier: TrustedTimeHeadAnchorEd25519Verifier,
        started_at_monotonic_ns: int,
    ) -> None:
        if type(authority) is not TrustedTimeWatchdogAuthority:
            raise TrustedTimeWatchdogError("trusted-time watchdog authority must be exact")
        authority.__post_init__()
        verify = getattr(verifier, "verify_ed25519", None)
        if not callable(verify):
            raise TrustedTimeWatchdogError("trusted-time watchdog Ed25519 verifier is unavailable")
        self._authority = authority
        self._verifier = verifier
        self._last_observed_monotonic_ns = _require_monotonic_ns(
            started_at_monotonic_ns,
            "startup monotonic instant",
        )
        self._last_candidate_successor_monotonic_ns: int | None = None
        self._record: TrustedTimeHeadAnchorRecord | None = None
        self._provider_unavailable_latched = False
        self._fatal = False
        self._fatal_reason: TrustedTimeWatchdogReason | None = None

    def _latch_fatal(
        self,
        reason: TrustedTimeWatchdogReason,
        message: str,
    ) -> Never:
        if not self._fatal:
            self._fatal = True
            self._fatal_reason = reason
        raise TrustedTimeWatchdogFatalError(message)

    def _observe_monotonic(self, value: object) -> int:
        try:
            observed = _require_monotonic_ns(value, "observation monotonic instant")
        except TrustedTimeWatchdogError:
            self._latch_fatal(
                TrustedTimeWatchdogReason.MONOTONIC_REGRESSION,
                "trusted-time watchdog monotonic observation is invalid",
            )
        if observed < self._last_observed_monotonic_ns:
            self._latch_fatal(
                TrustedTimeWatchdogReason.MONOTONIC_REGRESSION,
                "trusted-time watchdog monotonic clock regressed",
            )
        self._last_observed_monotonic_ns = observed
        return observed

    def _require_not_fatal(self) -> None:
        if self._fatal:
            raise TrustedTimeWatchdogFatalError(
                "trusted-time watchdog integrity failure is latched"
            )

    def _verify_record(self, record: TrustedTimeHeadAnchorRecord) -> None:
        authority = self._authority
        observed_identity = (
            record.anchor_authority_sha256,
            record.deployment_identity_sha256,
            record.runtime_database_identity_sha256,
            record.anchor_project_identity_sha256,
            record.anchor_project_ref,
            record.bucket_name,
            record.principal_id,
            record.signing_key_id,
            record.signing_public_key_sha256,
            record.host_id,
            record.source_id,
            record.source_authority_sha256,
            record.policy_sha256,
            record.persistence_contract_version,
            record.checkpoint_interval_seconds,
        )
        expected_identity = (
            authority.anchor_authority_sha256,
            authority.deployment_identity_sha256,
            authority.runtime_database_identity_sha256,
            authority.anchor_project_identity_sha256,
            authority.anchor_project_ref,
            authority.bucket_name,
            authority.principal_id,
            authority.signing_key_id,
            authority.signing_public_key_sha256,
            authority.host_id,
            authority.source_id,
            authority.source_authority_sha256,
            TRUSTED_TIME_POLICY.semantic_sha256,
            TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
            TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        )
        if observed_identity != expected_identity:
            self._latch_fatal(
                TrustedTimeWatchdogReason.AUTHORITY_MISMATCH,
                "trusted-time watchdog checkpoint crossed admitted authority",
            )
        try:
            verified = self._verifier.verify_ed25519(
                signing_key_id=record.signing_key_id,
                signing_public_key_sha256=record.signing_public_key_sha256,
                payload=record.signed_payload,
                signature=bytes.fromhex(record.signature_ed25519),
            )
        except Exception:
            self._latch_fatal(
                TrustedTimeWatchdogReason.SIGNATURE_INVALID,
                "trusted-time watchdog checkpoint signature verification failed",
            )
        if type(verified) is not bool or not verified:
            self._latch_fatal(
                TrustedTimeWatchdogReason.SIGNATURE_INVALID,
                "trusted-time watchdog checkpoint signature is invalid",
            )

    def observe_checkpoint_candidate(
        self,
        payload: bytes,
        *,
        observed_at_monotonic_ns: int,
    ) -> TrustedTimeWatchdogEvidence:
        """Authenticate one caller-supplied candidate without qualifying it.

        Candidate bytes do not prove that a real provider-terminal observation
        occurred.  Their observation time therefore cannot establish current or
        stale runtime state, including for a signed ``clean_stop`` record.
        """

        self._require_not_fatal()
        observed = self._observe_monotonic(observed_at_monotonic_ns)
        try:
            record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
        except Exception:
            self._latch_fatal(
                TrustedTimeWatchdogReason.INVALID_CHECKPOINT,
                "trusted-time watchdog checkpoint bytes are invalid",
            )
        self._verify_record(record)
        previous = self._record
        if previous is None:
            self._record = record
            return self._evidence(observed)
        if record.byte_sha256 == previous.byte_sha256:
            return self._evidence(observed)
        if record.anchor_sequence == previous.anchor_sequence:
            self._latch_fatal(
                TrustedTimeWatchdogReason.FORK,
                "trusted-time watchdog observed a same-sequence fork",
            )
        if record.anchor_sequence < previous.anchor_sequence:
            self._latch_fatal(
                TrustedTimeWatchdogReason.ROLLBACK,
                "trusted-time watchdog observed a checkpoint rollback",
            )
        if record.anchor_sequence != previous.anchor_sequence + 1:
            self._latch_fatal(
                TrustedTimeWatchdogReason.SEQUENCE_GAP,
                "trusted-time watchdog observed a checkpoint sequence gap",
            )
        if (
            record.previous_anchor_sha256 != previous.byte_sha256
            or record.previous_anchored_host_head_sha256 != previous.current_host_head_sha256
            or record.current_host_head_sha256 == previous.current_host_head_sha256
        ):
            self._latch_fatal(
                TrustedTimeWatchdogReason.CHAIN_MISMATCH,
                "trusted-time watchdog checkpoint predecessor chain conflicts",
            )
        self._record = record
        self._last_candidate_successor_monotonic_ns = observed
        self._provider_unavailable_latched = False
        return self._evidence(observed)

    def observe_provider_unavailable(
        self,
        *,
        observed_at_monotonic_ns: int,
    ) -> TrustedTimeWatchdogEvidence:
        """Retain an explicit outage without changing candidate-successor time."""

        self._require_not_fatal()
        observed = self._observe_monotonic(observed_at_monotonic_ns)
        self._provider_unavailable_latched = True
        return self._evidence(observed)

    def evidence(
        self,
        *,
        observed_at_monotonic_ns: int,
    ) -> TrustedTimeWatchdogEvidence:
        """Project dormant candidate state at the caller's monotonic instant."""

        observed = self._observe_monotonic(observed_at_monotonic_ns)
        return self._evidence(observed)

    def _evidence(self, observed: int) -> TrustedTimeWatchdogEvidence:
        record = self._record
        candidate_successor = self._last_candidate_successor_monotonic_ns
        if self._fatal:
            status = TrustedTimeWatchdogStatus.FATAL
            reason = self._fatal_reason
            if reason is None:
                raise TrustedTimeWatchdogError("trusted-time watchdog fatal reason is unavailable")
        elif self._provider_unavailable_latched:
            status = TrustedTimeWatchdogStatus.UNAVAILABLE
            reason = TrustedTimeWatchdogReason.PROVIDER_UNAVAILABLE
        elif record is None:
            status = TrustedTimeWatchdogStatus.UNAVAILABLE
            reason = TrustedTimeWatchdogReason.STARTUP_NO_BASELINE
        elif candidate_successor is None:
            status = TrustedTimeWatchdogStatus.UNAVAILABLE
            reason = TrustedTimeWatchdogReason.BASELINE_ONLY
        else:
            status = TrustedTimeWatchdogStatus.UNAVAILABLE
            reason = TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
        return _new_trusted_time_watchdog_evidence(
            authority_semantic_sha256=self._authority.semantic_sha256,
            status=status,
            reason=reason,
            observed_at_monotonic_ns=observed,
            anchor_sequence=None if record is None else record.anchor_sequence,
            anchor_sha256=None if record is None else record.byte_sha256,
            current_host_head_sha256=(None if record is None else record.current_host_head_sha256),
            checkpoint_reason=None if record is None else record.checkpoint_reason,
            last_candidate_successor_observed_at_monotonic_ns=candidate_successor,
            candidate_successor_observed=candidate_successor is not None,
            provider_unavailable_latched=self._provider_unavailable_latched,
            fatal_error_latched=self._fatal,
        )


__all__ = [
    "TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION",
    "TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS",
    "TrustedTimeWatchdogAuthority",
    "TrustedTimeWatchdogCore",
    "TrustedTimeWatchdogError",
    "TrustedTimeWatchdogEvidence",
    "TrustedTimeWatchdogFatalError",
    "TrustedTimeWatchdogReason",
    "TrustedTimeWatchdogStatus",
]
