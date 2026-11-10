from __future__ import annotations

import copy
import hashlib
import pickle
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from packages.application import trusted_time_head_anchor as anchor_contract
from packages.application import trusted_time_watchdog as watchdog_contract
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
    AuthenticatedTrustedTimeHeadTransition,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorRecord,
)
from packages.application.trusted_time_monitor import TrustedTimeProbeStatus
from packages.application.trusted_time_watchdog import (
    TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION,
    TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS,
    TrustedTimeWatchdogAuthority,
    TrustedTimeWatchdogCore,
    TrustedTimeWatchdogError,
    TrustedTimeWatchdogEvidence,
    TrustedTimeWatchdogFatalError,
    TrustedTimeWatchdogReason,
    TrustedTimeWatchdogStatus,
)
from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeHealth,
    TrustedTimeReason,
)

BASE = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
DEPLOYMENT_IDENTITY = "1" * 64
RUNTIME_DATABASE_IDENTITY = "2" * 64
ANCHOR_PROJECT_IDENTITY = "3" * 64
ANCHOR_AUTHORITY = "4" * 64
SOURCE_AUTHORITY = "5" * 64
ANCHOR_PROJECT_REF = "abcdefghijklmnopqrst"
PRINCIPAL_ID = "11111111-1111-4111-8111-111111111111"
SIGNING_KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
SIGNING_PUBLIC_KEY_SHA256 = hashlib.sha256(b"watchdog-test-public-key").hexdigest()
HOST_ID = "local-paper-docker-primary-v1"
SOURCE_ID = "chrony-nts-cloudflare-system76-virginia-v2"
MONITOR_EPOCH_ID = "22222222-2222-4222-8222-222222222222"


def _digest(number: int) -> str:
    return f"{number:064x}"


@dataclass
class _DeterministicEd25519:
    verification_result: bool | int = True
    verification_error: bool = False

    @staticmethod
    def _signature(
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        return hashlib.sha512(
            b"watchdog-test-key"
            + signing_key_id.encode()
            + signing_public_key_sha256.encode()
            + payload
        ).digest()

    def sign_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        return self._signature(
            signing_key_id=signing_key_id,
            signing_public_key_sha256=signing_public_key_sha256,
            payload=payload,
        )

    def verify_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        if self.verification_error:
            raise RuntimeError("verification dependency failed")
        if type(self.verification_result) is not bool:
            return self.verification_result  # type: ignore[return-value]
        return self.verification_result and signature == self._signature(
            signing_key_id=signing_key_id,
            signing_public_key_sha256=signing_public_key_sha256,
            payload=payload,
        )


CRYPTO = _DeterministicEd25519()


def _authority(**changes: object) -> TrustedTimeWatchdogAuthority:
    values: dict[str, object] = {
        "anchor_authority_sha256": ANCHOR_AUTHORITY,
        "deployment_identity_sha256": DEPLOYMENT_IDENTITY,
        "runtime_database_identity_sha256": RUNTIME_DATABASE_IDENTITY,
        "anchor_project_identity_sha256": ANCHOR_PROJECT_IDENTITY,
        "anchor_project_ref": ANCHOR_PROJECT_REF,
        "bucket_name": TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        "principal_id": PRINCIPAL_ID,
        "signing_key_id": SIGNING_KEY_ID,
        "signing_public_key_sha256": SIGNING_PUBLIC_KEY_SHA256,
        "host_id": HOST_ID,
        "source_id": SOURCE_ID,
        "source_authority_sha256": SOURCE_AUTHORITY,
    }
    values.update(changes)
    return TrustedTimeWatchdogAuthority(**values)  # type: ignore[arg-type]


def _transition(
    evaluation_sequence: int,
    *,
    current_host_head_sha256: str | None = None,
) -> AuthenticatedTrustedTimeHeadTransition:
    if evaluation_sequence < 0:
        raise AssertionError
    evaluated = BASE + timedelta(seconds=evaluation_sequence)
    previous_head = None if evaluation_sequence == 0 else _digest(99 + evaluation_sequence)
    current_head = current_host_head_sha256 or _digest(100 + evaluation_sequence)
    evaluation_id = (
        None
        if evaluation_sequence == 0
        else f"{evaluation_sequence:08x}-1111-4111-8111-111111111111"
    )
    return AuthenticatedTrustedTimeHeadTransition(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=PRINCIPAL_ID,
        head_authenticated_at_utc=evaluated,
        host_id=HOST_ID,
        source_id=SOURCE_ID,
        source_authority_sha256=SOURCE_AUTHORITY,
        policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
        persistence_contract_version=TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
        epoch_sequence=1,
        monitor_epoch_id=MONITOR_EPOCH_ID,
        epoch_sha256=_digest(10),
        evaluation_sequence=evaluation_sequence,
        evaluation_id=evaluation_id,
        evaluation_record_sha256=(
            None if evaluation_sequence == 0 else _digest(20 + evaluation_sequence)
        ),
        state_sha256=None if evaluation_sequence == 0 else _digest(30 + evaluation_sequence),
        probe_status=(None if evaluation_sequence == 0 else TrustedTimeProbeStatus.RECORDED),
        health=None if evaluation_sequence == 0 else TrustedTimeHealth.HEALTHY,
        reason=None if evaluation_sequence == 0 else TrustedTimeReason.WITHIN_LIMIT,
        hard_failure_latched=None if evaluation_sequence == 0 else False,
        clock_recovery_qualified=None if evaluation_sequence == 0 else True,
        evaluated_at_utc=None if evaluation_sequence == 0 else evaluated,
        evaluated_at_monotonic_ns=(
            None if evaluation_sequence == 0 else evaluation_sequence * 1_000_000_000
        ),
        previous_host_head_sha256=previous_head,
        current_host_head_sha256=current_head,
    )


def _record(
    anchor_sequence: int,
    transition: AuthenticatedTrustedTimeHeadTransition,
    *,
    previous: TrustedTimeHeadAnchorRecord | None,
    reason: TrustedTimeHeadAnchorCheckpointReason | None = None,
) -> TrustedTimeHeadAnchorRecord:
    checkpoint_reason = reason or (
        TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        if anchor_sequence == 1
        else TrustedTimeHeadAnchorCheckpointReason.PERIODIC
    )
    return anchor_contract._sign_record(
        transition,
        anchor_sequence=anchor_sequence,
        previous=previous,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        signer=CRYPTO,
        verifier=CRYPTO,
    )


def _records() -> tuple[
    TrustedTimeHeadAnchorRecord,
    TrustedTimeHeadAnchorRecord,
    TrustedTimeHeadAnchorRecord,
]:
    first = _record(1, _transition(0), previous=None)
    second = _record(2, _transition(1), previous=first)
    third = _record(3, _transition(2), previous=second)
    return first, second, third


def _core(
    *,
    authority: TrustedTimeWatchdogAuthority | None = None,
    verifier: _DeterministicEd25519 = CRYPTO,
) -> TrustedTimeWatchdogCore:
    return TrustedTimeWatchdogCore(
        authority=authority or _authority(),
        verifier=verifier,
        started_at_monotonic_ns=0,
    )


def _assert_fatal(
    core: TrustedTimeWatchdogCore,
    reason: TrustedTimeWatchdogReason,
    *,
    at: int,
) -> None:
    evidence = core.evidence(observed_at_monotonic_ns=at)
    assert evidence.status is TrustedTimeWatchdogStatus.FATAL
    assert evidence.reason is reason
    assert evidence.fatal_error_latched is True


def test_historical_candidate_pair_is_always_unavailable_and_never_becomes_stale() -> None:
    assert (
        TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION
        == "phase6e-provider-neutral-trusted-head-watchdog-state-v1"
    )
    assert TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS == 360_000_000_000
    assert set(TrustedTimeWatchdogStatus) == {
        TrustedTimeWatchdogStatus.UNAVAILABLE,
        TrustedTimeWatchdogStatus.FATAL,
    }
    first, second, _ = _records()
    core = _core()

    startup = core.evidence(observed_at_monotonic_ns=0)
    baseline = core.observe_checkpoint_candidate(
        first.canonical_bytes,
        observed_at_monotonic_ns=1,
    )
    unchanged_baseline = core.observe_checkpoint_candidate(
        first.canonical_bytes,
        observed_at_monotonic_ns=100,
    )
    successor = core.observe_checkpoint_candidate(
        second.canonical_bytes,
        observed_at_monotonic_ns=200,
    )
    huge_time = core.observe_checkpoint_candidate(
        second.canonical_bytes,
        observed_at_monotonic_ns=(200 + 1_000 * TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS),
    )

    assert startup.status is TrustedTimeWatchdogStatus.UNAVAILABLE
    assert startup.reason is TrustedTimeWatchdogReason.STARTUP_NO_BASELINE
    assert baseline.reason is TrustedTimeWatchdogReason.BASELINE_ONLY
    assert unchanged_baseline.last_candidate_successor_observed_at_monotonic_ns is None
    assert successor.status is TrustedTimeWatchdogStatus.UNAVAILABLE
    assert successor.reason is TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
    assert successor.last_candidate_successor_observed_at_monotonic_ns == 200
    assert successor.candidate_successor_observed is True
    assert huge_time.status is TrustedTimeWatchdogStatus.UNAVAILABLE
    assert huge_time.reason is TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
    assert huge_time.last_candidate_successor_observed_at_monotonic_ns == 200


def test_provider_unavailability_and_unchanged_candidate_never_refresh_successor_time() -> None:
    first, second, third = _records()
    core = _core()
    core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    successor = core.observe_checkpoint_candidate(
        second.canonical_bytes,
        observed_at_monotonic_ns=10,
    )

    unavailable = core.observe_provider_unavailable(observed_at_monotonic_ns=20)
    unchanged = core.observe_checkpoint_candidate(
        second.canonical_bytes,
        observed_at_monotonic_ns=30,
    )
    later_candidate = core.observe_checkpoint_candidate(
        third.canonical_bytes,
        observed_at_monotonic_ns=40,
    )

    assert successor.last_candidate_successor_observed_at_monotonic_ns == 10
    assert unavailable.status is TrustedTimeWatchdogStatus.UNAVAILABLE
    assert unavailable.reason is TrustedTimeWatchdogReason.PROVIDER_UNAVAILABLE
    assert unavailable.last_candidate_successor_observed_at_monotonic_ns == 10
    assert unchanged.reason is TrustedTimeWatchdogReason.PROVIDER_UNAVAILABLE
    assert unchanged.last_candidate_successor_observed_at_monotonic_ns == 10
    assert later_candidate.status is TrustedTimeWatchdogStatus.UNAVAILABLE
    assert later_candidate.reason is TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
    assert later_candidate.last_candidate_successor_observed_at_monotonic_ns == 40
    assert later_candidate.provider_unavailable_latched is False


def test_invalid_signature_and_authority_mismatch_are_fatal() -> None:
    first, _, _ = _records()
    invalid_signature = replace(first, signature_ed25519="0" * 128)
    signature_core = _core()

    with pytest.raises(TrustedTimeWatchdogFatalError, match="signature"):
        signature_core.observe_checkpoint_candidate(
            invalid_signature.canonical_bytes,
            observed_at_monotonic_ns=1,
        )
    _assert_fatal(signature_core, TrustedTimeWatchdogReason.SIGNATURE_INVALID, at=1)

    authority_core = _core(authority=_authority(host_id="different-host"))
    with pytest.raises(TrustedTimeWatchdogFatalError, match="authority"):
        authority_core.observe_checkpoint_candidate(
            first.canonical_bytes,
            observed_at_monotonic_ns=1,
        )
    _assert_fatal(authority_core, TrustedTimeWatchdogReason.AUTHORITY_MISMATCH, at=1)


@pytest.mark.parametrize(
    "verifier",
    (
        _DeterministicEd25519(verification_result=1),
        _DeterministicEd25519(verification_error=True),
    ),
)
def test_verifier_exception_or_non_boolean_result_is_fatal(
    verifier: _DeterministicEd25519,
) -> None:
    first, _, _ = _records()
    core = _core(verifier=verifier)

    with pytest.raises(TrustedTimeWatchdogFatalError, match="signature"):
        core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    _assert_fatal(core, TrustedTimeWatchdogReason.SIGNATURE_INVALID, at=1)


def test_sequence_gap_rollback_fork_and_predecessor_mismatch_are_fatal() -> None:
    first, second, _ = _records()

    gap_core = _core()
    gap_core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    gap = _record(3, _transition(1), previous=first)
    with pytest.raises(TrustedTimeWatchdogFatalError, match="sequence gap"):
        gap_core.observe_checkpoint_candidate(gap.canonical_bytes, observed_at_monotonic_ns=2)
    _assert_fatal(gap_core, TrustedTimeWatchdogReason.SEQUENCE_GAP, at=2)

    rollback_core = _core()
    rollback_core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    rollback_core.observe_checkpoint_candidate(second.canonical_bytes, observed_at_monotonic_ns=2)
    with pytest.raises(TrustedTimeWatchdogFatalError, match="rollback"):
        rollback_core.observe_checkpoint_candidate(
            first.canonical_bytes,
            observed_at_monotonic_ns=3,
        )
    _assert_fatal(rollback_core, TrustedTimeWatchdogReason.ROLLBACK, at=3)

    alternate_first = _record(
        1,
        _transition(0, current_host_head_sha256=_digest(999)),
        previous=None,
    )
    fork_core = _core()
    fork_core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    with pytest.raises(TrustedTimeWatchdogFatalError, match="fork"):
        fork_core.observe_checkpoint_candidate(
            alternate_first.canonical_bytes,
            observed_at_monotonic_ns=2,
        )
    _assert_fatal(fork_core, TrustedTimeWatchdogReason.FORK, at=2)

    foreign_successor = _record(2, _transition(1), previous=alternate_first)
    chain_core = _core()
    chain_core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    with pytest.raises(TrustedTimeWatchdogFatalError, match="predecessor"):
        chain_core.observe_checkpoint_candidate(
            foreign_successor.canonical_bytes,
            observed_at_monotonic_ns=2,
        )
    _assert_fatal(chain_core, TrustedTimeWatchdogReason.CHAIN_MISMATCH, at=2)


def test_malformed_candidate_and_monotonic_regression_preserve_first_fatal_reason() -> None:
    malformed_core = _core()
    with pytest.raises(TrustedTimeWatchdogFatalError, match="bytes"):
        malformed_core.observe_checkpoint_candidate(b"{}", observed_at_monotonic_ns=1)
    _assert_fatal(malformed_core, TrustedTimeWatchdogReason.INVALID_CHECKPOINT, at=1)

    first, _, _ = _records()
    invalid_signature = replace(first, signature_ed25519="0" * 128)
    first_fatal_core = _core()
    with pytest.raises(TrustedTimeWatchdogFatalError, match="signature"):
        first_fatal_core.observe_checkpoint_candidate(
            invalid_signature.canonical_bytes,
            observed_at_monotonic_ns=10,
        )
    with pytest.raises(TrustedTimeWatchdogFatalError, match="regressed"):
        first_fatal_core.evidence(observed_at_monotonic_ns=9)
    _assert_fatal(first_fatal_core, TrustedTimeWatchdogReason.SIGNATURE_INVALID, at=10)


def _reissue_evidence_with_changes(
    evidence: TrustedTimeWatchdogEvidence,
    **changes: object,
) -> TrustedTimeWatchdogEvidence:
    values: dict[str, Any] = {
        "authority_semantic_sha256": evidence.authority_semantic_sha256,
        "status": evidence.status,
        "reason": evidence.reason,
        "observed_at_monotonic_ns": evidence.observed_at_monotonic_ns,
        "anchor_sequence": evidence.anchor_sequence,
        "anchor_sha256": evidence.anchor_sha256,
        "current_host_head_sha256": evidence.current_host_head_sha256,
        "checkpoint_reason": evidence.checkpoint_reason,
        "last_candidate_successor_observed_at_monotonic_ns": (
            evidence.last_candidate_successor_observed_at_monotonic_ns
        ),
        "candidate_successor_observed": evidence.candidate_successor_observed,
        "provider_unavailable_latched": evidence.provider_unavailable_latched,
        "fatal_error_latched": evidence.fatal_error_latched,
    }
    values.update(changes)
    return watchdog_contract._new_trusted_time_watchdog_evidence(**values)


def test_evidence_is_factory_sealed_nonserializable_and_exhaustively_validated() -> None:
    evidence = _core().evidence(observed_at_monotonic_ns=0)

    assert evidence.contract_version == TRUSTED_TIME_WATCHDOG_CONTRACT_VERSION
    assert evidence.authority_semantic_sha256 == _authority().semantic_sha256
    assert copy.copy(evidence) is evidence
    assert copy.deepcopy(evidence) is evidence
    with pytest.raises(TypeError, match="issued by the watchdog core"):
        TrustedTimeWatchdogEvidence()
    with pytest.raises(TypeError):
        replace(evidence, reason=TrustedTimeWatchdogReason.BASELINE_ONLY)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(evidence)
    with pytest.raises(FrozenInstanceError):
        evidence.reason = TrustedTimeWatchdogReason.BASELINE_ONLY  # type: ignore[misc]
    with pytest.raises(TrustedTimeWatchdogError, match="projection is inconsistent"):
        _reissue_evidence_with_changes(
            evidence,
            reason=TrustedTimeWatchdogReason.BASELINE_ONLY,
        )
    with pytest.raises(TrustedTimeWatchdogError, match="must remain unavailable"):
        _reissue_evidence_with_changes(
            evidence,
            status=TrustedTimeWatchdogStatus.FATAL,
        )

    forged = object.__new__(TrustedTimeWatchdogEvidence)
    for field_name in evidence.__dataclass_fields__:
        object.__setattr__(
            forged,
            field_name,
            object() if field_name == "_seal" else getattr(evidence, field_name),
        )
    with pytest.raises(TrustedTimeWatchdogError, match="not factory-issued"):
        forged.__post_init__()

    semantic_forgery = object.__new__(TrustedTimeWatchdogEvidence)
    for field_name in evidence.__dataclass_fields__:
        value = getattr(evidence, field_name)
        if field_name == "_seal":
            value = watchdog_contract._WATCHDOG_EVIDENCE_SEAL
        elif field_name == "authority_semantic_sha256":
            value = "f" * 64
        object.__setattr__(semantic_forgery, field_name, value)
    with pytest.raises(TrustedTimeWatchdogError, match="semantic seal"):
        semantic_forgery.__post_init__()


def test_historical_clean_stop_and_huge_time_remain_unavailable_without_terminal_proof() -> None:
    first, _, _ = _records()
    clean_stop = _record(
        2,
        _transition(1),
        previous=first,
        reason=TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
    )
    core = _core()
    core.observe_checkpoint_candidate(first.canonical_bytes, observed_at_monotonic_ns=1)
    candidate = core.observe_checkpoint_candidate(
        clean_stop.canonical_bytes,
        observed_at_monotonic_ns=2,
    )
    much_later = core.evidence(
        observed_at_monotonic_ns=2 + 10_000 * TRUSTED_TIME_WATCHDOG_STALE_AFTER_NS,
    )

    for evidence in (candidate, much_later):
        assert evidence.status is TrustedTimeWatchdogStatus.UNAVAILABLE
        assert evidence.reason is TrustedTimeWatchdogReason.PROVIDER_TERMINAL_PROOF_ABSENT
        assert evidence.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
    for value in (_authority(), much_later):
        for field_name in (
            "operational_control_authorized",
            "readiness_authorized",
            "arming_authorized",
            "exposure_authorized",
            "new_exposure_authorized",
            "broker_action_authorized",
            "alert_delivery_authorized",
            "rearm_authorized",
            "automatic_rearm_authorized",
            "automatic_resume_authorized",
            "paper_trading_authorized",
            "live_trading_authorized",
        ):
            assert getattr(value, field_name) is False
