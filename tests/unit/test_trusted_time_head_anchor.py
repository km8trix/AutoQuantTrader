from __future__ import annotations

import copy
import hashlib
import pickle
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from packages.application import trusted_time_head_anchor as anchor_contract
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
    TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
    AuthenticatedTrustedTimeHeadTransition,
    CommittedTrustedTimeHeadAnchorIntentEvidence,
    PreparedTrustedTimeHeadAnchorReconciliation,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorConflict,
    TrustedTimeHeadAnchorError,
    TrustedTimeHeadAnchorProviderIdentity,
    TrustedTimeHeadAnchorProviderReadbackEvidence,
    TrustedTimeHeadAnchorProviderUnavailable,
    TrustedTimeHeadAnchorReconciliationResult,
    TrustedTimeHeadAnchorRecord,
    complete_trusted_time_head_anchor_reconciliation,
    prepare_bounded_trusted_time_head_anchor_reconciliation,
    prepare_incremental_trusted_time_head_anchor_reconciliation,
    prepare_persisted_trusted_time_head_anchor_intent_recovery,
    prepare_trusted_time_head_anchor_reconciliation,
    reconcile_trusted_time_head_anchors,
    trusted_time_head_anchor_object_name,
    trusted_time_head_anchor_object_prefix,
    verify_trusted_time_head_anchor_provider_readback,
)
from packages.application.trusted_time_monitor import TrustedTimeProbeStatus
from packages.domain.canonical import canonical_json_bytes
from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeHealth,
    TrustedTimeReason,
)

DEPLOYMENT_IDENTITY = "1" * 64
RUNTIME_DATABASE_IDENTITY = "4" * 64
ANCHOR_PROJECT_IDENTITY = "5" * 64
ANCHOR_PROJECT_REF = "abcdefghijklmnopqrst"
ANCHOR_AUTHORITY_SHA256 = "6" * 64
BUCKET = TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
PRINCIPAL = "11111111-1111-4111-8111-111111111111"
HOST = "aqt-local-paper-host"
SOURCE_V1 = "chrony-nts-cloudflare-netnod-v1"
SOURCE_V2 = "chrony-nts-cloudflare-system76-virginia-v2"
AUTHORITY_V1 = "2" * 64
AUTHORITY_V2 = "3" * 64
EPOCH_ID_V1 = "22222222-2222-4222-8222-22222222222a"
EPOCH_ID_V2 = "33333333-3333-4333-8333-33333333333b"
EVALUATION_ID_1 = "44444444-4444-4444-8444-44444444444c"
EVALUATION_ID_2 = "55555555-5555-4555-8555-55555555555d"
EVALUATION_ID_3 = "66666666-6666-4666-8666-66666666666e"
KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
KEY_SHA256 = hashlib.sha256(b"deterministic-test-public-key").hexdigest()
STARTED_AT = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def digest(number: int) -> str:
    return f"{number:064x}"


def local_chain() -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    return (
        AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=BUCKET,
            principal_id=PRINCIPAL,
            head_authenticated_at_utc=STARTED_AT,
            host_id=HOST,
            source_id=SOURCE_V1,
            source_authority_sha256=AUTHORITY_V1,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=(TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION),
            epoch_sequence=1,
            monitor_epoch_id=EPOCH_ID_V1,
            epoch_sha256=digest(10),
            evaluation_sequence=0,
            evaluation_id=None,
            evaluation_record_sha256=None,
            state_sha256=None,
            probe_status=None,
            health=None,
            reason=None,
            hard_failure_latched=None,
            clock_recovery_qualified=None,
            evaluated_at_utc=None,
            evaluated_at_monotonic_ns=None,
            previous_host_head_sha256=None,
            current_host_head_sha256=digest(100),
        ),
        AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=BUCKET,
            principal_id=PRINCIPAL,
            head_authenticated_at_utc=STARTED_AT + timedelta(seconds=1),
            host_id=HOST,
            source_id=SOURCE_V1,
            source_authority_sha256=AUTHORITY_V1,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=(TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION),
            epoch_sequence=1,
            monitor_epoch_id=EPOCH_ID_V1,
            epoch_sha256=digest(10),
            evaluation_sequence=1,
            evaluation_id=EVALUATION_ID_1,
            evaluation_record_sha256=digest(20),
            state_sha256=digest(30),
            probe_status=TrustedTimeProbeStatus.RECORDED,
            health=TrustedTimeHealth.WARNING,
            reason=TrustedTimeReason.STARTUP_QUALIFYING,
            hard_failure_latched=False,
            clock_recovery_qualified=False,
            evaluated_at_utc=STARTED_AT + timedelta(seconds=1),
            evaluated_at_monotonic_ns=1_000,
            previous_host_head_sha256=digest(100),
            current_host_head_sha256=digest(101),
        ),
        AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=BUCKET,
            principal_id=PRINCIPAL,
            head_authenticated_at_utc=STARTED_AT + timedelta(seconds=2),
            host_id=HOST,
            source_id=SOURCE_V1,
            source_authority_sha256=AUTHORITY_V1,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=(TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION),
            epoch_sequence=1,
            monitor_epoch_id=EPOCH_ID_V1,
            epoch_sha256=digest(10),
            evaluation_sequence=2,
            evaluation_id=EVALUATION_ID_2,
            evaluation_record_sha256=digest(21),
            state_sha256=digest(31),
            probe_status=TrustedTimeProbeStatus.RECORDED,
            health=TrustedTimeHealth.HEALTHY,
            reason=TrustedTimeReason.WITHIN_LIMIT,
            hard_failure_latched=False,
            clock_recovery_qualified=False,
            evaluated_at_utc=STARTED_AT + timedelta(seconds=2),
            evaluated_at_monotonic_ns=2_000,
            previous_host_head_sha256=digest(101),
            current_host_head_sha256=digest(102),
        ),
        AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=BUCKET,
            principal_id=PRINCIPAL,
            head_authenticated_at_utc=STARTED_AT + timedelta(seconds=3),
            host_id=HOST,
            source_id=SOURCE_V2,
            source_authority_sha256=AUTHORITY_V2,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=(TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION),
            epoch_sequence=2,
            monitor_epoch_id=EPOCH_ID_V2,
            epoch_sha256=digest(11),
            evaluation_sequence=0,
            evaluation_id=None,
            evaluation_record_sha256=None,
            state_sha256=None,
            probe_status=None,
            health=None,
            reason=None,
            hard_failure_latched=None,
            clock_recovery_qualified=None,
            evaluated_at_utc=None,
            evaluated_at_monotonic_ns=None,
            previous_host_head_sha256=digest(102),
            current_host_head_sha256=digest(103),
        ),
        AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=BUCKET,
            principal_id=PRINCIPAL,
            head_authenticated_at_utc=STARTED_AT + timedelta(seconds=4),
            host_id=HOST,
            source_id=SOURCE_V2,
            source_authority_sha256=AUTHORITY_V2,
            policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
            persistence_contract_version=(TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION),
            epoch_sequence=2,
            monitor_epoch_id=EPOCH_ID_V2,
            epoch_sha256=digest(11),
            evaluation_sequence=1,
            evaluation_id=EVALUATION_ID_3,
            evaluation_record_sha256=digest(22),
            state_sha256=digest(32),
            probe_status=TrustedTimeProbeStatus.RECORDED,
            health=TrustedTimeHealth.HEALTHY,
            reason=TrustedTimeReason.WITHIN_LIMIT,
            hard_failure_latched=False,
            clock_recovery_qualified=True,
            evaluated_at_utc=STARTED_AT + timedelta(seconds=4),
            evaluated_at_monotonic_ns=4_000,
            previous_host_head_sha256=digest(103),
            current_host_head_sha256=digest(104),
        ),
    )


@dataclass
class DeterministicEd25519TestDouble:
    key: bytes = b"deterministic-test-signing-key"
    verification_result: bool | int = True
    sign_calls: int = 0

    def _signature(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        return hashlib.sha512(
            self.key + signing_key_id.encode() + signing_public_key_sha256.encode() + payload
        ).digest()

    def sign_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        self.sign_calls += 1
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
        if type(self.verification_result) is not bool:
            return self.verification_result  # type: ignore[return-value]
        return self.verification_result and signature == self._signature(
            signing_key_id=signing_key_id,
            signing_public_key_sha256=signing_public_key_sha256,
            payload=payload,
        )


class MemoryProvider:
    def __init__(
        self,
        *,
        identity: TrustedTimeHeadAnchorProviderIdentity | None = None,
    ) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.confirmed_records: tuple[TrustedTimeHeadAnchorRecord, ...] = ()
        self.identity = identity or TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            principal_id=PRINCIPAL,
            bucket_name=BUCKET,
        )
        self.attestation_calls = 0
        self.list_calls: list[tuple[str, str]] = []
        self.page_calls: list[tuple[str, str, int, int]] = []
        self.sequence_list_calls: list[tuple[str, str, int]] = []
        self.download_calls: list[tuple[str, str]] = []
        self.upload_calls: list[tuple[str, str, bytes, str]] = []
        self.hide_next_listing = False
        self.return_list_instead_of_tuple = False
        self.return_bytearray = False
        self.mutate_upload = False
        self.upload_return: object = None

    def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity:
        self.attestation_calls += 1
        return self.identity

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]:
        self.list_calls.append((bucket_name, prefix))
        if self.hide_next_listing:
            self.hide_next_listing = False
            return ()
        names = tuple(
            sorted(
                name
                for (bucket, name) in self.objects
                if bucket == bucket_name and name.startswith(prefix)
            )
        )
        if self.return_list_instead_of_tuple:
            return list(names)  # type: ignore[return-value]
        return names

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        self.sequence_list_calls.append((bucket_name, prefix, anchor_sequence))
        sequence_prefix = f"{prefix}{anchor_sequence:020d}-"
        names = tuple(
            sorted(
                name
                for (bucket, name) in self.objects
                if bucket == bucket_name and name.startswith(sequence_prefix)
            )
        )
        if self.return_list_instead_of_tuple:
            return list(names)  # type: ignore[return-value]
        return names

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        self.page_calls.append((bucket_name, prefix, offset, limit))
        names = tuple(
            sorted(
                name
                for (bucket, name) in self.objects
                if bucket == bucket_name and name.startswith(prefix)
            )
        )
        return names[offset : offset + limit]

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        self.download_calls.append((bucket_name, object_name))
        payload = self.objects[(bucket_name, object_name)]
        if self.return_bytearray:
            return bytearray(payload)  # type: ignore[return-value]
        return payload

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None:
        self.upload_calls.append((bucket_name, object_name, payload, content_type))
        key = (bucket_name, object_name)
        if key in self.objects:
            raise FileExistsError(object_name)
        self.objects[key] = payload + b"\n" if self.mutate_upload else payload
        return self.upload_return  # type: ignore[return-value]


class UnavailableUploadProvider(MemoryProvider):
    def __init__(self, *, commit_before_failure: bool) -> None:
        super().__init__()
        self.commit_before_failure = commit_before_failure
        self.unavailable = TrustedTimeHeadAnchorProviderUnavailable(
            "provider temporarily unavailable"
        )

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None:
        if self.commit_before_failure:
            super().upload_object_no_overwrite(
                bucket_name=bucket_name,
                object_name=object_name,
                payload=payload,
                content_type=content_type,
            )
        raise self.unavailable


@dataclass
class MemoryIntentJournal:
    calls: list[PreparedTrustedTimeHeadAnchorReconciliation]

    def __init__(self) -> None:
        self.calls = []

    def commit_trusted_time_head_anchor_intent(
        self,
        *,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    ) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
        self.calls.append(prepared)
        candidate = prepared.candidate_record
        assert candidate is not None
        return anchor_contract._new_committed_trusted_time_head_anchor_intent_evidence(
            intent_id="77777777-7777-4777-8777-777777777777",
            committed_at_utc=STARTED_AT + timedelta(minutes=10),
            deployment_identity_sha256=candidate.deployment_identity_sha256,
            runtime_database_identity_sha256=candidate.runtime_database_identity_sha256,
            anchor_project_identity_sha256=candidate.anchor_project_identity_sha256,
            anchor_project_ref=candidate.anchor_project_ref,
            bucket_name=candidate.bucket_name,
            principal_id=candidate.principal_id,
            anchor_sequence=candidate.anchor_sequence,
            signed_envelope_sha256=candidate.byte_sha256,
            semantic_sha256=candidate.semantic_sha256,
            previous_anchor_sha256=candidate.previous_anchor_sha256,
            current_host_head_sha256=candidate.current_host_head_sha256,
            checkpoint_reason=candidate.checkpoint_reason,
            checkpoint_interval_seconds=candidate.checkpoint_interval_seconds,
            anchor_authority_sha256=candidate.anchor_authority_sha256,
        )


def reconcile(
    chain: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    provider: MemoryProvider,
    *,
    crypto: DeterministicEd25519TestDouble | None = None,
    allow_enrollment: bool = True,
    full_audit: bool = True,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None = None,
) -> TrustedTimeHeadAnchorReconciliationResult:
    signer_and_verifier = crypto or DeterministicEd25519TestDouble()
    reason = checkpoint_reason or (
        TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        if not provider.confirmed_records
        else TrustedTimeHeadAnchorCheckpointReason.PERIODIC
    )
    result = reconcile_trusted_time_head_anchors(
        chain,
        provider.confirmed_records,
        provider=provider,
        signer=signer_and_verifier,
        verifier=signer_and_verifier,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        checkpoint_reason=reason,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
        intent_journal=MemoryIntentJournal(),
        pending_anchor_intent=None,
        full_audit=full_audit,
        allow_enrollment=allow_enrollment,
    )
    provider.confirmed_records = result.anchor_records
    return result


def prepare_plan(
    chain: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    provider: MemoryProvider,
    *,
    crypto: DeterministicEd25519TestDouble | None = None,
    full_audit: bool = True,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason | None = None,
    pending_anchor_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None = None,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    signer_and_verifier = crypto or DeterministicEd25519TestDouble()
    reason = checkpoint_reason or (
        TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        if not provider.confirmed_records
        else TrustedTimeHeadAnchorCheckpointReason.PERIODIC
    )
    return prepare_trusted_time_head_anchor_reconciliation(
        chain,
        provider.confirmed_records,
        provider=provider,
        signer=signer_and_verifier,
        verifier=signer_and_verifier,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        checkpoint_reason=reason,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
        pending_anchor_intent=pending_anchor_intent,
        full_audit=full_audit,
        allow_enrollment=not provider.confirmed_records,
    )


def committed_evidence(
    prepared: PreparedTrustedTimeHeadAnchorReconciliation,
) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
    return MemoryIntentJournal().commit_trusted_time_head_anchor_intent(prepared=prepared)


def bounded_tip_and_provider(
    count: int,
) -> tuple[anchor_contract.AuthenticatedTrustedTimeHeadJournalTip, MemoryProvider]:
    transition = local_chain()[-1]
    provider = MemoryProvider()
    crypto = DeterministicEd25519TestDouble()
    previous: TrustedTimeHeadAnchorRecord | None = None
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    for sequence in range(1, count + 1):
        record = anchor_contract._sign_record(
            transition,
            anchor_sequence=sequence,
            previous=previous,
            checkpoint_reason=(
                TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
                if previous is None
                else TrustedTimeHeadAnchorCheckpointReason.PERIODIC
            ),
            checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
            anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
            signing_key_id=KEY_ID,
            signing_public_key_sha256=KEY_SHA256,
            signer=crypto,
            verifier=crypto,
        )
        name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=sequence,
            signed_envelope_sha256=record.byte_sha256,
        )
        provider.objects[(BUCKET, name)] = record.canonical_bytes
        previous = record
    assert previous is not None
    tip = anchor_contract._issue_authenticated_trusted_time_head_journal_tip(
        current_transition=transition,
        local_transition_count=count,
        first_local_host_head_sha256=local_chain()[0].current_host_head_sha256,
        confirmed_anchor_count=count,
        confirmed_anchor_tip=previous,
        first_anchored_local_transition_ordinal=1,
        confirmed_anchor_local_transition_ordinal=count,
    )
    return tip, provider


def only_record(provider: MemoryProvider) -> tuple[str, TrustedTimeHeadAnchorRecord]:
    assert len(provider.objects) == 1
    (_, object_name), payload = next(iter(provider.objects.items()))
    return object_name, TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)


def test_enrollment_signs_only_the_fully_replayed_current_head() -> None:
    chain = local_chain()
    provider = MemoryProvider()

    result = reconcile(chain, provider, allow_enrollment=True)

    assert result.external_head_anchor_evidence is True
    assert result.uploaded_anchor_count == 1
    assert result.idempotent_duplicate_count == 0
    assert result.local_transition_count == 5
    assert result.first_anchored_local_transition_ordinal == 5
    assert len(result.anchor_records) == 1
    record = result.anchor_records[0]
    assert record.anchor_sequence == 1
    assert record.current_host_head_sha256 == chain[-1].current_host_head_sha256
    assert record.local_previous_host_head_sha256 == chain[-1].previous_host_head_sha256
    assert record.previous_anchor_sha256 is None
    assert record.previous_anchored_host_head_sha256 is None
    assert record.signing_key_id == KEY_ID
    assert record.signing_public_key_sha256 == KEY_SHA256
    assert record.deployment_identity_sha256 == DEPLOYMENT_IDENTITY
    assert record.runtime_database_identity_sha256 == RUNTIME_DATABASE_IDENTITY
    assert record.anchor_project_identity_sha256 == ANCHOR_PROJECT_IDENTITY
    assert record.policy_sha256 == TRUSTED_TIME_POLICY.semantic_sha256
    assert record.persistence_contract_version == (
        TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION
    )
    assert record.byte_sha256 == hashlib.sha256(record.canonical_bytes).hexdigest()
    object_name = provider.upload_calls[0][1]
    assert object_name.startswith(f"v1/{DEPLOYMENT_IDENTITY}/")
    assert object_name.endswith(f"/{1:020d}-{record.byte_sha256}.json")
    assert len(record.canonical_bytes) <= 4_096
    assert provider.upload_calls[0][3] == TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE
    assert provider.download_calls
    assert result.historical_local_chain_externally_authenticated is False
    assert result.readiness_authorized is False
    assert result.operational_control_authorized is False
    assert result.arming_authorized is False
    assert result.exposure_authorized is False
    assert result.new_exposure_authorized is False
    assert result.rearm_authorized is False
    assert result.automatic_rearm_authorized is False
    assert result.automatic_resume_authorized is False
    assert result.broker_action_authorized is False


def test_authenticated_journal_tip_compacts_and_advances_exact_suffixes() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    first = reconcile(chain[:3], provider, allow_enrollment=True)
    tip = anchor_contract._new_authenticated_trusted_time_head_journal_tip(
        local_transitions=chain[:3],
        confirmed_anchor_records=first.anchor_records,
    )

    assert tip.local_transition_count == 3
    assert tip.current_transition == chain[2]
    assert tip.first_local_host_head_sha256 == chain[0].current_host_head_sha256
    assert tip.confirmed_anchor_count == 1
    assert tip.confirmed_anchor_tip == first.anchor_records[-1]
    assert tip.first_anchored_local_transition_ordinal == 3
    assert tip.confirmed_anchor_local_transition_ordinal == 3
    assert tip.readiness_authorized is False

    second = reconcile(
        chain,
        provider,
        allow_enrollment=False,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
    )
    advanced = anchor_contract._advance_authenticated_trusted_time_head_journal_tip(
        tip,
        appended_local_transitions=chain[3:],
        newly_confirmed_anchor_records=(second.anchor_records[-1],),
        newly_confirmed_anchor_local_transition_ordinals=(5,),
    )

    assert advanced.local_transition_count == 5
    assert advanced.current_transition == chain[-1]
    assert advanced.confirmed_anchor_count == 2
    assert advanced.confirmed_anchor_tip == second.anchor_records[-1]
    assert advanced.first_anchored_local_transition_ordinal == 3
    assert advanced.confirmed_anchor_local_transition_ordinal == 5


def test_authenticated_journal_tip_rejects_forgery_and_gapped_suffix() -> None:
    chain = local_chain()
    tip = anchor_contract._new_authenticated_trusted_time_head_journal_tip(
        local_transitions=chain[:2],
        confirmed_anchor_records=(),
    )

    with pytest.raises(TypeError, match="issued by authenticated persistence"):
        anchor_contract.AuthenticatedTrustedTimeHeadJournalTip()
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="predecessor"):
        anchor_contract._advance_authenticated_trusted_time_head_journal_tip(
            tip,
            appended_local_transitions=(chain[3],),
            newly_confirmed_anchor_records=(),
            newly_confirmed_anchor_local_transition_ordinals=(),
        )


def test_incremental_prepare_uses_only_compact_tip_and_exact_terminal_next_sequences() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    enrolled = reconcile(chain[:2], provider, allow_enrollment=True)
    initial_tip = anchor_contract._new_authenticated_trusted_time_head_journal_tip(
        local_transitions=chain[:2],
        confirmed_anchor_records=enrolled.anchor_records,
    )
    tip = anchor_contract._advance_authenticated_trusted_time_head_journal_tip(
        initial_tip,
        appended_local_transitions=chain[2:],
        newly_confirmed_anchor_records=(),
        newly_confirmed_anchor_local_transition_ordinals=(),
    )
    crypto = DeterministicEd25519TestDouble()
    provider.list_calls.clear()
    provider.sequence_list_calls.clear()

    prepared = prepare_incremental_trusted_time_head_anchor_reconciliation(
        tip,
        provider=provider,
        signer=crypto,
        verifier=crypto,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
        pending_anchor_intent=None,
    )

    assert prepared.full_audit is False
    assert prepared.confirmed_anchor_count == 1
    assert prepared.confirmed_anchor_records == (enrolled.anchor_records[-1],)
    assert prepared.local_transition_count == len(chain)
    assert prepared.candidate_record is not None
    assert prepared.candidate_record.anchor_sequence == 2
    assert prepared.candidate_record.current_host_head_sha256 == (
        chain[-1].current_host_head_sha256
    )
    assert provider.list_calls == []
    assert [call[2] for call in provider.sequence_list_calls] == [1, 2]


def test_compact_prepare_derives_sequence_from_count_not_retained_tuple_length() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    enrolled = reconcile(chain[:2], provider, allow_enrollment=True)
    second = reconcile(chain, provider, allow_enrollment=False)
    tip = anchor_contract._new_authenticated_trusted_time_head_journal_tip(
        local_transitions=chain,
        confirmed_anchor_records=second.anchor_records,
    )
    crypto = DeterministicEd25519TestDouble()

    prepared = prepare_incremental_trusted_time_head_anchor_reconciliation(
        tip,
        provider=provider,
        signer=crypto,
        verifier=crypto,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
        pending_anchor_intent=None,
    )

    assert len(enrolled.anchor_records) == 1
    assert tip.confirmed_anchor_count == 2
    assert prepared.confirmed_anchor_count == 2
    assert len(prepared.confirmed_anchor_records) == 1
    assert prepared.confirmed_anchor_records[-1].anchor_sequence == 2
    assert prepared.candidate_record is None


def test_incremental_prepare_cannot_enroll_or_bypass_pending_recovery() -> None:
    chain = local_chain()
    empty_tip = anchor_contract._new_authenticated_trusted_time_head_journal_tip(
        local_transitions=chain,
        confirmed_anchor_records=(),
    )
    crypto = DeterministicEd25519TestDouble()
    provider = MemoryProvider()

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="full startup"):
        prepare_incremental_trusted_time_head_anchor_reconciliation(
            empty_tip,
            provider=provider,
            signer=crypto,
            verifier=crypto,
            signing_key_id=KEY_ID,
            signing_public_key_sha256=KEY_SHA256,
            checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
            checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
            anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
            pending_anchor_intent=None,
        )

    enrolled_plan = prepare_plan(chain, provider)
    pending = committed_evidence(enrolled_plan)
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="recovered"):
        prepare_incremental_trusted_time_head_anchor_reconciliation(
            empty_tip,
            provider=provider,
            signer=crypto,
            verifier=crypto,
            signing_key_id=KEY_ID,
            signing_public_key_sha256=KEY_SHA256,
            checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
            checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
            anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
            pending_anchor_intent=pending,
        )


def test_empty_remote_history_requires_explicit_exact_enrollment_permission() -> None:
    provider = MemoryProvider()

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="enrollment is not approved"):
        reconcile(local_chain(), provider, allow_enrollment=False)
    with pytest.raises(TrustedTimeHeadAnchorError, match="exact boolean"):
        reconcile(local_chain(), provider, allow_enrollment=1)  # type: ignore[arg-type]
    assert provider.objects == {}


def test_sparse_reconciliation_appends_only_the_new_current_checkpoint() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    enrolled = reconcile(chain[:2], provider)

    result = reconcile(chain, provider, allow_enrollment=False)

    assert enrolled.first_anchored_local_transition_ordinal == 2
    assert len(result.anchor_records) == 2
    assert result.uploaded_anchor_count == 1
    assert result.first_anchored_local_transition_ordinal == 2
    first, second = result.anchor_records
    assert first.current_host_head_sha256 == chain[1].current_host_head_sha256
    assert second.current_host_head_sha256 == chain[4].current_host_head_sha256
    assert second.previous_anchored_host_head_sha256 == first.current_host_head_sha256
    assert second.previous_anchor_sha256 == first.byte_sha256
    assert second.local_previous_host_head_sha256 == chain[3].current_host_head_sha256
    assert {record.current_host_head_sha256 for record in result.anchor_records}.isdisjoint(
        {chain[2].current_host_head_sha256, chain[3].current_host_head_sha256}
    )


def test_exact_remote_bytes_are_idempotent() -> None:
    provider = MemoryProvider()
    first = reconcile(local_chain(), provider)
    upload_count = len(provider.upload_calls)

    second = reconcile(local_chain(), provider, allow_enrollment=False)

    assert second.anchor_records == first.anchor_records
    assert second.uploaded_anchor_count == 0
    assert second.idempotent_duplicate_count == 0
    assert len(provider.upload_calls) == upload_count


def test_exact_concurrent_no_overwrite_collision_is_idempotent() -> None:
    seed = MemoryProvider()
    expected = reconcile(local_chain(), seed)
    provider = MemoryProvider()
    provider.objects.update(seed.objects)
    provider.hide_next_listing = True

    result = reconcile(local_chain(), provider)

    assert result.anchor_records == expected.anchor_records
    assert result.uploaded_anchor_count == 0
    assert result.idempotent_duplicate_count == 1
    assert len(provider.upload_calls) == 0


def test_conflicting_no_overwrite_collision_fails_closed() -> None:
    seed = MemoryProvider()
    reconcile(local_chain(), seed)
    provider = MemoryProvider()
    (key, _) = next(iter(seed.objects.items()))
    provider.objects[key] = b"conflicting-existing-bytes"
    provider.hide_next_listing = True

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="bytes conflict"):
        reconcile(local_chain(), provider)


def test_upload_is_reread_and_mutation_fails_closed() -> None:
    provider = MemoryProvider()
    provider.mutate_upload = True

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="bytes conflict"):
        reconcile(local_chain(), provider)


def test_unavailable_upload_is_reconciled_before_retry_classification() -> None:
    committed = UnavailableUploadProvider(commit_before_failure=True)

    result = reconcile(local_chain(), committed)

    assert result.uploaded_anchor_count == 0
    assert result.idempotent_duplicate_count == 1
    assert len(result.anchor_records) == 1

    absent = UnavailableUploadProvider(commit_before_failure=False)
    with pytest.raises(TrustedTimeHeadAnchorProviderUnavailable) as captured:
        reconcile(local_chain(), absent)
    assert captured.value is absent.unavailable
    assert absent.objects == {}


def test_provider_unavailable_is_preserved_but_unknown_errors_are_not_transient() -> None:
    unavailable = MemoryProvider()
    marker = TrustedTimeHeadAnchorProviderUnavailable("identity unavailable")

    def unavailable_identity() -> TrustedTimeHeadAnchorProviderIdentity:
        raise marker

    unavailable.attest_identity = unavailable_identity  # type: ignore[method-assign]
    with pytest.raises(TrustedTimeHeadAnchorProviderUnavailable) as captured:
        reconcile(local_chain(), unavailable)
    assert captured.value is marker

    unknown = MemoryProvider()

    def unknown_identity() -> TrustedTimeHeadAnchorProviderIdentity:
        raise RuntimeError("unknown provider failure")

    unknown.attest_identity = unknown_identity  # type: ignore[method-assign]
    with pytest.raises(TrustedTimeHeadAnchorError) as captured_unknown:
        reconcile(local_chain(), unknown)
    assert not isinstance(captured_unknown.value, TrustedTimeHeadAnchorProviderUnavailable)


def test_remote_head_absent_from_local_chain_is_rollback_or_fork() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain, provider)
    fork = (
        *chain[:4],
        replace(
            chain[4],
            evaluation_record_sha256=digest(222),
            state_sha256=digest(232),
            current_host_head_sha256=digest(204),
        ),
    )

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="absent"):
        reconcile(fork, provider)


def test_remote_checkpoints_must_advance_through_local_history() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain[:3], provider)
    reconcile(chain, provider)
    names = sorted(name for (_, name) in provider.objects)
    first_payload = provider.objects[(BUCKET, names[0])]
    second_record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(
        provider.objects[(BUCKET, names[1])]
    )
    first_record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(first_payload)
    regressing = _resign_record(
        second_record,
        head_authenticated_at_utc=chain[1].head_authenticated_at_utc,
        source_id=chain[1].source_id,
        source_authority_sha256=chain[1].source_authority_sha256,
        epoch_sequence=chain[1].epoch_sequence,
        monitor_epoch_id=chain[1].monitor_epoch_id,
        epoch_sha256=chain[1].epoch_sha256,
        evaluation_sequence=chain[1].evaluation_sequence,
        evaluation_id=chain[1].evaluation_id,
        evaluation_record_sha256=chain[1].evaluation_record_sha256,
        state_sha256=chain[1].state_sha256,
        probe_status=chain[1].probe_status,
        health=chain[1].health,
        reason=chain[1].reason,
        hard_failure_latched=chain[1].hard_failure_latched,
        clock_recovery_qualified=chain[1].clock_recovery_qualified,
        evaluated_at_utc=chain[1].evaluated_at_utc,
        evaluated_at_monotonic_ns=chain[1].evaluated_at_monotonic_ns,
        local_previous_host_head_sha256=chain[1].previous_host_head_sha256,
        current_host_head_sha256=chain[1].current_host_head_sha256,
    )
    assert regressing.previous_anchor_sha256 == first_record.byte_sha256
    del provider.objects[(BUCKET, names[1])]
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    regressing_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=regressing.anchor_sequence,
        signed_envelope_sha256=regressing.byte_sha256,
    )
    provider.objects[(BUCKET, regressing_name)] = regressing.canonical_bytes

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="do not advance"):
        reconcile(chain, provider)


def _resign_record(
    record: TrustedTimeHeadAnchorRecord,
    **changes: object,
) -> TrustedTimeHeadAnchorRecord:
    """Recompute semantic digest/signature for deliberate remote-fixture mutation."""

    crypto = DeterministicEd25519TestDouble()
    values = {
        field_name: getattr(record, field_name)
        for field_name in record.__dataclass_fields__
        if field_name not in {"semantic_sha256", "signature_ed25519"}
    }
    values.update(changes)
    material = anchor_contract._anchor_semantic_material(
        anchor_sequence=values["anchor_sequence"],  # type: ignore[arg-type]
        deployment_identity_sha256=values["deployment_identity_sha256"],  # type: ignore[arg-type]
        runtime_database_identity_sha256=values[  # type: ignore[arg-type]
            "runtime_database_identity_sha256"
        ],
        anchor_project_identity_sha256=values[  # type: ignore[arg-type]
            "anchor_project_identity_sha256"
        ],
        anchor_project_ref=values["anchor_project_ref"],  # type: ignore[arg-type]
        bucket_name=values["bucket_name"],  # type: ignore[arg-type]
        principal_id=values["principal_id"],  # type: ignore[arg-type]
        signing_key_id=values["signing_key_id"],  # type: ignore[arg-type]
        signing_public_key_sha256=values["signing_public_key_sha256"],  # type: ignore[arg-type]
        head_authenticated_at_utc=values["head_authenticated_at_utc"],  # type: ignore[arg-type]
        host_id=values["host_id"],  # type: ignore[arg-type]
        source_id=values["source_id"],  # type: ignore[arg-type]
        source_authority_sha256=values["source_authority_sha256"],  # type: ignore[arg-type]
        policy_sha256=values["policy_sha256"],  # type: ignore[arg-type]
        persistence_contract_version=values["persistence_contract_version"],  # type: ignore[arg-type]
        checkpoint_reason=values["checkpoint_reason"],  # type: ignore[arg-type]
        checkpoint_interval_seconds=values["checkpoint_interval_seconds"],  # type: ignore[arg-type]
        anchor_authority_sha256=values["anchor_authority_sha256"],  # type: ignore[arg-type]
        epoch_sequence=values["epoch_sequence"],  # type: ignore[arg-type]
        monitor_epoch_id=values["monitor_epoch_id"],  # type: ignore[arg-type]
        epoch_sha256=values["epoch_sha256"],  # type: ignore[arg-type]
        evaluation_sequence=values["evaluation_sequence"],  # type: ignore[arg-type]
        evaluation_id=values["evaluation_id"],  # type: ignore[arg-type]
        evaluation_record_sha256=values["evaluation_record_sha256"],  # type: ignore[arg-type]
        state_sha256=values["state_sha256"],  # type: ignore[arg-type]
        probe_status=values["probe_status"],  # type: ignore[arg-type]
        health=values["health"],  # type: ignore[arg-type]
        reason=values["reason"],  # type: ignore[arg-type]
        hard_failure_latched=values["hard_failure_latched"],  # type: ignore[arg-type]
        clock_recovery_qualified=values["clock_recovery_qualified"],  # type: ignore[arg-type]
        evaluated_at_utc=values["evaluated_at_utc"],  # type: ignore[arg-type]
        evaluated_at_monotonic_ns=values["evaluated_at_monotonic_ns"],  # type: ignore[arg-type]
        previous_anchor_sha256=values["previous_anchor_sha256"],  # type: ignore[arg-type]
        previous_anchored_host_head_sha256=values[  # type: ignore[arg-type]
            "previous_anchored_host_head_sha256"
        ],
        local_previous_host_head_sha256=values["local_previous_host_head_sha256"],  # type: ignore[arg-type]
        current_host_head_sha256=values["current_host_head_sha256"],  # type: ignore[arg-type]
    )
    payload = canonical_json_bytes(material)
    signature = crypto.sign_ed25519(
        signing_key_id=values["signing_key_id"],  # type: ignore[arg-type]
        signing_public_key_sha256=values["signing_public_key_sha256"],  # type: ignore[arg-type]
        payload=payload,
    )
    return TrustedTimeHeadAnchorRecord(
        **values,  # type: ignore[arg-type]
        semantic_sha256=hashlib.sha256(payload).hexdigest(),
        signature_ed25519=signature.hex(),
    )


@pytest.mark.parametrize(
    "identity_field",
    (
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
    ),
)
def test_cross_identity_remote_record_is_rejected(identity_field: str) -> None:
    chain = local_chain()
    foreign_chain = tuple(replace(transition, **{identity_field: "a" * 64}) for transition in chain)
    foreign_provider = MemoryProvider(
        identity=TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=foreign_chain[-1].anchor_project_identity_sha256,
            anchor_project_ref=foreign_chain[-1].anchor_project_ref,
            principal_id=foreign_chain[-1].principal_id,
            bucket_name=foreign_chain[-1].bucket_name,
        )
    )
    reconcile(foreign_chain, foreign_provider)
    _, foreign_record = only_record(foreign_provider)
    provider = MemoryProvider()
    expected_prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    expected_name = trusted_time_head_anchor_object_name(
        prefix=expected_prefix,
        anchor_sequence=foreign_record.anchor_sequence,
        signed_envelope_sha256=foreign_record.byte_sha256,
    )
    provider.objects[(BUCKET, expected_name)] = foreign_record.canonical_bytes

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="deployment"):
        reconcile(chain, provider)


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    (
        ("evaluation_id", "77777777-7777-4777-8777-77777777777f"),
        ("evaluation_record_sha256", digest(500)),
        ("state_sha256", digest(501)),
        ("probe_status", TrustedTimeProbeStatus.SOURCE_UNAVAILABLE),
        ("health", TrustedTimeHealth.BLOCKED),
        ("reason", TrustedTimeReason.SOURCE_UNAVAILABLE),
        ("hard_failure_latched", True),
        ("clock_recovery_qualified", False),
        ("evaluated_at_monotonic_ns", 4_001),
    ),
)
def test_signed_remote_state_projection_must_match_authenticated_local_head(
    field_name: str,
    changed_value: object,
) -> None:
    provider = MemoryProvider()
    reconcile(local_chain(), provider)
    object_name, record = only_record(provider)
    changed = _resign_record(record, **{field_name: changed_value})
    del provider.objects[(BUCKET, object_name)]
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    changed_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=changed.anchor_sequence,
        signed_envelope_sha256=changed.byte_sha256,
    )
    provider.objects[(BUCKET, changed_name)] = changed.canonical_bytes

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="authenticated local head"):
        reconcile(local_chain(), provider)


def test_wrong_signature_is_rejected_independently_of_object_storage() -> None:
    provider = MemoryProvider()
    reconcile(local_chain(), provider)
    object_name, record = only_record(provider)
    forged = replace(record, signature_ed25519="0" * 128)
    del provider.objects[(BUCKET, object_name)]
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    forged_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=forged.anchor_sequence,
        signed_envelope_sha256=forged.byte_sha256,
    )
    provider.objects[(BUCKET, forged_name)] = forged.canonical_bytes

    with pytest.raises(TrustedTimeHeadAnchorError, match="signature is invalid"):
        reconcile(local_chain(), provider)


def test_verifier_must_return_exact_true() -> None:
    provider = MemoryProvider()
    crypto = DeterministicEd25519TestDouble(verification_result=1)

    with pytest.raises(TrustedTimeHeadAnchorError, match="signature is invalid"):
        reconcile(local_chain(), provider, crypto=crypto)


class BytearraySigner(DeterministicEd25519TestDouble):
    def sign_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        return bytearray(  # type: ignore[return-value]
            super().sign_ed25519(
                signing_key_id=signing_key_id,
                signing_public_key_sha256=signing_public_key_sha256,
                payload=payload,
            )
        )


def test_signer_must_return_exact_64_bytes() -> None:
    provider = MemoryProvider()
    crypto = BytearraySigner()

    with pytest.raises(TrustedTimeHeadAnchorError, match="noncanonical"):
        reconcile(local_chain(), provider, crypto=crypto)


@pytest.mark.parametrize(
    ("field_name", "invalid", "message"),
    (
        ("deployment_identity_sha256", "A" * 64, "lowercase SHA-256"),
        ("runtime_database_identity_sha256", "A" * 64, "lowercase SHA-256"),
        ("anchor_project_identity_sha256", "A" * 64, "lowercase SHA-256"),
        ("policy_sha256", "f" * 64, "not admitted"),
        ("persistence_contract_version", "phase6a-v1", "unsupported"),
        ("bucket_name", "bucket/name", "exact admitted bucket"),
        ("principal_id", "NOT-A-UUID", "canonical UUID"),
        ("head_authenticated_at_utc", STARTED_AT.replace(tzinfo=None), "must be UTC"),
        (
            "head_authenticated_at_utc",
            STARTED_AT.astimezone(timezone(timedelta(hours=1))),
            "must be UTC",
        ),
        ("epoch_sequence", True, "positive signed 64-bit"),
        ("monitor_epoch_id", EPOCH_ID_V1.upper(), "canonical UUID"),
        ("evaluation_sequence", False, "non-negative signed 64-bit"),
        ("current_host_head_sha256", "f" * 63, "lowercase SHA-256"),
    ),
)
def test_local_transition_strict_scalar_validation(
    field_name: str,
    invalid: object,
    message: str,
) -> None:
    transition = local_chain()[0]

    with pytest.raises(TrustedTimeHeadAnchorError, match=message):
        replace(transition, **{field_name: invalid})


def test_local_transition_requires_consistent_evaluation_zero_nullability() -> None:
    genesis = local_chain()[0]
    evaluated = local_chain()[1]

    with pytest.raises(TrustedTimeHeadAnchorError, match="evaluation zero"):
        replace(genesis, evaluation_record_sha256=digest(50))
    with pytest.raises(TrustedTimeHeadAnchorError, match="complete state projection"):
        replace(evaluated, state_sha256=None)
    with pytest.raises(TrustedTimeHeadAnchorError, match="only at local chain genesis"):
        replace(evaluated, previous_host_head_sha256=None)


@pytest.mark.parametrize(
    "field_name",
    (
        "evaluation_id",
        "evaluation_record_sha256",
        "state_sha256",
        "probe_status",
        "health",
        "reason",
        "hard_failure_latched",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
    ),
)
def test_every_evaluated_state_projection_field_is_required(field_name: str) -> None:
    with pytest.raises(TrustedTimeHeadAnchorError, match="complete state projection"):
        replace(local_chain()[1], **{field_name: None})


@pytest.mark.parametrize(
    ("field_name", "invalid", "message"),
    (
        ("evaluation_id", EVALUATION_ID_1.upper(), "canonical UUID"),
        ("probe_status", "recorded", "exact enum"),
        ("health", "healthy", "exact enum"),
        ("reason", "within_limit", "exact enum"),
        ("hard_failure_latched", 0, "exact boolean"),
        ("clock_recovery_qualified", 1, "exact boolean"),
        ("evaluated_at_monotonic_ns", False, "non-negative signed 64-bit"),
    ),
)
def test_evaluated_state_projection_requires_exact_types(
    field_name: str,
    invalid: object,
    message: str,
) -> None:
    with pytest.raises(TrustedTimeHeadAnchorError, match=message):
        replace(local_chain()[1], **{field_name: invalid})


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda chain: list(chain), "complete exact local chain"),
        (lambda chain: (), "complete exact local chain"),
        (lambda chain: (object(),), "must be exact"),
        (lambda chain: chain[1:], "does not begin at genesis"),
        (
            lambda chain: (
                *chain[:2],
                replace(chain[2], evaluation_sequence=3),
                *chain[3:],
            ),
            "not gap-free within its epoch",
        ),
        (
            lambda chain: (
                *chain[:2],
                replace(chain[2], previous_host_head_sha256=digest(999)),
                *chain[3:],
            ),
            "predecessor conflicts",
        ),
        (
            lambda chain: (
                *chain[:2],
                replace(chain[2], deployment_identity_sha256="b" * 64),
                *chain[3:],
            ),
            "crosses deployment identity",
        ),
        (
            lambda chain: (
                *chain[:1],
                replace(chain[1], source_id="changed-within-epoch"),
                *chain[2:],
            ),
            "not gap-free within its epoch",
        ),
        (
            lambda chain: (
                *chain[:3],
                replace(chain[3], epoch_sequence=3),
                *chain[4:],
            ),
            "epoch sequence is not gap-free",
        ),
    ),
)
def test_complete_local_chain_validation_is_fail_closed(mutate: object, message: str) -> None:
    provider = MemoryProvider()
    mutation = mutate
    assert callable(mutation)

    with pytest.raises(TrustedTimeHeadAnchorError, match=message):
        reconcile(mutation(local_chain()), provider)  # type: ignore[operator, arg-type]


def test_record_round_trip_is_byte_exact_canonical_and_frozen() -> None:
    provider = MemoryProvider()
    reconcile(local_chain(), provider)
    _, record = only_record(provider)

    assert TrustedTimeHeadAnchorRecord.from_canonical_bytes(record.canonical_bytes) == record
    with pytest.raises(TrustedTimeHeadAnchorError, match="byte-exact canonical"):
        TrustedTimeHeadAnchorRecord.from_canonical_bytes(record.canonical_bytes + b"\n")
    duplicate_key = record.canonical_bytes.replace(
        b'{"type":"tuple"',
        b'{"type":"tuple","type":"tuple"',
        1,
    )
    with pytest.raises(TrustedTimeHeadAnchorError, match="duplicate JSON key"):
        TrustedTimeHeadAnchorRecord.from_canonical_bytes(duplicate_key)
    with pytest.raises(FrozenInstanceError):
        record.anchor_sequence = 9  # type: ignore[misc]


def test_remote_object_names_are_exact_gap_free_and_content_bound() -> None:
    provider = MemoryProvider()
    reconcile(local_chain(), provider)
    object_name, record = only_record(provider)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    del provider.objects[(BUCKET, object_name)]
    provider.objects[(BUCKET, f"{prefix}{2:020d}-{record.byte_sha256}.json")] = (
        record.canonical_bytes
    )

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="not gap-free"):
        reconcile(local_chain(), provider)


def test_remote_payload_and_provider_return_types_must_be_exact() -> None:
    provider = MemoryProvider()
    reconcile(local_chain(), provider)
    provider.return_list_instead_of_tuple = True
    with pytest.raises(TrustedTimeHeadAnchorError, match="exact tuple"):
        reconcile(local_chain(), provider)

    provider.return_list_instead_of_tuple = False
    provider.return_bytearray = True
    with pytest.raises(TrustedTimeHeadAnchorError, match="exact bytes"):
        reconcile(local_chain(), provider)


def test_result_cannot_be_constructed_or_used_as_authority() -> None:
    with pytest.raises(TypeError, match="issued by successful reconciliation"):
        TrustedTimeHeadAnchorReconciliationResult()


def test_upload_port_must_return_exact_none() -> None:
    provider = MemoryProvider()
    provider.upload_return = False

    with pytest.raises(TrustedTimeHeadAnchorError, match="exact null"):
        reconcile(local_chain(), provider)


def test_prepare_is_opaque_frozen_signs_once_and_never_uploads() -> None:
    provider = MemoryProvider()
    crypto = DeterministicEd25519TestDouble()

    prepared = prepare_plan(local_chain(), provider, crypto=crypto)

    assert prepared.candidate_record is not None
    assert crypto.sign_calls == 1
    assert provider.upload_calls == []
    with pytest.raises(TypeError, match="issued by preparation"):
        PreparedTrustedTimeHeadAnchorReconciliation()
    with pytest.raises(FrozenInstanceError):
        prepared.full_audit = False  # type: ignore[misc]


def test_committed_intent_evidence_cannot_be_constructed_by_a_caller() -> None:
    with pytest.raises(TypeError, match="issued by a durable repository"):
        CommittedTrustedTimeHeadAnchorIntentEvidence()


def test_provider_readback_evidence_requires_an_exact_provider_get() -> None:
    provider = MemoryProvider()
    result = reconcile(local_chain(), provider)
    record = result.anchor_records[-1]
    object_name = next(iter(provider.objects))[1]

    evidence = verify_trusted_time_head_anchor_provider_readback(
        provider=provider,
        verifier=DeterministicEd25519TestDouble(),
        anchor_intent_id="11111111-1111-4111-8111-111111111111",
        anchor_intent_semantic_sha256="a" * 64,
        record=record,
        object_name=object_name,
    )

    assert type(evidence) is TrustedTimeHeadAnchorProviderReadbackEvidence
    assert evidence.provider_identity == provider.identity
    assert evidence.object_name == object_name
    assert evidence.candidate_bytes == record.canonical_bytes
    assert provider.download_calls[-1] == (BUCKET, object_name)
    assert copy.copy(evidence) is evidence
    assert copy.deepcopy(evidence) is evidence
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(evidence)
    with pytest.raises(TypeError, match="issued by provider verification"):
        TrustedTimeHeadAnchorProviderReadbackEvidence()


def test_bounded_full_remote_audit_uses_bounded_pages_and_rejects_page_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        anchor_contract,
        "TRUSTED_TIME_HEAD_ANCHOR_FULL_AUDIT_PAGE_SIZE",
        17,
    )
    tip, provider = bounded_tip_and_provider(513)
    crypto = DeterministicEd25519TestDouble()

    prepared = prepare_bounded_trusted_time_head_anchor_reconciliation(
        tip,
        provider=provider,
        signer=crypto,
        verifier=crypto,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
        checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
        anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
        pending_anchor_intent=None,
        allow_enrollment=False,
    )

    assert prepared.candidate_record is None
    assert prepared.confirmed_anchor_count == 513
    assert len(prepared.confirmed_anchor_records) == 1
    assert len(provider.page_calls) > 2 * (513 // 17)
    assert all(call[3] == 17 for call in provider.page_calls)

    drift_tip, drifting = bounded_tip_and_provider(40)
    original_page = drifting.list_object_names_page
    page_calls = 0

    def insert_fork_after_first_page(
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        nonlocal page_calls
        page = original_page(
            bucket_name=bucket_name,
            prefix=prefix,
            offset=offset,
            limit=limit,
        )
        page_calls += 1
        if page_calls == 1:
            drifting.objects[(BUCKET, f"{prefix}{1:020d}-{'0' * 64}.json")] = next(
                iter(drifting.objects.values())
            )
        return page

    drifting.list_object_names_page = insert_fork_after_first_page  # type: ignore[method-assign]
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="drifted between pages"):
        prepare_bounded_trusted_time_head_anchor_reconciliation(
            drift_tip,
            provider=drifting,
            signer=crypto,
            verifier=crypto,
            signing_key_id=KEY_ID,
            signing_public_key_sha256=KEY_SHA256,
            checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
            checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
            anchor_authority_sha256=ANCHOR_AUTHORITY_SHA256,
            pending_anchor_intent=None,
            allow_enrollment=False,
        )


def test_candidate_completion_requires_its_exact_opaque_committed_intent() -> None:
    provider = MemoryProvider()
    prepared = prepare_plan(local_chain(), provider)

    with pytest.raises(TrustedTimeHeadAnchorError, match="committed-intent evidence"):
        complete_trusted_time_head_anchor_reconciliation(
            prepared,
            provider=provider,
            committed_intent=None,
        )
    assert provider.upload_calls == []


def test_provider_identity_is_attested_before_listing_or_signing() -> None:
    provider = MemoryProvider(
        identity=TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256="a" * 64,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            principal_id=PRINCIPAL,
            bucket_name=BUCKET,
        )
    )
    crypto = DeterministicEd25519TestDouble()

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="provider identity"):
        prepare_plan(local_chain(), provider, crypto=crypto)

    assert provider.attestation_calls == 1
    assert provider.list_calls == []
    assert provider.sequence_list_calls == []
    assert crypto.sign_calls == 0


def test_full_audit_traverses_namespace_once_and_completion_does_not_repeat_it() -> None:
    provider = MemoryProvider()
    reconcile(local_chain()[:2], provider)
    reconcile(local_chain(), provider, allow_enrollment=False)
    provider.list_calls.clear()
    provider.sequence_list_calls.clear()
    provider.download_calls.clear()

    prepared = prepare_plan(local_chain(), provider, full_audit=True)

    assert prepared.candidate_record is None
    assert len(provider.list_calls) == 1
    assert provider.sequence_list_calls == []
    assert len(provider.download_calls) == len(provider.confirmed_records)
    result = complete_trusted_time_head_anchor_reconciliation(
        prepared,
        provider=provider,
        committed_intent=None,
    )
    assert result.anchor_records == provider.confirmed_records
    assert len(provider.list_calls) == 1


def test_incremental_prepare_has_constant_terminal_and_next_sequence_work() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    for terminal_ordinal in range(1, len(chain) + 1):
        reconcile(chain[:terminal_ordinal], provider)
    provider.list_calls.clear()
    provider.sequence_list_calls.clear()
    provider.download_calls.clear()

    prepared = prepare_plan(chain, provider, full_audit=False)

    terminal_sequence = len(provider.confirmed_records)
    assert prepared.candidate_record is None
    assert provider.list_calls == []
    assert [call[2] for call in provider.sequence_list_calls] == [
        terminal_sequence,
        terminal_sequence + 1,
    ]
    assert len(provider.download_calls) == 1
    complete_trusted_time_head_anchor_reconciliation(
        prepared,
        provider=provider,
        committed_intent=None,
    )
    assert provider.list_calls == []


def test_incremental_prepare_detects_rollback_fork_and_remote_ahead() -> None:
    chain = local_chain()
    rolled_back = MemoryProvider()
    reconcile(chain[:2], rolled_back)
    rolled_back.objects.clear()
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="rolled back"):
        prepare_plan(chain, rolled_back, full_audit=False)

    forked = MemoryProvider()
    reconcile(chain[:2], forked)
    terminal = forked.confirmed_records[-1]
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    forked.objects[(BUCKET, f"{prefix}{terminal.anchor_sequence:020d}-{'f' * 64}.json")] = (
        terminal.canonical_bytes
    )
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="terminal sequence contains a fork"):
        prepare_plan(chain, forked, full_audit=False)

    ahead = MemoryProvider()
    reconcile(chain[:2], ahead)
    pending = prepare_plan(chain, ahead, full_audit=False).candidate_record
    assert pending is not None
    pending_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=pending.anchor_sequence,
        signed_envelope_sha256=pending.byte_sha256,
    )
    ahead.objects[(BUCKET, pending_name)] = pending.canonical_bytes
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="ahead"):
        prepare_plan(chain, ahead, full_audit=False)

    multiple = MemoryProvider()
    reconcile(chain[:2], multiple)
    multiple_pending = prepare_plan(chain, multiple, full_audit=False).candidate_record
    assert multiple_pending is not None
    multiple_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=multiple_pending.anchor_sequence,
        signed_envelope_sha256=multiple_pending.byte_sha256,
    )
    multiple.objects[(BUCKET, multiple_name)] = multiple_pending.canonical_bytes
    multiple.objects[
        (
            BUCKET,
            f"{prefix}{multiple_pending.anchor_sequence:020d}-{'e' * 64}.json",
        )
    ] = multiple_pending.canonical_bytes
    with pytest.raises(TrustedTimeHeadAnchorConflict, match="multiple fork candidates"):
        prepare_plan(chain, multiple, full_audit=False)


def test_completion_reattests_the_exact_provider_identity_before_upload() -> None:
    provider = MemoryProvider()
    prepared = prepare_plan(local_chain(), provider)
    evidence = committed_evidence(prepared)
    provider.identity = replace(provider.identity, anchor_project_identity_sha256="a" * 64)

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="identity changed"):
        complete_trusted_time_head_anchor_reconciliation(
            prepared,
            provider=provider,
            committed_intent=evidence,
        )

    assert provider.upload_calls == []


def test_signed_enum_material_uses_stable_values_not_python_qualnames() -> None:
    provider = MemoryProvider()
    record = reconcile(local_chain(), provider).anchor_records[-1]

    assert TrustedTimeProbeStatus.__module__.encode() not in record.signed_payload
    assert TrustedTimeHealth.__module__.encode() not in record.signed_payload
    assert TrustedTimeReason.__module__.encode() not in record.signed_payload
    assert TrustedTimeProbeStatus.RECORDED.value.encode() in record.signed_payload
    assert TrustedTimeHealth.HEALTHY.value.encode() in record.signed_payload
    assert TrustedTimeReason.WITHIN_LIMIT.value.encode() in record.signed_payload


def test_evaluated_utc_must_equal_its_head_authentication_instant() -> None:
    transition = local_chain()[1]

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="evaluated UTC instant conflicts"):
        replace(
            transition,
            evaluated_at_utc=transition.head_authenticated_at_utc + timedelta(seconds=1),
        )


def test_utc_regressing_hard_failure_transition_can_be_anchored() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain[:2], provider)
    regressed_at = STARTED_AT - timedelta(seconds=30)
    regressing_failure = replace(
        chain[-1],
        head_authenticated_at_utc=regressed_at,
        evaluated_at_utc=regressed_at,
        probe_status=TrustedTimeProbeStatus.RECORDED,
        health=TrustedTimeHealth.BLOCKED,
        reason=TrustedTimeReason.UTC_REGRESSION,
        hard_failure_latched=True,
        clock_recovery_qualified=False,
    )
    regressing_chain = (*chain[:-1], regressing_failure)

    result = reconcile(
        regressing_chain,
        provider,
        allow_enrollment=False,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.HARD_FAILURE,
    )

    anchored = result.anchor_records[-1]
    assert anchored.head_authenticated_at_utc == regressed_at
    assert anchored.evaluated_at_utc == regressed_at
    assert anchored.reason is TrustedTimeReason.UTC_REGRESSION
    assert anchored.hard_failure_latched is True
    assert anchored.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.HARD_FAILURE


def test_pending_intent_blocks_normal_successor_preparation_before_signing() -> None:
    provider = MemoryProvider()
    reconcile(local_chain()[:2], provider)
    pending = prepare_plan(local_chain()[:3], provider, full_audit=False)
    evidence = committed_evidence(pending)
    crypto = DeterministicEd25519TestDouble()

    with pytest.raises(TrustedTimeHeadAnchorConflict, match="must be recovered"):
        prepare_plan(
            local_chain(),
            provider,
            crypto=crypto,
            full_audit=False,
            pending_anchor_intent=evidence,
        )

    assert crypto.sign_calls == 0


def test_crash_before_upload_recovers_exact_pending_intent_without_resigning() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain[:2], provider)
    original = prepare_plan(chain[:3], provider, full_audit=False)
    pending = original.candidate_record
    assert pending is not None
    evidence = committed_evidence(original)
    recovery_crypto = DeterministicEd25519TestDouble()

    recovered = prepare_persisted_trusted_time_head_anchor_intent_recovery(
        chain,
        provider.confirmed_records,
        pending_record=pending,
        committed_intent=evidence,
        provider=provider,
        verifier=recovery_crypto,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        full_audit=False,
    )
    result = complete_trusted_time_head_anchor_reconciliation(
        recovered,
        provider=provider,
        committed_intent=evidence,
    )

    assert recovery_crypto.sign_calls == 0
    assert result.anchor_records[-1] == pending
    assert result.current_host_head_sha256 == chain[2].current_host_head_sha256
    assert result.local_transition_count == len(chain)
    assert result.uploaded_anchor_count == 1


def test_upload_before_receipt_recovers_as_exact_idempotent_duplicate() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain[:2], provider)
    original = prepare_plan(chain[:3], provider, full_audit=False)
    pending = original.candidate_record
    assert pending is not None
    evidence = committed_evidence(original)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST,
    )
    object_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=pending.anchor_sequence,
        signed_envelope_sha256=pending.byte_sha256,
    )
    provider.objects[(BUCKET, object_name)] = pending.canonical_bytes

    recovered = prepare_persisted_trusted_time_head_anchor_intent_recovery(
        chain,
        provider.confirmed_records,
        pending_record=pending,
        committed_intent=evidence,
        provider=provider,
        verifier=DeterministicEd25519TestDouble(),
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        full_audit=False,
    )
    result = complete_trusted_time_head_anchor_reconciliation(
        recovered,
        provider=provider,
        committed_intent=evidence,
    )

    assert result.uploaded_anchor_count == 0
    assert result.idempotent_duplicate_count == 1
    assert result.anchor_records[-1] == pending


def test_recovered_pending_anchor_can_precede_later_authenticated_local_heads() -> None:
    chain = local_chain()
    provider = MemoryProvider()
    reconcile(chain[:2], provider)
    original = prepare_plan(chain[:3], provider, full_audit=False)
    pending = original.candidate_record
    assert pending is not None
    evidence = committed_evidence(original)

    recovered = prepare_persisted_trusted_time_head_anchor_intent_recovery(
        chain,
        provider.confirmed_records,
        pending_record=pending,
        committed_intent=evidence,
        provider=provider,
        verifier=DeterministicEd25519TestDouble(),
        signing_key_id=KEY_ID,
        signing_public_key_sha256=KEY_SHA256,
        full_audit=False,
    )
    recovered_result = complete_trusted_time_head_anchor_reconciliation(
        recovered,
        provider=provider,
        committed_intent=evidence,
    )
    provider.confirmed_records = recovered_result.anchor_records

    successor = reconcile(chain, provider, allow_enrollment=False, full_audit=False)

    assert recovered_result.current_host_head_sha256 == chain[2].current_host_head_sha256
    assert successor.current_host_head_sha256 == chain[-1].current_host_head_sha256
    assert successor.anchor_records[-1].previous_anchor_sha256 == pending.byte_sha256
