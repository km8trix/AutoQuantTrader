from __future__ import annotations

import copy
import hashlib
import pickle
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from apps.trusted_time_supervisor.head_anchor_attempt import (
    RepositoryBackedTrustedTimeHeadAnchorAttempt,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
)
from packages.application import trusted_time_head_anchor as anchor_contract
from packages.application.durable_trusted_time_monitor import (
    DurableTrustedTimeEpochSession,
    run_durable_trusted_time_probe_once,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    AuthenticatedTrustedTimeHeadTransition,
    TrustedTimeHeadAnchorProviderIdentity,
    TrustedTimeHeadAnchorProviderReadbackEvidence,
    TrustedTimeHeadAnchorRecord,
    prepare_trusted_time_head_anchor_reconciliation,
    verify_trusted_time_head_anchor_provider_readback,
)
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from packages.persistence import trusted_time_head_anchor as anchor_persistence
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
)
from packages.persistence.trusted_time import SqlTrustedTimeRepository
from packages.persistence.trusted_time_head_anchor import (
    PersistedTrustedTimeHeadAnchorIntent,
    SqlTrustedTimeHeadAnchorRepository,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorPersistenceConflict,
    TrustedTimeHeadAnchorPersistenceError,
    TrustedTimeHeadAnchorSnapshotAdvanced,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
DEPLOYMENT_IDENTITY = "1" * 64
RUNTIME_DATABASE_IDENTITY = "2" * 64
ANCHOR_PROJECT_IDENTITY = "3" * 64
ANCHOR_PROJECT_REF = "abcdefghijklmnopqrst"
SOURCE_AUTHORITY = "4" * 64
ANCHOR_AUTHORITY = "5" * 64
PRINCIPAL_ID = "11111111-1111-4111-8111-111111111111"
HOST_ID = "aqt-local-paper-host"
SOURCE_ID = "chrony-nts-system76-virginia-v2"
SIGNING_KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
SIGNING_PUBLIC_KEY_BYTES = b"phase6-sequence2-integration-key!"[:32]
SIGNING_PUBLIC_KEY_SHA256 = hashlib.sha256(SIGNING_PUBLIC_KEY_BYTES).hexdigest()


class DeterministicVerifier:
    key = b"trusted-time-anchor-test-key"

    def _signature(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        return hashlib.sha512(
            self.key
            + signing_key_id.encode("utf-8")
            + signing_public_key_sha256.encode("ascii")
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
        return signature == self._signature(
            signing_key_id=signing_key_id,
            signing_public_key_sha256=signing_public_key_sha256,
            payload=payload,
        )


VERIFIER = DeterministicVerifier()


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self._values = list(values)

    def __call__(self) -> object:
        if not self._values:
            raise RuntimeError("clock exhausted")
        return self._values.pop(0)


class TrustedSource:
    def __init__(self, reading: TrustedTimeSourceReading) -> None:
        self._reading = reading

    def read_trusted_time(self, *, deadline_monotonic_ns: int) -> object:
        assert deadline_monotonic_ns >= 1_000_000_000
        return self._reading


class EmptyAnchorProvider:
    def __init__(self) -> None:
        self.calls = 0

    def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity:
        self.calls += 1
        return TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            principal_id=PRINCIPAL_ID,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        )

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]:
        self.calls += 1
        assert bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        assert prefix.endswith("/")
        return ()

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        self.calls += 1
        assert bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        assert prefix.endswith("/")
        assert anchor_sequence > 0
        return ()

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        self.calls += 1
        raise AssertionError(f"unexpected download from {bucket_name}/{object_name}")

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None:
        self.calls += 1
        raise AssertionError(f"unexpected upload to {bucket_name}/{object_name} as {content_type}")


class ExactReadbackProvider(EmptyAnchorProvider):
    def __init__(
        self,
        intent: PersistedTrustedTimeHeadAnchorIntent,
        *,
        identity: TrustedTimeHeadAnchorProviderIdentity | None = None,
        payload: bytes | None = None,
    ) -> None:
        super().__init__()
        self._intent = intent
        self._identity = identity
        self._payload = intent.signed_envelope_bytes if payload is None else payload

    def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity:
        self.calls += 1
        if self._identity is not None:
            return self._identity
        return TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            principal_id=PRINCIPAL_ID,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        )

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        self.calls += 1
        assert bucket_name == self._intent.record.bucket_name
        assert object_name == self._intent.object_name
        return self._payload


class ImmutableHistoryProvider(EmptyAnchorProvider):
    def __init__(self, intents: tuple[PersistedTrustedTimeHeadAnchorIntent, ...]) -> None:
        super().__init__()
        self._objects = {intent.object_name: intent.signed_envelope_bytes for intent in intents}
        self.upload_calls = 0

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]:
        self.calls += 1
        assert bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        return tuple(sorted(name for name in self._objects if name.startswith(prefix)))

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        names = self.list_object_names(bucket_name=bucket_name, prefix=prefix)
        return names[offset : offset + limit]

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        self.calls += 1
        assert bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        sequence_prefix = f"{prefix}{anchor_sequence:020d}-"
        return tuple(sorted(name for name in self._objects if name.startswith(sequence_prefix)))

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        self.calls += 1
        assert bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        return self._objects[object_name]

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None:
        self.upload_calls += 1
        raise AssertionError(f"unexpected upload to {bucket_name}/{object_name} as {content_type}")


@dataclass(frozen=True, slots=True)
class System:
    engine: Engine
    trusted_time: SqlTrustedTimeRepository
    anchors: SqlTrustedTimeHeadAnchorRepository


def _config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _anchor_repository(engine: Engine) -> SqlTrustedTimeHeadAnchorRepository:
    return SqlTrustedTimeHeadAnchorRepository(
        engine,
        verifier=VERIFIER,
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
    )


@pytest.fixture
def system(tmp_path: Path) -> Iterator[System]:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6d-anchors.sqlite'}"
    command.upgrade(_config(database_url), "head")
    engine = create_database_engine(database_url)
    value = System(
        engine=engine,
        trusted_time=SqlTrustedTimeRepository(engine),
        anchors=_anchor_repository(engine),
    )
    yield value
    engine.dispose()


def _register_epoch(
    system: System,
    *,
    recorded_at: datetime,
) -> DurableTrustedTimeEpochSession:
    return system.trusted_time.register_new_epoch(
        source_id=SOURCE_ID,
        source_authority_sha256=SOURCE_AUTHORITY,
        host_id=HOST_ID,
        recorded_at=recorded_at,
    )


def _local_chain(engine: Engine) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    return SqlTrustedTimeRepository(engine).read_authenticated_head_transitions(
        host_id=HOST_ID,
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=PRINCIPAL_ID,
    )


def _load_startup(system: System) -> anchor_persistence.TrustedTimeHeadAnchorPersistenceSnapshot:
    return system.anchors.load_head_anchor_startup_snapshot(
        host_id=HOST_ID,
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=PRINCIPAL_ID,
    )


def _attempt_authority() -> TrustedTimeHeadAnchorAuthority:
    return TrustedTimeHeadAnchorAuthority(
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST_ID,
        source_authority_sha256=SOURCE_AUTHORITY,
        runtime_database_project_ref="bcdefghijklmnopqrstu",
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        anchor_project_url=f"https://{ANCHOR_PROJECT_REF}.supabase.co",
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=PRINCIPAL_ID,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        signing_public_key_bytes=SIGNING_PUBLIC_KEY_BYTES,
    )


def _append_probe(
    system: System,
    session: DurableTrustedTimeEpochSession,
    *,
    observed_at: datetime,
    monotonic_ns: int,
) -> None:
    reading = TrustedTimeSourceReading(
        source_id=session.binding.source_id,
        source_authority_sha256=session.binding.source_authority_sha256,
        local_observed_at_utc=observed_at,
        trusted_at_utc=observed_at,
        observed_at_monotonic_ns=monotonic_ns,
        source_uncertainty_milliseconds=Decimal("0"),
        source_evidence_sha256="9" * 64,
    )
    run_durable_trusted_time_probe_once(
        session,
        repository=system.trusted_time,
        source=TrustedSource(reading),  # type: ignore[arg-type]
        utc_clock=SequenceClock(observed_at, observed_at),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(monotonic_ns, monotonic_ns),  # type: ignore[arg-type]
    )


def _signed_record(
    transition: AuthenticatedTrustedTimeHeadTransition,
    *,
    previous: TrustedTimeHeadAnchorRecord | None,
) -> TrustedTimeHeadAnchorRecord:
    return anchor_contract._sign_record(
        transition,
        anchor_sequence=1 if previous is None else previous.anchor_sequence + 1,
        previous=previous,
        checkpoint_reason=(
            TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
            if previous is None
            else TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
        ),
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        signer=VERIFIER,
        verifier=VERIFIER,
    )


def _prepare_enrollment(
    system: System,
    chain: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
) -> PersistedTrustedTimeHeadAnchorIntent:
    return system.anchors.prepare_or_read_pending(
        chain,
        record=_signed_record(chain[-1], previous=None),
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        created_at=chain[-1].head_authenticated_at_utc,
        allow_enrollment=True,
    )


def _provider_readback(
    intent: PersistedTrustedTimeHeadAnchorIntent,
    *,
    provider: ExactReadbackProvider | None = None,
) -> TrustedTimeHeadAnchorProviderReadbackEvidence:
    exact_provider = ExactReadbackProvider(intent) if provider is None else provider
    return verify_trusted_time_head_anchor_provider_readback(
        provider=exact_provider,
        verifier=VERIFIER,
        anchor_intent_id=intent.anchor_intent_id,
        anchor_intent_semantic_sha256=intent.semantic_sha256,
        record=intent.record,
        object_name=intent.object_name,
    )


def test_sequence_two_observer_accepts_real_compact_startup_snapshots(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    first_chain = _local_chain(system.engine)
    first_intent = _prepare_enrollment(system, first_chain)
    system.anchors.confirm_remote_readback(
        first_chain,
        intent=first_intent,
        provider_readback=_provider_readback(first_intent),
        observed_at=BASE + timedelta(seconds=1),
    )

    second_session = _register_epoch(system, recorded_at=BASE + timedelta(seconds=2))
    second_chain = _local_chain(system.engine)
    second_intent = system.anchors.prepare_or_read_pending(
        second_chain,
        record=_signed_record(second_chain[-1], previous=first_intent.record),
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        created_at=BASE + timedelta(seconds=2),
    )
    system.anchors.confirm_remote_readback(
        second_chain,
        intent=second_intent,
        provider_readback=_provider_readback(second_intent),
        observed_at=BASE + timedelta(seconds=3),
    )
    _append_probe(
        system,
        second_session,
        observed_at=BASE + timedelta(seconds=4),
        monotonic_ns=4_000_000_000,
    )

    startup = _load_startup(system)
    assert startup.complete_replay is True
    assert startup.confirmed_anchor_count == 2
    assert startup.confirmed_anchor_records == ()
    assert startup.authenticated_journal_tip.confirmed_anchor_local_transition_ordinal == 2
    system.anchors.discard_head_anchor_snapshot(startup)

    provider = ImmutableHistoryProvider((first_intent, second_intent))
    attempt = RepositoryBackedTrustedTimeHeadAnchorAttempt(
        anchor_repository=system.anchors,
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        authority=_attempt_authority(),
        utc_clock=lambda: BASE + timedelta(seconds=5),
    )
    try:
        attempt.prime_startup()
        observed = attempt.reauthenticate_post_enrollment_start_successor()
    finally:
        attempt.close()

    assert observed.anchor_sequence == 2
    assert observed.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
    assert observed.confirmed_anchor_count == 2
    assert observed.local_transition_count == 3
    assert observed.confirmed_anchor_local_transition_ordinal == 2
    assert observed.remote_object_count == 2
    assert observed.predecessor_anchor_sha256 == first_intent.record.byte_sha256
    assert observed.current_anchor_sha256 == second_intent.record.byte_sha256
    assert observed.current_host_head_sha256 == second_intent.record.current_host_head_sha256
    assert provider.upload_calls == 0


def test_enrollment_defaults_closed_and_prepare_commits_exact_pending_bytes(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    record = _signed_record(chain[-1], previous=None)

    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="enrollment permission",
    ):
        system.anchors.prepare_or_read_pending(
            chain,
            record=record,
            checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
            created_at=BASE,
        )

    intent = _prepare_enrollment(system, chain)
    assert intent.record == record
    assert intent.signed_envelope_bytes == record.canonical_bytes
    assert intent.signed_envelope_text.encode("utf-8") == record.canonical_bytes
    assert intent.signed_envelope_sha256 == record.byte_sha256
    assert intent.object_name.endswith(f"-{record.byte_sha256}.json")
    assert len(intent.object_name) == 223
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_intents)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_receipts)
            )
            == 0
        )

    restarted = _anchor_repository(system.engine)
    assert restarted.read_pending(chain) == intent
    assert restarted.read_confirmed_anchor_records(chain) == ()
    evidence = restarted.issue_committed_intent_evidence(chain, intent=intent)
    assert evidence.intent_id == intent.anchor_intent_id
    assert evidence.signed_envelope_sha256 == intent.signed_envelope_sha256
    assert evidence.semantic_sha256 == intent.record.semantic_sha256
    assert evidence.anchor_project_ref == ANCHOR_PROJECT_REF


def test_application_intent_journal_port_commits_before_any_provider_io(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    provider_calls_after_prepare = provider.calls

    evidence = system.anchors.commit_trusted_time_head_anchor_intent(prepared=prepared)

    assert provider.calls == provider_calls_after_prepare
    pending_with_evidence = system.anchors.read_pending_with_committed_evidence(chain)
    assert pending_with_evidence is not None
    pending, recovered_evidence = pending_with_evidence
    assert pending.record == prepared.candidate_record
    assert recovered_evidence == evidence


def test_compact_snapshot_refreshes_only_local_and_anchor_suffixes(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    first_chain = _local_chain(system.engine)
    startup = _load_startup(system)

    assert startup.complete_replay is True
    assert startup.local_transitions == ()
    assert startup.local_transition_count == 1
    assert startup.confirmed_anchor_count == 0
    assert startup.pending_intent is None
    assert startup.authenticated_journal_tip.current_transition == first_chain[-1]

    compact = system.anchors.compact_head_anchor_snapshot(startup)
    assert compact.local_transitions == ()
    assert compact.confirmed_anchor_records == ()
    assert system.anchors.refresh_head_anchor_snapshot(compact) is compact
    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict, match="stale or foreign"):
        system.anchors.refresh_head_anchor_snapshot(startup)

    _register_epoch(system, recorded_at=BASE + timedelta(seconds=1))

    def reject_full_replay(*args: object, **kwargs: object) -> None:
        raise AssertionError("compact snapshot refresh attempted a full replay")

    monkeypatch.setattr(anchor_persistence, "_verify_global_integrity", reject_full_replay)
    monkeypatch.setattr(anchor_persistence, "_verified_host", reject_full_replay)
    advanced = system.anchors.refresh_head_anchor_snapshot(compact)
    assert advanced.local_transition_count == 2
    assert len(advanced.local_transitions) == 1
    assert advanced.local_transitions[0].previous_host_head_sha256 == (
        first_chain[-1].current_host_head_sha256
    )

    monkeypatch.undo()
    advanced_chain = _local_chain(system.engine)
    pending = _prepare_enrollment(system, advanced_chain)
    monkeypatch.setattr(anchor_persistence, "_verify_global_integrity", reject_full_replay)
    monkeypatch.setattr(anchor_persistence, "_verified_host", reject_full_replay)
    with_pending = system.anchors.refresh_head_anchor_snapshot(advanced)
    assert with_pending.pending_intent == pending
    assert with_pending.committed_pending_evidence is not None
    assert with_pending.confirmed_anchor_count == 0

    monkeypatch.undo()
    system.anchors.confirm_remote_readback(
        advanced_chain,
        intent=pending,
        provider_readback=_provider_readback(pending),
        observed_at=BASE + timedelta(seconds=2),
    )
    monkeypatch.setattr(anchor_persistence, "_verify_global_integrity", reject_full_replay)
    monkeypatch.setattr(anchor_persistence, "_verified_host", reject_full_replay)
    confirmed = system.anchors.refresh_head_anchor_snapshot(with_pending)
    assert confirmed.pending_intent is None
    assert confirmed.confirmed_anchor_records == (pending.record,)
    assert confirmed.confirmed_anchor_count == 1
    assert confirmed.authenticated_journal_tip.confirmed_anchor_tip == pending.record


def test_compact_snapshot_commit_and_confirmation_return_exact_proof_without_provider_io(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    provider_calls = provider.calls
    startup = _load_startup(system)

    def reject_full_replay(*args: object, **kwargs: object) -> None:
        raise AssertionError("compact mutation attempted a full replay")

    monkeypatch.setattr(anchor_persistence, "_verify_global_integrity", reject_full_replay)
    monkeypatch.setattr(anchor_persistence, "_verified_host", reject_full_replay)
    pending, evidence = system.anchors.commit_prepared_intent(
        startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )

    assert provider.calls == provider_calls
    assert pending.pending_intent is not None
    assert pending.committed_pending_evidence == evidence
    assert evidence.intent_id == pending.pending_intent.anchor_intent_id
    assert pending.confirmed_anchor_count == 0
    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict, match="stale or foreign"):
        system.anchors.refresh_head_anchor_snapshot(startup)

    confirmation_proof = _provider_readback(pending.pending_intent)
    copied_confirmation_proof = copy.copy(confirmation_proof)
    assert copied_confirmation_proof is confirmation_proof
    confirmed, receipt = system.anchors.confirm_remote_readback_from_snapshot(
        pending,
        intent=pending.pending_intent,
        provider_readback=confirmation_proof,
        observed_at_utc=BASE + timedelta(seconds=1),
    )

    assert provider.calls == provider_calls
    assert confirmed.pending_intent is None
    assert confirmed.confirmed_anchor_count == 1
    assert confirmed.confirmed_anchor_records == (pending.pending_intent.record,)
    assert receipt.intent == pending.pending_intent
    assert receipt.readback_bytes_sha256 == pending.pending_intent.signed_envelope_sha256
    assert confirmed.authenticated_journal_tip.confirmed_anchor_tip == (
        pending.pending_intent.record
    )
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="already consumed",
    ):
        system.anchors.confirm_remote_readback_from_snapshot(
            confirmed,
            intent=pending.pending_intent,
            provider_readback=copied_confirmation_proof,
            observed_at_utc=BASE + timedelta(seconds=8),
        )

    idempotent_proof = _provider_readback(pending.pending_intent)
    deepcopied_idempotent_proof = copy.deepcopy(idempotent_proof)
    assert deepcopied_idempotent_proof is idempotent_proof
    repeated_snapshot, repeated_receipt = system.anchors.confirm_remote_readback_from_snapshot(
        confirmed,
        intent=pending.pending_intent,
        provider_readback=deepcopied_idempotent_proof,
        observed_at_utc=BASE + timedelta(seconds=9),
    )
    assert repeated_snapshot is confirmed
    assert repeated_receipt == receipt
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="already consumed",
    ):
        system.anchors.confirm_remote_readback_from_snapshot(
            confirmed,
            intent=pending.pending_intent,
            provider_readback=idempotent_proof,
            observed_at_utc=BASE + timedelta(seconds=10),
        )
    system.anchors.discard_head_anchor_snapshot(confirmed)
    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict, match="stale or foreign"):
        system.anchors.refresh_head_anchor_snapshot(confirmed)


def test_provider_readback_claim_is_atomic_across_two_repository_threads(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=EmptyAnchorProvider(),
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    first_startup = _load_startup(system)
    first_pending, _ = system.anchors.commit_prepared_intent(
        first_startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    intent = first_pending.pending_intent
    assert intent is not None

    second_repository = _anchor_repository(system.engine)
    second_pending = _load_startup(
        System(
            engine=system.engine,
            trusted_time=system.trusted_time,
            anchors=second_repository,
        )
    )
    assert second_pending.pending_intent == intent
    proof = _provider_readback(intent)
    barrier = threading.Barrier(2)

    def confirm(
        repository: SqlTrustedTimeHeadAnchorRepository,
        snapshot: anchor_persistence.TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> object:
        barrier.wait(timeout=5)
        try:
            return repository.confirm_remote_readback_from_snapshot(
                snapshot,
                intent=intent,
                provider_readback=copy.copy(proof),
                observed_at_utc=BASE + timedelta(seconds=1),
            )
        except TrustedTimeHeadAnchorPersistenceConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(confirm, system.anchors, first_pending),
            executor.submit(confirm, second_repository, second_pending),
        )
        results = tuple(future.result(timeout=10) for future in futures)

    accepted = tuple(result for result in results if type(result) is tuple)
    rejected = tuple(
        result for result in results if type(result) is TrustedTimeHeadAnchorPersistenceConflict
    )
    assert len(accepted) == 1
    assert len(rejected) == 1
    assert "already consumed or is in use" in str(rejected[0])
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_receipts)
            )
            == 1
        )


def test_compact_pending_confirmation_survives_local_head_advance(
    system: System,
) -> None:
    session = _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    startup = _load_startup(system)
    pending_snapshot, _ = system.anchors.commit_prepared_intent(
        startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    pending = pending_snapshot.pending_intent
    assert pending is not None

    _append_probe(
        system,
        session,
        observed_at=BASE + timedelta(seconds=20),
        monotonic_ns=20_000_000_000,
    )
    advanced = system.anchors.refresh_head_anchor_snapshot(pending_snapshot)
    assert advanced.local_transition_count == 2
    assert advanced.pending_intent == pending

    confirmed, _ = system.anchors.confirm_remote_readback_from_snapshot(
        advanced,
        intent=pending,
        provider_readback=_provider_readback(pending),
        observed_at_utc=BASE + timedelta(seconds=21),
    )
    tip = confirmed.authenticated_journal_tip
    assert tip.local_transition_count == 2
    assert tip.confirmed_anchor_count == 1
    assert tip.confirmed_anchor_local_transition_ordinal == 1
    assert tip.current_transition.current_host_head_sha256 != (
        pending.record.current_host_head_sha256
    )


def test_compact_commit_classifies_an_authenticated_probe_append_as_advanced(
    system: System,
) -> None:
    session = _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    provider_calls = provider.calls
    startup = _load_startup(system)

    _append_probe(
        system,
        session,
        observed_at=BASE + timedelta(seconds=20),
        monotonic_ns=20_000_000_000,
    )

    with pytest.raises(TrustedTimeHeadAnchorSnapshotAdvanced) as captured:
        system.anchors.commit_prepared_intent(
            startup,
            prepared=prepared,
            created_at_utc=BASE,
            allow_enrollment=True,
        )

    assert type(captured.value) is TrustedTimeHeadAnchorSnapshotAdvanced
    assert captured.value.refreshed_snapshot is None
    assert provider.calls == provider_calls
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_intents)
            )
            == 0
        )
    advanced = system.anchors.refresh_head_anchor_snapshot(startup)
    assert advanced.local_transition_count == 2
    assert len(advanced.local_transitions) == 1
    assert advanced.local_transitions[0].evaluation_sequence == 1


def test_confirmation_race_returns_the_live_refreshed_snapshot_for_retry(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    startup = _load_startup(system)
    pending_snapshot, _ = system.anchors.commit_prepared_intent(
        startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    pending = pending_snapshot.pending_intent
    assert pending is not None

    _append_probe(
        system,
        session,
        observed_at=BASE + timedelta(seconds=20),
        monotonic_ns=20_000_000_000,
    )
    original_write_transaction = anchor_persistence._write_transaction
    injected = False

    @contextmanager
    def append_before_first_cas(engine: Engine) -> Iterator[Connection]:
        nonlocal injected
        if not injected:
            injected = True
            _append_probe(
                system,
                session,
                observed_at=BASE + timedelta(seconds=40),
                monotonic_ns=40_000_000_000,
            )
        with original_write_transaction(engine) as connection:
            yield connection

    monkeypatch.setattr(
        anchor_persistence,
        "_write_transaction",
        append_before_first_cas,
    )
    provider_readback = _provider_readback(pending)
    with pytest.raises(TrustedTimeHeadAnchorSnapshotAdvanced) as captured:
        system.anchors.confirm_remote_readback_from_snapshot(
            pending_snapshot,
            intent=pending,
            provider_readback=provider_readback,
            observed_at_utc=BASE + timedelta(seconds=41),
        )

    assert type(captured.value) is TrustedTimeHeadAnchorSnapshotAdvanced
    retry_snapshot = captured.value.refreshed_snapshot
    assert retry_snapshot is not None
    assert retry_snapshot is not pending_snapshot
    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict, match="stale or foreign"):
        system.anchors.refresh_head_anchor_snapshot(pending_snapshot)
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_receipts)
            )
            == 0
        )

    monkeypatch.setattr(
        anchor_persistence,
        "_write_transaction",
        original_write_transaction,
    )
    confirmed, receipt = system.anchors.confirm_remote_readback_from_snapshot(
        retry_snapshot,
        intent=pending,
        provider_readback=provider_readback,
        observed_at_utc=BASE + timedelta(seconds=42),
    )
    assert receipt.intent == pending
    assert confirmed.local_transition_count == 3
    assert confirmed.authenticated_journal_tip.confirmed_anchor_count == 1
    assert confirmed.authenticated_journal_tip.confirmed_anchor_local_transition_ordinal == 1


def test_startup_snapshot_streams_history_without_retaining_a_replay_batch(
    system: System,
) -> None:
    session = _register_epoch(system, recorded_at=BASE)
    _append_probe(
        system,
        session,
        observed_at=BASE + timedelta(seconds=20),
        monotonic_ns=20_000_000_000,
    )

    current = _load_startup(system)
    assert current.local_transition_count == 2
    assert current.local_transitions == ()
    assert current.confirmed_anchor_records == ()
    assert current.complete_replay is True
    assert current.current_host_head_sha256 == (
        _local_chain(system.engine)[-1].current_host_head_sha256
    )


def test_compact_mutations_reauthenticate_exact_local_and_pending_rows(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    startup = _load_startup(system)
    pending_snapshot, _ = system.anchors.commit_prepared_intent(
        startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    pending = pending_snapshot.pending_intent
    assert pending is not None
    secret_marker = "operator-secret-must-not-be-echoed"
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase6_trusted_time_head_anchor_intents)
            .where(
                phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                == pending.anchor_intent_id
            )
            .values(canonical_payload=secret_marker)
        )

    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict) as captured:
        system.anchors.commit_prepared_intent(
            pending_snapshot,
            prepared=prepared,
            created_at_utc=BASE + timedelta(seconds=1),
            allow_enrollment=True,
        )
    assert type(captured.value) is TrustedTimeHeadAnchorPersistenceConflict
    assert secret_marker not in str(captured.value)


def test_compact_commit_rejects_local_head_canonical_tampering_as_a_conflict(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    startup = _load_startup(system)
    secret_marker = "{}"
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase6_trusted_time_host_heads)
            .where(phase6_trusted_time_host_heads.c.host_id == HOST_ID)
            .values(canonical_payload=secret_marker)
        )

    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict) as captured:
        system.anchors.commit_prepared_intent(
            startup,
            prepared=prepared,
            created_at_utc=BASE,
            allow_enrollment=True,
        )
    assert type(captured.value) is TrustedTimeHeadAnchorPersistenceConflict


def test_compact_refresh_rejects_terminal_receipt_canonical_tampering(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    provider = EmptyAnchorProvider()
    prepared = prepare_trusted_time_head_anchor_reconciliation(
        chain,
        (),
        provider=provider,
        signer=VERIFIER,
        verifier=VERIFIER,
        signing_key_id=SIGNING_KEY_ID,
        signing_public_key_sha256=SIGNING_PUBLIC_KEY_SHA256,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        pending_anchor_intent=None,
        full_audit=True,
        allow_enrollment=True,
    )
    startup = _load_startup(system)
    pending_snapshot, _ = system.anchors.commit_prepared_intent(
        startup,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    pending = pending_snapshot.pending_intent
    assert pending is not None
    confirmed, receipt = system.anchors.confirm_remote_readback_from_snapshot(
        pending_snapshot,
        intent=pending,
        provider_readback=_provider_readback(pending),
        observed_at_utc=BASE + timedelta(seconds=1),
    )
    secret_marker = "operator-secret-must-not-be-echoed"
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase6_trusted_time_head_anchor_receipts)
            .where(
                phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id
                == receipt.anchor_receipt_id
            )
            .values(canonical_payload=secret_marker)
        )

    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict) as captured:
        system.anchors.refresh_head_anchor_snapshot(confirmed)
    assert type(captured.value) is TrustedTimeHeadAnchorPersistenceConflict
    assert secret_marker not in str(captured.value)


def test_pending_intent_is_resumed_after_local_head_advances_and_blocks_successor(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    first_chain = _local_chain(system.engine)
    first_intent = _prepare_enrollment(system, first_chain)

    _register_epoch(system, recorded_at=BASE + timedelta(seconds=1))
    advanced_chain = _local_chain(system.engine)
    successor = _signed_record(
        advanced_chain[-1],
        previous=first_intent.record,
    )
    recovered = system.anchors.prepare_or_read_pending(
        advanced_chain,
        record=successor,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        created_at=BASE + timedelta(seconds=1),
    )

    assert recovered == first_intent
    assert recovered.record.current_host_head_sha256 == first_chain[-1].current_host_head_sha256
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_intents)
            )
            == 1
        )

    receipt = system.anchors.confirm_remote_readback(
        advanced_chain,
        intent=recovered,
        provider_readback=_provider_readback(recovered),
        observed_at=BASE + timedelta(seconds=2),
    )
    assert receipt.intent == first_intent
    assert system.anchors.read_pending(advanced_chain) is None
    assert system.anchors.read_confirmed_anchor_records(advanced_chain) == (first_intent.record,)


def test_exact_confirmation_is_idempotent_and_confirmed_prefix_reconstructs_records(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    first_chain = _local_chain(system.engine)
    first_intent = _prepare_enrollment(system, first_chain)

    with pytest.raises(TypeError, match="issued by provider verification"):
        TrustedTimeHeadAnchorProviderReadbackEvidence()
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceError,
        match="requires exact provider-readback evidence",
    ):
        system.anchors.confirm_remote_readback(
            first_chain,
            intent=first_intent,
            provider_readback=first_intent.signed_envelope_bytes,  # type: ignore[arg-type]
            observed_at=BASE + timedelta(seconds=1),
        )
    with pytest.raises(anchor_contract.TrustedTimeHeadAnchorConflict, match="object name"):
        verify_trusted_time_head_anchor_provider_readback(
            provider=ExactReadbackProvider(first_intent),
            verifier=VERIFIER,
            anchor_intent_id=first_intent.anchor_intent_id,
            anchor_intent_semantic_sha256=first_intent.semantic_sha256,
            record=first_intent.record,
            object_name=f"{first_intent.object_name}.substituted",
        )
    substituted_identity = TrustedTimeHeadAnchorProviderIdentity(
        anchor_project_identity_sha256="a" * 64,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        principal_id=PRINCIPAL_ID,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    )
    with pytest.raises(anchor_contract.TrustedTimeHeadAnchorConflict, match="identity"):
        _provider_readback(
            first_intent,
            provider=ExactReadbackProvider(
                first_intent,
                identity=substituted_identity,
            ),
        )

    with pytest.raises(anchor_contract.TrustedTimeHeadAnchorConflict, match="bytes conflict"):
        _provider_readback(
            first_intent,
            provider=ExactReadbackProvider(
                first_intent,
                payload=first_intent.signed_envelope_bytes + b" ",
            ),
        )

    pickle_rejected = _provider_readback(first_intent)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(pickle_rejected)

    tampered_cell = _provider_readback(first_intent)
    object.__setattr__(tampered_cell, "_consumption_cell", object())
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="evidence is invalid",
    ):
        system.anchors.confirm_remote_readback(
            first_chain,
            intent=first_intent,
            provider_readback=tampered_cell,
            observed_at=BASE + timedelta(seconds=1),
        )

    first_proof = _provider_readback(first_intent)
    copied_first_proof = copy.copy(first_proof)
    assert copied_first_proof is first_proof
    first_receipt = system.anchors.confirm_remote_readback(
        first_chain,
        intent=first_intent,
        provider_readback=first_proof,
        observed_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="already consumed",
    ):
        system.anchors.confirm_remote_readback(
            first_chain,
            intent=first_intent,
            provider_readback=copied_first_proof,
            observed_at=BASE + timedelta(seconds=9),
        )
    idempotent_proof = _provider_readback(first_intent)
    deepcopied_idempotent_proof = copy.deepcopy(idempotent_proof)
    assert deepcopied_idempotent_proof is idempotent_proof
    repeated = system.anchors.confirm_remote_readback(
        first_chain,
        intent=first_intent,
        provider_readback=deepcopied_idempotent_proof,
        observed_at=BASE + timedelta(seconds=9),
    )
    assert repeated == first_receipt
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="already consumed",
    ):
        system.anchors.confirm_remote_readback(
            first_chain,
            intent=first_intent,
            provider_readback=idempotent_proof,
            observed_at=BASE + timedelta(seconds=10),
        )

    _register_epoch(system, recorded_at=BASE + timedelta(seconds=10))
    second_chain = _local_chain(system.engine)
    second_record = _signed_record(second_chain[-1], previous=first_intent.record)
    second_intent = system.anchors.prepare_or_read_pending(
        second_chain,
        record=second_record,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        created_at=BASE + timedelta(seconds=10),
    )
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="conflicts with the durable intent",
    ):
        system.anchors.confirm_remote_readback(
            second_chain,
            intent=second_intent,
            provider_readback=_provider_readback(first_intent),
            observed_at=BASE + timedelta(seconds=11),
        )
    assert system.anchors.read_confirmed_anchor_records(second_chain) == (first_intent.record,)
    second_receipt = system.anchors.confirm_remote_readback(
        second_chain,
        intent=second_intent,
        provider_readback=_provider_readback(second_intent),
        observed_at=BASE + timedelta(seconds=11),
    )

    assert second_receipt.intent.record == second_record
    confirmed = system.anchors.read_confirmed_anchor_records(second_chain)
    assert confirmed == (first_intent.record, second_record)
    assert tuple(record.canonical_bytes for record in confirmed) == (
        first_intent.signed_envelope_bytes,
        second_intent.signed_envelope_bytes,
    )
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_receipts)
            )
            == 2
        )


def test_restart_recovers_exact_intent_before_upload_and_after_upload_before_receipt(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    committed = _prepare_enrollment(system, chain)

    before_upload_restart = _anchor_repository(system.engine)
    before_upload = before_upload_restart.read_pending(chain)
    assert before_upload == committed
    assert before_upload is not None
    assert before_upload.record == committed.record
    assert before_upload.signed_envelope_bytes == committed.signed_envelope_bytes

    before_receipt_restart = _anchor_repository(system.engine)
    before_receipt = before_receipt_restart.read_pending(chain)
    assert before_receipt == committed
    assert before_receipt is not None
    receipt = before_receipt_restart.confirm_remote_readback(
        chain,
        intent=before_receipt,
        provider_readback=_provider_readback(before_receipt),
        observed_at=BASE + timedelta(seconds=1),
    )
    repeated = _anchor_repository(system.engine).confirm_remote_readback(
        chain,
        intent=committed,
        provider_readback=_provider_readback(committed),
        observed_at=BASE + timedelta(seconds=2),
    )
    assert repeated == receipt


def test_anchor_order_uses_sequences_and_hashes_while_all_utc_evidence_regresses(
    system: System,
) -> None:
    first_head_utc = BASE + timedelta(seconds=30)
    _register_epoch(system, recorded_at=first_head_utc)
    first_chain = _local_chain(system.engine)
    first_record = _signed_record(first_chain[-1], previous=None)
    first = system.anchors.prepare_or_read_pending(
        first_chain,
        record=first_record,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        created_at=first_head_utc + timedelta(seconds=30),
        allow_enrollment=True,
    )
    system.anchors.confirm_remote_readback(
        first_chain,
        intent=first,
        provider_readback=_provider_readback(first),
        observed_at=first_head_utc + timedelta(seconds=60),
    )

    regressed_head_utc = BASE
    _register_epoch(system, recorded_at=regressed_head_utc)
    regressed_chain = _local_chain(system.engine)
    second_record = _signed_record(regressed_chain[-1], previous=first.record)
    second = system.anchors.prepare_or_read_pending(
        regressed_chain,
        record=second_record,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        created_at=BASE - timedelta(seconds=1),
    )
    second_receipt = system.anchors.confirm_remote_readback(
        regressed_chain,
        intent=second,
        provider_readback=_provider_readback(second),
        observed_at=BASE - timedelta(seconds=2),
    )

    assert second.record.anchor_sequence == 2
    assert second.record.previous_anchor_sha256 == first.signed_envelope_sha256
    assert second.record.head_authenticated_at_utc < first.record.head_authenticated_at_utc
    assert second.created_at_utc < first.created_at_utc
    assert second_receipt.observed_at_utc < first.created_at_utc
    assert system.anchors.read_confirmed_anchor_records(regressed_chain) == (
        first.record,
        second.record,
    )


def test_complete_sql_replay_rejects_a_forged_or_truncated_local_chain(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    _register_epoch(system, recorded_at=BASE + timedelta(seconds=1))
    chain = _local_chain(system.engine)
    forged = (
        replace(chain[0], current_host_head_sha256="f" * 64),
        replace(chain[1], previous_host_head_sha256="f" * 64),
    )

    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="complete SQL replay",
    ):
        system.anchors.verify_integrity(forged)
    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="complete SQL replay",
    ):
        system.anchors.verify_integrity(chain[:1])


def test_integrity_replay_detects_canonical_row_tampering_without_echoing_content(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    chain = _local_chain(system.engine)
    intent = _prepare_enrollment(system, chain)
    system.anchors.confirm_remote_readback(
        chain,
        intent=intent,
        provider_readback=_provider_readback(intent),
        observed_at=BASE + timedelta(seconds=1),
    )
    secret_marker = "operator-secret-must-not-be-echoed"
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase6_trusted_time_head_anchor_intents)
            .where(
                phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                == intent.anchor_intent_id
            )
            .values(canonical_payload=secret_marker)
        )

    with pytest.raises(TrustedTimeHeadAnchorPersistenceConflict) as captured:
        system.anchors.verify_integrity(chain)
    assert secret_marker not in str(captured.value)


def test_integrity_replay_rejects_multiple_unresolved_intents_per_host(
    system: System,
) -> None:
    _register_epoch(system, recorded_at=BASE)
    first_chain = _local_chain(system.engine)
    first = _prepare_enrollment(system, first_chain)
    _register_epoch(system, recorded_at=BASE + timedelta(seconds=1))
    chain = _local_chain(system.engine)
    second_record = _signed_record(chain[-1], previous=first.record)
    prefix = anchor_contract.trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=second_record.deployment_identity_sha256,
        host_id=second_record.host_id,
    )
    second = anchor_persistence._new_intent(
        anchor_intent_id="22222222-2222-4222-8222-222222222222",
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        checkpoint_interval_seconds=(
            anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ),
        anchor_authority_sha256=ANCHOR_AUTHORITY,
        record=second_record,
        object_name=anchor_contract.trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=second_record.anchor_sequence,
            signed_envelope_sha256=second_record.byte_sha256,
        ),
        signed_envelope_bytes=second_record.canonical_bytes,
        created_at_utc=BASE + timedelta(seconds=1),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **anchor_persistence._intent_values(second)
            )
        )

    with pytest.raises(
        TrustedTimeHeadAnchorPersistenceConflict,
        match="multiple unresolved intents",
    ):
        system.anchors.read_pending(chain)


def test_large_startup_replay_bounds_anchor_pages_and_retains_only_exact_tips(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page_bound = anchor_persistence._ANCHOR_FULL_REPLAY_PAGE_SIZE
    history_count = page_bound + 1
    for index in range(history_count):
        _register_epoch(
            system,
            recorded_at=BASE + timedelta(seconds=index),
        )
    local_chain = _local_chain(system.engine)
    assert len(local_chain) == history_count

    prefix = anchor_contract.trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        host_id=HOST_ID,
    )
    intents: list[PersistedTrustedTimeHeadAnchorIntent] = []
    receipts: list[anchor_persistence.PersistedTrustedTimeHeadAnchorReceipt] = []
    previous_record: TrustedTimeHeadAnchorRecord | None = None
    for transition in local_chain:
        record = _signed_record(transition, previous=previous_record)
        intent = anchor_persistence._new_intent(
            anchor_intent_id=str(anchor_persistence.uuid.uuid4()),
            checkpoint_reason=record.checkpoint_reason,
            checkpoint_interval_seconds=(
                anchor_persistence.TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
            ),
            anchor_authority_sha256=ANCHOR_AUTHORITY,
            record=record,
            object_name=anchor_contract.trusted_time_head_anchor_object_name(
                prefix=prefix,
                anchor_sequence=record.anchor_sequence,
                signed_envelope_sha256=record.byte_sha256,
            ),
            signed_envelope_bytes=record.canonical_bytes,
            created_at_utc=record.head_authenticated_at_utc,
        )
        receipt = anchor_persistence._new_receipt(
            anchor_receipt_id=str(anchor_persistence.uuid.uuid4()),
            intent=intent,
            readback_bytes_sha256=intent.signed_envelope_sha256,
            observed_at_utc=record.head_authenticated_at_utc,
        )
        intents.append(intent)
        receipts.append(receipt)
        previous_record = record

    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents),
            [anchor_persistence._intent_values(intent) for intent in intents],
        )
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts),
            [anchor_persistence._receipt_values(receipt) for receipt in receipts],
        )

    retained_page_lengths: list[int] = []
    original_load_page = anchor_persistence._BoundedAnchorReplay._load_page

    def instrument_load_page(
        replay: anchor_persistence._BoundedAnchorReplay,
    ) -> None:
        original_load_page(replay)
        retained_page_lengths.append(len(replay._page))
        assert len(replay._page) <= page_bound

    monkeypatch.setattr(
        anchor_persistence._BoundedAnchorReplay,
        "_load_page",
        instrument_load_page,
    )

    snapshot = _load_startup(system)
    state = system.anchors._require_snapshot(snapshot)
    tip = snapshot.authenticated_journal_tip

    assert retained_page_lengths
    assert retained_page_lengths[0] == page_bound
    assert any(0 < length < page_bound for length in retained_page_lengths)
    assert max(retained_page_lengths) <= page_bound
    assert snapshot.complete_replay is True
    assert snapshot.local_transitions == ()
    assert snapshot.confirmed_anchor_records == ()
    assert snapshot.local_transition_count == history_count
    assert snapshot.confirmed_anchor_count == history_count
    assert snapshot.current_host_head_sha256 == local_chain[-1].current_host_head_sha256
    assert snapshot.pending_intent is None
    assert snapshot.pending_intent_local_transition_ordinal is None
    assert snapshot.committed_pending_evidence is None
    assert tip.current_transition == local_chain[-1]
    assert tip.local_transition_count == history_count
    assert tip.first_local_host_head_sha256 == local_chain[0].current_host_head_sha256
    assert tip.confirmed_anchor_count == history_count
    assert tip.confirmed_anchor_tip == intents[-1].record
    assert tip.first_anchored_local_transition_ordinal == 1
    assert tip.confirmed_anchor_local_transition_ordinal == history_count
    assert state.intent_count == history_count
    assert state.receipt_count == history_count
    assert state.terminal_intent == intents[-1]
    assert state.terminal_receipt == receipts[-1]
    assert state.terminal_intent_local_transition_ordinal == history_count
    assert state.pending is None
