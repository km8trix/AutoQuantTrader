from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, current_thread
from typing import Never
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event, inspect, make_url
from sqlalchemy.exc import IntegrityError

import packages.persistence.alpaca_paper_account_binding as binding_persistence_module
from packages.adapters.broker.alpaca_paper import ALPACA_AUTH_HEADER_NAMES
from packages.adapters.broker.alpaca_paper_account_assets import (
    create_alpaca_account_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_ID,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION,
    AlpacaPaperAccountBindingConflict,
    AlpacaPaperAccountTransportRequest,
    AlpacaPaperAccountTransportResponse,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperAuthenticatedAccountEvidence,
    AlpacaPaperCredentialReference,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    _observe_authenticated_alpaca_paper_account_with_transport,
    create_alpaca_paper_credential_envelope,
)
from packages.domain.account_coordinator import AccountFence, AccountLeasePolicy
from packages.domain.broker_ingress import BrokerIngressDelivery, BrokerIngressReceipt
from packages.domain.broker_request_budget import BrokerRequestPermitConflict
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
    alpaca_paper_account_binding_from_row,
    verify_alpaca_paper_account_binding_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_leases,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_request_heads,
    phase4_broker_request_permits,
)

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures/broker/alpaca_paper/account_active.json"
)
ACCOUNT_ID = "phase4g-paper-account"
PROVIDER_ACCOUNT_ID = "e6fe16f3-64a4-4921-8928-cadf02f92f98"
ROTATED_PROVIDER_ACCOUNT_ID = "00000000-0000-4000-8000-000000000001"
API_KEY_ID = "PK-PHASE4G-EPHEMERAL-KEY"
SECRET_KEY = "phase4g-ephemeral-secret-must-not-persist"
BASE = datetime(2026, 7, 27, 14, 0, tzinfo=UTC)
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


class SequenceClock:
    def __init__(self, instants: list[datetime]) -> None:
        self._instants = list(instants)

    def now(self) -> datetime:
        if not self._instants:
            raise AssertionError("trusted clock was sampled more times than expected")
        return self._instants.pop(0)


class FixedCredentialResolver:
    resolver_id = "phase4g-test-secret-store"
    resolver_version = "v1"

    def __init__(self) -> None:
        self.references: list[AlpacaPaperCredentialReference] = []
        self.materials: list[_AlpacaPaperCredentialMaterial] = []

    def _resolve_for_account_observation(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        self.references.append(reference)
        envelope = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(envelope) is _AlpacaPaperCredentialMaterial
        material = envelope
        self.materials.append(material)
        return material


class FixtureTransport:
    transport_id = ALPACA_PAPER_ACCOUNT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    def execute(
        self,
        request: AlpacaPaperAccountTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountTransportResponse:
        self.calls += 1
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        return AlpacaPaperAccountTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=f"phase4g-provider-request-{self.calls:03d}",
            media_type=ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
            response_body=self.body,
        )


class CapturingBindingRecorder:
    def __init__(self, delegate: SqlAlpacaPaperAccountBindingRepository) -> None:
        self.delegate = delegate
        self.evidence: list[AlpacaPaperAuthenticatedAccountEvidence] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountEvidence,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        self.evidence.append(evidence)
        return self.delegate.record(evidence)


class EvidenceCaptured(RuntimeError):
    pass


class CaptureOnlyBindingRecorder:
    def __init__(self) -> None:
        self.evidence: list[AlpacaPaperAuthenticatedAccountEvidence] = []

    def record(self, evidence: AlpacaPaperAuthenticatedAccountEvidence) -> Never:
        self.evidence.append(evidence)
        raise EvidenceCaptured


@dataclass(slots=True)
class RuntimeSystem:
    engine: Engine
    database_path: Path
    coordinator: SqlAccountCoordinator
    fence: AccountFence
    resolver: FixedCredentialResolver
    transport: FixtureTransport
    bindings: SqlAlpacaPaperAccountBindingRepository
    capture: CapturingBindingRecorder
    clock: SequenceClock

    def observe(
        self,
        suffix: str,
        *,
        provider_account_id: str = PROVIDER_ACCOUNT_ID,
        response_body: bytes | None = None,
        secret_version: str = "version-001",
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        if response_body is not None:
            self.transport.body = response_body
        return _observe_authenticated_alpaca_paper_account_with_transport(
            reference=AlpacaPaperCredentialReference(
                account_id=ACCOUNT_ID,
                expected_provider_account_id=provider_account_id,
                secret_ref="secret://paper/alpaca/trading",
                secret_version=secret_version,
            ),
            description=create_alpaca_account_observation_description(
                account_id=ACCOUNT_ID,
            ),
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=SqlBrokerRequestBudgetRepository(
                engine=self.engine,
                clock=self.clock,
            ),
            coordinator=self.coordinator,
            fence=self.fence,
            ingress_recorder=SqlBrokerIngressRepository(self.engine),
            binding_recorder=self.capture,
            clock=self.clock,
            request_idempotency_key=f"phase4g-account-request-{suffix}",
            delivery_idempotency_key=f"phase4g-account-delivery-{suffix}",
        )


def _runtime_instants(run_count: int) -> list[datetime]:
    instants = [BASE - timedelta(seconds=1)]
    for run_index in range(run_count):
        start = BASE + timedelta(seconds=run_index * 2)
        instants.extend(
            (
                start,
                start + timedelta(milliseconds=100),
                start + timedelta(milliseconds=200),
                start + timedelta(milliseconds=250),
                start + timedelta(milliseconds=300),
                start + timedelta(milliseconds=300),
                start + timedelta(milliseconds=400),
                start + timedelta(milliseconds=500),
                start + timedelta(milliseconds=600),
                start + timedelta(milliseconds=700),
                start + timedelta(milliseconds=800),
                start + timedelta(milliseconds=800),
            )
        )
    return instants


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def phase4g_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4G tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")

    config = _alembic_config(database_url)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def _system(
    database_path: Path,
    *,
    run_count: int = 1,
    migrated: bool = False,
    migration_revision: str = "head",
) -> RuntimeSystem:
    database_url = f"sqlite+pysqlite:///{database_path}"
    if migrated:
        command.upgrade(_alembic_config(database_url), migration_revision)
    engine = create_database_engine(database_url)
    if not migrated:
        metadata.create_all(engine)
    clock = SequenceClock(_runtime_instants(run_count))
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4g-binding-integration",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    fence = coordinator.acquire("phase4g-binding-worker").fence
    bindings = SqlAlpacaPaperAccountBindingRepository(engine)
    return RuntimeSystem(
        engine=engine,
        database_path=database_path,
        coordinator=coordinator,
        fence=fence,
        resolver=FixedCredentialResolver(),
        transport=FixtureTransport(ACCOUNT_FIXTURE.read_bytes()),
        bindings=bindings,
        capture=CapturingBindingRecorder(bindings),
        clock=clock,
    )


def _account_body(provider_account_id: str) -> bytes:
    payload = json.loads(ACCOUNT_FIXTURE.read_text())
    assert type(payload) is dict
    payload["id"] = provider_account_id
    return json.dumps(payload, separators=(",", ":")).encode()


def _rotated_account_body() -> bytes:
    return _account_body(ROTATED_PROVIDER_ACCOUNT_ID)


def _prepare_concurrent_postgres_evidence(
    engine: Engine,
    account_id: str,
) -> tuple[
    AlpacaPaperAuthenticatedAccountEvidence,
    AlpacaPaperAuthenticatedAccountEvidence,
]:
    provider_account_id = str(uuid4())
    first_run = _runtime_instants(1)[1:]
    same_terminal_time = BASE + timedelta(milliseconds=800)
    clock = SequenceClock(
        [BASE - timedelta(seconds=1)] + first_run + [same_terminal_time] * len(first_run)
    )
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4g-postgres-binding-lock",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    fence = coordinator.acquire("phase4g-postgres-binding-worker").fence
    resolver = FixedCredentialResolver()
    transport = FixtureTransport(_account_body(provider_account_id))
    budget = SqlBrokerRequestBudgetRepository(engine=engine, clock=clock)
    ingress = SqlBrokerIngressRepository(engine)
    capture = CaptureOnlyBindingRecorder()

    for suffix in ("first", "second"):
        with pytest.raises(EvidenceCaptured):
            _observe_authenticated_alpaca_paper_account_with_transport(
                reference=AlpacaPaperCredentialReference(
                    account_id=account_id,
                    expected_provider_account_id=provider_account_id,
                    secret_ref="secret://paper/alpaca/trading",
                    secret_version="version-001",
                ),
                description=create_alpaca_account_observation_description(
                    account_id=account_id,
                ),
                credential_resolver=resolver,
                transport=transport,
                budget=budget,
                coordinator=coordinator,
                fence=fence,
                ingress_recorder=ingress,
                binding_recorder=capture,
                clock=clock,
                request_idempotency_key=f"phase4g-pg-request-{suffix}",
                delivery_idempotency_key=f"phase4g-pg-delivery-{suffix}",
            )

    assert len(capture.evidence) == 2
    assert capture.evidence[0].qualified_at == capture.evidence[1].qualified_at
    assert all(material.closed for material in resolver.materials)
    return capture.evidence[0], capture.evidence[1]


def test_runtime_record_load_history_and_idempotent_evidence_are_exact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-exact.sqlite")

    binding = system.observe("001")
    retried = system.bindings.record(system.capture.evidence[0])

    assert retried == binding
    assert binding.sequence_number == 1
    assert binding.previous_binding_sha256 is None
    assert system.bindings.load(binding.binding_id) == binding
    assert system.bindings.history(ACCOUNT_ID) == (binding,)
    verify_alpaca_paper_account_binding_integrity(system.engine)
    with system.engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase4_alpaca_paper_account_bindings).where(
                    phase4_alpaca_paper_account_bindings.c.binding_id == binding.binding_id
                )
            )
            .mappings()
            .one()
        )
        assert alpaca_paper_account_binding_from_row(row) == binding
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_account_bindings)
            )
            == 1
        )


def test_exact_runtime_replay_cannot_send_twice_under_one_durable_debit(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "binding-no-double-send.sqlite",
        run_count=2,
    )
    original = system.observe("001")
    system.clock._instants = _runtime_instants(1)[1:]

    with pytest.raises(
        BrokerRequestPermitConflict,
        match="already has a durable permit",
    ):
        system.observe("001")

    assert system.transport.calls == 1
    assert system.bindings.history(ACCOUNT_ID) == (original,)
    assert all(material.closed for material in system.resolver.materials)
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase4_broker_request_permits))
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_ingress_receipts)
            )
            == 1
        )


def test_durable_source_authentication_rejects_nonqualifying_media(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "binding-source-qualification.sqlite")
    binding = system.observe("001")
    evidence = system.capture.evidence[0]
    original_receipt = evidence.persisted_observation.receipt
    altered_receipt = BrokerIngressReceipt(
        delivery=replace(
            original_receipt.delivery,
            media_type="text/plain",
        ),
        ingress_sequence=original_receipt.ingress_sequence,
        previous_receipt_sha256=original_receipt.previous_receipt_sha256,
    )
    altered_response = AlpacaPaperAccountTransportResponse(
        request_sha256=evidence.request.semantic_sha256,
        transport_id=ALPACA_PAPER_ACCOUNT_TRANSPORT_ID,
        transport_version=ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION,
        http_status=200,
        provider_request_id=altered_receipt.delivery.provider_request_id,
        media_type=altered_receipt.delivery.media_type,
        response_body=altered_receipt.delivery.body,
    )
    object.__setattr__(
        binding,
        "transport_response_sha256",
        altered_response.semantic_sha256,
    )
    monkeypatch.setattr(
        binding_persistence_module,
        "_authenticate_ingress_source",
        lambda connection, candidate: altered_receipt,
    )

    with (
        system.engine.connect() as connection,
        pytest.raises(
            AlpacaPaperAccountBindingConflict,
            match="source no longer qualifies",
        ),
    ):
        binding_persistence_module._authenticate_durable_sources(
            connection,
            binding,
        )


def test_account_local_binding_chain_is_append_only_and_secret_free(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "binding-chain.sqlite"
    system = _system(database_path, run_count=2)

    first = system.observe("001")
    second = system.observe("002", secret_version="version-002")

    assert second.sequence_number == 2
    assert second.previous_binding_sha256 == first.semantic_sha256
    assert system.bindings.history(ACCOUNT_ID) == (first, second)
    assert all(material.closed for material in system.resolver.materials)
    with system.engine.connect() as connection:
        rows = (
            connection.execute(
                sa.select(phase4_alpaca_paper_account_bindings).order_by(
                    phase4_alpaca_paper_account_bindings.c.sequence_number
                )
            )
            .mappings()
            .all()
        )
        persisted_text = repr([dict(row) for row in rows])
        assert rows[0]["secret_ref"] == "secret://paper/alpaca/trading"
        assert rows[1]["secret_version"] == "version-002"
        assert "api_key_id" not in rows[0]
        assert "secret_key" not in rows[0]
        assert API_KEY_ID not in persisted_text
        assert SECRET_KEY not in persisted_text
    system.engine.dispose()
    database_bytes = database_path.read_bytes()
    assert API_KEY_ID.encode() not in database_bytes
    assert SECRET_KEY.encode() not in database_bytes


def test_terminal_identity_authentication_survives_status_freshness_expiry(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-terminal-identity.sqlite")
    binding = system.observe("001")
    checked_at = binding.valid_until + timedelta(days=1)

    receipt = system.bindings.authenticate_terminal_identity(
        binding,
        checked_at=checked_at,
    )

    assert receipt.account_id == binding.account_id
    assert receipt.binding_id == binding.binding_id
    assert receipt.binding_sha256 == binding.semantic_sha256
    assert receipt.credential_reference_sha256 == binding.credential_reference_sha256
    assert receipt.expected_provider_account_id == binding.expected_provider_account_id
    assert receipt.sequence_number == binding.sequence_number
    assert receipt.binding_qualified_at == binding.qualified_at
    assert receipt.checked_at == checked_at
    assert receipt.account_identity_continuity_established
    assert not receipt.account_status_current
    assert not receipt.submission_authorized
    assert not receipt.trading_effect_authorized


def test_configured_terminal_identity_attests_exact_history_without_writes(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-configured-attestation.sqlite")
    reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )

    assert (
        system.bindings.authenticate_configured_terminal_identity(
            reference,
            checked_at=BASE,
        )
        is None
    )
    binding = system.observe("001")
    checked_at = binding.valid_until + timedelta(days=1)
    resolver_references_before = tuple(system.resolver.references)
    resolver_materials_before = tuple(system.resolver.materials)
    transport_calls_before = system.transport.calls
    with system.engine.connect() as connection:
        before = tuple(
            int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
            for table in (
                phase4_alpaca_paper_account_bindings,
                phase4_alpaca_paper_account_binding_heads,
                phase4_broker_request_permits,
                phase4_broker_ingress_receipts,
            )
        )

    statements: list[str] = []

    def capture_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement)

    event.listen(system.engine, "before_cursor_execute", capture_statement)
    try:
        receipt = system.bindings.authenticate_configured_terminal_identity(
            reference,
            checked_at=checked_at,
        )
        foreign_only = system.bindings.authenticate_configured_terminal_identity(
            AlpacaPaperCredentialReference(
                account_id="different-local-paper-account",
                expected_provider_account_id=PROVIDER_ACCOUNT_ID,
                secret_ref="secret://paper/alpaca/trading",
                secret_version="version-001",
            ),
            checked_at=checked_at,
        )
    finally:
        event.remove(system.engine, "before_cursor_execute", capture_statement)

    assert receipt is not None
    assert foreign_only is None
    assert receipt.binding_id == binding.binding_id
    assert receipt.binding_sha256 == binding.semantic_sha256
    assert receipt.credential_reference_sha256 == reference.semantic_sha256
    assert receipt.checked_at == checked_at
    assert not receipt.account_status_current
    assert not receipt.submission_authorized
    assert not receipt.trading_effect_authorized
    assert statements
    assert not any(
        statement.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE "))
        for statement in statements
    )
    assert tuple(system.resolver.references) == resolver_references_before
    assert tuple(system.resolver.materials) == resolver_materials_before
    assert system.transport.calls == transport_calls_before
    with system.engine.connect() as connection:
        after = tuple(
            int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
            for table in (
                phase4_alpaca_paper_account_bindings,
                phase4_alpaca_paper_account_binding_heads,
                phase4_broker_request_permits,
                phase4_broker_ingress_receipts,
            )
        )
    assert after == before


def test_configured_terminal_identity_selects_latest_binding_and_rejects_stale_pin(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "binding-configured-terminal.sqlite",
        run_count=2,
    )
    first = system.observe("001")
    terminal = system.observe("002", secret_version="version-002")
    terminal_reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-002",
    )
    checked_at = terminal.valid_until + timedelta(days=1)

    receipt = system.bindings.authenticate_configured_terminal_identity(
        terminal_reference,
        checked_at=checked_at,
    )

    assert system.bindings.history(ACCOUNT_ID) == (first, terminal)
    assert receipt is not None
    assert receipt.binding_id == terminal.binding_id
    assert receipt.binding_sha256 == terminal.semantic_sha256
    assert receipt.credential_reference_sha256 == terminal_reference.semantic_sha256
    assert receipt.sequence_number == 2
    assert receipt.checked_at == checked_at
    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="configured paper account identity conflicts",
    ):
        system.bindings.authenticate_configured_terminal_identity(
            AlpacaPaperCredentialReference(
                account_id=ACCOUNT_ID,
                expected_provider_account_id=PROVIDER_ACCOUNT_ID,
                secret_ref="secret://paper/alpaca/trading",
                secret_version="version-001",
            ),
            checked_at=checked_at,
        )


def test_configured_terminal_identity_rejects_every_configured_pin_mismatch(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-configured-mismatch.sqlite")
    binding = system.observe("001")
    checked_at = binding.valid_until + timedelta(days=1)
    mismatches = (
        AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id=ROTATED_PROVIDER_ACCOUNT_ID,
            secret_ref="secret://paper/alpaca/trading",
            secret_version="version-001",
        ),
        AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id=PROVIDER_ACCOUNT_ID,
            secret_ref="secret://paper/alpaca/other",
            secret_version="version-001",
        ),
        AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id=PROVIDER_ACCOUNT_ID,
            secret_ref="secret://paper/alpaca/trading",
            secret_version="version-002",
        ),
    )

    for reference in mismatches:
        with pytest.raises(
            AlpacaPaperAccountBindingConflict,
            match="configured paper account identity conflicts",
        ):
            system.bindings.authenticate_configured_terminal_identity(
                reference,
                checked_at=checked_at,
            )


def test_configured_terminal_identity_rejects_binding_orphaned_from_its_head(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-configured-orphan.sqlite")
    binding = system.observe("001")
    with system.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_alpaca_paper_account_binding_heads).where(
                phase4_alpaca_paper_account_binding_heads.c.account_id == ACCOUNT_ID
            )
        )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="without durable account heads",
    ):
        system.bindings.authenticate_configured_terminal_identity(
            AlpacaPaperCredentialReference(
                account_id=ACCOUNT_ID,
                expected_provider_account_id=PROVIDER_ACCOUNT_ID,
                secret_ref="secret://paper/alpaca/trading",
                secret_version="version-001",
            ),
            checked_at=binding.valid_until + timedelta(days=1),
        )


def test_configured_terminal_identity_rejects_unrelated_corrupt_binding_history(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-configured-unrelated-corruption.sqlite")
    configured_binding = system.observe("001")
    configured_reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    unrelated_evidence, _ = _prepare_concurrent_postgres_evidence(
        system.engine,
        "zz-phase4g-unrelated-account",
    )
    unrelated_binding = system.bindings.record(unrelated_evidence)
    checked_at = configured_binding.valid_until + timedelta(days=1)

    receipt = system.bindings.authenticate_configured_terminal_identity(
        configured_reference,
        checked_at=checked_at,
    )

    assert receipt is not None
    assert receipt.binding_id == configured_binding.binding_id
    assert unrelated_binding.account_id != configured_binding.account_id
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_bindings)
            .where(
                phase4_alpaca_paper_account_bindings.c.binding_id == unrelated_binding.binding_id
            )
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.authenticate_configured_terminal_identity(
            configured_reference,
            checked_at=checked_at,
        )


def test_terminal_reads_and_replay_reject_a_corrupted_predecessor(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "binding-broken-predecessor.sqlite",
        run_count=2,
    )
    first = system.observe("001")
    terminal = system.observe("002")

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.binding_id == first.binding_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.load(terminal.binding_id)
    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.authenticate_terminal_identity(
            terminal,
            checked_at=terminal.valid_until + timedelta(days=1),
        )
    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.authenticate_configured_terminal_identity(
            AlpacaPaperCredentialReference(
                account_id=ACCOUNT_ID,
                expected_provider_account_id=PROVIDER_ACCOUNT_ID,
                secret_ref="secret://paper/alpaca/trading",
                secret_version="version-002",
            ),
            checked_at=terminal.valid_until + timedelta(days=1),
        )
    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.authenticate_terminal_fresh(
            terminal,
            checked_at=terminal.qualified_at,
        )
    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.record(system.capture.evidence[1])


def test_binding_reads_reject_corruption_in_an_unbound_ingress_ancestor(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-broken-ingress-ancestor.sqlite")
    ancestor = SqlBrokerIngressRepository(system.engine).record(
        BrokerIngressDelivery(
            account_id=ACCOUNT_ID,
            delivery_idempotency_key="phase4g-unqualified-ingress-ancestor",
            provider_id="alpaca-paper",
            adapter_version="1.0.0",
            environment="paper",
            channel="trading-rest",
            operation="unqualified-account-probe",
            correlation_sha256="f" * 64,
            transport_status=503,
            provider_request_id="phase4g-unqualified-request",
            media_type="application/json",
            received_at=BASE - timedelta(milliseconds=900),
            recorded_at=BASE - timedelta(milliseconds=800),
            body=b'{"message":"temporarily unavailable"}',
        )
    )
    binding = system.observe("001")

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(phase4_broker_ingress_receipts.c.receipt_id == ancestor.receipt_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(AlpacaPaperAccountBindingConflict):
        system.bindings.load(binding.binding_id)
    with pytest.raises(AlpacaPaperAccountBindingConflict):
        system.bindings.authenticate_terminal_fresh(
            binding,
            checked_at=binding.qualified_at,
        )
    with pytest.raises(AlpacaPaperAccountBindingConflict):
        system.bindings.record(system.capture.evidence[0])


def test_provider_uuid_rotation_is_rejected_for_an_existing_local_account(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-provider-pin.sqlite", run_count=2)
    original = system.observe("001")

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="provider account UUID cannot change",
    ):
        system.observe(
            "002",
            provider_account_id=ROTATED_PROVIDER_ACCOUNT_ID,
            response_body=_rotated_account_body(),
        )

    assert system.bindings.history(ACCOUNT_ID) == (original,)
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase4_broker_request_permits))
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_ingress_receipts)
            )
            == 2
        )


def test_binding_foreign_keys_protect_exact_permit_and_raw_ingress(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "binding-foreign-keys.sqlite")
    binding = system.observe("001")
    foreign_keys = {
        foreign_key["name"]: foreign_key
        for foreign_key in inspect(system.engine).get_foreign_keys(
            phase4_alpaca_paper_account_bindings.name
        )
    }

    assert foreign_keys["fk_phase4_alpaca_account_bindings_permit"]["constrained_columns"] == [
        "account_id",
        "permit_id",
        "permit_sha256",
    ]
    assert foreign_keys["fk_phase4_alpaca_account_bindings_ingress"]["constrained_columns"] == [
        "account_id",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
    ]

    with pytest.raises(IntegrityError), system.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_broker_request_heads).where(
                phase4_broker_request_heads.c.account_id == ACCOUNT_ID
            )
        )
        connection.execute(
            sa.delete(phase4_broker_request_permits).where(
                phase4_broker_request_permits.c.permit_id == binding.permit_id
            )
        )
    with pytest.raises(IntegrityError), system.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_broker_ingress_heads).where(
                phase4_broker_ingress_heads.c.account_id == ACCOUNT_ID
            )
        )
        connection.execute(
            sa.delete(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.receipt_id == binding.ingress_receipt_id
            )
        )

    assert system.bindings.load(binding.binding_id) == binding


def test_binding_tamper_is_detected_by_repository_and_startup_readiness(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "binding-readiness.sqlite",
        migrated=True,
    )
    binding = system.observe("001")
    verify_operational_schema(system.engine, require_phase_zero_facts=False)

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.binding_id == binding.binding_id)
            .values(evidence_sha256="0" * 64)
        )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="evidence digest",
    ):
        system.bindings.load(binding.binding_id)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="account-binding integrity",
    ):
        verify_operational_schema(system.engine, require_phase_zero_facts=False)

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.binding_id == binding.binding_id)
            .values(
                evidence_sha256=binding.evidence_sha256,
                canonical_payload="[]",
            )
        )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="canonical_payload",
    ):
        system.bindings.load(binding.binding_id)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="account-binding integrity",
    ):
        verify_operational_schema(system.engine, require_phase_zero_facts=False)


def test_postgresql_configured_terminal_identity_attestation_is_read_only(
    phase4g_postgres_engine: Engine,
) -> None:
    base_engine = phase4g_postgres_engine
    schema_name = f"phase4g_attest_{uuid4().hex}"
    with base_engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema_name))
    engine = base_engine.execution_options(schema_translate_map={None: schema_name})
    try:
        metadata.create_all(engine)
        account_id = f"phase4g-pg-attestation-{uuid4().hex[:20]}"
        evidence, _unused = _prepare_concurrent_postgres_evidence(engine, account_id)
        repository = SqlAlpacaPaperAccountBindingRepository(engine)
        binding = repository.record(evidence)
        checked_at = binding.valid_until + timedelta(days=1)
        statements: list[str] = []

        def capture_statement(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", capture_statement)
        try:
            receipt = repository.authenticate_configured_terminal_identity(
                evidence.reference,
                checked_at=checked_at,
            )
        finally:
            event.remove(engine, "before_cursor_execute", capture_statement)

        assert receipt is not None
        assert receipt.account_id == account_id
        assert receipt.binding_id == binding.binding_id
        assert receipt.binding_sha256 == binding.semantic_sha256
        assert receipt.credential_reference_sha256 == evidence.reference.semantic_sha256
        assert receipt.checked_at == checked_at
        assert not receipt.account_status_current
        assert statements
        assert not any(
            statement.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE "))
            for statement in statements
        )
    finally:
        with base_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema_name, cascade=True, if_exists=True))


def test_postgresql_shared_account_lock_serializes_exact_binding_append_order(
    phase4g_postgres_engine: Engine,
) -> None:
    engine = phase4g_postgres_engine
    account_id = f"phase4g-pg-binding-{uuid4().hex[:20]}"
    first_lock_acquired = Event()
    second_lock_attempted = Event()
    release_first_lock = Event()

    def is_shared_account_lock(statement: str) -> bool:
        return "FROM phase2_account_lease_heads" in statement and "FOR UPDATE" in statement

    def pause_first_lock_holder(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if current_thread().name.endswith("_0") and is_shared_account_lock(statement):
            first_lock_acquired.set()
            if not release_first_lock.wait(timeout=10):
                raise TimeoutError("first binding lock holder was not released")

    def observe_second_lock_attempt(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if current_thread().name.endswith("_1") and is_shared_account_lock(statement):
            second_lock_attempted.set()

    try:
        first_evidence, second_evidence = _prepare_concurrent_postgres_evidence(
            engine,
            account_id,
        )
        first_repository = SqlAlpacaPaperAccountBindingRepository(engine)
        second_repository = SqlAlpacaPaperAccountBindingRepository(engine)
        event.listen(
            engine,
            "after_cursor_execute",
            pause_first_lock_holder,
        )
        event.listen(
            engine,
            "before_cursor_execute",
            observe_second_lock_attempt,
        )
        try:
            with ThreadPoolExecutor(
                max_workers=2,
                thread_name_prefix="phase4g-binding-lock",
            ) as executor:
                try:
                    first_future = executor.submit(
                        first_repository.record,
                        first_evidence,
                    )
                    assert first_lock_acquired.wait(timeout=10)
                    second_future = executor.submit(
                        second_repository.record,
                        second_evidence,
                    )
                    assert second_lock_attempted.wait(timeout=10)

                    deadline = time.monotonic() + 10
                    second_waited_on_postgres_lock = False
                    while time.monotonic() < deadline:
                        with engine.connect() as connection:
                            second_waited_on_postgres_lock = bool(
                                connection.scalar(
                                    sa.text(
                                        """
                                        SELECT EXISTS (
                                            SELECT 1
                                            FROM pg_stat_activity
                                            WHERE datname = current_database()
                                              AND pid <> pg_backend_pid()
                                              AND wait_event_type = 'Lock'
                                              AND query LIKE
                                                  '%phase2_account_lease_heads%'
                                              AND query LIKE '%FOR UPDATE%'
                                        )
                                        """
                                    )
                                )
                            )
                        if second_waited_on_postgres_lock:
                            break
                        time.sleep(0.01)
                    assert second_waited_on_postgres_lock
                finally:
                    release_first_lock.set()

                first = first_future.result(timeout=10)
                second = second_future.result(timeout=10)
        finally:
            release_first_lock.set()
            event.remove(
                engine,
                "after_cursor_execute",
                pause_first_lock_holder,
            )
            event.remove(
                engine,
                "before_cursor_execute",
                observe_second_lock_attempt,
            )

        assert first.sequence_number == 1
        assert first.previous_binding_sha256 is None
        assert first.evidence_sha256 == first_evidence.semantic_sha256
        assert second.sequence_number == 2
        assert second.previous_binding_sha256 == first.semantic_sha256
        assert second.evidence_sha256 == second_evidence.semantic_sha256
        assert first_repository.history(account_id) == (first, second)
    finally:
        release_first_lock.set()
        with engine.begin() as connection:
            connection.execute(
                sa.delete(phase4_alpaca_paper_account_binding_heads).where(
                    phase4_alpaca_paper_account_binding_heads.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_alpaca_paper_account_bindings).where(
                    phase4_alpaca_paper_account_bindings.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_broker_request_heads).where(
                    phase4_broker_request_heads.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_broker_request_permits).where(
                    phase4_broker_request_permits.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_broker_ingress_heads).where(
                    phase4_broker_ingress_heads.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_broker_ingress_receipts).where(
                    phase4_broker_ingress_receipts.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase2_account_leases).where(
                    phase2_account_leases.c.account_id == account_id
                )
            )


def test_phase4g_migration_is_additive_and_empty_downgrade_is_reversible(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'binding-migration.sqlite'}"
    config = _alembic_config(database_url)
    command.upgrade(config, "0012_phase4_request_budget")
    engine = create_database_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    engine.dispose()

    command.upgrade(config, "0013_phase4_account_binding")
    upgraded_engine = create_database_engine(database_url)
    assert set(inspect(upgraded_engine).get_table_names()) == prior_tables | {
        phase4_alpaca_paper_account_binding_heads.name,
        phase4_alpaca_paper_account_bindings.name,
    }
    assert tuple(
        column["name"]
        for column in inspect(upgraded_engine).get_columns(
            phase4_alpaca_paper_account_bindings.name
        )
    ) == tuple(phase4_alpaca_paper_account_bindings.c.keys())
    upgraded_engine.dispose()

    command.downgrade(config, "0012_phase4_request_budget")
    downgraded_engine = create_database_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase4g_migration_refuses_nonempty_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "binding-nonempty-downgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    system = _system(
        database_path,
        migrated=True,
        migration_revision="0013_phase4_account_binding",
    )
    binding = system.observe("001")
    system.engine.dispose()
    config = _alembic_config(database_url)

    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after durable Alpaca paper account bindings",
    ):
        command.downgrade(config, "0012_phase4_request_budget")

    preserved_engine = create_database_engine(database_url)
    with preserved_engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0013_phase4_account_binding"
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_account_bindings)
                .where(phase4_alpaca_paper_account_bindings.c.binding_id == binding.binding_id)
            )
            == 1
        )
    preserved_engine.dispose()
