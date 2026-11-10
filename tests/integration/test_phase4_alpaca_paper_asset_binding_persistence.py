from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Never
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, make_url
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper_account_assets import (
    create_alpaca_asset_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountBindingConflict,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperAssetBindingConflict,
    AlpacaPaperAuthenticatedAssetBinding,
    AlpacaPaperAuthenticatedAssetEvidence,
    AlpacaPaperSecurityReference,
    _observe_authenticated_alpaca_paper_asset_with_transport,
)
from packages.domain.broker_ingress import BrokerIngressDelivery
from packages.domain.broker_request_budget import BrokerRequestBudgetError
from packages.persistence.alpaca_paper_asset_binding import (
    SqlAlpacaPaperAssetBindingRepository,
    alpaca_paper_asset_binding_from_row,
    verify_alpaca_paper_asset_binding_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import SqlBrokerRequestBudgetRepository
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    instruments,
    phase2_account_lease_heads,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_asset_binding_heads,
    phase4_alpaca_paper_asset_bindings,
    phase4_broker_ingress_receipts,
    phase4_broker_request_permits,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_ID,
    BASE,
    PROVIDER_ACCOUNT_ID,
    RuntimeSystem,
    _alembic_config,
    _runtime_instants,
    _system,
)
from tests.unit.test_alpaca_paper_account_asset_ingress import _asset_body
from tests.unit.test_alpaca_paper_asset_runtime import AssetResolver, FixedAssetTransport

PROVIDER_ASSET_ID = "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415"
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
ROOT = Path(__file__).resolve().parents[2]


class CapturingAssetBindingRecorder:
    def __init__(self, delegate: SqlAlpacaPaperAssetBindingRepository) -> None:
        self.delegate = delegate
        self.evidence: list[AlpacaPaperAuthenticatedAssetEvidence] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> AlpacaPaperAuthenticatedAssetBinding:
        self.evidence.append(evidence)
        return self.delegate.record(evidence)


class AssetEvidenceCaptured(RuntimeError):
    pass


class CaptureOnlyAssetBindingRecorder:
    def __init__(self) -> None:
        self.evidence: list[AlpacaPaperAuthenticatedAssetEvidence] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> Never:
        self.evidence.append(evidence)
        raise AssetEvidenceCaptured


@dataclass(slots=True)
class AssetPersistenceSystem:
    account: RuntimeSystem
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    bindings: SqlAlpacaPaperAssetBindingRepository
    capture: CapturingAssetBindingRecorder

    def observe(
        self,
        suffix: str,
        *,
        instrument_id: str = "US-ETF-SPY",
        symbol: str = "SPY",
        provider_asset_id: str = PROVIDER_ASSET_ID,
        body: bytes | None = None,
        binding_recorder: (
            CapturingAssetBindingRecorder | CaptureOnlyAssetBindingRecorder | None
        ) = None,
    ) -> AlpacaPaperAuthenticatedAssetBinding:
        credential_reference = AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id=PROVIDER_ACCOUNT_ID,
            secret_ref="secret://paper/alpaca/trading",
            secret_version="version-001",
        )
        description = create_alpaca_asset_observation_description(
            account_id=ACCOUNT_ID,
            instrument_id=instrument_id,
            symbol=symbol,
        )
        return _observe_authenticated_alpaca_paper_asset_with_transport(
            security_reference=AlpacaPaperSecurityReference(
                credential_reference=credential_reference,
                instrument_id=instrument_id,
                symbol=symbol,
                expected_provider_asset_id=provider_asset_id,
            ),
            account_binding=self.account_binding,
            description=description,
            credential_resolver=AssetResolver(),
            transport=FixedAssetTransport(
                request_id=f"phase4h-provider-request-{suffix}",
                body=_asset_body() if body is None else body,
            ),
            budget=SqlBrokerRequestBudgetRepository(
                engine=self.account.engine,
                clock=self.account.clock,
            ),
            account_bindings=self.account.bindings,
            coordinator=self.account.coordinator,
            fence=self.account.fence,
            ingress_recorder=SqlBrokerIngressRepository(self.account.engine),
            binding_recorder=self.capture if binding_recorder is None else binding_recorder,
            clock=self.account.clock,
            request_idempotency_key=f"phase4h-asset-request-{suffix}",
            delivery_idempotency_key=f"phase4h-asset-delivery-{suffix}",
        )


def _seed_instruments(engine: Engine, *instrument_symbols: tuple[str, str]) -> None:
    with engine.begin() as connection:
        for instrument_id, symbol in instrument_symbols:
            connection.execute(
                sa.insert(instruments).values(
                    instrument_id=instrument_id,
                    name=f"{symbol} test instrument",
                    asset_class="etf",
                    currency="USD",
                    created_at=BASE,
                )
            )


def _asset_system(
    database_path: Path,
    *,
    account_run_count: int = 1,
    asset_run_count: int = 1,
    migrated: bool = False,
) -> AssetPersistenceSystem:
    account = _system(
        database_path,
        run_count=account_run_count,
        migrated=migrated,
    )
    _seed_instruments(account.engine, ("US-ETF-SPY", "SPY"))
    account_binding = account.observe("asset-source")
    for run_index in range(asset_run_count):
        account.clock._instants.extend(
            _asset_sql_runtime_instants(
                BASE + timedelta(seconds=(account_run_count * 2) - 1 + (run_index * 2))
            )
        )
    bindings = SqlAlpacaPaperAssetBindingRepository(account.engine)
    return AssetPersistenceSystem(
        account=account,
        account_binding=account_binding,
        bindings=bindings,
        capture=CapturingAssetBindingRecorder(bindings),
    )


def _asset_sql_runtime_instants(start: datetime) -> tuple[datetime, ...]:
    return (
        start,
        start + timedelta(milliseconds=50),
        start + timedelta(milliseconds=100),
        start + timedelta(milliseconds=200),
        start + timedelta(milliseconds=300),
        start + timedelta(milliseconds=300),
        start + timedelta(milliseconds=400),
        start + timedelta(milliseconds=500),
        start + timedelta(milliseconds=600),
        start + timedelta(milliseconds=700),
        start + timedelta(milliseconds=800),
        start + timedelta(milliseconds=900),
        start + timedelta(milliseconds=900),
        start + timedelta(seconds=1),
    )


def _append_later_account_runtime_instants(system: AssetPersistenceSystem) -> None:
    second_account_run = _runtime_instants(2)[13:]
    system.account.clock._instants.extend(
        instant + timedelta(seconds=1) for instant in second_account_run
    )


def _asset_body_for(
    *,
    symbol: str,
    provider_asset_id: str = PROVIDER_ASSET_ID,
) -> bytes:
    value = json.loads(_asset_body())
    assert type(value) is dict
    value["symbol"] = symbol
    value["id"] = provider_asset_id
    value["name"] = f"{symbol} test instrument"
    return json.dumps(value, separators=(",", ":")).encode()


def test_record_load_history_replay_and_exact_sources(tmp_path: Path) -> None:
    system = _asset_system(tmp_path / "asset-binding.sqlite")

    binding = system.observe("001")
    retried = system.bindings.record(system.capture.evidence[0])

    assert retried == binding
    assert binding.sequence_number == 1
    assert binding.previous_binding_sha256 is None
    assert binding.expected_provider_asset_id == PROVIDER_ASSET_ID
    assert system.bindings.load(binding.binding_id) == binding
    assert system.bindings.history(ACCOUNT_ID, "US-ETF-SPY") == (binding,)
    verify_alpaca_paper_asset_binding_integrity(system.account.engine)
    with system.account.engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase4_alpaca_paper_asset_bindings).where(
                    phase4_alpaca_paper_asset_bindings.c.binding_id == binding.binding_id
                )
            )
            .mappings()
            .one()
        )
        assert alpaca_paper_asset_binding_from_row(row) == binding
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_asset_bindings)
            )
            == 1
        )


def test_account_binding_authenticator_requires_exact_terminal_and_fresh(
    tmp_path: Path,
) -> None:
    system = _asset_system(tmp_path / "account-binding-freshness.sqlite")
    source = system.account_binding

    receipt = system.account.bindings.authenticate_terminal_fresh(
        source,
        source.qualified_at,
    )

    assert receipt.binding_id == source.binding_id
    assert receipt.binding_sha256 == source.semantic_sha256
    assert receipt.checked_at == source.qualified_at
    with pytest.raises(AlpacaPaperAccountBindingConflict, match="not fresh"):
        system.account.bindings.authenticate_terminal_fresh(
            source,
            source.valid_until,
        )


def test_account_predecessor_corruption_blocks_asset_runtime_and_reads(
    tmp_path: Path,
) -> None:
    system = _asset_system(
        tmp_path / "asset-account-broken-predecessor.sqlite",
        account_run_count=2,
        asset_run_count=2,
    )
    first_account = system.account_binding
    terminal_account = system.account.observe("asset-terminal")
    system.account_binding = terminal_account
    asset = system.observe("001")

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.binding_id == first_account.binding_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="before asset transport",
    ):
        system.observe("002")
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.load(asset.binding_id)
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.record(system.capture.evidence[0])


def test_permit_predecessor_corruption_blocks_asset_runtime_and_reads(
    tmp_path: Path,
) -> None:
    system = _asset_system(
        tmp_path / "asset-permit-broken-predecessor.sqlite",
        asset_run_count=2,
    )
    asset = system.observe("001")

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_request_permits)
            .where(phase4_broker_request_permits.c.permit_id == system.account_binding.permit_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(BrokerRequestBudgetError, match="canonical_payload"):
        system.observe("002")
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.load(asset.binding_id)
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.record(system.capture.evidence[0])


def test_unbound_ingress_ancestor_corruption_blocks_asset_runtime_and_reads(
    tmp_path: Path,
) -> None:
    system = _asset_system(
        tmp_path / "asset-ingress-broken-predecessor.sqlite",
        asset_run_count=2,
    )
    ancestor = SqlBrokerIngressRepository(system.account.engine).record(
        BrokerIngressDelivery(
            account_id=ACCOUNT_ID,
            delivery_idempotency_key="phase4h-unqualified-ingress-ancestor",
            provider_id="alpaca-paper",
            adapter_version="1.0.0",
            environment="paper",
            channel="trading-rest",
            operation="unqualified-asset-probe",
            correlation_sha256="e" * 64,
            transport_status=503,
            provider_request_id="phase4h-unqualified-request",
            media_type="application/json",
            received_at=BASE + timedelta(milliseconds=850),
            recorded_at=BASE + timedelta(milliseconds=900),
            body=b'{"message":"temporarily unavailable"}',
        )
    )
    asset = system.observe("001")

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(phase4_broker_ingress_receipts.c.receipt_id == ancestor.receipt_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="before asset transport",
    ):
        system.observe("002")
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.load(asset.binding_id)
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        system.bindings.record(system.capture.evidence[0])


def test_later_account_successor_preserves_historical_terminal_proof(
    tmp_path: Path,
) -> None:
    system = _asset_system(tmp_path / "historical-terminal.sqlite")
    asset = system.observe("001")

    _append_later_account_runtime_instants(system)
    later_account = system.account.observe("later")

    assert later_account.sequence_number == 2
    assert later_account.qualified_at > asset.post_account_binding_checked_at
    assert system.bindings.load(asset.binding_id) == asset
    assert system.bindings.record(system.capture.evidence[0]) == asset
    verify_alpaca_paper_asset_binding_integrity(system.account.engine)


def test_new_append_rejects_account_source_that_lost_terminal_position(
    tmp_path: Path,
) -> None:
    system = _asset_system(tmp_path / "stale-account-source.sqlite")
    capture = CaptureOnlyAssetBindingRecorder()
    with pytest.raises(AssetEvidenceCaptured):
        system.observe("pending", binding_recorder=capture)

    _append_later_account_runtime_instants(system)
    later_account = system.account.observe("later")
    assert later_account.sequence_number == 2

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="exact current terminal account source",
    ):
        system.bindings.record(capture.evidence[0])
    assert system.bindings.history(ACCOUNT_ID, "US-ETF-SPY") == ()


def test_provider_uuid_or_symbol_cannot_alias_another_instrument(
    tmp_path: Path,
) -> None:
    system = _asset_system(
        tmp_path / "asset-alias.sqlite",
        asset_run_count=2,
    )
    _seed_instruments(system.account.engine, ("US-ETF-QQQ", "QQQ"))
    original = system.observe("spy")

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="already bound to another instrument",
    ):
        system.observe(
            "qqq",
            instrument_id="US-ETF-QQQ",
            symbol="QQQ",
            body=_asset_body_for(symbol="QQQ"),
        )

    assert system.bindings.history(ACCOUNT_ID, "US-ETF-SPY") == (original,)
    assert system.bindings.history(ACCOUNT_ID, "US-ETF-QQQ") == ()


def test_tamper_and_source_deletion_are_detected(tmp_path: Path) -> None:
    system = _asset_system(tmp_path / "asset-tamper.sqlite", migrated=True)
    binding = system.observe("001")

    with pytest.raises(IntegrityError), system.account.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_alpaca_paper_account_binding_heads).where(
                phase4_alpaca_paper_account_binding_heads.c.account_id == ACCOUNT_ID
            )
        )
        connection.execute(
            sa.delete(phase4_alpaca_paper_account_bindings).where(
                phase4_alpaca_paper_account_bindings.c.binding_id == binding.account_binding_id
            )
        )

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_asset_bindings)
            .where(phase4_alpaca_paper_asset_bindings.c.binding_id == binding.binding_id)
            .values(evidence_sha256="0" * 64)
        )
    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="evidence digest",
    ):
        system.bindings.load(binding.binding_id)
    with pytest.raises(AlpacaPaperAssetBindingConflict):
        verify_alpaca_paper_asset_binding_integrity(system.account.engine)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="asset-binding integrity verification failed",
    ):
        verify_operational_schema(
            system.account.engine,
            require_phase_zero_facts=False,
        )


def test_load_and_replay_authenticate_the_complete_predecessor_chain(
    tmp_path: Path,
) -> None:
    system = _asset_system(
        tmp_path / "asset-broken-ancestor.sqlite",
        asset_run_count=2,
    )
    first = system.observe("001")
    second = system.observe("002")

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_asset_bindings)
            .where(phase4_alpaca_paper_asset_bindings.c.binding_id == first.binding_id)
            .values(evidence_sha256="0" * 64)
        )

    with pytest.raises(AlpacaPaperAssetBindingConflict, match="evidence digest"):
        system.bindings.load(second.binding_id)
    with pytest.raises(AlpacaPaperAssetBindingConflict, match="evidence digest"):
        system.bindings.record(system.capture.evidence[1])


def test_phase4h_migration_is_additive_reversible_and_refuses_nonempty_downgrade(
    tmp_path: Path,
) -> None:
    empty_url = f"sqlite+pysqlite:///{tmp_path / 'asset-empty.sqlite'}"
    config = _alembic_config(empty_url)
    command.upgrade(config, "0013_phase4_account_binding")
    prior_engine = create_database_engine(empty_url)
    prior_tables = set(inspect(prior_engine).get_table_names())
    prior_engine.dispose()

    command.upgrade(config, "0014_phase4_asset_binding")
    upgraded = create_database_engine(empty_url)
    assert set(inspect(upgraded).get_table_names()) == prior_tables | {
        phase4_alpaca_paper_asset_binding_heads.name,
        phase4_alpaca_paper_asset_bindings.name,
    }
    upgraded.dispose()
    command.downgrade(config, "0013_phase4_account_binding")
    downgraded = create_database_engine(empty_url)
    assert set(inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()

    populated = _asset_system(
        tmp_path / "asset-populated.sqlite",
        migrated=True,
    )
    persisted = populated.observe("001")
    populated.account.engine.dispose()
    populated_url = f"sqlite+pysqlite:///{tmp_path / 'asset-populated.sqlite'}"
    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after durable Alpaca paper asset bindings",
    ):
        command.downgrade(
            _alembic_config(populated_url),
            "0013_phase4_account_binding",
        )
    preserved = create_database_engine(populated_url)
    with preserved.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_asset_bindings)
                .where(phase4_alpaca_paper_asset_bindings.c.binding_id == persisted.binding_id)
            )
            == 1
        )
    preserved.dispose()


@pytest.fixture
def phase4h_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4H tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def test_postgresql_shared_account_lock_serializes_cross_instrument_heads(
    phase4h_postgres_engine: Engine,
) -> None:
    engine = phase4h_postgres_engine
    account_id = f"phase4h-pg-{uuid4().hex[:20]}"
    # The full PostgreSQL setup is exercised by the Phase 4G source fixture;
    # this assertion guards the asset repository's chosen serialization seam.
    first_lock_acquired = Event()
    second_lock_attempted = Event()
    release_first_lock = Event()

    # A focused lock-only transaction proves both instrument paths contend on
    # the account row; evidence construction remains covered by SQLite and the
    # Phase 4H runtime suite.
    from packages.persistence.account_coordinator import (
        _write_transaction,
        lock_account_capacity_serialization,
    )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=account_id,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE,
            )
        )

    try:

        def lock_once(*, first_holder: bool) -> None:
            with _write_transaction(engine) as connection:
                if not first_holder:
                    second_lock_attempted.set()
                lock_account_capacity_serialization(connection, account_id)
                if first_holder:
                    first_lock_acquired.set()
                    if not release_first_lock.wait(timeout=10):
                        raise TimeoutError("first asset lock holder was not released")

        with ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="phase4h-asset-lock",
        ) as executor:
            first = executor.submit(lock_once, first_holder=True)
            assert first_lock_acquired.wait(timeout=10)
            second = executor.submit(lock_once, first_holder=False)
            assert second_lock_attempted.wait(timeout=10)
            deadline = time.monotonic() + 10
            waited = False
            while time.monotonic() < deadline:
                with engine.connect() as connection:
                    waited = bool(
                        connection.scalar(
                            sa.text(
                                """
                                SELECT EXISTS (
                                    SELECT 1
                                    FROM pg_stat_activity
                                    WHERE datname = current_database()
                                      AND pid <> pg_backend_pid()
                                      AND wait_event_type = 'Lock'
                                      AND query LIKE '%phase2_account_lease_heads%'
                                      AND query LIKE '%FOR UPDATE%'
                                )
                                """
                            )
                        )
                    )
                if waited:
                    break
                time.sleep(0.01)
            assert waited
            release_first_lock.set()
            first.result(timeout=10)
            second.result(timeout=10)
    finally:
        release_first_lock.set()
        with engine.begin() as connection:
            connection.execute(
                sa.delete(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == account_id
                )
            )
