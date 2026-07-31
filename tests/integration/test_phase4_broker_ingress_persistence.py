from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from threading import Barrier, Event, current_thread
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event, make_url

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_VERSION,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAccountObservationOutcome,
    AlpacaAssetObservationOutcome,
    AlpacaPaperAccountAssetObservationError,
    create_alpaca_account_observation_description,
    create_alpaca_asset_observation_description,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL,
    ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION,
    ALPACA_PAPER_ASSET_INGRESS_CHANNEL,
    ALPACA_PAPER_ASSET_INGRESS_OPERATION,
    ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
    ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
    persist_then_decode_alpaca_account_observation_response,
    persist_then_decode_alpaca_asset_observation_response,
    persist_then_decode_alpaca_client_order_lookup_response,
)
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaClientOrderLookupDescription,
    AlpacaClientOrderLookupOutcome,
    AlpacaPaperObservationError,
    create_alpaca_client_order_lookup_description,
)
from packages.domain.broker_ingress import (
    BrokerIngressConflict,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
)
from packages.domain.walking_thread import WalkingThread
from packages.persistence.broker_ingress import (
    SqlBrokerIngressRepository,
    broker_ingress_receipt_from_row,
    immutable_broker_ingress_values,
    verify_broker_ingress_integrity,
)
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
)

RECEIVED_AT = datetime(2026, 7, 26, 15, 0, tzinfo=UTC)
RECORDED_AT = RECEIVED_AT + timedelta(milliseconds=2)
DEFAULT_ACCOUNT_ID = "paper-account"
ROOT = Path(__file__).resolve().parents[2]
BROKER_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/broker/alpaca_paper"
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


@pytest.fixture
def phase4_postgres_engine() -> Iterator[Engine]:
    """Migrate only an explicitly selected PostgreSQL test database."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4 ingress tests")
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


def _engine(path: Path, *account_ids: str) -> sa.Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    with engine.begin() as connection:
        for account_id in account_ids:
            connection.execute(
                sa.insert(phase2_account_lease_heads).values(
                    account_id=account_id,
                    last_fencing_generation=0,
                    current_fencing_generation=None,
                    current_lease_sha256=None,
                    updated_at=RECEIVED_AT,
                )
            )
    return engine


def _delivery(
    *,
    account_id: str = DEFAULT_ACCOUNT_ID,
    delivery_idempotency_key: str = "lookup-attempt-001",
    received_at: datetime = RECEIVED_AT,
    recorded_at: datetime = RECORDED_AT,
    body: bytes = b'{"id":"provider-order-1","status":"new"}',
) -> BrokerIngressDelivery:
    return BrokerIngressDelivery(
        account_id=account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id="alpaca",
        adapter_version="1.0.0",
        environment="paper",
        channel="trading-rest",
        operation="get-order-by-client-order-id",
        correlation_sha256="a" * 64,
        transport_status=200,
        provider_request_id=f"request-{delivery_idempotency_key}",
        media_type="application/json",
        received_at=received_at,
        recorded_at=recorded_at,
        body=body,
    )


def _count(engine: sa.Engine) -> int:
    with engine.connect() as connection:
        value = connection.scalar(
            sa.select(sa.func.count()).select_from(phase4_broker_ingress_receipts)
        )
    assert isinstance(value, int)
    return value


def test_record_commits_exact_raw_bytes_before_any_decode(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "raw-ingress.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    malformed = b"\xff\x00not-json{\x80"

    receipt = repository.record(_delivery(body=malformed))

    assert repository.runtime_store_identity == id(engine)
    assert receipt.ingress_sequence == 1
    assert receipt.previous_receipt_sha256 is None
    assert receipt.delivery.body == malformed
    assert receipt.delivery.body_size_bytes == len(malformed)
    assert repository.load(receipt.receipt_id) == receipt
    assert repository.history(DEFAULT_ACCOUNT_ID) == (receipt,)
    with engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase4_broker_ingress_receipts).where(
                    phase4_broker_ingress_receipts.c.receipt_id == receipt.receipt_id
                )
            )
            .mappings()
            .one()
        )
        assert row["body"] == malformed
        assert broker_ingress_receipt_from_row(row) == receipt


def test_empty_payload_is_retained_as_a_first_class_delivery(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "empty-ingress.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)

    receipt = repository.record(_delivery(body=b""))

    assert receipt.delivery.body == b""
    assert receipt.delivery.body_size_bytes == 0
    assert repository.load(receipt.receipt_id) == receipt


def test_exact_retry_returns_original_without_consuming_sequence(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "exact-retry.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    first_delivery = _delivery()

    first = repository.record(first_delivery)
    retried = repository.record(first_delivery)
    second = repository.record(
        _delivery(
            delivery_idempotency_key="lookup-attempt-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )

    assert retried == first
    assert retried.receipt_id == first.receipt_id
    assert second.ingress_sequence == 2
    assert second.previous_receipt_sha256 == first.semantic_sha256
    assert _count(engine) == 2


def test_conflicting_retry_is_rejected_without_consuming_sequence(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "conflicting-retry.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    first_delivery = _delivery()
    first = repository.record(first_delivery)

    with pytest.raises(BrokerIngressConflict, match="identity conflicts"):
        repository.record(
            replace(
                first_delivery,
                transport_status=404,
                body=b'{"code":40410000,"message":"order not found"}',
            )
        )

    second = repository.record(
        _delivery(
            delivery_idempotency_key="lookup-attempt-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )
    assert second.ingress_sequence == 2
    assert second.previous_receipt_sha256 == first.semantic_sha256
    assert _count(engine) == 2


def test_duplicate_bodies_are_distinct_transport_deliveries(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "duplicate-body.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    body = b'{"id":"same-provider-order","status":"new"}'

    first = repository.record(_delivery(delivery_idempotency_key="delivery-001", body=body))
    second = repository.record(
        _delivery(
            delivery_idempotency_key="delivery-002",
            received_at=RECEIVED_AT + timedelta(milliseconds=1),
            recorded_at=RECORDED_AT + timedelta(milliseconds=1),
            body=body,
        )
    )

    assert first.delivery.body_sha256 == second.delivery.body_sha256
    assert first.receipt_id != second.receipt_id
    assert first.delivery.semantic_sha256 != second.delivery.semantic_sha256
    assert repository.history(DEFAULT_ACCOUNT_ID) == (first, second)


def test_account_local_sequences_are_independent(tmp_path: Path) -> None:
    account_a = "paper-account-a"
    account_b = "paper-account-b"
    engine = _engine(tmp_path / "independent-accounts.sqlite", account_a, account_b)
    repository = SqlBrokerIngressRepository(engine)

    first_a = repository.record(_delivery(account_id=account_a))
    first_b = repository.record(_delivery(account_id=account_b))
    second_a = repository.record(
        _delivery(
            account_id=account_a,
            delivery_idempotency_key="lookup-attempt-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )

    assert (first_a.ingress_sequence, second_a.ingress_sequence) == (1, 2)
    assert first_b.ingress_sequence == 1
    assert first_a.previous_receipt_sha256 is None
    assert first_b.previous_receipt_sha256 is None
    assert second_a.previous_receipt_sha256 == first_a.semantic_sha256
    assert repository.history(account_a) == (first_a, second_a)
    assert repository.history(account_b) == (first_b,)
    verify_broker_ingress_integrity(engine)


def test_concurrent_deliveries_receive_one_contiguous_account_sequence(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "concurrent-sequence.sqlite", DEFAULT_ACCOUNT_ID)
    worker_count = 8
    barrier = Barrier(worker_count)

    def record(index: int) -> BrokerIngressReceipt:
        barrier.wait()
        return SqlBrokerIngressRepository(engine).record(
            _delivery(
                delivery_idempotency_key=f"concurrent-delivery-{index:03d}",
                received_at=RECEIVED_AT + timedelta(microseconds=index),
                recorded_at=RECORDED_AT + timedelta(microseconds=index),
                body=f'{{"worker":{index}}}'.encode(),
            )
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        receipts = tuple(executor.map(record, range(worker_count)))

    assert {receipt.ingress_sequence for receipt in receipts} == set(range(1, worker_count + 1))
    history = SqlBrokerIngressRepository(engine).history(DEFAULT_ACCOUNT_ID)
    assert tuple(receipt.ingress_sequence for receipt in history) == tuple(
        range(1, worker_count + 1)
    )
    assert all(
        receipt.previous_receipt_sha256 == prior.semantic_sha256
        for prior, receipt in pairwise(history)
    )


def test_postgres_history_remains_on_one_snapshot_during_concurrent_append(
    phase4_postgres_engine: Engine,
) -> None:
    token = uuid4().hex
    account_id = f"phase4-history-{token}"
    repository = SqlBrokerIngressRepository(phase4_postgres_engine)
    receipts_selected = Event()
    allow_head_read = Event()

    with phase4_postgres_engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=account_id,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=RECEIVED_AT,
            )
        )
    first = repository.record(
        _delivery(
            account_id=account_id,
            delivery_idempotency_key=f"history-first-{token}",
        )
    )

    def pause_reader_after_receipt_query(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if (
            current_thread().name.startswith("phase4-history-reader")
            and "FROM phase4_broker_ingress_receipts" in statement
            and "ORDER BY phase4_broker_ingress_receipts.ingress_sequence" in statement
        ):
            receipts_selected.set()
            if not allow_head_read.wait(timeout=10):
                raise TimeoutError("history reader was not released")

    event.listen(
        phase4_postgres_engine,
        "after_cursor_execute",
        pause_reader_after_receipt_query,
    )
    try:
        with ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="phase4-history-reader",
        ) as executor:
            snapshot_future = executor.submit(repository.history, account_id)
            assert receipts_selected.wait(timeout=10)
            second = repository.record(
                _delivery(
                    account_id=account_id,
                    delivery_idempotency_key=f"history-second-{token}",
                    received_at=RECEIVED_AT + timedelta(seconds=1),
                    recorded_at=RECORDED_AT + timedelta(seconds=1),
                )
            )
            allow_head_read.set()
            snapshot = snapshot_future.result(timeout=10)

        assert snapshot == (first,)
        assert repository.history(account_id) == (first, second)
        verify_broker_ingress_integrity(phase4_postgres_engine)
    finally:
        allow_head_read.set()
        event.remove(
            phase4_postgres_engine,
            "after_cursor_execute",
            pause_reader_after_receipt_query,
        )
        with phase4_postgres_engine.begin() as connection:
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


def test_record_requires_preexisting_account_serialization_head(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "missing-head.sqlite")
    repository = SqlBrokerIngressRepository(engine)

    with pytest.raises(BrokerIngressError, match="account head does not exist"):
        repository.record(_delivery())

    assert _count(engine) == 0


def test_ingress_head_cannot_claim_a_positive_sequence_without_terminal_digest(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "invalid-head.sqlite", DEFAULT_ACCOUNT_ID)

    with (
        pytest.raises(sa.exc.IntegrityError),
        engine.begin() as connection,
    ):
        connection.execute(
            sa.insert(phase4_broker_ingress_heads).values(
                account_id=DEFAULT_ACCOUNT_ID,
                last_ingress_sequence=1,
                last_receipt_sha256=None,
            )
        )


def test_three_receipts_form_a_contiguous_authenticated_chain(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "chain.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    receipts = tuple(
        repository.record(
            _delivery(
                delivery_idempotency_key=f"lookup-attempt-{sequence:03d}",
                received_at=RECEIVED_AT + timedelta(seconds=sequence),
                recorded_at=RECORDED_AT + timedelta(seconds=sequence),
                body=f'{{"sequence":{sequence}}}'.encode(),
            )
        )
        for sequence in range(1, 4)
    )

    assert tuple(receipt.ingress_sequence for receipt in receipts) == (1, 2, 3)
    assert tuple(receipt.previous_receipt_sha256 for receipt in receipts) == (
        None,
        receipts[0].semantic_sha256,
        receipts[1].semantic_sha256,
    )
    assert repository.history(DEFAULT_ACCOUNT_ID) == receipts
    verify_broker_ingress_integrity(engine)
    with engine.connect() as connection:
        head = (
            connection.execute(
                sa.select(phase4_broker_ingress_heads).where(
                    phase4_broker_ingress_heads.c.account_id == DEFAULT_ACCOUNT_ID
                )
            )
            .mappings()
            .one()
        )
        assert head["last_ingress_sequence"] == 3
        assert head["last_receipt_sha256"] == receipts[-1].semantic_sha256


def test_terminal_head_prevents_tail_deletion(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "protected-tail.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    first = repository.record(_delivery(delivery_idempotency_key="delivery-001"))
    second = repository.record(
        _delivery(
            delivery_idempotency_key="delivery-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )

    with (
        pytest.raises(sa.exc.IntegrityError),
        engine.begin() as connection,
    ):
        connection.execute(
            sa.delete(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.receipt_id == second.receipt_id
            )
        )

    assert repository.history(DEFAULT_ACCOUNT_ID) == (first, second)


def test_head_detects_tail_loss_even_when_database_constraints_are_bypassed(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "missing-tail.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    repository.record(_delivery(delivery_idempotency_key="delivery-001"))
    second = repository.record(
        _delivery(
            delivery_idempotency_key="delivery-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.delete(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.receipt_id == second.receipt_id
            )
        )
        connection.commit()

    with pytest.raises(BrokerIngressError, match="head sequence conflicts"):
        repository.history(DEFAULT_ACCOUNT_ID)
    with pytest.raises(BrokerIngressError, match="missing terminal receipt"):
        repository.record(
            _delivery(
                delivery_idempotency_key="delivery-003",
                received_at=RECEIVED_AT + timedelta(seconds=2),
                recorded_at=RECORDED_AT + timedelta(seconds=2),
            )
        )
    with pytest.raises(BrokerIngressError, match="head sequence conflicts"):
        verify_broker_ingress_integrity(engine)


@pytest.mark.parametrize(
    ("column_name", "tampered_value", "message"),
    (
        ("provider_id", "tampered-provider", "delivery_sha256 conflicts"),
        ("body_sha256", "f" * 64, "body_sha256 conflicts"),
        ("canonical_payload", '["tampered"]', "canonical_payload conflicts"),
        ("semantic_sha256", "f" * 64, "semantic_sha256 conflicts"),
    ),
)
def test_load_rejects_tampered_immutable_columns(
    tmp_path: Path,
    column_name: str,
    tampered_value: str,
    message: str,
) -> None:
    engine = _engine(tmp_path / f"tamper-{column_name}.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    receipt = repository.record(_delivery())
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(phase4_broker_ingress_receipts.c.receipt_id == receipt.receipt_id)
            .values(**{column_name: tampered_value})
        )
        connection.commit()

    with pytest.raises(BrokerIngressError, match=message):
        repository.load(receipt.receipt_id)
    with pytest.raises(BrokerIngressError, match=message):
        verify_broker_ingress_integrity(engine)


def test_history_rejects_a_tampered_predecessor_chain(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "tampered-chain.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    first = repository.record(_delivery(delivery_idempotency_key="delivery-001"))
    repository.record(
        _delivery(
            delivery_idempotency_key="delivery-002",
            received_at=RECEIVED_AT + timedelta(seconds=1),
            recorded_at=RECORDED_AT + timedelta(seconds=1),
        )
    )
    third = repository.record(
        _delivery(
            delivery_idempotency_key="delivery-003",
            received_at=RECEIVED_AT + timedelta(seconds=2),
            recorded_at=RECORDED_AT + timedelta(seconds=2),
        )
    )
    tampered_third = BrokerIngressReceipt(
        delivery=third.delivery,
        ingress_sequence=third.ingress_sequence,
        previous_receipt_sha256=first.semantic_sha256,
    )
    tampered_values = immutable_broker_ingress_values(tampered_third)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(phase4_broker_ingress_receipts.c.receipt_id == third.receipt_id)
            .values(
                previous_receipt_sha256=first.semantic_sha256,
                canonical_payload=tampered_values["canonical_payload"],
                semantic_sha256=tampered_values["semantic_sha256"],
            )
        )
        connection.commit()

    with pytest.raises(BrokerIngressError, match="predecessor chain conflicts"):
        repository.history(DEFAULT_ACCOUNT_ID)


def test_load_validates_receipt_identity_and_reports_absence(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "load.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)

    assert repository.load("f" * 64) is None
    with pytest.raises(BrokerIngressError, match="receipt ID"):
        repository.load("not-a-digest")


def _lookup_description() -> AlpacaClientOrderLookupDescription:
    return create_alpaca_client_order_lookup_description(
        account_id=DEFAULT_ACCOUNT_ID,
        submission=create_alpaca_paper_submission_description(WalkingThread.run().intent),
    )


def test_alpaca_lookup_boundary_persists_before_successful_decode(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "persist-then-decode.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    description = _lookup_description()
    body = (BROKER_FIXTURES / "lookup_found.json").read_bytes()

    result = persist_then_decode_alpaca_client_order_lookup_response(
        repository,
        description,
        delivery_idempotency_key="lookup-found-delivery",
        http_status=200,
        provider_request_id="phase4c-found-request",
        response_body=body,
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )

    assert result.observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert result.receipt == repository.load(result.receipt.receipt_id)
    assert result.receipt.delivery.adapter_version == ALPACA_PAPER_ADAPTER_VERSION
    assert result.receipt.delivery.channel == ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL
    assert result.receipt.delivery.operation == ALPACA_PAPER_LOOKUP_INGRESS_OPERATION
    assert result.receipt.delivery.correlation_sha256 == description.semantic_sha256
    assert result.receipt.delivery.body == body
    assert result.normalized_fact_authorized is False
    assert result.lifecycle_application_authorized is False
    assert result.trading_effect_authorized is False


def test_alpaca_account_and_asset_boundaries_persist_through_sql(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "account-asset-ingress.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    account_description = create_alpaca_account_observation_description(
        account_id=DEFAULT_ACCOUNT_ID
    )
    asset_description = create_alpaca_asset_observation_description(
        account_id=DEFAULT_ACCOUNT_ID,
        instrument_id="US-ETF-SPY",
        symbol="SPY",
    )
    account_body = (BROKER_FIXTURES / "account_active.json").read_bytes()
    asset_body = (BROKER_FIXTURES / "asset_spy_active.json").read_bytes()

    account = persist_then_decode_alpaca_account_observation_response(
        repository,
        account_description,
        delivery_idempotency_key="account-active-delivery",
        http_status=200,
        provider_request_id="phase4e-account-request",
        response_body=account_body,
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )
    asset = persist_then_decode_alpaca_asset_observation_response(
        repository,
        asset_description,
        delivery_idempotency_key="asset-spy-active-delivery",
        http_status=200,
        provider_request_id="phase4e-asset-request",
        response_body=asset_body,
        received_at=RECEIVED_AT + timedelta(milliseconds=1),
        recorded_at=RECORDED_AT + timedelta(milliseconds=1),
    )

    assert account.observation.outcome is (
        AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    )
    assert asset.observation.outcome is (AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE)
    assert account.receipt.ingress_sequence == 1
    assert asset.receipt.ingress_sequence == 2
    assert asset.receipt.previous_receipt_sha256 == account.receipt.semantic_sha256
    assert account.receipt.delivery.channel == ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL
    assert account.receipt.delivery.operation == ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION
    assert asset.receipt.delivery.channel == ALPACA_PAPER_ASSET_INGRESS_CHANNEL
    assert asset.receipt.delivery.operation == ALPACA_PAPER_ASSET_INGRESS_OPERATION
    assert repository.history(DEFAULT_ACCOUNT_ID) == (account.receipt, asset.receipt)
    assert verify_broker_ingress_integrity(engine) is None
    assert account.normalized_fact_authorized is False
    assert asset.normalized_fact_authorized is False
    assert account.trading_effect_authorized is False
    assert asset.trading_effect_authorized is False


def test_alpaca_account_asset_decode_failure_retains_sql_raw_receipt(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "account-asset-decode-failure.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    malformed = b'{"unreviewed_additive_field":true}'

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="reviewed wire profile",
    ):
        persist_then_decode_alpaca_asset_observation_response(
            repository,
            create_alpaca_asset_observation_description(
                account_id=DEFAULT_ACCOUNT_ID,
                instrument_id="US-ETF-SPY",
                symbol="SPY",
            ),
            delivery_idempotency_key="asset-schema-drift-delivery",
            http_status=200,
            provider_request_id="phase4e-asset-schema-drift-request",
            response_body=malformed,
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )

    (receipt,) = repository.history(DEFAULT_ACCOUNT_ID)
    assert receipt.delivery.body == malformed
    assert receipt.delivery.body_sha256
    assert receipt.ingress_sequence == 1
    assert receipt.normalized_fact_authorized is False


def test_alpaca_decode_failure_cannot_roll_back_raw_receipt(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "decode-failure-retained.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    description = _lookup_description()
    malformed = b'{"unreviewed_additive_field":true}'

    with pytest.raises(AlpacaPaperObservationError, match="accepted wire profile"):
        persist_then_decode_alpaca_client_order_lookup_response(
            repository,
            description,
            delivery_idempotency_key="lookup-schema-drift-delivery",
            http_status=200,
            provider_request_id="phase4c-schema-drift-request",
            response_body=malformed,
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )

    (receipt,) = repository.history(DEFAULT_ACCOUNT_ID)
    assert receipt.delivery.body == malformed
    assert receipt.delivery.body_sha256
    assert receipt.ingress_sequence == 1
    assert receipt.normalized_fact_authorized is False


def test_alpaca_lookup_missing_request_id_is_retained_before_rejection(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "lookup-missing-request-id.sqlite", DEFAULT_ACCOUNT_ID)
    repository = SqlBrokerIngressRepository(engine)
    body = (BROKER_FIXTURES / "lookup_found.json").read_bytes()

    with pytest.raises(AlpacaPaperObservationError, match="missing X-Request-ID"):
        persist_then_decode_alpaca_client_order_lookup_response(
            repository,
            _lookup_description(),
            delivery_idempotency_key="lookup-missing-request-id-delivery",
            http_status=200,
            provider_request_id=None,
            response_body=body,
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )

    (receipt,) = repository.history(DEFAULT_ACCOUNT_ID)
    assert receipt.delivery.provider_request_id is None
    assert receipt.delivery.body == body
    assert receipt.ingress_sequence == 1


def test_alpaca_boundary_rejects_a_mismatched_receipt_before_decoding() -> None:
    class MismatchedRecorder:
        def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
            return BrokerIngressReceipt(
                delivery=replace(delivery, body=b"different-unpersisted-bytes"),
                ingress_sequence=1,
                previous_receipt_sha256=None,
            )

    with pytest.raises(BrokerIngressError, match="different Alpaca lookup bytes"):
        persist_then_decode_alpaca_client_order_lookup_response(
            MismatchedRecorder(),
            _lookup_description(),
            delivery_idempotency_key="lookup-mismatched-recorder",
            http_status=200,
            provider_request_id="phase4c-mismatched-recorder",
            response_body=b'{"would_fail":"if decoded"}',
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )
