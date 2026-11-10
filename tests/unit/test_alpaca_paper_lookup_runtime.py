from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

import packages.adapters.broker.alpaca_paper_lookup_runtime as runtime_module
from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_TRADING_BASE_URL,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    _alpaca_paper_account_identity_continuity_receipt,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperSecurityReference,
)
from packages.adapters.broker.alpaca_paper_budget import (
    AlpacaPaperBudgetOperation,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT,
    ALPACA_PAPER_LOOKUP_TRANSPORT_ID,
    ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedLookupEvidence,
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
    AlpacaPaperLookupConflict,
    AlpacaPaperLookupTransportError,
    AlpacaPaperLookupTransportRequest,
    AlpacaPaperLookupTransportResponse,
    AlpacaPaperUnknownAttemptFreshnessReceipt,
    _alpaca_paper_authenticated_lookup_receipt,
    _alpaca_paper_unknown_attempt_freshness_receipt,
    _HttpxAlpacaPaperLookupTransport,
    _observe_authenticated_alpaca_paper_unknown_lookup_with_transport,
)
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaClientOrderLookupDescription,
    AlpacaPaperObservationError,
    create_alpaca_client_order_lookup_description,
)
from packages.domain.broker_request_budget import (
    BrokerRequestPermitConflict,
    BrokerRequestPurpose,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
    mark_submission_in_flight,
    mark_submission_unknown,
)
from tests.unit.test_alpaca_paper_account_asset_ingress import (
    InMemoryIngressRecorder,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    ACCOUNT_ID,
    API_KEY_ID,
    SECRET_KEY,
    InMemoryBudget,
    SequenceClock,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    _scenario as account_scenario,
)
from tests.unit.test_submission_attempt import (
    PREPARED_AT,
    fence_receipt,
    intent,
    pending_attempt,
)

REPOSITORY = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY / "tests/fixtures/broker/alpaca_paper"
PROVIDER_ASSET_ID = "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415"
OTHER_PROVIDER_ASSET_ID = "3f4f2c1a-2c5e-45e7-900c-cbb85e7386f1"
LOOKUP_BASE = datetime(2026, 7, 15, 13, 32, 10, tzinfo=UTC)


def _fixture(name: str) -> bytes:
    return (FIXTURE_ROOT / name).read_bytes()


def _body_override(**updates: object) -> bytes:
    value = json.loads(_fixture("lookup_found.json"))
    assert type(value) is dict
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def _unknown_attempt_and_description() -> tuple[
    CanonicalSubmissionAttempt, AlpacaClientOrderLookupDescription
]:
    order_intent = intent()
    submission = create_alpaca_paper_submission_description(order_intent)
    pending = pending_attempt(
        order_intent=order_intent,
        request=submission.request,
    )
    in_flight = mark_submission_in_flight(
        pending,
        dispatch_fence_receipt=fence_receipt(
            validated_at=PREPARED_AT + timedelta(seconds=1),
        ),
        occurred_at=PREPARED_AT + timedelta(seconds=1),
        recorded_at=PREPARED_AT + timedelta(seconds=1),
    )
    unknown = mark_submission_unknown(
        in_flight,
        occurred_at=PREPARED_AT + timedelta(seconds=2),
        recorded_at=PREPARED_AT + timedelta(seconds=2),
        error_class="TransportTimeout",
    )
    return unknown, create_alpaca_client_order_lookup_description(
        account_id=ACCOUNT_ID,
        submission=submission,
    )


class LookupResolver:
    resolver_id = "fixture-secret-store"
    resolver_version = "v1"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.references: list[AlpacaPaperCredentialReference] = []
        self.material: _AlpacaPaperCredentialMaterial | None = None

    def _resolve_for_client_order_lookup(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        self.references.append(reference)
        if self.fail:
            raise RuntimeError(f"unsafe resolver detail {SECRET_KEY}")
        material = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(material) is _AlpacaPaperCredentialMaterial
        self.material = material
        return material


class LookupTransport:
    transport_id = ALPACA_PAPER_LOOKUP_TRANSPORT_ID
    transport_version = ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION

    def __init__(
        self,
        *,
        status: int = 200,
        request_id: str | None = "phase4i-request-001",
        media_type: str | None = ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE,
        body: bytes | None = None,
        fail: bool = False,
    ) -> None:
        self.status = status
        self.request_id = request_id
        self.media_type = media_type
        self.body = _fixture("lookup_found.json") if body is None else body
        self.fail = fail
        self.requests: list[AlpacaPaperLookupTransportRequest] = []

    def execute(
        self,
        request: AlpacaPaperLookupTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperLookupTransportResponse:
        self.requests.append(request)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        if self.fail:
            raise RuntimeError(f"unsafe transport detail {SECRET_KEY}")
        return AlpacaPaperLookupTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=self.status,
            provider_request_id=self.request_id,
            media_type=self.media_type,
            response_body=self.body,
        )


class UnknownAuthenticator:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.fail_on_call = fail_on_call
        self.calls: list[tuple[str, datetime]] = []

    def authenticate_terminal_unknown(
        self,
        attempt: CanonicalSubmissionAttempt,
        checked_at: datetime,
    ) -> AlpacaPaperUnknownAttemptFreshnessReceipt:
        self.calls.append((attempt.attempt_id, checked_at))
        if len(self.calls) == self.fail_on_call:
            raise RuntimeError(f"unsafe UNKNOWN source detail {SECRET_KEY}")
        return _alpaca_paper_unknown_attempt_freshness_receipt(
            attempt,
            checked_at=checked_at,
        )


class IdentityAuthenticator:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.fail_on_call = fail_on_call
        self.calls: list[tuple[str, datetime]] = []

    def authenticate_terminal_identity(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt:
        self.calls.append((binding.binding_id, checked_at))
        if len(self.calls) == self.fail_on_call:
            raise RuntimeError(f"unsafe account source detail {SECRET_KEY}")
        return _alpaca_paper_account_identity_continuity_receipt(
            binding,
            checked_at=checked_at,
        )


class FixedCoordinator:
    account_id = ACCOUNT_ID

    def __init__(
        self,
        *,
        change_fence: bool = False,
        pre_validated_at: datetime = LOOKUP_BASE + timedelta(milliseconds=300),
        post_validated_at: datetime = LOOKUP_BASE + timedelta(seconds=1),
        pre_valid_until: datetime = LOOKUP_BASE + timedelta(seconds=30),
        post_valid_until: datetime = LOOKUP_BASE + timedelta(seconds=30),
    ) -> None:
        self.change_fence = change_fence
        self.pre_validated_at = pre_validated_at
        self.post_validated_at = post_validated_at
        self.pre_valid_until = pre_valid_until
        self.post_valid_until = post_valid_until
        self.calls = 0

    def revalidate(self, fence: object) -> object:
        del fence
        self.calls += 1
        return fence_receipt(
            validated_at=(self.pre_validated_at if self.calls == 1 else self.post_validated_at),
            valid_until=(self.pre_valid_until if self.calls == 1 else self.post_valid_until),
            fencing_generation=(2 if self.change_fence and self.calls == 2 else 1),
        )


class InMemoryLookupRecorder:
    def __init__(self) -> None:
        self.evidence: list[AlpacaPaperAuthenticatedLookupEvidence] = []
        self.receipts: list[AlpacaPaperAuthenticatedLookupReceipt] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedLookupEvidence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        previous = self.receipts[-1].semantic_sha256 if self.receipts else None
        receipt = _alpaca_paper_authenticated_lookup_receipt(
            evidence,
            commit_checked_at=evidence.authenticated_at,
            sequence_number=len(self.receipts) + 1,
            previous_receipt_sha256=previous,
        )
        self.evidence.append(evidence)
        self.receipts.append(receipt)
        return receipt


@dataclass(slots=True)
class LookupScenario:
    security_reference: AlpacaPaperSecurityReference
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    attempt: CanonicalSubmissionAttempt
    description: AlpacaClientOrderLookupDescription
    resolver: LookupResolver
    transport: LookupTransport
    budget: InMemoryBudget
    unknown_attempts: UnknownAuthenticator
    account_bindings: IdentityAuthenticator
    coordinator: FixedCoordinator
    ingress: InMemoryIngressRecorder
    lookups: InMemoryLookupRecorder
    clock: SequenceClock

    def run(
        self,
        *,
        delivery_idempotency_key: str = "phase4i-delivery-001",
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        return _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            attempt=self.attempt,
            description=self.description,
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=self.budget,  # type: ignore[arg-type]
            unknown_attempts=self.unknown_attempts,
            account_bindings=self.account_bindings,  # type: ignore[arg-type]
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=LOOKUP_BASE - timedelta(seconds=1),
                valid_until=LOOKUP_BASE + timedelta(seconds=30),
            ).fence,
            ingress_recorder=self.ingress,
            lookup_recorder=self.lookups,
            clock=self.clock,
            request_idempotency_key="phase4i-request-demand-001",
            delivery_idempotency_key=delivery_idempotency_key,
        )

    def run_public(self) -> AlpacaPaperAuthenticatedLookupReceipt:
        return runtime_module.observe_authenticated_alpaca_paper_unknown_lookup(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            attempt=self.attempt,
            description=self.description,
            credential_resolver=self.resolver,
            budget=self.budget,  # type: ignore[arg-type]
            unknown_attempts=self.unknown_attempts,
            account_bindings=self.account_bindings,  # type: ignore[arg-type]
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=LOOKUP_BASE - timedelta(seconds=1),
                valid_until=LOOKUP_BASE + timedelta(seconds=30),
            ).fence,
            ingress_recorder=self.ingress,
            lookup_recorder=self.lookups,
            clock=self.clock,
            request_idempotency_key="phase4i-request-demand-001",
            delivery_idempotency_key="phase4i-delivery-001",
        )


def _lookup_clock() -> SequenceClock:
    return SequenceClock(
        LOOKUP_BASE,
        LOOKUP_BASE + timedelta(milliseconds=50),
        LOOKUP_BASE + timedelta(milliseconds=100),
        LOOKUP_BASE + timedelta(milliseconds=500),
        LOOKUP_BASE + timedelta(milliseconds=600),
        LOOKUP_BASE + timedelta(milliseconds=700),
        LOOKUP_BASE + timedelta(milliseconds=800),
        LOOKUP_BASE + timedelta(milliseconds=900),
        LOOKUP_BASE + timedelta(milliseconds=1100),
        LOOKUP_BASE + timedelta(milliseconds=1200),
    )


def _scenario(
    *,
    transport: LookupTransport | None = None,
    budget: InMemoryBudget | None = None,
    unknown_attempts: UnknownAuthenticator | None = None,
    account_bindings: IdentityAuthenticator | None = None,
    coordinator: FixedCoordinator | None = None,
    clock: SequenceClock | None = None,
) -> LookupScenario:
    account = account_scenario()
    account_binding = account.run()
    attempt, description = _unknown_attempt_and_description()
    return LookupScenario(
        security_reference=AlpacaPaperSecurityReference(
            credential_reference=account.reference,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            expected_provider_asset_id=PROVIDER_ASSET_ID,
        ),
        account_binding=account_binding,
        attempt=attempt,
        description=description,
        resolver=LookupResolver(),
        transport=transport or LookupTransport(),
        budget=budget
        or InMemoryBudget(
            issued_at=LOOKUP_BASE + timedelta(milliseconds=200),
            checked_at=LOOKUP_BASE + timedelta(milliseconds=400),
        ),
        unknown_attempts=unknown_attempts or UnknownAuthenticator(),
        account_bindings=account_bindings or IdentityAuthenticator(),
        coordinator=coordinator or FixedCoordinator(),
        ingress=InMemoryIngressRecorder(),
        lookups=InMemoryLookupRecorder(),
        clock=clock or _lookup_clock(),
    )


@pytest.mark.parametrize(
    ("status", "body", "expected_outcome", "expected_mismatches"),
    (
        (
            200,
            _fixture("lookup_found.json"),
            AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED,
            (),
        ),
        (
            200,
            _body_override(qty="11"),
            AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH,
            ("quantity",),
        ),
        (
            200,
            _body_override(asset_id=None),
            AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH,
            (),
        ),
        (
            200,
            _body_override(asset_id=OTHER_PROVIDER_ASSET_ID, qty="11"),
            AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH,
            ("quantity",),
        ),
        (
            404,
            _fixture("lookup_not_found.json"),
            AlpacaPaperAuthenticatedLookupOutcome.NOT_VISIBLE_INCONCLUSIVE,
            (),
        ),
    ),
)
def test_closed_lookup_outcomes_are_typed_historical_reconciliation_only(
    status: int,
    body: bytes,
    expected_outcome: AlpacaPaperAuthenticatedLookupOutcome,
    expected_mismatches: tuple[str, ...],
) -> None:
    scenario = _scenario(transport=LookupTransport(status=status, body=body))

    receipt = scenario.run()

    assert receipt.outcome is expected_outcome
    assert receipt.mismatch_fields == expected_mismatches
    assert receipt.reconciliation_required is True
    assert receipt.unknown_resolution_authorized is False
    assert receipt.reservation_release_authorized is False
    assert receipt.lifecycle_application_authorized is False
    assert receipt.canonical_execution_fact_authorized is False
    assert receipt.retry_authorized is False
    assert receipt.trading_effect_authorized is False
    assert scenario.attempt.state is SubmissionAttemptState.UNKNOWN
    assert scenario.ingress.deliveries[0].body == body
    assert (
        scenario.lookups.evidence[0].persisted_observation.receipt == (scenario.ingress.receipts[0])
    )


def test_lookup_uses_new_unknown_permit_and_expired_status_independent_identity() -> None:
    scenario = _scenario()
    assert scenario.account_binding.valid_until < LOOKUP_BASE

    receipt = scenario.run()

    demand = scenario.budget.demands[0]
    request = scenario.transport.requests[0]
    assert demand.operation == (AlpacaPaperBudgetOperation.LOOKUP_UNKNOWN_BY_CLIENT_ORDER_ID.value)
    assert demand.purpose is BrokerRequestPurpose.UNKNOWN_LOOKUP
    assert request.method == "GET"
    assert request.url == (
        f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/orders:by_client_order_id"
        f"?client_order_id={scenario.description.submission.request.client_order_id}"
    )
    assert len(scenario.unknown_attempts.calls) == 2
    assert len(scenario.account_bindings.calls) == 2
    assert receipt.pre_account_identity_sha256 == (
        scenario.lookups.evidence[0].pre_account_identity.semantic_sha256
    )
    assert receipt.fence_fencing_generation == 1
    assert receipt.fence_sha256 == (
        scenario.lookups.evidence[0].pre_fence_receipt.fence.semantic_sha256
    )
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


@pytest.mark.parametrize(
    "transport",
    (
        LookupTransport(body=_body_override(client_order_id="different-client-order-id")),
        LookupTransport(body=b'{"unexpected":true}'),
        LookupTransport(request_id=None),
        LookupTransport(media_type="text/plain"),
        LookupTransport(status=500, body=b'{"provider":"failure"}'),
    ),
)
def test_decode_or_metadata_failure_retains_raw_without_typed_receipt(
    transport: LookupTransport,
) -> None:
    scenario = _scenario(transport=transport)

    with pytest.raises((AlpacaPaperObservationError, AlpacaPaperLookupConflict)):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == transport.body
    assert scenario.lookups.receipts == []
    assert scenario.attempt.state is SubmissionAttemptState.UNKNOWN


@pytest.mark.parametrize("source", ("unknown", "identity"))
def test_pre_transport_terminal_source_failure_cannot_send(source: str) -> None:
    scenario = _scenario(
        unknown_attempts=UnknownAuthenticator(fail_on_call=1 if source == "unknown" else None),
        account_bindings=IdentityAuthenticator(fail_on_call=1 if source == "identity" else None),
    )

    with pytest.raises(AlpacaPaperLookupConflict, match="failed before"):
        scenario.run()

    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []
    assert scenario.lookups.receipts == []


def test_invalid_delivery_idempotency_key_fails_before_secret_budget_or_send() -> None:
    scenario = _scenario()

    with pytest.raises(
        runtime_module.AlpacaPaperLookupRuntimeError,
        match="delivery idempotency key",
    ):
        scenario.run(delivery_idempotency_key=" invalid ")

    assert scenario.resolver.references == []
    assert scenario.budget.permits == []
    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []
    assert scenario.lookups.receipts == []


@pytest.mark.parametrize("source", ("unknown", "identity", "fence"))
def test_post_transport_source_failure_leaves_raw_only(source: str) -> None:
    scenario = _scenario(
        unknown_attempts=UnknownAuthenticator(fail_on_call=2 if source == "unknown" else None),
        account_bindings=IdentityAuthenticator(fail_on_call=2 if source == "identity" else None),
        coordinator=FixedCoordinator(change_fence=source == "fence"),
    )

    with pytest.raises(AlpacaPaperLookupConflict):
        scenario.run()

    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.lookups.receipts == []
    assert scenario.attempt.state is SubmissionAttemptState.UNKNOWN


@pytest.mark.parametrize("authority", ("credential", "permit", "fence"))
def test_authority_expiring_after_completed_response_leaves_raw_only(
    authority: str,
) -> None:
    if authority == "credential":
        scenario = _scenario(
            budget=InMemoryBudget(
                issued_at=LOOKUP_BASE + timedelta(seconds=29),
                checked_at=LOOKUP_BASE + timedelta(seconds=29, milliseconds=200),
            ),
            coordinator=FixedCoordinator(
                pre_validated_at=LOOKUP_BASE + timedelta(seconds=29, milliseconds=100),
                post_validated_at=LOOKUP_BASE + timedelta(seconds=30, milliseconds=300),
                pre_valid_until=LOOKUP_BASE + timedelta(seconds=40),
                post_valid_until=LOOKUP_BASE + timedelta(seconds=40),
            ),
            clock=SequenceClock(
                LOOKUP_BASE,
                LOOKUP_BASE + timedelta(milliseconds=50),
                LOOKUP_BASE + timedelta(milliseconds=100),
                LOOKUP_BASE + timedelta(seconds=29, milliseconds=300),
                LOOKUP_BASE + timedelta(seconds=29, milliseconds=400),
                LOOKUP_BASE + timedelta(seconds=29, milliseconds=500),
                LOOKUP_BASE + timedelta(seconds=30, milliseconds=100),
                LOOKUP_BASE + timedelta(seconds=30, milliseconds=200),
                LOOKUP_BASE + timedelta(seconds=30, milliseconds=400),
                LOOKUP_BASE + timedelta(seconds=30, milliseconds=500),
            ),
        )
    elif authority == "permit":
        scenario = _scenario(
            coordinator=FixedCoordinator(
                post_validated_at=LOOKUP_BASE + timedelta(seconds=3, milliseconds=400),
            ),
            clock=SequenceClock(
                LOOKUP_BASE,
                LOOKUP_BASE + timedelta(milliseconds=50),
                LOOKUP_BASE + timedelta(milliseconds=100),
                LOOKUP_BASE + timedelta(milliseconds=500),
                LOOKUP_BASE + timedelta(milliseconds=600),
                LOOKUP_BASE + timedelta(milliseconds=700),
                LOOKUP_BASE + timedelta(seconds=3, milliseconds=200),
                LOOKUP_BASE + timedelta(seconds=3, milliseconds=300),
                LOOKUP_BASE + timedelta(seconds=3, milliseconds=500),
                LOOKUP_BASE + timedelta(seconds=3, milliseconds=600),
            ),
        )
    else:
        scenario = _scenario(
            coordinator=FixedCoordinator(
                pre_valid_until=LOOKUP_BASE + timedelta(milliseconds=800),
                post_valid_until=LOOKUP_BASE + timedelta(seconds=30),
            ),
        )

    with pytest.raises(AlpacaPaperLookupConflict, match="expired"):
        scenario.run()

    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.lookups.receipts == []
    assert scenario.attempt.state is SubmissionAttemptState.UNKNOWN


def test_post_fence_expiring_before_post_source_checks_leaves_raw_only() -> None:
    post_validated_at = LOOKUP_BASE + timedelta(seconds=1)
    scenario = _scenario(
        coordinator=FixedCoordinator(
            post_validated_at=post_validated_at,
            post_valid_until=post_validated_at + timedelta(milliseconds=50),
        ),
    )

    with pytest.raises(AlpacaPaperLookupConflict, match="authority expired"):
        scenario.run()

    assert scenario.unknown_attempts.calls[-1][1] == (
        post_validated_at + timedelta(milliseconds=100)
    )
    assert scenario.account_bindings.calls[-1][1] == (
        post_validated_at + timedelta(milliseconds=200)
    )
    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.lookups.receipts == []
    assert scenario.attempt.state is SubmissionAttemptState.UNKNOWN


def test_new_only_lookup_demand_replay_cannot_send_twice() -> None:
    scenario = _scenario()
    scenario.run()
    scenario.clock = _lookup_clock()

    with pytest.raises(BrokerRequestPermitConflict, match="already has a durable permit"):
        scenario.run()

    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert len(scenario.lookups.receipts) == 1


def test_transport_failure_is_sanitized_closes_secret_and_invents_no_raw() -> None:
    scenario = _scenario(transport=LookupTransport(fail=True))

    with pytest.raises(AlpacaPaperLookupTransportError, match="sanitized") as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert len(scenario.budget.permits) == 1
    assert scenario.ingress.receipts == []
    assert scenario.lookups.receipts == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_public_orchestrator_constructs_only_the_restricted_lookup_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario()
    calls: list[str] = []

    def execute(
        self: object,
        request: AlpacaPaperLookupTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperLookupTransportResponse:
        del self
        calls.append(request.url)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        return AlpacaPaperLookupTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=ALPACA_PAPER_LOOKUP_TRANSPORT_ID,
            transport_version=ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION,
            http_status=200,
            provider_request_id="phase4i-public-request",
            media_type=ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE,
            response_body=_fixture("lookup_found.json"),
        )

    monkeypatch.setattr(
        runtime_module._HttpxAlpacaPaperLookupTransport,
        "execute",
        execute,
    )

    receipt = scenario.run_public()

    assert receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED
    assert calls == [
        (
            f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/orders:by_client_order_id"
            f"?client_order_id={scenario.description.submission.request.client_order_id}"
        )
    ]


def test_concrete_transport_fixes_tls_proxy_redirect_timeout_identity_and_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    scenario = _scenario()

    class FakeResponse:
        status_code = 200

        def __init__(self) -> None:
            self.headers = {
                "x-request-id": "strict-lookup-request",
                "content-type": "application/json; charset=utf-8",
            }
            self.request = httpx.Request("GET", request.url)

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def iter_raw(self) -> object:
            return iter((_fixture("lookup_found.json"),))

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            observed["client_kwargs"] = kwargs

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def stream(
            self,
            method: str,
            url: str,
            *,
            headers: _AlpacaPaperAuthenticationHeaders,
        ) -> FakeResponse:
            observed["method"] = method
            observed["url"] = url
            observed["header_names"] = tuple(headers)
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    request = AlpacaPaperLookupTransportRequest(
        description=scenario.description,
        credential_reference_sha256="1" * 64,
        security_reference_sha256="2" * 64,
        attempt_sha256="3" * 64,
        unknown_attempt_freshness_sha256="4" * 64,
        account_binding_sha256="5" * 64,
        account_identity_sha256="6" * 64,
        demand_sha256="7" * 64,
        permit_sha256="8" * 64,
        permit_freshness_sha256="9" * 64,
        fence_receipt_sha256="a" * 64,
        started_at=LOOKUP_BASE,
    )
    material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )

    response = _HttpxAlpacaPaperLookupTransport().execute(
        request,
        _AlpacaPaperAuthenticationHeaders(material),
    )
    material.close()

    kwargs = observed["client_kwargs"]
    assert type(kwargs) is dict
    assert kwargs["verify"] is True
    assert kwargs["trust_env"] is False
    assert kwargs["follow_redirects"] is False
    assert isinstance(kwargs["timeout"], httpx.Timeout)
    assert kwargs["timeout"].connect == 2.0
    assert kwargs["timeout"].read == 2.0
    assert kwargs["timeout"].write == 2.0
    assert kwargs["timeout"].pool == 2.0
    assert kwargs["headers"]["Accept-Encoding"] == "identity"
    assert observed["method"] == "GET"
    assert observed["url"] == request.url
    assert observed["header_names"] == ALPACA_AUTH_HEADER_NAMES
    assert response.response_body == _fixture("lookup_found.json")
    assert response.provider_request_id == "strict-lookup-request"
    assert response.media_type == ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE
    assert request.httpx_phase_timeout == ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT


def test_lookup_proof_types_reject_direct_construction_and_tampering() -> None:
    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperUnknownAttemptFreshnessReceipt()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAuthenticatedLookupEvidence()
    with pytest.raises(TypeError, match="recorder-produced"):
        AlpacaPaperAuthenticatedLookupReceipt()

    receipt = _scenario().run()
    object.__setattr__(receipt, "fence_sha256", "not-a-digest")
    with pytest.raises(runtime_module.AlpacaPaperLookupRuntimeError):
        receipt._validate()
