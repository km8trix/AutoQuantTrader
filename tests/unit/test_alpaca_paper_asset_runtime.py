from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
import pytest

import packages.adapters.broker.alpaca_paper_asset_runtime as runtime_module
from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_TRADING_BASE_URL,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaPaperAccountAssetObservationError,
    AlpacaPaperAssetObservationDescription,
    create_alpaca_asset_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountBindingFreshnessReceipt,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionError,
    _alpaca_paper_account_binding_freshness_receipt,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ASSET_BINDING_TTL,
    ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT,
    ALPACA_PAPER_ASSET_TRANSPORT_ID,
    ALPACA_PAPER_ASSET_TRANSPORT_VERSION,
    AlpacaPaperAssetBindingConflict,
    AlpacaPaperAssetRuntimeError,
    AlpacaPaperAssetTransportError,
    AlpacaPaperAssetTransportRequest,
    AlpacaPaperAssetTransportResponse,
    AlpacaPaperAuthenticatedAssetBinding,
    AlpacaPaperAuthenticatedAssetEvidence,
    AlpacaPaperSecurityReference,
    _alpaca_paper_authenticated_asset_binding,
    _HttpxAlpacaPaperAssetTransport,
    _observe_authenticated_alpaca_paper_asset_with_transport,
    alpaca_paper_asset_observation_correlation_sha256,
    create_alpaca_paper_asset_observation_demand,
    observe_authenticated_alpaca_paper_asset,
)
from packages.adapters.broker.alpaca_paper_budget import AlpacaPaperBudgetOperation
from packages.domain.broker_request_budget import (
    BrokerRequestPermitConflict,
    BrokerRequestPurpose,
)
from tests.unit.test_alpaca_paper_account_asset_ingress import (
    InMemoryIngressRecorder,
    _asset_body,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    API_KEY_ID,
    SECRET_KEY,
    InMemoryBudget,
    SequenceClock,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    _scenario as account_scenario,
)
from tests.unit.test_submission_attempt import fence_receipt

ACCOUNT_ID = "fixture-submission-account"
PROVIDER_ACCOUNT_ID = "e6fe16f3-64a4-4921-8928-cadf02f92f98"
PROVIDER_ASSET_ID = "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415"
BASE = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)


class AssetResolver:
    resolver_id = "fixture-secret-store"
    resolver_version = "v1"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.references: list[AlpacaPaperCredentialReference] = []
        self.material: _AlpacaPaperCredentialMaterial | None = None

    def _resolve_for_asset_observation(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        self.references.append(reference)
        if self.fail:
            raise RuntimeError(f"unsafe resolver detail {SECRET_KEY}")
        envelope = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(envelope) is _AlpacaPaperCredentialMaterial
        self.material = envelope
        return envelope


class FixedAssetTransport:
    transport_id = ALPACA_PAPER_ASSET_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ASSET_TRANSPORT_VERSION

    def __init__(
        self,
        *,
        status: int = 200,
        request_id: str | None = "phase4h-request-001",
        media_type: str | None = ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE,
        body: bytes | None = None,
        fail: bool = False,
    ) -> None:
        self.status = status
        self.request_id = request_id
        self.media_type = media_type
        self.body = _asset_body() if body is None else body
        self.fail = fail
        self.calls = 0
        self.requests: list[AlpacaPaperAssetTransportRequest] = []

    def execute(
        self,
        request: AlpacaPaperAssetTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAssetTransportResponse:
        self.calls += 1
        self.requests.append(request)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        if self.fail:
            raise RuntimeError(f"unsafe transport detail {SECRET_KEY}")
        return AlpacaPaperAssetTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=self.status,
            provider_request_id=self.request_id,
            media_type=self.media_type,
            response_body=self.body,
        )


class FixedAccountBindingAuthenticator:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.fail_on_call = fail_on_call
        self.calls: list[tuple[str, datetime]] = []

    def authenticate_terminal_fresh(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountBindingFreshnessReceipt:
        self.calls.append((binding.binding_id, checked_at))
        if len(self.calls) == self.fail_on_call:
            raise RuntimeError(f"unsafe source detail {SECRET_KEY}")
        return _alpaca_paper_account_binding_freshness_receipt(
            binding,
            checked_at=checked_at,
        )


class FixedCoordinator:
    account_id = ACCOUNT_ID

    def __init__(
        self,
        *,
        change_fence: bool = False,
        wrong_fence: bool = False,
        pre_validated_at: datetime = BASE + timedelta(milliseconds=1300),
        post_validated_at: datetime = BASE + timedelta(milliseconds=1900),
        valid_until: datetime = BASE + timedelta(seconds=20),
    ) -> None:
        self.change_fence = change_fence
        self.wrong_fence = wrong_fence
        self.pre_validated_at = pre_validated_at
        self.post_validated_at = post_validated_at
        self.valid_until = valid_until
        self.calls = 0

    def revalidate(self, fence: object) -> object:
        del fence
        self.calls += 1
        return fence_receipt(
            validated_at=self.pre_validated_at if self.calls == 1 else self.post_validated_at,
            valid_until=self.valid_until,
            fencing_generation=(
                2 if self.wrong_fence or (self.change_fence and self.calls == 2) else 1
            ),
        )


class InMemoryAssetBindingRecorder:
    def __init__(self) -> None:
        self.evidence: list[AlpacaPaperAuthenticatedAssetEvidence] = []
        self.bindings: list[AlpacaPaperAuthenticatedAssetBinding] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> AlpacaPaperAuthenticatedAssetBinding:
        previous = self.bindings[-1].semantic_sha256 if self.bindings else None
        binding = _alpaca_paper_authenticated_asset_binding(
            evidence,
            sequence_number=len(self.bindings) + 1,
            previous_binding_sha256=previous,
        )
        self.evidence.append(evidence)
        self.bindings.append(binding)
        return binding


class ForgingAssetBindingRecorder(InMemoryAssetBindingRecorder):
    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> AlpacaPaperAuthenticatedAssetBinding:
        binding = super().record(evidence)
        object.__setattr__(binding, "evidence_sha256", "0" * 64)
        return binding


@dataclass(slots=True)
class AssetScenario:
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    security_reference: AlpacaPaperSecurityReference
    resolver: AssetResolver
    transport: FixedAssetTransport
    budget: InMemoryBudget
    account_bindings: FixedAccountBindingAuthenticator
    coordinator: FixedCoordinator
    ingress: InMemoryIngressRecorder
    bindings: InMemoryAssetBindingRecorder
    clock: SequenceClock

    @property
    def description(self) -> AlpacaPaperAssetObservationDescription:
        return create_alpaca_asset_observation_description(
            account_id=ACCOUNT_ID,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
        )

    def run(self) -> AlpacaPaperAuthenticatedAssetBinding:
        return _observe_authenticated_alpaca_paper_asset_with_transport(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            description=self.description,
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=self.budget,  # type: ignore[arg-type]
            account_bindings=self.account_bindings,
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=BASE - timedelta(seconds=1),
                valid_until=BASE + timedelta(seconds=20),
            ).fence,
            ingress_recorder=self.ingress,
            binding_recorder=self.bindings,
            clock=self.clock,
            request_idempotency_key="phase4h-asset-request-001",
            delivery_idempotency_key="phase4h-asset-delivery-001",
        )

    def run_public(self) -> AlpacaPaperAuthenticatedAssetBinding:
        return observe_authenticated_alpaca_paper_asset(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            description=self.description,
            credential_resolver=self.resolver,
            budget=self.budget,  # type: ignore[arg-type]
            account_bindings=self.account_bindings,
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=BASE - timedelta(seconds=1),
                valid_until=BASE + timedelta(seconds=20),
            ).fence,
            ingress_recorder=self.ingress,
            binding_recorder=self.bindings,
            clock=self.clock,
            request_idempotency_key="phase4h-asset-request-001",
            delivery_idempotency_key="phase4h-asset-delivery-001",
        )


def _asset_clock(*extra: datetime) -> SequenceClock:
    return SequenceClock(
        BASE + timedelta(seconds=1),
        BASE + timedelta(milliseconds=1050),
        BASE + timedelta(milliseconds=1100),
        BASE + timedelta(milliseconds=1500),
        BASE + timedelta(milliseconds=1600),
        BASE + timedelta(milliseconds=1700),
        BASE + timedelta(milliseconds=1800),
        BASE + timedelta(milliseconds=2000),
        *extra,
    )


def _asset_scenario(
    *,
    expected_provider_asset_id: str = PROVIDER_ASSET_ID,
    transport: FixedAssetTransport | None = None,
    budget: InMemoryBudget | None = None,
    account_bindings: FixedAccountBindingAuthenticator | None = None,
    coordinator: FixedCoordinator | None = None,
    clock: SequenceClock | None = None,
) -> AssetScenario:
    account_binding = account_scenario().run()
    credential_reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    return AssetScenario(
        account_binding=account_binding,
        security_reference=AlpacaPaperSecurityReference(
            credential_reference=credential_reference,
            instrument_id="US-ETF-SPY",
            symbol="SPY",
            expected_provider_asset_id=expected_provider_asset_id,
        ),
        resolver=AssetResolver(),
        transport=transport or FixedAssetTransport(),
        budget=budget
        or InMemoryBudget(
            issued_at=BASE + timedelta(milliseconds=1200),
            checked_at=BASE + timedelta(milliseconds=1400),
        ),
        account_bindings=account_bindings or FixedAccountBindingAuthenticator(),
        coordinator=coordinator or FixedCoordinator(),
        ingress=InMemoryIngressRecorder(),
        bindings=InMemoryAssetBindingRecorder(),
        clock=clock or _asset_clock(),
    )


def _body_override(**updates: object) -> bytes:
    value = json.loads(_asset_body())
    assert type(value) is dict
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def test_security_reference_and_demand_are_operator_pinned_and_protected() -> None:
    scenario = _asset_scenario()
    reference = scenario.security_reference
    demand = create_alpaca_paper_asset_observation_demand(
        security_reference=reference,
        account_binding=scenario.account_binding,
        description=scenario.description,
        idempotency_key="asset-demand-001",
        requested_at=BASE + timedelta(seconds=1),
    )

    assert reference.instrument_id == "US-ETF-SPY"
    assert reference.symbol == "SPY"
    assert reference.expected_provider_asset_id == PROVIDER_ASSET_ID
    assert reference.credential_values_present is False
    assert reference.transport_authorized is False
    assert reference.trading_effect_authorized is False
    assert SECRET_KEY not in reference.canonical_json
    assert demand.operation == AlpacaPaperBudgetOperation.OBSERVE_ASSET.value
    assert demand.purpose is BrokerRequestPurpose.RECONCILIATION
    assert demand.correlation_sha256 == alpaca_paper_asset_observation_correlation_sha256(
        security_reference=reference,
        account_binding=scenario.account_binding,
        description=scenario.description,
    )


def test_successful_asset_get_is_raw_first_fresh_and_never_trading_authority() -> None:
    scenario = _asset_scenario()

    binding = scenario.run()

    assert binding.expected_provider_asset_id == PROVIDER_ASSET_ID
    assert binding.observed_provider_asset_id == PROVIDER_ASSET_ID
    assert binding.instrument_id == "US-ETF-SPY"
    assert binding.symbol == "SPY"
    assert binding.valid_until == scenario.account_binding.valid_until
    assert binding.valid_until <= binding.qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL
    assert binding.credential_resolution_established is True
    assert binding.authenticated_account_established is True
    assert binding.authenticated_security_established is True
    assert binding.durable_security_identity_binding_established is True
    assert binding.asset_tradability_established is True
    assert binding.raw_response_persisted is True
    assert binding.security_master_ready is False
    assert binding.security_mapping_ready is False
    assert binding.asset_tradability_validation_ready is False
    assert binding.reduce_only_validation_ready is False
    assert binding.exchange_calendar_binding_ready is False
    assert binding.quote_collar_ready is False
    assert binding.reconciliation_ready is False
    assert binding.transport_submission_ready is False
    assert binding.mark_in_flight_ready is False
    assert binding.coordinator_dispatch_ready is False
    assert binding.paper_startup_ready is False
    assert binding.submission_authorized is False
    assert binding.trading_effect_authorized is False
    assert len(scenario.account_bindings.calls) == 2
    assert scenario.ingress.deliveries[0].body == _asset_body()
    assert (
        scenario.bindings.evidence[0].persisted_observation.receipt
        == (scenario.ingress.receipts[0])
    )
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


def test_asset_resolver_failure_is_sanitized_before_budget_or_transport() -> None:
    scenario = _asset_scenario()
    scenario.resolver = AssetResolver(fail=True)

    with pytest.raises(AlpacaPaperCredentialResolutionError) as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert scenario.budget.permits == []
    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []


def test_asset_transport_failure_is_sanitized_and_zeroes_consumed_credentials() -> None:
    scenario = _asset_scenario(transport=FixedAssetTransport(fail=True))

    with pytest.raises(AlpacaPaperAssetTransportError, match="sanitized") as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert len(scenario.budget.permits) == 1
    assert scenario.transport.calls == 1
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


def test_pre_transport_account_authentication_failure_cannot_send() -> None:
    scenario = _asset_scenario(account_bindings=FixedAccountBindingAuthenticator(fail_on_call=1))

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="failed before asset transport",
    ) as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert len(scenario.budget.permits) == 1
    assert len(scenario.account_bindings.calls) == 1
    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


def test_expired_permit_cannot_send_asset_request() -> None:
    scenario = _asset_scenario(
        clock=SequenceClock(
            BASE + timedelta(seconds=1),
            BASE + timedelta(milliseconds=1050),
            BASE + timedelta(milliseconds=1100),
            BASE + timedelta(milliseconds=1500),
            BASE + timedelta(milliseconds=4200),
        )
    )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="permit is not current at asset transport start",
    ):
        scenario.run()

    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_expired_terminal_account_binding_cannot_send_asset_request() -> None:
    scenario = _asset_scenario()
    object.__setattr__(
        scenario.account_binding,
        "valid_until",
        BASE + timedelta(milliseconds=1600),
    )
    scenario.account_binding._validate()

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="terminal account binding is not current at asset transport start",
    ):
        scenario.run()

    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_expired_account_fence_cannot_send_asset_request() -> None:
    scenario = _asset_scenario(
        coordinator=FixedCoordinator(
            valid_until=BASE + timedelta(milliseconds=1600),
        )
    )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="account fence is not current at asset transport start",
    ):
        scenario.run()

    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_wrong_pre_request_fence_receipt_cannot_send_asset_request() -> None:
    scenario = _asset_scenario(coordinator=FixedCoordinator(wrong_fence=True))

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="receipt for another pre-request fence",
    ):
        scenario.run()

    assert scenario.transport.calls == 0
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_late_asset_response_is_retained_but_never_binds() -> None:
    scenario = _asset_scenario(
        coordinator=FixedCoordinator(
            post_validated_at=BASE + timedelta(milliseconds=4400),
        ),
        clock=SequenceClock(
            BASE + timedelta(seconds=1),
            BASE + timedelta(milliseconds=1050),
            BASE + timedelta(milliseconds=1100),
            BASE + timedelta(milliseconds=1500),
            BASE + timedelta(milliseconds=1600),
            BASE + timedelta(milliseconds=4200),
            BASE + timedelta(milliseconds=4300),
            BASE + timedelta(milliseconds=4500),
        ),
    )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="authority expired during transport",
    ):
        scenario.run()

    assert scenario.transport.calls == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == _asset_body()
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


@pytest.mark.parametrize(
    ("clock", "message"),
    [
        (
            SequenceClock(
                BASE + timedelta(seconds=1),
                BASE + timedelta(milliseconds=1050),
                BASE + timedelta(milliseconds=1100),
                BASE + timedelta(milliseconds=1500),
                BASE + timedelta(milliseconds=1600),
                BASE + timedelta(milliseconds=1550),
            ),
            "transport clock regressed",
        ),
        (
            SequenceClock(
                BASE + timedelta(seconds=1),
                BASE + timedelta(milliseconds=1050),
                BASE + timedelta(milliseconds=1100),
                BASE + timedelta(milliseconds=1500),
                BASE + timedelta(milliseconds=1600),
                BASE + timedelta(milliseconds=1700),
                BASE + timedelta(milliseconds=1650),
            ),
            "raw-record clock regressed",
        ),
    ],
)
def test_asset_clock_regression_cannot_persist_or_bind(
    clock: SequenceClock,
    message: str,
) -> None:
    scenario = _asset_scenario(clock=clock)

    with pytest.raises(AlpacaPaperAssetRuntimeError, match=message):
        scenario.run()

    assert scenario.transport.calls == 1
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_forged_recorder_return_is_rejected_after_raw_persistence() -> None:
    scenario = _asset_scenario()
    scenario.bindings = ForgingAssetBindingRecorder()

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="does not bind the exact runtime evidence",
    ):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert len(scenario.bindings.bindings) == 1


def test_operator_pinned_asset_uuid_mismatch_is_retained_but_never_binds() -> None:
    scenario = _asset_scenario(expected_provider_asset_id="d244db14-ae5c-43e6-9f37-c147dbec1957")

    with pytest.raises(AlpacaPaperAssetBindingConflict, match="operator-pinned"):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == _asset_body()
    assert scenario.bindings.bindings == []


@pytest.mark.parametrize(
    ("transport", "error_type"),
    [
        (
            FixedAssetTransport(request_id=None),
            AlpacaPaperAccountAssetObservationError,
        ),
        (
            FixedAssetTransport(body=b'{"schema_drift":true}'),
            AlpacaPaperAccountAssetObservationError,
        ),
        (
            FixedAssetTransport(status=404, body=b'{"code":40410000,"message":"not found"}'),
            AlpacaPaperAssetBindingConflict,
        ),
        (
            FixedAssetTransport(body=_body_override(tradable=False)),
            AlpacaPaperAssetBindingConflict,
        ),
    ],
)
def test_unqualified_asset_responses_are_retained_before_rejection(
    transport: FixedAssetTransport,
    error_type: type[Exception],
) -> None:
    scenario = _asset_scenario(transport=transport)

    with pytest.raises(error_type):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == transport.body
    assert scenario.bindings.bindings == []


def test_post_transport_account_binding_failure_is_sanitized_after_raw_persistence() -> None:
    scenario = _asset_scenario(account_bindings=FixedAccountBindingAuthenticator(fail_on_call=2))

    with pytest.raises(AlpacaPaperAssetBindingConflict) as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []


def test_changed_post_request_fence_rejects_after_raw_persistence() -> None:
    scenario = _asset_scenario(coordinator=FixedCoordinator(change_fence=True))

    with pytest.raises(AlpacaPaperAssetBindingConflict, match="fence changed"):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []


def test_new_only_demand_replay_cannot_send_twice() -> None:
    scenario = _asset_scenario()
    scenario.run()
    scenario.clock.instants = [
        BASE + timedelta(seconds=1),
        BASE + timedelta(milliseconds=1050),
        BASE + timedelta(milliseconds=1100),
    ]

    with pytest.raises(BrokerRequestPermitConflict, match="already has a durable permit"):
        scenario.run()

    assert scenario.transport.calls == 1
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_public_orchestrator_constructs_exact_restricted_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _asset_scenario()
    calls: list[str] = []

    def execute(
        self: object,
        request: AlpacaPaperAssetTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAssetTransportResponse:
        del self
        calls.append(request.url)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        return AlpacaPaperAssetTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=ALPACA_PAPER_ASSET_TRANSPORT_ID,
            transport_version=ALPACA_PAPER_ASSET_TRANSPORT_VERSION,
            http_status=200,
            provider_request_id="phase4h-public-request",
            media_type=ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE,
            response_body=_asset_body(),
        )

    monkeypatch.setattr(runtime_module._HttpxAlpacaPaperAssetTransport, "execute", execute)

    binding = observe_authenticated_alpaca_paper_asset(
        security_reference=scenario.security_reference,
        account_binding=scenario.account_binding,
        description=scenario.description,
        credential_resolver=scenario.resolver,
        budget=scenario.budget,  # type: ignore[arg-type]
        account_bindings=scenario.account_bindings,
        coordinator=scenario.coordinator,  # type: ignore[arg-type]
        fence=fence_receipt(
            validated_at=BASE - timedelta(seconds=1),
            valid_until=BASE + timedelta(seconds=20),
        ).fence,
        ingress_recorder=scenario.ingress,
        binding_recorder=scenario.bindings,
        clock=scenario.clock,
        request_idempotency_key="phase4h-asset-request-001",
        delivery_idempotency_key="phase4h-asset-delivery-001",
    )

    assert binding.observed_provider_asset_id == PROVIDER_ASSET_ID
    assert calls == ["https://paper-api.alpaca.markets/v2/assets/SPY"]


def test_public_transport_drops_overbound_metadata_after_retaining_raw_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _asset_scenario()

    class FakeResponse:
        status_code = 200

        def __init__(self) -> None:
            self.headers = {
                "x-request-id": "r" * 257,
                "content-type": f"{'a' * 129}; charset=utf-8",
            }
            self.request = httpx.Request(
                "GET",
                f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/assets/SPY",
            )

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def iter_raw(self) -> object:
            return iter((_asset_body(),))

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

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
            assert method == "GET"
            assert url == f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/assets/SPY"
            assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)

    with pytest.raises(AlpacaPaperAccountAssetObservationError):
        scenario.run_public()

    assert len(scenario.ingress.receipts) == 1
    delivery = scenario.ingress.receipts[0].delivery
    assert delivery.body == _asset_body()
    assert delivery.provider_request_id is None
    assert delivery.media_type is None
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_durable_asset_binding_rejects_tampered_validity_beyond_fixed_ttl() -> None:
    binding = _asset_scenario().run()
    tampered_valid_until = (
        binding.qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL + timedelta(microseconds=1)
    )
    object.__setattr__(binding, "valid_until", tampered_valid_until)
    object.__setattr__(
        binding,
        "account_binding_valid_until",
        tampered_valid_until + timedelta(seconds=1),
    )
    object.__setattr__(
        binding,
        "post_fence_valid_until",
        tampered_valid_until + timedelta(seconds=1),
    )

    with pytest.raises(
        AlpacaPaperAssetBindingConflict,
        match="exceeds the fixed maximum TTL",
    ):
        binding._validate()


def test_concrete_transport_fixes_target_tls_timeout_and_raw_content_coding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeResponse:
        status_code = 200

        def __init__(self) -> None:
            self.headers = {
                "x-request-id": "strict-asset-request",
                "content-type": "application/json; charset=utf-8",
            }
            if observed.get("encoded") is True:
                self.headers["content-encoding"] = "gzip"
            self.request = httpx.Request(
                "GET",
                f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/assets/SPY",
            )

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def iter_raw(self) -> object:
            body = b"gzip-wire-asset" if observed.get("encoded") is True else _asset_body()
            return iter((body,))

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
    request = AlpacaPaperAssetTransportRequest(
        description=_asset_scenario().description,
        credential_reference_sha256="1" * 64,
        security_reference_sha256="2" * 64,
        account_binding_sha256="3" * 64,
        account_binding_freshness_sha256="4" * 64,
        demand_sha256="5" * 64,
        permit_sha256="6" * 64,
        permit_freshness_sha256="7" * 64,
        fence_receipt_sha256="8" * 64,
        started_at=BASE,
    )
    material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )
    response = _HttpxAlpacaPaperAssetTransport().execute(
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
    assert observed["url"] == f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/assets/SPY"
    assert observed["header_names"] == ALPACA_AUTH_HEADER_NAMES
    assert response.provider_request_id == "strict-asset-request"
    assert response.media_type == ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE
    assert request.httpx_phase_timeout == ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT

    observed["encoded"] = True
    encoded_material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )
    encoded_response = _HttpxAlpacaPaperAssetTransport().execute(
        request,
        _AlpacaPaperAuthenticationHeaders(encoded_material),
    )
    encoded_material.close()
    assert encoded_response.response_body == b"gzip-wire-asset"
    assert encoded_response.media_type is None
