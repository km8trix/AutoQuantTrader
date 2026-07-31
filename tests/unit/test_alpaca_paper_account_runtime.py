from __future__ import annotations

import copy
import json
import pickle
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
import pytest

import packages.adapters.broker as broker_package
import packages.adapters.broker.alpaca_paper_account_runtime as runtime_module
from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_TRADING_BASE_URL,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaPaperAccountAssetObservationError,
    create_alpaca_account_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_BINDING_TTL,
    ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_ID,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION,
    ALPACA_PAPER_CREDENTIAL_SESSION_TTL,
    AlpacaPaperAccountBindingConflict,
    AlpacaPaperAccountRuntimeError,
    AlpacaPaperAccountTransportError,
    AlpacaPaperAccountTransportRequest,
    AlpacaPaperAccountTransportResponse,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperAuthenticatedAccountEvidence,
    AlpacaPaperCredentialExpired,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionError,
    _alpaca_paper_authenticated_account_binding,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    _HttpxAlpacaPaperAccountTransport,
    _observe_authenticated_alpaca_paper_account_with_transport,
    _resolve_alpaca_paper_credentials,
    alpaca_paper_account_observation_correlation_sha256,
    create_alpaca_paper_account_observation_demand,
    create_alpaca_paper_credential_envelope,
    observe_authenticated_alpaca_paper_account,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
)
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitConflict,
    BrokerRequestPurpose,
    _broker_request_permit_freshness_receipt,
    issue_broker_request_permit,
)
from tests.unit.test_alpaca_paper_account_asset_ingress import (
    InMemoryIngressRecorder,
    _account_body,
)
from tests.unit.test_submission_attempt import fence_receipt

ACCOUNT_ID = "fixture-submission-account"
PROVIDER_ACCOUNT_ID = "e6fe16f3-64a4-4921-8928-cadf02f92f98"
API_KEY_ID = "PKTESTACCOUNTKEY"
SECRET_KEY = "paper-secret-value-that-must-never-leak"
BASE = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)


class SequenceClock:
    def __init__(self, *instants: datetime) -> None:
        self.instants = list(instants)

    def now(self) -> datetime:
        if not self.instants:
            raise AssertionError("test clock was sampled more times than expected")
        return self.instants.pop(0)


class FixedResolver:
    resolver_id = "fixture-secret-store"
    resolver_version = "v1"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.references: list[AlpacaPaperCredentialReference] = []
        self.material: _AlpacaPaperCredentialMaterial | None = None

    def _resolve_for_account_observation(
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


class InMemoryBudget:
    def __init__(
        self,
        *,
        issued_at: datetime = BASE + timedelta(milliseconds=250),
        checked_at: datetime = BASE + timedelta(milliseconds=400),
        replace_permit: BrokerRequestPermit | None = None,
    ) -> None:
        self.issued_at = issued_at
        self.checked_at = checked_at
        self.replace_permit = replace_permit
        self.demands: list[BrokerRequestDemand] = []
        self.permits: list[BrokerRequestPermit] = []

    def issue_new(
        self,
        *,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        assert policy == ALPACA_PAPER_REQUEST_BUDGET_POLICY
        if demand in self.demands:
            raise BrokerRequestPermitConflict("broker request demand already has a durable permit")
        self.demands.append(demand)
        permit = issue_broker_request_permit(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            issued_at=self.issued_at,
            active_permits=(),
            previous_permit=None,
            previous_policy=None,
        )
        if self.replace_permit is not None:
            permit = self.replace_permit
        self.permits.append(permit)
        return permit

    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> object:
        assert policy == ALPACA_PAPER_REQUEST_BUDGET_POLICY
        return _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=self.checked_at,
        )


class FixedCoordinator:
    account_id = ACCOUNT_ID

    def __init__(
        self,
        *,
        change_fence: bool = False,
        wrong_fence: bool = False,
        post_validated_at: datetime = BASE + timedelta(milliseconds=800),
        valid_until: datetime = BASE + timedelta(seconds=30),
    ) -> None:
        self.change_fence = change_fence
        self.wrong_fence = wrong_fence
        self.post_validated_at = post_validated_at
        self.valid_until = valid_until
        self.calls = 0

    def revalidate(self, fence: object) -> object:
        self.calls += 1
        generation = 2 if self.wrong_fence or (self.change_fence and self.calls == 2) else 1
        validated_at = (
            BASE + timedelta(milliseconds=300) if self.calls == 1 else self.post_validated_at
        )
        return fence_receipt(
            validated_at=validated_at,
            valid_until=self.valid_until,
            fencing_generation=generation,
        )


class FixedTransport:
    transport_id = ALPACA_PAPER_ACCOUNT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION

    def __init__(
        self,
        *,
        status: int = 200,
        request_id: str | None = "phase4g-request-001",
        media_type: str | None = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
        body: bytes | None = None,
        fail: bool = False,
    ) -> None:
        self.status = status
        self.request_id = request_id
        self.media_type = media_type
        self.body = _account_body() if body is None else body
        self.fail = fail
        self.request_sha256s: list[str] = []
        self.header_names: tuple[str, ...] = ()

    def execute(
        self,
        request: AlpacaPaperAccountTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountTransportResponse:
        self.request_sha256s.append(request.semantic_sha256)
        self.header_names = tuple(headers)
        assert self.header_names == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        if self.fail:
            raise AlpacaPaperAccountTransportError(f"unsafe transport detail {SECRET_KEY}")
        return AlpacaPaperAccountTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=self.status,
            provider_request_id=self.request_id,
            media_type=self.media_type,
            response_body=self.body,
        )


class InMemoryBindingRecorder:
    def __init__(self) -> None:
        self.evidence: list[AlpacaPaperAuthenticatedAccountEvidence] = []
        self.bindings: list[AlpacaPaperAuthenticatedAccountBinding] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountEvidence,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        previous = self.bindings[-1].semantic_sha256 if self.bindings else None
        binding = _alpaca_paper_authenticated_account_binding(
            evidence,
            sequence_number=len(self.bindings) + 1,
            previous_binding_sha256=previous,
        )
        self.evidence.append(evidence)
        self.bindings.append(binding)
        return binding


class ForgingBindingRecorder(InMemoryBindingRecorder):
    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountEvidence,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        binding = super().record(evidence)
        object.__setattr__(binding, "account_id", "forged-account")
        return binding


@dataclass(slots=True)
class RuntimeScenario:
    reference: AlpacaPaperCredentialReference
    resolver: FixedResolver
    transport: FixedTransport
    budget: InMemoryBudget
    coordinator: FixedCoordinator
    ingress: InMemoryIngressRecorder
    bindings: InMemoryBindingRecorder
    clock: SequenceClock

    def run(self) -> AlpacaPaperAuthenticatedAccountBinding:
        return _observe_authenticated_alpaca_paper_account_with_transport(
            reference=self.reference,
            description=create_alpaca_account_observation_description(
                account_id=ACCOUNT_ID,
            ),
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=self.budget,
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=BASE - timedelta(seconds=1),
                valid_until=BASE + timedelta(seconds=30),
            ).fence,
            ingress_recorder=self.ingress,
            binding_recorder=self.bindings,
            clock=self.clock,
            request_idempotency_key="phase4g-account-request-001",
            delivery_idempotency_key="phase4g-account-delivery-001",
        )

    def run_public(self) -> AlpacaPaperAuthenticatedAccountBinding:
        return observe_authenticated_alpaca_paper_account(
            reference=self.reference,
            description=create_alpaca_account_observation_description(
                account_id=ACCOUNT_ID,
            ),
            credential_resolver=self.resolver,
            budget=self.budget,
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=BASE - timedelta(seconds=1),
                valid_until=BASE + timedelta(seconds=30),
            ).fence,
            ingress_recorder=self.ingress,
            binding_recorder=self.bindings,
            clock=self.clock,
            request_idempotency_key="phase4g-account-request-001",
            delivery_idempotency_key="phase4g-account-delivery-001",
        )


def _scenario(
    *,
    expected_provider_account_id: str = PROVIDER_ACCOUNT_ID,
    transport: FixedTransport | None = None,
    budget: InMemoryBudget | None = None,
    coordinator: FixedCoordinator | None = None,
    clock: SequenceClock | None = None,
) -> RuntimeScenario:
    return RuntimeScenario(
        reference=AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id=expected_provider_account_id,
            secret_ref="secret://paper/alpaca/trading",
            secret_version="version-001",
        ),
        resolver=FixedResolver(),
        transport=transport or FixedTransport(),
        budget=budget or InMemoryBudget(),
        coordinator=coordinator or FixedCoordinator(),
        ingress=InMemoryIngressRecorder(),
        bindings=InMemoryBindingRecorder(),
        clock=clock
        or SequenceClock(
            BASE,
            BASE + timedelta(milliseconds=100),
            BASE + timedelta(milliseconds=200),
            BASE + timedelta(milliseconds=500),
            BASE + timedelta(milliseconds=600),
            BASE + timedelta(milliseconds=700),
        ),
    )


def _json_override(body: bytes, **updates: object) -> bytes:
    value = json.loads(body)
    assert type(value) is dict
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def test_credential_reference_is_pinned_secret_free_and_non_authorizing() -> None:
    reference = _scenario().reference

    assert reference.provider_id == "alpaca-paper"
    assert reference.environment == "paper"
    assert reference.expected_provider_account_id == PROVIDER_ACCOUNT_ID
    assert reference.credential_values_present is False
    assert reference.transport_authorized is False
    assert reference.trading_effect_authorized is False
    assert API_KEY_ID not in reference.canonical_json
    assert SECRET_KEY not in reference.canonical_json

    for secret_ref in (
        "secret://live/alpaca",
        "secret://paper/../alpaca",
        "secret://paper/alpaca//trading",
        "secret://paper/alpaca?key=value",
    ):
        with pytest.raises(AlpacaPaperAccountRuntimeError):
            AlpacaPaperCredentialReference(
                account_id=ACCOUNT_ID,
                expected_provider_account_id=PROVIDER_ACCOUNT_ID,
                secret_ref=secret_ref,
                secret_version="version-001",
            )
    with pytest.raises(AlpacaPaperAccountRuntimeError, match="canonical UUID"):
        AlpacaPaperCredentialReference(
            account_id=ACCOUNT_ID,
            expected_provider_account_id="not-a-uuid",
            secret_ref="secret://paper/alpaca/trading",
            secret_version="version-001",
        )


def test_public_broker_api_exposes_no_independent_credential_or_transport_authority() -> None:
    sensitive_names = {
        "AlpacaPaperAuthenticationHeaders",
        "AlpacaPaperCredentialMaterial",
        "AlpacaPaperCredentialSession",
        "HttpxAlpacaPaperAccountTransport",
        "resolve_alpaca_paper_credentials",
    }

    assert sensitive_names.isdisjoint(runtime_module.__all__)
    assert sensitive_names.isdisjoint(broker_package.__all__)
    assert all(not hasattr(broker_package, name) for name in sensitive_names)
    assert "AlpacaPaperCredentialResolver" in runtime_module.__all__
    assert "observe_authenticated_alpaca_paper_account" in runtime_module.__all__


def test_credential_material_redacts_rejects_copy_and_zeroes_on_close() -> None:
    material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )
    headers = _AlpacaPaperAuthenticationHeaders(material)

    assert API_KEY_ID not in repr(material)
    assert SECRET_KEY not in repr(material)
    assert API_KEY_ID not in repr(headers)
    assert SECRET_KEY not in repr(headers)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(material)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(headers)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(material)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(headers)

    material.close()
    assert material.closed is True
    assert bytes(material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(material._secret_key) == b"\x00" * len(SECRET_KEY)
    with pytest.raises(AlpacaPaperCredentialExpired, match="closed"):
        headers[ALPACA_AUTH_HEADER_NAMES[0]]


def test_credential_material_zeroes_partial_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded_values: list[bytearray] = []

    def capture_then_fail(value: object) -> bytearray:
        encoded = bytearray(str(value).encode())
        encoded_values.append(encoded)
        if len(encoded_values) == 2:
            raise AlpacaPaperCredentialResolutionError("second secret rejected")
        return encoded

    monkeypatch.setattr(
        _AlpacaPaperCredentialMaterial,
        "_encode_secret",
        staticmethod(capture_then_fail),
    )

    with pytest.raises(
        AlpacaPaperCredentialResolutionError,
        match="second secret rejected",
    ):
        _AlpacaPaperCredentialMaterial(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )

    assert bytes(encoded_values[0]) == b"\x00" * len(API_KEY_ID)


def test_resolution_receipt_is_bounded_and_resolver_failures_are_sanitized() -> None:
    reference = _scenario().reference
    resolver = FixedResolver()
    session = _resolve_alpaca_paper_credentials(
        reference=reference,
        resolver=resolver,
        clock=SequenceClock(
            BASE,
            BASE + timedelta(milliseconds=1),
        ),
    )

    assert session.receipt.valid_until == (
        session.receipt.resolved_at + ALPACA_PAPER_CREDENTIAL_SESSION_TTL
    )
    assert session.receipt.is_fresh(session.receipt.resolved_at)
    assert session.receipt.is_fresh(session.receipt.valid_until) is False
    assert API_KEY_ID not in repr(session)
    assert SECRET_KEY not in repr(session)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(session)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(session)
    with pytest.raises(AlpacaPaperCredentialExpired):
        session.authentication_headers(checked_at=session.receipt.valid_until)
    session.close()

    with pytest.raises(AlpacaPaperCredentialResolutionError) as raised:
        _resolve_alpaca_paper_credentials(
            reference=reference,
            resolver=FixedResolver(fail=True),
            clock=SequenceClock(BASE),
        )
    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_resolution_rejects_wrong_material_without_leaking_close_failure() -> None:
    class WrongMaterial:
        def __getattribute__(self, name: str) -> object:
            if name == "close":
                raise RuntimeError(f"unsafe close lookup detail {SECRET_KEY}")
            return object.__getattribute__(self, name)

    class WrongMaterialResolver:
        resolver_id = "wrong-material-resolver"
        resolver_version = "v1"

        def _resolve_for_account_observation(
            self,
            reference: AlpacaPaperCredentialReference,
        ) -> object:
            del reference
            return WrongMaterial()

    with pytest.raises(AlpacaPaperCredentialResolutionError) as raised:
        _resolve_alpaca_paper_credentials(
            reference=_scenario().reference,
            resolver=WrongMaterialResolver(),  # type: ignore[arg-type]
            clock=SequenceClock(BASE),
        )

    assert "unsupported material" in str(raised.value)
    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_resolution_sanitizes_hostile_resolver_metadata_access() -> None:
    class HostileResolver:
        @property
        def resolver_id(self) -> str:
            raise RuntimeError(f"unsafe resolver property detail {SECRET_KEY}")

        @property
        def resolver_version(self) -> str:
            return "v1"

        def _resolve_for_account_observation(
            self,
            reference: AlpacaPaperCredentialReference,
        ) -> object:
            del reference
            raise AssertionError("resolution must not run after metadata failure")

    with pytest.raises(AlpacaPaperCredentialResolutionError) as raised:
        _resolve_alpaca_paper_credentials(
            reference=_scenario().reference,
            resolver=HostileResolver(),
            clock=SequenceClock(BASE),
        )

    assert "metadata access failed" in str(raised.value)
    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_account_demand_has_derived_reconciliation_purpose_and_correlation() -> None:
    scenario = _scenario()
    description = create_alpaca_account_observation_description(
        account_id=ACCOUNT_ID,
    )
    demand = create_alpaca_paper_account_observation_demand(
        reference=scenario.reference,
        description=description,
        idempotency_key="phase4g-demand-001",
        requested_at=BASE,
    )

    assert demand.operation == AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT.value
    assert demand.purpose is BrokerRequestPurpose.RECONCILIATION
    assert demand.correlation_sha256 == (
        alpaca_paper_account_observation_correlation_sha256(
            reference=scenario.reference,
            description=description,
        )
    )


def test_successful_account_get_is_raw_first_durable_and_never_trading_authority() -> None:
    scenario = _scenario()

    binding = scenario.run()

    assert binding.expected_provider_account_id == PROVIDER_ACCOUNT_ID
    assert binding.observed_provider_account_id == PROVIDER_ACCOUNT_ID
    assert binding.sequence_number == 1
    assert binding.previous_binding_sha256 is None
    assert binding.credential_resolution_established is True
    assert binding.authenticated_account_established is True
    assert binding.raw_response_persisted is True
    assert binding.durable_account_binding_established is True
    assert binding.is_fresh(binding.qualified_at) is True
    assert binding.is_fresh(binding.valid_until) is False
    assert binding.valid_until == binding.qualified_at + ALPACA_PAPER_ACCOUNT_BINDING_TTL
    assert binding.transport_submission_ready is False
    assert binding.mark_in_flight_ready is False
    assert binding.coordinator_dispatch_ready is False
    assert binding.paper_startup_ready is False
    assert binding.submission_authorized is False
    assert binding.trading_effect_authorized is False
    assert len(scenario.budget.permits) == 1
    assert scenario.coordinator.calls == 2
    assert len(scenario.transport.request_sha256s) == 1
    assert scenario.transport.header_names == ALPACA_AUTH_HEADER_NAMES
    assert len(scenario.ingress.receipts) == 1
    assert len(scenario.bindings.bindings) == 1
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert API_KEY_ID not in repr(binding)
    assert API_KEY_ID not in binding.canonical_json
    assert SECRET_KEY not in binding.canonical_json
    with pytest.raises(TypeError, match="recorder-produced"):
        AlpacaPaperAuthenticatedAccountBinding()


def test_exact_runtime_replay_is_rejected_before_a_second_transport_call() -> None:
    scenario = _scenario()
    original = scenario.run()
    scenario.clock.instants = [
        BASE,
        BASE + timedelta(milliseconds=100),
        BASE + timedelta(milliseconds=200),
    ]

    with pytest.raises(
        BrokerRequestPermitConflict,
        match="already has a durable permit",
    ):
        scenario.run()

    assert original.authenticated_account_established is True
    assert len(scenario.budget.permits) == 1
    assert len(scenario.transport.request_sha256s) == 1
    assert len(scenario.ingress.receipts) == 1
    assert len(scenario.bindings.bindings) == 1
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_public_orchestrator_constructs_the_exact_restricted_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario()

    def execute(
        _transport: _HttpxAlpacaPaperAccountTransport,
        request: AlpacaPaperAccountTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountTransportResponse:
        return scenario.transport.execute(request, headers)

    monkeypatch.setattr(_HttpxAlpacaPaperAccountTransport, "execute", execute)

    binding = scenario.run_public()

    assert binding.authenticated_account_established is True
    assert scenario.transport.request_sha256s


def test_orchestrator_rejects_a_recorder_returning_forged_binding_fields() -> None:
    scenario = _scenario()
    scenario.bindings = ForgingBindingRecorder()

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="conflicts with the exact runtime evidence",
    ):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert len(scenario.bindings.bindings) == 1


def test_binding_validator_rejects_a_window_beyond_the_fixed_maximum_ttl() -> None:
    binding = _scenario().run()
    object.__setattr__(
        binding,
        "valid_until",
        binding.qualified_at + ALPACA_PAPER_ACCOUNT_BINDING_TTL + timedelta(microseconds=1),
    )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="exceeds the fixed maximum TTL",
    ):
        binding._validate()


def test_provider_uuid_mismatch_retains_raw_bytes_but_never_records_binding() -> None:
    scenario = _scenario(expected_provider_account_id="00000000-0000-4000-8000-000000000001")

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="operator-pinned",
    ):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert len(scenario.transport.request_sha256s) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


@pytest.mark.parametrize(
    ("transport", "error_type"),
    (
        (
            FixedTransport(status=401, body=b'{"message":"unauthorized"}'),
            AlpacaPaperAccountAssetObservationError,
        ),
        (
            FixedTransport(status=200, body=b"{malformed"),
            AlpacaPaperAccountAssetObservationError,
        ),
        (
            FixedTransport(request_id=None),
            AlpacaPaperAccountAssetObservationError,
        ),
        (
            FixedTransport(media_type="text/plain"),
            AlpacaPaperAccountBindingConflict,
        ),
    ),
)
def test_failed_or_unqualified_responses_are_raw_first_and_never_bind(
    transport: FixedTransport,
    error_type: type[Exception],
) -> None:
    scenario = _scenario(transport=transport)

    with pytest.raises(error_type):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []


def test_concrete_transport_nulls_overbound_metadata_before_raw_first_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _account_body()

    class OverboundMetadataResponse:
        status_code = 200

        def __init__(self) -> None:
            self.headers = {
                "x-request-id": "r" * 257,
                "content-type": "a" * 129,
            }
            self.request = httpx.Request(
                "GET",
                f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/account",
            )

        def __enter__(self) -> OverboundMetadataResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def iter_raw(self) -> object:
            return iter((body,))

    class OverboundMetadataClient:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

        def __enter__(self) -> OverboundMetadataClient:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def stream(
            self,
            method: str,
            url: str,
            *,
            headers: _AlpacaPaperAuthenticationHeaders,
        ) -> OverboundMetadataResponse:
            assert method == "GET"
            assert url == f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/account"
            assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
            return OverboundMetadataResponse()

    monkeypatch.setattr(runtime_module.httpx, "Client", OverboundMetadataClient)
    scenario = _scenario()

    with pytest.raises(AlpacaPaperAccountAssetObservationError):
        scenario.run_public()

    assert len(scenario.ingress.receipts) == 1
    delivery = scenario.ingress.receipts[0].delivery
    assert delivery.body == body
    assert delivery.provider_request_id is None
    assert delivery.media_type is None
    assert scenario.bindings.bindings == []


def test_transport_failure_consumes_permit_closes_secret_and_has_no_raw_invention() -> None:
    scenario = _scenario(transport=FixedTransport(fail=True))

    with pytest.raises(AlpacaPaperAccountTransportError, match="sanitized") as raised:
        scenario.run()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert len(scenario.budget.permits) == 1
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


@pytest.mark.parametrize(
    "clock_instants",
    (
        (
            BASE,
            BASE + timedelta(milliseconds=100),
            BASE + timedelta(milliseconds=200),
            BASE + timedelta(milliseconds=500),
        ),
        (
            BASE,
            BASE + timedelta(milliseconds=100),
            BASE + timedelta(milliseconds=200),
            BASE + timedelta(milliseconds=500),
            BASE + timedelta(milliseconds=600),
        ),
    ),
)
def test_post_transport_trusted_clock_failure_invents_no_raw_receipt(
    clock_instants: tuple[datetime, ...],
) -> None:
    scenario = _scenario(clock=SequenceClock(*clock_instants))

    with pytest.raises(AssertionError, match="sampled more times"):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert len(scenario.transport.request_sha256s) == 1
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_expired_permit_blocks_before_transport() -> None:
    scenario = _scenario(
        clock=SequenceClock(
            BASE,
            BASE + timedelta(milliseconds=100),
            BASE + timedelta(milliseconds=200),
            BASE + timedelta(seconds=4),
        )
    )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="not current at transport start",
    ):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert scenario.transport.request_sha256s == []
    assert scenario.ingress.receipts == []


def test_response_after_permit_expiry_is_retained_but_cannot_bind() -> None:
    scenario = _scenario(
        coordinator=FixedCoordinator(
            post_validated_at=BASE + timedelta(seconds=4, milliseconds=200),
        ),
        clock=SequenceClock(
            BASE,
            BASE + timedelta(milliseconds=100),
            BASE + timedelta(milliseconds=200),
            BASE + timedelta(milliseconds=500),
            BASE + timedelta(seconds=4),
            BASE + timedelta(seconds=4, milliseconds=100),
        ),
    )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="permit expired before the account response completed",
    ):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_changed_post_request_fence_rejects_binding_after_raw_persistence() -> None:
    scenario = _scenario(coordinator=FixedCoordinator(change_fence=True))

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="fence changed",
    ):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []


def test_coordinator_receipt_for_another_fence_rejects_before_transport() -> None:
    scenario = _scenario(coordinator=FixedCoordinator(wrong_fence=True))

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="another pre-request fence",
    ):
        scenario.run()

    assert len(scenario.budget.permits) == 1
    assert scenario.transport.request_sha256s == []
    assert scenario.ingress.receipts == []
    assert scenario.bindings.bindings == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_altered_usable_account_status_never_qualifies() -> None:
    scenario = _scenario(
        transport=FixedTransport(
            body=_json_override(_account_body(), trading_blocked=True),
        )
    )

    with pytest.raises(
        AlpacaPaperAccountBindingConflict,
        match="usable authenticated observation",
    ):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.bindings.bindings == []


def test_concrete_transport_fixes_tls_redirect_timeout_target_and_header_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeResponse:
        status_code = 200

        def __init__(self) -> None:
            self.headers = {
                "x-request-id": "strict-request-id",
                "content-type": "application/json; charset=utf-8",
            }
            if observed.get("encoded") is True:
                self.headers["content-encoding"] = "gzip"
            self.request = httpx.Request(
                "GET",
                f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/account",
            )

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def iter_raw(self) -> object:
            body = b"gzip-wire-entity-body" if observed.get("encoded") is True else _account_body()
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
            assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
            assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
            return FakeResponse()

    monkeypatch.setattr(runtime_module.httpx, "Client", FakeClient)
    description = create_alpaca_account_observation_description(
        account_id=ACCOUNT_ID,
    )
    request = AlpacaPaperAccountTransportRequest(
        description=description,
        credential_reference_sha256="1" * 64,
        demand_sha256="2" * 64,
        permit_sha256="3" * 64,
        permit_freshness_sha256="4" * 64,
        fence_receipt_sha256="5" * 64,
        started_at=BASE,
    )
    material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )

    response = _HttpxAlpacaPaperAccountTransport().execute(
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
    assert observed["url"] == f"{ALPACA_PAPER_TRADING_BASE_URL}/v2/account"
    assert observed["header_names"] == ALPACA_AUTH_HEADER_NAMES
    assert response.provider_request_id == "strict-request-id"
    assert response.media_type == ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
    assert request.httpx_phase_timeout == ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT

    observed["encoded"] = True
    encoded_material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )
    encoded_response = _HttpxAlpacaPaperAccountTransport().execute(
        request,
        _AlpacaPaperAuthenticationHeaders(encoded_material),
    )
    encoded_material.close()

    assert encoded_response.response_body == b"gzip-wire-entity-body"
    assert encoded_response.media_type is None


def test_concrete_transport_drops_httpx_exception_context_with_auth_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingClient:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

        def __enter__(self) -> FailingClient:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def stream(
            self,
            method: str,
            url: str,
            *,
            headers: _AlpacaPaperAuthenticationHeaders,
        ) -> object:
            request_with_secrets = httpx.Request(
                method,
                url,
                headers=dict(headers),
            )
            raise httpx.ConnectError(
                f"unsafe HTTPX diagnostic {SECRET_KEY}",
                request=request_with_secrets,
            )

    monkeypatch.setattr(runtime_module.httpx, "Client", FailingClient)
    request = AlpacaPaperAccountTransportRequest(
        description=create_alpaca_account_observation_description(
            account_id=ACCOUNT_ID,
        ),
        credential_reference_sha256="1" * 64,
        demand_sha256="2" * 64,
        permit_sha256="3" * 64,
        permit_freshness_sha256="4" * 64,
        fence_receipt_sha256="5" * 64,
        started_at=BASE,
    )
    material = _AlpacaPaperCredentialMaterial(
        api_key_id=API_KEY_ID,
        secret_key=SECRET_KEY,
    )
    try:
        with pytest.raises(AlpacaPaperAccountTransportError) as raised:
            _HttpxAlpacaPaperAccountTransport().execute(
                request,
                _AlpacaPaperAuthenticationHeaders(material),
            )
    finally:
        material.close()

    assert SECRET_KEY not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
