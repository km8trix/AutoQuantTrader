from __future__ import annotations

import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import packages.adapters.broker.alpaca_paper_order_snapshot_runtime as runtime_module
from packages.adapters.broker.alpaca_paper import ALPACA_AUTH_HEADER_NAMES
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    _alpaca_paper_account_identity_continuity_receipt,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID,
    ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
    AlpacaPaperOrderSnapshotTransportError,
    AlpacaPaperOrderSnapshotTransportRequest,
    AlpacaPaperOrderSnapshotTransportResponse,
    _alpaca_paper_authenticated_order_snapshot_page_receipt,
    _alpaca_paper_authenticated_order_snapshot_prefix,
    _alpaca_paper_order_snapshot_page_preparation_receipt,
    _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport,
    alpaca_paper_order_snapshot_page_delivery_idempotency_key,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    create_alpaca_paper_order_snapshot_plan,
    start_alpaca_paper_order_snapshot,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitFreshnessReceipt,
    BrokerRequestPurpose,
    _broker_request_permit_freshness_receipt,
    issue_broker_request_permit,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    ACCOUNT_ID,
    API_KEY_ID,
    SECRET_KEY,
    SequenceClock,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    _scenario as account_scenario,
)
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order
from tests.unit.test_submission_attempt import fence_receipt

BASE = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)
VALID_UNTIL = BASE + timedelta(seconds=30)


class InMemoryIngress:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.deliveries: list[BrokerIngressDelivery] = []
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        self.events.append("raw")
        self.deliveries.append(delivery)
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=(
                None if not self.receipts else self.receipts[-1].semantic_sha256
            ),
        )
        self.receipts.append(receipt)
        return receipt


class Resolver:
    resolver_id = "phase4o-test-secret-store"
    resolver_version = "v1"

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.references: list[AlpacaPaperCredentialReference] = []
        self.material: _AlpacaPaperCredentialMaterial | None = None

    def _resolve_for_order_snapshot_page(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        self.events.append("resolve")
        self.references.append(reference)
        envelope = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(envelope) is _AlpacaPaperCredentialMaterial
        self.material = envelope
        return envelope


class Budget:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.demands: list[BrokerRequestDemand] = []
        self.permits: list[BrokerRequestPermit] = []

    def issue_new(
        self,
        *,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        self.events.append("permit")
        assert policy == ALPACA_PAPER_REQUEST_BUDGET_POLICY
        self.demands.append(demand)
        permit = issue_broker_request_permit(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            issued_at=BASE + timedelta(milliseconds=40),
            active_permits=(),
            previous_permit=None,
            previous_policy=None,
        )
        self.permits.append(permit)
        return permit

    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> object:
        self.events.append("permit-fresh")
        assert policy == ALPACA_PAPER_REQUEST_BUDGET_POLICY
        return _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=BASE + timedelta(milliseconds=60),
        )


class MismatchedFreshnessBudget(Budget):
    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> object:
        valid = super().authenticate_fresh(
            permit=permit,
            policy=policy,
            demand=demand,
        )
        assert type(valid) is BrokerRequestPermitFreshnessReceipt
        forged = object.__new__(BrokerRequestPermitFreshnessReceipt)
        for field_name, value in (
            ("permit_id", valid.permit_id),
            ("permit_sha256", valid.permit_sha256),
            ("policy_sha256", valid.policy_sha256),
            ("demand_sha256", "0" * 64),
            ("checked_at", valid.checked_at),
            ("expires_at", valid.expires_at),
        ):
            object.__setattr__(forged, field_name, value)
        return forged


class Identities:
    def __init__(self, events: list[str], *, fail_on_call: int | None = None) -> None:
        self.events = events
        self.fail_on_call = fail_on_call
        self.calls = 0

    def authenticate_terminal_identity(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt:
        self.calls += 1
        self.events.append(f"identity-{self.calls}")
        if self.calls == self.fail_on_call:
            raise RuntimeError(f"unsafe identity detail {SECRET_KEY}")
        return _alpaca_paper_account_identity_continuity_receipt(
            binding,
            checked_at=checked_at,
        )


class Coordinator:
    account_id = ACCOUNT_ID

    def __init__(
        self,
        events: list[str],
        *,
        change_post_fence: bool = False,
    ) -> None:
        self.events = events
        self.change_post_fence = change_post_fence
        self.calls = 0

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        del fence
        self.calls += 1
        self.events.append(f"fence-{self.calls}")
        return fence_receipt(
            validated_at=BASE + timedelta(milliseconds=50 if self.calls == 1 else 110),
            valid_until=VALID_UNTIL,
            fencing_generation=(2 if self.change_post_fence and self.calls == 2 else 1),
        )


class Transport:
    transport_id = ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION

    def __init__(
        self,
        events: list[str],
        *,
        body: bytes = b"[]",
        request_id: str | None = "phase4o-request-001",
        media_type: str | None = "application/json",
        request_sha256: str | None = None,
        fail: bool = False,
    ) -> None:
        self.events = events
        self.body = body
        self.request_id = request_id
        self.media_type = media_type
        self.request_sha256 = request_sha256
        self.fail = fail
        self.requests: list[AlpacaPaperOrderSnapshotTransportRequest] = []

    def execute(
        self,
        request: AlpacaPaperOrderSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperOrderSnapshotTransportResponse:
        self.events.append("transport")
        self.requests.append(request)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        if self.fail:
            raise RuntimeError(f"unsafe transport detail {SECRET_KEY}")
        return AlpacaPaperOrderSnapshotTransportResponse(
            request_sha256=self.request_sha256 or request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=self.request_id,
            media_type=self.media_type,
            response_body=self.body,
        )


class PageRuntime:
    def __init__(self, events: list[str], *, fail_prepare: bool = False) -> None:
        self.events = events
        self.fail_prepare = fail_prepare
        self.forge_prefix = False
        self.receipts: list[AlpacaPaperAuthenticatedOrderSnapshotPageReceipt] = []
        self.evidence: list[AlpacaPaperAuthenticatedOrderSnapshotPageEvidence] = []
        self.preparations: dict[str, AlpacaPaperOrderSnapshotPagePreparationReceipt] = {}

    def load_prefix(
        self,
        plan: Any,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        return _alpaca_paper_authenticated_order_snapshot_prefix(
            plan,
            page_receipts=tuple(self.receipts),
        )

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt:
        self.events.append("prepare")
        if self.fail_prepare:
            raise RuntimeError("already claimed")
        existing = self.preparations.get(description.semantic_sha256)
        if existing is not None:
            raise RuntimeError("unresolved single-use claim")
        prefix = self.load_prefix(description.plan)
        assert prefix.next_page_description == description
        previous = self.receipts[-1] if self.receipts else None
        preparation = _alpaca_paper_order_snapshot_page_preparation_receipt(
            description,
            prefix_capture_sha256=prefix.capture.semantic_sha256,
            prefix_page_count=prefix.page_count,
            previous_page_receipt_id=(None if previous is None else previous.receipt_id),
            previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
            prepared_at=checked_at,
        )
        self.preparations[description.semantic_sha256] = preparation
        if self.forge_prefix:
            return _alpaca_paper_order_snapshot_page_preparation_receipt(
                description,
                prefix_capture_sha256="0" * 64,
                prefix_page_count=preparation.prefix_page_count,
                previous_page_receipt_id=preparation.previous_page_receipt_id,
                previous_page_receipt_sha256=(preparation.previous_page_receipt_sha256),
                prepared_at=preparation.prepared_at,
            )
        return preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self.events.append("commit")
        post = evidence.post_fence_receipt
        commit_fence = _account_fence_receipt(
            fence=post.fence,
            validated_at=evidence.authenticated_at,
            valid_until=post.valid_until,
            policy_sha256=post.policy_sha256,
            lease_sha256=post.lease_sha256,
        )
        previous = self.receipts[-1] if self.receipts else None
        receipt = _alpaca_paper_authenticated_order_snapshot_page_receipt(
            evidence,
            commit_fence_receipt=commit_fence,
            previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
        )
        self.evidence.append(evidence)
        self.receipts.append(receipt)
        return receipt


@dataclass(slots=True)
class Scenario:
    reference: AlpacaPaperCredentialReference
    binding: AlpacaPaperAuthenticatedAccountBinding
    description: AlpacaPaperOrderSnapshotPageDescription
    resolver: Resolver
    transport: Transport
    budget: Budget
    identities: Identities
    coordinator: Coordinator
    ingress: InMemoryIngress
    pages: PageRuntime
    clock: SequenceClock
    events: list[str]

    def run(self) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        return _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport(
            reference=self.reference,
            account_binding=self.binding,
            description=self.description,
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=self.budget,  # type: ignore[arg-type]
            account_bindings=self.identities,  # type: ignore[arg-type]
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=fence_receipt(
                validated_at=BASE - timedelta(seconds=1),
                valid_until=VALID_UNTIL,
            ).fence,
            ingress_recorder=self.ingress,
            page_runtime=self.pages,
            clock=self.clock,
        )


def _clock() -> SequenceClock:
    return SequenceClock(
        BASE,
        BASE + timedelta(milliseconds=10),
        BASE + timedelta(milliseconds=20),
        BASE + timedelta(milliseconds=30),
        BASE + timedelta(milliseconds=70),
        BASE + timedelta(milliseconds=80),
        BASE + timedelta(milliseconds=90),
        BASE + timedelta(milliseconds=100),
        BASE + timedelta(milliseconds=120),
        BASE + timedelta(milliseconds=130),
    )


def _scenario(
    *,
    transport: Transport | None = None,
    pages: PageRuntime | None = None,
    coordinator: Coordinator | None = None,
    identities: Identities | None = None,
    body: bytes = b"[]",
    page_limit: int = 2,
) -> Scenario:
    account = account_scenario()
    binding = account.run()
    events: list[str] = []
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key="phase4o-capture-0001",
        page_limit=page_limit,
        maximum_pages=3,
    )
    description = start_alpaca_paper_order_snapshot(plan).next_page_description
    assert description is not None
    return Scenario(
        reference=account.reference,
        binding=binding,
        description=description,
        resolver=Resolver(events),
        transport=transport or Transport(events, body=body),
        budget=Budget(events),
        identities=identities or Identities(events),
        coordinator=coordinator or Coordinator(events),
        ingress=InMemoryIngress(events),
        pages=pages or PageRuntime(events),
        clock=_clock(),
        events=events,
    )


def _assert_higher_authority_withheld(value: object) -> None:
    for name in (
        "runtime_current",
        "monotonic_timing_qualified",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "converged",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_complete",
        "reconciliation_completion_authorized",
        "unknown_resolution_authorized",
        "canonical_execution_fact_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "reconciliation_ready",
        "readiness_transition_authorized",
        "transport_submission_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, name) is False


def test_one_page_is_prepared_before_secrets_and_capacity_then_committed() -> None:
    scenario = _scenario()

    receipt = scenario.run()

    assert scenario.events == [
        "prepare",
        "resolve",
        "permit",
        "fence-1",
        "permit-fresh",
        "identity-1",
        "transport",
        "raw",
        "fence-2",
        "identity-2",
        "commit",
    ]
    assert receipt.page_number == 1
    assert receipt.persisted_page.receipt == scenario.ingress.receipts[0]
    assert scenario.budget.demands[0].purpose is BrokerRequestPurpose.RECONCILIATION
    assert scenario.budget.demands[0].idempotency_key == (
        alpaca_paper_order_snapshot_page_delivery_idempotency_key(scenario.description)
    )
    assert scenario.ingress.deliveries[0].delivery_idempotency_key == (
        scenario.budget.demands[0].idempotency_key
    )
    assert receipt.request_budget_enforced is True
    assert receipt.authenticated_provider_evidence is True
    assert receipt.raw_response_persisted is True
    assert receipt.authenticated_order_snapshot_page_established is True
    assert receipt.committed_prefix_established is True
    _assert_higher_authority_withheld(receipt)
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


def test_prepare_conflict_fails_before_secret_permit_or_transport() -> None:
    scenario = _scenario()
    scenario.pages.fail_prepare = True

    with pytest.raises(AlpacaPaperOrderSnapshotConflict, match="preparation failed"):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.resolver.references == []
    assert scenario.budget.demands == []
    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []


def test_pre_permit_restart_refuses_the_existing_single_use_preparation() -> None:
    scenario = _scenario()
    scenario.pages.prepare_next(
        scenario.description,
        checked_at=BASE - timedelta(milliseconds=1),
    )
    scenario.events.clear()

    with pytest.raises(AlpacaPaperOrderSnapshotConflict, match="preparation failed"):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.resolver.references == []
    assert scenario.budget.demands == []
    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []


def test_mismatched_freshness_receipt_fails_before_page_transport() -> None:
    scenario = _scenario()
    scenario.budget = MismatchedFreshnessBudget(scenario.events)

    with pytest.raises(AlpacaPaperOrderSnapshotConflict, match="freshness receipt conflicts"):
        scenario.run()

    assert scenario.events == [
        "prepare",
        "resolve",
        "permit",
        "fence-1",
        "permit-fresh",
    ]
    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_forged_page_preparation_fails_before_secret_or_capacity() -> None:
    scenario = _scenario(body=_body(_order(1)), page_limit=1)
    scenario.run()
    prefix = scenario.pages.load_prefix(scenario.description.plan)
    next_description = prefix.next_page_description
    assert next_description is not None

    scenario.description = next_description
    scenario.pages.forge_prefix = True
    scenario.clock = _clock()
    scenario.events.clear()
    scenario.resolver = Resolver(scenario.events)
    scenario.transport = Transport(
        scenario.events,
        body=b"[]",
        request_id="phase4o-request-forged-preparation",
    )

    with pytest.raises(
        AlpacaPaperOrderSnapshotConflict,
        match="authenticated committed prefix",
    ):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.resolver.references == []
    assert scenario.transport.requests == []
    assert len(scenario.pages.receipts) == 1


@pytest.mark.parametrize(
    ("body", "request_id", "media_type"),
    (
        (b"{}", "phase4o-request-malformed", "application/json"),
        (b"[]", None, "application/json"),
        (b"[]", "phase4o-request-wrong-media", "text/plain"),
    ),
)
def test_decode_failure_keeps_raw_only(
    body: bytes,
    request_id: str | None,
    media_type: str | None,
) -> None:
    scenario = _scenario()
    scenario.transport.body = body
    scenario.transport.request_id = request_id
    scenario.transport.media_type = media_type

    with pytest.raises(ValueError):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == body
    assert scenario.pages.receipts == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_transport_failure_is_sanitized_and_zeroes_credentials() -> None:
    scenario = _scenario()
    scenario.transport.fail = True

    with pytest.raises(AlpacaPaperOrderSnapshotTransportError) as captured:
        scenario.run()

    assert SECRET_KEY not in str(captured.value)
    assert scenario.ingress.receipts == []
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_post_transport_fence_change_leaves_only_raw_page() -> None:
    scenario = _scenario()
    scenario.coordinator.change_post_fence = True

    with pytest.raises(AlpacaPaperOrderSnapshotConflict, match="fence changed"):
        scenario.run()

    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.pages.receipts == []


def test_response_for_another_request_cannot_reach_raw_persistence() -> None:
    scenario = _scenario()
    scenario.transport.request_sha256 = "0" * 64

    with pytest.raises(AlpacaPaperOrderSnapshotTransportError, match="another request"):
        scenario.run()

    assert scenario.ingress.receipts == []
    assert scenario.pages.receipts == []


def test_authenticated_prefix_proves_runtime_and_phase4m_predecessors() -> None:
    scenario = _scenario(body=_body(_order(1)), page_limit=1)
    first = scenario.run()
    prefix = scenario.pages.load_prefix(scenario.description.plan)
    second_description = prefix.next_page_description
    assert second_description is not None

    scenario.description = second_description
    scenario.clock = _clock()
    scenario.resolver = Resolver(scenario.events)
    scenario.budget = Budget(scenario.events)
    scenario.transport = Transport(
        scenario.events,
        body=b"[]",
        request_id="phase4o-request-002",
    )
    scenario.coordinator = Coordinator(scenario.events)
    scenario.identities = Identities(scenario.events)
    second = scenario.run()
    completed = scenario.pages.load_prefix(scenario.description.plan)

    assert second.previous_page_receipt_sha256 == first.semantic_sha256
    assert second.evidence.preparation.previous_page_receipt_id == first.receipt_id
    assert second.description.previous_page_sha256 == first.persisted_page.semantic_sha256
    assert completed.page_count == 2
    assert completed.capture.pagination_exhausted is True
    assert completed.next_page_description is None
    assert completed.provider_snapshot_complete is False
    assert completed.converged is False


def test_public_api_cannot_inject_transport_and_proofs_are_constructed() -> None:
    assert (
        "transport"
        not in inspect.signature(
            runtime_module.observe_authenticated_alpaca_paper_order_snapshot_page
        ).parameters
    )
    assert "_HttpxAlpacaPaperOrderSnapshotTransport" not in runtime_module.__all__
    for proof_type in (
        AlpacaPaperOrderSnapshotPagePreparationReceipt,
        AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
        AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
        AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ):
        with pytest.raises(TypeError):
            proof_type()
