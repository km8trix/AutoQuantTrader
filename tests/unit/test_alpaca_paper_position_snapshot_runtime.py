from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import packages.adapters.broker.alpaca_paper_position_snapshot_runtime as runtime_module
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
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID,
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotTransportError,
    AlpacaPaperPositionSnapshotTransportRequest,
    AlpacaPaperPositionSnapshotTransportResponse,
    _alpaca_paper_authenticated_position_snapshot_evidence,
    _alpaca_paper_authenticated_position_snapshot_receipt,
    _alpaca_paper_position_snapshot_preparation_receipt,
    _observe_authenticated_alpaca_paper_position_snapshot_with_transport,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
    persist_then_decode_alpaca_paper_position_snapshot_response,
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
from tests.unit.test_submission_attempt import fence_receipt

BASE = datetime(2026, 7, 28, 20, 0, tzinfo=UTC)
VALID_UNTIL = BASE + timedelta(seconds=30)


def _position(number: int) -> dict[str, object]:
    return {
        "asset_id": str(UUID(int=number)),
        "symbol": f"ASSET{number}",
        "exchange": "NYSE",
        "asset_class": "us_equity",
        "asset_marginable": True,
        "avg_entry_price": "10.00",
        "qty": "1",
        "side": "long",
        "market_value": "10.00",
        "cost_basis": "10.00",
        "unrealized_pl": "0.00",
        "unrealized_plpc": "0.00",
        "unrealized_intraday_pl": "0.00",
        "unrealized_intraday_plpc": "0.00",
        "current_price": "10.00",
        "lastday_price": "10.00",
        "change_today": "0.00",
    }


def _body(*positions: dict[str, object]) -> bytes:
    return json.dumps(positions, separators=(",", ":")).encode()


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
    resolver_id = "phase4t-test-secret-store"
    resolver_version = "v1"

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.references: list[AlpacaPaperCredentialReference] = []
        self.material: _AlpacaPaperCredentialMaterial | None = None

    def _resolve_for_position_snapshot(
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
    def __init__(
        self,
        events: list[str],
        *,
        fail_issue: bool = False,
        mismatch_freshness: bool = False,
    ) -> None:
        self.events = events
        self.fail_issue = fail_issue
        self.mismatch_freshness = mismatch_freshness
        self.demands: list[BrokerRequestDemand] = []
        self.permits: list[BrokerRequestPermit] = []

    def issue_new(
        self,
        *,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        self.events.append("permit")
        if self.fail_issue:
            raise RuntimeError(f"unsafe budget detail {SECRET_KEY}")
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
        valid = _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=BASE + timedelta(milliseconds=60),
        )
        if not self.mismatch_freshness:
            return valid
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
    def __init__(
        self,
        events: list[str],
        *,
        fail_on_call: int | None = None,
        wrong_instant_on_call: int | None = None,
    ) -> None:
        self.events = events
        self.fail_on_call = fail_on_call
        self.wrong_instant_on_call = wrong_instant_on_call
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
            checked_at=(
                checked_at + timedelta(microseconds=1)
                if self.calls == self.wrong_instant_on_call
                else checked_at
            ),
        )


class Coordinator:
    account_id = ACCOUNT_ID

    def __init__(
        self,
        events: list[str],
        *,
        change_fence_on_call: int | None = None,
        change_lease_on_call: int | None = None,
    ) -> None:
        self.events = events
        self.change_fence_on_call = change_fence_on_call
        self.change_lease_on_call = change_lease_on_call
        self.calls = 0

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        del fence
        self.calls += 1
        self.events.append(f"fence-{self.calls}")
        validated_at = BASE + timedelta(milliseconds={1: 50, 2: 110, 3: 130}[self.calls])
        receipt = fence_receipt(
            account_id=ACCOUNT_ID,
            validated_at=validated_at,
            valid_until=VALID_UNTIL,
            fencing_generation=(2 if self.calls == self.change_fence_on_call else 1),
        )
        if self.calls != self.change_lease_on_call:
            return receipt
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256="e" * 64,
        )


class Transport:
    transport_id = ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION

    def __init__(
        self,
        events: list[str],
        *,
        body: bytes = b"[]",
        request_id: str | None = "phase4t-request-001",
        media_type: str | None = "application/json",
        request_sha256: str | None = None,
        fail: bool = False,
        invalid_result: bool = False,
    ) -> None:
        self.events = events
        self.body = body
        self.request_id = request_id
        self.media_type = media_type
        self.request_sha256 = request_sha256
        self.fail = fail
        self.invalid_result = invalid_result
        self.requests: list[AlpacaPaperPositionSnapshotTransportRequest] = []

    def execute(
        self,
        request: AlpacaPaperPositionSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperPositionSnapshotTransportResponse:
        self.events.append("transport")
        self.requests.append(request)
        assert tuple(headers) == ALPACA_AUTH_HEADER_NAMES
        assert headers[ALPACA_AUTH_HEADER_NAMES[0]] == API_KEY_ID
        assert headers[ALPACA_AUTH_HEADER_NAMES[1]] == SECRET_KEY
        if self.fail:
            raise RuntimeError(f"unsafe transport detail {SECRET_KEY}")
        if self.invalid_result:
            return object()  # type: ignore[return-value]
        return AlpacaPaperPositionSnapshotTransportResponse(
            request_sha256=self.request_sha256 or request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=self.request_id,
            media_type=self.media_type,
            response_body=self.body,
        )


class SnapshotRuntime:
    def __init__(
        self,
        events: list[str],
        *,
        fail_prepare: bool = False,
        forge_prepared_at: bool = False,
        fail_record: bool = False,
        invalid_load: bool = False,
        commit_fence_mode: str | None = None,
    ) -> None:
        self.events = events
        self.fail_prepare = fail_prepare
        self.forge_prepared_at = forge_prepared_at
        self.fail_record = fail_record
        self.invalid_load = invalid_load
        self.commit_fence_mode = commit_fence_mode
        self.preparations: dict[
            str,
            AlpacaPaperPositionSnapshotPreparationReceipt,
        ] = {}
        self.receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None
        self.evidence: list[AlpacaPaperAuthenticatedPositionSnapshotEvidence] = []

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt:
        self.events.append("prepare")
        if self.fail_prepare:
            raise RuntimeError("already claimed")
        if plan.semantic_sha256 in self.preparations or self.receipt is not None:
            raise RuntimeError("unresolved or terminal single-use claim")
        preparation = _alpaca_paper_position_snapshot_preparation_receipt(
            plan,
            prepared_at=(
                checked_at + timedelta(microseconds=1) if self.forge_prepared_at else checked_at
            ),
        )
        self.preparations[plan.semantic_sha256] = preparation
        return preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        self.events.append("commit")
        if self.fail_record:
            raise RuntimeError(f"unsafe commit detail {SECRET_KEY}")
        final_fence = evidence.final_fence_receipt
        commit_fence = _account_fence_receipt(
            fence=final_fence.fence,
            validated_at=(
                evidence.authenticated_at - timedelta(microseconds=1)
                if self.commit_fence_mode == "before-authentication"
                else evidence.authenticated_at + timedelta(milliseconds=1)
            ),
            valid_until=final_fence.valid_until,
            policy_sha256=final_fence.policy_sha256,
            lease_sha256=(
                "f" * 64
                if self.commit_fence_mode == "different-lease"
                else final_fence.lease_sha256
            ),
        )
        receipt = _alpaca_paper_authenticated_position_snapshot_receipt(
            evidence,
            commit_fence_receipt=commit_fence,
        )
        self.evidence.append(evidence)
        self.receipt = receipt
        return receipt

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        self.events.append("load")
        assert self.receipt is None or self.receipt.plan == plan
        if self.invalid_load:
            return None
        return self.receipt


@dataclass(slots=True)
class Scenario:
    plan: AlpacaPaperPositionSnapshotRuntimePlan
    resolver: Resolver
    transport: Transport
    budget: Budget
    identities: Identities
    coordinator: Coordinator
    ingress: InMemoryIngress
    snapshots: SnapshotRuntime
    clock: SequenceClock
    events: list[str]
    fence: AccountFence

    def run(self) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        return _observe_authenticated_alpaca_paper_position_snapshot_with_transport(
            plan=self.plan,
            credential_resolver=self.resolver,
            transport=self.transport,
            budget=self.budget,  # type: ignore[arg-type]
            account_bindings=self.identities,  # type: ignore[arg-type]
            coordinator=self.coordinator,  # type: ignore[arg-type]
            fence=self.fence,
            ingress_recorder=self.ingress,
            snapshot_runtime=self.snapshots,
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
        BASE + timedelta(milliseconds=140),
    )


def _clock_with_response_at(received_at: datetime) -> SequenceClock:
    return SequenceClock(
        BASE,
        BASE + timedelta(milliseconds=10),
        BASE + timedelta(milliseconds=20),
        BASE + timedelta(milliseconds=30),
        BASE + timedelta(milliseconds=70),
        BASE + timedelta(milliseconds=80),
        received_at,
        received_at + timedelta(milliseconds=10),
        received_at + timedelta(milliseconds=30),
        received_at + timedelta(milliseconds=50),
    )


def _scenario(
    *,
    body: bytes = b"[]",
    transport: Transport | None = None,
    budget: Budget | None = None,
    identities: Identities | None = None,
    coordinator: Coordinator | None = None,
    snapshots: SnapshotRuntime | None = None,
) -> Scenario:
    account = account_scenario()
    binding = account.run()
    events: list[str] = []
    description = create_alpaca_paper_position_snapshot_description(
        account_id=ACCOUNT_ID,
        capture_idempotency_key="phase4t-position-capture-0001",
    )
    plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=description,
        reference=account.reference,
        account_binding=binding,
    )
    initial_fence = fence_receipt(
        account_id=ACCOUNT_ID,
        validated_at=BASE - timedelta(seconds=1),
        valid_until=VALID_UNTIL,
    ).fence
    return Scenario(
        plan=plan,
        resolver=Resolver(events),
        transport=transport or Transport(events, body=body),
        budget=budget or Budget(events),
        identities=identities or Identities(events),
        coordinator=coordinator or Coordinator(events),
        ingress=InMemoryIngress(events),
        snapshots=snapshots or SnapshotRuntime(events),
        clock=_clock(),
        events=events,
        fence=initial_fence,
    )


def _assert_higher_authority_withheld(value: object) -> None:
    for name in (
        "runtime_current",
        "monotonic_timing_qualified",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "converged",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "canonical_position_fact_authorized",
        "canonical_execution_fact_authorized",
        "canonical_account_fact_authorized",
        "canonical_ledger_fact_authorized",
        "canonical_cash_fact_authorized",
        "reconciliation_ready",
        "readiness_transition_authorized",
        "transport_submission_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, name) is False


def test_capture_is_claimed_before_secrets_then_committed_and_reloaded() -> None:
    scenario = _scenario(body=_body(_position(1)))

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
        "fence-3",
        "commit",
        "load",
    ]
    assert receipt == scenario.snapshots.receipt
    assert receipt.persisted_snapshot.receipt == scenario.ingress.receipts[0]
    assert receipt.persisted_snapshot.observation.position_count == 1
    assert receipt.commit_fence_receipt != receipt.evidence.final_fence_receipt
    assert receipt.commit_fence_receipt.validated_at > receipt.evidence.authenticated_at
    assert receipt.commit_fence_receipt.fence == receipt.evidence.final_fence_receipt.fence
    assert (
        receipt.commit_fence_receipt.lease_sha256
        == receipt.evidence.final_fence_receipt.lease_sha256
    )
    demand = scenario.budget.demands[0]
    assert demand.purpose is BrokerRequestPurpose.RECONCILIATION
    assert demand.idempotency_key == scenario.plan.description.capture_idempotency_key
    assert demand.correlation_sha256 == scenario.plan.semantic_sha256
    assert scenario.ingress.deliveries[0].delivery_idempotency_key == demand.idempotency_key
    assert receipt.request_budget_enforced is True
    assert receipt.authenticated_provider_evidence is True
    assert receipt.raw_response_persisted is True
    assert receipt.fresh_single_use_claim_established is True
    assert receipt.authenticated_position_snapshot_established is True
    assert receipt.durable_authenticated_position_snapshot_established is True
    _assert_higher_authority_withheld(receipt)
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True
    assert bytes(scenario.resolver.material._api_key_id) == b"\x00" * len(API_KEY_ID)
    assert bytes(scenario.resolver.material._secret_key) == b"\x00" * len(SECRET_KEY)


def test_stalled_preparation_fails_before_secrets_permit_or_transport() -> None:
    scenario = _scenario()
    scenario.snapshots.prepare(
        scenario.plan,
        checked_at=BASE - timedelta(microseconds=1),
    )
    scenario.events.clear()

    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="preparation failed"):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.resolver.references == []
    assert scenario.budget.demands == []
    assert scenario.transport.requests == []
    assert scenario.ingress.receipts == []


def test_completed_capture_has_no_retry_path_and_fails_at_prepare() -> None:
    scenario = _scenario()
    first = scenario.run()
    scenario.events.clear()
    scenario.clock = _clock()
    scenario.resolver = Resolver(scenario.events)
    scenario.budget = Budget(scenario.events)
    scenario.transport = Transport(
        scenario.events,
        request_id="phase4t-retry-request",
    )
    scenario.coordinator = Coordinator(scenario.events)
    scenario.identities = Identities(scenario.events)

    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="preparation failed"):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.snapshots.receipt == first
    assert len(scenario.ingress.receipts) == 1
    assert scenario.resolver.references == []


def test_forged_preparation_fails_before_secret_or_capacity() -> None:
    scenario = _scenario()
    scenario.snapshots.forge_prepared_at = True

    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="fresh position claim"):
        scenario.run()

    assert scenario.events == ["prepare"]
    assert scenario.resolver.references == []
    assert scenario.budget.demands == []
    assert scenario.transport.requests == []


def test_budget_failures_close_credentials_before_transport() -> None:
    issue = _scenario()
    issue.budget.fail_issue = True
    with pytest.raises(AlpacaPaperPositionSnapshotConflict) as captured:
        issue.run()
    assert SECRET_KEY not in str(captured.value)
    assert issue.events == ["prepare", "resolve", "permit"]
    assert issue.transport.requests == []
    assert issue.resolver.material is not None
    assert issue.resolver.material.closed is True

    freshness = _scenario()
    freshness.budget.mismatch_freshness = True
    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="freshness"):
        freshness.run()
    assert freshness.events == [
        "prepare",
        "resolve",
        "permit",
        "fence-1",
        "permit-fresh",
    ]
    assert freshness.transport.requests == []
    assert freshness.ingress.receipts == []


@pytest.mark.parametrize(
    ("body", "request_id", "media_type"),
    (
        (b"{}", "phase4t-malformed", "application/json"),
        (b"[]", None, "application/json"),
        (b"[]", "phase4t-wrong-media", "text/plain"),
    ),
)
def test_decode_or_media_failure_keeps_raw_without_authenticated_commit(
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
    assert scenario.snapshots.receipt is None
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


@pytest.mark.parametrize(
    ("received_at", "match"),
    (
        (BASE + timedelta(seconds=31), "credential bound"),
        (BASE + timedelta(seconds=4), "request permit expired"),
    ),
)
def test_late_response_is_retained_raw_before_authority_rejection(
    received_at: datetime,
    match: str,
) -> None:
    scenario = _scenario(body=_body(_position(1)))
    scenario.clock = _clock_with_response_at(received_at)

    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match=match):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.ingress.receipts[0].delivery.body == _body(_position(1))
    assert scenario.ingress.receipts[0].delivery.received_at == received_at
    assert scenario.snapshots.receipt is None
    assert scenario.events[-1] == "raw"


def test_authenticated_evidence_binds_permit_through_response_completion() -> None:
    scenario = _scenario(body=_body(_position(1)))
    receipt = scenario.run()
    evidence = receipt.evidence
    received_at = evidence.permit.expires_at
    ingress = InMemoryIngress([])
    persisted_snapshot = persist_then_decode_alpaca_paper_position_snapshot_response(
        ingress,
        evidence.plan.description,
        http_status=evidence.response.http_status,
        provider_request_id=evidence.response.provider_request_id,
        response_body=evidence.response.response_body,
        received_at=received_at,
        recorded_at=received_at + timedelta(milliseconds=1),
        media_type=evidence.response.media_type,
    )
    post_fence = _account_fence_receipt(
        fence=evidence.final_fence_receipt.fence,
        validated_at=received_at + timedelta(milliseconds=2),
        valid_until=evidence.final_fence_receipt.valid_until,
        policy_sha256=evidence.final_fence_receipt.policy_sha256,
        lease_sha256=evidence.final_fence_receipt.lease_sha256,
    )
    post_identity = _alpaca_paper_account_identity_continuity_receipt(
        evidence.plan.account_binding,
        checked_at=received_at + timedelta(milliseconds=3),
    )
    final_fence = _account_fence_receipt(
        fence=evidence.final_fence_receipt.fence,
        validated_at=received_at + timedelta(milliseconds=4),
        valid_until=evidence.final_fence_receipt.valid_until,
        policy_sha256=evidence.final_fence_receipt.policy_sha256,
        lease_sha256=evidence.final_fence_receipt.lease_sha256,
    )

    with pytest.raises(
        AlpacaPaperPositionSnapshotConflict,
        match="authority was not current",
    ):
        _alpaca_paper_authenticated_position_snapshot_evidence(
            plan=evidence.plan,
            preparation=evidence.preparation,
            credential_receipt=evidence.credential_receipt,
            pre_account_identity=evidence.pre_account_identity,
            policy=evidence.policy,
            demand=evidence.demand,
            permit=evidence.permit,
            permit_freshness=evidence.permit_freshness,
            pre_fence_receipt=evidence.pre_fence_receipt,
            request=evidence.request,
            response=evidence.response,
            persisted_snapshot=persisted_snapshot,
            post_fence_receipt=post_fence,
            post_account_identity=post_identity,
            final_fence_receipt=final_fence,
            authenticated_at=received_at + timedelta(milliseconds=5),
        )


def test_transport_failure_is_sanitized_and_zeroes_credentials() -> None:
    scenario = _scenario()
    scenario.transport.fail = True

    with pytest.raises(AlpacaPaperPositionSnapshotTransportError) as captured:
        scenario.run()

    assert SECRET_KEY not in str(captured.value)
    assert scenario.ingress.receipts == []
    assert scenario.snapshots.receipt is None
    assert scenario.resolver.material is not None
    assert scenario.resolver.material.closed is True


def test_response_for_another_request_cannot_reach_raw_persistence() -> None:
    scenario = _scenario()
    scenario.transport.request_sha256 = "0" * 64

    with pytest.raises(
        AlpacaPaperPositionSnapshotTransportError,
        match="another request",
    ):
        scenario.run()

    assert scenario.ingress.receipts == []
    assert scenario.snapshots.receipt is None


@pytest.mark.parametrize(
    ("change_fence_on_call", "change_lease_on_call", "match"),
    (
        (2, None, "fence changed"),
        (None, 2, "lease changed"),
        (3, None, "fence changed"),
        (None, 3, "lease changed"),
    ),
)
def test_post_and_final_fence_mutations_leave_only_raw_capture(
    change_fence_on_call: int | None,
    change_lease_on_call: int | None,
    match: str,
) -> None:
    scenario = _scenario()
    scenario.coordinator.change_fence_on_call = change_fence_on_call
    scenario.coordinator.change_lease_on_call = change_lease_on_call

    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match=match):
        scenario.run()

    assert len(scenario.transport.requests) == 1
    assert len(scenario.ingress.receipts) == 1
    assert scenario.snapshots.receipt is None


@pytest.mark.parametrize("call", (1, 2))
def test_terminal_account_identity_failure_never_commits(call: int) -> None:
    scenario = _scenario()
    scenario.identities.fail_on_call = call

    with pytest.raises(AlpacaPaperPositionSnapshotConflict) as captured:
        scenario.run()

    assert SECRET_KEY not in str(captured.value)
    assert scenario.snapshots.receipt is None
    assert len(scenario.ingress.receipts) == (0 if call == 1 else 1)


def test_commit_and_reload_fail_closed_after_raw_capture() -> None:
    commit = _scenario()
    commit.snapshots.fail_record = True
    with pytest.raises(AlpacaPaperPositionSnapshotConflict) as captured:
        commit.run()
    assert SECRET_KEY not in str(captured.value)
    assert len(commit.ingress.receipts) == 1
    assert commit.snapshots.receipt is None
    assert commit.events[-1] == "commit"

    reload = _scenario()
    reload.snapshots.invalid_load = True
    with pytest.raises(
        runtime_module.AlpacaPaperPositionSnapshotRuntimeError,
        match="loader returned invalid",
    ):
        reload.run()
    assert len(reload.ingress.receipts) == 1
    assert reload.snapshots.receipt is not None
    assert reload.events[-2:] == ["commit", "load"]


@pytest.mark.parametrize(
    "commit_fence_mode",
    ("before-authentication", "different-lease"),
)
def test_commit_requires_an_independent_current_exact_fence(
    commit_fence_mode: str,
) -> None:
    scenario = _scenario()
    scenario.snapshots.commit_fence_mode = commit_fence_mode

    with pytest.raises(
        AlpacaPaperPositionSnapshotConflict,
        match="commit failed",
    ):
        scenario.run()

    assert len(scenario.ingress.receipts) == 1
    assert scenario.snapshots.receipt is None
    assert scenario.events[-1] == "commit"


def test_plan_identity_public_api_and_proofs_are_closed() -> None:
    scenario = _scenario()
    plan = scenario.plan

    assert plan.description.account_id == plan.reference.account_id
    assert plan.reference.semantic_sha256 == (plan.account_binding.credential_reference_sha256)
    assert len(plan.semantic_sha256) == 64
    assert (
        "transport"
        not in inspect.signature(
            runtime_module.observe_authenticated_alpaca_paper_position_snapshot
        ).parameters
    )
    assert "_HttpxAlpacaPaperPositionSnapshotTransport" not in runtime_module.__all__
    for proof_type in (
        AlpacaPaperPositionSnapshotPreparationReceipt,
        AlpacaPaperAuthenticatedPositionSnapshotEvidence,
        AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    ):
        with pytest.raises(TypeError):
            proof_type()

    other_description = create_alpaca_paper_position_snapshot_description(
        account_id="different-account",
        capture_idempotency_key="phase4t-different-account",
    )
    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="account identities"):
        create_alpaca_paper_position_snapshot_runtime_plan(
            description=other_description,
            reference=plan.reference,
            account_binding=plan.account_binding,
        )


def test_wrong_fence_and_malformed_external_results_fail_closed() -> None:
    wrong_fence = _scenario()
    wrong_fence.fence = fence_receipt(
        account_id="different-account",
        validated_at=BASE,
        valid_until=VALID_UNTIL,
    ).fence
    with pytest.raises(AlpacaPaperPositionSnapshotConflict, match="another account"):
        wrong_fence.run()
    assert wrong_fence.events == []

    invalid_transport = _scenario()
    invalid_transport.transport.invalid_result = True
    with pytest.raises(
        AlpacaPaperPositionSnapshotTransportError,
        match="invalid response",
    ):
        invalid_transport.run()
    assert invalid_transport.ingress.receipts == []
    assert invalid_transport.resolver.material is not None
    assert invalid_transport.resolver.material.closed is True
