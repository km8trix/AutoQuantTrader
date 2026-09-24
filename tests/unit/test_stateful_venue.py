"""Independent synthetic venue oracles; source fixtures confer no provider permission."""

import hashlib
from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal, Inexact, Rounded, localcontext

import pytest

from packages.application import personal_codec
from packages.application.stateful_venue import (
    VenueInputError,
    advance_stateful_venue,
    initialize_stateful_venue,
    project_stateful_venue,
    venue_fact_page,
)
from packages.domain.accounting_contracts import RegisterVenueSubmission
from packages.domain.corporate_action_ledger import (
    create_cash_dividend,
    create_dividend_payment,
    create_stock_split,
)
from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardObservation,
    ForwardQuote,
    ForwardSource,
    ModeledAvailability,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import Side
from packages.domain.order_reducer import BrokerOrderEventKind
from packages.domain.personal_contracts import ContractRecord, VersionPin
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.stateful_venue_contracts import (
    VenueAccept,
    VenueCancel,
    VenueCommand,
    VenueCorrect,
    VenueModel,
    VenueQuote,
    VenueRunDue,
    VenueSourceReference,
    VenueSubmit,
)
from tests.unit.test_personal_accounting import BASE, POLICY, Harness

D = Decimal
VENUE_POLICY = replace(
    POLICY,
    model_id="stateful-venue-facts-v1",
    fee_per_share=D("0.25"),
    settlement_model="observed-only-v1",
    correction_settlement="explicit-only-v1",
    terminal_model="observed-only-v1",
)
FIXTURE = ForwardSource(
    "fixture-quotes",
    "fixture",
    "synthetic",
    "synthetic-account",
    "synthetic-only",
    "allowed",
    "fixture-owned",
    "not_required",
    None,
)


@dataclass(frozen=True, slots=True)
class FixtureOutboundRecord(ContractRecord):
    role: str
    description: str = "synthetic test receipt, no runtime or provider permission"


RISK = FixtureOutboundRecord("risk")
DISPATCH = FixtureOutboundRecord("dispatch")
SOURCE_BYTES = {r.semantic_sha256: personal_codec.encode_record(r) for r in (RISK, DISPATCH)}


def reference(record):
    raw = SOURCE_BYTES[record.semantic_sha256]
    return VenueSourceReference(
        VersionPin("fixture-outbound", "1", record.semantic_sha256),
        record.semantic_sha256,
        ObjectRef(hashlib.sha256(raw).hexdigest(), len(raw)),
    )


class FixtureVerifier:
    def verify_submission(self, model, submit, *, received_at):
        if model.source_mode != "synthetic_fixture":
            raise ValueError("FIXTURE_VERIFIER_CANNOT_APPROVE_RECORDED_MODE")
        for source, expected in ((submit.risk_source, RISK), (submit.dispatch_source, DISPATCH)):
            if source != reference(expected):
                raise ValueError("FIXTURE_SOURCE_DIFFERS")

    def verify_quote(self, model, source, observation):
        raise ValueError("FIXTURE_VERIFIER_CANNOT_QUALIFY_PROVIDER")


def model(funding="1000", **changes):
    value = VenueModel(
        account_id="synthetic-account",
        venue_id="independent-venue",
        producer=VersionPin("stateful-venue-fixture", "1", "e" * 64),
        instruments=(("spy", "SPY"),),
        sources=(FIXTURE,),
        source_mode="synthetic_fixture",
        execution_policy=VENUE_POLICY,
        initial_cash_flow=create_cash_flow(
            kind=CashFlowKind.CONTRIBUTION,
            currency="USD",
            amount=D(funding),
            effective_at=BASE,
            recorded_at=BASE,
            external_reference="venue-own-funding",
        ),
    )
    return replace(value, **changes)


def packet(m, *, name="one", quantity="4", price="110", side=Side.BUY, funding="1000"):
    # Genuine W2 installation against a separate source ledger. Its snapshot and
    # risk hashes are retained as outbound provenance, never substituted with
    # the venue snapshot. Fixture references are explicitly not a W4 risk proof.
    source = Harness(replace(POLICY, fee_per_share=D("0.25")), funding=funding)
    if side is Side.SELL:
        buy = source.install("source-funding-position", "4", "100", "1")
        source.fill(buy, "4", "100", "1")
    c = source.install(
        name, quantity, price, str(D(quantity) * D("0.25")), side=side, activate=False
    )
    submission = next(s for s in source.state.submissions if s.order_id == c.order_id)
    return VenueSubmit(
        RegisterVenueSubmission(
            account_id=m.account_id,
            submission=submission,
            source_commitment=c,
            source_risk_admission_sha256=RISK.semantic_sha256,
            source_dispatch_sha256=DISPATCH.semantic_sha256,
            venue_model_sha256=m.execution_policy.semantic_sha256,
        ),
        reference(RISK),
        reference(DISPATCH),
    )


def quote(at, *, name="quote-1", bid="99", ask="100", budget="4", side_at=None, observation=None):
    if observation is None:
        observation = ForwardObservation(
            name,
            FIXTURE.source_id,
            ForwardQuote(
                "spy",
                "SPY",
                at.date(),
                None if bid is None else D(bid),
                None if ask is None else D(ask),
                at,
                "USD",
                "unknown",
                bid_at=side_at or at,
                ask_at=side_at or at,
            ),
            ModeledAvailability(at, "explicit-synthetic-clock"),
            name,
        )
    return VenueQuote(observation, "fixture-boot", 0, D(budget))


FIXTURE_VERIFIER = FixtureVerifier()


class VenueHarness:
    def __init__(self, m=None):
        self.model = m or model()
        self.state = initialize_stateful_venue(self.model)
        self.last = None

    def command(self, payload, *, at=None, command_id=None, verifier=FIXTURE_VERIFIER):
        command = VenueCommand(
            command_id or f"venue-command-{self.state.sequence + 1}",
            at or self.state.as_of + timedelta(seconds=1),
            payload,
        )
        result = advance_stateful_venue(self.model, self.state, command, verified_sources=verifier)
        self.state, self.last = result.state, result.acknowledgment
        return command, result.acknowledgment

    def accepted(self, *, name="one", quantity="4", price="110", side=Side.BUY):
        outgoing = packet(self.model, name=name, quantity=quantity, price=price, side=side)
        at = max(
            outgoing.registration.submission.submitted_at, self.state.as_of + timedelta(seconds=1)
        )
        original, ack = self.command(outgoing, at=at)
        assert ack.disposition == "registered", ack.reasons
        order = outgoing.registration.submission.order_id
        _, ack = self.command(VenueAccept(order))
        assert ack.disposition == "applied", ack.reasons
        return original, order

    def filled(self, **values):
        at = self.state.as_of + timedelta(seconds=1)
        _, ack = self.command(quote(at, **values), at=at)
        assert ack.disposition == "applied", ack.reasons
        return self.project()

    def project(self):
        return project_stateful_venue(self.model, self.state)


def test_independent_cash_registration_and_explicit_acceptance():
    m = model(funding="100")
    state = initialize_stateful_venue(m)
    outgoing = packet(m)
    command = VenueCommand("submit", outgoing.registration.submission.submitted_at, outgoing)
    result = advance_stateful_venue(m, state, command, verified_sources=FixtureVerifier())
    assert result.acknowledgment.disposition == "rejected"
    assert result.acknowledgment.reasons == ("VENUE_CASH_CAPACITY_BLOCKED",)
    assert result.state.accounting == state.accounting and not result.state.accounting.submissions
    good = VenueHarness()
    outgoing = packet(good.model)
    _, ack = good.command(outgoing, at=outgoing.registration.submission.submitted_at)
    assert ack.disposition == "registered" and good.state.accounting.broker_events == ()
    assert good.state.accounting.submissions == (outgoing.registration.submission,)
    local = good.state.accounting.commitments[0]
    assert local.snapshot_sha256 == outgoing.registration.source_commitment.snapshot_sha256
    assert local.created_sequence != outgoing.registration.source_commitment.created_sequence
    assert good.project().snapshot.trade_date_cash == 1000


def test_venue_shares_are_independent_of_outbound_source_position():
    h = VenueHarness()
    outgoing = packet(h.model, side=Side.SELL)
    _, ack = h.command(outgoing, at=outgoing.registration.submission.submitted_at)
    assert ack.disposition == "rejected" and ack.reasons == ("VENUE_LONG_SHARE_CAPACITY_BLOCKED",)
    assert not h.project().snapshot.positions


def test_exact_retry_after_fill_returns_original_ack_and_conflict_rejects():
    h = VenueHarness()
    original, _ = h.accepted()
    original_ack = h.state.acknowledgments[0]
    h.filled()
    after = h.state
    result = advance_stateful_venue(h.model, after, original, verified_sources=None)
    assert result.state == after and result.acknowledgment == original_ack
    with pytest.raises(VenueInputError, match="COMMAND_ID_CONFLICT"):
        advance_stateful_venue(
            h.model,
            after,
            replace(original, received_at=original.received_at + timedelta(microseconds=1)),
        )


def test_quote_does_not_accept_and_same_time_or_old_side_cannot_fill():
    h = VenueHarness()
    outgoing = packet(h.model)
    h.command(outgoing, at=outgoing.registration.submission.submitted_at)
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at), at=at)
    assert ack.disposition == "no_effect" and not h.state.accounting.broker_events
    order = outgoing.registration.submission.order_id
    h.command(VenueAccept(order))
    accepted_at = h.state.as_of
    _, ack = h.command(quote(accepted_at, name="same"), at=accepted_at)
    assert ack.disposition == "no_effect"
    at = accepted_at + timedelta(seconds=1)
    _, ack = h.command(quote(at, name="old-side", side_at=accepted_at), at=at)
    assert ack.disposition == "no_effect" and len(h.state.accounting.broker_events) == 1


@pytest.mark.parametrize(
    "change",
    [
        "missing_bid",
        "stale_side",
        "future_side",
        "stale_receipt",
        "future_receipt",
        "wrong_session",
    ],
)
def test_fixture_quote_fail_closed_boundaries(change):
    h = VenueHarness()
    h.accepted()
    at = h.state.as_of + timedelta(seconds=2)
    q = quote(at)
    if change == "missing_bid":
        q = quote(at, bid=None)
    elif change == "stale_side":
        q = quote(at, side_at=at - timedelta(seconds=5))
    elif change == "future_side":
        q = quote(at, side_at=at + timedelta(microseconds=1))
    elif change in ("stale_receipt", "future_receipt"):
        receipt = (
            at - timedelta(seconds=1)
            if change == "stale_receipt"
            else at + timedelta(microseconds=1)
        )
        q = replace(
            q,
            observation=replace(
                q.observation, availability=ModeledAvailability(receipt, "fixture")
            ),
        )
    else:
        q = replace(
            q,
            observation=replace(
                q.observation,
                payload=replace(q.observation.payload, session=(at + timedelta(days=1)).date()),
            ),
        )
    _, ack = h.command(q, at=at)
    assert ack.disposition in ("no_effect", "rejected") and ack.reasons
    assert not h.project().executions


def test_partial_then_cancel_and_delayed_delivery_preserves_true_sequence():
    h = VenueHarness()
    _, order = h.accepted()
    h.filled(budget="2")
    prefix = h.state
    snapshot = h.project().snapshot
    assert (snapshot.positions[0].quantity, snapshot.trade_date_cash, snapshot.trade_payable) == (
        2,
        D("799.5"),
        D("200.5"),
    )
    _, ack = h.command(VenueCancel(order, "owner-cancel"))
    assert ack.disposition == "applied"
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at, name="after-cancel"), at=at)
    assert ack.disposition == "no_effect"
    events = sorted(h.state.accounting.broker_events, key=lambda e: e.broker_sequence)
    assert [e.kind for e in events] == [
        BrokerOrderEventKind.ACCEPTED,
        BrokerOrderEventKind.EXECUTION,
        BrokerOrderEventKind.CANCELED,
    ]
    assert [e.broker_sequence for e in events] == [1, 2, 3]
    # Delivery reads a pinned old state after cancel; it does not reorder or erase
    # a fill which the independent venue had already committed.
    earlier = venue_fact_page(h.model, prefix, through_sequence=prefix.sequence)
    assert any(f.payload == events[1] for f in earlier.facts)
    assert h.project().snapshot.buy_reserve == 0 and h.project().snapshot.positions[0].quantity == 2


def test_liquidity_is_consumed_once_across_orders_and_observation_retry():
    h = VenueHarness(model("2000"))
    _, first_order = h.accepted(name="one")
    _, second_order = h.accepted(name="two")
    at = h.state.as_of + timedelta(seconds=1)
    payload = quote(at, budget="5")
    h.command(payload, at=at)
    assert {e.order_id: e.quantity for e in h.project().executions} == {
        first_order: D(4),
        second_order: D(1),
    }
    _, ack = h.command(payload, at=at)
    assert ack.disposition == "no_effect" and ack.reasons == ("VENUE_QUOTE_ALREADY_CONSUMED",)
    assert sum(e.quantity for e in h.project().executions) == 5


def test_hand_oracle_fees_partial_correction_bust_and_explicit_settlement():
    h = VenueHarness()
    h.accepted()
    p = h.filled()
    assert (
        p.snapshot.trade_date_cash,
        p.snapshot.settled_cash,
        p.snapshot.trade_payable,
        p.snapshot.fees,
    ) == (599, 1000, 401, 1)
    initial_entries = set(p.journal_entries)
    execution = p.executions[0].execution_id
    _, ack = h.command(VenueCorrect(execution, D(3), D(101), D(2), "explicit correction"))
    assert ack.disposition == "applied", ack.reasons
    p = h.project()
    assert (
        p.snapshot.trade_date_cash,
        p.snapshot.trade_payable,
        p.snapshot.trade_receivable,
        p.snapshot.fees,
    ) == (695, 401, 96, 2)
    assert initial_entries <= set(p.journal_entries)
    due = max(d.due_at for d in h.state.due_settlements)
    # Projection at a later receipt does not synthesize settlement.
    h.command(VenueRunDue(), at=h.state.as_of + timedelta(seconds=1))
    assert h.project().snapshot.settled_cash == 1000
    _, ack = h.command(VenueRunDue(), at=due + timedelta(hours=1))
    assert ack.disposition == "applied" and not h.state.due_settlements
    assert h.project().snapshot.settled_cash == 695
    assert all(
        c.settled_at == due + timedelta(hours=1)
        for c in h.state.accounting.settlement_confirmations
    )
    _, ack = h.command(VenueCorrect(execution, D(0), D(101), D(2), "bust keeps explicit fee"))
    assert ack.disposition == "applied", ack.reasons
    assert h.project().snapshot.trade_date_cash == 998 and h.project().snapshot.fees == 2
    assert (
        next(
            e for e in h.state.accounting.broker_events if e.kind is BrokerOrderEventKind.EXECUTION
        ).fee
        == 1
    )


def test_actual_correction_overshoot_books_and_halts_without_modeling_cash():
    h = VenueHarness()
    h.accepted()
    p = h.filled()
    _, ack = h.command(
        VenueCorrect(p.executions[0].execution_id, D(4), D(400), D(9), "source correction")
    )
    assert ack.disposition == "applied" and "NEGATIVE_CASH_CAPACITY" in ack.reasons
    p = h.project()
    assert p.snapshot.trade_date_cash == -609 and p.state.halted
    assert p.snapshot.settled_cash == 1000


def test_cash_and_supported_action_facts_use_canonical_ledger():
    h = VenueHarness()
    h.accepted()
    h.filled()
    at = h.state.as_of + timedelta(seconds=1)
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="1",
        source_sha256="a" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(4),
        effective_at=at,
        recorded_at=at,
    )
    _, ack = h.command(split, at=at)
    assert ack.disposition == "applied", ack.reasons
    assert h.project().snapshot.positions[0].quantity == 8
    at += timedelta(seconds=1)
    dividend = create_cash_dividend(
        source_action_id="dividend",
        source_revision_id="dividend-1",
        source_sha256="b" * 64,
        instrument_id="spy",
        symbol="SPY",
        currency="USD",
        amount_per_share=D(1),
        entitled_quantity=D(8),
        effective_at=at,
        payable_at=at + timedelta(days=1),
        recorded_at=at,
    )
    _, ack = h.command(dividend, at=at)
    assert ack.disposition == "applied", ack.reasons
    assert h.project().snapshot.dividend_receivable == 8
    payment = create_dividend_payment(
        dividend,
        paid_at=at + timedelta(days=1),
        recorded_at=at + timedelta(days=1),
        external_reference="payment",
    )
    _, ack = h.command(payment, at=at + timedelta(days=1))
    assert ack.disposition == "applied", ack.reasons
    assert (
        h.project().snapshot.dividend_income == 8 and h.project().snapshot.dividend_receivable == 0
    )


def test_unresolved_split_rejects_atomically_and_cancel_still_works():
    h = VenueHarness()
    _, order = h.accepted()
    h.filled(budget="2")
    at = h.state.as_of + timedelta(seconds=1)
    before = h.state.accounting
    split = create_stock_split(
        source_action_id="split",
        source_revision_id="1",
        source_sha256="a" * 64,
        instrument_id="spy",
        symbol="SPY",
        numerator=D(2),
        denominator=D(1),
        entitled_quantity=D(2),
        effective_at=at,
        recorded_at=at,
    )
    _, ack = h.command(split, at=at)
    assert ack.disposition == "rejected" and h.state.accounting == before
    _, ack = h.command(VenueCancel(order, "owner-cancel"))
    assert ack.disposition == "applied"


def test_missing_outbound_verifier_cannot_register_and_no_provider_permission_is_inferred():
    h = VenueHarness()
    outgoing = packet(h.model)
    _, ack = h.command(outgoing, at=outgoing.registration.submission.submitted_at, verifier=None)
    assert ack.reasons == ("VENUE_VERIFIED_OUTBOUND_PORT_REQUIRED",)
    assert not h.state.accounting.submissions
    assert h.model.live_authorized is False and h.model.runtime_environment == "stateful_simulation"


def test_recorded_quote_requires_verified_source_and_both_actual_side_times():
    source = ForwardSource(
        "etrade",
        "etrade",
        "production",
        "separate-provider-account-scope",
        "retained identity",
        "allowed",
        "retained rights",
        "realtime",
        "retained agreement",
    )
    m = model(sources=(source,), source_mode="recorded_as_observed")
    h = VenueHarness(m)

    # A test resolver only: this exercises pure admission, never provider access.
    class TestRecordedResolver:
        def verify_submission(self, model, submit, *, received_at):
            pass

        def verify_quote(self, model, source, observation):
            pass

    outgoing = packet(m)
    h.command(
        outgoing, at=outgoing.registration.submission.submitted_at, verifier=TestRecordedResolver()
    )
    h.command(VenueAccept(outgoing.registration.submission.order_id))
    at = h.state.as_of + timedelta(seconds=1)
    receipt = CaptureReceipt(
        "capture", source.semantic_sha256, "c" * 64, "d" * 64, 20, at, at, at, "boot", 100, 100, 100
    )
    q = ForwardQuote(
        "spy",
        "SPY",
        at.date(),
        D(99),
        D(100),
        at,
        "USD",
        "realtime",
        at,
        at,
        "documented_side_times",
    )
    observation = ForwardObservation("recorded", source.source_id, q, receipt, "recorded")
    _, ack = h.command(VenueQuote(observation, "boot", 100, D(4)), at=at, verifier=None)
    assert ack.reasons == ("VENUE_VERIFIED_SOURCE_PORT_REQUIRED",) and not h.project().executions
    at += timedelta(microseconds=1)
    old = replace(q, bid_at=at - timedelta(seconds=5), source_at=at)
    bad = replace(observation, observation_id="old-side", revision_key="old-side", payload=old)
    _, ack = h.command(VenueQuote(bad, "boot", 101, D(4)), at=at, verifier=TestRecordedResolver())
    assert "QUOTE_BID_TIME_STALE_OR_FUTURE" in ack.reasons and not h.project().executions
    good = replace(observation, observation_id="good", revision_key="good")
    _, ack = h.command(VenueQuote(good, "boot", 101, D(4)), at=at, verifier=TestRecordedResolver())
    assert ack.disposition == "applied", ack.reasons
    assert h.project().snapshot.trade_date_cash == 599
    before = h.state.accounting
    sentinel = "review-only-private-quote-resolver-diagnostic"

    class BrokenQuoteResolver(TestRecordedResolver):
        def verify_quote(self, model, source, observation):
            raise OSError(sentinel)

    fresh = replace(good, observation_id="private-error", revision_key="private-error")
    _, ack = h.command(VenueQuote(fresh, "boot", 101, D(4)), at=at, verifier=BrokenQuoteResolver())
    assert ack.reasons == ("VENUE_SOURCE_VERIFICATION_FAILED",)
    assert ack.disposition == "rejected" and h.state.accounting == before
    assert sentinel.encode() not in personal_codec.encode_record(h.state)


def test_decimal_arithmetic_is_independent_of_ambient_context():
    h = VenueHarness()
    h.accepted()
    with localcontext() as ctx:
        ctx.prec = 3
        ctx.traps[Inexact] = ctx.traps[Rounded] = True
        p = h.filled(ask="100.123456789")
    assert p.executions[0].price == D("100.123456789")
    assert p.snapshot.trade_date_cash == D("598.506172844")


def test_backward_command_time_and_fixed_page_bounds():
    h = VenueHarness()
    h.accepted()
    h.filled()
    with pytest.raises(VenueInputError, match="TIME_REGRESSION"):
        advance_stateful_venue(h.model, h.state, VenueCommand("backdated", BASE, VenueRunDue()))
    page = venue_fact_page(h.model, h.state, through_sequence=0, limit=1)
    assert page.complete and page.facts[0].sequence == 0
    with pytest.raises(VenueInputError, match="PAGE_BOUND"):
        venue_fact_page(h.model, h.state, through_sequence=h.state.sequence, limit=201)


def test_zero_cash_delta_correction_creates_no_spurious_settlement_obligation():
    h = VenueHarness()
    h.accepted()
    p = h.filled()
    before = h.state.due_settlements
    _, ack = h.command(
        VenueCorrect(p.executions[0].execution_id, D(4), D(100), D(1), "no monetary change")
    )
    assert ack.disposition == "applied", ack.reasons
    assert len(ack.canonical_fact_ids) == 1
    assert h.state.due_settlements == before
    assert h.project().snapshot.trade_payable == 401


def test_partial_downward_correction_does_not_automatically_rearm_order():
    h = VenueHarness()
    _, order = h.accepted()
    p = h.filled(budget="2")
    _, ack = h.command(
        VenueCorrect(p.executions[0].execution_id, D(1), D(100), D("0.5"), "partial correction")
    )
    assert ack.disposition == "applied", ack.reasons
    assert h.state.accounting.commitments[0].state == "unknown"
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at, name="after-correction"), at=at)
    assert ack.disposition == "no_effect" and h.project().snapshot.positions[0].quantity == 1
    _, ack = h.command(VenueCancel(order, "resolve unknown"))
    assert ack.disposition == "applied"
    assert h.project().snapshot.buy_reserve == 0


def test_same_submission_under_new_command_cannot_create_second_order():
    h = VenueHarness()
    original, _ = h.accepted()
    before = h.state.accounting
    _, ack = h.command(original.payload)
    assert ack.disposition == "rejected" and h.state.accounting == before
    assert len(h.state.accounting.submissions) == 1


def test_expired_order_has_no_autonomous_fill_or_expiry_and_explicit_cancel_still_works():
    h = VenueHarness()
    _, order = h.accepted()
    expiration = h.state.accounting.commitments[0].expires_at
    _, ack = h.command(quote(expiration, name="expired"), at=expiration)
    assert ack.disposition == "no_effect" and not h.project().executions
    assert h.state.accounting.commitments[0].state == "working"
    _, ack = h.command(VenueCancel(order, "explicit expiry observation"))
    assert ack.disposition == "applied" and h.project().snapshot.buy_reserve == 0


def test_quote_over_protection_price_never_spends_unapproved_venue_cash():
    h = VenueHarness()
    h.accepted(price="100")
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at, ask="101"), at=at)
    assert ack.disposition == "no_effect" and ack.reasons == (
        "VENUE_EXECUTION_CASH_OR_PRICE_BLOCKED",
    )
    assert not h.project().executions and h.project().snapshot.trade_date_cash == 1000


def test_quote_revision_gap_and_fork_cannot_produce_a_fill_or_reopen_consumed_quote():
    h = VenueHarness()
    h.accepted()
    at = h.state.as_of + timedelta(seconds=1)
    first = quote(at)
    child = replace(
        first.observation,
        observation_id="revision-two",
        revision=2,
        predecessor_id=first.observation.observation_id,
    )
    _, ack = h.command(replace(first, observation=child), at=at)
    assert ack.disposition == "no_effect" and "REVISION_GAP" in ack.reasons
    _, ack = h.command(first, at=at)
    assert ack.disposition == "no_effect" and "VENUE_QUOTE_SUPERSEDED" in ack.reasons
    _, ack = h.command(replace(first, observation=child), at=at)
    assert ack.disposition == "no_effect" and "VENUE_QUOTE_ALREADY_CONSUMED" in ack.reasons
    fork = replace(first.observation, observation_id="forked")
    _, ack = h.command(replace(first, observation=fork), at=at)
    assert ack.disposition == "rejected" and ack.reasons == ("VENUE_QUOTE_ADMISSION_REJECTED",)
    assert not h.project().executions


def test_newer_calendar_gap_cannot_publish_half_a_modeled_fill():
    short_policy = replace(
        VENUE_POLICY,
        settlement_calendar=replace(
            VENUE_POLICY.settlement_calendar,
            business_dates=VENUE_POLICY.settlement_calendar.business_dates[:1],
        ),
    )
    h = VenueHarness(model(execution_policy=short_policy))
    h.accepted()
    before = h.state.accounting
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at), at=at)
    assert ack.disposition == "rejected" and h.state.accounting == before
    assert h.project().snapshot.settled_cash == 1000 and not h.project().executions


def test_cash_withdrawal_checks_own_reserves_and_never_reads_source_account():
    h = VenueHarness()
    h.accepted()
    at = h.state.as_of + timedelta(seconds=1)
    flow = create_cash_flow(
        kind=CashFlowKind.WITHDRAWAL,
        currency="USD",
        amount=D(600),
        effective_at=at,
        recorded_at=at,
        external_reference="withdrawal",
    )
    before = h.state.accounting
    _, ack = h.command(flow, at=at)
    assert ack.disposition == "rejected" and h.state.accounting == before
    valid = replace(
        flow, cash_flow_id="safe-withdrawal", external_reference="safe-withdrawal", amount=D(100)
    )
    _, ack = h.command(valid)
    assert ack.disposition == "applied" and h.project().snapshot.trade_date_cash == 900


def test_sell_uses_bid_and_original_fee_lineage_for_fifo_profit():
    h = VenueHarness()
    h.accepted()
    h.filled()
    h.accepted(name="sell", price="110", side=Side.SELL)
    at = h.state.as_of + timedelta(seconds=1)
    _, ack = h.command(quote(at, name="sell-quote", bid="110", ask="111"), at=at)
    assert ack.disposition == "applied", ack.reasons
    p = h.project()
    assert p.snapshot.gross_realized_pnl == 40 and p.snapshot.fees == 2
    assert p.snapshot.trade_date_cash == 1038 and p.snapshot.market_value == 0
    assert len(p.fifo_matches) == 1
    match = p.fifo_matches[0]
    assert (match.quantity, match.basis, match.proceeds, match.opening_fee, match.closing_fee) == (
        4,
        400,
        440,
        1,
        1,
    )


@pytest.mark.parametrize("change", ["live", "mode", "policy", "duplicate_source", "universe"])
def test_model_cannot_claim_live_or_mix_unscoped_sources(change):
    m = model()
    with pytest.raises(ValueError):
        if change == "live":
            replace(m, live_authorized=True)
        elif change == "mode":
            replace(m, source_mode="recorded_as_observed")
        elif change == "policy":
            replace(m, execution_policy=POLICY)
        elif change == "duplicate_source":
            replace(m, sources=(FIXTURE, FIXTURE))
        else:
            replace(m, instruments=(("unlisted", "UNLISTED"),))


@pytest.mark.parametrize("exception", [ValueError, RuntimeError, OSError])
def test_outbound_resolver_exception_never_enters_retained_ack(exception):
    sentinel = "review-only-private-diagnostic-sentinel"

    class BrokenResolver:
        def verify_submission(self, *args, **kwargs):
            raise exception(sentinel)

    h = VenueHarness()
    outgoing = packet(h.model)
    before = h.state.accounting
    _, ack = h.command(
        outgoing, at=outgoing.registration.submission.submitted_at, verifier=BrokenResolver()
    )
    assert ack.disposition == "rejected"
    assert ack.reasons == ("VENUE_SOURCE_VERIFICATION_FAILED",)
    assert h.state.accounting == before
    assert sentinel.encode() not in personal_codec.encode_record(h.state)


@pytest.mark.parametrize("behavior", ["raise", "rejected", "applied"])
def test_injected_accounting_diagnostics_are_static_and_bounded(behavior):
    from packages.backtest.personal_accounting import PersonalAccounting

    sentinel = "review-only-private-accounting-diagnostic"

    class DiagnosticAccounting(PersonalAccounting):
        def advance(self, **kwargs):
            if behavior == "raise":
                raise ValueError(sentinel)
            result = super().advance(**kwargs)
            return replace(result, disposition=behavior, reasons=(sentinel,))

    h = VenueHarness()
    outgoing = packet(h.model)
    command = VenueCommand("diagnostic", outgoing.registration.submission.submitted_at, outgoing)
    result = advance_stateful_venue(
        h.model,
        h.state,
        command,
        verified_sources=FIXTURE_VERIFIER,
        accounting=DiagnosticAccounting(),
    )
    expected = {
        "raise": "VENUE_COMMAND_REJECTED",
        "rejected": "VENUE_ACCOUNTING_REJECTED",
        "applied": "VENUE_ACCOUNTING_DIAGNOSTIC_UNAVAILABLE",
    }[behavior]
    assert result.acknowledgment.reasons == (expected,)
    assert sentinel.encode() not in personal_codec.encode_record(result.state)
    if behavior != "applied":
        assert result.state.accounting == h.state.accounting
