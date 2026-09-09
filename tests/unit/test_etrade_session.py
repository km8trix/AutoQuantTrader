from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from packages.adapters.broker.etrade import EtradeAccountIdKey, EtradeEnvironment
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeReadCredentials,
    EtradeReadError,
    EtradeReadOperation,
    EtradeReadRequest,
    EtradeReadResponse,
    EtradeSecretReference,
    sign_account_get,
)
from packages.application.etrade_session import (
    FINANCING_POLICY_ID,
    EtradeCaptureBounds,
    EtradePageEvidence,
    EtradeReadOnlySession,
    PrivateDirectoryEtradeJournal,
)
from scripts.qualify_etrade_readonly import main

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/broker/etrade_readonly/account_round.json"
NOW = datetime(2026, 9, 9, 14, tzinfo=UTC)
REFERENCE = EtradeSecretReference(EtradeEnvironment.SANDBOX, "envfile:///fixture-only?version=1")
BOUNDS = EtradeCaptureBounds(date(2026, 9, 1), date(2026, 9, 8))


def values(**overrides: str) -> dict[str, str]:
    return {
        "consumer_key": "mechanical-consumer",
        "consumer_secret": "mechanical-secret",
        "access_token": "mechanical-token",
        "access_secret": "mechanical-access-secret",
        "issued_at": "2026-09-09T13:00:00Z",
        "last_activity_at": "2026-09-09T13:59:00Z",
        "expires_at": "2026-09-10T04:00:00Z",
        **overrides,
    }


class Clock:
    def __init__(self) -> None:
        self.instant = NOW
        self.elapsed = 100.0

    def now(self) -> datetime:
        return self.instant

    def monotonic(self) -> float:
        return self.elapsed

    def advance(self, seconds: float) -> None:
        self.instant += timedelta(seconds=seconds)
        self.elapsed += seconds


class Store:
    def __init__(self) -> None:
        self.data = values()
        self.count = 0
        self.return_reference = REFERENCE
        self.resolved: list[EtradeReadCredentials] = []

    def resolve(self, reference: EtradeSecretReference) -> EtradeReadCredentials:
        assert reference == REFERENCE
        self.count += 1
        credentials = EtradeReadCredentials(self.return_reference, self.data)
        self.resolved.append(credentials)
        return credentials


class Journal:
    def __init__(self) -> None:
        self.pages: list[tuple[EtradePageEvidence, bytes | None]] = []

    def append(self, evidence: EtradePageEvidence, body: bytes | None) -> None:
        self.pages.append((evidence, body))


class Transport:
    evidence_class = "mechanical_fixture_not_provider_evidence"

    def __init__(self) -> None:
        self.payloads = json.loads(FIXTURE.read_text())
        self.requests: list[EtradeReadRequest] = []
        self.status = 200
        self.wrong_request = False
        self.raw_body: bytes | None = None
        self.on_get: Any = None
        self.queue: dict[str, list[dict[str, Any]]] = {}

    def get(
        self, request: EtradeReadRequest, *, authorization: str, deadline_seconds: float
    ) -> EtradeReadResponse:
        assert authorization.startswith("OAuth ")
        assert 0 < deadline_seconds <= 3
        self.requests.append(request)
        if self.on_get is not None:
            self.on_get()
        queued = self.queue.get(request.operation.value, [])
        payload = queued.pop(0) if queued else self.payloads[request.operation.value]
        body = self.raw_body if self.raw_body is not None else json.dumps(payload).encode()
        return EtradeReadResponse(
            "wrong" if self.wrong_request else request.digest, self.status, body
        )


def setup() -> tuple[EtradeReadOnlySession, Clock, Store, Transport, Journal]:
    clock, store, transport, journal = Clock(), Store(), Transport(), Journal()
    counter = iter(range(1000))
    session = EtradeReadOnlySession(
        reference=REFERENCE,
        store=store,
        transport=transport,
        journal=journal,
        clock=clock,
        monotonic=clock.monotonic,
        nonce=lambda: f"mechanical-nonce-{next(counter):016d}",
    )
    return session, clock, store, transport, journal


def selected() -> tuple[EtradeReadOnlySession, Clock, Store, Transport, Journal]:
    result = setup()
    session = result[0]
    account = session.discover_accounts()[0]
    session.select_account(account.fingerprint, owner_declared_exclusive=True)
    return result


def test_complete_fixture_round_keeps_cash_views_distinct_and_reports_limits() -> None:
    session, _, store, transport, journal = selected()
    capture = session.capture_account(BOUNDS)
    assert capture.traversal_complete
    assert capture.observations["balances"]["settledCashForInvestment"] == Decimal("8500.01")
    assert capture.observations["balances"]["cashBuyingPower"] == Decimal("9000")
    assert len(capture.pages) == 5
    assert len(journal.pages) == 6
    assert transport.requests[3].query == (("count", "50"),)
    assert "fromDate" in dict(transport.requests[4].query)
    assert "SINGLE_OBSERVATION_ROUND_NOT_RECONCILIATION" in capture.blockers
    assert "ACTIVITY_EXECUTION_CORRECTION_IDENTITY_UNQUALIFIED" in capture.blockers
    assert "SANDBOX_STORED_EXAMPLES_NOT_ACCOUNT_ECONOMICS" in capture.blockers
    portable = json.dumps(capture.portable())
    for private in (
        "00123456",
        "MechanicalKeyA_01",
        "8500.01",
        "mechanical-token",
        "Authorization",
    ):
        assert private not in portable
        assert private not in repr(capture)
    assert not capture.portable()["trading_authorized"]
    assert all(not credentials._values for credentials in store.resolved)


def test_discovery_requires_explicit_account_and_cash_exclusive_declaration() -> None:
    session, *_ = setup()
    accounts = session.discover_accounts()
    with pytest.raises(EtradeReadError, match="EXPLICIT_ACCOUNT_SELECTION_REQUIRED"):
        session.capture_account(BOUNDS)
    with pytest.raises(EtradeReadError, match="EXPLICIT_DISCOVERED_ACCOUNT_REQUIRED"):
        session.select_account("", owner_declared_exclusive=True)
    with pytest.raises(EtradeReadError, match="ACTIVE_BROKERAGE_CASH_ACCOUNT_REQUIRED"):
        session.select_account(accounts[1].fingerprint, owner_declared_exclusive=True)
    with pytest.raises(EtradeReadError, match="OWNER_EXCLUSIVITY_DECLARATION_REQUIRED"):
        session.select_account(accounts[0].fingerprint, owner_declared_exclusive=False)
    binding = session.select_account(accounts[0].fingerprint, owner_declared_exclusive=True)
    assert binding.owner_declared_exclusive
    assert not accounts[0].identifiers.account_binding_authorized


@pytest.mark.parametrize(
    "discovery_mode,balance_mode",
    [("CASH", "CASH"), ("CASH", "MARGIN"), ("MARGIN", "CASH"), ("MARGIN", "MARGIN")],
)
def test_explicit_margin_profile_preserves_modes_policy_and_zero_authority(
    discovery_mode: str, balance_mode: str
) -> None:
    session, _, _, transport, _ = setup()
    transport.payloads["accounts"]["AccountListResponse"]["Accounts"]["Account"][0][
        "accountMode"
    ] = discovery_mode
    transport.payloads["balances"]["BalanceResponse"]["accountMode"] = balance_mode
    account = session.discover_accounts()[0]
    binding = session.select_account(
        account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
    )
    capture = session.capture_account(BOUNDS)
    assert capture.traversal_complete and len(capture.pages) == 5
    expected_modes = {"discovery": discovery_mode, "balance": balance_mode}
    assert capture.observations["account_modes"] == expected_modes
    public = capture.portable()
    assert public["contract"] == "personal-v1-etrade-read-session/2"
    assert public["account_modes"] == expected_modes
    assert public["allow_margin_privileges"] is True
    assert public["read_profile"] == "cash_funded_cash_or_margin_privileges"
    assert (
        public["financing_policy_id"]
        == binding.financing_policy_id
        == FINANCING_POLICY_ID
        == "cash-funded-long-only/1"
    )
    assert ("ACCOUNT_MODE_DISAGREEMENT" in capture.blockers) == (discovery_mode != balance_mode)
    for flag in (
        "trading_authorized",
        "borrowing_authorized",
        "shorting_authorized",
        "cash_funding_qualified",
        "reconciliation_qualified",
        "canonical_facts_published",
    ):
        assert public[flag] is False
    if "MARGIN" in expected_modes.values():
        assert "MARGIN_LIABILITY_AND_CASH_FUNDING_UNQUALIFIED" in capture.blockers
        assert "MARGIN_CALLS_AND_RESTRICTIONS_UNQUALIFIED" in capture.blockers
    assert not account.identifiers.account_binding_authorized
    assert "MechanicalKey" not in json.dumps(public)


def test_opt_in_and_versioned_financing_policy_are_bound_to_selection() -> None:
    session, *_ = setup()
    account = session.discover_accounts()[0]
    original = session.select_account(account.fingerprint, owner_declared_exclusive=True)
    opted_in = session.select_account(
        account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
    )
    assert original.digest != opted_in.digest
    assert original.read_profile == "cash_only" and original.allow_margin_privileges is False
    assert original.financing_policy_id == opted_in.financing_policy_id == FINANCING_POLICY_ID


@pytest.mark.parametrize("value", [None, 1, 0, "true", "false", [], {}])
def test_nonboolean_opt_in_fails_and_clears_existing_binding(value: Any) -> None:
    session, *_ = setup()
    account = session.discover_accounts()[0]
    session.select_account(
        account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
    )
    with pytest.raises(EtradeReadError, match="OPT_IN_MUST_BE_BOOLEAN"):
        session.select_account(
            account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=value
        )
    with pytest.raises(EtradeReadError, match="EXPLICIT_ACCOUNT_SELECTION_REQUIRED"):
        session.capture_account(BOUNDS)


@pytest.mark.parametrize(
    "field,value",
    [
        ("accountMode", None),
        ("accountMode", "UNKNOWN"),
        ("accountMode", "PDT ACCOUNT"),
        ("accountMode", "margin"),
        ("accountStatus", "CLOSED"),
        ("institutionType", "STOCKPLAN"),
    ],
)
def test_opt_in_cannot_admit_unknown_modes_closed_or_nonbrokerage_accounts(
    field: str, value: Any
) -> None:
    session, _, _, transport, _ = setup()
    row = transport.payloads["accounts"]["AccountListResponse"]["Accounts"]["Account"][0]
    if value is None:
        row.pop(field)
    else:
        row[field] = value
    account = session.discover_accounts()[0]
    with pytest.raises(EtradeReadError, match="ACTIVE_BROKERAGE_CASH_OR_MARGIN_ACCOUNT_REQUIRED"):
        session.select_account(
            account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
        )
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "field,value,blocker",
    [
        ("accountMode", None, "BALANCE_CASH_OR_MARGIN_MODE_UNQUALIFIED"),
        ("accountMode", "PDT ACCOUNT", "BALANCE_CASH_OR_MARGIN_MODE_UNQUALIFIED"),
        ("accountId", "999", "RESPONSE_ACCOUNT_IDENTITY_MISMATCH"),
        ("currency", "EUR", "NON_USD_ACCOUNT_UNSUPPORTED"),
    ],
)
def test_opted_in_capture_still_rejects_missing_modes_identity_and_foreign_currency(
    field: str, value: Any, blocker: str
) -> None:
    session, _, _, transport, _ = setup()
    account = session.discover_accounts()[0]
    session.select_account(
        account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
    )
    balance = transport.payloads["balances"]["BalanceResponse"]
    if value is None:
        balance.pop(field)
    else:
        balance[field] = value
    capture = session.capture_account(BOUNDS)
    assert not capture.traversal_complete and capture.observations == {}
    assert blocker in capture.blockers
    assert len(transport.requests) == 2


def test_margin_opt_in_keeps_exclusivity_and_known_foreign_currency_checks() -> None:
    session, _, _, transport, _ = setup()
    account = session.discover_accounts()[0]
    with pytest.raises(EtradeReadError, match="OWNER_EXCLUSIVITY_DECLARATION_REQUIRED"):
        session.select_account(
            account.fingerprint, owner_declared_exclusive=False, allow_margin_privileges=True
        )
    transport.payloads["accounts"]["AccountListResponse"]["Accounts"]["Account"][0]["currency"] = (
        "EUR"
    )
    account = session.discover_accounts()[0]
    assert transport.payloads["balances"]["BalanceResponse"]["currency"] == "USD"
    with pytest.raises(EtradeReadError, match="NON_USD_ACCOUNT_UNSUPPORTED"):
        session.select_account(
            account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
        )
    assert all(request.operation is EtradeReadOperation.ACCOUNTS for request in transport.requests)


@pytest.mark.parametrize("reported_margin", [None, 0, "125.25", "-125.25"])
def test_margin_observations_preserve_sign_missing_fields_calls_and_cash_separation(
    reported_margin: Any,
) -> None:
    session, _, _, transport, _ = setup()
    row = transport.payloads["accounts"]["AccountListResponse"]["Accounts"]["Account"][0]
    row.update(accountMode="MARGIN")
    row.pop("currency")
    balance = transport.payloads["balances"]["BalanceResponse"]
    balance.update(
        accountMode="MARGIN", accountType="MARGIN", dayTraderStatus="FIXTURE_STATUS", quoteMode=1
    )
    balance.pop("currency")
    computed = balance["Computed"]
    computed.pop("settledCashForInvestment")
    computed.update(
        marginBalance=reported_margin,
        marginBuyingPower="999999",
        dtMarginBuyingPower="1999998",
        dtCashBuyingPower="2500",
        shortAdjustBalance="-10.05",
        OpenCalls={"cashCall": "12.50", "houseCall": "25.00"},
    )
    balance["Cash"] = {"fundsForOpenOrdersCash": "123", "moneyMktBalance": "456"}
    account = session.discover_accounts()[0]
    session.select_account(
        account.fingerprint, owner_declared_exclusive=True, allow_margin_privileges=True
    )
    capture = session.capture_account(BOUNDS)
    assert capture.traversal_complete
    assert capture.observations["balances"]["settledCashForInvestment"] is None
    assert capture.observations["balances"]["cashBuyingPower"] == Decimal("9000")
    margin = capture.observations["margin"]
    assert margin["Computed"]["marginBuyingPower"] == Decimal("999999")
    assert margin["Computed"]["marginBalance"] == (
        None if reported_margin is None else Decimal(reported_margin)
    )
    assert margin["Computed"]["shortAdjustBalance"] == Decimal("-10.05")
    assert margin["BalanceResponse"]["Margin"] is None
    assert margin["BalanceResponse"]["Cash"] == balance["Cash"]
    assert margin["BalanceResponse"]["dayTraderStatus"] == "FIXTURE_STATUS"
    assert margin["ComputedOpenCalls"]["OpenCalls"] == computed["OpenCalls"]
    assert "SETTLED_CASH_FIELD_UNAVAILABLE" in capture.blockers
    assert "ACCOUNT_CURRENCY_NOT_PROVEN_BY_RESPONSE" in capture.blockers
    assert "MARGIN_LIABILITY_AND_CASH_FUNDING_UNQUALIFIED" in capture.blockers
    assert ("MARGIN_BALANCE_FIELD_UNAVAILABLE" in capture.blockers) == (reported_margin is None)
    assert ("NONZERO_REPORTED_MARGIN_BALANCE_UNQUALIFIED" in capture.blockers) == (
        reported_margin not in (None, 0)
    )
    assert capture.portable()["cash_funding_qualified"] is False
    assert "999999" not in json.dumps(capture.portable())


@pytest.mark.parametrize("action", ["--inspect-reference", "--authorize-read"])
def test_cli_margin_flag_requires_account_capture_before_secret_or_journal_effects(
    tmp_path: Path, monkeypatch: Any, capsys: Any, action: str
) -> None:
    import scripts.qualify_etrade_readonly as cli

    monkeypatch.setattr(
        cli.EnvFileEtradeCredentialStore,
        "inspect",
        lambda *args: pytest.fail("unexpected secret read"),
    )
    monkeypatch.setattr(
        cli, "PrivateDirectoryEtradeJournal", lambda *args: pytest.fail("unexpected journal")
    )
    assert (
        main(
            [
                "--environment",
                "sandbox",
                "--secret-reference",
                REFERENCE.uri,
                action,
                "--allow-margin-privileges",
                "--private-output-dir",
                str(tmp_path / "never-created"),
            ]
        )
        == 2
    )
    assert "MARGIN_PRIVILEGES_OPT_IN_REQUIRES_ACCOUNT_CAPTURE" in capsys.readouterr().out


def test_cli_passes_explicit_margin_profile_to_bounded_capture(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    import scripts.qualify_etrade_readonly as cli

    session, _, _, transport, _ = setup()
    transport.payloads["accounts"]["AccountListResponse"]["Accounts"]["Account"][0][
        "accountMode"
    ] = "MARGIN"
    transport.payloads["balances"]["BalanceResponse"]["accountMode"] = "MARGIN"
    account = session.discover_accounts()[0]
    monkeypatch.setattr(cli, "EtradeReadOnlySession", lambda **kwargs: session)
    monkeypatch.setattr(cli, "PrivateDirectoryEtradeJournal", lambda *args: Journal())
    monkeypatch.setattr(cli, "SystemClock", Clock)
    assert (
        main(
            [
                "--environment",
                "sandbox",
                "--secret-reference",
                REFERENCE.uri,
                "--authorize-read",
                "--account-fingerprint",
                account.fingerprint,
                "--declare-exclusive",
                "--allow-margin-privileges",
                "--start-date",
                "2026-09-01",
                "--end-date",
                "2026-09-08",
                "--private-output-dir",
                str(tmp_path / "fixture-capture"),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["allow_margin_privileges"] is True
    assert result["traversal_complete"] is True and result["trading_authorized"] is False


@pytest.mark.parametrize(
    "overrides,error",
    [
        (
            {"last_activity_at": "2026-09-09T12:00:00Z", "issued_at": "2026-09-09T11:00:00Z"},
            "TOKEN_INACTIVE",
        ),
        ({"expires_at": "2026-09-09T14:00:00Z"}, "DAILY_REAUTHORIZATION"),
        (
            {"issued_at": "2026-09-09T14:01:00Z", "last_activity_at": "2026-09-09T14:01:00Z"},
            "TOKEN_TIME_METADATA_FUTURE",
        ),
    ],
)
def test_token_lifecycle_blocks_before_transport(overrides: dict[str, str], error: str) -> None:
    session, _, store, transport, journal = setup()
    store.data.update(overrides)
    with pytest.raises(EtradeReadError, match=error):
        session.discover_accounts()
    assert transport.requests == []
    assert len(journal.pages) == 1
    assert journal.pages[0][1] is None


@pytest.mark.parametrize(
    "at", [datetime(2026, 9, 10, 4, tzinfo=UTC), datetime(2026, 11, 2, 5, tzinfo=UTC)]
)
def test_eastern_midnight_expiry_overrides_later_claimed_expiry(at: datetime) -> None:
    session, clock, store, transport, _ = setup()
    clock.instant = at
    store.data = values(
        issued_at=(at - timedelta(hours=1)).isoformat(),
        last_activity_at=(at - timedelta(minutes=1)).isoformat(),
        expires_at=(at + timedelta(hours=5)).isoformat(),
    )
    with pytest.raises(EtradeReadError, match="DAILY_REAUTHORIZATION"):
        session.discover_accounts()
    assert transport.requests == []


def test_wrong_environment_reference_and_rotated_session_fail_closed() -> None:
    session, _, store, transport, _ = setup()
    store.return_reference = EtradeSecretReference(
        EtradeEnvironment.PRODUCTION, "envfile:///fixture-only?version=1"
    )
    with pytest.raises(EtradeReadError, match="SECRET_REFERENCE_MISMATCH"):
        session.discover_accounts()
    assert not transport.requests
    session, _, store, _, _ = selected()
    store.data["issued_at"] = "2026-09-09T13:30:00Z"
    capture = session.capture_account(BOUNDS)
    assert not capture.traversal_complete
    assert "SESSION_TOKEN_CHANGED_REDISCOVERY_REQUIRED" in capture.blockers


@pytest.mark.parametrize(
    "status,error",
    [
        (401, "AUTHENTICATION_REJECTED"),
        (403, "AUTHENTICATION_REJECTED"),
        (429, "PROVIDER_THROTTLED"),
        (503, "READ_HTTP_FAILED"),
        (302, "READ_HTTP_FAILED"),
    ],
)
def test_http_failures_are_not_retried_and_never_journal_error_bodies(
    status: int, error: str
) -> None:
    session, _, _, transport, journal = setup()
    transport.status = status
    transport.raw_body = b"private diagnostic with OAuth token"
    with pytest.raises(EtradeReadError, match=error):
        session.discover_accounts()
    assert len(transport.requests) == 1
    assert journal.pages[0][1] is None
    assert journal.pages[0][0].body_digest is None


@pytest.mark.parametrize(
    "body", [b'{"x":1,"x":2}', b'{"oauth_token":"never-journal"}', b'{"amount":NaN}', b"not-json"]
)
def test_malformed_or_secret_like_response_never_journaled(body: bytes) -> None:
    session, _, _, transport, journal = setup()
    transport.raw_body = body
    with pytest.raises(EtradeReadError):
        session.discover_accounts()
    assert journal.pages[0][1] is None


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda t: t.payloads["balances"]["BalanceResponse"].update(accountId="999"),
            "RESPONSE_ACCOUNT_IDENTITY_MISMATCH",
        ),
        (
            lambda t: t.payloads["balances"]["BalanceResponse"].update(accountMode="MARGIN"),
            "BALANCE_CASH_MODE_UNQUALIFIED",
        ),
        (
            lambda t: t.payloads["balances"]["BalanceResponse"].update(currency="EUR"),
            "NON_USD_ACCOUNT_UNSUPPORTED",
        ),
        (
            lambda t: t.payloads["portfolio"]["PortfolioResponse"]["AccountPortfolio"][0].pop(
                "totalNoOfPages"
            ),
            "PORTFOLIO_PAGE_COVERAGE_UNAVAILABLE",
        ),
        (
            lambda t: t.payloads["orders"]["OrdersResponse"].pop("marker"),
            "TERMINAL_MARKER_EVIDENCE_MISSING",
        ),
        (
            lambda t: t.payloads["activity"]["TransactionListResponse"].update(transactionCount=9),
            "ACTIVITY_COUNT_MISMATCH",
        ),
    ],
)
def test_account_and_coverage_failures_discard_combined_observation(
    mutation: Any, reason: str
) -> None:
    session, _, _, transport, journal = selected()
    mutation(transport)
    capture = session.capture_account(BOUNDS)
    assert not capture.traversal_complete
    assert capture.observations == {}
    assert reason in capture.blockers
    assert len(journal.pages) >= 2


def test_missing_cash_and_usd_are_unavailable_not_zero() -> None:
    session, _, _, transport, _ = selected()
    transport.payloads["balances"]["BalanceResponse"]["Computed"].pop("settledCashForInvestment")
    transport.payloads["balances"]["BalanceResponse"].pop("currency")
    capture = session.capture_account(BOUNDS)
    assert capture.traversal_complete
    assert capture.observations["balances"]["settledCashForInvestment"] is None
    assert "SETTLED_CASH_FIELD_UNAVAILABLE" in capture.blockers


def test_multi_page_portfolio_and_order_traversal_retains_exact_bounds() -> None:
    session, _, _, transport, _ = selected()
    first = copy.deepcopy(transport.payloads["portfolio"])
    first["PortfolioResponse"]["AccountPortfolio"][0].update(totalNoOfPages=2, nextPageNo="2")
    second = copy.deepcopy(first)
    second["PortfolioResponse"]["AccountPortfolio"][0].update(nextPageNo="0")
    second["PortfolioResponse"]["AccountPortfolio"][0]["Position"][0]["positionId"] = 1002
    transport.queue["portfolio"] = [first, second]
    orders1 = {"OrdersResponse": {"marker": "next-marker", "Order": [{"orderId": 8000}]}}
    orders2 = {"OrdersResponse": {"marker": "", "Order": [{"orderId": 8001}]}}
    transport.queue["orders"] = [orders1, orders2]
    capture = session.capture_account(BOUNDS)
    assert capture.traversal_complete
    assert len(capture.observations["portfolio"]) == 2
    assert len(capture.observations["orders_current"]) == 2
    assert any(dict(page.query).get("marker") == "next-marker" for page in capture.pages)
    assert "next-marker" not in json.dumps(capture.portable())


@pytest.mark.parametrize("page,body", [(1, b""), (2, b""), (1, b"unexpected-body")])
def test_documented_portfolio_204_is_initial_no_content_only(
    monkeypatch: Any, page: int, body: bytes
) -> None:
    session, _, _, transport, journal = selected()
    if page == 2:
        group = transport.payloads["portfolio"]["PortfolioResponse"]["AccountPortfolio"][0]
        group.update(totalNoOfPages=2, nextPageNo="2")
    original = transport.get

    def get(request: EtradeReadRequest, **kwargs: Any) -> EtradeReadResponse:
        response = original(request, **kwargs)
        if request.operation is EtradeReadOperation.PORTFOLIO and dict(request.query)[
            "pageNumber"
        ] == str(page):
            return replace(response, status=204, body=body)
        return response

    monkeypatch.setattr(transport, "get", get)
    capture = session.capture_account(BOUNDS)
    if page == 1 and not body:
        assert capture.traversal_complete
        assert capture.observations["portfolio"] == []
        assert (
            dict(capture.terminal_evidence)["portfolio"]
            == "documented_initial_portfolio_no_content"
        )
        assert "PORTFOLIO_NO_CONTENT_NOT_RECONCILED_POSITION_ABSENCE" in capture.blockers
        assert capture.portable()["reconciliation_qualified"] is False
        assert capture.portable()["canonical_facts_published"] is False
        portfolio_page = next(item for item in journal.pages if item[0].operation == "portfolio")
        assert portfolio_page[0].status == 204 and portfolio_page[1] == b""
        assert [request.operation for request in transport.requests][
            -1
        ] is EtradeReadOperation.ACTIVITY
    else:
        assert not capture.traversal_complete and capture.observations == {}
        expected = (
            "UNDOCUMENTED_EMPTY_RESPONSE"
            if body
            else "PORTFOLIO_NO_CONTENT_AFTER_PAGINATION_PROMISE"
        )
        assert expected in capture.blockers
        assert all(
            request.operation not in (EtradeReadOperation.ORDERS, EtradeReadOperation.ACTIVITY)
            for request in transport.requests
        )
        if page == 2:
            assert any(
                evidence.status == 200 and evidence.operation == "portfolio"
                for evidence, _ in journal.pages
            )


@pytest.mark.parametrize(
    "operation",
    [
        EtradeReadOperation.ACCOUNTS,
        EtradeReadOperation.BALANCES,
        EtradeReadOperation.ACTIVITY,
    ],
)
def test_portfolio_204_change_keeps_other_operation_handling(
    operation: EtradeReadOperation,
) -> None:
    session, _, _, transport, _ = selected()
    transport.status, transport.raw_body = 204, b""
    request = (
        EtradeReadRequest(REFERENCE.environment, operation)
        if operation is EtradeReadOperation.ACCOUNTS
        else session._request(
            operation,
            {"instType": "BROKERAGE", "realTimeNAV": "true"}
            if operation is EtradeReadOperation.BALANCES
            else {},
        )
    )
    if operation is EtradeReadOperation.ACTIVITY:
        assert session._get(request) == {
            "TransactionListResponse": {"Transaction": [], "transactionCount": 0}
        }
    else:
        with pytest.raises(EtradeReadError, match="UNDOCUMENTED_EMPTY_RESPONSE"):
            session._get(request)


@pytest.mark.parametrize("scope", ["current", "history", "both"])
@pytest.mark.parametrize("page,body", [(1, b""), (2, b""), (1, b"unexpected-body")])
def test_initial_order_api_204_is_query_scoped_and_not_reconciled_absence(
    monkeypatch: Any, scope: str, page: int, body: bytes
) -> None:
    session, _, _, transport, journal = selected()
    original = transport.get

    def get(request: EtradeReadRequest, **kwargs: Any) -> EtradeReadResponse:
        response = original(request, **kwargs)
        query = dict(request.query)
        selected_scope = scope == "both" or (("fromDate" in query) == (scope == "history"))
        if request.operation is EtradeReadOperation.ORDERS and selected_scope:
            if page == 2 and "marker" not in query:
                return replace(
                    response,
                    body=b'{"OrdersResponse":{"marker":"fixture-next","Order":[{"orderId":807}]}}',
                )
            return replace(response, status=204, body=body)
        return response

    monkeypatch.setattr(transport, "get", get)
    capture = session.capture_account(BOUNDS)
    if page == 1 and not body:
        assert capture.traversal_complete
        terminals = dict(capture.terminal_evidence)
        for name in ("current", "history"):
            if scope in (name, "both"):
                assert capture.observations["orders_" + name] == []
                assert terminals["orders_" + name] == "documented_order_api_initial_no_content"
        assert "ORDERS_NO_CONTENT_NOT_RECONCILED_ORDER_ABSENCE" in capture.blockers
        assert "LIST_ORDERS_204_RESPONSE_TABLE_AMBIGUITY" in capture.blockers
        empty_pages = [
            (evidence, raw)
            for evidence, raw in journal.pages
            if evidence.operation == "orders" and evidence.status == 204
        ]
        assert len(empty_pages) == (2 if scope == "both" else 1)
        assert all(raw == b"" and evidence.error is None for evidence, raw in empty_pages)
        assert all("marker" not in dict(evidence.query) for evidence, _ in empty_pages)
        if scope in ("history", "both"):
            history = [
                evidence for evidence, _ in empty_pages if "fromDate" in dict(evidence.query)
            ]
            assert dict(history[0].query)["fromDate"] == "09012026"
            assert dict(history[0].query)["toDate"] == "09082026"
        assert transport.requests[-1].operation is EtradeReadOperation.ACTIVITY
        assert capture.portable()["reconciliation_qualified"] is False
        assert capture.portable()["trading_authorized"] is False
    else:
        assert not capture.traversal_complete and capture.observations == {}
        expected = (
            "UNDOCUMENTED_EMPTY_RESPONSE"
            if body
            else "ORDERS_NO_CONTENT_AFTER_CONTINUATION_PROMISE"
        )
        assert expected in capture.blockers
        assert all(
            request.operation is not EtradeReadOperation.ACTIVITY for request in transport.requests
        )
        if page == 2:
            assert any(
                dict(request.query).get("marker") == "fixture-next"
                for request in transport.requests
            )


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("cycle", "PAGINATION_CURSOR_LOOP"),
        ("duplicate", "DUPLICATE_OR_CONFLICTING_PAGE_IDENTITY"),
        ("host", "CONTINUATION_SCOPE_MISMATCH"),
        ("query", "CONTINUATION_QUERY_MISMATCH"),
    ],
)
def test_cursor_cycles_duplicate_ids_and_scope_drift_fail(mode: str, reason: str) -> None:
    session, _, _, transport, _ = selected()
    first: dict[str, Any] = {"OrdersResponse": {"marker": "cursor-1", "Order": [{"orderId": 9000}]}}
    second: dict[str, Any] = {
        "OrdersResponse": {"marker": "cursor-2", "Order": [{"orderId": 9001}]}
    }
    if mode == "cycle":
        second["OrdersResponse"]["marker"] = "cursor-1"
    elif mode == "duplicate":
        second["OrdersResponse"]["Order"][0]["orderId"] = 9000
    else:
        origin = "https://evil.invalid" if mode == "host" else "https://apisb.etrade.com"
        second["OrdersResponse"]["next"] = (
            origin + "/v1/accounts/MechanicalKeyA_01/orders?marker=cursor-2&status=OPEN"
        )
    transport.queue["orders"] = [first, second]
    capture = session.capture_account(BOUNDS)
    assert not capture.traversal_complete
    assert reason in capture.blockers
    assert capture.observations == {}


def test_full_activity_page_requires_followup_even_if_more_false() -> None:
    session, _, _, transport, _ = selected()
    first = copy.deepcopy(transport.payloads["activity"])
    first["TransactionListResponse"].update(marker="next-transaction", moreTransactions=False)
    second = {"TransactionListResponse": {"Transaction": [], "transactionCount": 0}}
    transport.queue["activity"] = [first, second]
    capture = session.capture_account(replace(BOUNDS, page_size=1))
    assert capture.traversal_complete
    assert len([page for page in capture.pages if page.operation == "activity"]) == 2


def test_unknown_activity_truncation_is_not_empty_terminal() -> None:
    session, _, _, transport, _ = selected()
    transport.payloads["activity"]["TransactionListResponse"].update(moreTransactions=True)
    capture = session.capture_account(BOUNDS)
    assert "ACTIVITY_TERMINAL_CONFLICT" in capture.blockers
    assert not capture.traversal_complete


def test_time_regression_suspend_gap_and_deadline_stop_capture() -> None:
    for mode in ("utc", "mono", "suspend", "deadline"):
        session, clock, _, transport, _ = selected()
        if mode == "utc":
            clock.instant -= timedelta(seconds=1)
        elif mode == "mono":
            clock.elapsed -= 1
        elif mode == "suspend":
            clock.instant += timedelta(seconds=5)
        else:
            transport.on_get = lambda clock=clock: clock.advance(3)
        if mode != "deadline":
            with pytest.raises(EtradeReadError, match="SESSION_CLOCK_DISCONTINUITY"):
                session.capture_account(BOUNDS)
        else:
            capture = session.capture_account(BOUNDS)
            assert "READ_DEADLINE_EXCEEDED" in capture.blockers
            assert not capture.traversal_complete


def test_nonce_reuse_and_request_identity_fail_before_observation() -> None:
    session, _, _, transport, _ = selected()
    session.nonce = lambda: "mechanical-nonce-0000000000000000"
    capture = session.capture_account(BOUNDS)
    assert "OAUTH_NONCE_REUSED" in capture.blockers
    assert len(transport.requests) == 1
    session, _, _, transport, _ = selected()
    transport.wrong_request = True
    capture = session.capture_account(BOUNDS)
    assert "RESPONSE_REQUEST_IDENTITY_MISMATCH" in capture.blockers


def test_signing_binds_query_and_environment_and_never_serializes_secret() -> None:
    credentials = EtradeReadCredentials(REFERENCE, values())
    request = EtradeReadRequest(
        EtradeEnvironment.SANDBOX,
        EtradeReadOperation.ACTIVITY,
        EtradeAccountIdKey("MechanicalKeyA_01"),
        (("count", "50"), ("marker", "a/b+c=")),
    )
    first = sign_account_get(request, credentials, at=NOW, nonce="mechanical-nonce-123456")
    second = sign_account_get(
        replace(request, query=(("count", "49"),)),
        credentials,
        at=NOW,
        nonce="mechanical-nonce-123456",
    )
    assert first != second
    assert "mechanical-secret" not in first
    assert "mechanical-access-secret" not in first
    assert "a/b+c=" not in first
    with pytest.raises(EtradeReadError, match="ENVIRONMENT_MISMATCH"):
        sign_account_get(
            replace(request, environment=EtradeEnvironment.PRODUCTION),
            credentials,
            at=NOW,
            nonce="mechanical-nonce-123456",
        )
    with pytest.raises(TypeError):
        pickle.dumps(credentials)
    assert "mechanical" not in repr(credentials)
    credentials.close()
    assert not credentials._values


def test_no_arbitrary_order_method_path_or_oauth_query() -> None:
    with pytest.raises(EtradeReadError):
        EtradeReadRequest(EtradeEnvironment.SANDBOX, "place")  # type: ignore[arg-type]
    with pytest.raises(EtradeReadError):
        EtradeReadRequest(
            EtradeEnvironment.SANDBOX,
            EtradeReadOperation.ORDERS,
            EtradeAccountIdKey("MechanicalKeyA_01"),
            (("oauth_token", "bad"),),
        )
    with pytest.raises(ValueError):
        EtradeAccountIdKey("MechanicalKeyA_01/orders/cancel")


def _envfile(tmp_path: Path, text: str) -> EtradeSecretReference:
    path = tmp_path / "explicit-test-secrets"
    path.write_text(text)
    return EtradeSecretReference(EtradeEnvironment.SANDBOX, f"envfile://{path}?version=1")


def test_scoped_env_presence_does_not_consume_legacy_or_other_environment(
    tmp_path: Path, capsys: Any
) -> None:
    reference = _envfile(
        tmp_path,
        "ETRADE_SANDBOX_CONSUMER_KEY=one\nETRADE_SANDBOX_CONSUMER_SECRET=two\nETRADE_PROD_CONSUMER_KEY=prod\nETRADE_PROD_CONSUMER_SECRET=prodsecret\nETRADE_ACCESS_TOKEN=old\nETRADE_ACCESS_SECRET=oldsecret\n",
    )
    presence = EnvFileEtradeCredentialStore().inspect(reference)
    assert presence.consumer_pair_present
    assert not presence.scoped_access_pair_present
    assert presence.unscoped_access_pair_present
    with pytest.raises(EtradeReadError, match="SCOPED_ACCESS_TOKEN_OR_CONSUMER_UNAVAILABLE"):
        EnvFileEtradeCredentialStore().resolve(reference)
    assert (
        main(
            ["--environment", "sandbox", "--secret-reference", reference.uri, "--inspect-reference"]
        )
        == 2
    )
    output = capsys.readouterr().out
    assert "OWNER_OAUTH_CONSENT" in output
    assert '"provider_requests": 0' in output
    for secret in ("oldsecret", "prodsecret", '"one"', '"two"'):
        assert secret not in output


@pytest.mark.parametrize(
    "text,error",
    [
        (
            "ETRADE_SANDBOX_CONSUMER_KEY=one\nETRADE_SANDBOX_CONSUMER_KEY=two",
            "DUPLICATE_SCOPED_SECRET_VARIABLE",
        ),
        ("ETRADE_SANDBOX_CONSUMER_KEY=$(echo impossible)", "SECRET_FILE_INTERPOLATION_UNSUPPORTED"),
    ],
)
def test_envfile_does_not_evaluate_and_rejects_duplicate_scope(
    tmp_path: Path, text: str, error: str
) -> None:
    with pytest.raises(EtradeReadError, match=error):
        EnvFileEtradeCredentialStore().inspect(_envfile(tmp_path, text))


def test_private_journal_retains_raw_bytes_but_portable_output_does_not(tmp_path: Path) -> None:
    directory = tmp_path / "new-private-capture"
    journal = PrivateDirectoryEtradeJournal(directory)
    session, _, _, _, _ = setup()
    session.journal = journal
    session.discover_accounts()
    assert directory.stat().st_mode & 0o777 == 0o700
    page = directory / "page-0001.json"
    assert page.stat().st_mode & 0o777 == 0o600
    assert "00123456" in page.read_text()
    with pytest.raises(FileExistsError):
        PrivateDirectoryEtradeJournal(directory)


def test_cli_rejects_effects_before_resolving_when_private_output_missing(capsys: Any) -> None:
    assert (
        main(["--environment", "sandbox", "--secret-reference", REFERENCE.uri, "--authorize-read"])
        == 2
    )
    assert "EXPLICIT_PRIVATE_OUTPUT_DIRECTORY_REQUIRED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "field", ["consumer_key", "consumer_secret", "access_token", "access_secret"]
)
def test_same_timestamp_credential_rotation_invalidates_existing_binding(field: str) -> None:
    session, _, store, transport, _ = selected()
    store.data[field] = "rotated-mechanical-value"
    capture = session.capture_account(BOUNDS)
    assert not capture.traversal_complete
    assert capture.observations == {}
    assert "SESSION_TOKEN_CHANGED_REDISCOVERY_REQUIRED" in capture.blockers
    assert len(transport.requests) == 1


def test_signing_matches_etrade_published_mathematically_checked_vector() -> None:
    # Official nonsecret test vector, developer guide's explicitly checked table:
    # https://developer.etrade.com/getting-started/developer-guides
    reference = EtradeSecretReference(
        EtradeEnvironment.PRODUCTION, "envfile:///fixture-only?version=1"
    )
    credentials = EtradeReadCredentials(
        reference,
        values(
            consumer_key="c5bb4dcb7bd6826c7c4340df3f791188",
            consumer_secret="7d30246211192cda43ede3abd9b393b9",
            access_token="VbiNYl63EejjlKdQM6FeENzcnrLACrZ2JYD6NQROfVI=",
            access_secret="XCF9RzyQr4UEPloA+WlC06BnTfYC1P0Fwr3GUw/B0Es=",
        ),
    )
    header = sign_account_get(
        EtradeReadRequest(EtradeEnvironment.PRODUCTION, EtradeReadOperation.ACCOUNTS),
        credentials,
        at=datetime.fromtimestamp(1344885636, UTC),
        nonce="0bba225a40d1bbac2430aa0c6163ce44",
    )
    assert 'oauth_signature="UOnPVdzExTAgHkcGWLLfeTaaMSM%3D"' in header
    credentials.close()


def test_https_transport_pins_host_get_query_and_reads_connection_close_body(
    monkeypatch: Any,
) -> None:
    import packages.adapters.broker.etrade_readonly as adapter

    events: list[Any] = []

    class Socket:
        def settimeout(self, value: float) -> None:
            events.append(("timeout", value))

        def connect(self, address: Any) -> None:
            events.append(("connect", address))

        def shutdown(self, how: int) -> None:
            events.append(("shutdown", how))

        def close(self) -> None:
            events.append("close-socket")

    class Context:
        def wrap_socket(self, raw: Socket, *, server_hostname: str) -> Socket:
            events.append(("TLS", server_hostname))
            return raw

    class Response:
        status = 200

        def __init__(self) -> None:
            self.remaining = [b'{"OrdersResponse":', b'{"Order":[],"marker":""}}', b""]

        def read1(self, size: int) -> bytes:
            assert size > 0
            return self.remaining.pop(0)

        def getheader(self, name: str, default: str) -> str:
            assert name == "Content-Type"
            return "application/json"

    class Connection:
        def __init__(self, host: str, *, timeout: float, context: Context) -> None:
            events.append(("host", host))
            self.sock: Any = None

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            events.append((method, path, sorted(headers)))

        def getresponse(self) -> Response:
            self.sock = None  # Actual http.client behavior for Connection: close.
            return Response()

        def close(self) -> None:
            events.append("close-connection")

    monkeypatch.setattr(
        adapter.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 443))]
    )
    monkeypatch.setattr(adapter.socket, "socket", lambda *a: Socket())
    monkeypatch.setattr(adapter.ssl, "create_default_context", Context)
    monkeypatch.setattr(adapter.http.client, "HTTPSConnection", Connection)
    request = EtradeReadRequest(
        EtradeEnvironment.SANDBOX,
        EtradeReadOperation.ORDERS,
        EtradeAccountIdKey("MechanicalKeyA_01"),
        (("marker", "a/b+c="),),
    )
    result = adapter.EtradeHTTPSGetTransport().get(
        request, authorization="OAuth fixture", deadline_seconds=3
    )
    assert result.request_digest == request.digest
    assert json.loads(result.body)["OrdersResponse"]["Order"] == []
    assert ("host", "apisb.etrade.com") in events
    assert ("TLS", "apisb.etrade.com") in events
    assert (
        "GET",
        "/v1/accounts/MechanicalKeyA_01/orders?marker=a%2Fb%2Bc%3D",
        ["Accept", "Authorization"],
    ) in events
    assert events[-1] == "close-connection"
