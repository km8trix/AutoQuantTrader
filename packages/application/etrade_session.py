"""Bounded personal-v1 session/discovery/account-read feasibility workflow.

An explicit invocation is required. Results are observations, not normalized
ledger facts, reconciliation approval, quote entitlement or order permission.
Successful account bodies go to an explicit private journal before financial
normalization. Known credential field names are rejected, but arbitrary provider
free text is not universally scrubbed. Portable summaries omit bodies and IDs.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from datetime import time as wall_time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from packages.adapters.broker.etrade import (
    ETRADE_PROVIDER,
    EtradeAccountIdentifiers,
    EtradeAccountIdKey,
    EtradeEnvironment,
    EtradeLocalAccountAlias,
    EtradeNumericAccountId,
)
from packages.adapters.broker.etrade_readonly import (
    MAX_RESPONSE_BYTES,
    REQUEST_DEADLINE_SECONDS,
    EtradeCredentialStore,
    EtradeGetTransport,
    EtradeReadCredentials,
    EtradeReadError,
    EtradeReadOperation,
    EtradeReadRequest,
    EtradeSecretReference,
    require_utc,
    sign_account_get,
)
from packages.domain.clock import Clock

SESSION_CONTRACT = "personal-v1-etrade-read-session/2"
FINANCING_POLICY_ID = "cash-funded-long-only/1"
PRIMARY_DOCUMENTATION_REVIEWED = "2026-09-09"
PRIMARY_DOCUMENTATION = (
    "https://developer.etrade.com/getting-started/developer-guides",
    "https://apisb.etrade.com/docs/api/account/api-balance-v1.html",
    "https://apisb.etrade.com/docs/api/account/api-portfolio-v1.html",
    "https://apisb.etrade.com/docs/api/order/api-order-v1.html",
    "https://apisb.etrade.com/docs/api/account/api-transaction-v1.html",
)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise EtradeReadError("DUPLICATE_RESPONSE_FIELD")
        if any(
            word in name.lower()
            for word in ("oauth", "authorization", "password", "secret", "token")
        ):
            raise EtradeReadError("SECRET_LIKE_RESPONSE_FIELD_REJECTED")
        result[name] = value
    return result


def _reject_constant(value: str) -> Any:
    del value
    raise EtradeReadError("NONFINITE_RESPONSE_NUMBER")


def _decode(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            body, object_pairs_hook=_pairs, parse_float=Decimal, parse_constant=_reject_constant
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, EtradeReadError):
            raise
        raise EtradeReadError("RESPONSE_JSON_INVALID") from None
    return _object(value)


def _object(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise EtradeReadError("RESPONSE_OBJECT_REQUIRED")
    return value


def _rows(value: object) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 100:
        raise EtradeReadError("RESPONSE_ARRAY_REQUIRED")
    return [_object(item) for item in value]


def _identity(value: object) -> str:
    if type(value) is int:
        value = str(value)
    if type(value) is not str or not value or len(value) > 128:
        raise EtradeReadError("PROVIDER_IDENTITY_UNAVAILABLE")
    return value


def _number(value: object) -> Decimal:
    try:
        if type(value) not in (Decimal, int, str):
            raise InvalidOperation
        result = Decimal(cast(Decimal | int | str, value))
        if (
            not result.is_finite()
            or len(result.as_tuple().digits) > 28
            or abs(result.adjusted()) > 20
        ):
            raise InvalidOperation
        return result
    except (InvalidOperation, ValueError):
        raise EtradeReadError("PROVIDER_DECIMAL_UNAVAILABLE") from None


@dataclass(frozen=True, slots=True)
class EtradePageEvidence:
    sequence: int
    environment: str
    evidence_class: str
    operation: str
    request_digest: str
    query: tuple[tuple[str, str], ...] = field(repr=False)
    account_fingerprint: str | None
    received_at: str | None
    elapsed_seconds: float
    status: int | None
    body_digest: str | None
    error: str | None = None

    def portable(self) -> dict[str, Any]:
        result = asdict(self)
        # Exact markers remain private; dates/count/page shape are safe metadata.
        result["query"] = {
            name: (_digest(value.encode()) if name == "marker" else value)
            for name, value in self.query
        }
        return result


class EtradeCaptureJournal(Protocol):
    def append(self, evidence: EtradePageEvidence, body: bytes | None) -> None: ...


class PrivateDirectoryEtradeJournal:
    """New owner-only directory; pages fsync before any observation is returned.

    The caller must explicitly choose a private location outside the repository.
    No authorization headers or error/token response bodies enter this journal.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory.resolve()
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)

    def append(self, evidence: EtradePageEvidence, body: bytes | None) -> None:
        path = self.directory / f"page-{evidence.sequence:04d}.json"
        payload = {
            "evidence": asdict(evidence),
            "raw_body_utf8": None if body is None else body.decode("utf-8"),
        }
        with path.open("x", encoding="utf-8") as target:
            os.chmod(path, 0o600)
            json.dump(payload, target, sort_keys=True, separators=(",", ":"))
            target.flush()
            os.fsync(target.fileno())
        descriptor = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class EtradeDiscoveredAccount:
    identifiers: EtradeAccountIdentifiers = field(repr=False)
    fingerprint: str
    account_mode: str
    account_status: str
    institution_type: str
    currency: str | None
    discovery_digest: str

    @property
    def eligible_cash_candidate(self) -> bool:
        return self.eligible_read_candidate()

    def eligible_read_candidate(self, *, allow_margin_privileges: bool = False) -> bool:
        if type(allow_margin_privileges) is not bool:
            raise EtradeReadError("MARGIN_PRIVILEGES_OPT_IN_MUST_BE_BOOLEAN")
        return (
            self.account_mode in (("CASH", "MARGIN") if allow_margin_privileges else ("CASH",))
            and self.account_status == "ACTIVE"
            and self.institution_type == "BROKERAGE"
        )


@dataclass(frozen=True, slots=True)
class EtradeReadAccountBinding:
    account: EtradeDiscoveredAccount = field(repr=False)
    owner_declared_exclusive: bool
    version: int
    selected_at: datetime
    allow_margin_privileges: bool = False

    @property
    def financing_policy_id(self) -> str:
        return FINANCING_POLICY_ID

    @property
    def read_profile(self) -> str:
        return (
            "cash_funded_cash_or_margin_privileges" if self.allow_margin_privileges else "cash_only"
        )

    @property
    def fingerprint(self) -> str:
        return self.account.fingerprint

    @property
    def digest(self) -> str:
        return _digest(
            json.dumps(
                (
                    SESSION_CONTRACT,
                    self.fingerprint,
                    self.version,
                    self.account.discovery_digest,
                    self.owner_declared_exclusive,
                    self.selected_at.isoformat(),
                    self.allow_margin_privileges,
                    self.read_profile,
                    self.financing_policy_id,
                )
            ).encode()
        )


@dataclass(frozen=True, slots=True)
class EtradeCaptureBounds:
    start_date: date
    end_date: date
    page_size: int = 50
    max_pages: int = 5

    def validate(self, now: datetime) -> None:
        if type(self.start_date) is not date or type(self.end_date) is not date:
            raise EtradeReadError("EXPLICIT_HISTORY_DATES_REQUIRED")
        eastern_today = now.astimezone(ZoneInfo("America/New_York")).date()
        # Conservative common window. API pages disagree between two/three years;
        # this lane uses <=730 days and still reports retention unqualified.
        if (
            not eastern_today - timedelta(days=730)
            <= self.start_date
            < self.end_date
            <= eastern_today
        ):
            raise EtradeReadError("HISTORY_RANGE_UNSUPPORTED")
        if type(self.page_size) is not int or not 1 <= self.page_size <= 50:
            raise EtradeReadError("PAGE_SIZE_INVALID")
        if type(self.max_pages) is not int or not 1 <= self.max_pages <= 20:
            raise EtradeReadError("PAGE_LIMIT_INVALID")


@dataclass(frozen=True, slots=True)
class EtradeReadCapture:
    environment: str
    evidence_class: str
    binding_digest: str
    pages: tuple[EtradePageEvidence, ...]
    received_from: datetime
    received_through: datetime
    completed_at: datetime
    observations: dict[str, Any] = field(repr=False)
    terminal_evidence: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    traversal_complete: bool
    read_profile: str
    allow_margin_privileges: bool
    account_modes: tuple[tuple[str, str | None], ...]
    financing_policy_id: str

    def portable(self) -> dict[str, Any]:
        return {
            "contract": SESSION_CONTRACT,
            "environment": self.environment,
            "evidence_class": self.evidence_class,
            "binding_digest": self.binding_digest,
            "read_profile": self.read_profile,
            "financing_policy_id": self.financing_policy_id,
            "allow_margin_privileges": self.allow_margin_privileges,
            "account_modes": dict(self.account_modes),
            "received_from": self.received_from.isoformat(),
            "received_through": self.received_through.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "traversal_complete": self.traversal_complete,
            "pages": [page.portable() for page in self.pages],
            "terminal_evidence": dict(self.terminal_evidence),
            "blockers": list(self.blockers),
            "canonical_facts_published": False,
            "reconciliation_qualified": False,
            "trading_authorized": False,
            "borrowing_authorized": False,
            "shorting_authorized": False,
            "cash_funding_qualified": False,
            "atomic_snapshot": False,
        }


class EtradeReadOnlySession:
    """Synchronous, bounded, manually invoked read episode; no automatic retries.

    Caller-supplied transports and declarations describe evidence, never broker
    attestation. Production qualification must inspect the concrete HTTPS path.
    Every new process loads token metadata afresh and performs explicit selection.
    """

    def __init__(
        self,
        *,
        reference: EtradeSecretReference,
        store: EtradeCredentialStore,
        transport: EtradeGetTransport,
        journal: EtradeCaptureJournal,
        clock: Clock,
        monotonic: Callable[[], float] = time.monotonic,
        nonce: Callable[[], str] = lambda: secrets.token_hex(24),
    ) -> None:
        reference.__post_init__()
        self.reference = reference
        self.store = store
        self.transport = transport
        self.journal = journal
        self.clock = clock
        self.monotonic = monotonic
        self.nonce = nonce
        self._closed = False
        self._last_now: datetime | None = None
        self._last_mono: float | None = None
        self._last_activity: datetime | None = None
        self._token_identity: tuple[datetime, datetime, str] | None = None
        self._nonce_history: set[str] = set()
        self._accounts: tuple[EtradeDiscoveredAccount, ...] = ()
        self._discovered_at: datetime | None = None
        self._binding: EtradeReadAccountBinding | None = None
        self.pages: list[EtradePageEvidence] = []
        self._request_times: list[float] = []

    def close(self) -> None:
        self._closed = True
        self._binding = None
        self._accounts = ()

    def _now(self) -> tuple[datetime, float]:
        if self._closed:
            raise EtradeReadError("SESSION_CLOSED")
        now = require_utc(self.clock.now())
        mono = self.monotonic()
        if not math.isfinite(mono):
            self.close()
            raise EtradeReadError("SESSION_CLOCK_DISCONTINUITY")
        if (
            self._last_now is not None
            and self._last_mono is not None
            and (
                now < self._last_now
                or mono < self._last_mono
                or abs((now - self._last_now).total_seconds() - (mono - self._last_mono)) >= 1
            )
        ):
            self.close()
            raise EtradeReadError("SESSION_CLOCK_DISCONTINUITY")
        self._last_now, self._last_mono = now, mono
        return now, mono

    def _check_token(self, credentials: EtradeReadCredentials, now: datetime) -> None:
        if credentials.reference != self.reference:
            raise EtradeReadError("SECRET_REFERENCE_MISMATCH")
        # This credential-set digest stays in this process only, never evidence.
        token_identity = (
            credentials.issued_at,
            credentials.expires_at,
            _digest(
                json.dumps(
                    tuple(
                        credentials._value(name)
                        for name in (
                            "consumer_key",
                            "consumer_secret",
                            "access_token",
                            "access_secret",
                        )
                    )
                ).encode()
            ),
        )
        if self._token_identity is not None and self._token_identity != token_identity:
            self.close()
            raise EtradeReadError("SESSION_TOKEN_CHANGED_REDISCOVERY_REQUIRED")
        self._token_identity = token_identity
        eastern = credentials.issued_at.astimezone(ZoneInfo("America/New_York"))
        midnight = datetime.combine(
            eastern.date() + timedelta(days=1), wall_time(), ZoneInfo("America/New_York")
        ).astimezone(UTC)
        expiry = min(credentials.expires_at, midnight)
        activity = self._last_activity or credentials.last_activity_at
        if now < credentials.issued_at or now < activity:
            raise EtradeReadError("TOKEN_TIME_METADATA_FUTURE")
        if now >= expiry:
            self.close()
            raise EtradeReadError("DAILY_REAUTHORIZATION_REQUIRED")
        if now - activity >= timedelta(hours=2):
            self.close()
            raise EtradeReadError("TOKEN_INACTIVE_SUPERVISED_RENEWAL_REQUIRED")

    def _get(self, request: EtradeReadRequest) -> dict[str, Any]:
        now, started = self._now()
        # Local conservative budget; it is not an assertion of provider quota.
        self._request_times = [at for at in self._request_times if started - at < 60]
        if len(self._request_times) >= 10:
            raise EtradeReadError("LOCAL_READ_BUDGET_EXHAUSTED")
        if request.environment is not self.reference.environment:
            raise EtradeReadError("REQUEST_ENVIRONMENT_MISMATCH")
        self._request_times.append(started)
        response = None
        received: datetime | None = None
        credentials = None
        try:
            credentials = self.store.resolve(self.reference)
            self._check_token(credentials, now)
            nonce = self.nonce()
            if nonce in self._nonce_history:
                raise EtradeReadError("OAUTH_NONCE_REUSED")
            self._nonce_history.add(nonce)
            authorization = sign_account_get(request, credentials, at=now, nonce=nonce)
            remaining = REQUEST_DEADLINE_SECONDS - (self.monotonic() - started)
            if remaining <= 0:
                raise EtradeReadError("READ_DEADLINE_EXCEEDED")
            response = self.transport.get(
                request, authorization=authorization, deadline_seconds=remaining
            )
            del authorization
            received, finished = self._now()
            if finished - started >= REQUEST_DEADLINE_SECONDS:
                raise EtradeReadError("READ_DEADLINE_EXCEEDED")
            self._check_token(credentials, received)
            if response.request_digest != request.digest:
                raise EtradeReadError("RESPONSE_REQUEST_IDENTITY_MISMATCH")
            if response.status in (401, 403):
                self.close()
                raise EtradeReadError("AUTHENTICATION_REJECTED_REAUTHORIZE")
            if response.status == 429:
                raise EtradeReadError("PROVIDER_THROTTLED_NEW_OWNER_READ_REQUIRED")
            if response.status not in (200, 204):
                raise EtradeReadError("READ_HTTP_FAILED")
            if type(response.body) is not bytes or len(response.body) > MAX_RESPONSE_BYTES:
                raise EtradeReadError("RESPONSE_BODY_INVALID")
            if response.status == 204:
                if (
                    request.operation
                    not in (
                        EtradeReadOperation.ACTIVITY,
                        EtradeReadOperation.PORTFOLIO,
                        EtradeReadOperation.ORDERS,
                    )
                    or response.body
                ):
                    raise EtradeReadError("UNDOCUMENTED_EMPTY_RESPONSE")
                # Portfolio/order 204 is a transport observation, not a fabricated
                # provider account, row list, identity, marker or page count.
                decoded = (
                    {"TransactionListResponse": {"Transaction": [], "transactionCount": 0}}
                    if request.operation is EtradeReadOperation.ACTIVITY
                    else {}
                )
            else:
                if response.content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise EtradeReadError("RESPONSE_MEDIA_TYPE_UNSUPPORTED")
                # Validate absence of secret-like material before private journaling;
                # financial normalization is strictly after the append below.
                decoded = _decode(response.body)
            evidence = EtradePageEvidence(
                len(self.pages) + 1,
                request.environment.value,
                self.transport.evidence_class,
                request.operation.value,
                request.digest,
                request.query,
                None if self._binding is None else self._binding.fingerprint,
                received.isoformat(),
                finished - started,
                response.status,
                _digest(response.body),
            )
            self.journal.append(evidence, response.body)
            self.pages.append(evidence)
            self._last_activity = received
            return decoded
        except Exception as error:
            code = str(error) if isinstance(error, EtradeReadError) else "READ_DEPENDENCY_FAILED"
            evidence = EtradePageEvidence(
                len(self.pages) + 1,
                request.environment.value,
                self.transport.evidence_class,
                request.operation.value,
                request.digest,
                request.query,
                None if self._binding is None else self._binding.fingerprint,
                None if received is None else received.isoformat(),
                max(0, self.monotonic() - started),
                None if response is None else response.status,
                None,
                code,
            )
            try:
                self.journal.append(evidence, None)
                self.pages.append(evidence)
            except Exception:
                self.close()
                raise EtradeReadError("CAPTURE_JOURNAL_UNAVAILABLE") from None
            raise EtradeReadError(code) from None
        finally:
            if credentials is not None:
                credentials.close()

    def discover_accounts(self) -> tuple[EtradeDiscoveredAccount, ...]:
        self._binding = None
        self._accounts = ()
        payload = self._get(
            EtradeReadRequest(self.reference.environment, EtradeReadOperation.ACCOUNTS)
        )
        root = _object(payload.get("AccountListResponse"))
        accounts = _rows(_object(root.get("Accounts")).get("Account"))
        found: list[EtradeDiscoveredAccount] = []
        ids: set[str] = set()
        keys: set[str] = set()
        for index, row in enumerate(accounts):
            numeric = EtradeNumericAccountId(_identity(row.get("accountId")))
            key = EtradeAccountIdKey(_identity(row.get("accountIdKey")))
            if numeric.value in ids or key.value in keys:
                raise EtradeReadError("DUPLICATE_ACCOUNT_IDENTITY")
            ids.add(numeric.value)
            keys.add(key.value)
            identifiers = EtradeAccountIdentifiers(
                ETRADE_PROVIDER,
                self.reference.environment,
                EtradeLocalAccountAlias(f"account-{index + 1}"),
                numeric,
                key,
            )
            fingerprint = _digest(
                json.dumps(
                    ("etrade", self.reference.environment.value, numeric.value, key.value)
                ).encode()
            )
            found.append(
                EtradeDiscoveredAccount(
                    identifiers,
                    fingerprint,
                    str(row.get("accountMode", "UNKNOWN")),
                    str(row.get("accountStatus", "UNKNOWN")),
                    str(row.get("institutionType", "UNKNOWN")),
                    row.get("currency") if type(row.get("currency")) is str else None,
                    self.pages[-1].body_digest or "",
                )
            )
        self._accounts = tuple(found)
        self._discovered_at = self._now()[0]
        return self._accounts

    def select_account(
        self,
        fingerprint: str,
        *,
        owner_declared_exclusive: bool,
        allow_margin_privileges: bool = False,
    ) -> EtradeReadAccountBinding:
        self._binding = None
        if type(allow_margin_privileges) is not bool:
            raise EtradeReadError("MARGIN_PRIVILEGES_OPT_IN_MUST_BE_BOOLEAN")
        now, _ = self._now()
        if self._discovered_at is None or now - self._discovered_at >= timedelta(seconds=60):
            raise EtradeReadError("FRESH_DISCOVERY_REQUIRED")
        matches = [account for account in self._accounts if account.fingerprint == fingerprint]
        if len(matches) != 1:
            raise EtradeReadError("EXPLICIT_DISCOVERED_ACCOUNT_REQUIRED")
        account = matches[0]
        if not account.eligible_read_candidate(allow_margin_privileges=allow_margin_privileges):
            raise EtradeReadError(
                "ACTIVE_BROKERAGE_CASH_OR_MARGIN_ACCOUNT_REQUIRED"
                if allow_margin_privileges
                else "ACTIVE_BROKERAGE_CASH_ACCOUNT_REQUIRED"
            )
        if owner_declared_exclusive is not True:
            raise EtradeReadError("OWNER_EXCLUSIVITY_DECLARATION_REQUIRED")
        if account.currency not in (None, "USD"):
            raise EtradeReadError("NON_USD_ACCOUNT_UNSUPPORTED")
        self._binding = EtradeReadAccountBinding(account, True, 1, now, allow_margin_privileges)
        return self._binding

    def _request(self, operation: EtradeReadOperation, query: dict[str, str]) -> EtradeReadRequest:
        if self._binding is None:
            raise EtradeReadError("EXPLICIT_ACCOUNT_SELECTION_REQUIRED")
        return EtradeReadRequest(
            self.reference.environment,
            operation,
            self._binding.account.identifiers.account_id_key,
            tuple(sorted(query.items())),
        )

    def _account_identity(self, value: object) -> None:
        assert self._binding is not None
        if _identity(value) != self._binding.account.identifiers.numeric_account_id.value:
            raise EtradeReadError("RESPONSE_ACCOUNT_IDENTITY_MISMATCH")

    def _continuation(self, root: dict[str, Any], request: EtradeReadRequest) -> str:
        marker = root.get("marker")
        if type(marker) is not str:
            raise EtradeReadError("TERMINAL_MARKER_EVIDENCE_MISSING")
        if len(marker) > 1024:
            raise EtradeReadError("MARKER_TOO_LARGE")
        next_url = root.get("next")
        if next_url not in (None, ""):
            if type(next_url) is not str or not marker:
                raise EtradeReadError("CONFLICTING_CONTINUATION")
            parsed = urlsplit(next_url)
            if (
                parsed.scheme + "://" + parsed.netloc != request.origin
                or parsed.fragment
                or parsed.path.removesuffix(".json") != request.path.removesuffix(".json")
            ):
                raise EtradeReadError("CONTINUATION_SCOPE_MISMATCH")
            query = parse_qs(parsed.query, keep_blank_values=True)
            if query.get("marker") != [marker]:
                raise EtradeReadError("CONTINUATION_MARKER_MISMATCH")
            # Never follow a returned URL; retain original bounds and allowlist.
            current = dict(request.query)
            if any(
                name != "marker" and (name not in current or values != [current[name]])
                for name, values in query.items()
            ):
                raise EtradeReadError("CONTINUATION_QUERY_MISMATCH")
        return marker

    def _paged(
        self, operation: EtradeReadOperation, query: dict[str, str], bounds: EtradeCaptureBounds
    ) -> tuple[list[dict[str, Any]], str]:
        output: list[dict[str, Any]] = []
        seen_markers: set[str] = set()
        seen_ids: set[str] = set()
        expected_pages: int | None = None
        for page in range(1, bounds.max_pages + 1):
            if operation is EtradeReadOperation.PORTFOLIO:
                query["pageNumber"] = str(page)
            request = self._request(operation, query)
            payload = self._get(request)
            if operation is EtradeReadOperation.ORDERS and self.pages[-1].status == 204:
                if page != 1 or output or seen_markers or query.get("marker"):
                    raise EtradeReadError("ORDERS_NO_CONTENT_AFTER_CONTINUATION_PROMISE")
                # Shared Order API errors document 204; the List Orders response
                # table omits it. Keep this discrepancy visible in qualification.
                return [], "documented_order_api_initial_no_content"
            if operation is EtradeReadOperation.PORTFOLIO:
                if self.pages[-1].status == 204:
                    if page != 1 or expected_pages is not None or output:
                        raise EtradeReadError("PORTFOLIO_NO_CONTENT_AFTER_PAGINATION_PROMISE")
                    return [], "documented_initial_portfolio_no_content"
                groups = _rows(_object(payload.get("PortfolioResponse")).get("AccountPortfolio"))
                if len(groups) != 1:
                    raise EtradeReadError("PORTFOLIO_ACCOUNT_GROUP_AMBIGUOUS")
                root = groups[0]
                self._account_identity(root.get("accountId"))
                rows = _rows(root.get("Position"))
                total = root.get("totalNoOfPages")
                if (
                    type(total) is not int
                    or total < 1
                    or (expected_pages is not None and total != expected_pages)
                ):
                    raise EtradeReadError("PORTFOLIO_PAGE_COVERAGE_UNAVAILABLE")
                expected_pages = total
                next_page = root.get("nextPageNo")
                if page < total and str(next_page) != str(page + 1):
                    raise EtradeReadError("PORTFOLIO_PAGE_GAP")
                if page == total and next_page not in (None, "", "0", 0):
                    raise EtradeReadError("PORTFOLIO_TERMINAL_CONFLICT")
                if page == total and root.get("next") not in (None, ""):
                    raise EtradeReadError("PORTFOLIO_TERMINAL_CONFLICT")
                terminal = page == total
                terminal_reason = "totalNoOfPages_and_nextPageNo"
                identity_key = "positionId"
            else:
                is_activity = operation is EtradeReadOperation.ACTIVITY
                root = _object(
                    payload.get("TransactionListResponse" if is_activity else "OrdersResponse")
                )
                rows = _rows(root.get("Transaction" if is_activity else "Order"))
                identity_key = "transactionId" if is_activity else "orderId"
                if is_activity:
                    for row in rows:
                        self._account_identity(row.get("accountId"))
                    if type(root.get("transactionCount")) is not int or root[
                        "transactionCount"
                    ] != len(rows):
                        raise EtradeReadError("ACTIVITY_COUNT_MISMATCH")
                    terminal = len(rows) < bounds.page_size
                    if terminal:
                        if (
                            root.get("moreTransactions") is True
                            or root.get("marker") not in (None, "")
                            or root.get("next") not in (None, "")
                        ):
                            raise EtradeReadError("ACTIVITY_TERMINAL_CONFLICT")
                        marker = ""
                    else:
                        marker = self._continuation(root, request)
                        if not marker:
                            raise EtradeReadError("FULL_ACTIVITY_PAGE_WITHOUT_CONTINUATION")
                    terminal_reason = "transactionCount_less_than_requested"
                else:
                    marker = self._continuation(root, request)
                    terminal = marker == ""
                    terminal_reason = "explicit_empty_marker"
                if not terminal:
                    if marker in seen_markers:
                        raise EtradeReadError("PAGINATION_CURSOR_LOOP")
                    seen_markers.add(marker)
                    query["marker"] = marker
            if len(rows) > bounds.page_size:
                raise EtradeReadError("PAGE_COUNT_EXCEEDED")
            for row in rows:
                identity = _identity(row.get(identity_key))
                if identity in seen_ids:
                    raise EtradeReadError("DUPLICATE_OR_CONFLICTING_PAGE_IDENTITY")
                seen_ids.add(identity)
            output.extend(rows)
            if terminal:
                return output, terminal_reason
        raise EtradeReadError("PAGINATION_LIMIT_INCOMPLETE")

    def capture_account(self, bounds: EtradeCaptureBounds) -> EtradeReadCapture:
        started, _ = self._now()
        bounds.validate(started)
        if self._binding is None:
            raise EtradeReadError("EXPLICIT_ACCOUNT_SELECTION_REQUIRED")
        binding = self._binding
        page_start = len(self.pages)
        observations: dict[str, Any] = {}
        terminals: list[tuple[str, str]] = []
        blockers = [
            "PROVIDER_QUOTAS_UNQUALIFIED",
            "QUOTE_ENTITLEMENT_AND_EXECUTION_FRESHNESS_UNQUALIFIED",
            "ACTIVITY_EXECUTION_CORRECTION_IDENTITY_UNQUALIFIED",
            "HISTORY_RETENTION_UNQUALIFIED",
            "SINGLE_OBSERVATION_ROUND_NOT_RECONCILIATION",
            "CASH_FIELD_SEMANTICS_UNQUALIFIED",
        ]
        complete = False
        account_modes: dict[str, str | None] = {
            "discovery": binding.account.account_mode,
            "balance": None,
        }
        try:
            if started - binding.selected_at >= timedelta(seconds=60):
                raise EtradeReadError("ACCOUNT_BINDING_STALE_REDISCOVERY_REQUIRED")
            balance = _object(
                self._get(
                    self._request(
                        EtradeReadOperation.BALANCES,
                        {"instType": "BROKERAGE", "realTimeNAV": "true"},
                    )
                ).get("BalanceResponse")
            )
            self._account_identity(balance.get("accountId"))
            reported_mode = balance.get("accountMode")
            allowed_modes = ("CASH", "MARGIN") if binding.allow_margin_privileges else ("CASH",)
            account_modes["balance"] = (
                reported_mode if reported_mode in ("CASH", "MARGIN") else "UNSUPPORTED_OR_MISSING"
            )
            if reported_mode not in allowed_modes:
                raise EtradeReadError(
                    "BALANCE_CASH_OR_MARGIN_MODE_UNQUALIFIED"
                    if binding.allow_margin_privileges
                    else "BALANCE_CASH_MODE_UNQUALIFIED"
                )
            if reported_mode != binding.account.account_mode:
                blockers.append("ACCOUNT_MODE_DISAGREEMENT")
            currency = balance.get("currency", binding.account.currency)
            if currency is None:
                blockers.append("ACCOUNT_CURRENCY_NOT_PROVEN_BY_RESPONSE")
            elif currency != "USD":
                raise EtradeReadError("NON_USD_ACCOUNT_UNSUPPORTED")
            # Preserve distinct meanings. No fallback from buying power to cash.
            computed = _object(balance.get("Computed"))
            observations["balances"] = {
                name: _number(computed[name]) if name in computed else None
                for name in (
                    "cashBalance",
                    "netCash",
                    "cashAvailableForInvestment",
                    "settledCashForInvestment",
                    "unSettledCashForInvestment",
                    "fundsWithheldFromPurchasePower",
                    "cashBuyingPower",
                )
            }
            if observations["balances"]["settledCashForInvestment"] is None:
                blockers.append("SETTLED_CASH_FIELD_UNAVAILABLE")
            observations["account_modes"] = dict(account_modes)
            # Source fields remain private observations, with no debit-sign,
            # funding, reserve-inclusion or margin-call interpretation.
            observations["margin"] = {
                "Computed": {
                    name: _number(computed[name]) if computed.get(name) is not None else None
                    for name in (
                        "marginBalance",
                        "marginBuyingPower",
                        "dtMarginBuyingPower",
                        "dtCashBuyingPower",
                        "shortAdjustBalance",
                    )
                },
                "BalanceResponse": {
                    name: balance.get(name)
                    for name in (
                        "accountMode",
                        "accountType",
                        "dayTraderStatus",
                        "optionLevel",
                        "quoteMode",
                        "Cash",
                        "Margin",
                        "OpenCalls",
                        "openCalls",
                    )
                },
                "ComputedOpenCalls": {
                    name: computed.get(name) for name in ("OpenCalls", "openCalls")
                },
            }
            if "MARGIN" in account_modes.values():
                blockers.extend(
                    (
                        "MARGIN_LIABILITY_AND_CASH_FUNDING_UNQUALIFIED",
                        "MARGIN_CALLS_AND_RESTRICTIONS_UNQUALIFIED",
                    )
                )
                margin_balance = observations["margin"]["Computed"]["marginBalance"]
                if margin_balance is None:
                    blockers.append("MARGIN_BALANCE_FIELD_UNAVAILABLE")
                elif margin_balance != 0:
                    blockers.append("NONZERO_REPORTED_MARGIN_BALANCE_UNQUALIFIED")
            terminals.append(("balances", "single_account_response"))
            start, end = bounds.start_date.strftime("%m%d%Y"), bounds.end_date.strftime("%m%d%Y")
            for name, operation, query in (
                (
                    "portfolio",
                    EtradeReadOperation.PORTFOLIO,
                    {"view": "QUICK", "marketSession": "REGULAR"},
                ),
                ("orders_current", EtradeReadOperation.ORDERS, {}),
                ("orders_history", EtradeReadOperation.ORDERS, {"fromDate": start, "toDate": end}),
                (
                    "activity",
                    EtradeReadOperation.ACTIVITY,
                    {"startDate": start, "endDate": end, "sortOrder": "ASC"},
                ),
            ):
                rows, reason = self._paged(
                    operation, {"count": str(bounds.page_size), **query}, bounds
                )
                observations[name] = rows
                terminals.append((name, reason))
                if reason == "documented_initial_portfolio_no_content":
                    blockers.append("PORTFOLIO_NO_CONTENT_NOT_RECONCILED_POSITION_ABSENCE")
                elif reason == "documented_order_api_initial_no_content":
                    blockers.extend(
                        (
                            "ORDERS_NO_CONTENT_NOT_RECONCILED_ORDER_ABSENCE",
                            "LIST_ORDERS_204_RESPONSE_TABLE_AMBIGUITY",
                        )
                    )
            for row in observations["portfolio"]:
                quantity = _number(row.get("quantity"))
                product = _object(row.get("Product"))
                if (
                    quantity < 0
                    or quantity != quantity.to_integral_value()
                    or product.get("securityType") != "EQ"
                    or product.get("symbol") not in ("DIA", "IWM", "QQQ", "SPY")
                    or row.get("positionType") != "LONG"
                ):
                    blockers.append("UNSUPPORTED_OBSERVED_POSITION")
                if row.get("currency") not in (None, "USD"):
                    blockers.append("NON_USD_POSITION")
            complete = True
        except EtradeReadError as error:
            blockers.append(str(error))
        completed, _ = (
            self._now() if not self._closed else (require_utc(self.clock.now()), self.monotonic())
        )
        pages = tuple(self.pages[page_start:])
        receipts = [
            datetime.fromisoformat(page.received_at)
            for page in pages
            if page.received_at is not None
        ]
        if receipts:
            first = receipts[0]
            last = receipts[-1]
        else:
            first = last = started
        if completed - first >= timedelta(seconds=60):
            blockers.append("CAPTURE_STALE")
            complete = False
        if not complete:
            observations = {}  # Partial views cannot escape as a complete account observation.
        if self.reference.environment is EtradeEnvironment.SANDBOX:
            blockers.append("SANDBOX_STORED_EXAMPLES_NOT_ACCOUNT_ECONOMICS")
        return EtradeReadCapture(
            self.reference.environment.value,
            self.transport.evidence_class,
            binding.digest,
            pages,
            first,
            last,
            completed,
            observations,
            tuple(terminals),
            tuple(sorted(set(blockers))),
            complete,
            binding.read_profile,
            binding.allow_margin_privileges,
            tuple(account_modes.items()),
            binding.financing_policy_id,
        )
