"""Provider-neutral, non-applying broker reconciliation evidence.

Phase 4K normalizes one already-authenticated broker lookup into immutable
historical evidence.  The evidence deliberately stops before lifecycle
application, UNKNOWN resolution, execution accounting, reservation release, or
any trading effect.  Durable repositories may append it to an account-local
chain, but may not reinterpret that append as broker authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Protocol

from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

BROKER_RECONCILIATION_CONTRACT_VERSION = "phase4k-non-applying-broker-reconciliation-evidence-v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NORMALIZED_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_RAW_PROVIDER_TIMESTAMP = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})$"
)
_PROVIDER_TIMESTAMP_FIELD_ORDER = (
    "created_at",
    "updated_at",
    "submitted_at",
    "filled_at",
    "expired_at",
    "expires_at",
    "canceled_at",
    "failed_at",
    "replaced_at",
)
_PROVIDER_TIMESTAMP_FIELD_POSITION = {
    field_name: position for position, field_name in enumerate(_PROVIDER_TIMESTAMP_FIELD_ORDER)
}


class BrokerReconciliationError(ValueError):
    """Broker reconciliation evidence violates the frozen domain contract."""


class BrokerReconciliationConflict(BrokerReconciliationError):
    """A stable reconciliation identity conflicts with immutable content."""


class BrokerReconciliationOutcome(StrEnum):
    """Closed, historical meanings for one authenticated broker lookup."""

    ORDER_OBSERVED_CANDIDATE = "order_observed_candidate"
    QUARANTINED_ECONOMIC_MISMATCH = "quarantined_economic_mismatch"
    QUARANTINED_SECURITY_MISMATCH = "quarantined_security_mismatch"
    INCONCLUSIVE_NOT_VISIBLE = "inconclusive_not_visible"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum: int = 256,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or (not allow_empty and not value)
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerReconciliationError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_optional_text(
    value: object,
    field_name: str,
    *,
    maximum: int = 256,
    allow_empty: bool = False,
) -> str | None:
    if value is None:
        return None
    return _require_text(
        value,
        field_name,
        maximum=maximum,
        allow_empty=allow_empty,
    )


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BrokerReconciliationError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise BrokerReconciliationError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise BrokerReconciliationError(str(error)) from error
    return value


def _require_optional_decimal(
    value: object,
    field_name: str,
    *,
    allow_zero: bool,
) -> Decimal | None:
    if value is None:
        return None
    if type(value) is not Decimal or not value.is_finite():
        raise BrokerReconciliationError(f"{field_name} must be an exact finite Decimal or null")
    result = canonical_decimal(value)
    if result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise BrokerReconciliationError(f"{field_name} must be {qualifier}")
    return result


@dataclass(frozen=True, slots=True)
class BrokerProviderTimestampEvidence:
    """One provider timestamp retaining its raw nanosecond identity."""

    field_name: str
    raw: str
    normalized_utc: str
    nanosecond: int

    def __post_init__(self) -> None:
        if self.field_name not in _PROVIDER_TIMESTAMP_FIELD_POSITION:
            raise BrokerReconciliationError(
                "provider timestamp field is outside the closed order timestamp set"
            )
        raw = _require_text(self.raw, "provider timestamp raw value", maximum=40)
        matched = _RAW_PROVIDER_TIMESTAMP.fullmatch(raw)
        if matched is None or matched.group("zone") == "-00:00":
            raise BrokerReconciliationError(
                "provider timestamp raw value must be an exact RFC 3339 instant"
            )
        base_text = f"{matched.group('date')}T{matched.group('time')}"
        base_text += "+00:00" if matched.group("zone") == "Z" else matched.group("zone")
        try:
            parsed = datetime.fromisoformat(base_text)
        except ValueError as error:
            raise BrokerReconciliationError(
                "provider timestamp raw value is not a valid instant"
            ) from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise BrokerReconciliationError("provider timestamp raw value must include an offset")
        raw_fraction = matched.group("fraction") or ""
        raw_nanosecond = int(raw_fraction.ljust(9, "0")) if raw_fraction else 0
        normalized = _require_text(
            self.normalized_utc,
            "provider timestamp normalized UTC value",
            maximum=40,
        )
        if _NORMALIZED_UTC_TIMESTAMP.fullmatch(normalized) is None:
            raise BrokerReconciliationError(
                "provider timestamp normalized UTC value is not canonical"
            )
        if type(self.nanosecond) is not int or self.nanosecond < 0 or self.nanosecond > 999_999_999:
            raise BrokerReconciliationError(
                "provider timestamp nanosecond must be between zero and 999999999"
            )
        fraction = normalized.removesuffix("Z").partition(".")[2]
        normalized_nanosecond = int(fraction.ljust(9, "0")) if fraction else 0
        utc_second = parsed.astimezone(UTC).isoformat(timespec="seconds")
        expected_normalized = utc_second.replace("+00:00", "Z")
        if raw_nanosecond:
            expected_normalized = (
                f"{expected_normalized[:-1]}.{raw_nanosecond:09d}".rstrip("0") + "Z"
            )
        if (
            raw_nanosecond != self.nanosecond
            or normalized_nanosecond != self.nanosecond
            or normalized != expected_normalized
        ):
            raise BrokerReconciliationError(
                "provider timestamp raw, normalized UTC, and nanosecond values conflict"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BROKER_RECONCILIATION_CONTRACT_VERSION,
                "provider_timestamp_evidence",
                self.field_name,
                self.raw,
                self.normalized_utc,
                self.nanosecond,
            )
        )


@dataclass(frozen=True, slots=True)
class BrokerReconciliationEvidence:
    """Deterministic non-applying evidence normalized from one exact source."""

    account_id: str
    provider_id: str
    environment: str
    attempt_id: str
    order_id: str
    client_order_id: str
    instrument_id: str
    symbol: str
    outcome: BrokerReconciliationOutcome
    expected_provider_asset_id: str
    provider_order_id: str | None
    provider_order_status: str | None
    provider_replaced_by: str | None
    provider_replaces: str | None
    observed_provider_asset_id: str | None
    mismatch_fields: tuple[str, ...]
    provider_timestamps: tuple[BrokerProviderTimestampEvidence, ...]
    requested_quantity: Decimal | None
    requested_notional: Decimal | None
    cumulative_filled_quantity: Decimal | None
    cumulative_filled_average_price: Decimal | None
    provider_source: str | None
    source_lookup_receipt_id: str
    source_lookup_receipt_sha256: str
    source_ingress_receipt_id: str
    source_ingress_receipt_sha256: str
    source_ingress_sequence: int
    source_delivery_idempotency_key: str
    source_observation_sha256: str
    source_body_sha256: str
    http_status: int
    provider_request_id: str
    received_at: datetime
    raw_recorded_at: datetime
    authenticated_at: datetime
    source_committed_at: datetime

    def __post_init__(self) -> None:
        for required_value, required_field_name, required_maximum in (
            (self.account_id, "reconciliation account ID", 64),
            (self.provider_id, "reconciliation provider ID", 128),
            (self.environment, "reconciliation environment", 32),
            (self.attempt_id, "reconciliation attempt ID", 128),
            (self.order_id, "reconciliation order ID", 128),
            (self.client_order_id, "reconciliation client order ID", 128),
            (self.instrument_id, "reconciliation instrument ID", 128),
            (self.symbol, "reconciliation symbol", 32),
            (
                self.expected_provider_asset_id,
                "reconciliation expected provider asset ID",
                128,
            ),
            (
                self.source_lookup_receipt_id,
                "reconciliation source lookup receipt ID",
                128,
            ),
            (
                self.source_ingress_receipt_id,
                "reconciliation source ingress receipt ID",
                128,
            ),
            (
                self.source_delivery_idempotency_key,
                "reconciliation source delivery idempotency key",
                128,
            ),
            (
                self.provider_request_id,
                "reconciliation provider request ID",
                256,
            ),
        ):
            _require_text(
                required_value,
                required_field_name,
                maximum=required_maximum,
            )
        if type(self.outcome) is not BrokerReconciliationOutcome:
            raise BrokerReconciliationError("reconciliation outcome is unsupported")
        for optional_value, optional_field_name, optional_maximum in (
            (self.provider_order_id, "reconciliation provider order ID", 128),
            (
                self.provider_order_status,
                "reconciliation provider order status",
                128,
            ),
            (
                self.provider_replaced_by,
                "reconciliation provider replaced-by order ID",
                128,
            ),
            (
                self.provider_replaces,
                "reconciliation provider replaces order ID",
                128,
            ),
            (
                self.observed_provider_asset_id,
                "reconciliation observed provider asset ID",
                128,
            ),
            (self.provider_source, "reconciliation provider source", 128),
        ):
            _require_optional_text(
                optional_value,
                optional_field_name,
                maximum=optional_maximum,
                allow_empty=(optional_field_name == "reconciliation provider source"),
            )
        for digest_value, digest_field_name in (
            (
                self.source_lookup_receipt_sha256,
                "reconciliation source lookup receipt digest",
            ),
            (
                self.source_ingress_receipt_sha256,
                "reconciliation source ingress receipt digest",
            ),
            (
                self.source_observation_sha256,
                "reconciliation source observation digest",
            ),
            (self.source_body_sha256, "reconciliation source body digest"),
        ):
            _require_sha256(digest_value, digest_field_name)
        if type(self.source_ingress_sequence) is not int or self.source_ingress_sequence <= 0:
            raise BrokerReconciliationError(
                "reconciliation source ingress sequence must be positive"
            )
        if type(self.http_status) is not int or self.http_status not in (200, 404):
            raise BrokerReconciliationError(
                "reconciliation evidence supports only historical HTTP 200 or 404"
            )
        if (
            type(self.mismatch_fields) is not tuple
            or len(frozenset(self.mismatch_fields)) != len(self.mismatch_fields)
            or any(
                type(field_name) is not str or not field_name or field_name != field_name.strip()
                for field_name in self.mismatch_fields
            )
        ):
            raise BrokerReconciliationError(
                "reconciliation mismatch fields must be a unique trimmed tuple"
            )
        if type(self.provider_timestamps) is not tuple or any(
            type(timestamp) is not BrokerProviderTimestampEvidence
            for timestamp in self.provider_timestamps
        ):
            raise BrokerReconciliationError(
                "reconciliation provider timestamps must be an exact tuple"
            )
        for timestamp in self.provider_timestamps:
            timestamp.__post_init__()
        timestamp_fields = tuple(timestamp.field_name for timestamp in self.provider_timestamps)
        if (
            len(frozenset(timestamp_fields)) != len(timestamp_fields)
            or tuple(
                sorted(
                    timestamp_fields,
                    key=_PROVIDER_TIMESTAMP_FIELD_POSITION.__getitem__,
                )
            )
            != timestamp_fields
        ):
            raise BrokerReconciliationError(
                "reconciliation provider timestamps must be unique and canonically ordered"
            )
        requested_quantity = _require_optional_decimal(
            self.requested_quantity,
            "reconciliation requested quantity",
            allow_zero=False,
        )
        requested_notional = _require_optional_decimal(
            self.requested_notional,
            "reconciliation requested notional",
            allow_zero=False,
        )
        cumulative_filled_quantity = _require_optional_decimal(
            self.cumulative_filled_quantity,
            "reconciliation cumulative filled quantity",
            allow_zero=True,
        )
        cumulative_filled_average_price = _require_optional_decimal(
            self.cumulative_filled_average_price,
            "reconciliation cumulative filled average price",
            allow_zero=True,
        )
        for field_name, value in (
            ("requested_quantity", requested_quantity),
            ("requested_notional", requested_notional),
            ("cumulative_filled_quantity", cumulative_filled_quantity),
            (
                "cumulative_filled_average_price",
                cumulative_filled_average_price,
            ),
        ):
            object.__setattr__(self, field_name, value)
        received_at = _require_utc(
            self.received_at,
            "reconciliation received_at",
        )
        raw_recorded_at = _require_utc(
            self.raw_recorded_at,
            "reconciliation raw_recorded_at",
        )
        authenticated_at = _require_utc(
            self.authenticated_at,
            "reconciliation authenticated_at",
        )
        source_committed_at = _require_utc(
            self.source_committed_at,
            "reconciliation source_committed_at",
        )
        if not (received_at <= raw_recorded_at <= authenticated_at <= source_committed_at):
            raise BrokerReconciliationError("reconciliation source trusted-time order is invalid")

        inconclusive = self.outcome is BrokerReconciliationOutcome.INCONCLUSIVE_NOT_VISIBLE
        order_scalars = (
            self.provider_order_id,
            self.provider_order_status,
            self.provider_replaced_by,
            self.provider_replaces,
            self.observed_provider_asset_id,
            self.requested_quantity,
            self.requested_notional,
            self.cumulative_filled_quantity,
            self.cumulative_filled_average_price,
            self.provider_source,
        )
        if inconclusive:
            if (
                self.http_status != 404
                or any(value is not None for value in order_scalars)
                or self.mismatch_fields
                or self.provider_timestamps
            ):
                raise BrokerReconciliationError(
                    "inconclusive not-visible evidence cannot invent an observed order"
                )
            return
        if (
            self.http_status != 200
            or self.provider_order_id is None
            or self.provider_order_status is None
            or self.cumulative_filled_quantity is None
            or not self.provider_timestamps
            or self.provider_timestamps[0].field_name != "created_at"
            or (self.requested_quantity is None) == (self.requested_notional is None)
        ):
            raise BrokerReconciliationError("observed-order reconciliation evidence is incomplete")
        if (
            self.requested_quantity is not None
            and self.cumulative_filled_quantity > self.requested_quantity
        ):
            raise BrokerReconciliationError(
                "reconciliation cumulative fill exceeds observed quantity"
            )
        if self.outcome is BrokerReconciliationOutcome.ORDER_OBSERVED_CANDIDATE and (
            self.mismatch_fields
            or self.observed_provider_asset_id != self.expected_provider_asset_id
        ):
            raise BrokerReconciliationError(
                "order-observed candidate cannot retain a known mismatch"
            )
        if self.outcome is BrokerReconciliationOutcome.QUARANTINED_ECONOMIC_MISMATCH and (
            not self.mismatch_fields
            or self.observed_provider_asset_id != self.expected_provider_asset_id
        ):
            raise BrokerReconciliationError(
                "economic quarantine requires matched security and economic mismatches"
            )
        if (
            self.outcome is BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH
            and self.observed_provider_asset_id == self.expected_provider_asset_id
        ):
            raise BrokerReconciliationError(
                "security quarantine requires a null or different provider asset ID"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_RECONCILIATION_CONTRACT_VERSION,
            "broker_reconciliation_evidence",
            self.account_id,
            self.provider_id,
            self.environment,
            self.attempt_id,
            self.order_id,
            self.client_order_id,
            self.instrument_id,
            self.symbol,
            self.outcome,
            self.expected_provider_asset_id,
            self.provider_order_id,
            self.provider_order_status,
            self.provider_replaced_by,
            self.provider_replaces,
            self.observed_provider_asset_id,
            self.mismatch_fields,
            tuple(
                (
                    timestamp.field_name,
                    timestamp.raw,
                    timestamp.normalized_utc,
                    timestamp.nanosecond,
                    timestamp.semantic_sha256,
                )
                for timestamp in self.provider_timestamps
            ),
            self.requested_quantity,
            self.requested_notional,
            self.cumulative_filled_quantity,
            self.cumulative_filled_average_price,
            self.provider_source,
            self.source_lookup_receipt_id,
            self.source_lookup_receipt_sha256,
            self.source_ingress_receipt_id,
            self.source_ingress_receipt_sha256,
            self.source_ingress_sequence,
            self.source_delivery_idempotency_key,
            self.source_observation_sha256,
            self.source_body_sha256,
            self.http_status,
            self.provider_request_id,
            self.received_at,
            self.raw_recorded_at,
            self.authenticated_at,
            self.source_committed_at,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True, init=False)
class BrokerReconciliationFact:
    """One immutable account-local append of non-applying evidence."""

    evidence: BrokerReconciliationEvidence
    normalized_at: datetime
    account_sequence: int
    previous_fact_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("BrokerReconciliationFact must be repository-produced")

    def _validate(self) -> None:
        if type(self.evidence) is not BrokerReconciliationEvidence:
            raise BrokerReconciliationError(
                "reconciliation fact requires exact normalized evidence"
            )
        self.evidence.__post_init__()
        normalized_at = _require_utc(
            self.normalized_at,
            "reconciliation normalized_at",
        )
        if normalized_at < self.evidence.source_committed_at:
            raise BrokerReconciliationError(
                "reconciliation normalization cannot precede its source commit"
            )
        if type(self.account_sequence) is not int or self.account_sequence <= 0:
            raise BrokerReconciliationError("reconciliation account sequence must be positive")
        if self.account_sequence == 1:
            if self.previous_fact_sha256 is not None:
                raise BrokerReconciliationError(
                    "first reconciliation fact cannot have a predecessor"
                )
        elif self.previous_fact_sha256 is None:
            raise BrokerReconciliationError("later reconciliation facts require a predecessor")
        _require_optional_sha256(
            self.previous_fact_sha256,
            "reconciliation predecessor digest",
        )

    @property
    def fact_id(self) -> str:
        return canonical_id(
            "broker-reconciliation-fact",
            self.evidence.provider_id,
            self.evidence.environment,
            self.evidence.source_lookup_receipt_id,
        )

    @property
    def receipt_id(self) -> str:
        """Compatibility name for repositories that expose append receipts."""

        return self.fact_id

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_RECONCILIATION_CONTRACT_VERSION,
            "broker_reconciliation_fact",
            self.fact_id,
            self.evidence.semantic_sha256,
            self.normalized_at,
            self.account_sequence,
            self.previous_fact_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _broker_reconciliation_fact(
    evidence: BrokerReconciliationEvidence,
    *,
    normalized_at: datetime,
    account_sequence: int,
    previous_fact_sha256: str | None,
) -> BrokerReconciliationFact:
    """Construct the append fact a durable repository must authenticate."""

    if type(evidence) is not BrokerReconciliationEvidence:
        raise BrokerReconciliationError("reconciliation fact construction requires exact evidence")
    fact = object.__new__(BrokerReconciliationFact)
    object.__setattr__(fact, "evidence", evidence)
    object.__setattr__(fact, "normalized_at", normalized_at)
    object.__setattr__(fact, "account_sequence", account_sequence)
    object.__setattr__(fact, "previous_fact_sha256", previous_fact_sha256)
    fact._validate()
    return fact


class BrokerReconciliationRepository(Protocol):
    """Durably append and authenticate non-applying reconciliation facts."""

    def record(
        self,
        evidence: BrokerReconciliationEvidence,
    ) -> BrokerReconciliationFact:
        """Append exact evidence or return its identical durable retry."""

    def load(self, fact_id: str) -> BrokerReconciliationFact | None:
        """Load one authenticated fact by deterministic identity."""

    def history(self, account_id: str) -> tuple[BrokerReconciliationFact, ...]:
        """Return the authenticated account-local fact chain."""


__all__ = [
    "BROKER_RECONCILIATION_CONTRACT_VERSION",
    "BrokerProviderTimestampEvidence",
    "BrokerReconciliationConflict",
    "BrokerReconciliationError",
    "BrokerReconciliationEvidence",
    "BrokerReconciliationFact",
    "BrokerReconciliationOutcome",
    "BrokerReconciliationRepository",
]
