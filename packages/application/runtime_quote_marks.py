"""Normalize admitted side quotes for risk, without claiming execution or authority.

Source qualification fields and producer pins are retained declarations. The
account transaction must authenticate their actual source bytes and evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.application.personal_forward_data import quote_admission
from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardObservation,
    ForwardQuote,
    ForwardRequirement,
    ForwardSource,
    SourceEnvironment,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import (
    CausalMark,
    ContractRecord,
    VersionPin,
    content_digest,
)


@dataclass(frozen=True, slots=True)
class RuntimeQuoteMarkRequest(ContractRecord):
    contract_version: ClassVar[str] = "personal-runtime-quote-mark/1"
    observation: ForwardObservation
    source: ForwardSource
    expected: ForwardRequirement
    side: Side
    producer: VersionPin

    def __post_init__(self) -> None:
        super(RuntimeQuoteMarkRequest, self).__post_init__()
        if self.expected.kind != "quote":
            raise ValueError("runtime quote mark requires a quote scope")


def build_runtime_quote_marks(
    requests: tuple[RuntimeQuoteMarkRequest, ...],
    *,
    environment: SourceEnvironment,
    account_scope: str,
    evaluated_at: datetime,
    boot_id: str,
    evaluated_monotonic_ns: int,
) -> tuple[CausalMark, ...]:
    """Return ≤4 distinct instrument marks after all quote checks pass.

    BUY uses ask/ask_at and SELL uses bid/bid_at. Knowledge is the original
    validated capture availability. Rechecking never changes mark identity/time.
    """
    if type(requests) is not tuple or not 1 <= len(requests) <= 4:
        raise ValueError("runtime quote requests must be a bounded immutable tuple")
    if any(type(request) is not RuntimeQuoteMarkRequest for request in requests):
        raise ValueError("runtime quote requests require the exact input version")
    instruments = tuple(request.expected.instrument_id for request in requests)
    if len(instruments) != len(set(instruments)):
        raise ValueError("runtime quote marks cannot repeat an instrument")
    marks = []
    for request in sorted(requests, key=lambda request: request.expected.instrument_id):
        request.__post_init__()
        admission = quote_admission(
            request.observation,
            request.source,
            expected=request.expected,
            environment=environment,
            account_scope=account_scope,
            evaluated_at=evaluated_at,
            boot_id=boot_id,
            evaluated_monotonic_ns=evaluated_monotonic_ns,
        )
        if not admission.eligible:
            raise ValueError("runtime quote unavailable: " + ",".join(admission.reasons))
        quote, receipt = request.observation.payload, request.observation.availability
        if type(quote) is not ForwardQuote or type(receipt) is not CaptureReceipt:
            raise ValueError("runtime quote requires exact captured quote records")
        price = quote.ask if request.side is Side.BUY else quote.bid
        economic_at = quote.ask_at if request.side is Side.BUY else quote.bid_at
        assert price is not None and economic_at is not None
        provenance = request.semantic_sha256
        marks.append(
            CausalMark(
                mark_id=content_digest(("personal-runtime-quote-mark/1", provenance)),
                instrument_id=quote.instrument_id,
                symbol=quote.symbol,
                price=price,
                session=quote.session,
                economic_at=economic_at,
                knowledge_at=request.observation.known_at,
                source_sha256=provenance,
                basis="runtime_quote_ask_v1"
                if request.side is Side.BUY
                else "runtime_quote_bid_v1",
            )
        )
    return tuple(marks)
