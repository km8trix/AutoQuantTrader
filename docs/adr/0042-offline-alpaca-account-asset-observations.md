# ADR 0042: offline Alpaca account and asset observations

- Status: Accepted
- Date: 2026-07-27

## Context

The Phase 4A order compiler deliberately leaves current broker account state,
provider asset identity, and asset tradability unresolved. Phase 4B qualifies a
single client-order lookup shape, Phase 4C retains raw broker deliveries before
decoding, and Phase 4D allocates durable request capacity. None of those slices
can prove that an authenticated paper account is presently allowed to trade or
that one of the candidate DIA, IWM, QQQ, and SPY symbols presently identifies
an active, tradable U.S. equity at Alpaca.

Those missing observations are prerequisites to a truthful dispatch preflight.
A preflight built from caller-supplied booleans would turn an untrusted claim
into readiness evidence. Performing authenticated requests now would instead
skip unresolved credential, transport, freshness, reconciliation, and startup
gates. The next slice must therefore qualify exact response shapes while
remaining offline and non-authorizing.

Alpaca documents `GET /v2/account` as the account-information endpoint and
documents account status plus explicit account, trading, transfer, and
user-suspension flags. It documents
`GET /v2/assets/{symbol_or_asset_id}` as returning an Asset object or `404`, and
its Asset examples distinguish class, exchange, symbol, status, and tradability
from margin, shorting, borrowing, and fractional attributes. The Trading API
also returns an `X-Request-ID` response header that should be retained.

## Decision

1. Define Phase 4E as a pure, non-I/O Alpaca paper account/asset observation
   boundary. Deterministic request descriptions bind the Phase 4A adapter,
   paper environment, capability digest, local account alias, exact operation
   and path, and, for assets, one exact candidate instrument/symbol pair from
   the fixed DIA/IWM/QQQ/SPY map. Constructing or decoding a description never
   resolves a credential or performs a request.
2. Decode only bounded exact bytes through versioned, deliberately narrow
   accepted wire profiles. Reject an empty or oversized body, non-UTF-8 input,
   duplicate JSON keys, non-object roots, missing or unknown fields, wrong
   primitive types, malformed canonical UUIDs, malformed timestamps or decimal
   text, and unreviewed enum values. A future additive provider field therefore
   remains raw evidence but cannot silently broaden the trusted local profile.
   Pin the accepted model and enum evidence to Alpaca Python SDK commit
   `bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f`; mutable documentation URLs are
   supporting context, not the reproducible schema pin.
3. Retain the exact response body, byte count and SHA-256 digest, HTTP status,
   provider request ID, receipt time, and normalized observation digest. The
   Phase 4C wrapper must commit the raw delivery first and only then invoke the
   typed decoder. A decoder failure cannot erase its input.
4. An account observation retains the provider account UUID, equity-account
   status, currency, creation timestamp, and explicit account/trading/transfer/
   user-suspension and related reviewed flags. `ACTIVE`, `USD`, and all trading
   blockers being false may produce a locally usable-candidate observation;
   any other reviewed combination remains explicit fail-closed evidence.
   Treat `transfers_blocked` as an intentionally conservative local blocker
   even though the provider defines it for money transfers.
   Balances, buying power, margins, market values, and transfer amounts in the
   accepted response profile are validated and retained only through the exact
   raw body. They are not canonical economics, capacity, ledger state, or risk
   authority. The provider removed `pattern_day_trader`, `daytrade_count`, and
   `daytrading_buying_power` from responses on 2026-07-06; accept those only as
   absent/null or strictly typed legacy fields, never as readiness inputs.
   Validate the current options buying-power and approved/effective level fields
   as retained-only optional data.
5. The provider account UUID is an observed value, not an authenticated durable
   binding to the local account alias. Neither the response object nor a caller
   may assert its environment. Paper provenance comes only from the
   description and the raw ingress envelope; a later authenticated transport,
   credential binding, and reconciliation flow must establish identity and
   freshness.
6. An asset observation retains the provider asset UUID, class, exchange,
   symbol, name, status, tradability, and the reviewed margin, shorting,
   borrowing, fractional, maintenance-margin, and attribute fields. Name,
   maintenance margin, attributes, and the crypto-oriented minimum-size/
   increment fields are optional in the pinned SDK profile; if present they
   receive strict retained-only validation. A locally usable-candidate outcome
   requires the response symbol to equal the exact requested candidate mapping,
   a reviewed listed-U.S. exchange, `us_equity`, `active`, `tradable`, and no
   provider restriction attribute requiring review. A symbol mismatch,
   recognized but ineligible exchange, non-U.S.-equity class, inactive status,
   non-tradable flag, or recognized non-empty PTP attribute remains explicit
   fail-closed evidence; an unknown exchange or attribute fails decoding.
   `fractionable`, `shortable`, `marginable`, or `easy_to_borrow` never expands
   v1 beyond whole-share, long-only candidate trading.
7. A strictly profiled asset `404` is inconclusive evidence that the requested
   candidate was not visible to that response. It does not prove permanent
   absence, authorize a remap, or permit dispatch.
8. Cross-bind every successfully decoded account or asset observation to its
   exact Phase 4C receipt: account, provider, adapter version, paper
   environment, channel, operation, description digest, status, request ID,
   receipt time, and body must all agree.
9. Checked-in examples are documentation-derived or otherwise explicitly
   unqualified synthetic fixtures. They may exercise the deterministic
   contracts but are not authenticated paper-account captures, current runtime
   observations, provider-account bindings, or durable security-master facts.
10. Add no normalized provider-fact table or migration in this slice. Stable
    identities, revisions, event ordering, snapshot overlap, quarantine, and
    application receipts still need broader stream/snapshot/reconciliation
    contracts. Raw ingress remains the only durable broker evidence.
11. Keep every credential, transport, lookup scheduling, account/security
    readiness, reconciliation, dispatch, startup, normalized-fact, lifecycle,
    execution, and trading-effect authority false. A later dispatch preflight
    must consume authenticated, freshness-bounded account and asset evidence;
    these offline contracts cannot satisfy that requirement by themselves.

## Consequences

The repository can now freeze and adversarially test the account and asset
shapes needed by a future authenticated paper transport without pretending
that synthetic JSON is current broker truth. Schema drift and blocked or
mismatched states fail closed, while the exact raw response remains available
for review.

Phase 4E does not resolve secrets, call Alpaca, bind a provider account, create
a security master, prove observation freshness, establish an exchange session,
prove a sell reduce-only, normalize broker facts, reconcile state, dispatch an
order, or enable paper/live startup. Phase 4 and its exit gate remain open.

## Reviewed provider references

Reviewed on 2026-07-27:

- <https://docs.alpaca.markets/us/v1.1/docs/working-with-account>
- <https://docs.alpaca.markets/us/v1.1/docs/account-plans>
- <https://docs.alpaca.markets/us/v1.1/docs/accounts-statuses>
- <https://docs.alpaca.markets/us/reference/get-v2-assets-symbol_or_asset_id>
- <https://docs.alpaca.markets/us/docs/market-data-faq>
- <https://docs.alpaca.markets/us/docs/getting-started-with-trading-api>
- <https://raw.githubusercontent.com/alpacahq/alpaca-py/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/enums.py>
- <https://raw.githubusercontent.com/alpacahq/alpaca-py/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/models.py>
