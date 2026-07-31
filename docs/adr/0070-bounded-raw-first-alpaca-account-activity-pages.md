# ADR 0070: bounded raw-first Alpaca account-activity pages

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4AC makes the existing UNKNOWN-lookup evidence path restart-safe, but the
reconciliation barrier still needs an independent source of broker-reported
fill activity. Alpaca's Trading API exposes
`GET /v2/account/activities`, supports an `activity_types` filter, orders
results by activity time, limits a page to at most 100 entries, and accepts the
last activity ID from one page as the next page's `page_token`.

Those cursor semantics do not provide snapshot isolation, a provider revision,
or a cross-channel identity. Activity can arrive while pages are traversed,
and an activity occurrence does not by itself establish the canonical
execution, correction, fee, or order-lifecycle fact required by the reducer.
The system must therefore retain exact response bytes before interpretation,
apply a strict versioned local FILL profile, reject ambiguous page overlap, and
make terminal pagination evidence distinct from a locally truncated walk.

Reviewed provider references:

- [Retrieve Account Activities](https://docs.alpaca.markets/us/reference/getaccountactivities-2)
- [Trading API OpenAPI contract](https://docs.alpaca.markets/us/openapi/trading-api.json)

## Decision

1. Define Phase 4AD as a local, non-I/O Alpaca paper account-activity page
   contract. It introduces no credential resolver, HTTP runtime, deployed
   worker, schedule, SQL table, startup composition, or broker authority.
2. Freeze one request profile:
   - `GET https://paper-api.alpaca.markets/v2/account/activities`;
   - `activity_types=FILL`;
   - `direction=asc`;
   - an explicit `page_size` from 1 through 100;
   - no `category`, `date`, `after`, or `until` filter;
   - page one has no `page_token`; and
   - every later page uses the exact, unmodified final activity ID from the
     preceding full page as `page_token`.
3. Bound one immutable traversal to at most eight pages, at most
   `8 * page_size` activities and no more than 800 activities. Each response
   body is limited by the Phase 4C one-mebibyte raw-ingress ceiling, and the
   aggregate retained body size is at most eight mebibytes. Overflow is an
   explicit failure; no body or item array is silently truncated.
4. Derive a distinct reconciliation-purpose Phase 4D demand for each page.
   Its stable identity and correlation bind the capture, page number,
   predecessor page digest, exact requested page size, and exact page token or
   its page-one absence. The description is demand evidence only: it neither
   allocates a permit nor authorizes transport.
5. Route every representable response through the durable Phase 4C
   broker-ingress recorder before UTF-8, JSON, status, or provider-field
   decoding. The receipt retains exact bytes and digest, HTTP status, request
   description, provider request ID when present, and trusted receive/record
   times. A non-200 response, missing required metadata, or decoder failure
   grants no typed page; its independently committed raw receipt remains
   diagnostic evidence.
6. Accept only an HTTP 200 JSON array under a versioned local FILL profile.
   Reject malformed UTF-8 or JSON, non-standard constants, duplicate object
   keys at any depth, a non-array top level, non-object items, unknown keys,
   missing keys, wrong JSON types, or an `activity_type` other than exact
   `FILL`.
7. Freeze the local FILL object to exactly these string-valued keys:
   `activity_type`, `cum_qty`, `id`, `leaves_qty`, `order_id`,
   `price`, `qty`, `side`, `symbol`, `transaction_time`, and `type`. This is
   an intentionally narrow reviewed acceptance profile, not a claim that
   Alpaca cannot return a new or different FILL shape. Additive or semantic
   drift must be reviewed and versioned before typed admission.
8. Validate the accepted values strictly:
   - `id` is a bounded, nonempty opaque provider activity-ID lexeme suitable
     for exact cursor reuse, and `order_id` is a bounded canonical UUID lexeme;
   - `side` is exact `buy` or `sell`, `type` is exact `fill` or
     `partial_fill`;
   - `symbol` is a bounded, nonempty exact lexeme and is not a security-master
     binding;
   - `transaction_time` uses the pinned offset-aware RFC 3339 grammar with at
     most nanosecond precision, rejects the unknown `-00:00` offset, and parses
     to one UTC instant; and
   - `price`, `qty`, `cum_qty`, and `leaves_qty` use a plain-decimal grammar
     with at most 18 integral and 18 fractional digits and no sign prefix,
     exponent, `NaN`, infinity, leading decimal point, or trailing decimal
     point. Price, page quantity, and cumulative quantity are positive; leaves
     quantity is nonnegative.
9. Retain every accepted activity ID, order ID, timestamp, and decimal lexeme
   exactly alongside its parsed value. Parsing cannot trim, case-fold,
   reformat, round, or otherwise manufacture identifier or retry equality.
   Numeric JSON tokens and booleans are not substitutes for the required
   decimal strings.
10. Validate ordering and overlap before extending a typed chain:
    - transaction instants are nondecreasing within and across pages;
    - activity IDs are unique within each page and across the whole chain;
    - a later request's token equals the preceding page's exact final activity
      ID, while that token activity cannot recur in the later page;
    - page numbers, raw-ingress receipt sequences, and trusted receive times
      cannot regress; and
    - activity IDs are never treated as lexicographically ordered clocks.
      Equal timestamps and economically identical activities with different
      IDs retain provider array order and remain distinct observations rather
      than being deduplicated.
11. Emit explicit traversal-boundary evidence. A page shorter than the exact
    requested page size, including an empty page, sets pagination exhaustion
    only for that cursor walk. A full page that reaches either the configured
    page or item ceiling sets bounded truncation and retains the page's exact
    continuation token; it can never be reported as exhausted. Neither result
    proves that the account's activity history is complete, isolated, or
    current.
12. Bind every typed page and traversal result to the exact raw receipt,
    request description, predecessor digest, ordered item digests, counts,
    total retained bytes, and terminal-or-truncated evidence. The chain is an
    immutable local capture and not a provider snapshot or revision.
13. Keep every authority false. Phase 4AD cannot create a canonical execution,
    fee, bust, correction, or lifecycle revision; deduplicate REST and stream
    evidence; apply a broker fact; resolve `UNKNOWN`; release a reservation;
    qualify reconciliation; establish readiness; authorize a broker call; or
    cause a paper or live trading effect.

## Consequences

The repository now has a bounded, raw-first specification for ascending FILL
activity pages that preserves exact source lexemes and makes local pagination
exhaustion distinguishable from a safety-bound truncation. Strict failures
remain diagnosable from the raw journal, and duplicate or overlapping activity
IDs cannot silently become typed evidence.

Phase 4AD is implemented only as a bounded local adapter contract with typed
models, strict decoder/chain validation, and fixture-driven tests. Persistence,
authenticated single-use transport, restart-safe traversal, stream overlap and
cross-channel identity rules, execution/correction qualification,
authoritative application, two-view convergence, and startup composition
remain open. Phase 4 and its exit gate remain open.
