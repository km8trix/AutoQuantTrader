# ADR 0050: bounded raw-first Alpaca order-snapshot pages

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4L accounts durably for one source-scoped historical lookup, but the
reconciliation barrier also needs bounded order-list traversal. Alpaca's
Trading API exposes `GET /v2/orders` with a maximum page limit of 500 and
supports mutually exclusive order-ID cursors. The reviewed OpenAPI contract
permits a descending traversal using `before_order_id`, but does not provide
snapshot isolation or a provider revision that makes several pages one atomic
view.

Treating a short last page as an authoritative broker snapshot would therefore
be unsafe. Orders may be created or change while the client walks the cursor,
and a list occurrence does not establish a cross-channel event, execution,
bust, or correction identity. The system must retain every response before
strict interpretation and must bound both provider demand and local work.

Reviewed provider references:

- [Get All Orders](https://docs.alpaca.markets/us/v1.1/reference/getallorders-1)
- [Trading API OpenAPI contract](https://docs.alpaca.markets/us/openapi/trading-api.json)

## Decision

1. Define Phase 4M as a pure, non-I/O Alpaca paper order-page contract. It
   introduces no credential resolution, HTTP runtime, worker, schedule, or
   startup composition.
2. Freeze one request profile:
   - `GET https://paper-api.alpaca.markets/v2/orders`;
   - `status=all`;
   - `direction=desc`;
   - `nested=false`;
   - `asset_class=us_equity`;
   - a page limit from 1 through the reviewed provider maximum of 500;
   - no caller-supplied time cursor or `after_order_id`;
   - page one has no order-ID cursor; and
   - each later page uses only the exact final provider order ID from the
     preceding full page as `before_order_id`.
3. Bound one immutable traversal to at most eight pages. A short page,
   including an empty page, marks only pagination exhaustion for that exact
   cursor chain. A full eighth page is bounded truncation and can never be
   reported as exhaustion.
4. Derive a distinct reconciliation-purpose Phase 4D demand for each page and
   bind its correlation to the exact page description. This evidence neither
   allocates a permit nor authorizes transport; `request_budget_enforced`
   remains false in Phase 4M.
5. Route each representable response through the Phase 4C broker-ingress
   recorder before decoding. The raw receipt binds the exact account, adapter,
   paper environment, channel, operation, request correlation, status,
   provider request ID when present, trusted times, and response bytes. A
   missing request ID or decoder failure occurs only after the raw receipt was
   committed.
6. Decode retained HTTP 200 JSON arrays through the frozen Phase 4B order
   observation profile. Reject malformed UTF-8/JSON, duplicate object keys,
   non-object items, unknown or drifted order shapes, pages over the requested
   limit, duplicate provider order IDs, and non-descending submission times.
   Decoder rejection grants no typed page; the independent raw receipt remains
   durable.
7. Bind every typed page to its exact raw receipt and predecessor page digest.
   Page numbers and ingress receipt sequences must advance, receive time cannot
   regress, the cursor must be the exact preceding terminal order ID, and
   provider order IDs cannot overlap within the accepted typed chain.
8. Preserve the page bytes, digest, strict order observations, and provider
   request ID without promoting them to a provider revision or canonical fact.
   The page chain is an immutable local capture, not a durable application
   workflow or an isolated provider snapshot.
9. Keep all authority false. Phase 4M cannot establish snapshot isolation or
   convergence, deduplicate stream and snapshot sources, normalize or admit a
   broker fact, apply an order lifecycle, create an execution/fee/correction,
   resolve `UNKNOWN`, complete reconciliation, authorize a broker call, or
   cause a trading effect.
10. Keep `order_snapshot_pagination_ready` and every paper/live readiness flag
    false. An authenticated runtime must separately allocate and revalidate a
    purpose-matched permit, hold the current account fence, use the restricted
    raw-first transport, and define restart-safe traversal ownership before
    this contract can make a provider request.

## Consequences

The repository can now describe, retain, strictly decode, and validate the
local structure of a bounded descending order-page chain without mistaking cursor
exhaustion for broker truth. Malformed or drifting provider responses remain
available in the raw journal for diagnosis, and no traversal can consume
unbounded memory or request capacity.

Authenticated page transport, restart-safe durable traversal state, account,
position and activity snapshots, stream buffering/resume, provider-qualified
revision/execution/correction identities, cross-channel deduplication,
authoritative application, two-view convergence, and the Phase 4 paper gate
remain open.
