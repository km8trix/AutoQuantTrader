# ADR 0123: Injected E\*TRADE OAuth token runtime prerequisite

- Status: Accepted
- Date: 2026-08-26
- Extends: [ADR 0096](0096-etrade-live-broker-and-sandbox-qualification.md),
  [ADR 0118](0118-pure-etrade-oauth1-signing-and-supervised-session.md), and
  [ADR 0120](0120-durable-etrade-oauth-replay-session-head.md)

## Context

ADR 0118 can construct one exact OAuth 1.0a signature and advance a sanitized
in-memory replay guard. ADR 0120 can durably authenticate the sanitized replay
and session prefix, but deliberately accepts no credentials, signed request,
transport, or provider response. The next bounded prerequisite is a runtime
composition that proves how ephemeral resolution, signing, a durable
pre-transport replay burn, and raw-first token-response custody fit together
without adding a deployed secret store or a provider caller.

This composition has two distinct ambiguity boundaries. First, ADR 0120's
ordinary exact-retry behavior intentionally converges. That is appropriate for
durable evidence but cannot by itself tell a transport caller whether the same
signed request was already dispatched. Second, after a transport response is
received, this slice has no secret store that can commit the token values before
the sanitized session head names their nonsecret reference. Advancing the
session first would make a missing token look active; storing the token first
can leave an orphan if the later state compare-and-swap loses. Therefore this
slice may burn a fresh signing replay fact before its injected transport, but
it cannot safely commit a successful session transition or support any real
provider transport.

Token responses are themselves credential material. A raw-body digest,
ordinary response DTO, useful representation, exception detail, log field, or
SQL row could become a secret-derived artifact even if the decoded token fields
were omitted. Raw-first handling here must consequently mean exact bytes are
retained before decode inside an explicit ephemeral custody boundary, not that
those bytes or their digest are durable evidence.

## Decision

1. Implement Phase 4AN in
   `packages/application/etrade_oauth_token_runtime.py` under contract
   `phase4an-injected-etrade-oauth-token-runtime-prerequisite-v1`. It is an
   application composition over the exact ADR-0118 types and a store-issued
   ADR-0120 currentness/reservation capability; it does not accept a
   free-floating durable snapshot or a caller-selected coordinator. It has no
   CLI, API, worker, trader, scheduler, service
   registration, concrete resolver, concrete TLS client, or provider caller.
   The module imports no `httpx`, `requests`, socket, subprocess, filesystem,
   logging, or browser implementation.
2. Support only the request-token and access-token operations. The intent must
   preserve ADR 0118's exact `GET`, shared token endpoint, environment,
   endpoint-profile, consumer-reference scope/revision, generation, trusted
   timestamp, nonce, and—only for access exchange—the exact active
   request-token reference, confirmed-state identity, verifier object, and
   one-use capability. The output request/access token reference must use the
   matching environment and token scope, the exact lifecycle kind, and exactly
   the next session reference revision. Renewal, revocation, browser/OOB
   handoff, callback handling, and arbitrary methods, endpoints, parameters,
   URLs, queries, or headers remain unsupported.
3. Define one injected secret-resolver port with the fixed nonsecret identity
   `injected-ephemeral-etrade-oauth-secret-resolver` version `1.0.0`. Its sole
   private operation receives a secret-free request bound to the exact freshly
   replay-reserved ADR-0120 scope, event, sequence, state, replay guard, and
   signing intent. A
   test resolver can return only the proof-constructed opaque envelope from
   `create_etrade_oauth_token_secret_envelope`. The envelope binds the exact
   resolution request and consumer/token references, is one-use,
   context-managed, redacted, non-copyable, non-serializable, explicitly
   closable, and owns mutable bytearray copies that are overwritten on close. A
   closed, reused, cross-request, wrong-reference, wrong-revision,
   wrong-environment, malformed, or foreign envelope fails with constant
   secret-free errors.
4. Export the pure `authenticate_etrade_oauth_durable_snapshot` persistence
   function. It reconstructs the complete prefix from the exact initial state,
   applies every replay delta, revalidates every closed state edge, recomputes
   every state payload/digest and event payload/digest, checks predecessor and
   replay prefixes, and requires the exact final state, guard, sequence, and
   root. SQL load, ordinary advance, capability issuance/reservation, and the
   runtime all use this complete authenticator; shallow cursor equality is not
   a currentness proof.
5. `SqlEtradeOAuthCoordinator` alone may issue an
   `EtradeOAuthTokenRuntimeCurrentnessReservation` from its own authenticated
   load. The capability retains an unforgeable per-coordinator store identity,
   is process-bound at issuance, binds to the one claiming thread, is locked,
   sealed, one-claim/one-reservation, redacted, non-copyable, and
   non-serializable. Its private reservation operation can call only the
   issuing coordinator and requires the exact authenticated prefix and exact
   request/access signing intent. A store-A snapshot paired with store B, a
   stale prefix, a closed edge, a reused capability, or a cross-thread reserve
   fails before secret resolution or transport.
6. After secret-free preflight, use that capability to append the exact
   ADR-0120 signing replay-only event while the sanitized session state remains
   unchanged, before resolving, signing, or consuming an access-exchange
   verifier capability. Add the keyword-only `allow_exact_retry` option to
   `SqlEtradeOAuthCoordinator.advance`, defaulting to `true` so ADR 0120 and
   every existing caller retain their exact convergent retry semantics. Only
   the private store-bound reservation path calls it with
   `allow_exact_retry=false`. Under the existing SQL write lock this fresh-only
   call rejects an already-current identical event, proves the exact returned
   prefix and delta, and prevents the same signed intent from reaching the
   injected transport twice. Durable failure occurs before resolution,
   signing, verifier consumption, or transport. Resolver/signing/transport
   failure can leave this secret-independent replay fact committed, but cannot
   advance the session state. For access exchange, the runtime first obtains a
   locked, non-consuming reservation from the exact authorization capability.
   Reservation requires an unused capability and the exact supplied verifier
   object; it is released on every pre-consumption failure and passed opaquely
   to the signer for eventual one-use consumption. Thus an already-consumed,
   concurrently reserved, or distinct-but-equal verifier fails before the
   durable replay burn or secret resolution without consuming an otherwise
   valid capability.
7. Define one injected transport port with the exact identity
   `injected-fake-etrade-oauth-token-transport` version `1.0.0`. Freeze its
   metadata and exact bound method once before resolving secrets. It receives
   only a privately issued `EtradeOAuthEphemeralTransportRequest`: a redacted,
   non-serializable, locked one-presentation capability around the sealed
   ADR-0118 signing result. Its request, method, endpoint, environment, durable
   scope/event/sequence/state, replay guard, and timeout bindings are private,
   read-only, cached, and sealed by an immutable binding identity. The runtime
   validates them immediately before and after the injected call, and a raw
   response derives its structural binding only from those sealed cached
   values. It has no ordinary Authorization-header getter, URL/query
   serializer, network-send method, or concrete implementation. Synthetic
   transports may use the private, test-only constant-time header predicate to
   check a frozen signing vector and must bind their raw response to that exact
   request object through `create_etrade_oauth_injected_token_response`. The
   request owns a newly constructed raw response until the runtime completes a
   successful result transfer, so a transport that raises after construction
   cannot strand the runtime-owned mutable custody buffer. Before dispatch, the
   runtime also retains an independent private witness outside the
   transport-visible object graph: the exact intent identity and evidence,
   signing-result identity, sealed request binding, pre-reservation guard, and
   replay-only head. After return it compares that witness, re-derives the
   replay guard from the original head, and rejects even if a transport mutates
   intent/request fields and recomputes every attacker-visible unkeyed seal.
8. The injected response profile requires the exact shared token origin
   `https://api.etrade.com`, terminal HTTP status `200`, media type
   `application/x-www-form-urlencoded`, charset `utf-8`, a complete body of
   1-4,096 bytes, a positive TLS-peer-verification declaration, no followed or
   offered redirect, no proxy use, no timeout, and no transport error.
   Opposite origin, status/media/charset drift, redirect/proxy ambiguity,
   incomplete delivery, timeout/error flags, foreign request identity, or a
   non-proof-constructed response fails closed. These declarations and object
   bindings prove only the injected contract. They do not authenticate a real
   TLS channel, provider process, provider origin, production trust root, or
   response provenance.
   Raw-response construction, request presentation/ownership transfer, reads,
   and close are lock-protected so racing factories have exactly one winner.
   Every open/read/transfer validation rechecks that body custody remains an
   exact bytearray within the 1-4,096-byte bound; post-factory type replacement
   or out-of-bound expansion fails without adding a body hash or length to
   sanitized evidence.
9. Retain the exact raw body in private, context-managed, non-copyable mutable
   custody before strict decode.
   Request-token responses contain exactly one each of `oauth_token`,
   `oauth_token_secret`, and `oauth_callback_confirmed=true`; access-token
   responses contain exactly the two token fields. Reject empty/oversized
   bodies, malformed form structure or percent encoding, duplicate, missing,
   or unknown fields, non-ASCII/control/whitespace material, callback drift,
   and operation/schema mismatch. Do not accept Cookie, Set-Cookie, arbitrary
   response headers, provider request identifiers, credential-bearing URLs or
   query material into the response model.
10. Return a privately issued and sealed
   `EtradeOAuthEphemeralTokenExchangeResult` with the still-retained raw
   body, decoded token bytes, exact nonsecret output reference, replay-only
   snapshot, proposed pure successor state, and sanitized receipt. The result
   is context-managed, redacted, non-copyable, non-serializable, has no token,
   token-secret, raw-body, Authorization, Cookie, URL, query, or response-digest
   getter, and overwrites its mutable raw/decoded copies on close. Its only
   token-value check is a private one-shot constant-time synthetic-test
   predicate that closes custody. A future secret-store transfer needs a
   separate reviewed capability; no ordinary getter or persistence callback is
   introduced here. Result claim/consume/close is lock-protected and one-shot;
   its receipt, replay snapshot, proposed successor, and output reference are
   private fields exposed only through validating read-only properties. Every
   such property repeats the complete receipt-to-replay-to-successor-to-output-
   reference-to-raw-structural-binding cross-check and compares the initial
   receipt and raw-binding identities, so substituting another individually
   valid receipt cannot create a mixed result product.
11. The sanitized receipt is `init=False` and only the private runtime issuer
   can construct it. It binds provider, environment, operation, signing
   intent, durable scope/replay event/sequence/guard, output reference, exact
   resolver/transport/profile metadata, and a secret-independent structural
   response binding. It explicitly excludes the raw body, body digest, decoded
   values, value digests, signature, Authorization header, verifier, Cookie,
   credential-bearing URL/query, and secret-dependent request metadata.
   Changing only consumer/token inputs or raw response token values cannot
   change the receipt digest. The receipt may say the sealed signed-request
   capability was presented and the injected request/response objects were
   structurally bound; `provider_origin_authenticated` remains false. Its
   environment, operation, and output token reference kind/scope/revision are
   cross-validated, and callers cannot synthesize or mutate a receipt.
12. Do not advance the proposed request/access-token session successor. A
    pre-transport replay-only event is durable; a transport failure or decode
    failure leaves the durable phase unchanged. A successful ephemeral result
    also leaves it unchanged because this slice cannot atomically store token
    values and then bind their reference. Post-transport/pre-secret-store
    ambiguity is an explicit blocker for any concrete network implementation.
    No result, receipt, digest, reference, raw-byte custody object, or fake
    response authorizes a durable session transition.
13. Treat overwriting as defense in depth, not a CPython memory-erasure proof.
    Owned mutable resolver, raw-body, percent-decoding, and decoded-token
    buffers are overwritten on every close/failure path. Immutable input
    `bytes`, form-splitting copies, Python strings created by ADR 0118's signer,
    HMAC/Base64 implementation copies, allocator history, and interpreter
    temporaries cannot be proven zeroized. This limitation prohibits a
    production-secret or real-transport claim and must be resolved or accepted
    by a later threat-model review before deployment.
14. All authority flags remain false. This slice adds no deployed credential
    authority, token persistence, browser/callback authority, production trust
    root, authenticated provider response, renewal/revocation scheduler,
    account identity or binding, request budget, broker read/mutation,
    reconciliation fact, paper/live startup, or trading effect. It adds no
    schema or migration and does not reinterpret any Alpaca or existing
    E\*TRADE evidence or digest.

## Consequences

Tests can now exercise the exact authenticated store head → store-bound fresh
replay reservation → resolver → signer → sealed structurally request-bound raw
response → strict decode sequence without a network or real credential.
Durable authentication/currentness failure prevents resolver and transport;
transport ambiguity burns the nonce while leaving the session phase unchanged;
and response/profile/decoder faults close every owned secret custody object.
The SQL journal, receipts, representations, exceptions, and semantic digests
remain independent of consumer, token, verifier, signature, header, and raw
response values.

This is not an OAuth client and not authenticated provider evidence. A real
runtime remains blocked on a reviewed deployed secret resolver, a concrete
TLS/no-proxy/no-redirect transport and trust-root/origin proof, a secure
raw-response custody threat model, an operator-authorized OOB/browser handoff,
and an atomic or explicitly recoverable secret-store/session-head protocol.
Only after those dependencies exist can sandbox token acquisition be
considered, and production calls require separate approval beyond that.

No database migration is required. The full-prefix authenticator and
store-issued capability are additive; the one coordinator option preserves ADR
0120's default exact-retry behavior for all existing callers. There remains no
production caller of the capability or runtime.
