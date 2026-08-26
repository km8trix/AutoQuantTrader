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
   application composition over the exact ADR-0118 types and ADR-0120
   snapshot; it has no CLI, API, worker, trader, scheduler, service
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
   private operation receives a secret-free request bound to the exact current
   ADR-0120 scope, event, sequence, state, replay guard, and signing intent. A
   test resolver can return only the proof-constructed opaque envelope from
   `create_etrade_oauth_token_secret_envelope`. The envelope binds the exact
   resolution request and consumer/token references, is one-use,
   context-managed, redacted, non-copyable, non-serializable, explicitly
   closable, and owns mutable bytearray copies that are overwritten on close. A
   closed, reused, cross-request, wrong-reference, wrong-revision,
   wrong-environment, malformed, or foreign envelope fails with constant
   secret-free errors.
4. Resolve and sign before transport, then append the exact ADR-0120 replay-only
   event while the sanitized session state remains unchanged. Add the
   keyword-only `allow_exact_retry` option to
   `SqlEtradeOAuthCoordinator.advance`, defaulting to `true` so ADR 0120 and
   every existing caller retain their exact convergent retry semantics. Phase
   4AN calls the same operation with `allow_exact_retry=false`. Under the same
   existing SQL write lock this fresh-only call rejects an already-current
   identical event, so a timeout or ambiguous injected transport outcome
   cannot cause the runtime to present the same signed capability again.
   Failure or conflict in this durable step occurs before transport.
5. Define one injected transport port with the exact identity
   `injected-fake-etrade-oauth-token-transport` version `1.0.0`. Freeze its
   metadata and exact bound method once before resolving secrets. It receives
   only an `EtradeOAuthEphemeralTransportRequest`: a redacted,
   non-serializable, one-presentation capability around the sealed ADR-0118
   signing result. It has no ordinary Authorization-header getter, URL/query
   serializer, network-send method, or concrete implementation. Synthetic
   transports may use the private, test-only constant-time header predicate to
   check a frozen signing vector and must bind their raw response to that exact
   request object through `create_etrade_oauth_injected_token_response`. The
   request owns a newly constructed raw response until the runtime completes a
   successful result transfer, so a transport that raises after construction
   cannot strand the runtime-owned mutable custody buffer.
6. The injected response profile requires the exact shared token origin
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
7. Retain the exact raw body in private, context-managed, non-copyable mutable
   custody before strict decode.
   Request-token responses contain exactly one each of `oauth_token`,
   `oauth_token_secret`, and `oauth_callback_confirmed=true`; access-token
   responses contain exactly the two token fields. Reject empty/oversized
   bodies, malformed form structure or percent encoding, duplicate, missing,
   or unknown fields, non-ASCII/control/whitespace material, callback drift,
   and operation/schema mismatch. Do not accept Cookie, Set-Cookie, arbitrary
   response headers, provider request identifiers, credential-bearing URLs or
   query material into the response model.
8. Return `EtradeOAuthEphemeralTokenExchangeResult` with the still-retained raw
   body, decoded token bytes, exact nonsecret output reference, replay-only
   snapshot, proposed pure successor state, and sanitized receipt. The result
   is context-managed, redacted, non-copyable, non-serializable, has no token,
   token-secret, raw-body, Authorization, Cookie, URL, query, or response-digest
   getter, and overwrites its mutable raw/decoded copies on close. Its only
   token-value check is a private one-shot constant-time synthetic-test
   predicate that closes custody. A future secret-store transfer needs a
   separate reviewed capability; no ordinary getter or persistence callback is
   introduced here.
9. The sanitized receipt binds provider, environment, operation, signing
   intent, durable scope/replay event/sequence/guard, output reference, exact
   resolver/transport/profile metadata, and a secret-independent structural
   response binding. It explicitly excludes the raw body, body digest, decoded
   values, value digests, signature, Authorization header, verifier, Cookie,
   credential-bearing URL/query, and secret-dependent request metadata.
   Changing only consumer/token inputs or raw response token values cannot
   change the receipt digest. The receipt may say the sealed signed-request
   capability was presented and the injected request/response objects were
   structurally bound; `provider_origin_authenticated` remains false.
10. Do not advance the proposed request/access-token session successor. A
    pre-transport replay-only event is durable; a transport failure or decode
    failure leaves the durable phase unchanged. A successful ephemeral result
    also leaves it unchanged because this slice cannot atomically store token
    values and then bind their reference. Post-transport/pre-secret-store
    ambiguity is an explicit blocker for any concrete network implementation.
    No result, receipt, digest, reference, raw-byte custody object, or fake
    response authorizes a durable session transition.
11. Treat overwriting as defense in depth, not a CPython memory-erasure proof.
    Owned mutable resolver, raw-body, percent-decoding, and decoded-token
    buffers are overwritten on every close/failure path. Immutable input
    `bytes`, form-splitting copies, Python strings created by ADR 0118's signer,
    HMAC/Base64 implementation copies, allocator history, and interpreter
    temporaries cannot be proven zeroized. This limitation prohibits a
    production-secret or real-transport claim and must be resolved or accepted
    by a later threat-model review before deployment.
12. All authority flags remain false. This slice adds no deployed credential
    authority, token persistence, browser/callback authority, production trust
    root, authenticated provider response, renewal/revocation scheduler,
    account identity or binding, request budget, broker read/mutation,
    reconciliation fact, paper/live startup, or trading effect. It adds no
    schema or migration and does not reinterpret any Alpaca or existing
    E\*TRADE evidence or digest.

## Consequences

Tests can now exercise the exact resolver → signer → fresh durable replay burn
→ structurally request-bound raw response → strict decode sequence without a
network or real credential. Durable failure prevents the injected transport;
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

No database migration is required. The one coordinator option is additive and
preserves ADR 0120's default exact-retry behavior for all existing callers.
