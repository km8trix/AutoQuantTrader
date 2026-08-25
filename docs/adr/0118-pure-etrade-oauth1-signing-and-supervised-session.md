# ADR 0118: Pure E\*TRADE OAuth 1.0a signing and supervised session

- Status: Accepted
- Date: 2026-08-25
- Extends: [ADR 0096](0096-etrade-live-broker-and-sandbox-qualification.md),
  [ADR 0113](0113-recorded-offline-etrade-provider-foundation.md), and
  [ADR 0115](0115-bounded-recorded-offline-etrade-accounts-list-responses.md)

## Context

ADR 0113 pins E\*TRADE sandbox/production isolation, disjoint nonsecret
consumer/token scopes, the shared request/access/renew/revoke token resources,
the authorization page, and the literal out-of-band callback value `oob`.
It deliberately performs no OAuth work. ADR 0115 decodes only caller-declared
Accounts List bytes and likewise has no session, credential, or provider
authority.

The next safe dependency is the protocol contract itself: deterministic OAuth
1.0a parameter normalization and HMAC-SHA1 signing plus an explicit supervised
session reducer. This boundary must be testable without credentials or a
network and must not make an in-memory state, enum, digest, or synthetically
signed request look like authenticated provider evidence. Signing requires
secret values transiently, while durable or diagnostic evidence must remain
secret-free. A pure reducer also cannot establish durable replay prevention,
provider response authenticity, session currentness, or operational authority.

## Decision

1. Implement Phase 4AL in `packages/adapters/broker/etrade_oauth.py` as a pure,
   provider-specific, non-I/O contract. Its identity is
   `phase4al-etrade-oauth1-supervised-session-v1`. It imports no clock,
   randomness, filesystem, persistence, secret resolver, proxy, redirect,
   browser, callback server, network client, account adapter, or broker runtime.
2. Freeze the four token-control operations to exact typed members and exact
   ADR-0113 URLs:

   | Operation | Method | URL |
   |---|---|---|
   | Request token | `GET` | `https://api.etrade.com/oauth/request_token` |
   | Access token | `GET` | `https://api.etrade.com/oauth/access_token` |
   | Renew access token | `GET` | `https://api.etrade.com/oauth/renew_access_token` |
   | Revoke access token | `GET` | `https://api.etrade.com/oauth/revoke_access_token` |

   Request-token signing includes only the exact OOB callback metadata
   `oauth_callback=oob`. Access-token signing requires a verifier bound to the
   active authorization challenge. Renewal and revocation require the active
   access-token reference. Caller-supplied endpoint URLs, methods, callback
   values, query/body parameters, or OAuth parameters are unsupported.
3. Implement RFC 5849 percent encoding over UTF-8, encoded-name/encoded-value
   sorting, normalized parameter construction, signature-base-string
   construction, and HMAC-SHA1/Base64 signing. Duplicate decoded parameter
   names fail closed. `oauth_signature` is excluded while computing the
   signature and included once in the ephemeral Authorization header.
   Synthetic signature/header vectors and the RFC percent-encoding vectors pin
   the implementation.
4. Require exact caller-injected `EtradeOAuthTrustedTimestamp` and
   `EtradeOAuthNonce` values. The timestamp carries a nonsecret upstream
   trust-evidence identity; this type does not authenticate that upstream
   evidence. No ambient time or randomness fallback exists. The bounded pure
   replay guard consumes environment/consumer-reference/timestamp/nonce
   fingerprints and OOB authorization-challenge consumption fingerprints. The
   current returned guard must be threaded through every signing and verifier-
   consumption transition; reuse against that guard fails, including nonce
   reuse across operations and immutable-state verifier branching. Because this
   slice adds no persistence, the guard is explicitly not durable replay
   protection and cannot satisfy a deployed session gate.
5. Represent secret locations only through typed nonsecret reference
   revisions. Sandbox references must use the sandbox consumer/token scopes;
   production references must use the production scopes. Request-token and
   access-token references are different typed lifecycle kinds. Raw strings,
   opposite-environment scopes, wrong token kinds, stale reference-version
   reuse, or a credential wrapper bound to another reference fail closed.
6. Keep values that must transiently participate in signing inside exact
   ephemeral wrappers: consumer key, consumer secret, request/access token,
   token secret, and OOB verifier. The signature and Authorization header exist
   only in an ephemeral signing result. These wrappers redact `repr` and `str`,
   reject serialization, expose no evidence digest, and cannot be substituted
   by raw strings. The result exposes only constant-time test predicates for
   frozen vectors; it exposes no header/signature property or transport method.
7. Serialize and digest only sanitized intent material: provider/environment,
   exact endpoint/profile/operation, nonsecret reference versions and their
   sanitized identities, trusted timestamp and trust-evidence identity, nonce
   SHA-256, OOB callback-policy identity, and optional authorization-challenge
   identity. Session state also retains one monotonic trusted-time high-water
   and the sanitized identity of every driving signing intent or trusted-time
   observation. Consumer/token values, consumer/token secrets, verifier values,
   signatures, Authorization headers, signature base strings, signing keys,
   and token-bearing authorization URLs never enter any `repr`, log call,
   serialized evidence, or semantic digest. Changing ephemeral secret values
   cannot change sanitized evidence or its identity.
8. Define the closed secret-free session phases
   `NEEDS_REQUEST_TOKEN`, `REQUEST_TOKEN_RECEIVED`, `AUTHORIZATION_PENDING`,
   `AUTHORIZATION_CONFIRMED`, `ACCESS_TOKEN_ACTIVE`,
   `ACCESS_TOKEN_INACTIVE`, `ACCESS_TOKEN_EXPIRED`, `ACCESS_TOKEN_REVOKED`, and
   `REAUTHORIZATION_REQUIRED`. Every state is environment/profile/consumer-
   reference bound, predecessor-linked, and retains only token-reference
   revisions plus sanitized intent/challenge identities.
9. Permit only these explicit transitions:

   1. a fresh generation records one newer request-token reference from the
      exact request-token intent;
   2. that state opens one OOB authorization challenge without constructing a
      token-bearing URL;
   3. one challenge-bound verifier advances authorization once relative to the
      required current replay guard, without retaining or hashing the verifier;
   4. the exact access-token intent replaces the request-token reference with
      one newer access-token reference and caller-injected issuance/daily-expiry
      horizons;
   5. an active session can record caller-supervised activity before both
      horizons, while the documented renewal path can reactivate an active or
      inactivity-expired token only before daily expiry;
   6. injected time at or beyond two hours since activity produces
      `ACCESS_TOKEN_INACTIVE`, while daily expiry takes precedence and produces
      `ACCESS_TOKEN_EXPIRED`;
   7. exact-path revocation from an active session produces
      `ACCESS_TOKEN_REVOKED`; and
   8. inactive, expired, and revoked states require an explicit reasoned
      reauthorization state before a new generation can request a strictly
      newer token-reference revision.

   The trusted-time high-water survives authorization and reauthorization
   generations. Time regression, verifier replay relative to the threaded
   guard, token-reference replay, skipped phases, renewal/revocation after a
   horizon, and every other transition fail closed. Observations, activity,
   renewal, and revocation bind their sanitized trusted-time or signing-intent
   identities into predecessor-linked session evidence.
10. Every session and intent authority flag remains false. Transition names
    record caller-supervised protocol state only; they do not authenticate a
    provider response, resolve credentials, create a browser handoff, validate
    a callback, persist replay memory, perform transport, claim provider origin,
    bind an account, call a broker, start a trader, or authorize a trading
    effect. Sandbox remains protocol-shape-only and production remains live
    disabled.
11. Export the provider-specific types additively from
    `packages.adapters.broker`. Do not change historical Alpaca code, fixtures,
    schemas, digests, or meanings. Add no database schema or migration.

## Consequences

AutoQuantTrader can now reproduce and test the exact E\*TRADE OAuth control
signature algorithm and reduce a secret-free supervised session history. It
can deterministically reject canonicalization drift, duplicate parameters,
wrong endpoints, cross-environment material, nonce reuse, stale token-reference
versions, verifier reuse within the active chain, time regression, renewal
after daily expiry or revocation, and skipped transitions.

The result is still not an executable OAuth client. There is no secret-store
resolver, durable nonce store, authenticated provider response decoder,
interactive browser/OOB handoff, callback receiver, TLS transport, redirect or
proxy policy runtime, token persistence, scheduler, account binding, broker
request, or current-session proof. A later reviewed runtime must keep secret
resolution ephemeral, bind durable replay protection and provider response
evidence, preserve the exact endpoint/environment rules, and obtain separate
operator authorization before any sandbox or production call.

No database migration is necessary for this pure slice. Any durable session,
nonce, token-reference, or authenticated response evidence requires a separate
ADR and centrally reserved migration ID.

## Reviewed sources

- OAuth 1.0 protocol parameter normalization and HMAC-SHA1 signing:
  <https://www.rfc-editor.org/rfc/rfc5849>
- E\*TRADE request-token, authorization, access-token, renewal, and revocation
  resources already pinned by ADR 0113:
  <https://apisb.etrade.com/docs/api/authorization/request_token.html>,
  <https://apisb.etrade.com/docs/api/authorization/authorize.html>,
  <https://apisb.etrade.com/docs/api/authorization/get_access_token.html>,
  <https://apisb.etrade.com/docs/api/authorization/renew_access_token.html>, and
  <https://apisb.etrade.com/docs/api/authorization/revoke_access_token.html>
