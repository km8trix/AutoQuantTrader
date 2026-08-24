# ADR 0113: Recorded-offline E\*TRADE provider foundation

- Status: Accepted
- Date: 2026-08-23
- Extends: [ADR 0096](0096-etrade-live-broker-and-sandbox-qualification.md)

## Context

ADR 0096 selects E\*TRADE as the intended v1 live venue but deliberately adds
no implementation or authority. The first implementation must establish
provider and environment identity before credentials, OAuth sessions, recorded
responses, or provider calls exist. Reusing an Alpaca request, account type,
endpoint, digest, or evidence vocabulary would falsely erase the provider
boundary that ADR 0096 requires.

The smallest coherent read-only surface is Accounts List. It is needed before
numeric account ID and opaque `accountIdKey` evidence can eventually be paired,
but describing the request does not discover or bind an account. Freezing the
other account reads now would also expand the reviewed query and pagination
surface before one raw response profile has passed recorded-offline tests.

E\*TRADE's request-token contract uses the literal `oauth_callback=oob`, even
when a callback is preconfigured with the provider. A future interactive flow
may qualify that separately, but this slice must not accept a caller-supplied
callback, construct a secret-bearing authorization URL, or imply browser or
verifier authority.

## Decision

1. Add a new provider-specific pure adapter contract in
   `packages/adapters/broker/etrade.py`. Its provider identity is exactly
   `etrade`, and its adapter identity is `etrade-recorded-offline`. Its types
   are neither Alpaca types nor provider-neutral canonical broker facts. Every
   public constructor requires exact E\*TRADE types rather than enum-like raw
   strings or arbitrary URLs.
2. Freeze the typed REST environment pins:

   | Environment | Data root | Order root | Consumer scope | Token scope |
   |---|---|---|---|---|
   | Sandbox | `https://apisb.etrade.com/v1` | `https://apisb.etrade.com/v1` | `etrade-sandbox-oauth1-consumer-v1` | `etrade-sandbox-oauth1-token-v1` |
   | Production | `https://api.etrade.com/v1` | `https://api.etrade.com/v1` | `etrade-production-oauth1-consumer-v1` | `etrade-production-oauth1-token-v1` |

   Account, request-budget, persistence, audit, and banner scopes are also
   distinct. Replacing an environment while retaining any opposite-environment
   origin or scope fails closed. Response provenance can match only the exact
   typed data or order root. Arbitrary origins and cross-environment
   substitution are unsupported.
3. Freeze the shared OAuth service for both environments to these nonsecret
   endpoint identities only:

   - `https://api.etrade.com/oauth/request_token`
   - `https://api.etrade.com/oauth/access_token`
   - `https://api.etrade.com/oauth/renew_access_token`
   - `https://api.etrade.com/oauth/revoke_access_token`
   - `https://us.etrade.com/e/t/etws/authorize`

   The active callback metadata is exactly out-of-band with
   `oauth_callback=oob`; registered callback origin and path are absent.
   Dynamic callback handling, browser authorization, verifier replay, token
   acquisition, renewal, and revocation all remain unauthorized. The contract
   never constructs or retains an authorization URL carrying a token or
   verifier.
4. Introduce distinct syntax-only values for a lowercase local account alias,
   a provider numeric account ID retained as exact digit text, and the opaque,
   case-preserving `accountIdKey`. The selected fail-closed profile admits 1-32
   ASCII digits for the numeric ID and 1-128 ASCII letters, digits, underscore,
   or hyphen for the path-safe key; any recorded drift requires a new reviewed
   profile. Their aggregate always binds provider and environment. It is
   explicitly not an authenticated account binding, and account-list order or
   display text cannot populate it.
5. Implement only the versioned `etrade-accounts-list-json-v1` request profile:
   exact `GET`, data root, `/accounts/list`, `Accept: application/json`, empty
   query, and no body. JSON is a local qualification media selection, not an
   observed response claim. The nonsecret endpoint-profile, capability,
   request-profile, and complete request-description identities are
   deterministic SHA-256 digests. Sandbox and production descriptions have
   different identities. Authorization and OAuth headers are absent.
6. Balance, Portfolio, Orders, Transactions, Preview, Place, Cancel,
   submission, and every other operation are unsupported. The capability,
   endpoint profile, account identifiers, callback policy, and request
   description grant no credential resolution, OAuth session, callback,
   transport, budget, persistence, account discovery/binding, reconciliation,
   canonical application, broker mutation, startup, or trading authority.
7. Sandbox is protocol-shape-only. Explicit false gates prevent it from
   satisfying traversal semantics, completeness, lifecycle, reconciliation,
   timing, economics, paper soak, or live readiness.
8. This slice adds no response decoder, raw bytes, persistence, secret
   reference, network implementation, or migration. All historical Alpaca
   modules, schemas, migrations, fixtures, observations, and digests retain
   their existing meanings unchanged.

## Consequences

AutoQuantTrader can now identify one exact E\*TRADE environment and reproduce
one secret-free Accounts List request description without gaining the ability
to send it. Cross-environment mixing fails when the typed objects are built,
and a change to any endpoint, callback, scope, media, or request field changes
or invalidates the recorded identity.

The exact next dependency is a bounded recorded-offline Accounts List response
profile that retains the exact supplied bytes before strict decoding and binds
them to the request, environment, media profile, and response-origin evidence.
It must reject duplicate or unknown keys, malformed numeric account ID and
`accountIdKey` pairs, schema/media drift, and opposite-origin provenance. It
still must not resolve credentials, acquire OAuth tokens, call E\*TRADE, or
create an authenticated account binding.

No database migration is necessary. Any later durable raw-ingress scope,
authenticated E\*TRADE account binding, OAuth/session record, or provider
client-order mapping requires a separate justification and centrally reserved
migration ID.

## Reviewed E\*TRADE sources

- Accounts List resource and environment roots:
  <https://apisb.etrade.com/docs/api/account/api-account-v1.html>
- Provider API format support used for the locally selected JSON profile:
  <https://developer.etrade.com/support/frequently-asked-questions>
- Request-token callback and OAuth service contract:
  <https://apisb.etrade.com/docs/api/authorization/request_token.html>
- Shared authorization, access-token, renewal, and revocation resources:
  <https://apisb.etrade.com/docs/api/authorization/authorize.html>,
  <https://apisb.etrade.com/docs/api/authorization/get_access_token.html>,
  <https://apisb.etrade.com/docs/api/authorization/renew_access_token.html>, and
  <https://apisb.etrade.com/docs/api/authorization/revoke_access_token.html>
