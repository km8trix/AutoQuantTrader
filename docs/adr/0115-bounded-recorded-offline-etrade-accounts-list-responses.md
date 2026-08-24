# ADR 0115: Bounded offline E\*TRADE Accounts List caller declarations

- Status: Accepted
- Date: 2026-08-24
- Extends: [ADR 0113](0113-recorded-offline-etrade-provider-foundation.md)

## Context

ADR 0113 establishes exact E\*TRADE provider, environment, endpoint, account-
identifier, and Accounts List request-description contracts, but deliberately
adds no response evidence or decoder. Its next dependency is a bounded raw-
first decoder that cannot detach supplied bytes from the exact caller-declared
request, environment, media, and schema metadata that give them meaning.

An Accounts List body can expose the numeric account ID and opaque
`accountIdKey` pair needed by later account-binding work. It cannot prove that
the pair is current, belongs to an authenticated session, or is safe to use for
trading. Display fields and array order are not identities, and accepting a
duplicate or conflicting ID/key mapping would make account selection
ambiguous. This repository has no genuine proof-constructed authenticated
E\*TRADE capture artifact or reviewed admission boundary that can establish
provider origin. Consequently, arbitrary caller-supplied bytes and metadata,
including a fixture relabeled by its caller, are all this pure boundary can
accept. A type, enum selection, declaration ID, raw-body digest, or semantic
digest cannot turn those declarations into authenticated provider evidence.

## Decision

1. Define Phase 4AK as a separate provider-specific, pure, in-memory response
   contract. It performs no filesystem access, persistence, credential
   resolution, OAuth work, network transport, retry, provider call, runtime
   composition, or broker mutation.
2. Freeze contract identity
   `phase4ak-etrade-accounts-list-unauthenticated-origin-declaration-v1`,
   response profile
   `etrade-accounts-list-unauthenticated-declared-json-utf8-v1`, and schema
   profile `etrade-accounts-list-response-schema-v1`. Their identities and
   every typed response identity are deterministic SHA-256 digests over the
   complete canonical contract material. The profile admits at most 262,144
   exact raw bytes and at most 128 account objects; overflow fails rather than
   truncating evidence.
3. Represent origin only as
   `EtradeAccountsListOriginDeclarationKind.UNAUTHENTICATED_CALLER_DECLARATION`
   and `EtradeAccountsListUnauthenticatedOriginDeclaration`. Create it through
   `create_etrade_accounts_list_unauthenticated_origin_declaration`; retain its
   bytes as `EtradeAccountsListCallerDeclaredResponse` through
   `create_etrade_accounts_list_caller_declared_response`; and decode only through
   `decode_etrade_accounts_list_caller_declared_response`. The declaration
   exposes `provider_origin_authenticated=false` and
   `fixture_relabeling_detection_supported=false`. The exact enum rejects a raw
   string or foreign enum but does not prove who supplied the bytes, where they
   came from, or whether the caller relabeled a fixture.
4. Construct immutable caller-declared raw evidence before decoding. It binds
   the exact typed E\*TRADE provider, `EtradeEnvironment`, endpoint-isolation
   profile, canonical Accounts List request description and identities,
   environment-matching data origin, exact `application/json` media type, exact
   `utf-8` charset, unauthenticated origin declaration, response and schema
   profiles, supplied byte sequence, and raw byte SHA-256. Every provider,
   environment, origin, request, media, charset,
   profile, schema, declaration, or byte substitution within one evidence value
   changes its identity or is rejected. These checks establish internal
   consistency only. A caller can construct a new internally consistent
   declaration around arbitrary bytes; opposite-environment, cross-request, and
   fixture relabeling therefore remain undetectable as claims about actual
   provider origin.
5. Decode only the retained raw bytes through the bound response and schema
   profiles. Reject an empty or oversized body, malformed UTF-8 or JSON,
   non-standard JSON constants, duplicate object keys at any depth, a wrong
   JSON type, missing keys, unknown keys, and an account array beyond the
   fixed bound.
6. Freeze the closed wire schema as exactly
   `AccountListResponse -> Accounts -> Account`. Each account object requires
   exactly `accountId`, `accountIdKey`, `accountMode`, `accountDesc`,
   `accountName`, `accountType`, `institutionType`, `accountStatus`, and
   `closedDate`; no field is optional and no additional field is admitted.
   The ID/key and six metadata values are exact bounded JSON strings.
   `closedDate` is an exact non-boolean JSON integer from 0 through 99991231.
   Description and name may be empty but must remain trimmed, bounded valid
   Unicode; the other metadata strings are nonempty and bounded.
7. Convert only `accountId` and `accountIdKey` through ADR 0113's strict
   provider-specific identifier types. Preserve response order and display
   metadata as unverified caller-declared wire values only. Reject a repeated
   numeric account ID, repeated `accountIdKey`, repeated pair, or any mapping
   in which either identifier could designate more than one caller-declared account. Raw-
   string environment or operation values cannot substitute for the exact
   enum members used by ADR 0113.
8. Bind every decoded result back to the exact caller-declared raw evidence,
   provider, environment, request, origin, media/charset, unauthenticated origin
   declaration, response profile,
   schema profile, raw bytes, raw digest, and ordered decoded identities. The
   result is an immutable historical, unqualified observation. It does not
   create a local alias, authenticated account binding, provider revision,
   canonical broker fact, or current account fact.
9. Keep unsupported-operation and authority flags explicit and false. Balance,
   Portfolio, Orders, Transactions, Preview, Place, Cancel, submission, and
   every operation other than offline Accounts List decoding remain
   unsupported. Credential, OAuth, provider-network, read-only transport,
   persistence, authenticated discovery/binding, lifecycle, reconciliation,
   timing, economics, paper-soak, startup, mutation, canonical application,
   and trading authority remain closed. Sandbox bytes remain protocol-shape
   evidence only and are not an economic simulator or readiness evidence.
10. Add no database schema or migration. Historical Alpaca modules, schemas,
    fixtures, observations, and digests retain their exact existing meanings
    and cannot be passed directly as E\*TRADE typed evidence. Copying any bytes
    into a new E\*TRADE caller declaration remains possible and
    unauthenticated. ADR 0113's exact typed-tuple protections also remain
    unchanged.

## Consequences

AutoQuantTrader can now retain supplied offline Accounts List bytes in one
immutable caller-declared in-memory value and strictly decode them into exact
historical, unqualified E\*TRADE account identity observations. Malformed or
drifted bytes remain available in the raw value when decoding fails, while an
internally inconsistent substitution or ambiguous identity never produces a
typed decoded result.

This contract expressly permits a mechanically constructed fixture to be
declared and decoded because it has no origin authenticator. Such a result
remains caller-attributed evidence: every declaration, raw response, decoded
identity, and observation reports that provider origin is unauthenticated and
fixture-relabeling detection is unsupported. It cannot be consumed as
authenticated provider evidence. The contract does not claim that repository
test bytes are provider captures, that supplied bytes describe the provider
now, or that sandbox behavior models production economics. A separately
reviewed authenticated capture/admission artifact, durable raw-ingress design,
exact account enrollment/binding, OAuth session, and broader read surface
remain future work. Any later persistence requires a separate justification
and a centrally reserved migration ID.

## Reviewed E\*TRADE source

- Accounts List resource and response shape:
  <https://apisb.etrade.com/docs/api/account/api-account-v1.html>
