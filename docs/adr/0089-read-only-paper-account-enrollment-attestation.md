# ADR 0089: read-only paper-account enrollment attestation

- Status: Accepted
- Date: 2026-07-31

## Context

ADR 0088 deliberately began with an unbound local smoke preflight. Its database
check authenticated every durable Phase 4G binding chain but projected only the
global number of binding heads. Once an owner-approved enrollment had run, the
presence of any head could therefore be reported as `bound_non_authorizing`
without proving that the configured local account alias, independently pinned
provider-account UUID, secret reference, and secret version matched that exact
terminal history.

On 2026-07-31, the separately approved recovery invocation established one
durable terminal binding for the intended paper account. The original raw-only
attempt and the recovery attempt remain preserved. The binding's account-status
freshness window was at most five seconds and has expired. This is useful
historical identity evidence, but it is not current account status, operational
control, reconciliation, risk, strategy, or broker-effect authority.

The local preflight needs to distinguish that exact historical enrollment from
an unrelated global binding head without making another provider request or
weakening ADR 0088's non-authorizing result.

## Decision

Add the pure
`phase5-paper-account-enrollment-attestation-v1` contract and a read-only
repository seam for an exact configured paper credential reference.

The reference contains only the existing nonsecret
`AQT_PAPER_ACCOUNT_ID`, `AQT_PAPER_PROVIDER_ACCOUNT_ID`,
`AQT_PAPER_BROKER_SECRET_REF`, and `AQT_PAPER_BROKER_SECRET_VERSION` pins.
Configuration is all-or-none. The preflight does not request, select, return,
resolve, or use `ALPACA_PAPER_API_KEY`, `ALPACA_PAPER_API_SECRET`, or
`ALPACA_PAPER_BASE_URL`, and it does not construct a transport. The shared
dotenv parser nevertheless parses the complete owner-only file before
filtering selected variables, so the preflight process remains inside that
file's credential boundary. The path must be absolute, have no symlinked
parent component, name a current-user-owned mode-`0600` regular file no larger
than 128 KiB, and contain no duplicate variable assignments.

In one repeatable-read database snapshot, the repository:

1. authenticates every binding/head chain so an orphan or corruption outside
   the configured account cannot be hidden;
2. reconstructs the configured account's complete binding history and each
   permit, raw-ingress, response, and decoded-observation source;
3. proves that the head is the exact terminal fact; and
4. requires its account, provider, environment, provider-account UUID, secret
   reference, secret version, credential-reference digest, and capability
   digest to equal the configured reference.

Absence returns no identity receipt. A partial configuration, mismatch,
rollback, fork, orphan, malformed row, or corrupt durable source fails the
configured attestation closed. The application contract accepts only the exact
repository-produced terminal identity-continuity receipt and rechecks its
reference, provider account, sequence, and check time.

The public projection contains only the contract/status, binding,
credential-reference, and identity-receipt SHA-256 values, plus the positive
binding sequence. It omits account IDs, provider-account IDs, timestamps,
provider request IDs, raw bytes, decoded account economics, DSNs, and
credential values.

The result is explicitly
`historical_paper_account_enrollment_attested_non_authorizing`. It always
reports account status and binding freshness as false and exposes no
operational-control, broker-action, new-exposure, automatic-rearm, or
strategy-invocation authority. An expired binding is valid input because the
contract proves historical identity continuity only.

When all four nonsecret pins are present, the ADR 0088 host-side preflight
requires this exact attestation. When none is present, the original unbound
preflight remains available and any unrelated binding heads are labeled
unattested rather than bound. Existing smoke readiness and every Phase 5
activation/authority result remain unchanged.

## Consequences

The supervised preflight can now prove that its configured paper-account
identity matches the exact durable enrollment history without another Alpaca
call or a database write. The check is repeatable after the five-second status
window expires and does not retain a new attestation row.

This decision adds no migration, credential resolver, provider transport,
account refresh, asset check, operational-control head, risk-policy
assignment, reconciliation, strategy invocation, alert route, trusted-time
source, deployment worker, or trading authority. It does not make the account
currently usable or close a Phase 4 or Phase 5 exit gate. A future current
account observation remains a separately approved provider effect.
