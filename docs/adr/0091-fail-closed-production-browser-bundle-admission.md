# ADR 0091: fail-closed production browser bundle admission

- Status: Accepted
- Date: 2026-07-31

## Context

Phase 6B already lazy-loads each implemented browser feature route. That keeps
route pages out of the startup module graph, but the default Vite build still
emits one 514,571-byte shared entry asset and only reports its 500-kilobyte
advisory as a warning. The build did not produce a machine-readable admission
decision proving that every implemented route remained dynamic, that shared
runtime partitions were present, or that emitted files stayed within reviewed
byte ceilings.

Naively assigning every dependency from a package family to one manual chunk
can also defeat route splitting: a package module used only by a lazy route can
be pulled into a partition that the entry loads eagerly. The partition policy
must therefore distinguish the entry's static dependency graph from modules
reachable only through a dynamic import.

This is an offline build-integrity boundary. It must not treat browser bundle
shape as deployment approval, production-session security, operational
readiness, or trading authority.

## Decision

Add the `phase6b-production-bundle-admission-v1` contract.

1. Vite emits its production manifest. A graph-aware manual-chunk function
   partitions only third-party modules statically reachable from the entry into
   stable `react-runtime`, `mui-runtime`, `query-runtime`, and
   `vendor-runtime` assets. Dependencies reachable only through a route's
   dynamic boundary remain outside those eager shared partitions.
2. A checked-in policy fixes the single entry module, the exact eleven
   implemented route modules, all required shared partition names, a
   300,000-byte per-asset ceiling, and a 625,000-byte total ceiling for the
   entry's unique static asset graph. Ceiling equality is admitted; one byte
   over fails.
3. The offline verifier accepts only a bounded regular policy and Vite
   manifest with supported fields and normalized relative identifiers. It
   requires exactly one entry, the exact route allowlist as both dynamic
   entries and entry dynamic imports, distinct output files, resolvable import
   references, and exactly one instance of every required shared partition.
4. Static-graph traversal must not encounter any route module. Every
   manifest-addressed JavaScript, CSS, or supporting asset must be a positive-
   length regular non-symlink file whose canonical path remains strictly below
   the selected `dist` directory. Missing files, traversal, aliasing two asset
   names to one file, malformed graphs, duplicate output ownership, and budget
   overflow fail closed.
5. The verifier measures each referenced asset once and counts each asset in
   the entry's static closure once. Its success result contains only the
   contract/status, counts, byte measurements and ceilings, plus explicit false
   deployment, operational-control, and trading-authority fields. It reads no
   asset contents, environment variables, credentials, browser state, or
   runtime service data.
6. Fixture-driven Node tests cover valid admission and adversarial policy,
   manifest, graph, path, file, partition, and byte-boundary cases. The normal
   production build invokes the verifier, and CI runs both those tests and the
   admitted build.

## Consequences

The reviewed build emits a 33,015-byte entry plus four eager shared-runtime
assets. Its largest emitted asset is 277,872 bytes and its five-asset initial
static graph is 615,022 bytes, within the checked-in ceilings. This replaces a
single oversized asset with stable cache and parsing boundaries and removes
the Vite size advisory. Partitioning is not claimed to reduce total startup
bytes; cross-chunk boundaries add overhead, which is why the initial graph has
its own explicit measured ceiling.

Route splitting and shared-runtime budgets are now CI-enforced instead of
being inferred from build log filenames. Policy changes require review and
cannot silently accompany an oversized build.

This decision adds no CSP, production OIDC/session or CSRF validation, static
hosting configuration, table virtualization, chart downsampling, backend SSE,
multi-browser end-to-end evidence, deployment attestation, control capability,
or broker authority. Those remain separate Phase 6 work. Verification must run
against a quiescent or immutable build directory: no user-space path sequence
can completely exclude a malicious concurrent parent-directory rename, even
though no-follow handles, inode checks, and before/after path revalidation close
ordinary replacement and alias cases.
