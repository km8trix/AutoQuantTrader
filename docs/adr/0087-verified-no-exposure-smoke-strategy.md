# ADR 0087: verified no-exposure smoke strategy artifact

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0075 defines a strict subprocess boundary and ADRs 0077 and 0079 make its
claim/result lifecycle durable. Until now the repository intentionally selected
no concrete strategy artifact. Deployment preparation needs a first executable
that can prove artifact loading, invocation identity, canonical protocol, and
supervision behavior without proposing a position, an order, or new exposure.

This first artifact must be useful for local and later deployment smoke tests
without becoming a shortcut around startup, account assignment, operational
control, risk, dispatch, or broker gates. Merely naming a file digest in
`StrategySubprocessSpec` is insufficient: the bytes must be verified before the
spec is constructed, and the child must reject an invocation bound to different
bytes.

## Decision

1. Check in one standard-library-only artifact,
   `strategy_artifacts/no_exposure_smoke_v1/strategy.py`, and one canonical JSON
   manifest. The manifest fixes the artifact format, entrypoint, SHA-256 of the
   exact source bytes, Phase 5C protocol version, result-contract version,
   strategy ID/version, and the digest of a configuration with no configurable
   values. The loader also pins the reviewed manifest and artifact digests in
   code, so changing only the manifest and artifact cannot silently retain this
   version's identity.
2. Verify bounded, stable, regular, non-symlink manifest and artifact files.
   Reject duplicate manifest keys, floats, non-finite values, noncanonical JSON,
   extra or missing fields, identity changes, path substitution, and any
   artifact-byte mismatch before constructing `StrategySubprocessSpec`.
3. Launch with the current absolute CPython executable, isolated mode (`-I`),
   disabled site initialization (`-S`), and a code-pinned bootstrap in `-c`.
   The bootstrap reads at most 65,536 artifact bytes, compares SHA-256 with the
   code-pinned digest passed in the exact argv, then compiles and executes those
   same in-memory bytes. Replacing the path before the read fails the digest;
   replacing it afterward cannot change the already authenticated source being
   executed. The existing ADR 0075 runner still supplies the no-shell launch,
   fixed sanitized environment, bounded pipes, process group, deadline, and
   cleanup behavior. Interpreter version, bootstrap, path, artifact digest, and
   resulting exact argv participate in the runtime and launch-spec identities.
4. Have the artifact read at most the Phase 5C request bound, require the exact
   canonical protocol envelope, match the fixed strategy ID/version/
   configuration, runtime artifact digest, invocation identity, and
   market-batch identity before responding.
5. Emit exactly one canonical result:

   ```json
   {
     "contract_version": "aqt-no-exposure-smoke-result-v1",
     "decision": "NO_EXPOSURE",
     "market_batch_id": "<bound batch ID>",
     "market_batch_sha256": "<bound batch digest>",
     "proposed_intents": []
   }
   ```

   It contains no target portfolio, order instruction, cancel/flatten command,
   control transition, or broker operation.
6. Require a separate exact response verifier to convert that opaque Phase 5C
   response into non-authorizing smoke evidence. It requires the sealed
   verified artifact, exact runtime binding, fixed strategy ID/version/
   configuration, bound market batch, and an empty intent list. It fixes both
   proposed-intent count and exposure authority to zero/false. Any identity
   substitution or added intent material is rejected.
7. Provide `make no-exposure-smoke-verify` as a credential-free, offline
   manifest/byte verification command. It prints only public identities and
   does not execute the artifact, open a database, read `.env`, contact a
   broker, create a strategy claim, or change startup state.

## Consequences

The repository now has a deterministic first strategy artifact that exercises
the real strict subprocess protocol while making no exposure proposal.
Manifest tampering and artifact tampering fail closed. The trusted bootstrap
hashes and executes the same bounded source snapshot, so a replacement that
removes checks from the artifact is not executed under the pinned digest. The
manifest digest gives review and packaging workflows an exact identity to pin.

SHA-256 verification is integrity checking, not code signing or deployment
approval. The code-pinned values are protected by trusted repository review;
an attacker able to coordinate changes to the loader, bootstrap, manifest, and
artifact is outside this local smoke boundary. The CPython executable and
package are not signed or attested, and ADR 0075 remains process isolation
rather than a hostile-code sandbox. Signed packaging, immutable deployment
storage, OS sandbox/resource policy, runtime attestation, and an externally
approved manifest digest remain later deployment controls.

This artifact is not assigned to any account or environment. The verification
command does not run it, and the executable cannot obtain a durable start
authorization on its own. Even a completed supervised smoke invocation does
not authorize exposure, re-arm control, enable paper/live startup, or satisfy
the Phase 5 exit gate.
