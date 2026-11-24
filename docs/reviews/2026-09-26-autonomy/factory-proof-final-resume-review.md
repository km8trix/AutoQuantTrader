# Final resumability review — factory proof candidate

Read-only review on 2026-09-26 of `AGENTS.md` and `docs/{SPEC,ARCHITECTURE,PLAN,STATUS,DECISIONS,TESTING}.md` in `autonomous-development`, candidate `2a9fc2c5adda25c49e7d1c1ca78e2845b7bb64eb`. Only `docs/STATUS.md` is locally modified, intentionally recording the active exact-candidate run without cancelling it. No provider/access inspection, source review, tests or repository edits were performed for this review.

## Assessment

The documents consistently describe A2.3 as approved development with local evidence, not completed Linux acceptance. They retain the previous failures, original caps and checks, restricted CPython profile, separate actual-source/initializer gates, and lack of merge/provider/live/deployment authority. The 100-case combined result and final targeted nested-data refinement are accurately distinguished by the linked source-bound JSON records. No unsupported claim that A2, Wave 4, genuine capture or live readiness is complete was found in the seven current operating documents.

The current local STATUS supplies the exact candidate, active run `36285774497`, PR #56, verified interpreter and immediate instruction to inspect CI. Preserve this uncommitted update until the active run completes as already directed. A fresh task must inspect Git state and the linked run before taking any acceptance decision; this review does not report a CI outcome.

## Findings to address in the next documentation update

1. **Make the post-CI branch explicit and carry the existing A4 question into the short handoff.** `docs/STATUS.md:47–58` says the measured-source question is unanswered and points to CI, but does not state the question or the next action after a successful result. `docs/PLAN.md:262–279` groups all A4 work together. The precise existing input is currently buried in the dated assessment: identify the supervised Mac's measured-time source and a non-secret qualification record, then review the genuine source/qualification producer contract. Add that existing input and a direct link to `capture-bridge-contract.md`'s implementation findings to STATUS or A4. On CI success, record exact tested revision/result and close only applicable A2 acceptance; A4 remains blocked on that input, and W4/merge/provider/initializer gates remain. On failure, preserve exact logs and return to the failed gate's diagnosis. This is clarification of the established queue, not a new architecture choice or request to inspect private state.

2. **Bind the known failure to its historical commit.** `docs/STATUS.md:39–44` describes run `36279615517` as failing “at published head.” The same document now names published candidate `2a9fc2c`. Replace this phrase with “at `7c73cd6`” so a new task cannot attribute the old 60.118-second failure to the active candidate. The linked failure record already supplies that identity.

3. **Repair the stale milestone reference.** `docs/PLAN.md:244` says measured health ownership cannot satisfy “A3.4 admission,” but the executable plan has no A3.4 and explicitly assigns genuine integration to A4. Use A4 here. The earlier A3.x proposal remains historical and need not be rewritten.

4. **State the qualified-test behavior in TESTING.** `docs/TESTING.md:257–291` gives the right focused commands but does not explain that positive proof-admission tests require the qualified CPython 3.12.13 profile and intentionally skip outside it, while applicable ordinary-owner/genesis/unsupported controls remain active. The environment section supports Python 3.12–3.13 and ARCHITECTURE correctly limits the pilot; add the same test interpretation here so a fallback-runtime skip is never counted as proof acceptance. No actual Python 3.13 qualification should be claimed.

5. **Clarify the two PR roles before GitHub closeout.** Current STATUS correctly identifies candidate PR #56; `docs/PLAN.md:284–291` names only original Wave 4 PR #55 and `gh pr checks 55`. PR #55 is a preserved integration record, so this is not evidence it should be replaced blindly. Add the established relationship between the autonomous-development candidate and the original Wave 4 integration PR, and require checking the exact applicable revision for each. Until that relationship is recorded, a fresh task should follow STATUS's PR #56 acceptance run and must not infer merge authority.

## Small optional handoff improvements

- `docs/ARCHITECTURE.md:13` still says worker-probe acceptance is reopened without the narrower current result: the original worker gates and `7c73cd6` worker shard passed, while exact-candidate regression remains pending with the aggregate. This is conservative rather than a false completion claim, but the next update can distinguish the repaired probe from remaining restore acceptance.
- Link the existing provider-rights/retention approval record directly from A4/STATUS (currently reached through the dated assessment and `docs/IMPLEMENTATION_PLAN.md` to `reviews/2026-09-10-wave4/recovery-2026-09-20.md`). This helps a fresh task avoid asking for the already-recorded approval again while preserving the separate current OAuth/window and initializer gates.

No changes to the approved pilot contract, limits, source code, tests or product direction are proposed by this review.

## Resolution

All five findings were corrected in the subsequent local documentation update:
explicit CI success/failure branches and A4 input, historical failure revision,
A4 reference, qualified-test skip interpretation, and verified PR relationships.
GitHub confirms #56 targets the W4 branch and #55 targets main; both remain open
drafts. The documents also link the preserved rights/retention approval record.
No source, test, limit or authorization boundary changed.
