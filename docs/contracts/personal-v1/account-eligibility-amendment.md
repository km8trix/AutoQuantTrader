# Account eligibility amendment — 2026-09-09

Amendment `personal-v1/account-eligibility/2` is authorized by the owner's instruction to revise the cash-only account requirement after confirming margin privileges on the selected, application-exclusive production account. The [architecture](../../ARCHITECTURE.md) and [implementation plan](../../IMPLEMENTATION_PLAN.md) remain the authoritative design and status register.

## Scope and precedence

Personal v1 permits one explicitly selected, application-exclusive USD brokerage account with CASH or MARGIN privileges, used by one cash-funded, long-only strategy. Account privileges and the strategy's financing policy are distinct. MARGIN is recorded as MARGIN; it is never relabelled CASH.

This amendment supersedes only the cash-only account-eligibility wording in the frozen `personal-v1/1` [scope/defaults](scope-defaults.md) owner/account row, [core/engine](core-engine.md) scope, and [account/runtime](account-runtime.md) account scope/binding and cash-account feasibility requirements. The original Wave 0 contract files and hash-bound evidence remain unchanged as the historical baseline. Current consumers apply this amendment with that pack. Research's cash-based accounting, numerical examples and settlement/reservation invariants retain their existing meaning.

The accepted financing policy is `cash-funded-long-only/1`: no borrowing, leverage, shorting, derivatives or new account-wide financing authority. Whole-share DIA/IWM/QQQ/SPY, regular-session DAY market order targets and other existing product limits remain. Actual orders are still disabled at this wave.

## Read eligibility and evidence

Wave 1's read-session contract advances to version 2. Cash-only selection remains the compatibility default. An explicitly selected account may opt in to margin privileges with `--allow-margin-privileges`; the choice is included in the account binding and portable capture evidence. This flag records the revised read profile and does not prove financial eligibility or grant OAuth permissions.

Discovery must identify exactly the selected account in the selected environment, with ACTIVE status and BROKERAGE institution. CASH and opted-in MARGIN are the permitted modes. IRA, checking, savings, missing and unrecognized modes remain outside this read profile. Owner exclusivity remains an explicit owner declaration. Fresh selection, credential rotation, session timing and exact balance/account identity checks remain enforced.

If discovery and balance report different modes but both fall within the explicitly selected CASH/MARGIN read profile, traversal may continue while recording both values and an account-mode-disagreement blocker. An unsupported or missing balance mode or mismatched account identity stops the capture. An HTTP success, allowed privilege mode, or completed traversal is not account reconciliation or execution qualification.

## Financing constraints

Preserve the provider's cash, margin, buying-power, reserve and call observations in separate fields. Missing data remains unavailable; no missing liability is converted to zero. Positive cash or margin buying power, withdrawal capacity, account equity, and absence of a Margin object do not establish cash-funded capacity. E*TRADE documents these as distinct balance views and describes `accountMode` as account privileges. [Balance API](https://apisb.etrade.com/docs/api/account/api-balance-v1.html)

Before any execution qualification, establish account USD currency, actual settled-cash availability, restrictions, margin-liability/sign semantics and corroborated absence of borrowing. Reconcile broker holds/open-order reserves with local executed buy payables and still-unfilled reservations so every obligation is counted once. Pending or unsettled sales do not fund buys. Nonzero or unknown financing liabilities, calls, unsupported positions, mode discrepancies, or unexplained economic differences block new exposure until resolved. W1 preserves these observations and blockers; it does not implement a borrowing engine or manufacture a usable-cash number.

Special day-trader or portfolio-margin regimes are not automatically qualified by an ordinary MARGIN label. Their restrictions and financing semantics require explicit evidence. Quote entitlement/freshness, retention, provider quotas and recovery/correction identity likewise remain separate feasibility inputs.

## Acceptance and continuation

Tests must show cash compatibility, explicit margin opt-in and binding, fail-closed unsupported modes/identity mismatches, preserved mode disagreement, distinct cash/margin fields, missing-value handling and all-false financial authority. Real production read qualification uses the owner's existing selected account and a current explicitly scoped session. Prior failed cash-only captures remain factual history and are not retroactively changed to passes.

Wave 1 closes only under the canonical plan's exit gates. After closure, the standing owner workflow is commit, GitHub PR, required checks/review, merge, verify the merged revision, and then continue through the orchestration task. This amendment does not activate Preview, Place, Cancel, deployment, or unattended execution.
