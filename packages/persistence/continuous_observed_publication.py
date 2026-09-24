"""Publish actual independent venue observations through the sole C/B/A owners.

The caller supplies an original resolved financial-scope capture. Registration
mapping and capture acquisition remain with their concrete owners. This wrapper
does not create observations, choose an outcome or renew risk/source authority.
"""

from dataclasses import dataclass, field, fields
from typing import cast
from weakref import WeakValueDictionary, finalize

from packages.application.continuous_venue_frontier import (
    continuous_initial_cash_application,
    project_continuous_venue_frontier,
)
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_observed_hold_sources import (
    PreparedContinuousObservedHoldSource,
    SqlContinuousObservedHoldSources,
)
from packages.persistence.continuous_reconciliation_publication import (
    ContinuousReconciliationPublicationReceipt,
    PreparedContinuousReconciliationPublication,
    ResolvedContinuousReconciliationPublication,
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.continuous_venue_sources import ResolvedContinuousVenueSources
from packages.persistence.daily_runtime_risk import (
    PreparedDailyObservedHolds,
    ResolvedDailyRuntimeSnapshot,
)


class ContinuousObservedPublicationError(ValueError):
    """Static ownership, scope or original-source mismatch."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousObservedPublication:
    source: PreparedContinuousObservedHoldSource
    holds: PreparedDailyObservedHolds
    publication: PreparedContinuousReconciliationPublication
    prior: ResolvedContinuousReconciliationPublication | None
    seal: object = field(repr=False, compare=False)


class SqlContinuousObservedPublication:
    def __init__(self, *, account: SqlContinuousAccount) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(account.composer) is not SqlContinuousCommitComposer
            or type(account.composer.producer_history) is not SqlContinuousRuntimeSources
        ):
            raise ContinuousObservedPublicationError("EXACT_OBSERVED_PUBLICATION_OWNERS_REQUIRED")
        self.account, self.composer = account, account.composer
        self.runtime = cast(SqlContinuousRuntimeSources, self.composer.producer_history)
        publisher, observed = self.runtime.publisher, self.runtime.observed_hold_sources
        if (
            type(publisher) is not SqlContinuousReconciliationPublication
            or type(observed) is not SqlContinuousObservedHoldSources
            or publisher.account is not account
            or publisher.composer is not self.composer
            or publisher.sources is not self.composer.venue_sources
            or publisher.accounting is not self.runtime.accounting
            or self.runtime.accounts is not account
            or self.runtime.daily is not self.composer.daily
            or self.composer.daily.producers is not self.runtime
            or account.preparer.runtime_evidence is not self.runtime
            or account.preparer.accounting is not self.runtime.accounting
            or account.codec is not self.runtime.codec
            or account.artifacts is not self.runtime.artifacts
            or publisher.codec is not account.codec
            or publisher.artifacts is not account.artifacts
        ):
            raise ContinuousObservedPublicationError("EXACT_OBSERVED_PUBLICATION_GRAPH_REQUIRED")
        self.publisher, self.observed, self.daily = publisher, observed, self.composer.daily
        self.venue_sources = publisher.sources
        self.runtime.bind_observed_hold_sources(observed)
        self._seal = object()
        self._owned: WeakValueDictionary[int, PreparedContinuousObservedPublication] = (
            WeakValueDictionary()
        )
        self._originals: dict[int, tuple[object, ...]] = {}
        self._bindings = self._current_bindings()

    def _current_bindings(self) -> tuple[object, ...]:
        return (
            self.account,
            self.composer,
            self.runtime,
            self.publisher,
            self.observed,
            self.daily,
            self.venue_sources,
            self.account.engine,
            self.account.coordinator,
            self.account.composer,
            self.account.preparer,
            self.account.codec,
            self.account.artifacts,
            self.account.preparer.runtime_evidence,
            self.account.preparer.accounting,
            self.runtime.accounts,
            self.runtime.daily,
            self.runtime.publisher,
            self.runtime.observed_hold_sources,
            self.runtime.accounting,
            self.runtime.strategy,
            self.runtime.current_fence,
            self.composer.daily,
            self.composer.producer_history,
            self.composer.venue_sources,
            self.composer.fence,
            self.daily.producers,
            self.daily.accounting,
            self.daily.codec,
            self.publisher.account,
            self.publisher.composer,
            self.publisher.sources,
            self.publisher.applied,
            self.publisher.applied.reader,
            self.publisher.journal,
            self.publisher.accounting,
            self.publisher.codec,
            self.publisher.artifacts,
            self.observed.accounts,
            self.observed.daily,
            self.observed.preparer,
            self.observed.venue_sources,
            self.venue_sources.model,
            self.venue_sources.scope,
            self.venue_sources.journal,
            self.venue_sources.resolver,
        )

    def _require_bindings(self) -> None:
        if any(
            original is not current
            for original, current in zip(self._bindings, self._current_bindings(), strict=True)
        ):
            raise ContinuousObservedPublicationError("ORIGINAL_OBSERVED_PUBLICATION_OWNERS_CHANGED")
        self.runtime.bind_observed_hold_sources(self.observed)

    def prepare(
        self,
        *,
        command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        venue: ResolvedContinuousVenueSources,
        prior: ResolvedContinuousReconciliationPublication | None,
    ) -> PreparedContinuousObservedPublication:
        """Prepare original captured economics outside the account write transaction."""
        self._require_bindings()
        self.account.require_resolved(previous)
        self.daily.require_resolved_snapshot(current)
        self.venue_sources.require_resolved(venue)
        if prior is not None:
            self.publisher.require_resolved(prior)
        scope = previous.receipt.commit.scope
        if (
            current.raw.account_id != scope.account_id
            or current.raw.receipt.fence != self.runtime.current_fence()
            or current.raw.receipt.fence != self.composer.fence
            or venue.capture.manifest.scope != self.venue_sources.scope
            or venue.capture.observed.scope != self.venue_sources.scope
            or (prior is not None and prior.continuous.receipt.commit.scope != scope)
        ):
            raise ContinuousObservedPublicationError("ORIGINAL_OBSERVED_SCOPE_OR_FENCE_DIFFERS")
        applications = (
            (
                continuous_initial_cash_application(
                    previous.checkpoint, accounting=self.runtime.accounting
                ),
            )
            if prior is None
            else prior.reconciliation.resolved.applications.applications
        )
        frontier = project_continuous_venue_frontier(
            checkpoint=previous.checkpoint,
            capture=venue.capture,
            prior_applications=applications,
            frontier_id=command_id,
            admitted_at=current.raw.receipt.validated_at,
        )
        transition = self.account.preparer.prepare_frontier(
            command_id=command_id, checkpoint=previous.checkpoint, frontier=frontier
        )
        if transition.new_decisions:
            raise ContinuousObservedPublicationError(
                "VENUE_FRONTIER_REQUIRES_SEPARATE_MARKET_ADMISSION"
            )
        source = self.observed.retain_source(
            previous=previous, transition=transition, venue=venue, current=current
        )
        resolved = self.daily.resolve_snapshot(
            self.daily.read_observed_hold_snapshot(
                account_id=scope.account_id,
                fence=current.raw.receipt.fence,
                source_ref=source.reference,
            )
        )
        holds = self.daily.prepare_observed_holds(resolved)
        if holds.retry:
            raise ContinuousObservedPublicationError("OBSERVED_RESTORE_ORIGINAL_RETRY_REQUIRED")
        canonical = self.account.prepare(
            transition,
            scope=scope,
            previous=previous,
            source_evidence=source.inputs.source.venue_capture,
            observed_holds=holds,
        )
        publication = self.publisher.prepare(canonical, previous=prior)
        value = PreparedContinuousObservedPublication(source, holds, publication, prior, self._seal)
        self._owned[id(value)] = value
        self._originals[id(value)] = tuple(getattr(value, item.name) for item in fields(value))
        finalize(value, self._originals.pop, id(value), None)
        self.require_prepared(value)
        return value

    def require_prepared(self, value: PreparedContinuousObservedPublication) -> None:
        """Full original source/hold/A content validation before entering SQL."""
        self._require_bindings()
        if (
            type(value) is not PreparedContinuousObservedPublication
            or self._owned.get(id(value)) is not value
            or value.seal is not self._seal
            or any(
                getattr(value, item.name) is not original
                for item, original in zip(fields(value), self._originals[id(value)], strict=True)
            )
        ):
            raise ContinuousObservedPublicationError("OWNED_ORIGINAL_OBSERVED_PUBLICATION_REQUIRED")
        self.observed.require_prepared(value.source)
        self.daily.require_prepared_observed_holds(value.holds)
        self.daily.require_resolved_snapshot(value.holds.snapshot)
        self.publisher.require_prepared(value.publication)
        if value.prior is not None:
            self.publisher.require_resolved(value.prior)
        if (
            value.publication.continuous.previous is not value.source.previous
            or value.publication.continuous.commit.source_evidence
            != value.source.inputs.source.venue_capture
            or value.holds.snapshot.raw.requested_observed_source != value.source.reference
            or value.publication.continuous.commit.transition.command_id
            != value.source.transition.command_id
            or value.publication.continuous.commit.transition.checkpoint_sha256
            != value.source.transition.checkpoint.semantic_sha256
        ):
            raise ContinuousObservedPublicationError(
                "ORIGINAL_OBSERVED_PUBLICATION_BINDINGS_DIFFER"
            )

    def publish(
        self, value: PreparedContinuousObservedPublication
    ) -> ContinuousReconciliationPublicationReceipt:
        self.require_prepared(value)
        fence = self.runtime.current_fence()
        if fence != value.source.current.raw.receipt.fence:
            raise ContinuousObservedPublicationError("ORIGINAL_OBSERVED_PUBLICATION_FENCE_CHANGED")
        # The actual A owner performs exact post-C/B/A/source readbacks after its
        # write. The C owner checks the original deadline again before outer COMMIT.
        return self.publisher.publish(value.publication, fence=fence)
