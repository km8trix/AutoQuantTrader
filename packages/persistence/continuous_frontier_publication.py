"""Compose original retained market frontiers through the sole C/B engine.

The caller supplies captures and clock references retained by the actual source
owners. This module performs no provider acquisition or clock renewal and does
not create an account, change controls, authorize an assignment or deliver orders.
"""

from hashlib import sha256
from typing import cast

from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.application.continuous_source_events import project_continuous_daily_frontier
from packages.domain.continuous_composition_contracts import FORWARD_CLOSURE_SCHEMA
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousAccountReceipt,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
)
from packages.domain.identifiers import canonical_id
from packages.domain.runtime_operating_contracts import RuntimeClockReference
from packages.persistence.continuous_account import (
    PreparedContinuousCommit,
    ResolvedContinuousAccount,
    SqlContinuousAccount,
)
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_forward_sources import ResolvedContinuousForwardSources
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources


class SqlContinuousFrontierPublication:
    def __init__(self, *, account: SqlContinuousAccount) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(account.composer) is not SqlContinuousCommitComposer
            or type(account.composer.producer_history) is not SqlContinuousRuntimeSources
        ):
            raise ValueError("EXACT_CONTINUOUS_FRONTIER_OWNERS_REQUIRED")
        self.account, self.composer = account, account.composer
        self.runtime = cast(SqlContinuousRuntimeSources, self.composer.producer_history)
        self.daily = self.composer.daily
        if (
            self.runtime.accounts is not account
            or self.runtime.daily is not self.daily
            or self.daily.producers is not self.runtime
            or self.account.preparer.runtime_evidence is not self.runtime
            or self.composer.forward_sources is not self.runtime.forward_sources
        ):
            raise ValueError("EXACT_CONTINUOUS_FRONTIER_GRAPH_REQUIRED")
        self._bindings = self._current_bindings()

    def _current_bindings(self) -> tuple[object, ...]:
        return (
            self.account,
            self.composer,
            self.runtime,
            self.daily,
            self.account.engine,
            self.account.coordinator,
            self.account.preparer,
            self.account.composer,
            self.account.artifacts,
            self.account.codec,
            self.composer.daily,
            self.composer.producer_history,
            self.composer.forward_sources,
            self.runtime.accounts,
            self.runtime.daily,
            self.runtime.forward_sources,
            self.runtime.operating,
            self.runtime.accounting,
            self.runtime.strategy,
            self.runtime.current_fence,
            self.daily.producers,
            self.account.preparer.runtime_evidence,
        )

    def _require_bindings(self) -> None:
        if any(
            left is not right
            for left, right in zip(self._current_bindings(), self._bindings, strict=True)
        ):
            raise ValueError("ORIGINAL_CONTINUOUS_FRONTIER_OWNERS_CHANGED")

    def publish(self, prepared: PreparedContinuousCommit) -> ContinuousAccountReceipt:
        self._require_bindings()
        self.composer.require_prepared(prepared.composition)
        if prepared.previous is None or prepared.commit.source_evidence.schema_id not in (
            FORWARD_CLOSURE_SCHEMA,
            CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
        ):
            raise ValueError("ORIGINAL_CONTINUOUS_MARKET_FRONTIER_REQUIRED")
        fence = self.runtime.current_fence()
        with self.account.write_transaction() as connection:
            receipt = self.account.commit_in_transaction(connection, prepared=prepared, fence=fence)
            self.composer.recheck_frontier_publication_in_transaction(
                connection, prepared, receipt, fence=fence
            )
        return receipt

    def _market_reference(
        self, previous: ResolvedContinuousAccount, market: ResolvedContinuousForwardSources
    ) -> ContinuousEvidenceRef:
        self._require_bindings()
        self.account.require_resolved(previous)
        self.runtime.forward_sources.require_resolved(market)
        closure = market.closure
        if closure.account_id != previous.receipt.commit.scope.account_id:
            raise ValueError("ORIGINAL_MARKET_ACCOUNT_SCOPE_DIFFERS")
        payload = self.account.codec.encode_record(closure)
        if not 0 < len(payload) <= MAX_CONTINUOUS_OBJECT_BYTES:
            raise ValueError("ORIGINAL_MARKET_CLOSURE_BOUND_EXCEEDED")
        reference = self.account.artifacts.put(payload, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
        if (reference.byte_count, reference.object_sha256, reference.codec_version) != (
            len(payload),
            sha256(payload).hexdigest(),
            "personal-record/1",
        ):
            raise ValueError("ORIGINAL_MARKET_CLOSURE_STORAGE_DIFFERS")
        return ContinuousEvidenceRef(
            FORWARD_CLOSURE_SCHEMA
            if type(closure) is ContinuousForwardClosure
            else CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
            reference,
            closure.semantic_sha256,
        )

    def prepare_quote(
        self,
        *,
        command_id: str,
        previous: ResolvedContinuousAccount,
        market: ResolvedContinuousForwardSources,
    ) -> PreparedContinuousCommit:
        reference = self._market_reference(previous, market)
        if type(market.closure) is not ContinuousQuoteClosure:
            raise ValueError("ORIGINAL_QUOTE_FRONTIER_REQUIRED")
        frontier = project_continuous_quote_frontier(
            checkpoint=previous.checkpoint, closure=market.closure, source_state=market.state
        )
        transition = self.account.preparer.prepare_frontier(
            command_id=command_id, checkpoint=previous.checkpoint, frontier=frontier
        )
        if transition.new_decisions:
            raise ValueError("QUOTE_FRONTIER_CANNOT_CREATE_DAILY_DECISIONS")
        return self.account.prepare(
            transition,
            scope=previous.receipt.commit.scope,
            previous=previous,
            source_evidence=reference,
        )

    def prepare_daily(
        self,
        *,
        command_id: str,
        previous: ResolvedContinuousAccount,
        market: ResolvedContinuousForwardSources,
        clock_reference: RuntimeClockReference,
    ) -> PreparedContinuousCommit:
        reference = self._market_reference(previous, market)
        closure = market.closure
        if type(closure) is not ContinuousForwardClosure:
            raise ValueError("ORIGINAL_DAILY_FRONTIER_REQUIRED")
        scope = previous.receipt.commit.scope
        frontier = project_continuous_daily_frontier(
            checkpoint=previous.checkpoint,
            source_state=market.state,
            observation_ids=closure.observation_ids,
            frontier_id=closure.closure_id,
            admitted_at=closure.admitted_at,
            benchmark_instrument_id=self.composer.benchmark_instrument_id,
            capture_evidence_class=closure.evidence_class,
        )
        fence = self.runtime.current_fence()
        descriptor = self.runtime.prepare_descriptor(
            descriptor_id=canonical_id(
                "continuous-frontier-source/1", command_id, reference.semantic_sha256
            ),
            scope=scope,
            request=frontier,
            market_source=reference,
            previous=previous,
            fence=fence,
            clock_reference=clock_reference,
            request_kind="frontier",
            accounts=self.account,
            daily=self.daily,
        )
        with self.account.write_transaction() as connection:
            self.runtime.append_descriptor_in_transaction(connection, descriptor, fence=fence)
        resolved = self.runtime.resolve_prepared_descriptor(descriptor)
        self.runtime.require_resolved(resolved)
        transition = self.account.preparer.prepare_frontier(
            command_id=command_id, checkpoint=previous.checkpoint, frontier=frontier
        )
        if len(transition.new_decisions) > 1:
            raise ValueError("ONE_CANONICAL_DAILY_DECISION_FRONTIER_REQUIRED")
        admissions = []
        for decision in transition.new_decisions:
            admission_id = canonical_id(
                "continuous-frontier-admission/1", command_id, decision.batch.semantic_sha256
            )
            current = self.daily.resolve_snapshot(
                self.daily.read_snapshot(
                    account_id=scope.account_id,
                    fence=fence,
                    command_id=admission_id,
                    input_refs=decision.evidence.inputs,
                )
            )
            admissions.append(
                self.daily.prepare_admission(
                    current,
                    command_id=admission_id,
                    request_sha256=decision.batch.semantic_sha256,
                    batch=decision.batch,
                    assignment_sha256=decision.evidence.assignment.semantic_sha256,
                    input_refs=decision.evidence.inputs,
                    prepared_commitments=decision.installed_commitments,
                )
            )
        return self.account.prepare(
            transition,
            scope=scope,
            previous=previous,
            source_evidence=reference,
            admissions=tuple(admissions),
        )
