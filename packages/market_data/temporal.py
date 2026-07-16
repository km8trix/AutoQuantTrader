"""Causal revision selection shared by market and security-master facts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from packages.market_data.models import RevisionPolicy, require_utc


class RevisionConflictError(ValueError):
    """One logical observation has two different facts at the same revision."""


class RevisionedFact(Protocol):
    @property
    def observation_id(self) -> str: ...

    @property
    def event_revision_id(self) -> str: ...

    @property
    def revision(self) -> int: ...

    @property
    def available_at(self) -> datetime: ...

    @property
    def event_time(self) -> datetime: ...


def _select_as_of[RevisionedT: RevisionedFact](
    facts: Iterable[RevisionedT],
    *,
    as_of: datetime,
    policy: RevisionPolicy,
    reject_conflicts: bool,
) -> tuple[RevisionedT, ...]:
    require_utc(as_of, "as_of")
    visible: dict[str, list[RevisionedT]] = defaultdict(list)
    for fact in facts:
        if fact.available_at <= as_of:
            visible[fact.observation_id].append(fact)

    selected: list[RevisionedT] = []
    for observation_id, revisions in visible.items():
        by_revision: dict[int, list[RevisionedT]] = defaultdict(list)
        for fact in revisions:
            by_revision[fact.revision].append(fact)
        for revision, same_revision in by_revision.items():
            event_ids = {fact.event_revision_id for fact in same_revision}
            if reject_conflicts and len(event_ids) > 1:
                raise RevisionConflictError(
                    f"observation {observation_id!r} has conflicting revision {revision}"
                )

        desired_revision = (
            min(by_revision) if policy is RevisionPolicy.FIRST_SEEN else max(by_revision)
        )
        # Exact duplicates collapse deterministically. Quality checks still
        # report them when given the uncollapsed input sequence.
        selected.append(
            min(
                by_revision[desired_revision],
                key=lambda fact: fact.event_revision_id,
            )
        )

    return tuple(
        sorted(
            selected,
            key=lambda fact: (
                fact.event_time,
                fact.available_at,
                fact.observation_id,
                fact.revision,
                fact.event_revision_id,
            ),
        )
    )


def select_as_of[RevisionedT: RevisionedFact](
    facts: Iterable[RevisionedT],
    *,
    as_of: datetime,
    policy: RevisionPolicy,
) -> tuple[RevisionedT, ...]:
    """Select the causal fact for each observation at ``as_of``.

    ``FIRST_SEEN`` retains the first vendor revision. ``REVISED_AS_OF`` exposes
    only the latest correction that had become available by the simulated
    clock. Conflicting facts at one revision fail closed.
    """

    return _select_as_of(
        facts,
        as_of=as_of,
        policy=policy,
        reject_conflicts=True,
    )


def select_as_of_for_quality[RevisionedT: RevisionedFact](
    facts: Iterable[RevisionedT],
    *,
    as_of: datetime,
    policy: RevisionPolicy,
) -> tuple[RevisionedT, ...]:
    """Deterministic selection used after conflicts have been reported."""

    return _select_as_of(
        facts,
        as_of=as_of,
        policy=policy,
        reject_conflicts=False,
    )
