"""Point-in-time security identity and universe resolution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from packages.market_data.models import (
    RevisionPolicy,
    Security,
    SecurityIdentifier,
    UniverseMembership,
    require_utc,
)
from packages.market_data.temporal import RevisionConflictError, select_as_of


class SecurityResolutionError(LookupError):
    """Base class for fail-closed security-master lookups."""


class UnknownSecurityError(SecurityResolutionError):
    pass


class AmbiguousSecurityError(SecurityResolutionError):
    pass


class NonTradableSecurityError(SecurityResolutionError):
    pass


@dataclass(frozen=True, slots=True)
class SecurityMaster:
    securities: tuple[Security, ...]
    identifiers: tuple[SecurityIdentifier, ...]
    memberships: tuple[UniverseMembership, ...] = ()

    def __post_init__(self) -> None:
        if not self.securities:
            raise ValueError("security master requires at least one security")
        security_ids = [security.security_id for security in self.securities]
        if len(security_ids) != len(set(security_ids)):
            raise ValueError("security IDs must be unique")
        known = set(security_ids)
        if any(identifier.security_id not in known for identifier in self.identifiers):
            raise ValueError("every identifier must reference a known security")
        if any(membership.security_id not in known for membership in self.memberships):
            raise ValueError("every membership must reference a known security")

    def get(self, security_id: str) -> Security:
        matches = [security for security in self.securities if security.security_id == security_id]
        if not matches:
            raise UnknownSecurityError(f"unknown security ID: {security_id!r}")
        return matches[0]

    def resolve_identifier(
        self,
        *,
        symbol: str,
        venue: str,
        effective_at: datetime,
        as_of: datetime,
        policy: RevisionPolicy = RevisionPolicy.REVISED_AS_OF,
        require_tradable: bool = True,
    ) -> SecurityIdentifier:
        require_utc(effective_at, "effective_at")
        require_utc(as_of, "as_of")
        try:
            visible = select_as_of(self.identifiers, as_of=as_of, policy=policy)
        except RevisionConflictError as error:
            raise AmbiguousSecurityError(str(error)) from error
        matches = [
            identifier
            for identifier in visible
            if identifier.symbol == symbol
            and identifier.venue == venue
            and identifier.is_effective_at(effective_at)
        ]
        if not matches:
            raise UnknownSecurityError(f"no causal security mapping for {symbol!r} on {venue!r}")
        security_ids = {identifier.security_id for identifier in matches}
        if len(matches) != 1 or len(security_ids) != 1:
            raise AmbiguousSecurityError(
                f"ambiguous causal security mapping for {symbol!r} on {venue!r}"
            )
        if require_tradable and not matches[0].tradable:
            raise NonTradableSecurityError(
                f"security mapping for {symbol!r} on {venue!r} is not tradable"
            )
        return matches[0]

    def resolve_security(
        self,
        *,
        symbol: str,
        venue: str,
        effective_at: datetime,
        as_of: datetime,
        policy: RevisionPolicy = RevisionPolicy.REVISED_AS_OF,
        require_tradable: bool = True,
    ) -> Security:
        identifier = self.resolve_identifier(
            symbol=symbol,
            venue=venue,
            effective_at=effective_at,
            as_of=as_of,
            policy=policy,
            require_tradable=require_tradable,
        )
        return self.get(identifier.security_id)

    def universe_members(
        self,
        *,
        universe_id: str,
        effective_at: datetime,
        as_of: datetime,
        policy: RevisionPolicy = RevisionPolicy.REVISED_AS_OF,
    ) -> tuple[Security, ...]:
        require_utc(effective_at, "effective_at")
        require_utc(as_of, "as_of")
        try:
            visible = select_as_of(self.memberships, as_of=as_of, policy=policy)
        except RevisionConflictError as error:
            raise AmbiguousSecurityError(str(error)) from error
        effective = [
            membership
            for membership in visible
            if membership.universe_id == universe_id and membership.is_effective_at(effective_at)
        ]
        by_security: dict[str, set[bool]] = {}
        for membership in effective:
            by_security.setdefault(membership.security_id, set()).add(membership.included)
        ambiguous = [security_id for security_id, states in by_security.items() if len(states) > 1]
        if ambiguous:
            raise AmbiguousSecurityError(
                f"conflicting universe membership for security IDs: {sorted(ambiguous)!r}"
            )
        return tuple(
            sorted(
                (
                    self.get(security_id)
                    for security_id, states in by_security.items()
                    if states == {True}
                ),
                key=lambda security: security.security_id,
            )
        )
