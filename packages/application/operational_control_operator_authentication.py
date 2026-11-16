"""Distinct transient statement authentication, never durable resolution authority."""

from dataclasses import dataclass, field
from datetime import datetime

from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, repr=False)
class AuthenticatedOperationalControlOperatorStatement:
    statement: OperationalControlOperatorStatement
    session_expires_at: datetime
    seal: object = field(repr=False, compare=False)
