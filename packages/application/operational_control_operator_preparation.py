"""Transient prepared record inputs, never retained resolution authority."""

from dataclasses import dataclass, field
from datetime import datetime

from packages.application.operational_control_operator_authentication import (
    AuthenticatedOperationalControlOperatorStatement,
)
from packages.domain.operational_control_operator_record import (
    OperationalControlOperatorStatementRecord,
)


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, repr=False)
class PreparedOperationalControlOperatorStatementRecord:
    record: OperationalControlOperatorStatementRecord
    authenticated: AuthenticatedOperationalControlOperatorStatement
    before_read_at: datetime
    checked_at: datetime
    seal: object = field(repr=False, compare=False)
