"""Pure retained statement metadata, never authenticated or durable resolution.

Copy this record before generic codec traversal. The unchanged codec is not a
mutation-admission boundary. No file, session, journal or control is consulted.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
    copy_operational_control_operator_statement,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.research_job_contracts import ObjectRef

OPERATOR_STATEMENT_RECORD_SCHEMA = "operational-control-operator-statement-record/1"
_VERSION = "personal-operational-control-operator-statement-record/1"
_ERROR = "OPERATOR_STATEMENT_RECORD_INVALID"

type _Values = tuple[OperationalControlOperatorStatement, ObjectRef, datetime]


def _native_fields(digest: object, count: object, codec: object, expiry: object) -> bool:
    return (
        type(digest) is str
        and type(count) is int
        and type(codec) is str
        and type(expiry) is datetime
        and expiry.tzinfo is UTC
    )


@dataclass(frozen=True, slots=True, kw_only=True, eq=False, repr=False)
class OperationalControlOperatorStatementRecord(ContractRecord):
    contract_version: ClassVar[str] = _VERSION
    statement: OperationalControlOperatorStatement
    evidence: ObjectRef
    session_expires_at: datetime

    def __post_init__(self) -> None:
        values = _validated_values(self)
        object.__setattr__(self, "statement", values[0])
        object.__setattr__(self, "evidence", values[1])
        object.__setattr__(self, "session_expires_at", values[2])

    @property
    def record_id(self) -> str:
        return _validated_values(self)[0].statement_id

    @property
    def semantic_sha256(self) -> str:
        statement, evidence, expiry = _validated_values(self)
        return content_digest(
            (
                _VERSION,
                "operator_statement_record",
                statement.semantic_sha256,
                evidence.object_sha256,
                evidence.byte_count,
                evidence.codec_version,
                expiry,
            )
        )


def _validated_values(value: object) -> _Values:
    if type(value) is not OperationalControlOperatorStatementRecord:
        raise ValueError(_ERROR)
    statement, evidence, expiry = value.statement, value.evidence, value.session_expires_at
    if (
        type(statement) is not OperationalControlOperatorStatement
        or type(evidence) is not ObjectRef
    ):
        raise ValueError(_ERROR)
    digest, count, codec = evidence.object_sha256, evidence.byte_count, evidence.codec_version
    # Freeze all reference leaves and expiry before D can invoke any helper.
    if not _native_fields(digest, count, codec, expiry):
        raise ValueError(_ERROR)
    copied_statement = copy_operational_control_operator_statement(statement)
    copied_evidence = ObjectRef(digest, count, codec)
    checked = copied_statement.authentication_checked_at
    if (
        copied_statement.resolution_claim.resolution_evidence_sha256 != digest
        or copied_statement.actor.authenticated_at != checked
        or copied_statement.attested_at != checked
        or not checked < expiry
    ):
        raise ValueError(_ERROR)
    return copied_statement, copied_evidence, expiry


def copy_operational_control_operator_statement_record(
    value: OperationalControlOperatorStatementRecord,
) -> OperationalControlOperatorStatementRecord:
    """Freeze declared data before encoding; copying grants no ownership."""
    statement, evidence, expiry = _validated_values(value)
    return OperationalControlOperatorStatementRecord(
        statement=statement,
        evidence=evidence,
        session_expires_at=expiry,
    )
