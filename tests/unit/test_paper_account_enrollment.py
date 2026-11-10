from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperCredentialReference,
)
from packages.application.paper_account_enrollment import (
    PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION,
    PaperAccountEnrollmentAttestation,
    PaperAccountEnrollmentAttestationError,
    attest_paper_account_enrollment,
)

ACCOUNT_ID = "paper-account-primary"
PROVIDER_ACCOUNT_ID = "734cfc97-320f-49b1-9a50-8ec9f96b569c"
BINDING_ID = "9bcb1bf9-30f5-41d7-bfaa-e0a207d7c49c"
BINDING_SHA256 = "1" * 64
CHECKED_AT = datetime(2026, 7, 31, 14, 30, tzinfo=UTC)
QUALIFIED_AT = CHECKED_AT - timedelta(days=1)


def _reference() -> AlpacaPaperCredentialReference:
    return AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/primary",
        secret_version="2026-07-30",
    )


def _receipt(
    reference: AlpacaPaperCredentialReference,
    *,
    account_id: str = ACCOUNT_ID,
    expected_provider_account_id: str = PROVIDER_ACCOUNT_ID,
    credential_reference_sha256: str | None = None,
    checked_at: datetime = CHECKED_AT,
    sequence_number: int = 2,
) -> AlpacaPaperAccountIdentityContinuityReceipt:
    receipt = object.__new__(AlpacaPaperAccountIdentityContinuityReceipt)
    for field_name, value in (
        ("account_id", account_id),
        ("binding_id", BINDING_ID),
        ("binding_sha256", BINDING_SHA256),
        (
            "credential_reference_sha256",
            (
                reference.semantic_sha256
                if credential_reference_sha256 is None
                else credential_reference_sha256
            ),
        ),
        ("expected_provider_account_id", expected_provider_account_id),
        ("sequence_number", sequence_number),
        ("binding_qualified_at", QUALIFIED_AT),
        ("checked_at", checked_at),
    ):
        object.__setattr__(receipt, field_name, value)
    return receipt


class FixedRepository:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[AlpacaPaperCredentialReference, datetime]] = []

    def authenticate_configured_terminal_identity(
        self,
        reference: AlpacaPaperCredentialReference,
        checked_at: datetime,
    ) -> object:
        self.calls.append((reference, checked_at))
        return self.result


def test_attests_exact_historical_enrollment_without_authority() -> None:
    reference = _reference()
    receipt = _receipt(reference)
    repository = FixedRepository(receipt)

    result = attest_paper_account_enrollment(
        reference,
        repository=repository,  # type: ignore[arg-type]
        checked_at=CHECKED_AT,
    )

    assert repository.calls == [(reference, CHECKED_AT)]
    assert result.binding_sha256 == receipt.binding_sha256
    assert result.credential_reference_sha256 == reference.semantic_sha256
    assert result.identity_receipt_sha256 == receipt.semantic_sha256
    assert result.sequence_number == receipt.sequence_number
    assert result.historical is True
    assert result.current is False
    assert result.account_status_current is False
    assert result.binding_fresh is False
    assert result.operational_control_authenticated is False
    assert result.broker_action_authorized is False
    assert result.new_exposure_authorized is False
    assert result.automatic_rearm_authorized is False
    assert result.strategy_invocation_authorized is False
    assert len(result.semantic_sha256) == 64


def test_public_payload_is_digest_only_and_non_authorizing() -> None:
    reference = _reference()
    receipt = _receipt(reference)
    result = attest_paper_account_enrollment(
        reference,
        repository=FixedRepository(receipt),  # type: ignore[arg-type]
        checked_at=CHECKED_AT,
    )

    assert result.public_payload == {
        "account_status_current": False,
        "automatic_rearm_authorized": False,
        "binding_fresh": False,
        "binding_sha256": BINDING_SHA256,
        "broker_action_authorized": False,
        "contract_version": PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION,
        "credential_reference_sha256": reference.semantic_sha256,
        "current": False,
        "historical": True,
        "identity_receipt_sha256": receipt.semantic_sha256,
        "new_exposure_authorized": False,
        "operational_control_authenticated": False,
        "sequence_number": 2,
        "status": "historical_paper_account_enrollment_attested_non_authorizing",
        "strategy_invocation_authorized": False,
    }
    serialized = json.dumps(result.public_payload, sort_keys=True)
    for sensitive_value in (
        ACCOUNT_ID,
        PROVIDER_ACCOUNT_ID,
        BINDING_ID,
        reference.secret_ref,
        reference.secret_version,
        CHECKED_AT.isoformat(),
        QUALIFIED_AT.isoformat(),
    ):
        assert sensitive_value not in serialized


def test_attestation_constructor_is_not_public() -> None:
    with pytest.raises(TypeError, match="must be produced"):
        PaperAccountEnrollmentAttestation()


@pytest.mark.parametrize(
    "reference",
    [
        None,
        object(),
        {
            "account_id": ACCOUNT_ID,
            "expected_provider_account_id": PROVIDER_ACCOUNT_ID,
        },
    ],
)
def test_rejects_non_exact_credential_reference_before_repository(
    reference: object,
) -> None:
    repository = FixedRepository(None)

    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="exact Alpaca paper credential reference",
    ):
        attest_paper_account_enrollment(
            reference,  # type: ignore[arg-type]
            repository=repository,  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )

    assert repository.calls == []


@pytest.mark.parametrize(
    "checked_at",
    [
        None,
        "2026-07-31T14:30:00Z",
        datetime(2026, 7, 31, 14, 30),
        datetime(2026, 7, 31, 10, 30, tzinfo=timezone(timedelta(hours=-4))),
    ],
)
def test_rejects_non_exact_utc_check_time_before_repository(
    checked_at: object,
) -> None:
    repository = FixedRepository(None)

    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="checked_at must be an exact UTC datetime",
    ):
        attest_paper_account_enrollment(
            _reference(),
            repository=repository,  # type: ignore[arg-type]
            checked_at=checked_at,  # type: ignore[arg-type]
        )

    assert repository.calls == []


def test_rejects_missing_repository_method() -> None:
    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="does not implement",
    ):
        attest_paper_account_enrollment(
            _reference(),
            repository=object(),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )


def test_repository_failure_is_redacted() -> None:
    secret_detail = "secret-provider-detail"

    class FailingRepository:
        def authenticate_configured_terminal_identity(
            self,
            reference: AlpacaPaperCredentialReference,
            checked_at: datetime,
        ) -> None:
            del reference, checked_at
            raise RuntimeError(secret_detail)

    with pytest.raises(PaperAccountEnrollmentAttestationError) as raised:
        attest_paper_account_enrollment(
            _reference(),
            repository=FailingRepository(),
            checked_at=CHECKED_AT,
        )

    assert secret_detail not in str(raised.value)
    assert raised.value.__cause__ is None


def test_repository_method_lookup_failure_is_redacted() -> None:
    secret_detail = "secret-descriptor-detail"

    class FailingRepository:
        @property
        def authenticate_configured_terminal_identity(self) -> None:
            raise RuntimeError(secret_detail)

    with pytest.raises(PaperAccountEnrollmentAttestationError) as raised:
        attest_paper_account_enrollment(
            _reference(),
            repository=FailingRepository(),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )

    assert secret_detail not in str(raised.value)
    assert raised.value.__cause__ is None


def test_rejects_absent_enrollment_history() -> None:
    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="enrollment history is absent",
    ):
        attest_paper_account_enrollment(
            _reference(),
            repository=FixedRepository(None),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )


@pytest.mark.parametrize("result", [object(), {}, "receipt"])
def test_rejects_non_exact_identity_receipt(result: object) -> None:
    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="returned invalid evidence",
    ):
        attest_paper_account_enrollment(
            _reference(),
            repository=FixedRepository(result),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"account_id": "another-paper-account"}, "conflicts"),
        (
            {"expected_provider_account_id": "7fe4ac38-df11-4057-b22e-594a27628762"},
            "conflicts",
        ),
        ({"credential_reference_sha256": "2" * 64}, "conflicts"),
        ({"checked_at": CHECKED_AT + timedelta(microseconds=1)}, "conflicts"),
    ],
)
def test_rejects_identity_continuity_mismatch(
    overrides: dict[str, Any],
    expected_message: str,
) -> None:
    reference = _reference()
    receipt = _receipt(reference, **overrides)

    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match=expected_message,
    ):
        attest_paper_account_enrollment(
            reference,
            repository=FixedRepository(receipt),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )


def test_rejects_malformed_exact_identity_receipt() -> None:
    reference = _reference()
    receipt = _receipt(reference, sequence_number=True)

    with pytest.raises(
        PaperAccountEnrollmentAttestationError,
        match="identity evidence is malformed",
    ):
        attest_paper_account_enrollment(
            reference,
            repository=FixedRepository(receipt),  # type: ignore[arg-type]
            checked_at=CHECKED_AT,
        )
