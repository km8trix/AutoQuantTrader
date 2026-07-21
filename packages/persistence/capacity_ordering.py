"""Authenticated ordering metadata for capacity-affecting SQL facts."""

from __future__ import annotations

import hashlib

from packages.domain.canonical import canonical_json_bytes

CAPACITY_VISIBILITY_CONTRACT_VERSION = "phase2-capacity-visibility-v1"
SUBMISSION_EVENT_VISIBILITY_KIND = "submission_event"
ORDER_EVENT_VISIBILITY_KIND = "order_event"
RESERVATION_RELEASE_VISIBILITY_KIND = "reservation_release"


class CapacityVisibilityError(ValueError):
    """A capacity mutation has malformed or unauthenticated ordering metadata."""


def capacity_visibility_sha256(
    *,
    account_id: str,
    fact_kind: str,
    fact_sha256: str,
    visible_after_observation_sequence: int,
) -> str:
    """Bind one current-writer mutation to its account decision watermark."""

    if type(account_id) is not str or not account_id or account_id != account_id.strip():
        raise CapacityVisibilityError("capacity visibility requires a valid account ID")
    if fact_kind not in {
        SUBMISSION_EVENT_VISIBILITY_KIND,
        ORDER_EVENT_VISIBILITY_KIND,
        RESERVATION_RELEASE_VISIBILITY_KIND,
    }:
        raise CapacityVisibilityError("capacity visibility fact kind is unsupported")
    if (
        type(fact_sha256) is not str
        or len(fact_sha256) != 64
        or any(character not in "0123456789abcdef" for character in fact_sha256)
    ):
        raise CapacityVisibilityError("capacity visibility requires a SHA-256 fact digest")
    if (
        type(visible_after_observation_sequence) is not int
        or visible_after_observation_sequence <= 0
    ):
        raise CapacityVisibilityError(
            "current capacity mutations require a positive decision watermark"
        )
    return hashlib.sha256(
        canonical_json_bytes(
            (
                CAPACITY_VISIBILITY_CONTRACT_VERSION,
                account_id,
                fact_kind,
                fact_sha256,
                visible_after_observation_sequence,
            )
        )
    ).hexdigest()


def capacity_visibility_values(
    *,
    account_id: str,
    fact_kind: str,
    fact_sha256: str,
    visible_after_observation_sequence: int,
) -> dict[str, object]:
    return {
        "visible_after_observation_sequence": visible_after_observation_sequence,
        "capacity_visibility_sha256": capacity_visibility_sha256(
            account_id=account_id,
            fact_kind=fact_kind,
            fact_sha256=fact_sha256,
            visible_after_observation_sequence=visible_after_observation_sequence,
        ),
    }


def verify_capacity_visibility(
    *,
    account_id: str,
    fact_kind: str,
    fact_sha256: str,
    visible_after_observation_sequence: object,
    capacity_visibility_sha256_value: object,
) -> int:
    """Authenticate either one migrated legacy marker or a current binding."""

    if type(visible_after_observation_sequence) is not int:
        raise CapacityVisibilityError("capacity visibility sequence must be an integer")
    if visible_after_observation_sequence == 0:
        if capacity_visibility_sha256_value is not None:
            raise CapacityVisibilityError("legacy capacity visibility cannot have a digest")
        return 0
    expected = capacity_visibility_sha256(
        account_id=account_id,
        fact_kind=fact_kind,
        fact_sha256=fact_sha256,
        visible_after_observation_sequence=visible_after_observation_sequence,
    )
    if capacity_visibility_sha256_value != expected:
        raise CapacityVisibilityError("capacity visibility digest conflicts")
    return visible_after_observation_sequence
