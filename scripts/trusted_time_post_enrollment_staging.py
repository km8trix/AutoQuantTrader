"""Dormant claimed-release handoff for a future trusted-time start.

This module does not create or inspect containers, execute Docker, publish the
release marker, observe sequence 2, retain an outcome, or expose a CLI.  A
future host executor may call the ``_under_lock`` coordinator only while it
holds the global trusted-time launcher lock and owns an already-authenticated
staged topology.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
)
from apps.trusted_time_supervisor.post_enrollment_start import (
    bind_post_enrollment_start_reauthentication,
)
from packages.domain.trusted_time_enrollment_evidence import (
    TrustedTimeConfirmedFirstEnrollment,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentRuntimeReauthentication,
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimePostEnrollmentStartClaim,
)
from scripts.trusted_time_post_enrollment_evidence import (
    load_confirmed_first_enrollment_evidence,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    TrustedTimePostEnrollmentStartClaimConsumed,
    _TrustedTimePostEnrollmentStartClaimCheckpointRejected,
    require_no_retained_post_enrollment_start_claim,
    retain_post_enrollment_start_claim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    _authenticated_recovery_claim_binder_is_available,
    _TrustedTimePostEnrollmentRecoveryClaimBinder,
)

POST_ENROLLMENT_START_RELEASE_COMMAND = (
    "/opt/venv/bin/autoquant-trusted-time-post-enrollment-release"
)
POST_ENROLLMENT_START_CONTAINER_USER = "10001:10001"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


def _authority_is_never_granted(_: object) -> bool:
    return False


class TrustedTimePostEnrollmentStartStagingRejected(RuntimeError):
    """No claim was created and the staged handoff was rejected."""


class TrustedTimePostEnrollmentStartClaimedRecoveryRequired(RuntimeError):
    """A retained claim exists or claim durability may be uncertain."""


class TrustedTimePostEnrollmentStartReauthenticationIssuer(Protocol):
    """Single-owner read-only sequence-1 issuer consumed by the coordinator."""

    def reauthenticate_first_enrollment_postcondition(
        self,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition: ...

    def close(self) -> None: ...


def post_enrollment_start_release_argv(
    supervisor_container_id: str,
) -> tuple[str, ...]:
    """Project the one inert, argument-free marker command for an exact container."""

    if (
        type(supervisor_container_id) is not str
        or _CONTAINER_ID_PATTERN.fullmatch(supervisor_container_id) is None
    ):
        raise TrustedTimePostEnrollmentStartStagingRejected(
            "trusted-time post-enrollment staged supervisor identity is invalid"
        )
    return (
        "docker",
        "container",
        "exec",
        "--user",
        POST_ENROLLMENT_START_CONTAINER_USER,
        supervisor_container_id,
        POST_ENROLLMENT_START_RELEASE_COMMAND,
    )


def _validated_artifact_directory(
    artifact_directory: Path,
    *,
    ignored_root: Path,
) -> Path:
    try:
        canonical_root = Path(os.path.abspath(ignored_root))
        canonical_directory = Path(os.path.abspath(artifact_directory))
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentStartStagingRejected(
            "trusted-time post-enrollment staging artifact binding is invalid"
        ) from None
    if (
        not isinstance(artifact_directory, Path)
        or not isinstance(ignored_root, Path)
        or not artifact_directory.is_absolute()
        or not ignored_root.is_absolute()
        or artifact_directory != canonical_directory
        or ignored_root != canonical_root
        or artifact_directory != canonical_root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentStartStagingRejected(
            "trusted-time post-enrollment staging artifact binding is invalid"
        )
    return canonical_directory


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartStagingHandoff:
    """Immutable, claimed, non-authorizing data for a later release executor."""

    approval: TrustedTimePostEnrollmentStartApproval
    approval_sha256: str
    confirmed_enrollment: TrustedTimeConfirmedFirstEnrollment
    reauthentication: TrustedTimePostEnrollmentRuntimeReauthentication
    retained_claim: RetainedTrustedTimePostEnrollmentStartClaim
    artifact_directory: Path
    ignored_root: Path
    supervisor_container_id: str
    release_argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.approval) is not TrustedTimePostEnrollmentStartApproval
            or type(self.approval_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.approval_sha256) is None
            or type(self.confirmed_enrollment) is not TrustedTimeConfirmedFirstEnrollment
            or type(self.reauthentication) is not TrustedTimePostEnrollmentRuntimeReauthentication
            or type(self.retained_claim) is not RetainedTrustedTimePostEnrollmentStartClaim
            or not isinstance(self.artifact_directory, Path)
            or not isinstance(self.ignored_root, Path)
            or type(self.release_argv) is not tuple
        ):
            raise TrustedTimePostEnrollmentStartStagingRejected(
                "trusted-time post-enrollment staging handoff is invalid"
            )
        try:
            self.approval.__post_init__()
            self.confirmed_enrollment.__post_init__()
            self.reauthentication.__post_init__()
            self.retained_claim.__post_init__()
            artifact_directory = _validated_artifact_directory(
                self.artifact_directory,
                ignored_root=self.ignored_root,
            )
            expected_argv = post_enrollment_start_release_argv(self.supervisor_container_id)
        except Exception:
            raise TrustedTimePostEnrollmentStartStagingRejected(
                "trusted-time post-enrollment staging handoff is invalid"
            ) from None
        claim = self.retained_claim.claim
        if (
            self.approval_sha256 != self.approval.approval_sha256
            or self.confirmed_enrollment != self.approval.confirmed_enrollment
            or self.reauthentication.operation_id != self.approval.operation_id
            or claim.approval != self.approval
            or claim.reauthentication != self.reauthentication
            or self.retained_claim.operation_id != self.approval.operation_id
            or self.retained_claim.artifact_path
            != artifact_directory / self.retained_claim.artifact_path.name
            or not revalidate_retained_post_enrollment_start_claim(
                self.retained_claim,
                artifact_directory=artifact_directory,
                ignored_root=self.ignored_root,
            )
            or self.release_argv != expected_argv
        ):
            raise TrustedTimePostEnrollmentStartStagingRejected(
                "trusted-time post-enrollment staging handoff is invalid"
            )

    @property
    def status(self) -> str:
        return "claimed_release_handoff_unqualified"

    authority_granted = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


def _load_exact_confirmed_enrollment(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    artifact_directory: Path,
) -> TrustedTimeConfirmedFirstEnrollment:
    expected = approval.confirmed_enrollment
    observed = load_confirmed_first_enrollment_evidence(
        operation_id=expected.operation_id,
        claim_sha256=expected.claim_sha256,
        outcome_sha256=expected.outcome_sha256,
        artifact_directory=artifact_directory,
    )
    if observed != expected:
        raise TrustedTimePostEnrollmentStartStagingRejected(
            "trusted-time confirmed enrollment evidence changed"
        )
    return observed


def prepare_post_enrollment_start_release_under_lock(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    expected_approval_sha256: str,
    supervisor_container_id: str,
    reauthentication_issuer: TrustedTimePostEnrollmentStartReauthenticationIssuer,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    _retained_claim_binder: _TrustedTimePostEnrollmentRecoveryClaimBinder | None = None,
) -> TrustedTimePostEnrollmentStartStagingHandoff:
    """Consume one staged issuer and retain a claim without executing release.

    The caller must already hold the global trusted-time launcher lock.  The
    returned argv is inert data and every authority property remains false.
    """

    try:
        if type(approval) is not TrustedTimePostEnrollmentStartApproval:
            raise ValueError
        approval.__post_init__()
        if (
            type(expected_approval_sha256) is not str
            or _SHA256_PATTERN.fullmatch(expected_approval_sha256) is None
            or expected_approval_sha256 != approval.approval_sha256
            or not callable(
                getattr(
                    reauthentication_issuer,
                    "reauthenticate_first_enrollment_postcondition",
                    None,
                )
            )
            or not callable(getattr(reauthentication_issuer, "close", None))
            or (
                _retained_claim_binder is not None
                and type(_retained_claim_binder)
                is not _TrustedTimePostEnrollmentRecoveryClaimBinder
            )
        ):
            raise ValueError
        release_argv = post_enrollment_start_release_argv(supervisor_container_id)
        artifact_directory = _validated_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if _retained_claim_binder is not None and not (
            _authenticated_recovery_claim_binder_is_available(
                _retained_claim_binder,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        ):
            raise ValueError
    except Exception:
        raise TrustedTimePostEnrollmentStartStagingRejected(
            "trusted-time post-enrollment staging inputs are invalid"
        ) from None

    issuer_close_attempted = False
    claim_retention_attempted = False
    primary_error: BaseException | None = None

    def close_issuer_once() -> None:
        nonlocal issuer_close_attempted
        issuer_close_attempted = True
        reauthentication_issuer.close()

    try:
        try:
            require_no_retained_post_enrollment_start_claim(
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except TrustedTimePostEnrollmentStartClaimConsumed:
            raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                "trusted-time post-enrollment start claim requires recovery"
            ) from None
        except Exception:
            raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                "trusted-time post-enrollment start claim state requires recovery"
            ) from None

        try:
            confirmed = _load_exact_confirmed_enrollment(
                approval,
                artifact_directory=artifact_directory,
            )
            observed: TrustedTimeHeadAnchorFirstEnrollmentPostcondition | None = None
            reauthentication_error: BaseException | None = None
            try:
                observed = reauthentication_issuer.reauthenticate_first_enrollment_postcondition()
            except BaseException as error:
                reauthentication_error = error
            try:
                close_issuer_once()
            except BaseException:
                raise TrustedTimePostEnrollmentStartStagingRejected(
                    "trusted-time post-enrollment reauthentication issuer close is unconfirmed"
                ) from None
            if reauthentication_error is not None or observed is None:
                raise TrustedTimePostEnrollmentStartStagingRejected(
                    "trusted-time post-enrollment runtime reauthentication is unavailable"
                ) from None
            reauthentication = bind_post_enrollment_start_reauthentication(
                approval=approval,
                observed=observed,
            )
            claim = TrustedTimePostEnrollmentStartClaim(
                approval=approval,
                reauthentication=reauthentication,
            )
            if (
                _load_exact_confirmed_enrollment(
                    approval,
                    artifact_directory=artifact_directory,
                )
                != confirmed
            ):
                raise TrustedTimePostEnrollmentStartStagingRejected(
                    "trusted-time confirmed enrollment evidence changed"
                )
            try:
                require_no_retained_post_enrollment_start_claim(
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            except Exception:
                raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                    "trusted-time post-enrollment start claim state requires recovery"
                ) from None
        except TrustedTimePostEnrollmentStartClaimConsumed:
            raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                "trusted-time post-enrollment start claim requires recovery"
            ) from None
        except TrustedTimePostEnrollmentStartClaimedRecoveryRequired:
            raise
        except TrustedTimePostEnrollmentStartStagingRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentStartStagingRejected(
                "trusted-time post-enrollment staging preconditions are unavailable"
            ) from None

        claim_retention_attempted = True
        try:
            retained = retain_post_enrollment_start_claim(
                claim,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
                _retained_claim_binder=_retained_claim_binder,
            )
            if not revalidate_retained_post_enrollment_start_claim(
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ):
                raise RuntimeError
            if _retained_claim_binder is not None:
                _retained_claim_binder(retained)
            if (
                _load_exact_confirmed_enrollment(
                    approval,
                    artifact_directory=artifact_directory,
                )
                != confirmed
            ):
                raise RuntimeError
            return TrustedTimePostEnrollmentStartStagingHandoff(
                approval=approval,
                approval_sha256=expected_approval_sha256,
                confirmed_enrollment=confirmed,
                reauthentication=reauthentication,
                retained_claim=retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
                supervisor_container_id=supervisor_container_id,
                release_argv=release_argv,
            )
        except _TrustedTimePostEnrollmentStartClaimCheckpointRejected:
            raise TrustedTimePostEnrollmentStartStagingRejected(
                "trusted-time recovery claim binder is unavailable"
            ) from None
        except BaseException:
            raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                "trusted-time post-enrollment retained claim requires recovery"
            ) from None
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if not issuer_close_attempted:
            try:
                close_issuer_once()
            except BaseException:
                if claim_retention_attempted or isinstance(
                    primary_error,
                    TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
                ):
                    raise TrustedTimePostEnrollmentStartClaimedRecoveryRequired(
                        "trusted-time post-enrollment reauthentication issuer close "
                        "requires recovery"
                    ) from None
                raise TrustedTimePostEnrollmentStartStagingRejected(
                    "trusted-time post-enrollment reauthentication issuer close is unconfirmed"
                ) from None


__all__ = [
    "POST_ENROLLMENT_START_CONTAINER_USER",
    "POST_ENROLLMENT_START_RELEASE_COMMAND",
    "TrustedTimePostEnrollmentStartClaimedRecoveryRequired",
    "TrustedTimePostEnrollmentStartReauthenticationIssuer",
    "TrustedTimePostEnrollmentStartStagingHandoff",
    "TrustedTimePostEnrollmentStartStagingRejected",
    "post_enrollment_start_release_argv",
    "prepare_post_enrollment_start_release_under_lock",
]
