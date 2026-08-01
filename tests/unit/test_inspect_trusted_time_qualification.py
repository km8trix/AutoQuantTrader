from __future__ import annotations

import argparse
import json
import stat
import subprocess
import sys
from collections.abc import Callable
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import Connection, Engine

from apps.trusted_time_supervisor.config import (
    DATABASE_CA_PATH,
    TrustedTimeDeploymentAuthority,
)
from scripts import inspect_trusted_time_qualification as inspector
from scripts.inspect_trusted_time_qualification import (
    CheckedInAuthority,
    HostSnapshot,
    RunningImageIds,
    TrustedTimeQualificationInspectionError,
    qualify_host_snapshot,
    write_qualification_artifact,
)
from scripts.verify_trusted_time_images import TrustedTimeImageAdmission

BASE = datetime(2026, 7, 31, 18, 0, tzinfo=UTC)
EPOCH_ID = "11111111-1111-4111-8111-111111111111"
SOURCE_AUTHORITY_SHA256 = "9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c"
LEGACY_SOURCE_ID = "chrony-nts-cloudflare-netnod-v1"
LEGACY_SOURCE_AUTHORITY_SHA256 = "356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab"
CHRONY_CONFIG_SHA256 = "5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23"
EPOCH_SHA256 = "c" * 64
SOURCE_IMAGE_ID = "sha256:" + "d" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "e" * 64
SUPERVISOR_STARTED_AT = BASE - timedelta(seconds=1)
LINUX_TIME_NAMESPACE = "time:[4026531834]"
SUPERVISOR_LINUX_TIME_NAMESPACE = "time:[4026531835]"
LINUX_BOOT_ID = "12345678-1234-4234-8234-123456789abc"
ZERO_TIME_NAMESPACE_OFFSETS = inspector._ZERO_TIME_NAMESPACE_OFFSETS
NONZERO_TIME_NAMESPACE_OFFSETS: inspector.TimeNamespaceOffsets = (
    ("monotonic", 0, 0),
    ("boottime", 1, 0),
)
DOCKER_DAEMON = inspector.LocalDockerDaemonIdentity(
    context_name="desktop-linux",
    endpoint="unix:///private/tmp/aqt-docker.sock",
    daemon_id="LOCAL:DAEMON:1",
)
DATABASE_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:top-secret-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)


def _image_admission() -> TrustedTimeImageAdmission:
    return TrustedTimeImageAdmission(
        path=inspector.DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        identities=inspector.TrustedTimeImageIdentities(
            source_id=SOURCE_IMAGE_ID,
            supervisor_id=SUPERVISOR_IMAGE_ID,
        ),
        source_revision_sha256="1" * 64,
        artifact_sha256="2" * 64,
        created_at_utc="2026-07-31T18:00:00.000000Z",
        created_monotonic_ns=1,
    )


def _authority() -> CheckedInAuthority:
    return CheckedInAuthority(
        deployment=TrustedTimeDeploymentAuthority(
            source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            source_id="chrony-nts-cloudflare-system76-virginia-v2",
            host_id=inspector.HOST_ID,
            chrony_version="4.8",
            chronyc_path=Path("/usr/local/bin/chronyc"),
            chrony_socket_path=Path("/run/chrony/chronyd.sock"),
            database_ca_path=DATABASE_CA_PATH,
            database_ca_sha256=("700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"),
            ordered_source_names=(
                "time.cloudflare.com",
                "virginia.time.system76.com",
            ),
            ordered_ntp_ports=(123, 123),
            maximum_reference_age_seconds=30,
            maximum_source_uncertainty_milliseconds=Decimal("100"),
            probe_deadline_ns=1_000_000_000,
            cadence_ns=20_000_000_000,
            maximum_gap_ns=30_000_000_000,
        ),
        chrony_config_sha256=CHRONY_CONFIG_SHA256,
        authority_flags=inspector._AUTHORITY_FLAGS,
    )


def _images(
    *,
    source_started_at: datetime = BASE - timedelta(seconds=2),
    supervisor_started_at: datetime = SUPERVISOR_STARTED_AT,
    source_pid1_start_ticks: int = 1,
    supervisor_pid1_start_ticks: int = 2,
    clock_ticks_per_second: int = 100,
    source_time_namespace: str = LINUX_TIME_NAMESPACE,
    source_time_namespace_offsets: inspector.TimeNamespaceOffsets = ZERO_TIME_NAMESPACE_OFFSETS,
    supervisor_time_namespace: str = SUPERVISOR_LINUX_TIME_NAMESPACE,
    supervisor_time_namespace_offsets: inspector.TimeNamespaceOffsets = (
        ZERO_TIME_NAMESPACE_OFFSETS
    ),
    source_boot_id: str = LINUX_BOOT_ID,
    supervisor_boot_id: str = LINUX_BOOT_ID,
) -> RunningImageIds:
    return RunningImageIds(
        source=SOURCE_IMAGE_ID,
        supervisor=SUPERVISOR_IMAGE_ID,
        source_container_id="a" * 64,
        source_started_at_utc=source_started_at,
        source_pid1_start_ticks=source_pid1_start_ticks,
        source_time_namespace=source_time_namespace,
        source_time_namespace_offsets=source_time_namespace_offsets,
        source_boot_id=source_boot_id,
        supervisor_container_id="b" * 64,
        supervisor_started_at_utc=supervisor_started_at,
        supervisor_pid1_start_ticks=supervisor_pid1_start_ticks,
        supervisor_time_namespace=supervisor_time_namespace,
        supervisor_time_namespace_offsets=supervisor_time_namespace_offsets,
        supervisor_boot_id=supervisor_boot_id,
        clock_ticks_per_second=clock_ticks_per_second,
        docker_daemon=DOCKER_DAEMON,
    )


def _recorded_evaluation(sequence: int) -> dict[str, object]:
    scheduled_seconds = (sequence - 1) * 20
    started = BASE + timedelta(seconds=scheduled_seconds)
    completed = started + timedelta(milliseconds=100)
    evaluated_ns = scheduled_seconds * 1_000_000_000 + 100_000_000
    terminal = sequence >= 4
    return {
        "host_id": inspector.HOST_ID,
        "monitor_epoch_id": EPOCH_ID,
        "evaluation_id": f"00000000-0000-4000-8000-{sequence:012d}",
        "evaluation_sequence": sequence,
        "probe_status": "recorded",
        "sample_sequence": sequence,
        "source_evidence_sha256": f"{100 + sequence:064x}",
        "probe_started_at_utc": started,
        "probe_completed_at_utc": completed,
        "probe_started_monotonic_ns": scheduled_seconds * 1_000_000_000,
        "probe_completed_monotonic_ns": evaluated_ns,
        "source_uncertainty_milliseconds": Decimal(f"{sequence}.125"),
        "health": "healthy",
        "reason": "within_limit" if terminal else "startup_qualifying",
        "hard_failure_latched": False,
        "clock_recovery_qualified": terminal,
        "evaluated_at_utc": completed,
        "evaluated_at_monotonic_ns": evaluated_ns,
        "state_sha256": f"{200 + sequence:064x}",
        "semantic_sha256": f"{300 + sequence:064x}",
    }


def _head(evaluation: dict[str, object], *, epoch_sequence: int = 1) -> dict[str, object]:
    return {
        "host_id": inspector.HOST_ID,
        "epoch_sequence": epoch_sequence,
        "monitor_epoch_id": EPOCH_ID,
        "epoch_sha256": EPOCH_SHA256,
        "evaluation_sequence": evaluation["evaluation_sequence"],
        "evaluation_id": evaluation["evaluation_id"],
        "evaluation_record_sha256": evaluation["semantic_sha256"],
        "state_sha256": evaluation["state_sha256"],
        "health": evaluation["health"],
        "reason": evaluation["reason"],
        "hard_failure_latched": evaluation["hard_failure_latched"],
        "clock_recovery_qualified": evaluation["clock_recovery_qualified"],
        "evaluated_at_utc": evaluation["evaluated_at_utc"],
        "evaluated_at_monotonic_ns": evaluation["evaluated_at_monotonic_ns"],
        "semantic_sha256": "f" * 64,
    }


def _snapshot(count: int = 4) -> HostSnapshot:
    evaluations = tuple(_recorded_evaluation(sequence) for sequence in range(1, count + 1))
    return HostSnapshot(
        epochs=(
            {
                "host_id": inspector.HOST_ID,
                "epoch_sequence": 1,
                "monitor_epoch_id": EPOCH_ID,
                "source_id": "chrony-nts-cloudflare-system76-virginia-v2",
                "source_authority_sha256": SOURCE_AUTHORITY_SHA256,
                "registered_at_utc": BASE,
                "semantic_sha256": EPOCH_SHA256,
            },
        ),
        head=_head(evaluations[-1]),
        evaluations=evaluations,
    )


def _snapshot_after_authority_rotation(count: int = 4) -> HostSnapshot:
    current = _snapshot(count)
    current_epoch = dict(current.epochs[0])
    current_epoch["epoch_sequence"] = 2
    prior_epoch = {
        "host_id": inspector.HOST_ID,
        "epoch_sequence": 1,
        "monitor_epoch_id": "22222222-2222-4222-8222-222222222222",
        "source_id": LEGACY_SOURCE_ID,
        "source_authority_sha256": LEGACY_SOURCE_AUTHORITY_SHA256,
        "registered_at_utc": BASE - timedelta(minutes=1),
        "semantic_sha256": "d" * 64,
    }
    assert current.head is not None
    return HostSnapshot(
        epochs=(prior_epoch, current_epoch),
        head={**current.head, "epoch_sequence": 2},
        evaluations=current.evaluations,
    )


def _failed_evaluation(sequence: int) -> dict[str, object]:
    row = _recorded_evaluation(sequence)
    row.update(
        {
            "probe_status": "source_unavailable",
            "health": "blocked",
            "reason": "startup_no_sample" if sequence == 1 else "source_unavailable",
            "clock_recovery_qualified": False,
        }
    )
    for field in inspector._SAMPLE_FIELDS:
        row[field] = None
    return row


def _failure_snapshot(count: int = 4) -> HostSnapshot:
    baseline = _snapshot(count)
    evaluations = tuple(_failed_evaluation(sequence) for sequence in range(1, count + 1))
    return HostSnapshot(
        epochs=baseline.epochs,
        head=_head(evaluations[-1]),
        evaluations=evaluations,
    )


def _qualified_payload(snapshot: HostSnapshot | None = None) -> dict[str, object]:
    exact_snapshot = _snapshot() if snapshot is None else snapshot
    terminal_boottime_ns = cast(
        int,
        exact_snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )
    return qualify_host_snapshot(
        exact_snapshot,
        authority=_authority(),
        images=_images(),
        minimum_evaluations=4,
        current_boottime_ns=terminal_boottime_ns + 1_000_000_000,
    )


def _reseal_payload(payload: dict[str, object]) -> None:
    payload.pop("qualification_sha256", None)
    payload["qualification_sha256"] = inspector.hashlib.sha256(
        inspector._canonical_json_bytes(payload)
    ).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    assert type(value) is dict
    return cast(dict[str, Any], value)


def _mutable_evaluation(snapshot: HostSnapshot, index: int) -> dict[str, object]:
    return cast(dict[str, object], snapshot.evaluations[index])


def _mutate_uncertainty(snapshot: HostSnapshot) -> None:
    _mutable_evaluation(snapshot, 1)["source_uncertainty_milliseconds"] = Decimal("100.0000000001")


def _mutate_authority(snapshot: HostSnapshot) -> None:
    cast(dict[str, object], snapshot.epochs[0])["source_authority_sha256"] = "0" * 64


def _mutate_head(snapshot: HostSnapshot) -> None:
    assert snapshot.head is not None
    cast(dict[str, object], snapshot.head)["evaluation_sequence"] = 3


def test_qualified_snapshot_is_canonical_sanitized_and_non_authorizing() -> None:
    payload = _qualified_payload()
    encoded = inspector._canonical_json_bytes(payload)

    assert payload["status"] == "qualified"
    assert payload["qualification_passed"] is True
    assert payload["counts"] == {
        "current_epoch_evaluations": 4,
        "epochs": 1,
        "failures": 0,
        "heads": 1,
        "minimum_required_recorded": 4,
        "recorded": 4,
        "status": {
            "invalid_reading": 0,
            "recorded": 4,
            "source_identity_mismatch": 0,
            "source_unavailable": 0,
        },
    }
    assert payload["current"] == {
        "clock_recovery_qualified": True,
        "epoch_sequence": 1,
        "evaluation_sequence": 4,
        "hard_failure_latched": False,
        "health": "healthy",
        "reason": "within_limit",
    }
    assert payload["images"] == {
        "admitted": True,
        "current_epoch_process_bound": True,
        "source": SOURCE_IMAGE_ID,
        "supervisor": SUPERVISOR_IMAGE_ID,
    }
    timing = _mapping(payload["timing"])
    assert timing["evaluation_gaps_ns"] == [20_000_000_000] * 3
    assert timing["terminal_age_ns"] == 1_000_000_000
    assert timing["terminal_fresh"] is True
    authority = _mapping(payload["authority"])
    assert authority["all_false"] is True
    assert all(flag is False for flag in _mapping(authority["flags"]).values())
    assert encoded == inspector._canonical_json_bytes(json.loads(encoded))
    for prohibited in (
        "top-secret-password",
        "aws-0-us-east-1.pooler.supabase.com",
        "time.cloudflare.com",
        "virginia.time.system76.com",
        "postgresql+psycopg",
        "chronyc",
        "LOCAL:DAEMON:1",
        "aqt-docker.sock",
        "desktop-linux",
    ):
        assert prohibited.encode() not in encoded


def test_retired_authority_history_can_precede_current_qualified_epoch() -> None:
    payload = _qualified_payload(_snapshot_after_authority_rotation())

    assert payload["qualification_passed"] is True
    assert _mapping(payload["counts"])["epochs"] == 2
    assert _mapping(payload["current"])["epoch_sequence"] == 2


def test_retired_authority_generation_is_derived_from_archived_exact_bytes() -> None:
    archived_path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "adr"
        / "evidence"
        / "0092-source-authority-v1.json"
    )
    archived = archived_path.read_bytes()
    decoded = json.loads(archived)

    assert inspector.hashlib.sha256(archived).hexdigest() == LEGACY_SOURCE_AUTHORITY_SHA256
    assert decoded["source_id"] == LEGACY_SOURCE_ID
    assert inspector._SOURCE_AUTHORITY_GENERATIONS[0] == (
        decoded["source_id"],
        LEGACY_SOURCE_AUTHORITY_SHA256,
    )


def test_retired_authority_cannot_remain_current() -> None:
    snapshot = deepcopy(_snapshot())
    current = cast(dict[str, object], snapshot.epochs[0])
    current["source_id"] = LEGACY_SOURCE_ID
    current["source_authority_sha256"] = LEGACY_SOURCE_AUTHORITY_SHA256

    with pytest.raises(
        TrustedTimeQualificationInspectionError,
        match="current_epoch_authority_invalid",
    ):
        _qualified_payload(snapshot)


def test_unknown_historical_authority_and_authority_reversion_are_rejected() -> None:
    unknown = _snapshot_after_authority_rotation()
    cast(dict[str, object], unknown.epochs[0])["source_authority_sha256"] = "0" * 64
    with pytest.raises(TrustedTimeQualificationInspectionError, match="epoch_chain_invalid"):
        _qualified_payload(unknown)

    baseline = _snapshot_after_authority_rotation()
    early_current = dict(baseline.epochs[1])
    early_current.update(
        {
            "epoch_sequence": 1,
            "monitor_epoch_id": "33333333-3333-4333-8333-333333333333",
            "registered_at_utc": BASE - timedelta(minutes=2),
            "semantic_sha256": "e" * 64,
        }
    )
    retired = dict(baseline.epochs[0])
    retired["epoch_sequence"] = 2
    current = dict(baseline.epochs[1])
    current["epoch_sequence"] = 3
    assert baseline.head is not None
    reverted = HostSnapshot(
        epochs=(early_current, retired, current),
        head={**baseline.head, "epoch_sequence": 3},
        evaluations=baseline.evaluations,
    )
    with pytest.raises(TrustedTimeQualificationInspectionError, match="epoch_chain_invalid"):
        _qualified_payload(reverted)


@pytest.mark.parametrize("minimum_evaluations", [True, 0, 2, 3])
def test_recorded_sample_floor_cannot_be_reduced(minimum_evaluations: object) -> None:
    snapshot = _snapshot()

    with pytest.raises(
        TrustedTimeQualificationInspectionError,
        match="minimum_evaluations_invalid",
    ):
        qualify_host_snapshot(
            snapshot,
            authority=_authority(),
            images=_images(),
            minimum_evaluations=cast(int, minimum_evaluations),
            current_boottime_ns=cast(
                int,
                snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
            ),
        )


@pytest.mark.parametrize("value", ["not-an-integer", "2", "3"])
def test_cli_recorded_sample_floor_cannot_be_reduced(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="at least 4"):
        inspector._minimum_evaluations(value)


def test_closed_artifact_schema_rejects_a_reduced_sample_floor() -> None:
    payload = deepcopy(_qualified_payload())
    _mapping(payload["counts"])["minimum_required_recorded"] = 3
    _reseal_payload(payload)

    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_invalid"):
        inspector._validate_sanitized_evidence_payload(payload)


@pytest.mark.parametrize(
    "field_name",
    [
        "chrony_config_sha256",
        "database_ca_sha256",
        "source_authority_registry_sha256",
        "source_authority_sha256",
    ],
)
def test_closed_artifact_binds_exact_authority_generation_inputs(field_name: str) -> None:
    payload = deepcopy(_qualified_payload())
    _mapping(payload["hashes"])[field_name] = "0" * 64
    _reseal_payload(payload)

    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_invalid"):
        inspector._validate_sanitized_evidence_payload(payload)


def test_v4_artifact_cannot_validate_as_v5() -> None:
    payload = deepcopy(_qualified_payload())
    payload["contract_version"] = "phase6c-live-trusted-time-qualification-inspection-v4"
    _reseal_payload(payload)

    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_invalid"):
        inspector._validate_sanitized_evidence_payload(payload)


def test_terminal_evaluation_must_be_fresh_on_current_boottime_clock() -> None:
    snapshot = _snapshot()
    terminal_ns = cast(
        int,
        snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )

    boundary = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(),
        minimum_evaluations=4,
        current_boottime_ns=terminal_ns + 30_000_000_000,
    )
    stale = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(),
        minimum_evaluations=4,
        current_boottime_ns=terminal_ns + 30_000_000_001,
    )

    assert boundary["qualification_passed"] is True
    assert _mapping(boundary["timing"])["terminal_fresh"] is True
    assert stale["qualification_passed"] is False
    assert _mapping(stale["timing"])["terminal_age_ns"] == 30_000_000_001
    assert _mapping(stale["timing"])["terminal_fresh"] is False


def test_current_boottime_cannot_precede_terminal_evaluation() -> None:
    snapshot = _snapshot()
    terminal_ns = cast(
        int,
        snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )

    with pytest.raises(TrustedTimeQualificationInspectionError, match="boottime_clock_regressed"):
        qualify_host_snapshot(
            snapshot,
            authority=_authority(),
            images=_images(),
            minimum_evaluations=4,
            current_boottime_ns=terminal_ns - 1,
        )


def test_supervisor_restart_with_old_epoch_is_not_process_bound() -> None:
    snapshot = _snapshot()
    terminal_ns = cast(
        int,
        snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )

    payload = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(
            supervisor_started_at=BASE - timedelta(seconds=20),
            supervisor_pid1_start_ticks=10,
        ),
        minimum_evaluations=4,
        current_boottime_ns=terminal_ns,
    )

    assert payload["qualification_passed"] is False
    assert _mapping(payload["images"])["current_epoch_process_bound"] is False


def test_regressed_utc_source_restart_after_supervisor_fails_process_order() -> None:
    snapshot = _snapshot()
    terminal_ns = cast(
        int,
        snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )

    payload = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(
            source_started_at=BASE - timedelta(seconds=20),
            source_pid1_start_ticks=3,
            supervisor_pid1_start_ticks=2,
        ),
        minimum_evaluations=4,
        current_boottime_ns=terminal_ns,
    )

    assert payload["qualification_passed"] is False
    assert _mapping(payload["images"])["current_epoch_process_bound"] is False


def test_fresh_process_order_uses_boot_ticks_not_utc_order() -> None:
    payload = qualify_host_snapshot(
        _snapshot(),
        authority=_authority(),
        images=_images(
            source_started_at=BASE + timedelta(seconds=20),
            supervisor_started_at=BASE - timedelta(seconds=20),
            source_pid1_start_ticks=1,
            supervisor_pid1_start_ticks=2,
        ),
        minimum_evaluations=4,
        current_boottime_ns=60_100_000_000,
    )

    assert payload["qualification_passed"] is True
    assert _mapping(payload["images"])["current_epoch_process_bound"] is True


@pytest.mark.parametrize(
    ("first_evaluation_ns", "expected_bound"),
    [
        (29_999_999, False),
        (30_000_000, True),
    ],
)
def test_first_evaluation_conservatively_follows_supervisor_tick_interval(
    first_evaluation_ns: int,
    expected_bound: bool,
) -> None:
    snapshot = deepcopy(_snapshot())
    first = _mutable_evaluation(snapshot, 0)
    first["probe_completed_monotonic_ns"] = first_evaluation_ns
    first["evaluated_at_monotonic_ns"] = first_evaluation_ns

    payload = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(),
        minimum_evaluations=4,
        current_boottime_ns=60_100_000_000,
    )

    assert _mapping(payload["images"])["current_epoch_process_bound"] is expected_bound
    assert payload["qualification_passed"] is expected_bound


@pytest.mark.parametrize("clock_ticks_per_second", [cast(int, True), 0, 250])
def test_running_identity_requires_exact_non_boolean_clk_tck(
    clock_ticks_per_second: int,
) -> None:
    with pytest.raises(
        TrustedTimeQualificationInspectionError,
        match="runtime_images_invalid",
    ):
        _images(clock_ticks_per_second=clock_ticks_per_second)


def test_running_identity_allows_distinct_zero_offset_time_namespaces() -> None:
    images = _images()

    assert images.source_time_namespace == LINUX_TIME_NAMESPACE
    assert images.supervisor_time_namespace == SUPERVISOR_LINUX_TIME_NAMESPACE
    assert images.source_time_namespace_offsets == ZERO_TIME_NAMESPACE_OFFSETS
    assert images.supervisor_time_namespace_offsets == ZERO_TIME_NAMESPACE_OFFSETS


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_time_namespace_offsets": NONZERO_TIME_NAMESPACE_OFFSETS},
        {"supervisor_time_namespace_offsets": NONZERO_TIME_NAMESPACE_OFFSETS},
        {"supervisor_boot_id": "22345678-1234-4234-8234-123456789abc"},
        {"source_time_namespace": "time:[0]"},
    ],
)
def test_running_identity_requires_zero_offsets_valid_namespaces_and_shared_boot(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(
        TrustedTimeQualificationInspectionError,
        match="runtime_images_invalid",
    ):
        _images(**cast(Any, overrides))


def test_epoch_process_binding_does_not_depend_on_registration_utc_order() -> None:
    snapshot = deepcopy(_snapshot())
    cast(dict[str, object], snapshot.epochs[0])["registered_at_utc"] = BASE + timedelta(
        milliseconds=101
    )
    terminal_ns = cast(
        int,
        snapshot.evaluations[-1]["evaluated_at_monotonic_ns"],
    )

    payload = qualify_host_snapshot(
        snapshot,
        authority=_authority(),
        images=_images(),
        minimum_evaluations=4,
        current_boottime_ns=terminal_ns,
    )

    assert payload["qualification_passed"] is True
    assert _mapping(payload["images"])["current_epoch_process_bound"] is True


def test_source_failures_are_visible_but_cannot_qualify() -> None:
    payload = _qualified_payload(_failure_snapshot())

    assert payload["status"] == "not_qualified"
    assert payload["qualification_passed"] is False
    counts = _mapping(payload["counts"])
    assert counts["recorded"] == 0
    assert counts["failures"] == 4
    assert _mapping(counts["status"])["source_unavailable"] == 4
    assert _mapping(payload["current"])["health"] == "blocked"
    assert _mapping(payload["uncertainty_milliseconds"])["observed_maximum"] is None


def test_prior_failure_remains_visible_after_four_recorded_samples_qualify() -> None:
    evaluations = (
        _failed_evaluation(1),
        *(_recorded_evaluation(sequence) for sequence in range(2, 6)),
    )
    for sample_sequence, row in enumerate(evaluations[1:], start=1):
        row["sample_sequence"] = sample_sequence
    evaluations[-1]["reason"] = "within_limit"
    evaluations[-1]["clock_recovery_qualified"] = True
    baseline = _snapshot()
    snapshot = HostSnapshot(
        epochs=baseline.epochs,
        head=_head(evaluations[-1]),
        evaluations=evaluations,
    )

    payload = _qualified_payload(snapshot)

    assert payload["qualification_passed"] is True
    counts = _mapping(payload["counts"])
    assert counts["recorded"] == 4
    assert counts["failures"] == 1


@pytest.mark.parametrize(
    ("mutation", "expected_status"),
    [
        (
            _mutate_uncertainty,
            "sample_uncertainty_invalid",
        ),
        (
            _mutate_authority,
            "epoch_chain_invalid",
        ),
        (
            _mutate_head,
            "current_head_invalid",
        ),
    ],
)
def test_snapshot_rejects_uncertainty_identity_and_head_drift(
    mutation: Callable[[HostSnapshot], None],
    expected_status: str,
) -> None:
    snapshot = deepcopy(_snapshot())
    mutation(snapshot)

    with pytest.raises(TrustedTimeQualificationInspectionError, match=expected_status):
        _qualified_payload(snapshot)


def test_bad_cadence_and_unrecovered_terminal_state_are_not_qualified() -> None:
    cadence = deepcopy(_snapshot())
    cadence_row = _mutable_evaluation(cadence, 2)
    cadence_row["evaluated_at_monotonic_ns"] = 21_000_000_000
    cadence_row["probe_started_monotonic_ns"] = 20_900_000_000
    cadence_row["probe_completed_monotonic_ns"] = 21_000_000_000
    cadence_payload = _qualified_payload(cadence)
    assert cadence_payload["qualification_passed"] is False

    unrecovered = deepcopy(_snapshot())
    unrecovered_row = _mutable_evaluation(unrecovered, -1)
    unrecovered_row["reason"] = "startup_qualifying"
    unrecovered_row["clock_recovery_qualified"] = False
    unrecovered = HostSnapshot(
        epochs=unrecovered.epochs,
        head=_head(unrecovered_row),
        evaluations=unrecovered.evaluations,
    )
    unrecovered_payload = _qualified_payload(unrecovered)
    assert unrecovered_payload["qualification_passed"] is False


def test_owner_loader_extracts_only_exact_runtime_database_url(tmp_path: Path) -> None:
    env_file = tmp_path / "runtime.env"
    env_file.write_text(
        f"AQT_DATABASE_URL={DATABASE_URL}\nALPACA_PAPER_API_SECRET=not-loaded\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    assert inspector.load_runtime_database_url(env_file) == DATABASE_URL


def test_read_only_engine_is_bounded_and_uses_explicit_pinned_ca() -> None:
    sentinel = cast(Engine, object())
    with (
        patch.object(inspector, "validate_supabase_session_database_url") as validate,
        patch.object(
            inspector,
            "pinned_verify_full_connect_args",
            return_value={"sslmode": "verify-full", "sslrootcert": "/pinned/ca.crt"},
        ) as pinned,
        patch(
            "scripts.inspect_trusted_time_qualification.sa.create_engine",
            return_value=sentinel,
        ) as create,
    ):
        assert inspector.create_read_only_qualification_engine(DATABASE_URL) is sentinel

    validate.assert_called_once_with(DATABASE_URL)
    pinned.assert_called_once_with(DATABASE_URL, required=True)
    assert create.call_args.kwargs == {
        "connect_args": {
            "connect_timeout": 3,
            "options": (
                "-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=1000"
            ),
            "sslmode": "verify-full",
            "sslrootcert": "/pinned/ca.crt",
        },
        "max_overflow": 0,
        "pool_pre_ping": True,
        "pool_size": 1,
        "pool_timeout": 3.0,
    }


def _running_source(
    *,
    container_id: str = "a" * 64,
    image_id: str = SOURCE_IMAGE_ID,
    started_at: datetime = BASE - timedelta(seconds=2),
    pid1_start_ticks: int = 1,
    time_namespace: str = LINUX_TIME_NAMESPACE,
    time_namespace_offsets: inspector.TimeNamespaceOffsets = ZERO_TIME_NAMESPACE_OFFSETS,
    boot_id: str = LINUX_BOOT_ID,
) -> inspector._RunningContainer:
    return inspector._RunningContainer(
        container_id=container_id,
        image_id=image_id,
        started_at_utc=started_at,
        pid1_start_ticks=pid1_start_ticks,
        time_namespace=time_namespace,
        time_namespace_offsets=time_namespace_offsets,
        boot_id=boot_id,
    )


def _running_supervisor(
    *,
    container_id: str = "b" * 64,
    image_id: str = SUPERVISOR_IMAGE_ID,
    started_at: datetime = SUPERVISOR_STARTED_AT,
    pid1_start_ticks: int = 2,
    time_namespace: str = SUPERVISOR_LINUX_TIME_NAMESPACE,
    time_namespace_offsets: inspector.TimeNamespaceOffsets = ZERO_TIME_NAMESPACE_OFFSETS,
    boot_id: str = LINUX_BOOT_ID,
) -> inspector._RunningContainer:
    return inspector._RunningContainer(
        container_id=container_id,
        image_id=image_id,
        started_at_utc=started_at,
        pid1_start_ticks=pid1_start_ticks,
        time_namespace=time_namespace,
        time_namespace_offsets=time_namespace_offsets,
        boot_id=boot_id,
    )


def _proc_stat(start_ticks: int, *, pid: int = 1, state: str = "S") -> str:
    suffix = [state, *("0" for _ in range(18)), str(start_ticks), *("0" for _ in range(30))]
    return f"{pid} (docker-init) {' '.join(suffix)}\n"


def _zero_offsets() -> str:
    return "monotonic           0         0\nboottime            0         0\n"


def _pid1_clock_identity_output(
    stat_output: str,
    *,
    pid1_offsets: str | None = None,
    reader_offsets: str | None = None,
) -> str:
    return (
        "pid1-stat-v1\n"
        f"{stat_output.removesuffix(chr(10))}\n"
        "pid1-offsets-v1\n"
        f"{pid1_offsets if pid1_offsets is not None else _zero_offsets()}"
        "reader-offsets-v1\n"
        f"{reader_offsets if reader_offsets is not None else _zero_offsets()}"
    )


def _boottime_reader_output(value: int, *, offsets: str | None = None) -> str:
    return (
        f"boottime-ns-v1\n{value}\nreader-offsets-v1\n"
        f"{offsets if offsets is not None else _zero_offsets()}"
    )


def test_pid1_start_ticks_parses_exact_proc_field_22() -> None:
    with patch.object(
        inspector,
        "_docker",
        return_value=subprocess.CompletedProcess(
            (), 0, _pid1_clock_identity_output(_proc_stat(123_456)), ""
        ),
    ) as docker:
        assert inspector._pid1_start_ticks("a" * 64) == 123_456

    assert docker.call_args.args == (
        "container",
        "exec",
        "--user",
        "10001:10001",
        "a" * 64,
        "/bin/sh",
        "-c",
        inspector._PID1_CLOCK_IDENTITY_SCRIPT,
    )


@pytest.mark.parametrize(
    "stdout",
    [
        _proc_stat(1, pid=2),
        _proc_stat(1, state="?"),
        _proc_stat(0),
        _proc_stat(1).removesuffix("\n"),
        "1 (truncated) S 0 0\n",
    ],
)
def test_pid1_start_ticks_rejects_malformed_proc_stat(stdout: str) -> None:
    framed = _pid1_clock_identity_output(stdout) if stdout.endswith("\n") else stdout
    with (
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess((), 0, framed, ""),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector._pid1_start_ticks("a" * 64)


@pytest.mark.parametrize("offsets", [_zero_offsets(), "monotonic\t0\t0\nboottime  0\t0\n"])
def test_pid1_clock_reader_accepts_exact_zero_offsets(offsets: str) -> None:
    with patch.object(
        inspector,
        "_docker",
        return_value=subprocess.CompletedProcess(
            (),
            0,
            _pid1_clock_identity_output(
                _proc_stat(1), pid1_offsets=offsets, reader_offsets=offsets
            ),
            "",
        ),
    ):
        assert inspector._pid1_start_ticks("a" * 64) == 1


@pytest.mark.parametrize(
    "stdout",
    [
        "monotonic 1 0\nboottime 0 0\n",
        "monotonic 0 1\nboottime 0 0\n",
        "monotonic 0 0\nboottime -1 0\n",
        "monotonic +0 0\nboottime 0 0\n",
        "monotonic 00 0\nboottime 0 0\n",
        "boottime 0 0\nmonotonic 0 0\n",
        "monotonic 0 0 extra\nboottime 0 0\n",
        "monotonic 0 0\nboottime 0 0\nextra 0 0\n",
        "monotonic 0 0\nboottime 0 0",
        "monotonic 0 0\r\nboottime 0 0\r\n",
        "monotonic\u00a00 0\nboottime 0 0\n",
    ],
)
@pytest.mark.parametrize("nonzero_side", ["pid1", "reader"])
def test_pid1_clock_reader_rejects_nonzero_or_malformed_fields(
    stdout: str, nonzero_side: str
) -> None:
    kwargs = {f"{nonzero_side}_offsets": stdout}
    with (
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (), 0, _pid1_clock_identity_output(_proc_stat(1), **kwargs), ""
            ),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector._pid1_start_ticks("a" * 64)


def test_pid1_clock_reader_rejects_time_for_children_mismatch() -> None:
    with (
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess((), 41, "", ""),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector._pid1_start_ticks("a" * 64)

    assert "[ /proc/1/ns/time -ef /proc/1/ns/time_for_children ]" in (
        inspector._PID1_CLOCK_IDENTITY_SCRIPT
    )


@pytest.mark.parametrize("stdout", ["True\n", "0\n", "250\n", "100 \n", "100"])
def test_clk_tck_authentication_rejects_malformed_or_non_100(stdout: str) -> None:
    with (
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess((), 0, stdout, ""),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector._clock_ticks_per_second("b" * 64)


def test_clk_tck_is_authenticated_by_exact_supervisor_python() -> None:
    with patch.object(
        inspector,
        "_docker",
        return_value=subprocess.CompletedProcess((), 0, "100\n", ""),
    ) as docker:
        assert inspector._clock_ticks_per_second("b" * 64) == 100

    assert docker.call_args.args[5:9] == ("/usr/local/bin/python", "-I", "-S", "-c")


@pytest.mark.parametrize(
    "swap",
    ["container", "process", "time_namespace", "boot"],
)
def test_running_container_snapshot_rejects_swap_during_reads(swap: str) -> None:
    container_ids = ("a" * 64, "c" * 64) if swap == "container" else ("a" * 64,) * 2
    process_ticks = (1, 2) if swap == "process" else (1, 1)
    time_namespaces = (
        (LINUX_TIME_NAMESPACE, "time:[4026531835]")
        if swap == "time_namespace"
        else (LINUX_TIME_NAMESPACE,) * 2
    )
    boot_ids = (
        (LINUX_BOOT_ID, "22345678-1234-4234-8234-123456789abc")
        if swap == "boot"
        else (LINUX_BOOT_ID,) * 2
    )
    with (
        patch.object(
            inspector,
            "_listed_service_container_id",
            side_effect=container_ids,
        ),
        patch.object(
            inspector,
            "_inspected_container_runtime",
            return_value=(SOURCE_IMAGE_ID, BASE - timedelta(seconds=2)),
        ),
        patch.object(inspector, "_pid1_start_ticks", side_effect=process_ticks),
        patch.object(inspector, "_pid1_time_namespace", side_effect=time_namespaces),
        patch.object(inspector, "_linux_boot_id", side_effect=boot_ids),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_changed_during_inspection",
        ),
    ):
        inspector._running_service_container("chrony-nts")


def test_running_container_snapshot_rejects_second_atomic_clock_fence_nonzero() -> None:
    with (
        patch.object(
            inspector,
            "_listed_service_container_id",
            side_effect=("a" * 64, "a" * 64),
        ),
        patch.object(
            inspector,
            "_inspected_container_runtime",
            return_value=(SOURCE_IMAGE_ID, BASE - timedelta(seconds=2)),
        ),
        patch.object(
            inspector,
            "_docker",
            side_effect=(
                subprocess.CompletedProcess((), 0, _pid1_clock_identity_output(_proc_stat(1)), ""),
                subprocess.CompletedProcess(
                    (),
                    0,
                    _pid1_clock_identity_output(
                        _proc_stat(1), reader_offsets="monotonic 0 0\nboottime 1 0\n"
                    ),
                    "",
                ),
            ),
        ),
        patch.object(
            inspector,
            "_pid1_time_namespace",
            side_effect=(LINUX_TIME_NAMESPACE, LINUX_TIME_NAMESPACE),
        ),
        patch.object(inspector, "_linux_boot_id", side_effect=(LINUX_BOOT_ID, LINUX_BOOT_ID)),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector._running_service_container("chrony-nts")


def test_running_image_inspection_consumes_artifact_and_admits_exact_reviewed_ids() -> None:
    admission = _image_admission()
    admitted = admission.identities
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ) as daemon,
        patch.object(
            inspector,
            "load_image_admission_artifact",
            return_value=admission,
        ) as load,
        patch.object(inspector, "verify_images", return_value=admitted) as verify,
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(_running_source(), _running_supervisor()),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100) as clock_ticks,
        patch.object(inspector, "_validate_current_runtime_topology") as topology,
    ):
        images = inspector.inspect_running_image_ids()

    assert images == _images()
    assert daemon.call_count == 2
    assert load.call_count == 3
    verify.assert_called_once_with(SOURCE_IMAGE_ID, SUPERVISOR_IMAGE_ID)
    clock_ticks.assert_called_once_with("b" * 64)
    topology.assert_called_once_with(images)


def test_running_image_inspection_rejects_lookalike_running_image_id() -> None:
    admission = _image_admission()
    admitted = admission.identities
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "load_image_admission_artifact",
            return_value=admission,
        ) as load,
        patch.object(inspector, "verify_images", return_value=admitted),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(
                _running_source(image_id="sha256:" + "f" * 64),
                _running_supervisor(),
            ),
        ),
        patch.object(inspector, "_clock_ticks_per_second") as clock_ticks,
        patch.object(inspector, "_validate_current_runtime_topology") as topology,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_images_not_admitted",
        ),
    ):
        inspector.inspect_running_image_ids()

    assert load.call_count == 2
    clock_ticks.assert_not_called()
    topology.assert_not_called()


def test_running_image_inspection_rejects_boot_identity_mismatch() -> None:
    supervisor = _running_supervisor(boot_id="22345678-1234-4234-8234-123456789abc")
    admission = _image_admission()
    admitted = admission.identities
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "load_image_admission_artifact",
            return_value=admission,
        ),
        patch.object(inspector, "verify_images", return_value=admitted),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(_running_source(), supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second") as clock_ticks,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_process_identity_unavailable",
        ),
    ):
        inspector.inspect_running_image_ids()

    clock_ticks.assert_not_called()


def test_running_image_inspection_rejects_invalid_launch_artifact() -> None:
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "load_image_admission_artifact",
            side_effect=inspector.TrustedTimeImageVerificationError("rejected"),
        ),
        patch.object(inspector, "_running_service_container") as running,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_images_not_admitted",
        ),
    ):
        inspector.inspect_running_image_ids()

    running.assert_not_called()


def test_running_image_inspection_rejects_artifact_swap_before_container_contact() -> None:
    admission = _image_admission()
    changed = replace(admission, artifact_sha256="f" * 64)
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "load_image_admission_artifact",
            side_effect=(admission, changed),
        ),
        patch.object(inspector, "verify_images", return_value=admission.identities),
        patch.object(inspector, "_running_service_container") as running,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_images_not_admitted",
        ),
    ):
        inspector.inspect_running_image_ids()

    running.assert_not_called()


def test_running_image_inspection_rejects_artifact_swap_after_current_topology_fence() -> None:
    admission = _image_admission()
    changed = replace(admission, artifact_sha256="f" * 64)
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "load_image_admission_artifact",
            side_effect=(admission, admission, changed),
        ),
        patch.object(inspector, "verify_images", return_value=admission.identities),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(_running_source(), _running_supervisor()),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(inspector, "_validate_current_runtime_topology") as topology,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_images_not_admitted",
        ),
    ):
        inspector.inspect_running_image_ids()

    topology.assert_called_once()


def test_live_topology_validation_is_secretless_and_identity_fenced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    monkeypatch.setenv("AQT_TRUSTED_TIME_DATABASE_URL", DATABASE_URL)
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ) as daemon,
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, source, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(inspector, "validate_live_trusted_time_topology") as validate,
    ):
        inspector._validate_current_runtime_topology(_images())

    assert daemon.call_count == 2
    validate.assert_called_once()
    assert validate.call_args.kwargs["source_container_id"] == "a" * 64
    assert validate.call_args.kwargs["supervisor_container_id"] == "b" * 64
    environment = cast(dict[str, str], validate.call_args.kwargs["environment"])
    assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment


def test_live_topology_validation_rejects_metadata_drift() -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(
            inspector,
            "validate_live_trusted_time_topology",
            side_effect=inspector.TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime command or image configuration drifted"
            ),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_topology_not_admitted",
        ),
    ):
        inspector._validate_current_runtime_topology(_images())


def test_live_topology_validation_rejects_container_swap_after_metadata_read() -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    restarted_source = _running_source(
        container_id="c" * 64,
        started_at=BASE,
        pid1_start_ticks=3,
    )
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, restarted_source, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(inspector, "validate_live_trusted_time_topology") as validate,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_changed_during_inspection",
        ),
    ):
        inspector._validate_current_runtime_topology(_images())

    validate.assert_called_once()


@pytest.mark.parametrize(
    "changed_source",
    [
        _running_source(time_namespace="time:[4026531835]"),
        _running_source(boot_id="22345678-1234-4234-8234-123456789abc"),
    ],
)
def test_live_topology_validation_rejects_clock_identity_drift(
    changed_source: inspector._RunningContainer,
) -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, changed_source, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(inspector, "validate_live_trusted_time_topology") as validate,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_changed_during_inspection",
        ),
    ):
        inspector._validate_current_runtime_topology(_images())

    validate.assert_called_once()


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp://docker.example:2376",
        "ssh://operator@docker.example",
    ],
)
def test_running_image_inspection_rejects_remote_docker_before_topology_contact(
    endpoint: str,
) -> None:
    with (
        patch.dict(inspector.os.environ, {"DOCKER_HOST": endpoint}, clear=True),
        patch("scripts.start_trusted_time_supervisor._run_docker") as daemon_contact,
        patch.object(inspector, "_docker") as docker,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="local_docker_daemon_unavailable",
        ),
    ):
        inspector.inspect_running_image_ids()

    docker.assert_not_called()
    daemon_contact.assert_not_called()


def test_boottime_is_read_inside_unchanged_running_supervisor() -> None:
    current_boottime_ns = 12_345_678_901
    source = _running_source()
    supervisor = _running_supervisor()
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ) as daemon,
        patch.object(
            inspector,
            "_unchanged_running_containers",
            return_value=(source, supervisor),
        ) as unchanged,
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (), 0, _boottime_reader_output(current_boottime_ns), ""
            ),
        ) as docker,
        patch.object(inspector, "_validate_current_runtime_topology") as topology,
    ):
        assert inspector._boottime_monotonic_ns(_images()) == current_boottime_ns

    docker.assert_called_once()
    assert unchanged.call_count == 2
    assert daemon.call_count == 2
    topology.assert_called_once_with(_images())
    assert docker.call_args.args[:5] == (
        "container",
        "exec",
        "--user",
        "10001:10001",
        "b" * 64,
    )
    assert docker.call_args.args[5:] == (
        "/usr/local/bin/python",
        "-I",
        "-S",
        "-c",
        inspector._BOOTTIME_READER_SCRIPT,
    )


def test_boottime_same_call_rejects_nonzero_reader_offsets() -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_unchanged_running_containers",
            return_value=(source, supervisor),
        ),
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (),
                0,
                _boottime_reader_output(
                    12_345_678_901,
                    offsets="monotonic 0 0\nboottime 1 0\n",
                ),
                "",
            ),
        ),
        patch.object(inspector, "_validate_current_runtime_topology") as topology,
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="boottime_clock_unavailable",
        ),
    ):
        inspector._boottime_monotonic_ns(_images())

    topology.assert_not_called()


def test_boottime_read_rejects_a_supervisor_restart_after_the_clock_read() -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    restarted = _running_supervisor(pid1_start_ticks=3)
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, source, restarted),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (), 0, _boottime_reader_output(12_345_678_901), ""
            ),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_changed_during_inspection",
        ),
    ):
        inspector._boottime_monotonic_ns(_images())


def test_boottime_read_rejects_a_source_restart_after_the_clock_read() -> None:
    source = _running_source()
    supervisor = _running_supervisor()
    restarted = _running_source(pid1_start_ticks=4)
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            return_value=DOCKER_DAEMON,
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, restarted, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (), 0, _boottime_reader_output(12_345_678_901), ""
            ),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_changed_during_inspection",
        ),
    ):
        inspector._boottime_monotonic_ns(_images())


def test_boottime_read_rejects_a_local_daemon_swap_after_the_clock_read() -> None:
    changed_daemon = inspector.LocalDockerDaemonIdentity(
        context_name=DOCKER_DAEMON.context_name,
        endpoint=DOCKER_DAEMON.endpoint,
        daemon_id="LOCAL:DAEMON:2",
    )
    source = _running_source()
    supervisor = _running_supervisor()
    with (
        patch.object(
            inspector,
            "_qualified_local_docker_daemon",
            side_effect=(DOCKER_DAEMON, changed_daemon),
        ),
        patch.object(
            inspector,
            "_running_service_container",
            side_effect=(source, supervisor, source, supervisor),
        ),
        patch.object(inspector, "_clock_ticks_per_second", return_value=100),
        patch.object(
            inspector,
            "_docker",
            return_value=subprocess.CompletedProcess(
                (), 0, _boottime_reader_output(12_345_678_901), ""
            ),
        ),
        pytest.raises(
            TrustedTimeQualificationInspectionError,
            match="runtime_daemon_changed_during_inspection",
        ),
    ):
        inspector._boottime_monotonic_ns(_images())


def test_orchestration_mocks_all_effects_disposes_engine_and_never_emits_dsn() -> None:
    engine = MagicMock(spec=Engine)
    connection = cast(Connection, object())
    events: list[str] = []
    snapshot = _snapshot()
    current_boottime_ns = (
        cast(int, snapshot.evaluations[-1]["evaluated_at_monotonic_ns"]) + 1_000_000_000
    )

    def read_snapshot(_: Connection) -> HostSnapshot:
        events.append("snapshot")
        return snapshot

    def inspect_images() -> RunningImageIds:
        events.append("fresh_images")
        return _images()

    def load_database(_: Path) -> str:
        events.append("database_secret")
        return DATABASE_URL

    def read_boottime(images: RunningImageIds) -> int:
        events.append("boottime")
        assert images == _images()
        return current_boottime_ns

    with (
        patch.object(inspector, "load_runtime_database_url", side_effect=load_database),
        patch.object(inspector, "verify_operational_schema") as verify_schema,
        patch.object(inspector, "verify_trusted_time_integrity") as verify_integrity,
        patch.object(
            inspector,
            "_read_only_repeatable_read",
            return_value=nullcontext(connection),
        ),
        patch.object(inspector, "_read_host_snapshot", side_effect=read_snapshot),
    ):
        payload = inspector.inspect_trusted_time_qualification(
            env_file=Path("/owner/runtime.env"),
            engine_factory=lambda _: engine,
            authority_loader=_authority,
            image_inspector=inspect_images,
            boottime_clock=read_boottime,
        )

    verify_schema.assert_called_once_with(engine, require_phase_zero_facts=False)
    verify_integrity.assert_called_once_with(engine)
    engine.dispose.assert_called_once_with()
    assert events == ["fresh_images", "database_secret", "snapshot", "boottime"]
    serialized = json.dumps(payload, sort_keys=True)
    assert "top-secret-password" not in serialized
    assert "pooler.supabase.com" not in serialized


def test_snapshot_transaction_is_repeatable_read_and_explicitly_read_only() -> None:
    engine = MagicMock(spec=Engine)
    raw_connection = MagicMock(spec=Connection)
    connection = MagicMock(spec=Connection)
    transaction = MagicMock()
    engine.connect.return_value.__enter__.return_value = raw_connection
    raw_connection.execution_options.return_value = connection
    connection.begin.return_value = transaction

    with inspector._read_only_repeatable_read(engine) as observed:
        assert observed is connection

    raw_connection.execution_options.assert_called_once_with(isolation_level="REPEATABLE READ")
    connection.exec_driver_sql.assert_called_once_with("SET TRANSACTION READ ONLY")
    transaction.rollback.assert_called_once_with()


def test_atomic_artifact_is_exact_owner_only_and_rejects_secret_schema(
    tmp_path: Path,
) -> None:
    payload = _qualified_payload()
    encoded = inspector._canonical_json_bytes(payload)
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"

    artifact_path = write_qualification_artifact(
        artifact_dir,
        encoded,
        qualification_sha256=cast(str, payload["qualification_sha256"]),
        ignored_root=ignored_root,
    )

    assert artifact_path.read_bytes() == encoded
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(ignored_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact_dir.stat().st_mode) == 0o700
    assert not tuple(artifact_dir.glob(".*.tmp"))
    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_already_exists"):
        write_qualification_artifact(
            artifact_dir,
            encoded,
            qualification_sha256=cast(str, payload["qualification_sha256"]),
            ignored_root=ignored_root,
        )

    secret_payload = dict(payload)
    secret_payload["database_url"] = DATABASE_URL
    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_invalid"):
        write_qualification_artifact(
            artifact_dir,
            inspector._canonical_json_bytes(secret_payload),
            qualification_sha256=cast(str, payload["qualification_sha256"]),
            ignored_root=ignored_root,
        )


def test_artifact_directory_rejects_symlinks_and_paths_outside_ignored_root(
    tmp_path: Path,
) -> None:
    payload = _qualified_payload()
    encoded = inspector._canonical_json_bytes(payload)
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (ignored_root / "linked").symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_write_failed"):
        write_qualification_artifact(
            ignored_root / "linked",
            encoded,
            qualification_sha256=cast(str, payload["qualification_sha256"]),
            ignored_root=ignored_root,
        )
    with pytest.raises(TrustedTimeQualificationInspectionError, match="artifact_directory_invalid"):
        write_qualification_artifact(
            elsewhere,
            encoded,
            qualification_sha256=cast(str, payload["qualification_sha256"]),
            ignored_root=ignored_root,
        )


def test_cli_prints_and_writes_identical_canonical_qualified_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _qualified_payload()
    with (
        patch.object(
            sys,
            "argv",
            [
                "inspect_trusted_time_qualification.py",
                "--env-file",
                "/owner/runtime.env",
                "--artifact-dir",
                str(inspector.IGNORED_ARTIFACT_ROOT / "trusted-time"),
            ],
        ),
        patch.object(inspector, "inspect_trusted_time_qualification", return_value=payload),
        patch.object(inspector, "write_qualification_artifact") as write,
    ):
        inspector.main()

    output = capsys.readouterr().out.encode()
    assert output == inspector._canonical_json_bytes(payload)
    assert write.call_args.args[1] == output


def test_cli_prints_not_qualified_evidence_then_exits_three(
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _qualified_payload(_failure_snapshot())
    with (
        patch.object(
            sys,
            "argv",
            ["inspect_trusted_time_qualification.py", "--env-file", "/owner/runtime.env"],
        ),
        patch.object(inspector, "inspect_trusted_time_qualification", return_value=payload),
        pytest.raises(SystemExit) as raised,
    ):
        inspector.main()

    assert raised.value.code == 3
    assert json.loads(capsys.readouterr().out)["status"] == "not_qualified"


def test_cli_sanitizes_unexpected_failure_and_exits_two(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch.object(
            sys,
            "argv",
            ["inspect_trusted_time_qualification.py", "--env-file", "/owner/runtime.env"],
        ),
        patch.object(
            inspector,
            "inspect_trusted_time_qualification",
            side_effect=RuntimeError(DATABASE_URL),
        ),
        pytest.raises(SystemExit) as raised,
    ):
        inspector.main()

    output = capsys.readouterr().out
    assert raised.value.code == 2
    assert json.loads(output) == {
        "authority_granted": False,
        "database_secret_disclosed": False,
        "reason": "qualification_inspection_rejected",
        "service": "trusted-time-qualification-inspector",
        "status": "fatal",
    }
    assert "top-secret-password" not in output
    assert "pooler.supabase.com" not in output
