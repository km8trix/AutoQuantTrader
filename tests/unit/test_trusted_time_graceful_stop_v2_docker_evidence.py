from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
)
from packages.domain.trusted_time_graceful_stop_v2_docker import (
    COMMAND_SOCKET_VOLUME,
    STATE_VOLUME,
    DockerAdmissionCapture,
    DockerAdmissionRootedTracePrefix,
    DockerConnectionIdentity,
    DockerMutationResultSemantic,
    DockerOrdinalEvidence,
    DockerPlanIdentity,
    DockerRequestSemantic,
    DockerVolumePreservationResult,
    TrustedTimeDockerEvidenceRejected,
    docker_call_spec,
    docker_evidence_non_authority_facts,
    parse_docker_response,
    validate_complete_docker_trace,
    validate_docker_request_bytes,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    CLEAN_STOP_ERROR_CONTRACT_VERSION,
    CLEAN_STOP_RESULT_CONTRACT_VERSION,
    LISTENER_PATH,
    SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
    SUPERVISOR_RAW_KEY_PATH,
    WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
    LifecycleV2AuthenticatedTerminalEnvelopeProof,
    LifecycleV2CleanStopError,
    LifecycleV2CleanStopResult,
    LifecycleV2SupervisorCleanupCommitment,
    LifecycleV2TerminalProjection,
    LifecycleV2TerminalWireEvidence,
    LifecycleV2WirePublicationReceipt,
    _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof_for_tests,
    decode_lifecycle_v2_clean_stop_error,
    decode_lifecycle_v2_clean_stop_result,
    terminal_non_authority_facts,
    validate_terminal_envelope_payload,
)
from tests.unit.trusted_time_graceful_stop_v2_docker_fakes import (
    FakeDockerDaemon,
    FakeDockerDaemonFault,
    FakeDockerFault,
    FakeDockerHttpAdapter,
    fake_docker_non_authority_facts,
)

ROOT = Path(__file__).resolve().parents[2]
OPERATION_ID = "323e4567-e89b-42d3-a456-426614174099"
ENVIRONMENT = "test"
CHANNEL_ID = "4" * 64
ROOT_SHA256 = "5" * 64
SUPERVISOR_ID = "1" * 64
SOURCE_ID = "2" * 64
NETWORK_ID = "3" * 64
PLAN_IDENTITY = DockerPlanIdentity(SUPERVISOR_ID, SOURCE_ID, NETWORK_ID)
UTC_TEXT = "2026-08-27T12:00:00.000000Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _adapter(
    *, fault: FakeDockerFault | None = None
) -> tuple[FakeDockerDaemon, FakeDockerHttpAdapter]:
    daemon = FakeDockerDaemon(PLAN_IDENTITY, fault=fault)
    adapter = FakeDockerHttpAdapter(
        daemon,
        PLAN_IDENTITY,
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
    )
    return daemon, adapter


def _complete_evidence() -> tuple[FakeDockerDaemon, FakeDockerHttpAdapter, tuple[Any, ...]]:
    daemon, adapter = _adapter()
    return daemon, adapter, adapter.run_complete_plan()


def _entry_with_connection(
    entry: Any,
    *,
    updates: dict[str, object],
) -> DockerOrdinalEvidence:
    fields = entry.connection.to_dict()
    fields.update(updates)
    return DockerOrdinalEvidence.construct(
        spec=entry.spec,
        request=entry.request,
        connection=DockerConnectionIdentity.capture(fields),
        response=entry.response,
        previous_trace_entry_sha256=entry.trace.to_dict()["previous_trace_entry_sha256"],
    )


def _rebuild_entry(
    entry: Any,
    *,
    previous_trace_entry_sha256: str | None,
    connection_updates: dict[str, object] | None = None,
) -> DockerOrdinalEvidence:
    fields = entry.connection.to_dict()
    fields.update(connection_updates or {})
    return DockerOrdinalEvidence.construct(
        spec=entry.spec,
        request=entry.request,
        connection=DockerConnectionIdentity.capture(fields),
        response=entry.response,
        previous_trace_entry_sha256=previous_trace_entry_sha256,
    )


def _trace_prefix(
    admission: DockerAdmissionCapture,
    entries: tuple[Any, ...] | list[Any],
    last_ordinal: int,
) -> DockerAdmissionRootedTracePrefix:
    prefix = DockerAdmissionRootedTracePrefix.from_admission(
        admission=admission,
        entries=entries[:6],
    )
    for entry in entries[6 : last_ordinal + 1]:
        prefix = prefix.append(entry)
    assert prefix.last_ordinal == last_ordinal
    assert prefix.trace_head_sha256 == entries[last_ordinal].trace.sha256
    return prefix


def test_literal_request_plan_closes_every_method_query_header_and_body() -> None:
    expected = [
        "GET /v1.45/info HTTP/1.1",
        f"GET /v1.45/containers/{SUPERVISOR_ID}/json HTTP/1.1",
        f"GET /v1.45/containers/{SOURCE_ID}/json HTTP/1.1",
        f"GET /v1.45/networks/{NETWORK_ID} HTTP/1.1",
        f"GET /v1.45/volumes/{COMMAND_SOCKET_VOLUME} HTTP/1.1",
        f"GET /v1.45/volumes/{STATE_VOLUME} HTTP/1.1",
        f"POST /v1.45/containers/{SUPERVISOR_ID}/stop?t=30 HTTP/1.1",
        f"GET /v1.45/containers/{SUPERVISOR_ID}/json HTTP/1.1",
        f"POST /v1.45/containers/{SOURCE_ID}/stop?t=30 HTTP/1.1",
        f"GET /v1.45/containers/{SOURCE_ID}/json HTTP/1.1",
        (f"DELETE /v1.45/containers/{SUPERVISOR_ID}?v=false&force=false&link=false HTTP/1.1"),
        f"GET /v1.45/containers/{SUPERVISOR_ID}/json HTTP/1.1",
        (f"DELETE /v1.45/containers/{SOURCE_ID}?v=false&force=false&link=false HTTP/1.1"),
        f"GET /v1.45/containers/{SOURCE_ID}/json HTTP/1.1",
        f"DELETE /v1.45/networks/{NETWORK_ID} HTTP/1.1",
        f"GET /v1.45/networks/{NETWORK_ID} HTTP/1.1",
        f"GET /v1.45/volumes/{COMMAND_SOCKET_VOLUME} HTTP/1.1",
        f"GET /v1.45/volumes/{STATE_VOLUME} HTTP/1.1",
    ]
    for ordinal, request_line in enumerate(expected):
        spec = docker_call_spec(ordinal, PLAN_IDENTITY)
        semantic = DockerRequestSemantic.from_spec(spec)
        encoded = semantic.request_bytes(spec)
        assert encoded.split(b"\r\n", 1)[0].decode("ascii") == request_line
        assert encoded.endswith(b"\r\n\r\n")
        assert b"Transfer-Encoding" not in encoded
        assert b"Content-Type" not in encoded
        assert b"User-Agent" not in encoded
        if spec.method == "GET":
            assert b"Content-Length" not in encoded
        else:
            assert encoded.count(b"Content-Length: 0\r\n") == 1
        assert validate_docker_request_bytes(encoded, spec=spec) == semantic


@pytest.mark.parametrize(
    "ordinal,transform",
    [
        (6, lambda value: value.replace(b"?t=30", b"?signal=SIGTERM&t=30")),
        (
            10,
            lambda value: value.replace(
                b"?v=false&force=false&link=false", b"?force=false&v=false&link=false"
            ),
        ),
        (10, lambda value: value.replace(b"v=false", b"v=true")),
        (0, lambda value: value.replace(b"Connection: close", b"connection: close")),
        (0, lambda value: value + b"{}"),
    ],
)
def test_request_tamper_is_rejected_before_fake_daemon_dispatch(
    ordinal: int,
    transform: Any,
) -> None:
    spec = docker_call_spec(ordinal, PLAN_IDENTITY)
    encoded = DockerRequestSemantic.from_spec(spec).request_bytes(spec)
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        validate_docker_request_bytes(transform(encoded), spec=spec)


def test_complete_fake_daemon_plan_produces_gap_free_typed_ordinals() -> None:
    daemon, _, entries = _complete_evidence()
    exact = validate_complete_docker_trace(entries)
    assert [entry.spec.ordinal for entry in exact] == list(range(18))
    assert [entry.trace.ordinal for entry in exact] == list(range(18))
    assert len({entry.connection.sha256 for entry in exact}) == 18
    assert daemon.volume_delete_call_count == 0
    assert [event.split(":", 2)[1] for event in daemon.events] == [
        "GET",
        "GET",
        "GET",
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
        "POST",
        "GET",
        "DELETE",
        "GET",
        "DELETE",
        "GET",
        "DELETE",
        "GET",
        "GET",
        "GET",
    ]
    assert all("/volumes/" not in event or ":GET:" in event for event in daemon.events)


def test_admission_mutation_and_volume_result_semantics_bind_complete_nested_evidence() -> None:
    daemon, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    results = [
        DockerMutationResultSemantic.from_pair(
            result_kind=kind,
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, ordinal + 1),
            admitted_target=entries[{6: 1, 8: 2, 10: 1, 12: 2, 14: 3}[ordinal]],
            previous=entries[ordinal - 1],
            primary=entries[ordinal],
            post_inspect=entries[ordinal + 1],
        )
        for kind, ordinal in (
            ("container_stop", 6),
            ("container_stop", 8),
            ("container_remove", 10),
            ("container_remove", 12),
            ("network_remove", 14),
        )
    ]
    assert len({result.sha256 for result in results}) == 5
    volume = DockerVolumePreservationResult.from_pair(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=ROOT_SHA256,
        admission=admission,
        trace_prefix=_trace_prefix(admission, entries, 17),
        previous=entries[15],
        command_socket=entries[16],
        state=entries[17],
        volume_delete_call_count=daemon.volume_delete_call_count,
    )
    assert (
        volume.to_dict()["admission_volume_projection_sha256_list"]
        == volume.to_dict()["post_volume_projection_sha256_list"]
    )
    assert volume.to_dict()["volume_delete_call_count"] == 0


def test_nested_admission_result_and_trace_tamper_is_rejected() -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    admission_value = admission.to_dict()
    admission_value["ordered_trace_entry_sha256_list"][2] = "0" * 64  # type: ignore[index]
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerAdmissionCapture.capture(admission_value)

    result = DockerMutationResultSemantic.from_pair(
        result_kind="container_stop",
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=ROOT_SHA256,
        admission=admission,
        trace_prefix=_trace_prefix(admission, entries, 7),
        admitted_target=entries[1],
        previous=entries[5],
        primary=entries[6],
        post_inspect=entries[7],
    )
    result_value = result.to_dict()
    result_value["primary_request_semantic_sha256"] = "0" * 64
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerMutationResultSemantic.capture(
            result_value,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 7),
            admitted_target=entries[1],
            previous=entries[5],
            primary=entries[6],
            post_inspect=entries[7],
        )

    reordered = list(entries)
    reordered[6], reordered[7] = reordered[7], reordered[6]
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        validate_complete_docker_trace(reordered)


@pytest.mark.parametrize(
    "kind",
    [
        "disconnect",
        "truncated_body",
        "surplus_body",
        "chunked",
        "duplicate_header",
        "wrong_status",
        "oversized_header",
    ],
)
def test_every_byte_or_framing_fault_burns_adapter_and_daemon(kind: str) -> None:
    ordinal = 0 if kind != "wrong_status" else 6
    daemon, adapter = _adapter(fault=FakeDockerFault(ordinal, kind))
    for current in range(ordinal):
        adapter.execute_ordinal(current)
    with pytest.raises((FakeDockerDaemonFault, TrustedTimeDockerEvidenceRejected)):
        adapter.execute_ordinal(ordinal)
    assert adapter.burned is True
    assert daemon.burned is True
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(ordinal)


@pytest.mark.parametrize("ordinal", range(18))
def test_disconnect_at_every_ordinal_burns_without_retry(ordinal: int) -> None:
    daemon, adapter = _adapter(fault=FakeDockerFault(ordinal, "disconnect"))
    for current in range(ordinal):
        adapter.execute_ordinal(current)
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(ordinal)
    assert adapter.burned is True
    assert daemon.burned is True
    assert len(adapter.evidence) == ordinal


def test_order_violation_and_replay_burn_the_byte_fake() -> None:
    daemon, adapter = _adapter()
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(1)
    assert adapter.burned is True
    assert daemon.events == []

    daemon, adapter = _adapter()
    adapter.execute_ordinal(0)
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(0)
    assert adapter.burned is True
    assert len(daemon.events) == 1


def test_post_plan_and_repeated_complete_calls_burn_both_fakes() -> None:
    daemon, adapter = _adapter()
    adapter.run_complete_plan()
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(18)
    assert adapter.burned is True
    assert daemon.burned is True

    daemon, adapter = _adapter()
    adapter.run_complete_plan()
    with pytest.raises(FakeDockerDaemonFault):
        daemon.exchange(18, b"")
    assert daemon.burned is True

    daemon, adapter = _adapter()
    adapter.run_complete_plan()
    with pytest.raises(FakeDockerDaemonFault):
        adapter.run_complete_plan()
    assert adapter.burned is True
    assert daemon.burned is True


@pytest.mark.parametrize("ordinal", [False, True])
def test_boolean_fake_ordinal_burns_both_fakes(ordinal: bool) -> None:
    daemon, adapter = _adapter()
    with pytest.raises(FakeDockerDaemonFault):
        adapter.execute_ordinal(ordinal)
    assert adapter.burned is True
    assert daemon.burned is True


@pytest.mark.parametrize(
    "kind",
    [
        "post_image_id_drift",
        "post_config_image_drift",
        "post_stop_signal_drift",
        "post_container_name_drift",
    ],
)
def test_post_stop_projection_must_preserve_admitted_identity_and_config(kind: str) -> None:
    _, adapter = _adapter(fault=FakeDockerFault(7, kind))
    entries = adapter.run_complete_plan()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerMutationResultSemantic.from_pair(
            result_kind="container_stop",
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 7),
            admitted_target=entries[1],
            previous=entries[5],
            primary=entries[6],
            post_inspect=entries[7],
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"environment": "other"},
        {"graceful_stop_operation_id": "other-operation"},
        {"channel_id": "9" * 64},
        {"peer_pid": 1_000},
        {"socket_path_inode": 201},
        {"local_socket_inode": 300},
        {"local_socket_cookie": 400},
        {"path_preconnect_validated_boottime_ns": 1_000_003},
    ],
)
def test_complete_trace_rejects_context_core_reuse_and_time_overlap(
    updates: dict[str, object],
) -> None:
    _, _, entries = _complete_evidence()
    changed = list(entries)
    changed[1] = _entry_with_connection(entries[1], updates=updates)
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        validate_complete_docker_trace(changed)


def test_admission_rooted_trace_prefix_is_sealed_and_advances_through_volume_proof() -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    with pytest.raises(TypeError):
        DockerAdmissionRootedTracePrefix()
    forged = object.__new__(DockerAdmissionRootedTracePrefix)
    with pytest.raises(TrustedTimeDockerEvidenceRejected, match="not sealed"):
        _ = forged.last_ordinal

    prefix = DockerAdmissionRootedTracePrefix.from_admission(
        admission=admission,
        entries=entries[:6],
    )
    assert prefix.last_ordinal == 5
    for ordinal, entry in enumerate(entries[6:], start=6):
        prefix = prefix.append(entry)
        assert prefix.last_ordinal == ordinal
        assert prefix.trace_head_sha256 == entry.trace.sha256
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        prefix.append(entries[17])


@pytest.mark.parametrize(
    "previous_ordinal,result_kind,admitted_ordinal",
    [
        (7, "container_stop", 2),
        (9, "container_remove", 1),
        (11, "container_remove", 2),
        (13, "network_remove", 3),
        (15, "volume_preservation", None),
    ],
)
def test_every_later_orphan_predecessor_is_rejected_by_the_admission_rooted_prefix(
    previous_ordinal: int,
    result_kind: str,
    admitted_ordinal: int | None,
) -> None:
    daemon, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    previous = _rebuild_entry(
        entries[previous_ordinal],
        previous_trace_entry_sha256=_digest(f"orphan-{previous_ordinal}"),
    )
    primary = _rebuild_entry(
        entries[previous_ordinal + 1],
        previous_trace_entry_sha256=previous.trace.sha256,
    )
    post = _rebuild_entry(
        entries[previous_ordinal + 2],
        previous_trace_entry_sha256=primary.trace.sha256,
    )
    orphaned = [*entries[:previous_ordinal], previous, primary, post]
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerAdmissionRootedTracePrefix.from_admission(
            admission=admission,
            entries=orphaned,
        )

    admitted_prefix = _trace_prefix(admission, entries, previous_ordinal + 2)
    if result_kind == "volume_preservation":
        with pytest.raises(TrustedTimeDockerEvidenceRejected):
            DockerVolumePreservationResult.from_pair(
                environment=ENVIRONMENT,
                graceful_stop_operation_id=OPERATION_ID,
                root_sha256=ROOT_SHA256,
                admission=admission,
                trace_prefix=admitted_prefix,
                previous=previous,
                command_socket=primary,
                state=post,
                volume_delete_call_count=daemon.volume_delete_call_count,
            )
    else:
        assert admitted_ordinal is not None
        with pytest.raises(TrustedTimeDockerEvidenceRejected):
            DockerMutationResultSemantic.from_pair(
                result_kind=result_kind,
                environment=ENVIRONMENT,
                graceful_stop_operation_id=OPERATION_ID,
                root_sha256=ROOT_SHA256,
                admission=admission,
                trace_prefix=admitted_prefix,
                admitted_target=entries[admitted_ordinal],
                previous=previous,
                primary=primary,
                post_inspect=post,
            )


def test_cross_run_prior_head_cannot_be_substituted_into_a_valid_result_cursor() -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    cross_run_previous = _rebuild_entry(
        entries[9],
        previous_trace_entry_sha256=_digest("cross-run-prior-head"),
        connection_updates={
            "local_socket_inode": 30_009,
            "local_socket_cookie": 40_009,
        },
    )
    primary = _rebuild_entry(
        entries[10],
        previous_trace_entry_sha256=cross_run_previous.trace.sha256,
        connection_updates={
            "local_socket_inode": 30_010,
            "local_socket_cookie": 40_010,
        },
    )
    post = _rebuild_entry(
        entries[11],
        previous_trace_entry_sha256=primary.trace.sha256,
        connection_updates={
            "local_socket_inode": 30_011,
            "local_socket_cookie": 40_011,
        },
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerMutationResultSemantic.from_pair(
            result_kind="container_remove",
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 11),
            admitted_target=entries[1],
            previous=cross_run_previous,
            primary=primary,
            post_inspect=post,
        )


def test_post_admission_local_socket_identity_cannot_be_reused() -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    prior_connection = entries[6].connection.to_dict()
    reused = _rebuild_entry(
        entries[8],
        previous_trace_entry_sha256=entries[7].trace.sha256,
        connection_updates={
            "local_socket_device": prior_connection["local_socket_device"],
            "local_socket_inode": prior_connection["local_socket_inode"],
            "local_socket_cookie": prior_connection["local_socket_cookie"],
        },
    )
    post = _rebuild_entry(
        entries[9],
        previous_trace_entry_sha256=reused.trace.sha256,
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected, match="identity was reused"):
        DockerAdmissionRootedTracePrefix.from_admission(
            admission=admission,
            entries=[*entries[:8], reused, post],
        )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerMutationResultSemantic.from_pair(
            result_kind="container_stop",
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 9),
            admitted_target=entries[2],
            previous=entries[7],
            primary=reused,
            post_inspect=post,
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"channel_id": "9" * 64},
        {"peer_pid": 1_001},
        {"path_preconnect_validated_boottime_ns": 1_000_703},
    ],
)
def test_post_admission_prefix_rejects_channel_daemon_and_time_discontinuity(
    updates: dict[str, object],
) -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    changed = _rebuild_entry(
        entries[8],
        previous_trace_entry_sha256=entries[7].trace.sha256,
        connection_updates=updates,
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerAdmissionRootedTracePrefix.from_admission(
            admission=admission,
            entries=[*entries[:8], changed],
        )


def test_complete_trace_rejects_mixed_plan_and_exact_prior_head_substitution() -> None:
    _, _, entries = _complete_evidence()
    alternate_identity = DockerPlanIdentity("a" * 64, "b" * 64, "c" * 64)
    daemon = FakeDockerDaemon(alternate_identity)
    alternate = FakeDockerHttpAdapter(
        daemon,
        alternate_identity,
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
    ).run_complete_plan()
    mixed = list(entries)
    mixed[2] = alternate[2]
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        validate_complete_docker_trace(mixed)

    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerMutationResultSemantic.from_pair(
            result_kind="container_stop",
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 7),
            admitted_target=entries[1],
            previous=entries[4],
            primary=entries[6],
            post_inspect=entries[7],
        )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerVolumePreservationResult.from_pair(
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 17),
            previous=entries[14],
            command_socket=entries[16],
            state=entries[17],
            volume_delete_call_count=0,
        )


@pytest.mark.parametrize(
    "size,accepted",
    [
        (268_435_455, True),
        (268_435_456, True),
        (268_435_457, False),
    ],
)
def test_daemon_executable_size_boundary(size: int, accepted: bool) -> None:
    _, _, entries = _complete_evidence()
    value = entries[0].connection.to_dict()
    value["daemon_executable_size"] = size
    if accepted:
        assert DockerConnectionIdentity.capture(value).to_dict()["daemon_executable_size"] == size
    else:
        with pytest.raises(TrustedTimeDockerEvidenceRejected):
            DockerConnectionIdentity.capture(value)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("peer_uid", False),
        ("peer_gid", False),
        ("socket_path_uid", 1),
        ("socket_path_gid", 1),
        ("daemon_executable_uid", 1),
        ("daemon_executable_gid", 1),
        ("socket_path_mode", 0o100600),
        ("daemon_executable_mode", 0o140755),
        ("daemon_executable_mode", 0o100775),
        ("socket_mount_major_minor", "00:42"),
        ("socket_mount_root", "relative"),
        ("socket_mount_source", "x" * 256),
    ],
)
def test_connection_identity_rejects_unsafe_or_unbounded_facts(
    field: str,
    replacement: object,
) -> None:
    _, _, entries = _complete_evidence()
    value = entries[0].connection.to_dict()
    value[field] = replacement
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerConnectionIdentity.capture(value)


def test_volume_identity_drift_is_structural_evidence_but_never_preservation() -> None:
    daemon, adapter = _adapter(fault=FakeDockerFault(16, "volume_identity_drift"))
    entries = adapter.run_complete_plan()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerVolumePreservationResult.from_pair(
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=ROOT_SHA256,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 17),
            previous=entries[15],
            command_socket=entries[16],
            state=entries[17],
            volume_delete_call_count=daemon.volume_delete_call_count,
        )


def test_boolean_admission_ordinals_and_volume_delete_count_are_rejected() -> None:
    _, _, entries = _complete_evidence()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    admission_value = admission.to_dict()
    admission_value["first_connection_ordinal"] = False
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerAdmissionCapture.capture(admission_value)

    volume = DockerVolumePreservationResult.from_pair(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=ROOT_SHA256,
        admission=admission,
        trace_prefix=_trace_prefix(admission, entries, 17),
        previous=entries[15],
        command_socket=entries[16],
        state=entries[17],
        volume_delete_call_count=0,
    )
    value = volume.to_dict()
    value["volume_delete_call_count"] = False
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        DockerVolumePreservationResult.capture(
            value,
            admission=admission,
            trace_prefix=_trace_prefix(admission, entries, 17),
            previous=entries[15],
            command_socket=entries[16],
            state=entries[17],
        )


def test_response_parser_accepts_closed_204_and_404_forms_only() -> None:
    mutation = docker_call_spec(6, PLAN_IDENTITY)
    accepted = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    assert parse_docker_response(accepted, spec=mutation).http_status == 204
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(accepted + b"{}", spec=mutation)

    absent = docker_call_spec(11, PLAN_IDENTITY)
    body = _compact_json({"message": f"No such container: {SUPERVISOR_ID}"}) + b"\n"
    response = _json_http_response(404, body)
    assert parse_docker_response(response, spec=absent).http_status == 404
    wrong_body = _compact_json({"message": f"No such container: {SUPERVISOR_ID}"}) + b" "
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(_json_http_response(404, wrong_body), spec=absent)


def test_response_parser_rejects_declared_limit_duplicate_json_and_depth() -> None:
    info = docker_call_spec(0, PLAN_IDENTITY)
    oversized = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nContent-Type: application/json\r\n\r\n"
    )
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(oversized, spec=info)

    duplicate = b'{"ID":"a","ID":"b"}'
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(_json_http_response(200, duplicate), spec=info)

    deep: object = "leaf"
    for _ in range(18):
        deep = {"nested": deep}
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(_json_http_response(200, _compact_json(deep)), spec=info)

    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(
            _json_http_response(200, b'{"ID":"\\ud800"}'),
            spec=info,
        )


@pytest.mark.parametrize("offset,accepted", [(-1, True), (0, True), (1, False)])
def test_info_response_body_ceiling_minus_exact_plus(offset: int, accepted: bool) -> None:
    spec = docker_call_spec(0, PLAN_IDENTITY)
    target = spec.body_ceiling + offset
    value: dict[str, object] = {
        "ID": "fake-daemon",
        "DockerRootDir": "/var/lib/docker",
        "Name": "fake-host",
        "ServerVersion": "27.5.1",
        "OperatingSystem": "Fake Linux",
        "OSType": "linux",
        "Architecture": "x86_64",
        "Driver": "overlay2",
        "SecurityOptions": ["name=seccomp,profile=default"],
        "Padding": [""] * 16,
    }
    baseline = _compact_json(value)
    remaining = target - len(baseline)
    assert 0 <= remaining <= 16 * 65_536
    chunks = [min(65_536, max(0, remaining - index * 65_536)) for index in range(16)]
    value["Padding"] = ["x" * size for size in chunks]
    body = _compact_json(value)
    assert len(body) == target
    response = _json_http_response(200, body)
    if accepted:
        assert parse_docker_response(response, spec=spec).http_status == 200
    else:
        with pytest.raises(TrustedTimeDockerEvidenceRejected):
            parse_docker_response(response, spec=spec)


@pytest.mark.parametrize(
    "ordinal,ceiling",
    [(0, 1_048_576), (1, 524_288), (3, 262_144), (4, 131_072), (11, 4_096)],
)
def test_every_response_body_ceiling_rejects_before_allocation(
    ordinal: int,
    ceiling: int,
) -> None:
    spec = docker_call_spec(ordinal, PLAN_IDENTITY)
    response = (
        f"HTTP/1.1 {spec.expected_status} Any\r\n"
        f"Content-Length: {ceiling + 1}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(response, spec=spec, volume_host_identity=(1, 2))


@pytest.mark.parametrize(
    "header",
    [
        b"Content-Length: 01\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Encoding: gzip\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: keep-alive\r\n",
    ],
)
def test_prohibited_or_noncanonical_framing_headers_reject(header: bytes) -> None:
    spec = docker_call_spec(0, PLAN_IDENTITY)
    response = b"HTTP/1.1 200 OK\r\n" + header + b"Content-Type: application/json\r\n\r\n{}"
    with pytest.raises(TrustedTimeDockerEvidenceRejected):
        parse_docker_response(response, spec=spec)


def test_unknown_raw_fields_change_body_digest_but_not_typed_projection() -> None:
    _, _, entries = _complete_evidence()
    baseline = entries[0].response
    raw = {
        "ID": "fake-daemon",
        "DockerRootDir": "/var/lib/docker",
        "Name": "fake-host",
        "ServerVersion": "27.5.1",
        "OperatingSystem": "Fake Linux",
        "OSType": "linux",
        "Architecture": "x86_64",
        "Driver": "overlay2",
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
        "AnotherUnknown": 7,
    }
    parsed = parse_docker_response(
        _json_http_response(200, _compact_json(raw)),
        spec=docker_call_spec(0, PLAN_IDENTITY),
    )
    assert parsed.response_projection_sha256 == baseline.response_projection_sha256
    assert parsed.response_body_sha256 != baseline.response_body_sha256


def _compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _json_http_response(status: int, body: bytes) -> bytes:
    reason = {200: "OK", 404: "Not Found"}[status]
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def _root() -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        graceful_stop_target_sha256=_digest("target"),
        graceful_stop_decision_v1_sha256=_digest("decision"),
        graceful_stop_operator_attestation_envelope_sha256=_digest("attestation"),
        historical_decision_receipt_sha256=_digest("receipt"),
        admission_sha256=_digest("admission"),
        topology_sha256=_digest("topology"),
        topology_lease_sha256=_digest("topology-lease"),
        trusted_head_sha256=_digest("head"),
        stop_authority_sha256=_digest("authority"),
        transport_authority_manifest_sha256=_digest("manifest"),
        transport_key_generation=1,
        host_transport_key_id="host-key-1",
        supervisor_transport_key_id="supervisor-key-1",
        boot_epoch_sha256=_digest("boot"),
        host_process_epoch_sha256=_digest("host-process"),
        supervisor_process_epoch_sha256=_digest("supervisor-process"),
        channel_id=_digest("channel"),
        supervisor_container_id=SUPERVISOR_ID,
        source_container_id=SOURCE_ID,
        project_network_id=NETWORK_ID,
        chrony_command_socket_volume_identity_sha256=_digest("command-volume"),
        chrony_state_volume_identity_sha256=_digest("state-volume"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest]:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    intent = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=1,
        stage=LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
        predecessor_sha256=root.sha256,
        effect_kind="clean_stop_request",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "target_identity_sha256": root.supervisor_container_id,
                "arguments_sha256": basis.sha256,
                "admission_sha256": root.admission_sha256,
                "channel_id": root.channel_id,
                "call_deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )
    return root, LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)


def _terminal_projection() -> LifecycleV2TerminalProjection:
    value: dict[str, object] = {
        "request_sequence": 3,
        "request_scheduled_monotonic_ns": 10,
        "anchor_sequence": 3,
        "checkpoint_reason": "clean_stop",
        "confirmed_anchor_count": 3,
        "local_transition_count": 4,
        "confirmed_anchor_local_transition_ordinal": 4,
        "predecessor_anchor_sha256": _digest("predecessor"),
        "current_host_head_sha256": _digest("host-head"),
        "current_anchor_sha256": _digest("anchor"),
        "current_anchor_semantic_sha256": _digest("anchor-semantic"),
        "receipt_observed_at_utc": UTC_TEXT,
        "full_audit_completed": True,
        "prior_pending_intent_recovered": False,
        "uploaded_anchor_count": 1,
        "idempotent_duplicate_count": 0,
        "current_anchor_intent_semantic_sha256": _digest("intent-semantic"),
        "current_candidate_remote_readback_sha256": _digest("anchor"),
        "current_receipt_semantic_sha256": _digest("receipt-semantic"),
        "clean_stop_terminal_result_semantic_sha256": "0" * 64,
    }
    semantic_payload = {
        "anchor_sequence": value["anchor_sequence"],
        "checkpoint_reason": value["checkpoint_reason"],
        "confirmed_anchor_count": value["confirmed_anchor_count"],
        "confirmed_anchor_local_transition_ordinal": value[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "contract_version": "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1",
        "current_anchor_intent_semantic_sha256": value["current_anchor_intent_semantic_sha256"],
        "current_anchor_semantic_sha256": value["current_anchor_semantic_sha256"],
        "current_anchor_sha256": value["current_anchor_sha256"],
        "current_candidate_remote_readback_sha256": value[
            "current_candidate_remote_readback_sha256"
        ],
        "current_host_head_sha256": value["current_host_head_sha256"],
        "current_receipt_semantic_sha256": value["current_receipt_semantic_sha256"],
        "full_audit_completed": value["full_audit_completed"],
        "idempotent_duplicate_count": value["idempotent_duplicate_count"],
        "local_transition_count": value["local_transition_count"],
        "predecessor_anchor_sha256": value["predecessor_anchor_sha256"],
        "prior_pending_intent_recovered": value["prior_pending_intent_recovered"],
        "receipt_observed_at_utc": value["receipt_observed_at_utc"],
        "request_scheduled_monotonic_ns": value["request_scheduled_monotonic_ns"],
        "request_sequence": value["request_sequence"],
        "status": "exact_current_new_record_clean_stop_completed",
        "uploaded_anchor_count": value["uploaded_anchor_count"],
    }
    value["clean_stop_terminal_result_semantic_sha256"] = hashlib.sha256(
        canonical_v2_json_bytes(semantic_payload, maximum_bytes=64 * 1_024)
    ).hexdigest()
    return LifecycleV2TerminalProjection.capture(value)


def _cleanup(
    root: LifecycleV2Root, request: LifecycleV2CleanStopRequest
) -> LifecycleV2SupervisorCleanupCommitment:
    request_fields = request.to_dict()
    return LifecycleV2SupervisorCleanupCommitment.capture(
        {
            "contract_version": SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "status": "supervisor_transport_cleanup_committed",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "admission_sha256": root.admission_sha256,
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "transport_authority_manifest_sha256": root.transport_authority_manifest_sha256,
            "key_generation": root.transport_key_generation,
            "supervisor_key_id": root.supervisor_transport_key_id,
            "supervisor_socket_identity_sha256": _digest("socket"),
            "supervisor_peer_credential_sha256": _digest("peer"),
            "listener_path": LISTENER_PATH,
            "listener_path_device": 1,
            "listener_path_inode": 2,
            "listener_fd_socket_inode": 3,
            "accepted_fd_socket_inode": 4,
            "raw_key_path": SUPERVISOR_RAW_KEY_PATH,
            "raw_key_device": 5,
            "raw_key_inode": 6,
            "supervisor_challenge_sha256": _digest("challenge"),
            "supervisor_process_nonce_sha256": _digest("nonce"),
            "cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
        }
    )


def _result() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest, LifecycleV2CleanStopResult]:
    root, request = _request()
    projection = _terminal_projection()
    cleanup = _cleanup(root, request)
    request_fields = request.to_dict()
    result = LifecycleV2CleanStopResult.capture(
        {
            "contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "exact_operation_bound_new_record_clean_stop_correlated_unqualified",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "admission_sha256": root.admission_sha256,
            "lifecycle_dispatch_prefix_sha256": request_fields["lifecycle_dispatch_prefix_sha256"],
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "operation_bound_request": request.to_dict(),
            "request_sha256": request.sha256,
            "terminal_projection": projection.to_dict(),
            "terminal_projection_sha256": projection.sha256,
            "supervisor_transport_cleanup_commitment": cleanup.to_dict(),
            "supervisor_transport_cleanup_commitment_sha256": cleanup.sha256,
            "result_completed_boottime_ns": root.admission_started_boottime_ns + 1,
            "transport_cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
    )
    return root, request, result


def _error() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest, LifecycleV2CleanStopError]:
    root, request = _request()
    cleanup = _cleanup(root, request)
    request_fields = request.to_dict()
    error = LifecycleV2CleanStopError.capture(
        {
            "contract_version": CLEAN_STOP_ERROR_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "operation_bound_clean_stop_failed_unqualified",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "request_sha256": request.sha256,
            "admission_sha256": root.admission_sha256,
            "lifecycle_dispatch_prefix_sha256": request_fields["lifecycle_dispatch_prefix_sha256"],
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "error_code": "clean_stop_failed",
            "failure_boundary": "during_or_after_selection",
            "call_may_have_occurred": True,
            "retryable": False,
            "observed_boottime_ns": root.admission_started_boottime_ns + 1,
            "supervisor_transport_cleanup_commitment": cleanup.to_dict(),
            "supervisor_transport_cleanup_commitment_sha256": cleanup.sha256,
            "transport_cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        },
        request=request,
    )
    return root, request, error


def _envelope(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    *,
    frame_type: str,
    payload: bytes,
) -> UnverifiedLifecycleV2TransportEnvelope:
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": "supervisor_to_host",
            "frame_type": frame_type,
            "payload_contract_version": (
                CLEAN_STOP_RESULT_CONTRACT_VERSION
                if frame_type == "clean_stop_result"
                else CLEAN_STOP_ERROR_CONTRACT_VERSION
            ),
            "key_generation": root.transport_key_generation,
            "signing_key_id": root.supervisor_transport_key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": request.to_dict()[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "message_counter": 1,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _terminal_proof(
    root: LifecycleV2Root,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> LifecycleV2AuthenticatedTerminalEnvelopeProof:
    return _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof_for_tests(
        envelope,
        root=root,
    )


def _publication_receipt_value(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    *,
    publication_authorized_boottime_ns: int,
) -> dict[str, object]:
    kind = "result" if envelope.frame_type == "clean_stop_result" else "error"
    file_name = f"trusted-time-post-enrollment-graceful-stop-v2-wire-{kind}-{envelope.sha256}.json"
    return {
        "contract_version": WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
        "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
        "status": "wire_envelope_published",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "artifact_kind": f"signed_{kind}_envelope",
        "artifact_directory_path": "/injected/adr0121/trusted-time",
        "artifact_directory_device": 1,
        "artifact_directory_inode": 2,
        "artifact_path": f"/injected/adr0121/trusted-time/{file_name}",
        "file_name": file_name,
        "file_device": 1,
        "file_inode": 3,
        "file_mode": 384,
        "file_size": len(envelope.encoded),
        "signed_envelope_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": envelope.frame_type,
        "payload_contract_version": envelope.to_dict()["payload_contract_version"],
        "payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "signature_sha256": envelope.signature_sha256,
        "key_generation": 1,
        "signing_key_id": "supervisor-key-1",
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": request.to_dict()["lifecycle_dispatch_prefix_sha256"],
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "directory_fsync_completed": True,
        "stable_readback_completed": True,
        "publication_authorized_boottime_ns": publication_authorized_boottime_ns,
    }


def test_complete_clean_stop_result_and_error_codecs_bind_exact_request() -> None:
    root, request, result = _result()
    assert decode_lifecycle_v2_clean_stop_result(result.encoded) == result
    result_envelope = _envelope(
        root,
        request,
        frame_type="clean_stop_result",
        payload=result.encoded,
    )
    assert validate_terminal_envelope_payload(result_envelope, request=request) == result

    root, request, error = _error()
    assert decode_lifecycle_v2_clean_stop_error(error.encoded, request=request) == error
    error_envelope = _envelope(
        root,
        request,
        frame_type="clean_stop_error",
        payload=error.encoded,
    )
    assert validate_terminal_envelope_payload(error_envelope, request=request) == error


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("request_sha256",), "0" * 64),
        (("channel_id",), "0" * 64),
        (("result_completed_boottime_ns",), 1_000_000_000 + 120_000_000_000),
        (("terminal_projection", "clean_stop_terminal_result_semantic_sha256"), "0" * 64),
        (("supervisor_transport_cleanup_commitment", "listener_path"), "/tmp/fake.sock"),
    ],
)
def test_clean_stop_result_rejects_correlation_semantic_deadline_and_nested_tamper(
    path: tuple[str, ...],
    replacement: object,
) -> None:
    _, _, result = _result()
    value = result.to_dict()
    target = value
    for name in path[:-1]:
        target = target[name]  # type: ignore[assignment]
    target[path[-1]] = replacement
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2CleanStopResult.capture(value)


def test_clean_stop_error_is_nonretryable_request_bound_and_deadline_bounded() -> None:
    _, request, error = _error()
    for name, replacement in (
        ("retryable", True),
        ("error_code", "unknown_failure"),
        ("failure_boundary", "after_success"),
        ("request_sha256", "0" * 64),
        ("observed_boottime_ns", request.to_dict()["operation_deadline_boottime_ns"]),
    ):
        value = error.to_dict()
        value[name] = replacement
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2CleanStopError.capture(value, request=request)


def test_wire_publication_receipt_binds_full_envelope_name_path_signature_and_cutoff() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    proof = _terminal_proof(root, envelope)
    file_name = f"trusted-time-post-enrollment-graceful-stop-v2-wire-result-{envelope.sha256}.json"
    receipt = LifecycleV2WirePublicationReceipt.capture(
        {
            "contract_version": WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
            "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
            "status": "wire_envelope_published",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "artifact_kind": "signed_result_envelope",
            "artifact_directory_path": "/injected/adr0121/trusted-time",
            "artifact_directory_device": 1,
            "artifact_directory_inode": 2,
            "artifact_path": f"/injected/adr0121/trusted-time/{file_name}",
            "file_name": file_name,
            "file_device": 1,
            "file_inode": 3,
            "file_mode": 384,
            "file_size": len(envelope.encoded),
            "signed_envelope_sha256": envelope.sha256,
            "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "frame_type": "clean_stop_result",
            "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
            "signature_sha256": envelope.signature_sha256,
            "key_generation": 1,
            "signing_key_id": "supervisor-key-1",
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": request.to_dict()[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "message_counter": 1,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "directory_fsync_completed": True,
            "stable_readback_completed": True,
            "publication_authorized_boottime_ns": (root.clean_stop_result_deadline_boottime_ns - 1),
        },
        proof=proof,
        request=request,
        root=root,
    )
    assert receipt.to_dict()["signed_envelope_sha256"] == envelope.sha256
    for name, replacement in (
        ("artifact_path", "/injected/adr0121/trusted-time/result.json"),
        ("file_size", len(envelope.encoded) - 1),
        ("signature_sha256", "0" * 64),
        ("publication_authorized_boottime_ns", root.clean_stop_result_deadline_boottime_ns),
        ("directory_fsync_completed", False),
    ):
        value = receipt.to_dict()
        value[name] = replacement
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2WirePublicationReceipt.capture(
                value,
                proof=proof,
                request=request,
                root=root,
            )


def test_typed_ordinal_two_evidence_binds_payload_receipt_and_all_wire_digests() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    proof = _terminal_proof(root, envelope)
    file_name = f"trusted-time-post-enrollment-graceful-stop-v2-wire-result-{envelope.sha256}.json"
    receipt = LifecycleV2WirePublicationReceipt.capture(
        {
            "contract_version": WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
            "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
            "status": "wire_envelope_published",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "artifact_kind": "signed_result_envelope",
            "artifact_directory_path": "/injected/adr0121/trusted-time",
            "artifact_directory_device": 1,
            "artifact_directory_inode": 2,
            "artifact_path": f"/injected/adr0121/trusted-time/{file_name}",
            "file_name": file_name,
            "file_device": 1,
            "file_inode": 3,
            "file_mode": 384,
            "file_size": len(envelope.encoded),
            "signed_envelope_sha256": envelope.sha256,
            "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "frame_type": "clean_stop_result",
            "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
            "signature_sha256": envelope.signature_sha256,
            "key_generation": 1,
            "signing_key_id": "supervisor-key-1",
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": request.to_dict()[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "message_counter": 1,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "directory_fsync_completed": True,
            "stable_readback_completed": True,
            "publication_authorized_boottime_ns": root.admission_started_boottime_ns + 3,
        },
        proof=proof,
        request=request,
        root=root,
    )
    value = {
        "intent_sha256": request.to_dict()["request_intent_sha256"],
        "responder_identity_sha256": root.supervisor_process_epoch_sha256,
        "disposition": "authenticated_result",
        "clean_stop_result_artifact_path": receipt.to_dict()["artifact_path"],
        "clean_stop_result_artifact_name": file_name,
        "clean_stop_result_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": "clean_stop_result",
        "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
        "clean_stop_result_payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "clean_stop_result_signature_sha256": envelope.signature_sha256,
        "terminal_projection_sha256": result.terminal_projection.sha256,
        "key_generation": 1,
        "signing_key_id": "supervisor-key-1",
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": request.to_dict()["lifecycle_dispatch_prefix_sha256"],
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "wire_publication_receipt": receipt.to_dict(),
        "wire_publication_receipt_sha256": receipt.sha256,
        "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
        "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
    }
    evidence = LifecycleV2TerminalWireEvidence.capture(
        value,
        proof=proof,
        request=request,
        root=root,
        responder_identity_sha256=root.supervisor_process_epoch_sha256,
    )
    assert evidence.receipt == receipt
    for name in (
        "clean_stop_result_sha256",
        "clean_stop_result_payload_sha256",
        "clean_stop_result_signature_sha256",
        "wire_publication_receipt_sha256",
    ):
        tampered = evidence.to_dict()
        tampered[name] = "0" * 64
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2TerminalWireEvidence.capture(
                tampered,
                proof=proof,
                request=request,
                root=root,
                responder_identity_sha256=root.supervisor_process_epoch_sha256,
            )


def test_typed_ordinal_two_error_evidence_binds_signed_diagnostic() -> None:
    root, request, error = _error()
    envelope = _envelope(root, request, frame_type="clean_stop_error", payload=error.encoded)
    proof = _terminal_proof(root, envelope)
    receipt = LifecycleV2WirePublicationReceipt.capture(
        _publication_receipt_value(
            root,
            request,
            envelope,
            publication_authorized_boottime_ns=root.admission_started_boottime_ns + 3,
        ),
        proof=proof,
        request=request,
        root=root,
    )
    value = {
        "intent_sha256": request.to_dict()["request_intent_sha256"],
        "responder_identity_sha256": root.supervisor_process_epoch_sha256,
        "disposition": "authenticated_error",
        "clean_stop_error_artifact_path": receipt.to_dict()["artifact_path"],
        "clean_stop_error_artifact_name": receipt.to_dict()["file_name"],
        "clean_stop_error_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": "clean_stop_error",
        "payload_contract_version": CLEAN_STOP_ERROR_CONTRACT_VERSION,
        "clean_stop_error_payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "clean_stop_error_signature_sha256": envelope.signature_sha256,
        "key_generation": 1,
        "signing_key_id": "supervisor-key-1",
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": request.to_dict()["lifecycle_dispatch_prefix_sha256"],
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "wire_publication_receipt": receipt.to_dict(),
        "wire_publication_receipt_sha256": receipt.sha256,
        "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
        "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
        "error_code": "clean_stop_failed",
        "failure_boundary": "during_or_after_selection",
    }
    evidence = LifecycleV2TerminalWireEvidence.capture(
        value,
        proof=proof,
        request=request,
        root=root,
        responder_identity_sha256=root.supervisor_process_epoch_sha256,
    )
    assert evidence.to_dict()["disposition"] == "authenticated_error"
    tampered = evidence.to_dict()
    tampered["error_code"] = "worker_busy"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2TerminalWireEvidence.capture(
            tampered,
            proof=proof,
            request=request,
            root=root,
            responder_identity_sha256=root.supervisor_process_epoch_sha256,
        )


def test_docker_and_terminal_modules_remain_non_authoritative_and_transport_free() -> None:
    assert not any(docker_evidence_non_authority_facts().values())
    assert not any(terminal_non_authority_facts().values())
    assert not any(fake_docker_non_authority_facts().values())
    assert not hasattr(FakeDockerHttpAdapter, "request")
    assert not hasattr(FakeDockerHttpAdapter, "delete_volume")
    assert not hasattr(FakeDockerHttpAdapter, "retry")
    for relative in (
        "packages/domain/trusted_time_graceful_stop_v2_docker.py",
        "packages/domain/trusted_time_graceful_stop_v2_terminal.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        admitted_provenance_read = (
            'with open(adapter_source, "rb") as adapter_source_file:'
        )
        expected_provenance_reads = 1 if relative.endswith("_terminal.py") else 0
        assert source.count(admitted_provenance_read) == expected_provenance_reads
        source_without_admitted_read = source.replace(admitted_provenance_read, "")
        assert "import socket" not in source
        assert "import httpx" not in source
        assert "import requests" not in source
        assert "import docker" not in source
        assert "import subprocess" not in source
        assert "open(" not in source_without_admitted_read
