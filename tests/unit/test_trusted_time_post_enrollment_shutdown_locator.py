from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_shutdown_locator as locator_module
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from scripts import (
    trusted_time_post_enrollment_active_controller_admission as active_controller_admission,
)
from scripts import trusted_time_post_enrollment_controller_outcome as controller_outcome
from scripts import trusted_time_post_enrollment_execution_admission as execution_admission
from scripts import trusted_time_post_enrollment_persistent_topology as persistent_topology
from scripts.start_trusted_time_supervisor import (
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
)
from scripts.trusted_time_post_enrollment_topology import (
    post_enrollment_created_topology_network_name,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_persistent_topology as persistent_fx


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fx._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _locator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocator,
    object,
]:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    topology = persistent_fx._validate(inputs)
    admission = cast(
        TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    locator = locator_module.build_post_enrollment_graceful_stop_shutdown_locator(
        admission=admission,
        persistent_topology=topology,
        persistent_topology_transcript_sha256="d" * 64,
    )
    return locator, topology


def test_shutdown_locator_round_trips_complete_canonical_topology(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, topology = _locator(monkeypatch, tmp_path)

    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    decoded = locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(encoded)
    payload = decoded.payload()

    assert decoded == locator
    assert decoded.persistent_topology == cast(Any, topology).payload()
    assert payload["persistent_topology"] == cast(Any, topology).payload()
    assert payload["persistent_topology_sha256"] == cast(Any, topology).snapshot_sha256
    assert payload["persistent_topology_transcript_sha256"] == "d" * 64
    assert payload["network_name"] == post_enrollment_created_topology_network_name(
        locator.active_controller_session_sha256
    )
    assert payload["socket_volume_name"] == COMPOSE_SOCKET_VOLUME_NAME
    assert payload["state_volume_name"] == COMPOSE_STATE_VOLUME_NAME
    assert payload["status"] == "durable_shutdown_locator_unqualified"
    assert hashlib.sha256(encoded).hexdigest() == (
        locator_module.post_enrollment_graceful_stop_shutdown_locator_sha256(locator)
    )
    assert len(encoded) <= (
        locator_module.POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES
    )
    assert locator_module._MAXIMUM_PERSISTENT_TOPOLOGY_BYTES == 64 * 1_024
    assert locator_module.POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES == 64 * 1_024

    closed = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | set(locator_module._CLOSED_FIELDS)
    assert all(payload[field_name] is False for field_name in closed)
    assert decoded.shutdown_authorized is False
    assert decoded.retry_authorized is False
    assert decoded.teardown_authorized is False
    assert decoded.volume_removal_authorized is False


def test_shutdown_locator_authority_projections_are_exact_builtin_tuples(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    projection = locator_module._shutdown_locator_projection_from_encoded(encoded)

    assert type(projection) is tuple
    assert tuple.__getitem__(projection, 0) == "trusted-time-shutdown-locator-projection-v1"
    assert not hasattr(projection, "_fields")

    class HeapTuple(tuple[object, ...]):
        pass

    forged = HeapTuple(projection)
    for malformed in (
        cast(Any, forged),
        ("wrong-shutdown-locator-tag", *projection[1:]),
        projection[:-1],
    ):
        with pytest.raises(locator_module._InvalidLocator):
            locator_module._shutdown_locator_slot(
                malformed,
                8,
            )


def test_shutdown_locator_authority_uses_literal_tuple_slots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    expected = locator_module._shutdown_locator_projection_from_encoded(encoded)

    index_names = tuple(
        name
        for name in vars(locator_module)
        if name.startswith(("_CONTAINER_", "_TOPOLOGY_", "_LOCATOR_"))
        and type(getattr(locator_module, name)) is int
    )
    assert not index_names

    assert locator_module._shutdown_locator_projection_from_encoded(encoded) == expected


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("active_controller_session_sha256",), "e" * 64),
        (("network_name",), "autoquanttrader-trusted-time-post-enrollment-" + "e" * 64),
        (("socket_volume_name",), "other-socket-volume"),
        (("state_volume_name",), "other-state-volume"),
        (("persistent_topology_sha256",), "e" * 64),
        (("persistent_topology_transcript_sha256",), "not-a-digest"),
        (("shutdown_authorized",), True),
        (("persistent_topology", "network_id"), "e" * 64),
        (("persistent_topology", "source_container", "service"), "trusted-time-supervisor"),
        (("persistent_topology", "volume_identities", "state_sha256"), None),
    ],
)
def test_shutdown_locator_rejects_mutated_locator_or_nested_topology(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    payload = deepcopy(locator.payload())
    cursor = payload
    for part in path[:-1]:
        cursor = cast(dict[str, object], cursor[part])
    cursor[path[-1]] = replacement

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(
            canonical_first_enrollment_json_bytes(payload)
        )


@pytest.mark.parametrize("duplicate_scope", ["top_level", "nested"])
def test_shutdown_locator_rejects_duplicate_json_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    duplicate_scope: str,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    if duplicate_scope == "top_level":
        mutated = b'{"contract_version":"duplicate",' + encoded[1:]
    else:
        marker = b'"daemon_identity":{'
        assert marker in encoded
        mutated = encoded.replace(
            marker,
            marker + b'"context_name":"duplicate",',
            1,
        )

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(mutated)


@pytest.mark.parametrize(
    ("scope", "field_name"),
    [
        ("approved_launch", "git_revision"),
        ("daemon_identity", "context_name"),
        ("source_container", "service"),
    ],
)
def test_shutdown_locator_rejects_nested_duplicates_without_mutable_hook_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scope: str,
    field_name: str,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    topology = cast(dict[str, object], locator.payload()["persistent_topology"])
    nested = cast(dict[str, object], topology[scope])
    marker = f'"{scope}":{{'.encode()
    duplicate = (
        f'"{field_name}":'.encode()
        + json.dumps(nested[field_name], ensure_ascii=True, separators=(",", ":")).encode()
        + b","
    )
    mutated = encoded.replace(marker, marker + duplicate, 1)
    assert mutated != encoded

    monkeypatch.setattr(
        locator_module,
        "_unique_json_object",
        lambda pairs: locator_module._new_canonical_json_object(tuple(pairs)),
    )
    monkeypatch.setattr(locator_module, "_require_bounded_json_tree", lambda _root: None)

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(mutated)


@pytest.mark.parametrize(
    "invalid_json_value",
    [
        b"1.5",
        b"NaN",
        b"1" + b"0" * 80,
        b"[" * 18 + b"null" + b"]" * 18,
        b"[" + b",".join([b"null"] * 1_025) + b"]",
    ],
    ids=["float", "nan", "huge_integer", "depth", "node_count"],
)
def test_shutdown_locator_rejects_unbounded_or_noninteger_json_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    invalid_json_value: bytes,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    marker = b'"shutdown_authorized":false'
    assert marker in encoded
    mutated = encoded.replace(
        marker,
        b'"shutdown_authorized":' + invalid_json_value,
        1,
    )

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(mutated)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda encoded: encoded.removesuffix(b"\n"),
        lambda encoded: b" " + encoded,
        lambda encoded: encoded.replace(b'"network_name":', b'"network_name" :', 1),
        lambda _encoded: (
            b"x" * (locator_module.POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES + 1)
        ),
    ],
)
def test_shutdown_locator_rejects_noncanonical_or_oversized_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: Any,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(mutation(encoded))


def test_shutdown_locator_accepts_maximum_astral_daemon_endpoint_within_64_kib_caps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    payload = deepcopy(locator.payload())
    topology = cast(dict[str, object], payload["persistent_topology"])
    daemon = cast(dict[str, object], topology["daemon_identity"])
    endpoint_prefix = "unix:///"
    endpoint = endpoint_prefix + chr(0x1F600) * (4_096 - len(endpoint_prefix))
    daemon["endpoint"] = endpoint
    topology_encoded = canonical_first_enrollment_json_bytes(topology)
    payload["persistent_topology_sha256"] = hashlib.sha256(topology_encoded).hexdigest()
    encoded = canonical_first_enrollment_json_bytes(payload)

    decoded = locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(encoded)

    assert len(endpoint) == 4_096
    assert len(topology_encoded) > 16 * 1_024
    assert len(topology_encoded) <= locator_module._MAXIMUM_PERSISTENT_TOPOLOGY_BYTES
    assert len(encoded) > 16 * 1_024
    assert len(encoded) <= (
        locator_module.POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES
    )
    decoded_daemon = cast(dict[str, object], decoded.persistent_topology["daemon_identity"])
    assert decoded_daemon["endpoint"] == endpoint


def test_shutdown_locator_payload_returns_isolated_nested_topology(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded_before = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(
        locator
    )
    payload = locator.payload()
    topology = cast(dict[str, object], payload["persistent_topology"])
    topology["network_id"] = "e" * 64

    isolated = locator.payload()

    assert cast(dict[str, object], isolated["persistent_topology"])["network_id"] != ("e" * 64)
    assert (
        locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
        == encoded_before
    )


def test_shutdown_locator_detects_frozen_instance_tampering_on_next_public_method(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    object.__setattr__(locator, "persistent_topology_transcript_sha256", "invalid")

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["post_init", "canonicalizer", "decoder"])
def test_shutdown_locator_preserves_async_interruption_at_nested_codec_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interruption: type[BaseException],
    boundary: str,
) -> None:
    locator, _ = _locator(monkeypatch, tmp_path)
    encoded = locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise interruption

    if boundary == "post_init":
        monkeypatch.setattr(
            locator_module,
            "_persistent_topology_from_encoded",
            interrupt,
        )
    elif boundary == "canonicalizer":
        monkeypatch.setattr(
            locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocator,
            "payload",
            interrupt,
        )
    else:
        monkeypatch.setattr(
            locator_module,
            "TrustedTimePostEnrollmentGracefulStopShutdownLocator",
            interrupt,
        )

    with pytest.raises(interruption):
        if boundary == "post_init":
            locator.__post_init__()
        elif boundary == "canonicalizer":
            locator_module.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
        else:
            locator_module.decode_post_enrollment_graceful_stop_shutdown_locator(encoded)


def test_shutdown_locator_closes_exact_source_and_locator_specific_authority_set() -> None:
    def authority_fields(values: object) -> set[str]:
        return {
            field_name
            for field_name in cast(Any, values)
            if field_name.endswith("_authorized")
            or field_name
            in {
                "authority_granted",
                "database_secret_disclosed",
                "qualified",
            }
        }

    locator_specific_authority_fields = {
        "clean_stop_authorized",
        "container_removal_authorized",
        "network_removal_authorized",
        "source_stop_authorized",
        "supervisor_signal_authorized",
        "supervisor_stop_authorized",
        "teardown_authorized",
        "volume_removal_authorized",
    }
    source_fields = authority_fields(
        {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            *execution_admission._CLOSED_EXECUTION_FIELDS,
            *active_controller_admission._CLOSED_ADMISSION_FIELDS,
            *persistent_topology._CLOSED_FIELDS,
            *controller_outcome._CLOSED_FIELDS,
        }
    )
    execution_admission_properties = authority_fields(
        {
            field_name
            for field_name, value in vars(
                execution_admission.TrustedTimePostEnrollmentExecutionAdmission
            ).items()
            if isinstance(value, property)
        }
    )
    expected = source_fields | execution_admission_properties | locator_specific_authority_fields
    first_enrollment_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    locator_closed_fields = set(locator_module._CLOSED_FIELDS)

    assert first_enrollment_fields.isdisjoint(locator_closed_fields)
    assert first_enrollment_fields | locator_closed_fields == expected
    assert locator_closed_fields == expected - first_enrollment_fields


def test_shutdown_locator_builder_rejects_unbound_transcript(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)

    with pytest.raises(locator_module.TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected):
        locator_module.build_post_enrollment_graceful_stop_shutdown_locator(
            admission=cast(Any, inputs["admission"]),
            persistent_topology=persistent_fx._validate(inputs),
            persistent_topology_transcript_sha256="invalid",
        )


def test_shutdown_locator_module_has_no_cli_or_effecting_import_surface() -> None:
    source = Path(locator_module.__file__).read_text(encoding="utf-8")

    assert "def main(" not in source
    assert "if __name__" not in source
    assert "subprocess" not in source
    assert "sqlalchemy" not in source
    assert "alpaca" not in source.lower()
    assert "requests" not in source
    assert "httpx" not in source
    assert "time." not in source
