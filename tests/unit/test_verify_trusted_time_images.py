from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from scripts.verify_trusted_time_images import (
    AUTHORITY_SHA256,
    CONFIG_SHA256,
    DATABASE_CA_SHA256,
    EXPECTED_CATALOG_RELATIONS,
    EXPECTED_SCHEMA_REVISION,
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    SOURCE_IMAGE,
    SUPERVISOR_APPLICATION_PYTHON,
    SUPERVISOR_IMAGE,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
    _probe_runtime_topology,
    build_and_verify_images,
    build_trusted_time_images,
    load_image_admission_artifact,
    resolve_image_id,
    reviewed_input_bindings,
    validate_ca_trust_store,
    validate_chronyc_version,
    validate_chronyd_version,
    validate_config_hashes,
    validate_database_ca_metadata,
    validate_operational_schema_contract,
    validate_secretless_supervisor,
    validate_source_inspection,
    validate_static_chronyc,
    validate_supervisor_inspection,
    write_image_admission_artifact,
)

SOURCE_ID = "sha256:" + "1" * 64
SUPERVISOR_ID = "sha256:" + "2" * 64


def _write_admission(tmp_path: Path) -> tuple[Path, Path, int]:
    ignored_root = tmp_path / "artifacts"
    path = ignored_root / "trusted-time" / "image-admission.json"
    created_monotonic_ns = 10_000_000_000
    write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=SOURCE_ID,
            supervisor_id=SUPERVISOR_ID,
        ),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
        monotonic_ns=created_monotonic_ns,
    )
    return path, ignored_root, created_monotonic_ns


def _source_inspection() -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "User": "10001:10001",
                "Entrypoint": ["/usr/sbin/chronyd"],
                "Cmd": [
                    "-x",
                    "-d",
                    "-U",
                    "-f",
                    "/etc/autoquant/trusted-time/chrony.conf",
                ],
                "ExposedPorts": None,
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"],
            }
        }
    ]


def _supervisor_inspection() -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "User": "10001:10001",
                "Entrypoint": None,
                "Cmd": ["autoquant-trusted-time-supervisor"],
                "ExposedPorts": None,
                "Env": [
                    "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin",
                    "PYTHONDONTWRITEBYTECODE=1",
                ],
            }
        }
    ]


def test_image_inspections_accept_exact_nonroot_outbound_only_contract() -> None:
    validate_source_inspection(_source_inspection())
    validate_supervisor_inspection(_supervisor_inspection())


@pytest.mark.parametrize(
    ("source", "field_name", "value"),
    [
        (True, "User", "0:0"),
        (True, "Entrypoint", ["/bin/sh"]),
        (True, "Cmd", ["-d"]),
        (True, "ExposedPorts", {"123/udp": {}}),
        (False, "User", "root"),
        (False, "Cmd", ["autoquant-trader"]),
        (False, "ExposedPorts", {"8000/tcp": {}}),
    ],
)
def test_image_inspections_reject_identity_command_or_port_drift(
    source: bool,
    field_name: str,
    value: object,
) -> None:
    inspection = _source_inspection() if source else _supervisor_inspection()
    configuration = cast(dict[str, object], inspection[0]["Config"])
    configuration[field_name] = value

    with pytest.raises(TrustedTimeImageVerificationError):
        if source:
            validate_source_inspection(inspection)
        else:
            validate_supervisor_inspection(inspection)


@pytest.mark.parametrize(
    "environment_entry",
    [
        "AQT_DATABASE_URL=secret",
        "AQT_TRUSTED_TIME_DATABASE_URL_FILE=/secret",
        "ALPACA_PAPER_API_SECRET=secret",
        "SENTRY_DSN=secret",
    ],
)
def test_image_inspection_rejects_embedded_secret_material(
    environment_entry: str,
) -> None:
    inspection = _supervisor_inspection()
    configuration = cast(dict[str, object], inspection[0]["Config"])
    environment = cast(list[str], configuration["Env"])
    environment.append(environment_entry)

    with pytest.raises(TrustedTimeImageVerificationError, match="secret"):
        validate_supervisor_inspection(inspection)


def test_runtime_versions_require_exact_chrony_48_and_source_nts_feature() -> None:
    validate_chronyd_version(
        0,
        "chronyd (chrony) version 4.8 (+CMDMON +NTP +NTS +PRIVDROP)\n",
        "",
    )
    validate_chronyc_version(0, "chronyc (chrony) version 4.8 (-READLINE)\n", "")

    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(0, "chronyd (chrony) version 4.8 (+NTP)\n", "")
    with pytest.raises(TrustedTimeImageVerificationError, match=r"version 4\.8"):
        validate_chronyc_version(0, "chronyc (chrony) version 4.9\n", "")
    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(
            0,
            "prefix chronyd (chrony) version 4.8 (+NTP +NTS)\n",
            "",
        )
    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(0, "chronyd (chrony) version 4.8 (+NTP -NTS)\n", "")


def test_static_client_and_ca_store_probes_require_quiet_success() -> None:
    validate_static_chronyc(0, "", "")
    validate_ca_trust_store(0, "", "")

    with pytest.raises(TrustedTimeImageVerificationError, match="dynamic ELF"):
        validate_static_chronyc(1, "", "")
    with pytest.raises(TrustedTimeImageVerificationError, match="CA trust store"):
        validate_ca_trust_store(0, "unexpected", "")


def test_pinned_database_ca_requires_exact_root_owned_read_only_metadata() -> None:
    validate_database_ca_metadata(0, "0:0:444\n", "")

    for output in ("10001:0:444\n", "0:0:644\n", "0:0:444"):
        with pytest.raises(TrustedTimeImageVerificationError, match="metadata drifted"):
            validate_database_ca_metadata(0, output, "")


def test_supervisor_schema_probe_requires_exact_0036_head_and_anchor_relations() -> None:
    assert SUPERVISOR_APPLICATION_PYTHON == "/opt/venv/bin/python"
    exact = json.dumps(
        {
            "catalog_relations": list(EXPECTED_CATALOG_RELATIONS),
            "schema_revision": EXPECTED_SCHEMA_REVISION,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    validate_operational_schema_contract(0, f"{exact}\n", "")

    for changed in (
        exact.replace(EXPECTED_SCHEMA_REVISION, "0035_phase6_time_uncertainty"),
        exact.replace(f',"{EXPECTED_CATALOG_RELATIONS[1]}"', ""),
        exact.replace("]", ',"phase6_trusted_time_head_anchor_extra"]'),
    ):
        with pytest.raises(TrustedTimeImageVerificationError, match="schema contract"):
            validate_operational_schema_contract(0, f"{changed}\n", "")


def test_image_hash_output_binds_config_authority_and_database_ca_bytes() -> None:
    source_output = f"{CONFIG_SHA256}  /etc/autoquant/trusted-time/chrony.conf\n"
    supervisor_output = source_output + (
        f"{AUTHORITY_SHA256}  /etc/autoquant/trusted-time/source-authority.json\n"
        f"{DATABASE_CA_SHA256}  "
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt\n"
    )

    validate_config_hashes(
        source_output=source_output,
        supervisor_output=supervisor_output,
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="bytes drifted"):
        validate_config_hashes(
            source_output=source_output,
            supervisor_output=supervisor_output.replace(AUTHORITY_SHA256, "0" * 64),
        )

    with pytest.raises(TrustedTimeImageVerificationError, match="bytes drifted"):
        validate_config_hashes(
            source_output=source_output,
            supervisor_output=supervisor_output.replace(DATABASE_CA_SHA256, "0" * 64),
        )


def test_secretless_supervisor_requires_exact_sanitized_blocked_payload() -> None:
    payload = {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "reason": "configuration_rejected",
        "service": "trusted-time-supervisor",
        "status": "fatal",
    }

    validate_secretless_supervisor(2, json.dumps(payload), "")

    payload["readiness_authorized"] = True
    with pytest.raises(TrustedTimeImageVerificationError, match="blocked contract"):
        validate_secretless_supervisor(2, json.dumps(payload), "")
    with pytest.raises(TrustedTimeImageVerificationError, match="quietly"):
        validate_secretless_supervisor(2, "{}", "secret detail")


def test_image_identity_resolution_requires_one_exact_sha256_id() -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "image", "inspect"],
        0,
        f"{SOURCE_ID}\n",
        "",
    )
    with patch("scripts.verify_trusted_time_images._docker", return_value=completed):
        assert resolve_image_id(SOURCE_IMAGE) == SOURCE_ID

    malformed = subprocess.CompletedProcess(
        ["docker", "image", "inspect"],
        0,
        f"{SOURCE_ID}\n{SUPERVISOR_ID}\n",
        "",
    )
    with (
        patch("scripts.verify_trusted_time_images._docker", return_value=malformed),
        pytest.raises(TrustedTimeImageVerificationError, match="one immutable"),
    ):
        resolve_image_id(SOURCE_IMAGE)

    with pytest.raises(TrustedTimeImageVerificationError, match="identities are malformed"):
        TrustedTimeImageIdentities(source_id=SOURCE_ID, supervisor_id=SOURCE_ID)


def test_build_uses_fixed_tags_without_forwarding_database_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AQT_TRUSTED_TIME_DATABASE_URL", "must-not-be-forwarded")
    observed: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = cast(dict[str, str], kwargs["env"])
        observed.append((argv, environment))
        return subprocess.CompletedProcess(argv, 0, "", "")

    with patch("scripts.verify_trusted_time_images.subprocess.run", side_effect=fake_run):
        build_trusted_time_images()

    argv, environment = observed[0]
    assert argv[-1] == "build"
    assert environment["AQT_TRUSTED_TIME_SOURCE_IMAGE"] == SOURCE_IMAGE
    assert environment["AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"] == SUPERVISOR_IMAGE
    assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment


def test_build_workflow_admits_compose_before_any_image_build() -> None:
    events: list[str] = []
    bindings = reviewed_input_bindings()
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )

    def verified_images() -> TrustedTimeImageIdentities:
        events.append("images-verified")
        return identities

    with (
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ),
        patch(
            "scripts.verify_trusted_time_images.validate_prebuild_compose_contract",
            side_effect=lambda: events.append("compose-admitted"),
        ),
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            side_effect=lambda: events.append("images-built"),
        ),
        patch(
            "scripts.verify_trusted_time_images.verify_images",
            side_effect=verified_images,
        ),
    ):
        assert build_and_verify_images() == identities

    assert events == ["compose-admitted", "images-built", "images-verified"]


def test_atomic_image_admission_is_canonical_owner_only_and_source_bound(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    admission = load_image_admission_artifact(
        path,
        ignored_root=ignored_root,
        monotonic_ns=created + 1,
    )
    encoded = path.read_bytes()
    payload = json.loads(encoded)

    assert admission.identities == TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    assert admission.artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    archive = path.with_name(f"image-admission-{admission.artifact_sha256}.json")
    assert (
        encoded
        == json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert archive.read_bytes() == encoded
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert archive.stat().st_nlink == 1
    assert stat.S_IMODE(ignored_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert payload["inputs"]["source_revision_sha256"] == (
        reviewed_input_bindings().source_revision_sha256
    )
    assert payload["inputs"]["schema_revision"] == "0036_phase6_time_anchors"
    assert payload["inputs"]["catalog_relations"] == list(EXPECTED_CATALOG_RELATIONS)
    migration = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "versions"
        / "0036_phase6_trusted_time_head_anchors.py"
    )
    assert (
        payload["inputs"]["migration_sha256"] == hashlib.sha256(migration.read_bytes()).hexdigest()
    )
    assert "password" not in encoded.decode().lower()
    assert not tuple(path.parent.glob(".*.tmp"))


def test_content_addressed_image_admission_archive_is_never_overwritten(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    archive.write_bytes(b"tampered")
    archive.chmod(0o600)

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        write_image_admission_artifact(
            path,
            TrustedTimeImageIdentities(
                source_id=SOURCE_ID,
                supervisor_id=SUPERVISOR_ID,
            ),
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=created,
        )


def test_second_generation_retains_both_exact_admission_artifacts(tmp_path: Path) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    prior = path.read_bytes()
    prior_archive = path.with_name(f"image-admission-{hashlib.sha256(prior).hexdigest()}.json")

    write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=SOURCE_ID,
            supervisor_id=SUPERVISOR_ID,
        ),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
        monotonic_ns=created + 1,
    )
    current = path.read_bytes()
    current_archive = path.with_name(f"image-admission-{hashlib.sha256(current).hexdigest()}.json")

    assert current != prior
    assert prior_archive.read_bytes() == prior
    assert current_archive.read_bytes() == current
    assert stat.S_IMODE(prior_archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(current_archive.stat().st_mode) == 0o600


def test_archive_failure_occurs_before_canonical_replacement(tmp_path: Path) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    prior = path.read_bytes()
    candidate_path = ignored_root / "candidate" / "image-admission.json"
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    write_image_admission_artifact(
        candidate_path,
        identities,
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
        monotonic_ns=created + 1,
    )
    candidate = candidate_path.read_bytes()
    conflicting_archive = path.with_name(
        f"image-admission-{hashlib.sha256(candidate).hexdigest()}.json"
    )
    conflicting_archive.write_bytes(b"tampered")
    conflicting_archive.chmod(0o600)

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        write_image_admission_artifact(
            path,
            identities,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
            monotonic_ns=created + 1,
        )

    assert path.read_bytes() == prior


def test_canonical_loader_requires_its_exact_content_addressed_archive(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    archive.unlink()

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_rejects_stale_clock_regression_and_noncanonical_tampering(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    for observed in (
        created - 1,
        created + (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS + 1) * 1_000_000_000,
    ):
        with pytest.raises(TrustedTimeImageVerificationError, match="stale"):
            load_image_admission_artifact(
                path,
                ignored_root=ignored_root,
                monotonic_ns=observed,
            )

    payload = json.loads(path.read_bytes())
    payload["inputs"]["migration_sha256"] = "0" * 64
    path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    path.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    _write_admission(tmp_path)
    path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    path.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="not canonical"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_rejects_broad_mode_symlink_and_lookalike_path(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    path.chmod(0o644)
    with pytest.raises(TrustedTimeImageVerificationError, match="metadata"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    path.chmod(0o600)
    target = path.with_name("held.json")
    path.replace(target)
    path.symlink_to(target)
    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    lookalike = tmp_path / "lookalike" / "trusted-time" / "image-admission.json"
    lookalike.parent.mkdir(parents=True)
    lookalike.write_bytes(target.read_bytes())
    lookalike.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="path is invalid"):
        load_image_admission_artifact(
            lookalike,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_writer_rejects_symlink_target_and_source_revision_toctou(
    tmp_path: Path,
) -> None:
    path, ignored_root, _ = _write_admission(tmp_path)
    target = path.with_name("held.json")
    path.replace(target)
    path.symlink_to(target)
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    bindings = reviewed_input_bindings()
    with pytest.raises(TrustedTimeImageVerificationError, match="target is invalid"):
        write_image_admission_artifact(
            path,
            identities,
            bindings=bindings,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=1,
        )

    path.unlink()
    changed = replace(bindings, source_revision_sha256="0" * 64)
    with (
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=changed,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="changed during admission"),
    ):
        write_image_admission_artifact(
            path,
            identities,
            bindings=bindings,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=1,
        )


def test_real_topology_probe_uses_one_hardened_shared_socket_and_cleans_up() -> None:
    token = "a" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"
    source_name = f"aqt-trusted-time-admission-{token}-source"
    calls: list[tuple[str, ...]] = []

    def result(arguments: tuple[str, ...], stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["docker", *arguments], 0, stdout, "")

    def fake_docker(*arguments: str, **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:2] == ("volume", "create"):
            return result(arguments, f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, "3" * 64 + "\n")
        if arguments[:2] == ("container", "inspect"):
            inspection = [
                {
                    "Image": SOURCE_ID,
                    "Config": {"User": "10001:10001"},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges"],
                        "Binds": None,
                        "Tmpfs": {
                            "/tmp": (
                                "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"
                            ),
                            "/var/lib/chrony": (
                                "rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"
                            ),
                        },
                        "Mounts": [
                            {
                                "Type": "volume",
                                "Source": volume_name,
                                "Target": "/run/chrony",
                                "VolumeOptions": {"NoCopy": True},
                            }
                        ],
                    },
                    "Mounts": [
                        {
                            "Type": "volume",
                            "Name": volume_name,
                            "Destination": "/run/chrony",
                            "RW": True,
                        }
                    ],
                }
            ]
            return result(arguments, json.dumps(inspection))
        if arguments[:2] == ("container", "exec") and "/bin/stat" in arguments:
            return result(arguments, "10001:10001:750\n")
        if arguments[:2] == ("container", "exec"):
            return result(arguments, "200 OK\n")
        if arguments[:2] == ("run", "--rm"):
            return result(arguments, "200 OK\n")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, f"{source_name}\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
    ):
        _probe_runtime_topology(SOURCE_ID, SUPERVISOR_ID)

    source_run = next(call for call in calls if call[:2] == ("run", "--detach"))
    supervisor_run = next(call for call in calls if call[:2] == ("run", "--rm"))
    assert "none" in source_run and "--read-only" in source_run and "ALL" in source_run
    assert SOURCE_ID in source_run and SUPERVISOR_ID in supervisor_run
    assert any(volume_name in argument for argument in source_run)
    assert any(volume_name in argument for argument in supervisor_run)
    assert calls[-2:] == [
        ("container", "rm", "--force", source_name),
        ("volume", "rm", volume_name),
    ]


def test_partial_source_start_still_attempts_known_name_cleanup() -> None:
    token = "b" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"
    source_name = f"aqt-trusted-time-admission-{token}-source"
    calls: list[tuple[str, ...]] = []

    def result(
        arguments: tuple[str, ...],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", *arguments],
            returncode,
            stdout,
            stderr,
        )

    def fake_docker(*arguments: str, **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, returncode=125, stderr="sanitized start failure")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, stdout=f"{source_name}\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, stdout=f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
        pytest.raises(TrustedTimeImageVerificationError, match="source socket probe"),
    ):
        _probe_runtime_topology(SOURCE_ID, SUPERVISOR_ID)

    assert ("container", "rm", "--force", source_name) in calls
    assert calls[-1] == ("volume", "rm", volume_name)


def test_partial_source_start_surfaces_cleanup_failure_without_resource_detail() -> None:
    token = "c" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"

    def result(
        arguments: tuple[str, ...],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", *arguments],
            returncode,
            stdout,
            stderr,
        )

    def fake_docker(*arguments: str, **_: object) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, returncode=125, stderr="start failure detail")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, returncode=1, stderr="remove failure detail")
        if arguments[:2] == ("container", "ls"):
            return result(arguments, stdout="still-present\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, returncode=1, stderr="volume failure detail")
        if arguments[:2] == ("volume", "ls"):
            return result(arguments, stdout=f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
        pytest.raises(
            TrustedTimeImageVerificationError, match="topology probe cleanup failed"
        ) as error,
    ):
        _probe_runtime_topology(SOURCE_ID, SUPERVISOR_ID)

    assert isinstance(error.value.__cause__, TrustedTimeImageVerificationError)
    assert "start failure detail" not in str(error.value)
    assert "remove failure detail" not in str(error.value)
