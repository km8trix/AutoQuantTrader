from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from apps.trusted_time_supervisor.config import (
    DATABASE_CA_PATH,
    TrustedTimeSupervisorConfigurationError,
    decode_trusted_time_authority,
    load_database_url_secret,
    load_trusted_time_authority,
)

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "infra" / "trusted-time" / "source-authority.json"
CHRONY_CONFIG_PATH = ROOT / "infra" / "trusted-time" / "chrony.conf"
CHECKED_IN_DATABASE_CA_PATH = (
    ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt"
)


def _authority_payload() -> bytes:
    return AUTHORITY_PATH.read_bytes()


def _chrony_payload() -> bytes:
    return CHRONY_CONFIG_PATH.read_bytes()


def _database_ca_payload() -> bytes:
    return CHECKED_IN_DATABASE_CA_PATH.read_bytes()


def test_checked_in_authority_is_exact_and_non_authorizing() -> None:
    authority = decode_trusted_time_authority(
        _authority_payload(),
        chrony_config_payload=_chrony_payload(),
        database_ca_payload=_database_ca_payload(),
    )

    assert authority.source_id == "chrony-nts-cloudflare-system76-virginia-v2"
    assert authority.host_id == "local-paper-docker-primary-v1"
    assert authority.chrony_version == "4.8"
    assert authority.ordered_source_names == (
        "time.cloudflare.com",
        "virginia.time.system76.com",
    )
    assert authority.ordered_ntp_ports == (123, 123)
    assert authority.database_ca_path == DATABASE_CA_PATH
    assert authority.database_ca_sha256 == (
        "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
    )
    assert authority.maximum_reference_age_seconds == 30
    assert authority.probe_deadline_ns == 1_000_000_000
    assert authority.cadence_ns == 20_000_000_000
    assert authority.maximum_gap_ns == 30_000_000_000
    assert not authority.readiness_authorized
    assert not authority.operational_control_authorized
    assert not authority.new_exposure_authorized
    assert not authority.alert_delivery_authorized
    assert not authority.automatic_rearm_authorized
    assert not authority.paper_trading_authorized
    assert not authority.live_trading_authorized


@pytest.mark.parametrize(
    ("section", "field_name", "value"),
    [
        ("root", "host_id", "rotated-host"),
        ("runtime", "clock_adjustment_mode", "normal"),
        ("chrony", "monitoring_udp_port", 323),
        ("database_tls", "sslmode", "require"),
        ("database_tls", "ca_path", "/tmp/substituted-ca.crt"),
        ("admission", "maximum_reference_age_seconds", 31),
        ("supervision", "same_tick_retries", 1),
        ("authority", "readiness", True),
    ],
)
def test_authority_rejects_any_semantic_drift(
    section: str,
    field_name: str,
    value: object,
) -> None:
    payload = json.loads(_authority_payload())
    target = payload if section == "root" else payload[section]
    target[field_name] = value

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="differs from the approved contract",
    ):
        decode_trusted_time_authority(
            json.dumps(payload).encode(),
            chrony_config_payload=_chrony_payload(),
            database_ca_payload=_database_ca_payload(),
        )


def test_authority_rejects_duplicate_fields_and_config_substitution() -> None:
    duplicated = _authority_payload().replace(
        b'{\n  "contract_version":',
        b'{\n  "host_id": "duplicate",\n  "contract_version":',
        1,
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="duplicate field"):
        decode_trusted_time_authority(
            duplicated,
            chrony_config_payload=_chrony_payload(),
            database_ca_payload=_database_ca_payload(),
        )

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="digest differs"):
        decode_trusted_time_authority(
            _authority_payload(),
            chrony_config_payload=_chrony_payload() + b"\n",
            database_ca_payload=_database_ca_payload(),
        )


def test_authority_rejects_database_ca_tamper_and_unavailable_payload() -> None:
    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="database CA digest differs",
    ):
        decode_trusted_time_authority(
            _authority_payload(),
            chrony_config_payload=_chrony_payload(),
            database_ca_payload=_database_ca_payload() + b"\n",
        )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="database CA is unavailable",
    ):
        decode_trusted_time_authority(
            _authority_payload(),
            chrony_config_payload=_chrony_payload(),
            database_ca_payload=b"",
        )


def test_protected_authority_loader_rejects_writable_and_symlinked_inputs(
    tmp_path: Path,
) -> None:
    authority_path = tmp_path / "authority.json"
    config_path = tmp_path / "chrony.conf"
    database_ca_path = tmp_path / "supabase-prod-ca-2021.crt"
    authority_path.write_bytes(_authority_payload())
    config_path.write_bytes(_chrony_payload())
    database_ca_path.write_bytes(_database_ca_payload())
    authority_path.chmod(0o600)
    config_path.chmod(0o600)
    database_ca_path.chmod(0o600)

    authority = load_trusted_time_authority(
        authority_path,
        chrony_config_path=config_path,
        database_ca_path=database_ca_path,
        expected_owner_uid=os.getuid(),
    )
    assert authority.source_authority_sha256

    config_path.chmod(0o622)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="writable"):
        load_trusted_time_authority(
            authority_path,
            chrony_config_path=config_path,
            database_ca_path=database_ca_path,
            expected_owner_uid=os.getuid(),
        )

    config_path.chmod(0o600)
    link_path = tmp_path / "authority-link.json"
    link_path.symlink_to(authority_path)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="unavailable"):
        load_trusted_time_authority(
            link_path,
            chrony_config_path=config_path,
            database_ca_path=database_ca_path,
            expected_owner_uid=os.getuid(),
        )


def test_protected_authority_loader_rejects_database_ca_tamper_and_unsafe_file(
    tmp_path: Path,
) -> None:
    authority_path = tmp_path / "authority.json"
    config_path = tmp_path / "chrony.conf"
    database_ca_path = tmp_path / "database-ca.crt"
    authority_path.write_bytes(_authority_payload())
    config_path.write_bytes(_chrony_payload())
    database_ca_path.write_bytes(_database_ca_payload())
    authority_path.chmod(0o600)
    config_path.chmod(0o600)
    database_ca_path.chmod(0o600)

    database_ca_path.write_bytes(_database_ca_payload() + b"\n")
    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="database CA digest differs",
    ):
        load_trusted_time_authority(
            authority_path,
            chrony_config_path=config_path,
            database_ca_path=database_ca_path,
            expected_owner_uid=os.getuid(),
        )

    database_ca_path.write_bytes(_database_ca_payload())
    database_ca_path.chmod(0o622)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="writable"):
        load_trusted_time_authority(
            authority_path,
            chrony_config_path=config_path,
            database_ca_path=database_ca_path,
            expected_owner_uid=os.getuid(),
        )

    database_ca_path.chmod(0o600)
    database_ca_link = tmp_path / "database-ca-link.crt"
    database_ca_link.symlink_to(database_ca_path)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="unavailable"):
        load_trusted_time_authority(
            authority_path,
            chrony_config_path=config_path,
            database_ca_path=database_ca_link,
            expected_owner_uid=os.getuid(),
        )


def test_database_secret_loader_accepts_only_complete_psycopg_postgres_dsn(
    tmp_path: Path,
) -> None:
    secret_path = tmp_path / "database-url"
    secret_path.write_text(
        "postgresql+psycopg://postgres.abcdefghijklmnopqrst:secret"
        "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full",
        encoding="utf-8",
    )
    secret_path.chmod(0o600)

    database_url = load_database_url_secret(
        secret_path,
        expected_owner_uid=os.getuid(),
    )

    assert database_url.startswith("postgresql+psycopg://")


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite+pysqlite:///:memory:",
        "postgresql://user:secret@db.example.invalid/autoquant",
        "postgresql+psycopg://user@db.example.invalid/autoquant",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=disable",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=allow",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=prefer",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=require",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=verify-ca",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=verify-full&sslmode=require",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant?sslmode=verify-full&application_name=trusted-time",
        " postgresql+psycopg://user:secret@db.example.invalid/autoquant",
        "postgresql+psycopg://user:secret@db.example.invalid/autoquant\n",
    ],
)
def test_database_secret_loader_rejects_unsafe_or_incomplete_values(
    tmp_path: Path,
    database_url: str,
) -> None:
    secret_path = tmp_path / "database-url"
    secret_path.write_text(database_url, encoding="utf-8")
    secret_path.chmod(0o600)

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        load_database_url_secret(
            secret_path,
            expected_owner_uid=os.getuid(),
        )
