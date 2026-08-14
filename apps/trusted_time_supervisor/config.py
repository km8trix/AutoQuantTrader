"""Strict, nonsecret deployment authority and secret-file loading."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import make_url
from sqlalchemy.exc import ArgumentError

from packages.persistence.postgres_tls import is_supabase_session_pooler_url

AUTHORITY_PATH = Path("/etc/autoquant/trusted-time/source-authority.json")
CHRONY_CONFIG_PATH = Path("/etc/autoquant/trusted-time/chrony.conf")
DATABASE_CA_PATH = Path("/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt")
DATABASE_URL_SECRET_PATH = Path("/run/secrets/trusted_time_database_url")
DATABASE_URL_EXPECTED_SHA256_ENVIRONMENT = "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256"
MAXIMUM_AUTHORITY_BYTES = 32_768
MAXIMUM_CHRONY_CONFIG_BYTES = 16_384
MAXIMUM_DATABASE_CA_BYTES = 8_192
MAXIMUM_DATABASE_SECRET_BYTES = 8_192

_EXPECTED_AUTHORITY: dict[str, object] = {
    "contract_version": "phase6c-local-chrony-nts-authority-v2",
    "source_id": "chrony-nts-cloudflare-system76-virginia-v2",
    "host_id": "local-paper-docker-primary-v1",
    "runtime": {
        "base_image": (
            "alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
        ),
        "chrony_version": "4.8",
        "chrony_package": "chrony=4.8-r2",
        "chrony_source_sha256": (
            "33ea8eb2a4daeaa506e8fcafd5d6d89027ed6f2f0609645c6f149b560d301706"
        ),
        "clock_adjustment_mode": "-x",
        "daemon_user": "autoquant",
        "runtime_uid": 10001,
        "runtime_gid": 10001,
        "chronyd_path": "/usr/sbin/chronyd",
        "supervisor_chronyc_path": "/usr/local/bin/chronyc",
    },
    "chrony": {
        "config_path": "/etc/autoquant/trusted-time/chrony.conf",
        "config_sha256": ("5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23"),
        "socket_path": "/run/chrony/chronyd.sock",
        "socket_directory_mode": "0750",
        "socket_volume": "ephemeral_tmpfs_read_write",
        "command_transport": "unix_socket_only",
        "ntp_server_port": 0,
        "monitoring_udp_port": 0,
        "minimum_selectable_sources": 2,
        "minimum_poll_exponent": 4,
        "maximum_poll_exponent": 4,
    },
    "database_tls": {
        "provider": "supabase",
        "sslmode": "verify-full",
        "ca_path": "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
        "ca_sha256": ("700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"),
        "certificate_role": "server_root_ca",
        "not_after_utc": "2031-04-26T10:56:53Z",
    },
    "sources": [
        {
            "name": "time.cloudflare.com",
            "protocol": "nts",
            "nts_ke_port": 4460,
            "ntp_port": 123,
            "required": True,
        },
        {
            "name": "virginia.time.system76.com",
            "protocol": "nts",
            "nts_ke_port": 4460,
            "ntp_port": 123,
            "required": True,
        },
    ],
    "admission": {
        "exact_source_set_required": True,
        "selected_source_count": 1,
        "combined_source_count": 1,
        "authentication_mode": "NTS",
        "allowed_aead_algorithms": [15, 30],
        "authenticated_ntp_packets_required": True,
        "normal_leap_state_required": True,
        "maximum_reference_age_seconds": 30,
        "maximum_source_uncertainty_milliseconds": 100,
        "uncertainty_formula": (
            "root_dispersion_plus_half_absolute_root_delay_plus_inner_half_duration_plus_"
            "cross_clock_projection_plus_microsecond_rounding"
        ),
    },
    "supervision": {
        "startup_probe_required": True,
        "cadence_seconds": 20,
        "probe_deadline_seconds": 1,
        "deadline_clock": "linux_clock_boottime",
        "same_tick_retries": 0,
        "maximum_gap_seconds": 30,
        "database_connect_timeout_seconds": 3,
        "database_statement_timeout_milliseconds": 3000,
        "database_lock_timeout_milliseconds": 1000,
        "failover_enabled": False,
        "epoch_rotation_enabled": False,
    },
    "authority": {
        "readiness": False,
        "operational_control": False,
        "new_exposure": False,
        "alert_delivery": False,
        "automatic_rearm": False,
        "paper_trading": False,
        "live_trading": False,
        "external_head_anchor": False,
    },
}


class TrustedTimeSupervisorConfigurationError(RuntimeError):
    """The deployment authority or database secret failed closed."""


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time authority contains a duplicate field"
            )
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time authority contains unsupported JSON"
        ) from None


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time authority {field_name} is malformed"
        )
    return value


def _text(mapping: Mapping[str, object], field_name: str) -> str:
    value = mapping[field_name]
    if type(value) is not str:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time authority {field_name} is malformed"
        )
    return value


def _integer(mapping: Mapping[str, object], field_name: str) -> int:
    value = mapping[field_name]
    if type(value) is not int:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time authority {field_name} is malformed"
        )
    return value


@dataclass(frozen=True, slots=True)
class TrustedTimeDeploymentAuthority:
    """Exact reviewed source/scheduler identity and its raw content hash."""

    source_authority_sha256: str
    source_id: str
    host_id: str
    chrony_version: str
    chronyc_path: Path
    chrony_socket_path: Path
    database_ca_path: Path
    database_ca_sha256: str
    ordered_source_names: tuple[str, str]
    ordered_ntp_ports: tuple[int, int]
    maximum_reference_age_seconds: int
    maximum_source_uncertainty_milliseconds: Decimal
    probe_deadline_ns: int
    cadence_ns: int
    maximum_gap_ns: int

    def __post_init__(self) -> None:
        if self.source_authority_sha256 != self.source_authority_sha256.lower() or (
            len(self.source_authority_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.source_authority_sha256
            )
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time authority SHA-256 is malformed"
            )
        if self.source_id != "chrony-nts-cloudflare-system76-virginia-v2":
            raise TrustedTimeSupervisorConfigurationError("trusted-time source identity drifted")
        if self.host_id != "local-paper-docker-primary-v1":
            raise TrustedTimeSupervisorConfigurationError("trusted-time host identity drifted")
        if self.chrony_version != "4.8":
            raise TrustedTimeSupervisorConfigurationError("trusted-time Chrony version drifted")
        if self.chronyc_path != Path("/usr/local/bin/chronyc"):
            raise TrustedTimeSupervisorConfigurationError("trusted-time client path drifted")
        if self.chrony_socket_path != Path("/run/chrony/chronyd.sock"):
            raise TrustedTimeSupervisorConfigurationError("trusted-time socket path drifted")
        if self.database_ca_path != DATABASE_CA_PATH:
            raise TrustedTimeSupervisorConfigurationError("trusted-time database CA path drifted")
        if self.database_ca_sha256 != (
            "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
        ):
            raise TrustedTimeSupervisorConfigurationError("trusted-time database CA drifted")
        if self.ordered_source_names != (
            "time.cloudflare.com",
            "virginia.time.system76.com",
        ):
            raise TrustedTimeSupervisorConfigurationError("trusted-time source set drifted")
        if self.ordered_ntp_ports != (123, 123):
            raise TrustedTimeSupervisorConfigurationError("trusted-time NTP port set drifted")
        if self.maximum_reference_age_seconds != 30:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time reference-age policy drifted"
            )
        if self.maximum_source_uncertainty_milliseconds != Decimal("100"):
            raise TrustedTimeSupervisorConfigurationError("trusted-time uncertainty policy drifted")
        if self.probe_deadline_ns != 1_000_000_000:
            raise TrustedTimeSupervisorConfigurationError("trusted-time deadline policy drifted")
        if self.cadence_ns != 20_000_000_000 or self.maximum_gap_ns != 30_000_000_000:
            raise TrustedTimeSupervisorConfigurationError("trusted-time cadence policy drifted")

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def alert_delivery_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def paper_trading_authorized(self) -> bool:
        return False

    @property
    def live_trading_authorized(self) -> bool:
        return False


def decode_trusted_time_authority(
    authority_payload: bytes,
    *,
    chrony_config_payload: bytes,
    database_ca_payload: bytes,
) -> TrustedTimeDeploymentAuthority:
    """Decode only the byte-exact authority, Chrony config, and database CA."""

    if type(authority_payload) is not bytes or not authority_payload:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time authority payload is unavailable"
        )
    if len(authority_payload) > MAXIMUM_AUTHORITY_BYTES:
        raise TrustedTimeSupervisorConfigurationError("trusted-time authority is oversized")
    if type(chrony_config_payload) is not bytes or not chrony_config_payload:
        raise TrustedTimeSupervisorConfigurationError("trusted-time Chrony config is unavailable")
    if len(chrony_config_payload) > MAXIMUM_CHRONY_CONFIG_BYTES:
        raise TrustedTimeSupervisorConfigurationError("trusted-time Chrony config is oversized")
    if type(database_ca_payload) is not bytes or not database_ca_payload:
        raise TrustedTimeSupervisorConfigurationError("trusted-time database CA is unavailable")
    if len(database_ca_payload) > MAXIMUM_DATABASE_CA_BYTES:
        raise TrustedTimeSupervisorConfigurationError("trusted-time database CA is oversized")
    try:
        decoded: Any = json.loads(
            authority_payload.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except TrustedTimeSupervisorConfigurationError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time authority is not strict JSON"
        ) from None
    if type(decoded) is not dict or _canonical_json(decoded) != _canonical_json(
        _EXPECTED_AUTHORITY
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time authority differs from the approved contract"
        )
    root = _mapping(decoded, "root")
    runtime = _mapping(root["runtime"], "runtime")
    chrony = _mapping(root["chrony"], "chrony")
    database_tls = _mapping(root["database_tls"], "database TLS")
    sources = root["sources"]
    admission = _mapping(root["admission"], "admission")
    supervision = _mapping(root["supervision"], "supervision")
    if type(sources) is not list or len(sources) != 2:
        raise TrustedTimeSupervisorConfigurationError("trusted-time source set is malformed")
    source_names = tuple(_text(_mapping(source, "source"), "name") for source in sources)
    source_ports = tuple(_integer(_mapping(source, "source"), "ntp_port") for source in sources)
    config_sha256 = hashlib.sha256(chrony_config_payload).hexdigest()
    if config_sha256 != _text(chrony, "config_sha256"):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Chrony config digest differs from authority"
        )
    database_ca_sha256 = hashlib.sha256(database_ca_payload).hexdigest()
    if database_ca_sha256 != _text(database_tls, "ca_sha256"):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database CA digest differs from authority"
        )
    return TrustedTimeDeploymentAuthority(
        source_authority_sha256=hashlib.sha256(authority_payload).hexdigest(),
        source_id=_text(root, "source_id"),
        host_id=_text(root, "host_id"),
        chrony_version=_text(runtime, "chrony_version"),
        chronyc_path=Path(_text(runtime, "supervisor_chronyc_path")),
        chrony_socket_path=Path(_text(chrony, "socket_path")),
        database_ca_path=Path(_text(database_tls, "ca_path")),
        database_ca_sha256=database_ca_sha256,
        ordered_source_names=(source_names[0], source_names[1]),
        ordered_ntp_ports=(source_ports[0], source_ports[1]),
        maximum_reference_age_seconds=_integer(
            admission,
            "maximum_reference_age_seconds",
        ),
        maximum_source_uncertainty_milliseconds=Decimal(
            _integer(admission, "maximum_source_uncertainty_milliseconds")
        ),
        probe_deadline_ns=_integer(supervision, "probe_deadline_seconds") * 1_000_000_000,
        cadence_ns=_integer(supervision, "cadence_seconds") * 1_000_000_000,
        maximum_gap_ns=_integer(supervision, "maximum_gap_seconds") * 1_000_000_000,
    )


def _read_protected_file(
    path: Path,
    *,
    maximum_bytes: int,
    expected_owner_uid: int,
    label: str,
) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TrustedTimeSupervisorConfigurationError(f"{label} path is invalid")
    if type(expected_owner_uid) is not int or expected_owner_uid < 0:
        raise TrustedTimeSupervisorConfigurationError(f"{label} owner policy is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(f"{label} is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TrustedTimeSupervisorConfigurationError(f"{label} is not a regular file")
        if metadata.st_uid != expected_owner_uid:
            raise TrustedTimeSupervisorConfigurationError(f"{label} owner is invalid")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TrustedTimeSupervisorConfigurationError(f"{label} is writable by another user")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise TrustedTimeSupervisorConfigurationError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes or len(payload) != metadata.st_size:
            raise TrustedTimeSupervisorConfigurationError(f"{label} read is invalid")
        return payload
    finally:
        os.close(descriptor)


def load_trusted_time_authority(
    authority_path: Path = AUTHORITY_PATH,
    *,
    chrony_config_path: Path = CHRONY_CONFIG_PATH,
    database_ca_path: Path = DATABASE_CA_PATH,
    expected_owner_uid: int = 0,
) -> TrustedTimeDeploymentAuthority:
    authority_payload = _read_protected_file(
        authority_path,
        maximum_bytes=MAXIMUM_AUTHORITY_BYTES,
        expected_owner_uid=expected_owner_uid,
        label="trusted-time authority",
    )
    config_payload = _read_protected_file(
        chrony_config_path,
        maximum_bytes=MAXIMUM_CHRONY_CONFIG_BYTES,
        expected_owner_uid=expected_owner_uid,
        label="trusted-time Chrony config",
    )
    database_ca_payload = _read_protected_file(
        database_ca_path,
        maximum_bytes=MAXIMUM_DATABASE_CA_BYTES,
        expected_owner_uid=expected_owner_uid,
        label="trusted-time database CA",
    )
    return decode_trusted_time_authority(
        authority_payload,
        chrony_config_payload=config_payload,
        database_ca_payload=database_ca_payload,
    )


def load_database_url_secret(
    path: Path = DATABASE_URL_SECRET_PATH,
    *,
    expected_owner_uid: int = 10001,
    expected_sha256: str | None = None,
) -> str:
    payload = _read_protected_file(
        path,
        maximum_bytes=MAXIMUM_DATABASE_SECRET_BYTES,
        expected_owner_uid=expected_owner_uid,
        label="trusted-time database secret",
    )
    if expected_sha256 is not None and (
        type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret differs from its staged-input binding"
        )
    try:
        database_url = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret is malformed"
        ) from None
    return validate_database_url(database_url)


def validate_database_url(database_url: str) -> str:
    """Validate a secret DSN without logging or returning parsed credentials."""

    if type(database_url) is not str or (
        not database_url
        or database_url != database_url.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in database_url)
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time database secret is malformed")
    try:
        url = make_url(database_url)
    except ArgumentError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret is malformed"
        ) from None
    if url.get_backend_name() != "postgresql" or url.get_driver_name() != "psycopg":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret must select PostgreSQL with psycopg"
        )
    if not is_supabase_session_pooler_url(url):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret must select the approved Supabase Session pooler"
        )
    if not url.username or not url.password or not url.host or not url.database:
        raise TrustedTimeSupervisorConfigurationError("trusted-time database secret is incomplete")
    if dict(url.query) != {"sslmode": "verify-full"}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database transport must use exact verify-full TLS"
        )
    return database_url


__all__ = [
    "AUTHORITY_PATH",
    "CHRONY_CONFIG_PATH",
    "DATABASE_CA_PATH",
    "DATABASE_URL_EXPECTED_SHA256_ENVIRONMENT",
    "DATABASE_URL_SECRET_PATH",
    "TrustedTimeDeploymentAuthority",
    "TrustedTimeSupervisorConfigurationError",
    "decode_trusted_time_authority",
    "load_database_url_secret",
    "load_trusted_time_authority",
    "validate_database_url",
]
