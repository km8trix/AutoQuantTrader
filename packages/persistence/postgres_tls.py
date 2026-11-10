"""Pinned PostgreSQL TLS trust for the reviewed Supabase deployment."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from sqlalchemy import make_url
from sqlalchemy.engine import URL
from sqlalchemy.exc import ArgumentError

SUPABASE_DATABASE_CA_PATH = Path(__file__).resolve().parent / "certs" / "supabase-prod-ca-2021.crt"
SUPABASE_DATABASE_CA_SHA256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
MAXIMUM_DATABASE_CA_BYTES = 8_192
_SUPABASE_POOLER_HOST = re.compile(
    r"^[A-Za-z0-9-]+[.]pooler[.]supabase[.]com$",
    re.IGNORECASE,
)
_SUPABASE_PROJECT_REF = re.compile(r"^[a-z0-9]{20}$")


class PostgresTLSConfigurationError(RuntimeError):
    """The reviewed PostgreSQL TLS trust contract failed closed."""


def _is_supabase_provider_host(host: str | None) -> bool:
    """Return whether a host belongs to a recognized Supabase database domain."""

    if host is None:
        return False
    normalized = host.casefold()
    return (
        _SUPABASE_POOLER_HOST.fullmatch(host) is not None
        or normalized.endswith(".supabase.co")
        or normalized.endswith(".supabase.com")
    )


def is_supabase_session_pooler_url(url: URL) -> bool:
    """Return whether a parsed URL selects the reviewed Supabase Session pooler."""

    username = url.username
    return (
        isinstance(url, URL)
        and url.drivername == "postgresql+psycopg"
        and url.host is not None
        and _SUPABASE_POOLER_HOST.fullmatch(url.host) is not None
        and url.port == 5432
        and bool(url.database)
        and username is not None
        and "." in username
        and _SUPABASE_PROJECT_REF.fullmatch(username.rsplit(".", 1)[1]) is not None
        and bool(url.password)
    )


def validate_pinned_supabase_database_ca(
    path: Path | None = None,
) -> Path:
    """Validate and return the exact checked-in Supabase root CA path."""

    resolved_path = SUPABASE_DATABASE_CA_PATH if path is None else path
    if not isinstance(resolved_path, Path) or not resolved_path.is_absolute():
        raise PostgresTLSConfigurationError("database CA path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved_path, flags)
    except OSError:
        raise PostgresTLSConfigurationError("database CA is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PostgresTLSConfigurationError("database CA is not a regular file")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise PostgresTLSConfigurationError("database CA owner is invalid")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PostgresTLSConfigurationError("database CA is writable by another user")
        if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_DATABASE_CA_BYTES:
            raise PostgresTLSConfigurationError("database CA size is invalid")
        remaining = MAXIMUM_DATABASE_CA_BYTES + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > MAXIMUM_DATABASE_CA_BYTES:
            raise PostgresTLSConfigurationError("database CA read is invalid")
        if hashlib.sha256(payload).hexdigest() != SUPABASE_DATABASE_CA_SHA256:
            raise PostgresTLSConfigurationError("database CA digest is invalid")
    finally:
        os.close(descriptor)
    return resolved_path


def pinned_verify_full_connect_args(
    database_url: str,
    *,
    required: bool,
    ca_path: Path | None = None,
) -> dict[str, str]:
    """Return explicit psycopg trust arguments for an exact verify-full DSN."""

    try:
        url = make_url(database_url)
    except (ArgumentError, TypeError, ValueError):
        if required:
            raise PostgresTLSConfigurationError("database URL is invalid") from None
        return {}
    is_psycopg_postgres = url.drivername == "postgresql+psycopg"
    is_supabase_provider_host = _is_supabase_provider_host(url.host)
    is_supabase = is_supabase_session_pooler_url(url)
    query = dict(url.query)
    exact_verify_full = query == {"sslmode": "verify-full"}
    if is_supabase_provider_host and (not is_supabase or not exact_verify_full):
        raise PostgresTLSConfigurationError(
            "Supabase database URL must select the Session pooler with exact verify-full TLS"
        )
    if required and (not is_psycopg_postgres or not is_supabase):
        raise PostgresTLSConfigurationError(
            "database URL must select the Supabase Session pooler with exact verify-full TLS"
        )
    if not is_psycopg_postgres or not is_supabase:
        return {}
    assert exact_verify_full
    pinned_path = validate_pinned_supabase_database_ca(ca_path)
    return {
        "sslmode": "verify-full",
        "sslrootcert": str(pinned_path),
    }


__all__ = [
    "MAXIMUM_DATABASE_CA_BYTES",
    "SUPABASE_DATABASE_CA_PATH",
    "SUPABASE_DATABASE_CA_SHA256",
    "PostgresTLSConfigurationError",
    "is_supabase_session_pooler_url",
    "pinned_verify_full_connect_args",
    "validate_pinned_supabase_database_ca",
]
