from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest
from sqlalchemy import Engine

from packages.persistence.database import create_database_engine
from packages.persistence.postgres_tls import (
    SUPABASE_DATABASE_CA_PATH,
    SUPABASE_DATABASE_CA_SHA256,
    PostgresTLSConfigurationError,
    pinned_verify_full_connect_args,
    validate_pinned_supabase_database_ca,
)

DATABASE_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:secret"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)


def test_checked_in_supabase_ca_is_the_exact_pinned_trust_root() -> None:
    assert validate_pinned_supabase_database_ca() == SUPABASE_DATABASE_CA_PATH
    assert len(SUPABASE_DATABASE_CA_SHA256) == 64
    assert pinned_verify_full_connect_args(DATABASE_URL, required=True) == {
        "sslmode": "verify-full",
        "sslrootcert": str(SUPABASE_DATABASE_CA_PATH),
    }


def test_shared_persistence_factory_passes_the_explicit_pinned_trust_root() -> None:
    sentinel = cast(Engine, object())
    with (
        patch("packages.persistence.database.create_engine", return_value=sentinel) as create,
        patch(
            "packages.persistence.database.enforce_sqlite_foreign_keys",
            return_value=sentinel,
        ),
    ):
        assert create_database_engine(DATABASE_URL) is sentinel

    assert create.call_args.kwargs == {
        "connect_args": {
            "sslmode": "verify-full",
            "sslrootcert": str(SUPABASE_DATABASE_CA_PATH),
        },
        "pool_pre_ping": True,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload[:-1],
        lambda payload: payload + b"\n",
        lambda payload: payload[:50] + bytes([payload[50] ^ 1]) + payload[51:],
    ],
)
def test_database_ca_rejects_truncation_append_and_substitution(
    tmp_path: Path,
    mutation: Callable[[bytes], bytes],
) -> None:
    path = tmp_path / "database-ca.crt"
    path.write_bytes(mutation(SUPABASE_DATABASE_CA_PATH.read_bytes()))
    path.chmod(0o600)

    with pytest.raises(PostgresTLSConfigurationError, match=r"digest|size"):
        validate_pinned_supabase_database_ca(path)


def test_database_ca_rejects_writable_and_symlinked_files(tmp_path: Path) -> None:
    path = tmp_path / "database-ca.crt"
    path.write_bytes(SUPABASE_DATABASE_CA_PATH.read_bytes())
    path.chmod(0o622)
    with pytest.raises(PostgresTLSConfigurationError, match="writable"):
        validate_pinned_supabase_database_ca(path)

    path.chmod(0o600)
    link = tmp_path / "linked-ca.crt"
    link.symlink_to(path)
    with pytest.raises(PostgresTLSConfigurationError, match="unavailable"):
        validate_pinned_supabase_database_ca(link)


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite+pysqlite:///:memory:",
        DATABASE_URL.replace("verify-full", "require"),
        f"{DATABASE_URL}&sslrootcert=/tmp/substituted.crt",
    ],
)
def test_required_verify_full_contract_rejects_other_transports(database_url: str) -> None:
    with pytest.raises(PostgresTLSConfigurationError, match="exact verify-full"):
        pinned_verify_full_connect_args(database_url, required=True)
    if "pooler.supabase.com" in database_url:
        with pytest.raises(PostgresTLSConfigurationError, match="exact verify-full"):
            pinned_verify_full_connect_args(database_url, required=False)
    else:
        assert pinned_verify_full_connect_args(database_url, required=False) == {}


def test_non_supabase_postgres_is_not_forced_onto_the_supabase_ca() -> None:
    custom_url = (
        "postgresql+psycopg://user:secret@database.example.invalid:5432/app?sslmode=verify-full"
    )

    assert pinned_verify_full_connect_args(custom_url, required=False) == {}
    with pytest.raises(PostgresTLSConfigurationError, match="Supabase Session pooler"):
        pinned_verify_full_connect_args(custom_url, required=True)


def test_shared_factory_rejects_supabase_without_exact_verify_full() -> None:
    with pytest.raises(PostgresTLSConfigurationError, match="exact verify-full"):
        create_database_engine(DATABASE_URL.replace("?sslmode=verify-full", ""))


@pytest.mark.parametrize(
    "database_url",
    [
        DATABASE_URL.replace(":5432/", ":6543/"),
        DATABASE_URL.replace("postgres.abcdefghijklmnopqrst", "postgres"),
        DATABASE_URL.replace("?sslmode=verify-full", ""),
        (
            "postgresql+psycopg://postgres:secret"
            "@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=verify-full"
        ),
    ],
)
def test_shared_factory_rejects_every_malformed_supabase_pooler_binding(
    database_url: str,
) -> None:
    with pytest.raises(PostgresTLSConfigurationError, match="Session pooler"):
        create_database_engine(database_url)
