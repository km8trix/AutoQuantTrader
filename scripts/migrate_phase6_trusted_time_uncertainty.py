"""Apply the exact empty-history Phase 6 trusted-time uncertainty migration.

This operator is intentionally narrower than the general Alembic CLI.  It
loads only the runtime and test PostgreSQL bindings from an owner-only dotenv,
requires the pinned Supabase CA and exact reviewed migration bytes, writes a
short-lived canonical preflight artifact, and can apply only revision 0035
from revision 0034.  Its public output and artifacts contain opaque hashes,
never a database URL, hostname, username, or password.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import types
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

import sqlalchemy as sa
from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import URL, Connection

from packages.persistence.database import verify_operational_schema
from packages.persistence.postgres_tls import (
    SUPABASE_DATABASE_CA_PATH,
    SUPABASE_DATABASE_CA_SHA256,
    PostgresTLSConfigurationError,
    validate_pinned_supabase_database_ca,
)
from packages.persistence.schema import (
    metadata,
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from scripts.credential_env import load_owner_only_environment
from scripts.local_artifact import read_owner_only_artifact
from scripts.verify_local_paper_smoke_preflight import (
    LocalPaperSmokePreflightError,
    create_bounded_supabase_runtime_engine,
    validate_distinct_database_bindings,
    validate_supabase_session_database_url,
)

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "migrations/versions/0035_phase6_trusted_time_uncertainty.py"
ALEMBIC_CONFIG_PATH = ROOT / "alembic.ini"
PRIOR_REVISION = "0034_phase6_trusted_time"
TARGET_REVISION = "0035_phase6_time_uncertainty"
EXPECTED_MIGRATION_SHA256 = "2e06332674859670d0e1b3237a3551f7ad91dc78956c06aaff33524ac8909545"
OLD_POLICY_SHA256 = "e2ed2efe97b6a13764fba36976916001eec074773f1f2fcf37f759c80e474944"
NEW_POLICY_SHA256 = "64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c"

_CONTRACT_VERSION = "aqt-phase6-time-uncertainty-migration-v1"
_PREFLIGHT_ARTIFACT_TYPE = "phase6_time_uncertainty_preflight"
_POSTFLIGHT_ARTIFACT_TYPE = "phase6_time_uncertainty_postflight"
_ARTIFACT_LIFETIME_SECONDS = 15 * 60
_MAXIMUM_CLOCK_SKEW_SECONDS = 5
_MAXIMUM_ENVIRONMENT_BYTES = 128 * 1024
_MAXIMUM_ARTIFACT_BYTES = 256 * 1024
_MAXIMUM_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_TEST_POSTGRES_TIMEOUT_SECONDS = 10 * 60
_ADVISORY_LOCK_KEY = 4_709_446_131_663_551_061
SUPPORTED_POSTGRES_MAJOR_VERSIONS = frozenset({16, 17})
_TEST_POSTGRES_PATH = Path("tests/integration/test_phase6_trusted_time_postgres.py")
_PYTEST_COUNT = re.compile(r"(?<![0-9])(\d+) (passed|failed|errors?|skipped)(?![a-z])")
_TABLES = (
    "phase6_trusted_time_epoch_registrations",
    "phase6_trusted_time_probe_evaluations",
    "phase6_trusted_time_host_heads",
)
_SOURCE_BINDING_PATHS = (
    Path("alembic.ini"),
    Path("migrations/env.py"),
    Path("migrations/versions/0034_phase6_trusted_time.py"),
    Path("migrations/versions/0035_phase6_trusted_time_uncertainty.py"),
    Path("packages/persistence/database.py"),
    Path("packages/persistence/postgres_tls.py"),
    Path("packages/persistence/schema.py"),
    Path("scripts/credential_env.py"),
    Path("scripts/migrate_phase6_trusted_time_uncertainty.py"),
    Path("scripts/verify_local_paper_smoke_preflight.py"),
    Path("tests/integration/test_phase6_trusted_time_postgres.py"),
)
_PHASE6_TABLE_OBJECTS = (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_probe_evaluations,
    phase6_trusted_time_host_heads,
)
_POSTGRES_DIALECT = postgresql.dialect()  # type: ignore[no-untyped-call]
_EMPTY_DEFINITION_SHA256 = hashlib.sha256(b"").hexdigest()


class MigrationOperatorError(RuntimeError):
    """A migration boundary failed with a public, secret-free reason code."""

    def __init__(
        self,
        reason_code: str,
        *,
        migration_committed: bool | None = False,
        interrupted: bool = False,
    ) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.migration_committed = migration_committed
        self.interrupted = interrupted


type ColumnContract = tuple[str, int, str, bool, str, str, str]
type ConstraintContract = tuple[str, str, str, bool, bool]
type IndexContract = tuple[str, str, bool, bool, bool]


def _normalize_catalog_definition(value: str) -> str:
    if type(value) is not str:
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    return " ".join(value.split())


def _normalize_postgres_type(value: str) -> str:
    normalized = " ".join(value.lower().split()).replace(", ", ",")
    if normalized.startswith("varchar("):
        normalized = "character varying(" + normalized.removeprefix("varchar(")
    return normalized


def _catalog_boolean(value: object) -> bool:
    if type(value) is not bool:
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    return value


_PRE_CONSTRAINT_DEFINITION_SHA256 = dict(
    (
        (
            "ck_phase6_trusted_time_epoch_registrations_phase6_trust_95fd",
            "c8d8ae1591ffbeaf166c290c0a4805619da3010b52537d08134e958033d9a352",
        ),
        (
            "ck_phase6_trusted_time_epoch_registrations_phase6_trust_991c",
            "7ecc9d03cdebbd4f463aaaa6ed9c7a6efcae6d153e7346505e157a567ac283a9",
        ),
        (
            "ck_phase6_trusted_time_epoch_registrations_phase6_trust_d1d2",
            "1706a8c5d78412fbd3df813c322aacb50f836c08f84cc849c56296bda752313a",
        ),
        (
            "fk_phase6_trusted_time_epoch_predecessor",
            "77e586c18969367350979daf273e3ad62ad74e85e5c4d1f63d19adc4af31e24f",
        ),
        (
            "pk_phase6_trusted_time_epoch_registrations",
            "9e00604f16ae3a3f673e53233e2532d01d9962f1000a6df1d83a4196b4a5ad66",
        ),
        (
            "uq_phase6_trusted_time_epoch_exact",
            "966e96d03d178d7875779c79eaf18b7a158bed764ac142692d3ddb34cddc57c5",
        ),
        (
            "uq_phase6_trusted_time_epoch_host_sequence",
            "4a60630e7baac10583b3b9b3357e80ef83f9e4ac43ad947d5031a4f405fe0891",
        ),
        (
            "uq_phase6_trusted_time_epoch_registrations_semantic_sha256",
            "5c820794ce612838f2c3b5c8b6cb89b25e98467cde9540d072132f7e918480ab",
        ),
        (
            "uq_phase6_trusted_time_epoch_tip",
            "33d62e2679b6ec0bf09c73dc9b06e45f09a17ab7128423c4765f2a7a1174ae30",
        ),
        (
            "ck_phase6_trusted_time_host_heads_phase6_trusted_time_h_1f1a",
            "218584bacfc736206f47aae9822a8bfc1b032da78745ee5aa35f60330c97615b",
        ),
        (
            "ck_phase6_trusted_time_host_heads_phase6_trusted_time_h_3f90",
            "1706a8c5d78412fbd3df813c322aacb50f836c08f84cc849c56296bda752313a",
        ),
        (
            "ck_phase6_trusted_time_host_heads_phase6_trusted_time_h_402d",
            "16666541f38633a35e0b9f07c19453e5626e4ed8a2041c15fc6bf19752e14d56",
        ),
        (
            "ck_phase6_trusted_time_host_heads_phase6_trusted_time_h_95ea",
            "fa84c4c128bfef33d53e7eae13e96fee03dc2432f10438274dd3e6a462a6979f",
        ),
        (
            "fk_phase6_trusted_time_head_epoch",
            "d57e0ca19c91b02fc5ed1a09997754850729b06e5207a3d4a484f80de5f2de11",
        ),
        (
            "fk_phase6_trusted_time_head_tip",
            "057e472550d1115eb66717a0038c1b51941d198dcb5b334e7d498f93834a26da",
        ),
        (
            "pk_phase6_trusted_time_host_heads",
            "d127547073eea25f2a92c5579e3babd52c4eca5165cf02134459518afb670167",
        ),
        (
            "uq_phase6_trusted_time_host_heads_semantic_sha256",
            "5c820794ce612838f2c3b5c8b6cb89b25e98467cde9540d072132f7e918480ab",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_19ba",
            "28befdb9536ff76b871f67eed06ae9fe2938c14731f4b2732c46ccc712628856",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_3cd5",
            "2dd812fb0ab8af1fcb2019fbef5cf631895b5ed2f9d9929e888c3349fe007c6e",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_4604",
            "641ca1f480ec34ea4ca919697dc990683ad1f979a95f41118775ea7769ba8fd4",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_5d55",
            "c2532787ed3a59d96ef2c7658b1052524dc956f69f28ce7fa193b63ea6ff36ca",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_9308",
            "6341aec9aad7a9b9ce6f9d3ecd3d6c280738aec7316bdd6d3ae013fce44e2bee",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_9c3c",
            "9d217562c507f306a2fdbb29bddfbdf71ab8e91b88c2b5c24869f28197ccd887",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_afdc",
            "2934ae5ef7b4f4167e05ab10794e7cbcf4ffba6cbadb6195fd26be89393aa181",
        ),
        (
            "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_fc75",
            "0889c5a417b7cc23d0325fe94cfe855c3302cde556272b025507bc5e386b97d0",
        ),
        (
            "fk_phase6_trusted_time_eval_epoch",
            "b62b713414b365e00bbe5bb4380117f452d92edd2cd5db290b215a83d33d0a47",
        ),
        (
            "fk_phase6_trusted_time_eval_predecessor",
            "5821b69a0e85876dcc2e8c2eaf83420e5401d04e677ba589171fa30bf8780070",
        ),
        (
            "pk_phase6_trusted_time_probe_evaluations",
            "cc5a2fb5a1764a7e8ea36189f516f34698cc47449df36eb8731d9d6017b85b65",
        ),
        (
            "uq_phase6_trusted_time_eval_epoch_sequence",
            "9a885112a96bd510779522c9b3b9574e54248314ed55bddaf9ece2ad5372f626",
        ),
        (
            "uq_phase6_trusted_time_eval_exact",
            "907ce8af24ec83414ded5346af68245053f1cf59689045ee63b1bee92f4f44ab",
        ),
        (
            "uq_phase6_trusted_time_eval_tip",
            "78053f93349ee23083b10858cffdf479254f944d1b33cf6462c21f0447600320",
        ),
        (
            "uq_phase6_trusted_time_probe_evaluations_semantic_sha256",
            "5c820794ce612838f2c3b5c8b6cb89b25e98467cde9540d072132f7e918480ab",
        ),
    )
)
_POST_CONSTRAINT_DEFINITION_SHA256 = {
    **_PRE_CONSTRAINT_DEFINITION_SHA256,
    "ck_phase6_trusted_time_epoch_registrations_phase6_trust_95fd": (
        "0d64191a53a603ef548cd53404945db841193f501824d164e0113c5299a71c31"
    ),
    "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_4604": (
        "b4cd8ba600d80fc45967244f994613a810b82c7b1955b67f1f6d2b287e509558"
    ),
    "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_9308": (
        "7023fa851c68a7597ff689607393dd3c99a42b4afbd03dd5e8c6cf2aa58caf12"
    ),
    "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_fc75": (
        "50aa2784cc1f337a7939785ff9f1f1cc84622d5d1803c445c57c50c493b78e97"
    ),
}
_INDEX_DEFINITION_SHA256 = dict(
    (
        (
            "ix_phase6_trusted_time_epoch_host_registered",
            "fb20bd4697164268888dc97b66c806dd9ea4e4a27df04cd485c2e315c6093bd7",
        ),
        (
            "pk_phase6_trusted_time_epoch_registrations",
            "cf2fde33017595a5eb9ff5d90fa8ecbdf155a12746ac38f9a1749415a2cba414",
        ),
        (
            "uq_phase6_trusted_time_epoch_exact",
            "db870ad32eba7b51a834fb3bf2a4d651bddda2a1c5b2c5faec96a67a06b0ea37",
        ),
        (
            "uq_phase6_trusted_time_epoch_host_sequence",
            "a50c24e340517293112fe91c9268f5623e26f0f0c3317cc8120e42e5a145f891",
        ),
        (
            "uq_phase6_trusted_time_epoch_registrations_semantic_sha256",
            "e8cbe769eb045bf2a21b476c94cd17ef9fa74fa21898320baf12c2a82602404e",
        ),
        (
            "uq_phase6_trusted_time_epoch_tip",
            "b5cda41752448115fc88ca9265413615104dd7e410aff1e4219cbc1b19b071a2",
        ),
        (
            "pk_phase6_trusted_time_host_heads",
            "006d66065d21e845d341a7a953ca4ebc3866251256f41a6d5bdf176119c04fde",
        ),
        (
            "uq_phase6_trusted_time_host_heads_semantic_sha256",
            "d22d8834429984c6ced73e71078ed51f501e6f40d28ddc33976dff723a51b290",
        ),
        (
            "ix_phase6_trusted_time_eval_host_time",
            "0034466ce3ac3bc75912bf96db3d1f6d60ec9d7e785a51fbd7763914b094cd54",
        ),
        (
            "pk_phase6_trusted_time_probe_evaluations",
            "f89a3f9f1cc6f1bc1906b6557024720316ebcdec68d54b56084cbf9b988f904a",
        ),
        (
            "uq_phase6_trusted_time_eval_epoch_sequence",
            "bd906f0c05ec054c158cb6765fa8350ef6c76610d13b518c774ba64f9660657c",
        ),
        (
            "uq_phase6_trusted_time_eval_exact",
            "a0db44678f9482c0e3c882697ac201663842221e04a1c710a48926c32e39ba30",
        ),
        (
            "uq_phase6_trusted_time_eval_tip",
            "f52c31ab2bda55cb1cb051439f70c3a8babf777fd277d719f2977c52704b29c8",
        ),
        (
            "uq_phase6_trusted_time_probe_evaluations_semantic_sha256",
            "ddaa02119fce13f556f3cc1ad82b63de1a30bbb8408ef09aed9ed35a5bf9ec08",
        ),
    )
)


def _constraint_kind(constraint: sa.Constraint) -> str:
    if isinstance(constraint, sa.PrimaryKeyConstraint):
        return "p"
    if isinstance(constraint, sa.UniqueConstraint):
        return "u"
    if isinstance(constraint, sa.ForeignKeyConstraint):
        return "f"
    if isinstance(constraint, sa.CheckConstraint):
        return "c"
    raise MigrationOperatorError("source_catalog_contract_invalid")


def _physical_constraint_name(constraint: sa.Constraint) -> str:
    if constraint.name is None:
        raise MigrationOperatorError("source_catalog_contract_invalid")
    rendered = _POSTGRES_DIALECT.identifier_preparer.format_constraint(constraint)
    if not rendered or rendered.startswith('"'):
        raise MigrationOperatorError("source_catalog_contract_invalid")
    return rendered


def _physical_index_name(index: sa.Index) -> str:
    if index.name is None:
        raise MigrationOperatorError("source_catalog_contract_invalid")
    rendered = _POSTGRES_DIALECT.identifier_preparer.format_index(index)
    if not rendered or rendered.startswith('"'):
        raise MigrationOperatorError("source_catalog_contract_invalid")
    return rendered


def _expected_column_contracts(
    *,
    include_uncertainty: bool,
) -> Mapping[str, tuple[ColumnContract, ...]]:
    columns: dict[str, tuple[ColumnContract, ...]] = {}
    for table in _PHASE6_TABLE_OBJECTS:
        table_columns: list[ColumnContract] = []
        for column in table.columns:
            if not include_uncertainty and column.name == "source_uncertainty_milliseconds":
                continue
            if (
                column.server_default is not None
                or column.identity is not None
                or column.computed is not None
            ):
                raise MigrationOperatorError("source_catalog_contract_invalid")
            table_columns.append(
                (
                    column.name,
                    len(table_columns) + 1,
                    _normalize_postgres_type(column.type.compile(dialect=_POSTGRES_DIALECT)),
                    not column.nullable,
                    "",
                    "",
                    _EMPTY_DEFINITION_SHA256,
                )
            )
        columns[table.name] = tuple(table_columns)
    return columns


def _expected_catalog_inventory(
    definition_sha256: Mapping[str, str],
) -> tuple[
    Mapping[str, tuple[ConstraintContract, ...]],
    Mapping[str, tuple[IndexContract, ...]],
]:
    constraints: dict[str, tuple[ConstraintContract, ...]] = {}
    indexes: dict[str, tuple[IndexContract, ...]] = {}
    for table in _PHASE6_TABLE_OBJECTS:
        constraint_rows = tuple(
            sorted(
                (
                    _physical_constraint_name(constraint),
                    _constraint_kind(constraint),
                    definition_sha256[_physical_constraint_name(constraint)],
                    True,
                    True,
                )
                for constraint in table.constraints
            )
        )
        implicit_indexes = {
            name: True
            for name, kind, _digest, _validated, _enforced in constraint_rows
            if kind in {"p", "u"}
        }
        explicit_indexes = {
            _physical_index_name(index): bool(index.unique) for index in table.indexes
        }
        index_rows = tuple(
            sorted(
                (
                    name,
                    _INDEX_DEFINITION_SHA256[name],
                    True,
                    True,
                    unique,
                )
                for name, unique in (implicit_indexes | explicit_indexes).items()
            )
        )
        constraints[table.name] = constraint_rows
        indexes[table.name] = index_rows
    if tuple(table.name for table in _PHASE6_TABLE_OBJECTS) != _TABLES:
        raise MigrationOperatorError("source_catalog_contract_invalid")
    expected_constraint_names = {
        name for entries in constraints.values() for name, *_rest in entries
    }
    expected_index_names = {name for entries in indexes.values() for name, *_rest in entries}
    if expected_constraint_names != set(definition_sha256) or expected_index_names != set(
        _INDEX_DEFINITION_SHA256
    ):
        raise MigrationOperatorError("source_catalog_contract_invalid")
    return constraints, indexes


_EXPECTED_PRE_COLUMNS = _expected_column_contracts(include_uncertainty=False)
_EXPECTED_POST_COLUMNS = _expected_column_contracts(include_uncertainty=True)
_EXPECTED_PRE_CONSTRAINTS, _EXPECTED_INDEXES = _expected_catalog_inventory(
    _PRE_CONSTRAINT_DEFINITION_SHA256,
)
_EXPECTED_POST_CONSTRAINTS, _EXPECTED_POST_INDEXES = _expected_catalog_inventory(
    _POST_CONSTRAINT_DEFINITION_SHA256,
)
if _EXPECTED_POST_INDEXES != _EXPECTED_INDEXES:
    raise MigrationOperatorError("source_catalog_contract_invalid")


@dataclass(frozen=True, slots=True)
class StaticBindings:
    migration_sha256: str
    database_ca_sha256: str
    source_state_sha256: str
    migration_payload: bytes = field(repr=False, compare=False)

    @property
    def public_payload(self) -> dict[str, str]:
        return {
            "database_ca_sha256": self.database_ca_sha256,
            "migration_sha256": self.migration_sha256,
            "source_state_sha256": self.source_state_sha256,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentBindings:
    owner_environment_version_sha256: str
    database_targets_sha256: str
    runtime_database_url: str = field(repr=False, compare=False)
    test_database_url: str = field(repr=False, compare=False)

    @property
    def public_payload(self) -> dict[str, str]:
        return {
            "database_targets_sha256": self.database_targets_sha256,
            "owner_environment_version_sha256": self.owner_environment_version_sha256,
        }


@dataclass(frozen=True, slots=True)
class CatalogSnapshot:
    revision: str
    database_time_unix_seconds: int
    server_major_version: int
    tls_active: bool
    public_schema_active: bool
    public_search_path_only: bool
    table_counts: tuple[tuple[str, int], ...]
    uncertainty_column: tuple[tuple[str, object], ...] | None
    old_policy_constraint_count: int
    new_policy_constraint_count: int
    columns: tuple[tuple[str, tuple[ColumnContract, ...]], ...]
    constraints: tuple[tuple[str, tuple[ConstraintContract, ...]], ...]
    indexes: tuple[tuple[str, tuple[IndexContract, ...]], ...]

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "columns": {
                table: [
                    {
                        "data_type": data_type,
                        "default_expression_sha256": default_expression_sha256,
                        "generated_kind": generated_kind,
                        "identity_kind": identity_kind,
                        "name": name,
                        "not_null": not_null,
                        "ordinal_position": ordinal_position,
                    }
                    for (
                        name,
                        ordinal_position,
                        data_type,
                        not_null,
                        identity_kind,
                        generated_kind,
                        default_expression_sha256,
                    ) in entries
                ]
                for table, entries in self.columns
            },
            "constraints": {
                table: [
                    {
                        "definition_sha256": definition_sha256,
                        "enforced": enforced,
                        "kind": kind,
                        "name": name,
                        "validated": validated,
                    }
                    for name, kind, definition_sha256, validated, enforced in entries
                ]
                for table, entries in self.constraints
            },
            "indexes": {
                table: [
                    {
                        "definition_sha256": definition_sha256,
                        "name": name,
                        "ready": ready,
                        "unique": unique,
                        "valid": valid,
                    }
                    for name, definition_sha256, valid, ready, unique in entries
                ]
                for table, entries in self.indexes
            },
            "new_policy_constraint_count": self.new_policy_constraint_count,
            "old_policy_constraint_count": self.old_policy_constraint_count,
            "public_schema_active": self.public_schema_active,
            "public_search_path_only": self.public_search_path_only,
            "revision": self.revision,
            "server_major_version": self.server_major_version,
            "table_counts": dict(self.table_counts),
            "tls_active": self.tls_active,
            "uncertainty_column": (
                None if self.uncertainty_column is None else dict(self.uncertainty_column)
            ),
        }


class CatalogReader(Protocol):
    def __call__(self, connection: Connection) -> CatalogSnapshot: ...


class MigrationRunner(Protocol):
    def __call__(self, connection: Connection, bindings: StaticBindings) -> None: ...


type EngineFactory = Callable[[str], Engine]
type SchemaVerifier = Callable[..., None]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )


def _read_source(path: Path) -> bytes:
    try:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise MigrationOperatorError("source_binding_invalid")
        if metadata.st_size < 1 or metadata.st_size > _MAXIMUM_SOURCE_FILE_BYTES:
            raise MigrationOperatorError("source_binding_invalid")
        payload = path.read_bytes()
    except OSError:
        raise MigrationOperatorError("source_binding_invalid") from None
    if len(payload) != metadata.st_size:
        raise MigrationOperatorError("source_binding_invalid")
    return payload


def _source_state_sha256() -> str:
    material: list[tuple[str, str]] = []
    for relative_path in _SOURCE_BINDING_PATHS:
        material.append((relative_path.as_posix(), _sha256(_read_source(ROOT / relative_path))))
    return _sha256(_canonical_json_bytes([_CONTRACT_VERSION, "source-state", material]))


def check_static_bindings() -> StaticBindings:
    """Validate the exact migration graph, migration bytes, CA, and source state."""

    migration_payload = _read_source(MIGRATION_PATH)
    migration_sha256 = _sha256(migration_payload)
    if migration_sha256 != EXPECTED_MIGRATION_SHA256:
        raise MigrationOperatorError("migration_binding_invalid")
    try:
        ca_path = validate_pinned_supabase_database_ca()
    except PostgresTLSConfigurationError:
        raise MigrationOperatorError("database_ca_invalid") from None
    if ca_path != SUPABASE_DATABASE_CA_PATH or _sha256(_read_source(ca_path)) != (
        SUPABASE_DATABASE_CA_SHA256
    ):
        raise MigrationOperatorError("database_ca_invalid")
    try:
        config = Config(str(ALEMBIC_CONFIG_PATH))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        migration = ScriptDirectory.from_config(config).get_revision(TARGET_REVISION)
    except Exception:
        raise MigrationOperatorError("migration_graph_invalid") from None
    if (
        migration is None
        or migration.revision != TARGET_REVISION
        or migration.down_revision != (PRIOR_REVISION)
    ):
        raise MigrationOperatorError("migration_graph_invalid")
    return StaticBindings(
        migration_sha256=migration_sha256,
        database_ca_sha256=SUPABASE_DATABASE_CA_SHA256,
        source_state_sha256=_source_state_sha256(),
        migration_payload=migration_payload,
    )


def _environment_file_identity(path: Path) -> tuple[int, ...]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        raise MigrationOperatorError("owner_environment_invalid") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
    ):
        raise MigrationOperatorError("owner_environment_invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _database_identity(url: URL) -> tuple[object, ...]:
    return (
        url.host.lower() if url.host is not None else None,
        url.port,
        url.database,
        url.username,
        "sslmode=verify-full",
    )


def load_environment_bindings(path: Path) -> EnvironmentBindings:
    """Load only the two database DSNs and retain only opaque public metadata."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise MigrationOperatorError("owner_environment_invalid")
    before = _environment_file_identity(path)
    try:
        environment = load_owner_only_environment(
            path,
            variables=("AQT_DATABASE_URL", "AQT_TEST_POSTGRES_URL"),
            maximum_bytes=_MAXIMUM_ENVIRONMENT_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except (OSError, ValueError):
        raise MigrationOperatorError("owner_environment_invalid") from None
    after = _environment_file_identity(path)
    if before != after:
        raise MigrationOperatorError("owner_environment_changed")
    runtime_url = environment.get("AQT_DATABASE_URL", "")
    test_url = environment.get("AQT_TEST_POSTGRES_URL", "")
    if not runtime_url or not test_url:
        raise MigrationOperatorError("database_binding_missing")
    try:
        validate_distinct_database_bindings(runtime_url, test_url)
        runtime = validate_supabase_session_database_url(runtime_url)
        test = validate_supabase_session_database_url(test_url)
    except LocalPaperSmokePreflightError as error:
        raise MigrationOperatorError(error.reason_code) from None
    environment_sha256 = _sha256(
        _canonical_json_bytes([_CONTRACT_VERSION, "owner-env-version", list(before)])
    )
    targets_sha256 = _sha256(
        _canonical_json_bytes(
            [
                _CONTRACT_VERSION,
                "database-targets",
                _database_identity(runtime),
                _database_identity(test),
                SUPABASE_DATABASE_CA_SHA256,
            ]
        )
    )
    return EnvironmentBindings(
        owner_environment_version_sha256=environment_sha256,
        database_targets_sha256=targets_sha256,
        runtime_database_url=runtime_url,
        test_database_url=test_url,
    )


def _test_postgres_child_environment(
    test_database_url: str,
    ambient: Mapping[str, str],
) -> dict[str, str]:
    """Build the child environment from a tiny non-database allowlist."""

    allowed = ("LANG", "LC_ALL", "LC_CTYPE", "PATH", "TMPDIR")
    child = {name: ambient[name] for name in allowed if ambient.get(name)}
    child.update(
        {
            "AQT_DATABASE_URL": test_database_url,
            "AQT_TEST_POSTGRES_URL": test_database_url,
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return child


def _pytest_summary_counts(payload: str) -> tuple[int, int, int]:
    counts = {"passed": 0, "failed": 0, "error": 0, "errors": 0, "skipped": 0}
    for value, label in _PYTEST_COUNT.findall(payload[-4_096:]):
        counts[label] = max(counts[label], int(value))
    return (
        counts["passed"],
        counts["failed"] + max(counts["error"], counts["errors"]),
        counts["skipped"],
    )


def test_postgres(
    *,
    env_file: Path,
) -> tuple[dict[str, object], int]:
    """Run only the isolated Phase 6 PostgreSQL proof against the test DSN."""

    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    child_environment = _test_postgres_child_environment(
        environment.test_database_url,
        os.environ,
    )
    argv = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "--disable-warnings",
        str(_TEST_POSTGRES_PATH),
    ]
    try:
        completed = subprocess.run(
            argv,
            cwd=ROOT,
            env=child_environment,
            capture_output=True,
            text=True,
            timeout=_TEST_POSTGRES_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return (
            {
                "failed_count": 1,
                "migration_committed": False,
                "passed_count": 0,
                "reason": "test_postgres_process_failed",
                "runtime_target_untouched": True,
                "skipped_count": 0,
                "status": "failed",
                "target_revision": TARGET_REVISION,
            },
            2,
        )
    passed, failed, skipped = _pytest_summary_counts(f"{completed.stdout}\n{completed.stderr}")
    succeeded = completed.returncode == 0 and failed == 0 and passed > 0
    return (
        {
            "database_targets_sha256": environment.database_targets_sha256,
            "failed_count": failed if failed > 0 else (0 if succeeded else 1),
            "migration_committed": False,
            "migration_sha256": static.migration_sha256,
            "passed_count": passed,
            "reason": "test_postgres_passed" if succeeded else "test_postgres_failed",
            "runtime_target_untouched": True,
            "skipped_count": skipped,
            "status": "passed" if succeeded else "failed",
            "target_revision": TARGET_REVISION,
        },
        0 if succeeded else 2,
    )


def _client_tls_active(connection: Connection) -> bool:
    try:
        driver_connection = getattr(connection.connection, "driver_connection", None)
        pg_connection = getattr(driver_connection, "pgconn", None)
        return getattr(pg_connection, "ssl_in_use", False) is True
    except TypeError:
        return False


def _database_time_unix_seconds(connection: Connection) -> int:
    value = connection.scalar(
        sa.text("SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint"),
    )
    if type(value) is not int or value < 0:
        raise MigrationOperatorError("database_clock_invalid")
    return value


def _set_operator_search_path(connection: Connection) -> None:
    """Remove Supabase's trailing extensions schema for exact unqualified DDL."""

    connection.exec_driver_sql("SET LOCAL search_path TO public")


def collect_catalog_snapshot(connection: Connection) -> CatalogSnapshot:
    """Collect the exact, nonsecret Phase 6 catalog state from one connection."""

    database_time = _database_time_unix_seconds(connection)
    server_version_num = connection.scalar(
        sa.text("SELECT pg_catalog.current_setting('server_version_num')::integer"),
    )
    if type(server_version_num) is not int or server_version_num < 100_000:
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    server_major_version = server_version_num // 10_000
    if server_major_version not in SUPPORTED_POSTGRES_MAJOR_VERSIONS:
        raise MigrationOperatorError("postgres_server_major_unsupported")
    revision_rows = tuple(
        str(value)
        for value in connection.execute(
            sa.text("SELECT version_num FROM public.alembic_version"),
        ).scalars()
    )
    if len(revision_rows) != 1:
        raise MigrationOperatorError("schema_revision_invalid")
    schema_row = (
        connection.execute(
            sa.text(
                "SELECT current_schema() AS current_schema, "
                "current_schemas(false) AS effective_schemas"
            )
        )
        .mappings()
        .one()
    )
    effective_schemas = tuple(str(value) for value in schema_row["effective_schemas"])
    catalog_tls = connection.scalar(
        sa.text("SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_backend_pid()"),
    )
    if type(catalog_tls) is not bool:
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    table_counts = tuple(
        (
            table,
            int(connection.scalar(sa.text(f'SELECT count(*) FROM public."{table}"')) or 0),
        )
        for table in _TABLES
    )
    column_material: dict[str, list[ColumnContract]] = {table: [] for table in _TABLES}
    for row in connection.execute(
        sa.text(
            "SELECT table_row.relname AS table_name, attribute_row.attname AS name, "
            "attribute_row.attnum AS ordinal_position, "
            "pg_catalog.format_type(attribute_row.atttypid, attribute_row.atttypmod) "
            "AS data_type, attribute_row.attnotnull AS not_null, "
            "attribute_row.attidentity AS identity_kind, "
            "attribute_row.attgenerated AS generated_kind, "
            "COALESCE(pg_catalog.pg_get_expr(default_row.adbin, default_row.adrelid, false), '') "
            "AS default_expression "
            "FROM pg_catalog.pg_attribute AS attribute_row "
            "JOIN pg_catalog.pg_class AS table_row "
            "ON table_row.oid = attribute_row.attrelid "
            "JOIN pg_catalog.pg_namespace AS schema_row "
            "ON schema_row.oid = table_row.relnamespace "
            "LEFT JOIN pg_catalog.pg_attrdef AS default_row "
            "ON default_row.adrelid = attribute_row.attrelid "
            "AND default_row.adnum = attribute_row.attnum "
            "WHERE schema_row.nspname = 'public' "
            "AND table_row.relname IN "
            "('phase6_trusted_time_epoch_registrations', "
            "'phase6_trusted_time_probe_evaluations', "
            "'phase6_trusted_time_host_heads') "
            "AND attribute_row.attnum > 0 AND NOT attribute_row.attisdropped "
            "ORDER BY table_row.relname, attribute_row.attnum"
        )
    ).mappings():
        table_name = str(row["table_name"])
        column_material[table_name].append(
            (
                str(row["name"]),
                len(column_material[table_name]) + 1,
                _normalize_postgres_type(str(row["data_type"])),
                _catalog_boolean(row["not_null"]),
                str(row["identity_kind"]),
                str(row["generated_kind"]),
                _sha256(_normalize_catalog_definition(str(row["default_expression"])).encode()),
            )
        )
    column_rows = tuple(
        connection.execute(
            sa.text(
                "SELECT data_type, is_nullable, numeric_precision, numeric_scale, "
                "column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND table_name = 'phase6_trusted_time_probe_evaluations' "
                "AND column_name = 'source_uncertainty_milliseconds'"
            )
        ).mappings()
    )
    if len(column_rows) > 1:
        raise MigrationOperatorError("uncertainty_column_invalid")
    uncertainty_column = (
        None
        if not column_rows
        else tuple(
            sorted(
                {
                    "data_type": str(column_rows[0]["data_type"]),
                    "nullable": column_rows[0]["is_nullable"] == "YES",
                    "numeric_precision": int(column_rows[0]["numeric_precision"]),
                    "numeric_scale": int(column_rows[0]["numeric_scale"]),
                    "ordinal_position": next(
                        ordinal_position
                        for (
                            name,
                            ordinal_position,
                            _data_type,
                            _not_null,
                            _identity,
                            _generated,
                            _default,
                        ) in column_material["phase6_trusted_time_probe_evaluations"]
                        if name == "source_uncertainty_milliseconds"
                    ),
                }.items()
            )
        )
    )
    policy_counts: dict[str, int] = {}
    for label, digest in (("old", OLD_POLICY_SHA256), ("new", NEW_POLICY_SHA256)):
        policy_counts[label] = int(
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_catalog.pg_constraint AS constraint_row "
                    "JOIN pg_catalog.pg_class AS table_row "
                    "ON table_row.oid = constraint_row.conrelid "
                    "JOIN pg_catalog.pg_namespace AS schema_row "
                    "ON schema_row.oid = table_row.relnamespace "
                    "WHERE schema_row.nspname = 'public' "
                    "AND table_row.relname IN "
                    "('phase6_trusted_time_epoch_registrations', "
                    "'phase6_trusted_time_probe_evaluations', "
                    "'phase6_trusted_time_host_heads') "
                    "AND constraint_row.contype = 'c' "
                    "AND position(:policy_sha256 in "
                    "pg_catalog.pg_get_constraintdef(constraint_row.oid, false)) > 0"
                ),
                {"policy_sha256": digest},
            )
            or 0
        )
    enforcement_supported = connection.scalar(
        sa.text(
            "SELECT EXISTS ("
            "SELECT 1 FROM pg_catalog.pg_attribute AS attribute_row "
            "JOIN pg_catalog.pg_class AS table_row "
            "ON table_row.oid = attribute_row.attrelid "
            "JOIN pg_catalog.pg_namespace AS schema_row "
            "ON schema_row.oid = table_row.relnamespace "
            "WHERE schema_row.nspname = 'pg_catalog' "
            "AND table_row.relname = 'pg_constraint' "
            "AND attribute_row.attname = 'conenforced' "
            "AND attribute_row.attnum > 0 AND NOT attribute_row.attisdropped)"
        )
    )
    if type(enforcement_supported) is not bool:
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    enforced_projection = "constraint_row.conenforced" if enforcement_supported else "TRUE"
    constraint_material: dict[str, list[ConstraintContract]] = {table: [] for table in _TABLES}
    for row in connection.execute(
        sa.text(
            "SELECT table_row.relname AS table_name, constraint_row.conname AS name, "
            "constraint_row.contype AS kind, "
            "pg_catalog.pg_get_constraintdef(constraint_row.oid, false) AS definition, "
            "constraint_row.convalidated AS validated, "
            f"{enforced_projection} AS enforced "
            "FROM pg_catalog.pg_constraint AS constraint_row "
            "JOIN pg_catalog.pg_class AS table_row "
            "ON table_row.oid = constraint_row.conrelid "
            "JOIN pg_catalog.pg_namespace AS schema_row "
            "ON schema_row.oid = table_row.relnamespace "
            "WHERE schema_row.nspname = 'public' "
            "AND table_row.relname IN "
            "('phase6_trusted_time_epoch_registrations', "
            "'phase6_trusted_time_probe_evaluations', "
            "'phase6_trusted_time_host_heads') "
            "ORDER BY table_row.relname, constraint_row.conname"
        )
    ).mappings():
        constraint_material[str(row["table_name"])].append(
            (
                str(row["name"]),
                str(row["kind"]),
                _sha256(_normalize_catalog_definition(str(row["definition"])).encode()),
                _catalog_boolean(row["validated"]),
                _catalog_boolean(row["enforced"]),
            )
        )
    index_material: dict[str, list[IndexContract]] = {table: [] for table in _TABLES}
    for row in connection.execute(
        sa.text(
            "SELECT table_row.relname AS table_name, index_row.relname AS name, "
            "pg_catalog.pg_get_indexdef(index_row.oid, 0, false) AS definition, "
            "catalog_index.indisvalid AS valid, catalog_index.indisready AS ready, "
            "catalog_index.indisunique AS unique "
            "FROM pg_catalog.pg_index AS catalog_index "
            "JOIN pg_catalog.pg_class AS index_row "
            "ON index_row.oid = catalog_index.indexrelid "
            "JOIN pg_catalog.pg_class AS table_row "
            "ON table_row.oid = catalog_index.indrelid "
            "JOIN pg_catalog.pg_namespace AS schema_row "
            "ON schema_row.oid = table_row.relnamespace "
            "WHERE schema_row.nspname = 'public' "
            "AND table_row.relname IN "
            "('phase6_trusted_time_epoch_registrations', "
            "'phase6_trusted_time_probe_evaluations', "
            "'phase6_trusted_time_host_heads') "
            "ORDER BY table_row.relname, index_row.relname"
        )
    ).mappings():
        index_material[str(row["table_name"])].append(
            (
                str(row["name"]),
                _sha256(_normalize_catalog_definition(str(row["definition"])).encode()),
                _catalog_boolean(row["valid"]),
                _catalog_boolean(row["ready"]),
                _catalog_boolean(row["unique"]),
            )
        )
    return CatalogSnapshot(
        revision=revision_rows[0],
        database_time_unix_seconds=database_time,
        server_major_version=server_major_version,
        # Supabase's Session pooler terminates the verified client TLS session;
        # pg_stat_ssl describes the pooler's separate backend hop and is false.
        tls_active=_client_tls_active(connection),
        public_schema_active=schema_row["current_schema"] == "public",
        public_search_path_only=effective_schemas == ("public",),
        table_counts=table_counts,
        uncertainty_column=uncertainty_column,
        old_policy_constraint_count=policy_counts["old"],
        new_policy_constraint_count=policy_counts["new"],
        columns=tuple((table, tuple(column_material[table])) for table in _TABLES),
        constraints=tuple((table, tuple(sorted(constraint_material[table]))) for table in _TABLES),
        indexes=tuple((table, tuple(sorted(index_material[table]))) for table in _TABLES),
    )


def _verify_common_catalog(
    snapshot: CatalogSnapshot,
    *,
    require_client_tls: bool,
) -> None:
    if (
        type(snapshot.database_time_unix_seconds) is not int
        or snapshot.database_time_unix_seconds < 0
        or (require_client_tls and snapshot.tls_active is not True)
        or type(snapshot.tls_active) is not bool
        or snapshot.public_schema_active is not True
        or snapshot.public_search_path_only is not True
        or snapshot.table_counts != tuple((table, 0) for table in _TABLES)
        or dict(snapshot.indexes) != dict(_EXPECTED_INDEXES)
    ):
        raise MigrationOperatorError("trusted_time_catalog_invalid")
    if (
        type(snapshot.server_major_version) is not int
        or snapshot.server_major_version not in SUPPORTED_POSTGRES_MAJOR_VERSIONS
    ):
        raise MigrationOperatorError("postgres_server_major_unsupported")


def verify_preflight_catalog(
    snapshot: CatalogSnapshot,
    *,
    require_client_tls: bool = True,
) -> None:
    _verify_common_catalog(snapshot, require_client_tls=require_client_tls)
    if (
        snapshot.revision != PRIOR_REVISION
        or snapshot.uncertainty_column is not None
        or snapshot.old_policy_constraint_count != 2
        or snapshot.new_policy_constraint_count != 0
        or dict(snapshot.columns) != dict(_EXPECTED_PRE_COLUMNS)
        or dict(snapshot.constraints) != dict(_EXPECTED_PRE_CONSTRAINTS)
    ):
        raise MigrationOperatorError("runtime_preflight_rejected")


def verify_postflight_catalog(
    snapshot: CatalogSnapshot,
    *,
    require_client_tls: bool = True,
) -> None:
    _verify_common_catalog(snapshot, require_client_tls=require_client_tls)
    expected_column: tuple[tuple[str, object], ...] = tuple(
        sorted(
            {
                "data_type": "numeric",
                "nullable": True,
                "numeric_precision": 28,
                "numeric_scale": 10,
                "ordinal_position": 34,
            }.items()
        )
    )
    if (
        snapshot.revision != TARGET_REVISION
        or snapshot.uncertainty_column != expected_column
        or snapshot.old_policy_constraint_count != 0
        or snapshot.new_policy_constraint_count != 2
        or dict(snapshot.columns) != dict(_EXPECTED_POST_COLUMNS)
        or dict(snapshot.constraints) != dict(_EXPECTED_POST_CONSTRAINTS)
    ):
        raise MigrationOperatorError("runtime_postflight_rejected", migration_committed=True)


def _artifact_body(
    *,
    artifact_type: str,
    static: StaticBindings,
    environment: EnvironmentBindings,
    database: CatalogSnapshot,
    now_seconds: int,
    preflight_artifact_sha256: str | None = None,
) -> dict[str, object]:
    bindings: dict[str, object] = {
        **static.public_payload,
        **environment.public_payload,
        "prior_revision": PRIOR_REVISION,
        "target_revision": TARGET_REVISION,
    }
    body: dict[str, object] = {
        "artifact_type": artifact_type,
        "bindings": bindings,
        "contract_version": _CONTRACT_VERSION,
        "created_at_unix_seconds": now_seconds,
        "database": database.public_payload,
        "restore_capable": False,
    }
    if artifact_type == _PREFLIGHT_ARTIFACT_TYPE:
        body["expires_at_unix_seconds"] = now_seconds + _ARTIFACT_LIFETIME_SECONDS
    elif preflight_artifact_sha256 is not None:
        body["preflight_artifact_sha256"] = preflight_artifact_sha256
    return body


def _seal_artifact(body: Mapping[str, object]) -> dict[str, object]:
    sealed = dict(body)
    sealed["artifact_sha256"] = _sha256(_canonical_json_bytes(body))
    return sealed


def _open_directory(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(
        absolute.anchor,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def write_owner_only_artifact(path: Path, payload: Mapping[str, object]) -> str:
    """Create one canonical owner-only artifact atomically without overwriting."""

    if not isinstance(path, Path) or not path.is_absolute() or not path.name:
        raise MigrationOperatorError("artifact_path_invalid")
    encoded = _canonical_json_bytes(payload)
    if len(encoded) > _MAXIMUM_ARTIFACT_BYTES:
        raise MigrationOperatorError("artifact_invalid")
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    temporary_name = f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    try:
        directory_descriptor = _open_directory(path.parent)
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError("short artifact write")
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
    except FileExistsError:
        raise MigrationOperatorError("artifact_already_exists") from None
    except (OSError, ValueError):
        raise MigrationOperatorError("artifact_write_failed") from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_created and directory_descriptor is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    return _sha256(encoded)


def read_and_validate_preflight_artifact(
    path: Path,
    *,
    static: StaticBindings,
    environment: EnvironmentBindings,
    now_seconds: int,
) -> tuple[dict[str, object], str]:
    """Read, authenticate structurally, and bind a short-lived preflight artifact."""

    try:
        encoded = read_owner_only_artifact(
            path,
            limit=_MAXIMUM_ARTIFACT_BYTES,
            label="phase6 migration preflight artifact",
        )
        decoded: object = json.loads(encoded)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise MigrationOperatorError("preflight_artifact_invalid") from None
    if not isinstance(decoded, dict) or any(type(key) is not str for key in decoded):
        raise MigrationOperatorError("preflight_artifact_invalid")
    artifact = cast(dict[str, object], decoded)
    if encoded != _canonical_json_bytes(artifact):
        raise MigrationOperatorError("preflight_artifact_not_canonical")
    artifact_sha256 = artifact.get("artifact_sha256")
    body = dict(artifact)
    body.pop("artifact_sha256", None)
    if type(artifact_sha256) is not str or artifact_sha256 != _sha256(_canonical_json_bytes(body)):
        raise MigrationOperatorError("preflight_artifact_modified")
    expected_bindings: dict[str, object] = {
        **static.public_payload,
        **environment.public_payload,
        "prior_revision": PRIOR_REVISION,
        "target_revision": TARGET_REVISION,
    }
    created = body.get("created_at_unix_seconds")
    expires = body.get("expires_at_unix_seconds")
    if (
        set(body)
        != {
            "artifact_type",
            "bindings",
            "contract_version",
            "created_at_unix_seconds",
            "database",
            "expires_at_unix_seconds",
            "restore_capable",
        }
        or body.get("artifact_type") != _PREFLIGHT_ARTIFACT_TYPE
        or body.get("contract_version") != _CONTRACT_VERSION
        or body.get("bindings") != expected_bindings
        or body.get("restore_capable") is not False
        or type(created) is not int
        or type(expires) is not int
        or expires != created + _ARTIFACT_LIFETIME_SECONDS
        or created > now_seconds + _MAXIMUM_CLOCK_SKEW_SECONDS
        or expires <= now_seconds
    ):
        raise MigrationOperatorError("preflight_artifact_stale")
    return artifact, _sha256(encoded)


def _new_engine(database_url: str, engine_factory: EngineFactory) -> Engine:
    try:
        return engine_factory(database_url)
    except Exception:
        raise MigrationOperatorError("database_connection_configuration_failed") from None


def _dispose_engine(engine: Engine) -> None:
    """Best-effort cleanup must never overwrite a known migration outcome."""

    with contextlib.suppress(Exception):
        engine.dispose()


def _reprobe_commit_outcome(
    *,
    database_url: str,
    engine_factory: EngineFactory,
    catalog_reader: CatalogReader,
) -> tuple[bool | None, CatalogSnapshot | None]:
    """Classify an ambiguous COMMIT on one fresh pinned connection.

    The ACCESS SHARE lock waits for any still-running 0035 DDL transaction to
    resolve before the catalog is read.  Only an exact preflight catalog proves
    rollback; every other non-postflight result remains unknown.
    """

    probe_engine: Engine | None = None
    try:
        probe_engine = _new_engine(database_url, engine_factory)
        with probe_engine.begin() as connection:
            _set_operator_search_path(connection)
            connection.exec_driver_sql(
                "LOCK TABLE "
                + ", ".join(f'public."{table}"' for table in _TABLES)
                + " IN ACCESS SHARE MODE"
            )
            snapshot = catalog_reader(connection)
        try:
            verify_postflight_catalog(snapshot)
        except MigrationOperatorError:
            try:
                verify_preflight_catalog(snapshot)
            except MigrationOperatorError:
                return None, None
            return False, snapshot
        return True, snapshot
    except Exception:
        return None, None
    finally:
        if probe_engine is not None:
            _dispose_engine(probe_engine)


def preflight_runtime(
    *,
    env_file: Path,
    artifact_path: Path,
    engine_factory: EngineFactory = create_bounded_supabase_runtime_engine,
    catalog_reader: CatalogReader = collect_catalog_snapshot,
) -> dict[str, object]:
    """Verify revision 0034 and write the only artifact accepted by apply-runtime."""

    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    engine = _new_engine(environment.runtime_database_url, engine_factory)
    try:
        with engine.connect() as connection:
            _set_operator_search_path(connection)
            snapshot = catalog_reader(connection)
            artifact_time = _database_time_unix_seconds(connection)
        verify_preflight_catalog(snapshot)
    except MigrationOperatorError:
        raise
    except Exception:
        raise MigrationOperatorError("runtime_preflight_query_failed") from None
    finally:
        _dispose_engine(engine)
    artifact = _seal_artifact(
        _artifact_body(
            artifact_type=_PREFLIGHT_ARTIFACT_TYPE,
            static=static,
            environment=environment,
            database=snapshot,
            now_seconds=artifact_time,
        )
    )
    artifact_file_sha256 = write_owner_only_artifact(artifact_path, artifact)
    return {
        "artifact_file_sha256": artifact_file_sha256,
        "artifact_type": _PREFLIGHT_ARTIFACT_TYPE,
        "migration_committed": False,
        "status": "ready",
        "target_revision": TARGET_REVISION,
    }


def run_exact_migration(connection: Connection, bindings: StaticBindings) -> None:
    """Execute only the captured reviewed 0035 upgrade through Alembic Operations."""

    if _sha256(bindings.migration_payload) != EXPECTED_MIGRATION_SHA256:
        raise MigrationOperatorError("migration_binding_invalid")
    module = types.ModuleType("aqt_reviewed_phase6_time_uncertainty_migration")
    module.__file__ = str(MIGRATION_PATH)
    try:
        exec(compile(bindings.migration_payload, str(MIGRATION_PATH), "exec"), module.__dict__)
    except Exception:
        raise MigrationOperatorError("migration_load_failed") from None
    if (
        module.__dict__.get("revision") != TARGET_REVISION
        or module.__dict__.get("down_revision") != PRIOR_REVISION
        or not callable(module.__dict__.get("upgrade"))
    ):
        raise MigrationOperatorError("migration_binding_invalid")
    migration_context = MigrationContext.configure(
        connection,
        opts={"target_metadata": metadata},
    )
    if migration_context.get_current_revision() != PRIOR_REVISION:
        raise MigrationOperatorError("migration_revision_changed")
    config = Config(str(ALEMBIC_CONFIG_PATH))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    script_directory = ScriptDirectory.from_config(config)
    try:
        with Operations.context(migration_context):
            cast(Callable[[], None], module.__dict__["upgrade"])()
        migration_context.stamp(script_directory, TARGET_REVISION)
    except MigrationOperatorError:
        raise
    except Exception:
        raise MigrationOperatorError("migration_execution_failed") from None


def apply_runtime(
    *,
    env_file: Path,
    preflight_artifact_path: Path,
    postflight_artifact_path: Path,
    engine_factory: EngineFactory = create_bounded_supabase_runtime_engine,
    catalog_reader: CatalogReader = collect_catalog_snapshot,
    migration_runner: MigrationRunner = run_exact_migration,
    schema_verifier: SchemaVerifier = verify_operational_schema,
) -> dict[str, object]:
    """Apply the exact target transaction and persist secret-free postflight evidence."""

    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    engine = _new_engine(environment.runtime_database_url, engine_factory)
    migration_committed: bool | None = False
    commit_attempted = False
    interruption_observed = False
    postflight: CatalogSnapshot | None = None
    preflight_file_sha256 = ""
    try:
        transaction_error: BaseException | None = None
        try:
            with engine.begin() as connection:
                _set_operator_search_path(connection)
                lock_acquired = connection.scalar(
                    sa.text("SELECT pg_catalog.pg_try_advisory_xact_lock(:lock_key)"),
                    {"lock_key": _ADVISORY_LOCK_KEY},
                )
                if lock_acquired is not True:
                    raise MigrationOperatorError("migration_operator_busy")
                live_preflight = catalog_reader(connection)
                verify_preflight_catalog(live_preflight)
                catalog_completed_time = _database_time_unix_seconds(connection)
                artifact, preflight_file_sha256 = read_and_validate_preflight_artifact(
                    preflight_artifact_path,
                    static=static,
                    environment=environment,
                    now_seconds=catalog_completed_time,
                )
                if live_preflight.public_payload != artifact.get("database"):
                    raise MigrationOperatorError("preflight_artifact_stale")
                if check_static_bindings().public_payload != static.public_payload:
                    raise MigrationOperatorError("source_binding_changed")
                current_environment = load_environment_bindings(env_file)
                if current_environment.public_payload != environment.public_payload:
                    raise MigrationOperatorError("owner_environment_changed")
                migration_authorization_time = _database_time_unix_seconds(connection)
                final_artifact, final_preflight_file_sha256 = read_and_validate_preflight_artifact(
                    preflight_artifact_path,
                    static=static,
                    environment=environment,
                    now_seconds=migration_authorization_time,
                )
                if (
                    final_preflight_file_sha256 != preflight_file_sha256
                    or final_artifact != artifact
                ):
                    raise MigrationOperatorError("preflight_artifact_changed")
                migration_runner(connection, static)
                commit_attempted = True
        except BaseException as error:
            transaction_error = error

        if transaction_error is not None:
            if not commit_attempted:
                if isinstance(transaction_error, MigrationOperatorError):
                    raise transaction_error
                if not isinstance(transaction_error, Exception):
                    raise MigrationOperatorError(
                        "migration_interrupted",
                        migration_committed=False,
                        interrupted=True,
                    ) from None
                raise MigrationOperatorError("migration_operation_failed") from None
            interruption_observed = not isinstance(transaction_error, Exception)
            migration_committed = None
            _dispose_engine(engine)
            outcome, recovered_postflight = _reprobe_commit_outcome(
                database_url=environment.runtime_database_url,
                engine_factory=engine_factory,
                catalog_reader=catalog_reader,
            )
            if outcome is None:
                migration_committed = None
                raise MigrationOperatorError(
                    "migration_commit_outcome_unknown",
                    migration_committed=None,
                    interrupted=interruption_observed,
                )
            if outcome is False:
                migration_committed = False
                if isinstance(transaction_error, MigrationOperatorError):
                    raise transaction_error
                if interruption_observed:
                    raise MigrationOperatorError(
                        "migration_interrupted",
                        migration_committed=False,
                        interrupted=True,
                    ) from None
                raise MigrationOperatorError("migration_operation_failed") from None
            assert recovered_postflight is not None
            migration_committed = True
            postflight = recovered_postflight
            engine = _new_engine(environment.runtime_database_url, engine_factory)
        else:
            migration_committed = True

        if postflight is None:
            with engine.connect() as connection:
                _set_operator_search_path(connection)
                postflight = catalog_reader(connection)
        verify_postflight_catalog(postflight)
        try:
            schema_verifier(
                engine,
                require_phase_zero_facts=False,
                expected_revision=TARGET_REVISION,
            )
        except Exception:
            raise MigrationOperatorError(
                "operational_schema_verification_failed",
                migration_committed=True,
            ) from None
    except MigrationOperatorError as error:
        if migration_committed is True and error.migration_committed is not True:
            raise MigrationOperatorError(
                error.reason_code,
                migration_committed=True,
                interrupted=error.interrupted,
            ) from None
        if migration_committed is None and error.migration_committed is False:
            raise MigrationOperatorError(
                error.reason_code,
                migration_committed=None,
                interrupted=error.interrupted,
            ) from None
        raise
    except Exception:
        raise MigrationOperatorError(
            "migration_operation_failed",
            migration_committed=migration_committed,
        ) from None
    except BaseException:
        raise MigrationOperatorError(
            "migration_interrupted",
            migration_committed=migration_committed,
            interrupted=True,
        ) from None
    finally:
        _dispose_engine(engine)
    assert postflight is not None
    artifact_time = postflight.database_time_unix_seconds
    postflight_artifact = _seal_artifact(
        _artifact_body(
            artifact_type=_POSTFLIGHT_ARTIFACT_TYPE,
            static=static,
            environment=environment,
            database=postflight,
            now_seconds=artifact_time,
            preflight_artifact_sha256=preflight_file_sha256,
        )
    )
    try:
        postflight_file_sha256 = write_owner_only_artifact(
            postflight_artifact_path,
            postflight_artifact,
        )
    except MigrationOperatorError as error:
        raise MigrationOperatorError(
            error.reason_code,
            migration_committed=True,
            interrupted=interruption_observed or error.interrupted,
        ) from None
    except BaseException:
        raise MigrationOperatorError(
            "migration_interrupted",
            migration_committed=True,
            interrupted=True,
        ) from None
    if interruption_observed:
        raise MigrationOperatorError(
            "migration_interrupted",
            migration_committed=True,
            interrupted=True,
        )
    return {
        "artifact_file_sha256": postflight_file_sha256,
        "artifact_type": _POSTFLIGHT_ARTIFACT_TYPE,
        "migration_committed": True,
        "restore_capable": False,
        "status": "complete",
        "target_revision": TARGET_REVISION,
    }


def _safe_failure(error: MigrationOperatorError) -> dict[str, object]:
    return {
        "migration_committed": error.migration_committed,
        "reason": error.reason_code,
        "status": "failed",
        "target_revision": TARGET_REVISION,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "check-bindings",
        help="verify reviewed migration, CA, Alembic graph, and source bindings offline",
    )
    test_parser = subparsers.add_parser(
        "test-postgres",
        help="run only the Phase 6 PostgreSQL integration proof against the test DSN",
    )
    test_parser.add_argument("--env-file", required=True, type=Path)
    preflight_parser = subparsers.add_parser(
        "preflight-runtime",
        help="verify revision 0034 and create a short-lived owner-only artifact",
    )
    preflight_parser.add_argument("--env-file", required=True, type=Path)
    preflight_parser.add_argument("--artifact", required=True, type=Path)
    apply_parser = subparsers.add_parser(
        "apply-runtime",
        help="apply only revision 0035 after validating the preflight artifact",
    )
    apply_parser.add_argument("--env-file", required=True, type=Path)
    apply_parser.add_argument("--preflight-artifact", required=True, type=Path)
    apply_parser.add_argument("--postflight-artifact", required=True, type=Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.command == "check-bindings":
            static = check_static_bindings()
            result: dict[str, object] = {
                **static.public_payload,
                "migration_committed": False,
                "prior_revision": PRIOR_REVISION,
                "status": "ready",
                "target_revision": TARGET_REVISION,
            }
            exit_code = 0
        elif parsed.command == "test-postgres":
            result, exit_code = test_postgres(env_file=parsed.env_file)
        elif parsed.command == "preflight-runtime":
            result = preflight_runtime(
                env_file=parsed.env_file,
                artifact_path=parsed.artifact,
            )
            exit_code = 0
        else:
            result = apply_runtime(
                env_file=parsed.env_file,
                preflight_artifact_path=parsed.preflight_artifact,
                postflight_artifact_path=parsed.postflight_artifact,
            )
            exit_code = 0
    except MigrationOperatorError as error:
        print(json.dumps(_safe_failure(error), sort_keys=True), flush=True)
        return 130 if error.interrupted else 2
    except Exception:
        print(
            json.dumps(
                _safe_failure(MigrationOperatorError("internal_operator_failure")),
                sort_keys=True,
            ),
            flush=True,
        )
        return 2
    except BaseException:
        print(
            json.dumps(
                _safe_failure(
                    MigrationOperatorError(
                        "operator_interrupted",
                        interrupted=True,
                    )
                ),
                sort_keys=True,
            ),
            flush=True,
        )
        return 130
    print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
