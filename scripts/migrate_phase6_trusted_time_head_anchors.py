"""Apply the exact additive Phase 6D trusted-time head-anchor migration.

This purpose-built operator is intentionally narrower than the Alembic CLI.
It accepts only the exact 0035 -> 0036 edge, loads only the runtime and test
PostgreSQL bindings from an owner-only dotenv, requires the checked-in pinned
Supabase CA, proves the isolated test database first, and uses short-lived
canonical pre/post artifacts that never contain database connection details.

Unlike the Phase 6C operator, existing local trusted-time epoch, evaluation,
and head history is explicitly allowed.  The migration itself remains strictly
additive: both new anchor tables must be absent before it runs and empty after
it commits.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
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
from sqlalchemy.engine import Connection

from packages.persistence.database import verify_operational_schema
from packages.persistence.postgres_tls import (
    SUPABASE_DATABASE_CA_PATH,
    SUPABASE_DATABASE_CA_SHA256,
    PostgresTLSConfigurationError,
    validate_pinned_supabase_database_ca,
)
from packages.persistence.schema import (
    metadata,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
)
from scripts import migrate_phase6_trusted_time_uncertainty as phase6c_operator
from scripts.local_artifact import read_owner_only_artifact
from scripts.verify_local_paper_smoke_preflight import (
    create_bounded_supabase_runtime_engine,
)

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "migrations/versions/0036_phase6_trusted_time_head_anchors.py"
ALEMBIC_CONFIG_PATH = ROOT / "alembic.ini"
PRIOR_REVISION = "0035_phase6_time_uncertainty"
TARGET_REVISION = "0036_phase6_time_anchors"
EXPECTED_MIGRATION_SHA256 = "9928c457f2593c7b3b4d6f3520eec716bb63375edb1dba3226d44d88cddcdda4"

_CONTRACT_VERSION = "aqt-phase6-trusted-time-head-anchor-migration-v1"
_PREFLIGHT_ARTIFACT_TYPE = "phase6_trusted_time_head_anchor_preflight"
_POSTFLIGHT_ARTIFACT_TYPE = "phase6_trusted_time_head_anchor_postflight"
_ARTIFACT_LIFETIME_SECONDS = 15 * 60
_MAXIMUM_CLOCK_SKEW_SECONDS = 5
_MAXIMUM_ARTIFACT_BYTES = 256 * 1024
_MAXIMUM_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_TEST_POSTGRES_TIMEOUT_SECONDS = 10 * 60
_ADVISORY_LOCK_KEY = 5_355_421_789_239_718_013
SUPPORTED_POSTGRES_MAJOR_VERSIONS = frozenset({16, 17})
_TEST_POSTGRES_PATH = Path(
    "tests/integration/test_phase6_trusted_time_head_anchor_migration_postgres.py"
)
_PYTEST_COUNT = phase6c_operator._PYTEST_COUNT
_BASE_TABLES = phase6c_operator._TABLES
_ANCHOR_TABLES = (
    "phase6_trusted_time_head_anchor_intents",
    "phase6_trusted_time_head_anchor_receipts",
)
_ALL_LOCKED_TABLES = ("alembic_version", *_BASE_TABLES)
_SOURCE_BINDING_PATHS = (
    Path("alembic.ini"),
    Path("migrations/env.py"),
    Path("migrations/versions/0035_phase6_trusted_time_uncertainty.py"),
    Path("migrations/versions/0036_phase6_trusted_time_head_anchors.py"),
    Path("packages/persistence/database.py"),
    Path("packages/persistence/postgres_tls.py"),
    Path("packages/persistence/schema.py"),
    Path("scripts/credential_env.py"),
    Path("scripts/migrate_phase6_trusted_time_uncertainty.py"),
    Path("scripts/migrate_phase6_trusted_time_head_anchors.py"),
    Path("scripts/verify_local_paper_smoke_preflight.py"),
    _TEST_POSTGRES_PATH,
    Path("tests/unit/test_migrate_phase6_trusted_time_head_anchors.py"),
)
_ANCHOR_TABLE_OBJECTS = (
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
)
_POSTGRES_DIALECT = postgresql.dialect()  # type: ignore[no-untyped-call]
_EMPTY_DEFINITION_SHA256 = hashlib.sha256(b"").hexdigest()

MigrationOperatorError = phase6c_operator.MigrationOperatorError
EnvironmentBindings = phase6c_operator.EnvironmentBindings

type ColumnContract = tuple[str, int, str, bool, str, str, str]
type ConstraintContract = tuple[str, str, str, bool, bool]
type IndexContract = tuple[str, str, bool, bool, bool]
type RelationContract = tuple[str, str, str, bool, bool]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )


def _normalize_catalog_definition(value: str) -> str:
    if type(value) is not str:
        raise MigrationOperatorError("trusted_time_anchor_catalog_invalid")
    return " ".join(value.split())


def _normalize_postgres_type(value: str) -> str:
    normalized = " ".join(value.lower().split()).replace(", ", ",")
    if normalized.startswith("varchar("):
        normalized = "character varying(" + normalized.removeprefix("varchar(")
    return normalized


def _catalog_boolean(value: object) -> bool:
    if type(value) is not bool:
        raise MigrationOperatorError("trusted_time_anchor_catalog_invalid")
    return value


def _read_source(path: Path) -> bytes:
    try:
        source_metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(source_metadata.st_mode) or path.is_symlink():
            raise MigrationOperatorError("source_binding_invalid")
        if source_metadata.st_size < 1 or source_metadata.st_size > _MAXIMUM_SOURCE_FILE_BYTES:
            raise MigrationOperatorError("source_binding_invalid")
        payload = path.read_bytes()
    except OSError:
        raise MigrationOperatorError("source_binding_invalid") from None
    if len(payload) != source_metadata.st_size:
        raise MigrationOperatorError("source_binding_invalid")
    return payload


def _source_state_sha256() -> str:
    material = tuple(
        (relative_path.as_posix(), _sha256(_read_source(ROOT / relative_path)))
        for relative_path in _SOURCE_BINDING_PATHS
    )
    return _sha256(_canonical_json_bytes([_CONTRACT_VERSION, "source-state", material]))


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


def _expected_column_contracts() -> Mapping[str, tuple[ColumnContract, ...]]:
    expected: dict[str, tuple[ColumnContract, ...]] = {}
    for table in _ANCHOR_TABLE_OBJECTS:
        entries: list[ColumnContract] = []
        for column in table.columns:
            if (
                column.server_default is not None
                or column.identity is not None
                or column.computed is not None
            ):
                raise MigrationOperatorError("source_catalog_contract_invalid")
            entries.append(
                (
                    column.name,
                    len(entries) + 1,
                    _normalize_postgres_type(column.type.compile(dialect=_POSTGRES_DIALECT)),
                    not column.nullable,
                    "",
                    "",
                    _EMPTY_DEFINITION_SHA256,
                )
            )
        expected[table.name] = tuple(entries)
    return expected


_CONSTRAINT_DEFINITION_SHA256: Mapping[str, Mapping[str, str]] = {
    "phase6_trusted_time_head_anchor_intents": dict(
        (
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_281f",
                "cd4ceb7d52ee83349e67e29a9d44331b1875ca0bde5771de7df2ff53e1d59c66",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_55fd",
                "3d67080cf6f1455138fe3368084a7cccd681dc40b928eeb30371b2cf83ab1975",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_60db",
                "aa0cd986e6c58b89ff6dab25e450a12d1439ebdc8b5feef15da41c8ce1bf8d05",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_b0fd",
                "843d2f417b713e7c817b17796592fb42493fc5be787f76fea916daebb89e548b",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_c512",
                "42e5d579145802505643b743710da848eb024fafc745f76dc13c6540a0453de9",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_f117",
                "1d4326bfdb511a942109c336034787d1e5613e7bd4f4442549b6eecc88a5366e",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_intents_phase6_ancho_f607",
                "50374c6c36fbbddaec7140a2fe79190549e13f97c8949d00e34a41fd53d2921c",
            ),
            (
                "fk_phase6_anchor_intent_epoch",
                "d57e0ca19c91b02fc5ed1a09997754850729b06e5207a3d4a484f80de5f2de11",
            ),
            (
                "fk_phase6_anchor_intent_evaluation",
                "057e472550d1115eb66717a0038c1b51941d198dcb5b334e7d498f93834a26da",
            ),
            (
                "fk_phase6_anchor_intent_predecessor",
                "8bf43836d32e85f0ac93a3091550fb7312147e40f6afc6cebb1c88f112c36151",
            ),
            (
                "pk_phase6_trusted_time_head_anchor_intents",
                "1034f74bfbb151106028d692e4cea9c0605af525ca273a9a5c45267bbcdb5e2c",
            ),
            (
                "uq_phase6_anchor_intent_envelope",
                "0fcfb76a4de662226d20dbfa27273b34643af1c0ce638098b159330be80cf46d",
            ),
            (
                "uq_phase6_anchor_intent_host_head",
                "9f7e4e79ddd2d9111a517da4b3e8e3c8fa5571d4fc90aad91b21077584f00c4e",
            ),
            (
                "uq_phase6_anchor_intent_host_sequence",
                "697eee93080382b77bafe2461c4c6b973c0f7eb82fe8501d6135ec8fc49c5778",
            ),
            (
                "uq_phase6_anchor_intent_object",
                "ffa6d931d6e1fe2424724f601f9e5ff97074b31e065fef78865b1e4fc9da5a82",
            ),
            (
                "uq_phase6_anchor_intent_predecessor_target",
                "d1460b826ae1f68d4f0b5919d87225b38a0ff3f6cb59f26877574f5aa52eb4cd",
            ),
            (
                "uq_phase6_anchor_intent_receipt_binding",
                "966a4daddb9126e8c01c97ae51b4203b88b969f4bce5d7dde2c8d5882a631626",
            ),
            (
                "uq_phase6_anchor_intent_semantic",
                "5c820794ce612838f2c3b5c8b6cb89b25e98467cde9540d072132f7e918480ab",
            ),
        )
    ),
    "phase6_trusted_time_head_anchor_receipts": dict(
        (
            (
                "ck_phase6_trusted_time_head_anchor_receipts_phase6_anch_7be9",
                "1706a8c5d78412fbd3df813c322aacb50f836c08f84cc849c56296bda752313a",
            ),
            (
                "ck_phase6_trusted_time_head_anchor_receipts_phase6_anch_d4a0",
                "1e3446a85dc946aa9584f779ccb92a635ea4b2f49ce1cadf2405b8e0a0651c17",
            ),
            (
                "fk_phase6_anchor_receipt_intent",
                "e87c5abe77f05c97912d017b699628dc8e4b25187be770106f73f5b7e8389ec4",
            ),
            (
                "pk_phase6_trusted_time_head_anchor_receipts",
                "bde1fe164c1ef915831e6f4fd481564915bc5253041fe55ce9b6893d7a7ded8d",
            ),
            (
                "uq_phase6_anchor_receipt_intent",
                "331c0235ee2392c5582761d9d384d65235afaa4888992edf9444c987999bafe3",
            ),
            (
                "uq_phase6_anchor_receipt_semantic",
                "5c820794ce612838f2c3b5c8b6cb89b25e98467cde9540d072132f7e918480ab",
            ),
        )
    ),
}

_INDEX_CONTRACTS: Mapping[str, tuple[IndexContract, ...]] = {
    "phase6_trusted_time_head_anchor_intents": (
        (
            "ix_phase6_anchor_intent_host_created",
            "6801beb8b8f93bc4caffd28502f036c64585724f5ef973efde9b598007db7adb",
            True,
            True,
            False,
        ),
        (
            "pk_phase6_trusted_time_head_anchor_intents",
            "95853f7c38be17e2c91c29bf095b983e9a96a3a210db3a83b18eefc4c8b1a871",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_envelope",
            "825066fd8f0e34edff425808f8c6067aed3882fe00f4ed13bf281a40f9da8aeb",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_host_head",
            "efc2a3b4359d0967b59bdc4f5d47f256e87c70a4df2172280c82182ba93b7fef",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_host_sequence",
            "8a2d548e3a8e8c4a6cf080fa7eb993440811489e0f2e5eb7d07b815f95a5d852",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_object",
            "323e68104d2818cb7694678217db920efe45ca19f75c307100398de84a31123f",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_predecessor_target",
            "a5a1cb86470b7cb64f34fd9b2f43200d5c59e8569cf682919a921ee97ef4d0d6",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_receipt_binding",
            "7a34b055eb1eac79ce2a57bcaca523e52b13e4032e62f295c49333a78e0a7c09",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_intent_semantic",
            "ecd896c4b7d4b81d7166de53d27ad29e46872b47553fcb65ae744bf375dd71b5",
            True,
            True,
            True,
        ),
    ),
    "phase6_trusted_time_head_anchor_receipts": (
        (
            "ix_phase6_anchor_receipt_observed",
            "33cffdec5f40d286e3e39a319a3513ee937adc86f1c36caab0e1cb13abb295ec",
            True,
            True,
            False,
        ),
        (
            "pk_phase6_trusted_time_head_anchor_receipts",
            "b38c0d6675a7b36f55d035497793daab6f5ef496e7cbe68064c47d170c638415",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_receipt_intent",
            "461c48a07373f11a4e51c340e33ea49c134f3fd0d2e9468081245a54920979cd",
            True,
            True,
            True,
        ),
        (
            "uq_phase6_anchor_receipt_semantic",
            "cf7b1ee04f455a1a836ae6e7001aab0d686beae2c713c265197d9ea33e92a89f",
            True,
            True,
            True,
        ),
    ),
}


def _expected_constraint_contracts() -> Mapping[str, tuple[ConstraintContract, ...]]:
    expected: dict[str, tuple[ConstraintContract, ...]] = {}
    for table in _ANCHOR_TABLE_OBJECTS:
        definitions = _CONSTRAINT_DEFINITION_SHA256[table.name]
        entries = tuple(
            sorted(
                (
                    _physical_constraint_name(constraint),
                    _constraint_kind(constraint),
                    definitions[_physical_constraint_name(constraint)],
                    True,
                    True,
                )
                for constraint in table.constraints
            )
        )
        if {entry[0] for entry in entries} != set(definitions):
            raise MigrationOperatorError("source_catalog_contract_invalid")
        expected[table.name] = entries
    return expected


def _validate_expected_index_names() -> None:
    for table in _ANCHOR_TABLE_OBJECTS:
        explicit = {_physical_index_name(index) for index in table.indexes}
        implicit = {
            _physical_constraint_name(constraint)
            for constraint in table.constraints
            if isinstance(constraint, (sa.PrimaryKeyConstraint, sa.UniqueConstraint))
        }
        if explicit | implicit != {entry[0] for entry in _INDEX_CONTRACTS[table.name]}:
            raise MigrationOperatorError("source_catalog_contract_invalid")


_EXPECTED_COLUMNS = _expected_column_contracts()
_EXPECTED_CONSTRAINTS = _expected_constraint_contracts()
_validate_expected_index_names()
_EXPECTED_RELATIONS: tuple[RelationContract, ...] = tuple(
    (table, "r", "p", False, False) for table in _ANCHOR_TABLES
)
_EXPECTED_UNCERTAINTY_COLUMN = tuple(
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
_EXPECTED_BASE_CATALOG_SHA256 = _sha256(
    _canonical_json_bytes(
        [
            _EXPECTED_UNCERTAINTY_COLUMN,
            0,
            2,
            tuple(
                (table, phase6c_operator._EXPECTED_POST_COLUMNS[table]) for table in _BASE_TABLES
            ),
            tuple(
                (table, phase6c_operator._EXPECTED_POST_CONSTRAINTS[table])
                for table in _BASE_TABLES
            ),
            tuple((table, phase6c_operator._EXPECTED_INDEXES[table]) for table in _BASE_TABLES),
        ]
    )
)


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
class CatalogSnapshot:
    revision: str
    database_time_unix_seconds: int
    server_major_version: int
    tls_active: bool
    public_schema_active: bool
    public_search_path_only: bool
    local_history_counts: tuple[tuple[str, int], ...]
    base_catalog_sha256: str
    anchor_relations: tuple[RelationContract, ...]
    anchor_table_counts: tuple[tuple[str, int], ...]
    columns: tuple[tuple[str, tuple[ColumnContract, ...]], ...]
    constraints: tuple[tuple[str, tuple[ConstraintContract, ...]], ...]
    indexes: tuple[tuple[str, tuple[IndexContract, ...]], ...]

    @property
    def schema_binding_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                [
                    _CONTRACT_VERSION,
                    "catalog-schema-binding",
                    self.revision,
                    self.server_major_version,
                    self.tls_active,
                    self.public_schema_active,
                    self.public_search_path_only,
                    self.base_catalog_sha256,
                    self.anchor_relations,
                    self.columns,
                    self.constraints,
                    self.indexes,
                ]
            )
        )

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "anchor_relations": [
                {
                    "force_row_security": force_row_security,
                    "kind": kind,
                    "name": name,
                    "persistence": persistence,
                    "row_security": row_security,
                }
                for (
                    name,
                    kind,
                    persistence,
                    row_security,
                    force_row_security,
                ) in self.anchor_relations
            ],
            "anchor_table_counts": dict(self.anchor_table_counts),
            "base_catalog_sha256": self.base_catalog_sha256,
            "columns": {
                table: [
                    {
                        "data_type": data_type,
                        "default_expression_sha256": default_sha256,
                        "generated_kind": generated_kind,
                        "identity_kind": identity_kind,
                        "name": name,
                        "not_null": not_null,
                        "ordinal_position": ordinal,
                    }
                    for (
                        name,
                        ordinal,
                        data_type,
                        not_null,
                        identity_kind,
                        generated_kind,
                        default_sha256,
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
            "local_history_counts": dict(self.local_history_counts),
            "public_schema_active": self.public_schema_active,
            "public_search_path_only": self.public_search_path_only,
            "revision": self.revision,
            "schema_binding_sha256": self.schema_binding_sha256,
            "server_major_version": self.server_major_version,
            "tls_active": self.tls_active,
        }


class CatalogReader(Protocol):
    def __call__(self, connection: Connection) -> CatalogSnapshot: ...


class MigrationRunner(Protocol):
    def __call__(self, connection: Connection, bindings: StaticBindings) -> None: ...


type EngineFactory = Callable[[str], Engine]
type SchemaVerifier = Callable[..., None]


def check_static_bindings() -> StaticBindings:
    """Pin exact migration bytes, the one-edge Alembic graph, CA, and source state."""

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
        scripts = ScriptDirectory.from_config(config)
        migration = scripts.get_revision(TARGET_REVISION)
        prior = scripts.get_revision(PRIOR_REVISION)
    except Exception:
        raise MigrationOperatorError("migration_graph_invalid") from None
    if (
        migration is None
        or prior is None
        or migration.revision != TARGET_REVISION
        or migration.down_revision != PRIOR_REVISION
        or Path(migration.path).resolve() != MIGRATION_PATH.resolve()
        or TARGET_REVISION not in prior.nextrev
    ):
        raise MigrationOperatorError("migration_graph_invalid")
    return StaticBindings(
        migration_sha256=migration_sha256,
        database_ca_sha256=SUPABASE_DATABASE_CA_SHA256,
        source_state_sha256=_source_state_sha256(),
        migration_payload=migration_payload,
    )


def load_environment_bindings(path: Path) -> EnvironmentBindings:
    """Reuse the audited strict loader for exactly the two distinct DSNs."""

    return phase6c_operator.load_environment_bindings(path)


def _test_postgres_child_environment(
    test_database_url: str,
    ambient: Mapping[str, str],
) -> dict[str, str]:
    return phase6c_operator._test_postgres_child_environment(test_database_url, ambient)


def _pytest_summary_counts(payload: str) -> tuple[int, int, int]:
    return phase6c_operator._pytest_summary_counts(payload)


def test_postgres(*, env_file: Path) -> tuple[dict[str, object], int]:
    """Run only the isolated exact 0035 -> 0036 PostgreSQL proof on the test DSN."""

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
        completed = None
    if completed is None:
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


def _base_catalog_sha256(snapshot: phase6c_operator.CatalogSnapshot) -> str:
    return _sha256(
        _canonical_json_bytes(
            [
                snapshot.uncertainty_column,
                snapshot.old_policy_constraint_count,
                snapshot.new_policy_constraint_count,
                snapshot.columns,
                snapshot.constraints,
                snapshot.indexes,
            ]
        )
    )


def collect_catalog_snapshot(connection: Connection) -> CatalogSnapshot:
    """Read the exact local-history and external-anchor PostgreSQL catalog."""

    base = phase6c_operator.collect_catalog_snapshot(connection)
    relation_rows = tuple(
        connection.execute(
            sa.text(
                "SELECT table_row.relname AS name, table_row.relkind AS kind, "
                "table_row.relpersistence AS persistence, "
                "table_row.relrowsecurity AS row_security, "
                "table_row.relforcerowsecurity AS force_row_security "
                "FROM pg_catalog.pg_class AS table_row "
                "JOIN pg_catalog.pg_namespace AS schema_row "
                "ON schema_row.oid = table_row.relnamespace "
                "WHERE schema_row.nspname = 'public' "
                "AND table_row.relname IN "
                "('phase6_trusted_time_head_anchor_intents', "
                "'phase6_trusted_time_head_anchor_receipts') "
                "ORDER BY table_row.relname"
            )
        ).mappings()
    )
    relations: tuple[RelationContract, ...] = tuple(
        (
            str(row["name"]),
            str(row["kind"]),
            str(row["persistence"]),
            _catalog_boolean(row["row_security"]),
            _catalog_boolean(row["force_row_security"]),
        )
        for row in relation_rows
    )
    exact_tables = {
        name
        for name, kind, persistence, row_security, force_row_security in relations
        if kind == "r" and persistence == "p" and not row_security and not force_row_security
    }
    anchor_counts = tuple(
        (
            table,
            int(connection.scalar(sa.text(f'SELECT count(*) FROM public."{table}"')) or 0),
        )
        for table in _ANCHOR_TABLES
        if table in exact_tables
    )
    column_material: dict[str, list[ColumnContract]] = {table: [] for table in _ANCHOR_TABLES}
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
            "('phase6_trusted_time_head_anchor_intents', "
            "'phase6_trusted_time_head_anchor_receipts') "
            "AND attribute_row.attnum > 0 AND NOT attribute_row.attisdropped "
            "ORDER BY table_row.relname, attribute_row.attnum"
        )
    ).mappings():
        table_name = str(row["table_name"])
        column_material[table_name].append(
            (
                str(row["name"]),
                int(row["ordinal_position"]),
                _normalize_postgres_type(str(row["data_type"])),
                _catalog_boolean(row["not_null"]),
                str(row["identity_kind"]),
                str(row["generated_kind"]),
                _sha256(_normalize_catalog_definition(str(row["default_expression"])).encode()),
            )
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
        raise MigrationOperatorError("trusted_time_anchor_catalog_invalid")
    enforced_projection = "constraint_row.conenforced" if enforcement_supported else "TRUE"
    constraint_material: dict[str, list[ConstraintContract]] = {
        table: [] for table in _ANCHOR_TABLES
    }
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
            "('phase6_trusted_time_head_anchor_intents', "
            "'phase6_trusted_time_head_anchor_receipts') "
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
    index_material: dict[str, list[IndexContract]] = {table: [] for table in _ANCHOR_TABLES}
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
            "('phase6_trusted_time_head_anchor_intents', "
            "'phase6_trusted_time_head_anchor_receipts') "
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
        revision=base.revision,
        database_time_unix_seconds=base.database_time_unix_seconds,
        server_major_version=base.server_major_version,
        tls_active=base.tls_active,
        public_schema_active=base.public_schema_active,
        public_search_path_only=base.public_search_path_only,
        local_history_counts=base.table_counts,
        base_catalog_sha256=_base_catalog_sha256(base),
        anchor_relations=relations,
        anchor_table_counts=anchor_counts,
        columns=tuple(
            (table, tuple(column_material[table]))
            for table in _ANCHOR_TABLES
            if column_material[table]
        ),
        constraints=tuple(
            (table, tuple(sorted(constraint_material[table])))
            for table in _ANCHOR_TABLES
            if constraint_material[table]
        ),
        indexes=tuple(
            (table, tuple(sorted(index_material[table])))
            for table in _ANCHOR_TABLES
            if index_material[table]
        ),
    )


def _verify_common_catalog(
    snapshot: CatalogSnapshot,
    *,
    require_client_tls: bool,
) -> None:
    if (
        type(snapshot.database_time_unix_seconds) is not int
        or snapshot.database_time_unix_seconds < 0
        or type(snapshot.tls_active) is not bool
        or (require_client_tls and snapshot.tls_active is not True)
        or snapshot.public_schema_active is not True
        or snapshot.public_search_path_only is not True
        or snapshot.base_catalog_sha256 != _EXPECTED_BASE_CATALOG_SHA256
        or tuple(table for table, _count in snapshot.local_history_counts) != _BASE_TABLES
        or any(
            type(count) is not int or count < 0 for _table, count in snapshot.local_history_counts
        )
    ):
        raise MigrationOperatorError("trusted_time_anchor_catalog_invalid")
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
    """Require exact 0035 schema and absent anchor relations; history may be nonempty."""

    _verify_common_catalog(snapshot, require_client_tls=require_client_tls)
    if (
        snapshot.revision != PRIOR_REVISION
        or snapshot.anchor_relations
        or snapshot.anchor_table_counts
        or snapshot.columns
        or snapshot.constraints
        or snapshot.indexes
    ):
        raise MigrationOperatorError("runtime_preflight_rejected")


def verify_postflight_catalog(
    snapshot: CatalogSnapshot,
    *,
    require_client_tls: bool = True,
) -> None:
    """Require exact reviewed 0036 additive catalog with no implicit backfill."""

    _verify_common_catalog(snapshot, require_client_tls=require_client_tls)
    if (
        snapshot.revision != TARGET_REVISION
        or snapshot.anchor_relations != _EXPECTED_RELATIONS
        or snapshot.anchor_table_counts != tuple((table, 0) for table in _ANCHOR_TABLES)
        or dict(snapshot.columns) != dict(_EXPECTED_COLUMNS)
        or dict(snapshot.constraints) != dict(_EXPECTED_CONSTRAINTS)
        or dict(snapshot.indexes) != dict(_INDEX_CONTRACTS)
    ):
        # This verifier is also run inside the still-rollback-capable migration
        # transaction.  apply_runtime upgrades the outcome to committed=True
        # only after COMMIT is known to have succeeded.
        raise MigrationOperatorError("runtime_postflight_rejected")


def _artifact_body(
    *,
    artifact_type: str,
    static: StaticBindings,
    environment: EnvironmentBindings,
    database: CatalogSnapshot,
    now_seconds: int,
    preflight_artifact_sha256: str | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {
        "artifact_type": artifact_type,
        "bindings": {
            **static.public_payload,
            **environment.public_payload,
            "prior_revision": PRIOR_REVISION,
            "target_revision": TARGET_REVISION,
        },
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


def write_owner_only_artifact(path: Path, payload: Mapping[str, object]) -> str:
    return phase6c_operator.write_owner_only_artifact(path, payload)


def read_and_validate_preflight_artifact(
    path: Path,
    *,
    static: StaticBindings,
    environment: EnvironmentBindings,
    now_seconds: int,
) -> tuple[dict[str, object], str]:
    """Validate canonical owner-only artifact bytes, bindings, and database time."""

    try:
        encoded = read_owner_only_artifact(
            path,
            limit=_MAXIMUM_ARTIFACT_BYTES,
            label="Phase 6D trusted-time anchor migration preflight artifact",
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
    database = body.get("database")
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
        or not isinstance(database, dict)
        or type(database.get("schema_binding_sha256")) is not str
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
    with contextlib.suppress(Exception):
        engine.dispose()


def _set_operator_search_path(connection: Connection) -> None:
    connection.exec_driver_sql("SET LOCAL search_path TO public")


def _database_time_unix_seconds(connection: Connection) -> int:
    return phase6c_operator._database_time_unix_seconds(connection)


def _lock_additive_boundary(connection: Connection, *, mode: str) -> None:
    if mode not in {"ACCESS SHARE", "SHARE ROW EXCLUSIVE"}:
        raise MigrationOperatorError("migration_lock_mode_invalid")
    connection.exec_driver_sql(
        "LOCK TABLE "
        + ", ".join(f'public."{table}"' for table in _ALL_LOCKED_TABLES)
        + f" IN {mode} MODE"
    )


def _verify_operational_revision(
    engine: Engine,
    *,
    revision: str,
    schema_verifier: SchemaVerifier,
) -> None:
    try:
        schema_verifier(
            engine,
            require_phase_zero_facts=False,
            expected_revision=revision,
        )
    except Exception:
        raise MigrationOperatorError("operational_schema_verification_failed") from None


def _reprobe_commit_outcome(
    *,
    database_url: str,
    engine_factory: EngineFactory,
    catalog_reader: CatalogReader,
) -> tuple[bool | None, CatalogSnapshot | None]:
    """Classify an ambiguous COMMIT from one fresh pinned connection."""

    probe_engine: Engine | None = None
    try:
        probe_engine = _new_engine(database_url, engine_factory)
        with probe_engine.begin() as connection:
            _set_operator_search_path(connection)
            _lock_additive_boundary(connection, mode="ACCESS SHARE")
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
    schema_verifier: SchemaVerifier = verify_operational_schema,
) -> dict[str, object]:
    """Verify exact additive readiness and write a short-lived owner-only artifact."""

    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    engine = _new_engine(environment.runtime_database_url, engine_factory)
    try:
        _verify_operational_revision(
            engine,
            revision=PRIOR_REVISION,
            schema_verifier=schema_verifier,
        )
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
    """Execute only the captured reviewed 0036 upgrade via Alembic Operations."""

    if _sha256(bindings.migration_payload) != EXPECTED_MIGRATION_SHA256:
        raise MigrationOperatorError("migration_binding_invalid")
    module = types.ModuleType("aqt_reviewed_phase6_trusted_time_head_anchor_migration")
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
    scripts = ScriptDirectory.from_config(config)
    try:
        with Operations.context(migration_context):
            cast(Callable[[], None], module.__dict__["upgrade"])()
        migration_context.stamp(scripts, TARGET_REVISION)
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
    """Apply the guarded additive transaction and persist postflight evidence."""

    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    engine = _new_engine(environment.runtime_database_url, engine_factory)
    migration_committed: bool | None = False
    commit_attempted = False
    interruption_observed = False
    postflight: CatalogSnapshot | None = None
    preflight_file_sha256 = ""
    try:
        _verify_operational_revision(
            engine,
            revision=PRIOR_REVISION,
            schema_verifier=schema_verifier,
        )
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
                _lock_additive_boundary(connection, mode="SHARE ROW EXCLUSIVE")
                live_preflight = catalog_reader(connection)
                verify_preflight_catalog(live_preflight)
                artifact_time = _database_time_unix_seconds(connection)
                artifact, preflight_file_sha256 = read_and_validate_preflight_artifact(
                    preflight_artifact_path,
                    static=static,
                    environment=environment,
                    now_seconds=artifact_time,
                )
                artifact_database = cast(dict[str, object], artifact["database"])
                if artifact_database.get("schema_binding_sha256") != (
                    live_preflight.schema_binding_sha256
                ):
                    raise MigrationOperatorError("preflight_artifact_stale")
                if check_static_bindings().public_payload != static.public_payload:
                    raise MigrationOperatorError("source_binding_changed")
                current_environment = load_environment_bindings(env_file)
                if current_environment.public_payload != environment.public_payload:
                    raise MigrationOperatorError("owner_environment_changed")
                authorization_time = _database_time_unix_seconds(connection)
                final_artifact, final_file_sha256 = read_and_validate_preflight_artifact(
                    preflight_artifact_path,
                    static=static,
                    environment=environment,
                    now_seconds=authorization_time,
                )
                if final_artifact != artifact or final_file_sha256 != preflight_file_sha256:
                    raise MigrationOperatorError("preflight_artifact_changed")
                migration_runner(connection, static)
                postflight = catalog_reader(connection)
                verify_postflight_catalog(postflight)
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
            outcome, recovered = _reprobe_commit_outcome(
                database_url=environment.runtime_database_url,
                engine_factory=engine_factory,
                catalog_reader=catalog_reader,
            )
            if outcome is None:
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
            assert recovered is not None
            migration_committed = True
            postflight = recovered
            engine = _new_engine(environment.runtime_database_url, engine_factory)
        else:
            migration_committed = True

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
    postflight_artifact = _seal_artifact(
        _artifact_body(
            artifact_type=_POSTFLIGHT_ARTIFACT_TYPE,
            static=static,
            environment=environment,
            database=postflight,
            now_seconds=postflight.database_time_unix_seconds,
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
        help="verify reviewed 0036 bytes, CA, Alembic graph, and source bindings offline",
    )
    test_parser = subparsers.add_parser(
        "test-postgres",
        help="prove exact 0035 -> 0036 only against the designated test PostgreSQL DSN",
    )
    test_parser.add_argument("--env-file", required=True, type=Path)
    preflight_parser = subparsers.add_parser(
        "preflight-runtime",
        help="verify exact 0035 additive readiness and create a short-lived artifact",
    )
    preflight_parser.add_argument("--env-file", required=True, type=Path)
    preflight_parser.add_argument("--artifact", required=True, type=Path)
    apply_parser = subparsers.add_parser(
        "apply-runtime",
        help="apply only exact reviewed revision 0036 after validating preflight evidence",
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
                _safe_failure(MigrationOperatorError("operator_interrupted", interrupted=True)),
                sort_keys=True,
            ),
            flush=True,
        )
        return 130
    print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
