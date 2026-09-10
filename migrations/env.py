"""Alembic migration environment."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from packages.persistence.postgres_tls import pinned_verify_full_connect_args
from packages.persistence.research_catalog_schema import RESEARCH_CATALOG_TABLES
from packages.persistence.research_schema_v2 import RESEARCH_TABLES_V2
from packages.persistence.schema import metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

explicit_database_url = config.attributes.get("aqt_explicit_database_url")
database_url = (
    explicit_database_url
    if isinstance(explicit_database_url, str)
    else os.getenv("AQT_DATABASE_URL")
)
if database_url:
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

target_metadata = metadata
assert all(
    table.metadata is target_metadata for table in (*RESEARCH_TABLES_V2, *RESEARCH_CATALOG_TABLES)
)


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configured_url = config.get_main_option("sqlalchemy.url")
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=pinned_verify_full_connect_args(configured_url, required=False),
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
