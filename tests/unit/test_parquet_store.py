from decimal import Decimal
from pathlib import Path

import pyarrow as pa

from packages.datasets import (
    ARROW_SEMANTIC_CHECKSUM_VERSION,
    INPUT_SEMANTIC_CHECKSUM_VERSION,
    LocalParquetObjectStore,
    parquet_semantic_checksum_version,
)
from packages.datasets.parquet import canonicalize_rows


def test_parquet_publication_is_deterministic_for_shuffled_rows(tmp_path: Path) -> None:
    store = LocalParquetObjectStore(tmp_path)
    schema = pa.schema([("sequence", pa.int64()), ("symbol", pa.string())])
    rows = [
        {"sequence": 2, "symbol": "SPY"},
        {"sequence": 1, "symbol": "QQQ"},
    ]

    first = store.write(layer="normalized", rows=rows, schema=schema)
    second = store.write(layer="normalized", rows=list(reversed(rows)), schema=schema)
    changed = store.write(
        layer="normalized",
        rows=[*rows, {"sequence": 3, "symbol": "IWM"}],
        schema=schema,
    )

    assert first == second
    assert first.object_id == first.byte_checksum
    assert first.semantic_checksum == second.semantic_checksum
    assert first.object_key.startswith("normalized/sha256/")
    assert changed.object_id != first.object_id
    assert len(tuple(tmp_path.rglob("*.parquet"))) == 2
    store.verify(first)


def test_arrow_v2_hashes_persisted_values_without_reinterpreting_input_v1(
    tmp_path: Path,
) -> None:
    store = LocalParquetObjectStore(tmp_path)
    schema = pa.schema([("price", pa.decimal128(28, 10))])
    rows = [{"price": Decimal("100.00")}, {"price": Decimal("101.2")}]

    legacy = store.write(
        layer="normalized",
        rows=rows,
        schema=schema,
        semantic_checksum_version=INPUT_SEMANTIC_CHECKSUM_VERSION,
    )
    current = store.write(layer="normalized", rows=rows, schema=schema)
    legacy_table = store.read_table(legacy.object_key)
    current_table = store.read_table(current.object_key)
    _, expected_legacy = canonicalize_rows(
        rows,
        semantic_checksum_version=INPUT_SEMANTIC_CHECKSUM_VERSION,
    )
    _, expected_current = canonicalize_rows(
        current_table.to_pylist(),
        semantic_checksum_version=ARROW_SEMANTIC_CHECKSUM_VERSION,
    )

    assert legacy.semantic_checksum == expected_legacy
    assert current.semantic_checksum == expected_current
    assert legacy.semantic_checksum != current.semantic_checksum
    assert legacy.object_id != current.object_id
    assert parquet_semantic_checksum_version(legacy_table) == INPUT_SEMANTIC_CHECKSUM_VERSION
    assert parquet_semantic_checksum_version(current_table) == ARROW_SEMANTIC_CHECKSUM_VERSION
