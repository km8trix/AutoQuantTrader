from pathlib import Path

import pyarrow as pa

from packages.datasets import LocalParquetObjectStore


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
