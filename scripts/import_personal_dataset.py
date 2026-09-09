"""Import explicit local Tiingo EOD files into a reproducible research archive."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from packages.adapters.market_data.tiingo_eod import _json
from packages.adapters.market_data.tiingo_eod_calendar import _calendar_from_dict
from packages.adapters.market_data.tiingo_eod_import import (
    OwnerImportedTiingoSource,
    TiingoImportDeclaration,
)
from packages.application.research_dataset import (
    import_research_dataset,
    research_dataset_to_json_bytes,
)


def _read_metadata(path: Path) -> bytes:
    with path.open("rb") as source:
        payload = source.read(1_048_577)
    if len(payload) > 1_048_576:
        raise ValueError("metadata file exceeds the 1 MiB limit")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--declaration", required=True, type=Path)
    parser.add_argument("--calendar", required=True, type=Path)
    parser.add_argument("--source", required=True, action="append", metavar="SYMBOL=PATH")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        paths: dict[str, Path] = {}
        for value in args.source:
            symbol, separator, path = value.partition("=")
            if not separator or not path or symbol in paths:
                raise ValueError("source arguments require unique SYMBOL=PATH bindings")
            paths[symbol] = Path(path)
        declaration = TiingoImportDeclaration.from_json_bytes(_read_metadata(args.declaration))
        calendar = _calendar_from_dict(_json(_read_metadata(args.calendar)), "calendar")
        dataset = import_research_dataset(
            OwnerImportedTiingoSource(
                paths=paths,
                declaration=declaration,
                calendar=calendar,
                imported_at=datetime.now(UTC),
            )
        )
        payload = research_dataset_to_json_bytes(dataset)
        # Exclusive create preserves previous imports. Paid payloads remain owner-readable only.
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
        print(
            json.dumps(
                {
                    "dataset_id": dataset.dataset_id,
                    "data_class": dataset.manifest.data_class.value,
                    "rows": len(dataset.rows),
                    "exclusions": dataset.manifest.exclusions,
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError) as error:
        print(f"dataset import failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
