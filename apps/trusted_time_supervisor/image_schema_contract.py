"""Fixed, read-only projection of the installed operational schema contract."""

from __future__ import annotations

import sys

from packages.persistence.schema import metadata

_TARGET_ID = "image-schema-contract"
_RELATION_PREFIX = "phase6_trusted_time_head_anchor_"
_FAILURE_MESSAGE = "trusted-time operational schema contract probe failed\n"
EXPECTED_SCHEMA_REVISION = "0036_phase6_time_anchors"
_INSTALLED_RELATION_TUPLE = tuple(
    sorted(
        name
        for name in metadata.tables
        if type(name) is str and name.startswith("phase6_trusted_time_head_anchor_")
    )
)


def _schema_contract_bytes(
    *,
    _installed_relations: object = _INSTALLED_RELATION_TUPLE,
    _installed_revision: object = EXPECTED_SCHEMA_REVISION,
) -> bytes:
    """Return the sole literal receipt after checking the installed objects exactly."""

    if (
        type(_installed_relations) is not tuple
        or _installed_relations
        != (
            "phase6_trusted_time_head_anchor_intents",
            "phase6_trusted_time_head_anchor_receipts",
        )
        or type(_installed_revision) is not str
        or _installed_revision != "0036_phase6_time_anchors"
    ):
        raise ValueError
    return (
        b'{"catalog_relations":["phase6_trusted_time_head_anchor_intents",'
        b'"phase6_trusted_time_head_anchor_receipts"],'
        b'"schema_revision":"0036_phase6_time_anchors"}'
    )


def schema_contract_main(*, _emit: object = _schema_contract_bytes) -> None:
    """Emit one canonical installed-schema receipt for the exact launcher target."""

    stdout_write = sys.stdout.write
    stderr_write = sys.stderr.write
    try:
        if type(sys.argv) is not list or sys.argv != ["image-schema-contract"]:
            raise ValueError
        if not callable(_emit):
            raise ValueError
        encoded = _emit()
        if type(encoded) is not bytes:
            raise ValueError
        stdout_write(encoded.decode("ascii") + "\n")
    except BaseException:
        stderr_write("trusted-time operational schema contract probe failed\n")
        raise SystemExit(2) from None


__all__: tuple[()] = ()
