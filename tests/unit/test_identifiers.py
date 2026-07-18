from decimal import Decimal

import pytest

from packages.domain.identifiers import canonical_id, deterministic_id


def test_legacy_deterministic_id_behavior_is_preserved() -> None:
    assert deterministic_id("target", "a:b", "c") == ("6bdc67d8-2748-5cd4-879e-f82014280483")
    assert deterministic_id("target", "a:b", "c") == deterministic_id(
        "target",
        "a",
        "b:c",
    )


def test_canonical_id_is_stable_typed_and_delimiter_safe() -> None:
    assert canonical_id("target", "a:b", "c") == ("c1ae012c-1624-59fc-a277-f7087eda1325")
    assert canonical_id("target", "a:b", "c") != canonical_id(
        "target",
        "a",
        "b:c",
    )
    assert canonical_id("target", 1) != canonical_id("target", "1")
    assert canonical_id("target", ("a", "b")) != canonical_id("target", ["a", "b"])
    assert canonical_id("target", Decimal("10.0")) == canonical_id(
        "target",
        Decimal("10.00"),
    )


@pytest.mark.parametrize("kind", ["", " target", "target "])
def test_canonical_id_requires_a_trimmed_kind(kind: str) -> None:
    with pytest.raises(ValueError, match="non-empty, trimmed"):
        canonical_id(kind, "part")
