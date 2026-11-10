"""Pure fixed hold-revision CASE profile; no fixture, SQL, or history authority."""

from copy import copy
from operator import ge, le

import pytest
import sqlalchemy as sa
from sqlalchemy.sql.elements import Case

from packages.persistence import continuous_integrity as integrity
from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_events as holds


def original_case(*, empty=False):
    limits = {} if empty else {"synthetic-hold-a": 1, "synthetic-hold-b": 2}
    result = sa.case(limits, value=holds.c.hold_id, else_=0)
    # Keep mutation tests isolated from SQLAlchemy's shared default literal types.
    result.type = copy(result.type)
    result.else_.type = copy(result.else_.type)
    for key, revision in result.whens:
        key.type, revision.type = copy(key.type), copy(revision.type)
    return result


def seal(case):
    return integrity._factory_structure((holds.c.revision <= case,))


@pytest.mark.parametrize("empty", [False, True])
def test_exact_original_case_shape_is_sealed_without_sql(empty):
    case = original_case(empty=empty)
    records = seal(case)
    assert sum(kind == "fields" and item is case for kind, item, *_ in records) == 1
    assert any(item is case.whens for _, item, *_ in records)
    integrity._require_factory_structure(records)


@pytest.mark.parametrize("kind", ["foreign_value", "foreign_left", "wrong_operator", "subclass"])
def test_only_original_hold_columns_operator_and_exact_case_are_accepted(kind):
    case = original_case()
    left, operator = holds.c.revision, le
    if kind == "foreign_value":
        case.value = sa.column("hold_id")
    elif kind == "foreign_left":
        left = holds.c.account_id
    elif kind == "wrong_operator":
        operator = ge
    else:

        class OtherCase(Case):
            pass

        case = OtherCase({"synthetic-hold": 1}, value=holds.c.hold_id, else_=0)
    with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN"):
        integrity._factory_structure((operator(left, case),))


@pytest.mark.parametrize(
    "fault",
    [
        "tuple_whens",
        "list_pair",
        "short_pair",
        "long_pair",
        "unknown_bind",
        "bool_key",
        "int_key",
        "bool_revision",
        "str_revision",
        "negative_revision",
        "bool_default",
        "nonzero_default",
        "key_sql_type",
        "revision_sql_type",
        "default_sql_type",
        "case_sql_type",
        "key_length",
        "key_collation",
    ],
)
def test_unknown_case_shape_does_not_expand_the_sql_profile(fault):
    case = original_case()
    if fault == "tuple_whens":
        case.whens = tuple(case.whens)
    elif fault == "list_pair":
        case.whens[0] = list(case.whens[0])
    elif fault == "short_pair":
        case.whens[0] = case.whens[0][:1]
    elif fault == "long_pair":
        case.whens[0] = (*case.whens[0], case.whens[0][1])
    elif fault == "unknown_bind":
        case.whens[0] = (object(), case.whens[0][1])
    elif fault == "bool_key":
        case.whens[0][0].value = True
    elif fault == "int_key":
        case.whens[0][0].value = 1
    elif fault == "bool_revision":
        case.whens[0][1].value = True
    elif fault == "str_revision":
        case.whens[0][1].value = "1"
    elif fault == "negative_revision":
        case.whens[0][1].value = -1
    elif fault == "bool_default":
        case.else_.value = False
    elif fault == "nonzero_default":
        case.else_.value = 1
    elif fault == "key_sql_type":
        case.whens[0][0].type = sa.Integer()
    elif fault == "revision_sql_type":
        case.whens[0][1].type = sa.String()
    elif fault == "default_sql_type":
        case.else_.type = sa.String()
    elif fault == "case_sql_type":
        case.type = sa.String()
    elif fault == "key_length":
        case.whens[0][0].type.length = 10
    else:
        case.whens[0][0].type.collation = "synthetic-collation"
    with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN_SQL_CASE"):
        seal(case)


@pytest.mark.parametrize("location", ["key", "revision", "default"])
@pytest.mark.parametrize("flag", ["callable", "expanding", "expand_op", "literal_execute"])
def test_case_requires_original_literal_bind_flags(location, flag):
    case = original_case()
    bind = {"key": case.whens[0][0], "revision": case.whens[0][1], "default": case.else_}[location]
    setattr(
        bind, flag, (lambda: pytest.fail("dynamic bind called")) if flag == "callable" else True
    )
    with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN_SQL_CASE"):
        seal(case)


@pytest.mark.parametrize("bound", ["edges", "containers"])
def test_case_preflights_original_bounds_before_scanning_invalid_pairs(monkeypatch, bound):
    case = original_case()
    case.whens = [object(), object(), object()]
    monkeypatch.setattr(
        integrity, "_MAX_FACTORY_BINDINGS" if bound == "edges" else "_MAX_FACTORY_CONTAINERS", 4
    )
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((case,))


@pytest.mark.parametrize(
    "fault",
    [
        "value",
        "when_list",
        "order",
        "pair_copy",
        "key",
        "revision",
        "default",
        "else_bind",
        "case_type",
        "key_type",
        "integer_class",
        "string_class",
        "key_length",
        "key_collation",
        "bind_callable",
        "bind_expanding",
        "bind_expand_op",
        "bind_literal_execute",
    ],
)
def test_original_case_and_nested_identity_or_type_mutation_is_rejected(fault):
    case = original_case()
    records = seal(case)
    if fault == "value":
        case.value = holds.c.account_id
    elif fault == "when_list":
        case.whens = list(case.whens)
    elif fault == "order":
        case.whens.reverse()
    elif fault == "pair_copy":
        case.whens[0] = tuple(list(case.whens[0]))
    elif fault == "key":
        case.whens[0][0].value = "changed-synthetic-hold"
    elif fault == "revision":
        case.whens[0][1].value = 8
    elif fault == "default":
        case.else_.value = 9
    elif fault == "else_bind":
        case.else_ = copy(case.else_)
    elif fault == "case_type":
        case.type = copy(case.type)
    elif fault == "key_type":
        case.whens[0][0].type = copy(case.whens[0][0].type)
    elif fault == "integer_class":

        class OtherInteger(sa.Integer):
            pass

        case.type.__class__ = OtherInteger
    elif fault == "string_class":

        class OtherString(sa.String):
            pass

        case.whens[0][0].type.__class__ = OtherString
    elif fault == "key_length":
        case.whens[0][0].type.length = 12
    elif fault == "key_collation":
        case.whens[0][0].type.collation = "changed-synthetic-collation"
    else:
        setattr(case.whens[0][1], fault.removeprefix("bind_"), object())
    with pytest.raises(integrity.ContinuousIntegrityError, match=r"STRUCTURE_CHANGED|TYPE_CHANGED"):
        integrity._require_factory_structure(records)
