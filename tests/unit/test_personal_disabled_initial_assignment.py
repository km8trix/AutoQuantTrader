"""Pure constructor and modeled evaluation-boundary tests, not financial owner proofs.

The two byte vectors were captured before extraction from selection33cc500d and
codec ef21916d; see s4.5c-original-constructor-baseline.json. Codec checks use only
that fixed standard Decimal context. No context-independent wire claim is made.
"""

import base64
import builtins
import hashlib
import socket
import sqlite3
import subprocess
import time
from datetime import UTC, datetime
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.trader import synthetic_initial_selection as selection
from packages.application.personal_codec import decode_record, encode_record
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.engine_contracts import DailyRiskPolicy
from packages.domain.personal_contracts import VersionPin, content_digest

# Full original bytes and three distinct hashes; none is computed from the helper.
_BASELINES = (
    (
        "one-instrument",
        1560,
        "31d40b376246520ebe8a38be5b76fa3fcf3f5b3279e2a131abd5ae3bf54dadb0",
        "27823fbec85259a308821aa584a02325c6c707593677c5bed87cb2380693da51",
        "32e5c18fbde34a635bccce224a9e55f2bc1547a95db20d2b5ef0465591621b27",
        (
            "eyJjb2RlYyI6InBlcnNvbmFsLXJlY29yZC8xIiwidmFsdWUiOnsiJHJlY29yZCI6InBhY2thZ2VzLmRvbWFpbi5k"
            "YWlseV9ydW50aW1lX2NvbnRyYWN0cy5SdW50aW1lUmlza0Fzc2lnbm1lbnQiLCJmaWVsZHMiOnsiYWNjb3VudF9i"
            "aW5kaW5nX3NoYTI1NiI6ImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
            "YWFhYWFhYWFhYWFhYWEiLCJhY2NvdW50X2lkIjoiczQ1Yy1iYXNlbGluZS1vbmUiLCJjb25maWd1cmF0aW9uX3No"
            "YTI1NiI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJi"
            "YmJiYmIiLCJlZmZlY3RpdmVfYXQiOnsiJGRhdGV0aW1lIjoiMjAyNi0xMC0yOFQxNDozMDowMS4yMzQ1NjcrMDA6"
            "MDAifSwiZW5hYmxlZF9mb3JfbmV3X2V4cG9zdXJlIjpmYWxzZSwiZW52aXJvbm1lbnQiOiJzdGF0ZWZ1bF9zaW11"
            "bGF0aW9uIiwiZmluYW5jaW5nX3BvbGljeSI6ImNhc2gtZnVuZGVkLWxvbmctb25seS8xIiwiZ2VuZXJhdGlvbiI6"
            "MSwiaW5zdHJ1bWVudF9zeW1ib2xzIjpbWyJzcHkiLCJTUFkiXV0sImxpdmVfYXV0aG9yaXplZCI6ZmFsc2UsInBv"
            "bGljeSI6eyIkcmVjb3JkIjoicGFja2FnZXMuZG9tYWluLmVuZ2luZV9jb250cmFjdHMuRGFpbHlSaXNrUG9saWN5"
            "IiwiZmllbGRzIjp7ImFkdmVyc2VfcmVzZXJ2ZV9mcmFjdGlvbiI6eyIkZGVjaW1hbCI6IjAuMDEifSwiZGFpbHlf"
            "bG9zc19ib3VuZGFyeSI6eyIkZGVjaW1hbCI6Ii0wLjAzIn0sImRyYXdkb3duX2JvdW5kYXJ5Ijp7IiRkZWNpbWFs"
            "IjoiMC4xNSJ9LCJmZWVfcGVyX3NoYXJlIjp7IiRkZWNpbWFsIjoiMC4wMSJ9LCJtYXhfYmF0Y2hfbmF2X2ZyYWN0"
            "aW9uIjp7IiRkZWNpbWFsIjoiMC45NSJ9LCJtYXhfZ3Jvc3NfbmF2X2ZyYWN0aW9uIjp7IiRkZWNpbWFsIjoiMC45"
            "NSJ9LCJtYXhfbmV3X2ludGVudHNfcGVyX3Nlc3Npb24iOjgsIm1heF9vcGVuX2ludGVudHMiOjQsIm1heF9vcmRl"
            "cl9uYXZfZnJhY3Rpb24iOnsiJGRlY2ltYWwiOiIwLjI1In0sIm1heF9vcmRlcl9xdWFudGl0eSI6eyIkZGVjaW1h"
            "bCI6IjEwMDAifSwibWF4X3Blcl9zeW1ib2xfaW50ZW50cyI6MSwibWF4X3N5bWJvbF9uYXZfZnJhY3Rpb24iOnsi"
            "JGRlY2ltYWwiOiIwLjI1In0sInBvbGljeV9pZCI6InBlcnNvbmFsLWRhaWx5LXN0YXRlZnVsLXNpbXVsYXRpb24v"
            "MSIsInBvbGljeV9zY29wZSI6InByb2R1Y3QifX0sInByZXZpb3VzX2Fzc2lnbm1lbnRfc2hhMjU2IjpudWxsLCJw"
            "cm9kdWNlcl9tYXBfc2hhMjU2IjoiY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj"
            "Y2NjY2NjY2NjY2NjY2NjY2NjYyIsInN0cmF0ZWd5Ijp7IiRyZWNvcmQiOiJwYWNrYWdlcy5kb21haW4ucGVyc29u"
            "YWxfY29udHJhY3RzLlZlcnNpb25QaW4iLCJmaWVsZHMiOnsibmFtZSI6InM0NWMtYmFzZWxpbmUtb25lLXN0cmF0"
            "ZWd5Iiwic2hhMjU2IjoiZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRk"
            "ZGRkZGRkZGRkZGRkZCIsInZlcnNpb24iOiJmaXh0dXJlLzEifX19fX0K"
        ),
    ),
    (
        "four-instrument",
        1604,
        "5bc9b0f85812b92915eeb03be2b131889d26308b43b4ace9d6f6a43bab92b4f4",
        "043c249b58612e9f15d16e02d0943fa1039c6d81320e3a703907e950ff3dc616",
        "f314ddd92fa20a6ab6de78a41cf01a4136d61d664eeb2edd16d21380fc329ff5",
        (
            "eyJjb2RlYyI6InBlcnNvbmFsLXJlY29yZC8xIiwidmFsdWUiOnsiJHJlY29yZCI6InBhY2thZ2VzLmRvbWFpbi5k"
            "YWlseV9ydW50aW1lX2NvbnRyYWN0cy5SdW50aW1lUmlza0Fzc2lnbm1lbnQiLCJmaWVsZHMiOnsiYWNjb3VudF9i"
            "aW5kaW5nX3NoYTI1NiI6ImVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVl"
            "ZWVlZWVlZWVlZWVlZWUiLCJhY2NvdW50X2lkIjoiczQ1Yy1iYXNlbGluZS1mb3VyIiwiY29uZmlndXJhdGlvbl9z"
            "aGEyNTYiOiJmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
            "ZmZmZmZmIiwiZWZmZWN0aXZlX2F0Ijp7IiRkYXRldGltZSI6IjIwMjYtMTEtMDJUMTU6MzA6MDIuMzQ1Njc4KzAw"
            "OjAwIn0sImVuYWJsZWRfZm9yX25ld19leHBvc3VyZSI6ZmFsc2UsImVudmlyb25tZW50Ijoic3RhdGVmdWxfc2lt"
            "dWxhdGlvbiIsImZpbmFuY2luZ19wb2xpY3kiOiJjYXNoLWZ1bmRlZC1sb25nLW9ubHkvMSIsImdlbmVyYXRpb24i"
            "OjEsImluc3RydW1lbnRfc3ltYm9scyI6W1siZGlhIiwiRElBIl0sWyJpd20iLCJJV00iXSxbInFxcSIsIlFRUSJd"
            "LFsic3B5IiwiU1BZIl1dLCJsaXZlX2F1dGhvcml6ZWQiOmZhbHNlLCJwb2xpY3kiOnsiJHJlY29yZCI6InBhY2th"
            "Z2VzLmRvbWFpbi5lbmdpbmVfY29udHJhY3RzLkRhaWx5Umlza1BvbGljeSIsImZpZWxkcyI6eyJhZHZlcnNlX3Jl"
            "c2VydmVfZnJhY3Rpb24iOnsiJGRlY2ltYWwiOiIwLjAxIn0sImRhaWx5X2xvc3NfYm91bmRhcnkiOnsiJGRlY2lt"
            "YWwiOiItMC4wMyJ9LCJkcmF3ZG93bl9ib3VuZGFyeSI6eyIkZGVjaW1hbCI6IjAuMTUifSwiZmVlX3Blcl9zaGFy"
            "ZSI6eyIkZGVjaW1hbCI6IjAuMDEifSwibWF4X2JhdGNoX25hdl9mcmFjdGlvbiI6eyIkZGVjaW1hbCI6IjAuOTUi"
            "fSwibWF4X2dyb3NzX25hdl9mcmFjdGlvbiI6eyIkZGVjaW1hbCI6IjAuOTUifSwibWF4X25ld19pbnRlbnRzX3Bl"
            "cl9zZXNzaW9uIjo4LCJtYXhfb3Blbl9pbnRlbnRzIjo0LCJtYXhfb3JkZXJfbmF2X2ZyYWN0aW9uIjp7IiRkZWNp"
            "bWFsIjoiMC4yNSJ9LCJtYXhfb3JkZXJfcXVhbnRpdHkiOnsiJGRlY2ltYWwiOiIxMDAwIn0sIm1heF9wZXJfc3lt"
            "Ym9sX2ludGVudHMiOjEsIm1heF9zeW1ib2xfbmF2X2ZyYWN0aW9uIjp7IiRkZWNpbWFsIjoiMC4yNSJ9LCJwb2xp"
            "Y3lfaWQiOiJwZXJzb25hbC1kYWlseS1zdGF0ZWZ1bC1zaW11bGF0aW9uLzEiLCJwb2xpY3lfc2NvcGUiOiJwcm9k"
            "dWN0In19LCJwcmV2aW91c19hc3NpZ25tZW50X3NoYTI1NiI6bnVsbCwicHJvZHVjZXJfbWFwX3NoYTI1NiI6IjAx"
            "MjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJz"
            "dHJhdGVneSI6eyIkcmVjb3JkIjoicGFja2FnZXMuZG9tYWluLnBlcnNvbmFsX2NvbnRyYWN0cy5WZXJzaW9uUGlu"
            "IiwiZmllbGRzIjp7Im5hbWUiOiJzNDVjLWJhc2VsaW5lLWZvdXItc3RyYXRlZ3kiLCJzaGEyNTYiOiIxMTExMTEx"
            "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwidmVyc2lv"
            "biI6ImZpeHR1cmUvMiJ9fX19fQo="
        ),
    ),
)

_ARGUMENT_ORDER = (
    "account_id",
    "account_binding_sha256",
    "policy",
    "strategy",
    "configuration_sha256",
    "instrument_symbols",
    "producer_map_sha256",
    "effective_at",
)


def _standard_context():
    return Context(
        prec=28,
        rounding=ROUND_HALF_EVEN,
        Emin=-999999,
        Emax=999999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


def _policy():
    return DailyRiskPolicy(
        policy_id="personal-daily-stateful-simulation/1",
        max_order_quantity=Decimal("1000"),
        max_order_nav_fraction=Decimal("0.25"),
        max_batch_nav_fraction=Decimal("0.95"),
        max_symbol_nav_fraction=Decimal("0.25"),
        max_gross_nav_fraction=Decimal("0.95"),
        adverse_reserve_fraction=Decimal("0.01"),
        fee_per_share=Decimal("0.01"),
        max_open_intents=4,
        max_per_symbol_intents=1,
        max_new_intents_per_session=8,
        daily_loss_boundary=Decimal("-0.03"),
        drawdown_boundary=Decimal("0.15"),
        policy_scope="product",
    )


def _inputs(index):
    if index == 0:
        return {
            "account_id": "s45c-baseline-one",
            "account_binding_sha256": "a" * 64,
            "policy": _policy(),
            "strategy": VersionPin("s45c-baseline-one-strategy", "fixture/1", "d" * 64),
            "configuration_sha256": "b" * 64,
            "instrument_symbols": (("spy", "SPY"),),
            "producer_map_sha256": "c" * 64,
            "effective_at": datetime(2026, 10, 28, 14, 30, 1, 234567, tzinfo=UTC),
        }
    assert index == 1
    return {
        "account_id": "s45c-baseline-four",
        "account_binding_sha256": "e" * 64,
        "policy": _policy(),
        "strategy": VersionPin("s45c-baseline-four-strategy", "fixture/2", "1" * 64),
        "configuration_sha256": "f" * 64,
        "instrument_symbols": (("dia", "DIA"), ("iwm", "IWM"), ("qqq", "QQQ"), ("spy", "SPY")),
        "producer_map_sha256": "0123456789abcdef" * 4,
        "effective_at": datetime(2026, 11, 2, 15, 30, 2, 345678, tzinfo=UTC),
    }


def _assert_fields(record, values):
    assert type(record) is RuntimeRiskAssignment
    for name in _ARGUMENT_ORDER:
        assert getattr(record, name) == values[name]
    for name in ("policy", "strategy", "instrument_symbols", "effective_at"):
        assert getattr(record, name) is values[name]
    assert type(record.generation) is int and record.generation == 1
    assert record.previous_assignment_sha256 is None
    assert record.enabled_for_new_exposure is False
    assert record.live_authorized is False
    assert record.environment == "stateful_simulation"
    assert record.financing_policy == "cash-funded-long-only/1"
    assert record.contract_version == "personal-daily-runtime-risk/1"


@pytest.mark.parametrize("index", [0, 1], ids=["one-instrument", "four-instruments"])
def test_literal_original_bytes_defaults_and_nested_identity_without_effects(index):
    with localcontext(_standard_context()):
        values = _inputs(index)
        assert values["policy"] == DailyRiskPolicy(policy_id="personal-daily-stateful-simulation/1")
        effects = []

        def forbidden(*args, **kwargs):
            effects.append("unexpected-effect")
            raise AssertionError("pure assignment construction attempted an effect")

        # These traps cover only the direct helper invocation, not pytest,
        # import machinery, codec operations, or genuine owner validation.
        with pytest.MonkeyPatch.context() as local:
            for target, name in (
                (builtins, "open"),
                (Path, "open"),
                (Path, "read_bytes"),
                (Path, "write_bytes"),
                (socket, "socket"),
                (sqlite3, "connect"),
                (subprocess, "Popen"),
                (time, "time"),
                (time, "monotonic"),
                (time, "monotonic_ns"),
                (selection, "_current"),
                (selection, "_require_owners"),
            ):
                local.setattr(target, name, forbidden)
            record = selection._default_synthetic_initial_assignment(**values)
        assert effects == []
        _assert_fields(record, values)
        name, size, raw_sha, semantic_sha, generic_sha, encoded = _BASELINES[index]
        assert name == ("one-instrument" if index == 0 else "four-instrument")
        original_bytes = base64.b64decode(encoded, validate=True)
        assert len(original_bytes) == size
        assert hashlib.sha256(original_bytes).hexdigest() == raw_sha
        payload = encode_record(record)
        assert payload == original_bytes
        assert len(payload) == size
        assert hashlib.sha256(payload).hexdigest() == raw_sha
        assert record.semantic_sha256 == semantic_sha
        assert content_digest(record) == generic_sha
        assert semantic_sha != generic_sha
        restored = decode_record(payload, RuntimeRiskAssignment)
        assert type(restored) is RuntimeRiskAssignment
        assert restored == record and restored is not record
        assert encode_record(restored) == original_bytes
        assert restored.semantic_sha256 == semantic_sha
        assert content_digest(restored) == generic_sha


@pytest.mark.parametrize("invalid", ["naive-time", "configuration-digest", "policy-id"])
def test_helper_retains_original_constructor_denials(invalid):
    with localcontext(_standard_context()):
        values = _inputs(0)
        if invalid == "naive-time":
            values["effective_at"] = datetime(2026, 10, 28, 14, 30, 1)
        elif invalid == "configuration-digest":
            values["configuration_sha256"] = "not-a-digest"
        else:
            # A valid original policy record with the wrong runtime policy ID.
            values["policy"] = DailyRiskPolicy()
        with pytest.raises(ValueError) as original:
            RuntimeRiskAssignment(
                account_id=values["account_id"],
                account_binding_sha256=values["account_binding_sha256"],
                generation=1,
                policy=values["policy"],
                strategy=values["strategy"],
                configuration_sha256=values["configuration_sha256"],
                instrument_symbols=values["instrument_symbols"],
                producer_map_sha256=values["producer_map_sha256"],
                effective_at=values["effective_at"],
                previous_assignment_sha256=None,
                enabled_for_new_exposure=False,
                live_authorized=False,
            )
        with pytest.raises(ValueError) as extracted:
            selection._default_synthetic_initial_assignment(**values)
        assert type(extracted.value) is type(original.value)
        assert str(extracted.value) == str(original.value)


class _Leaves:
    """Modeled getters for expression order only; never admitted real owners."""

    def __init__(self, values, labels, trace, failure_label=None, failure=None):
        self.values = values
        self.labels = labels
        self.trace = trace
        self.failure_label = failure_label
        self.failure = failure

    def __getattr__(self, name):
        if name not in self.values:
            raise AttributeError(name)
        label = self.labels.get(name)
        if label is not None:
            self.trace.append(label)
            if label == self.failure_label:
                raise self.failure
        return self.values[name]


def _modeled_boundary(monkeypatch, *, fail_at=None, change_alias=False):
    values = _inputs(0)
    configuration = (("lookback", 2), ("warmup", 2))
    values["configuration_sha256"] = content_digest(configuration)
    trace = []
    current_calls = []
    dependency_calls = []
    substitute_calls = []
    primary = LookupError("modeled original expression failed")
    dependency_stop = LookupError("stop before any genuine dependency preparation")

    def leaves(data, labels, failure_label=None):
        return _Leaves(data, labels, trace, failure_label, primary)

    genesis = SimpleNamespace(
        scope=leaves(
            {
                "account_id": values["account_id"],
                "account_binding_sha256": values["account_binding_sha256"],
            },
            {"account_id": "account_id", "account_binding_sha256": "account_binding_sha256"},
        )
    )
    spec = leaves(
        {
            "risk_policy": values["policy"],
            "strategy": values["strategy"],
            "strategy_configuration": configuration,
            "instruments": values["instrument_symbols"],
        },
        {"risk_policy": "policy", "strategy": "strategy", "instruments": "instrument_symbols"},
    )
    previous = SimpleNamespace(checkpoint=SimpleNamespace(inputs=SimpleNamespace(spec=spec)))
    current = SimpleNamespace(
        raw=SimpleNamespace(
            receipt=leaves(
                {"validated_at": values["effective_at"]}, {"validated_at": "effective_at"}
            )
        )
    )
    fence = object()
    lease = SimpleNamespace(fence=fence)

    def stop_before_dependencies(*, previous, proposed, fence):
        dependency_calls.append((previous, proposed, fence))
        trace.append("dependency-boundary")
        raise dependency_stop

    def forbidden_owner_operation(*args, **kwargs):
        raise AssertionError("modeled order test reached a later owner operation")

    owners = SimpleNamespace(
        runtime=SimpleNamespace(
            producer_map=leaves(
                {"semantic_sha256": values["producer_map_sha256"]},
                {"semantic_sha256": "producer_map_sha256"},
                fail_at if fail_at == "producer_map_sha256" else None,
            )
        ),
        owners=SimpleNamespace(
            prepare_dependencies=stop_before_dependencies,
            require_prepared=forbidden_owner_operation,
        ),
    )

    def replacement(*args, **kwargs):
        substitute_calls.append("replacement")
        raise AssertionError("captured original helper was redirected")

    def modeled_current(given_genesis, given_owners, given_lease):
        current_calls.append((given_genesis, given_owners, given_lease))
        if change_alias:
            # The production caller has already captured its original helper.
            monkeypatch.setattr(selection, "_DEFAULT_SYNTHETIC_INITIAL_ASSIGNMENT", replacement)
        return previous, current

    def original_digest(value):
        assert value is configuration
        trace.append("configuration_sha256")
        if fail_at == "configuration_sha256":
            raise primary
        return content_digest(value)

    monkeypatch.setattr(selection, "_current", modeled_current)
    monkeypatch.setattr(selection, "content_digest", original_digest)
    monkeypatch.setattr(selection, "_require_owners", forbidden_owner_operation)
    return SimpleNamespace(
        values=values,
        genesis=genesis,
        owners=owners,
        lease=lease,
        previous=previous,
        fence=fence,
        trace=trace,
        current_calls=current_calls,
        dependency_calls=dependency_calls,
        substitute_calls=substitute_calls,
        primary=primary,
        dependency_stop=dependency_stop,
    )


def _call_modeled(model):
    return selection.prepare_synthetic_initial_selection(
        model.genesis, owners=model.owners, lease=model.lease
    )


def _assert_dependency_boundary(model):
    assert model.current_calls == [(model.genesis, model.owners, model.lease)]
    assert model.trace == [*_ARGUMENT_ORDER, "dependency-boundary"]
    assert len(model.dependency_calls) == 1
    previous, proposed, fence = model.dependency_calls[0]
    assert previous is model.previous and fence is model.fence
    _assert_fields(proposed, model.values)


def test_modeled_caller_retains_all_eight_expression_evaluations_before_dependencies(monkeypatch):
    with localcontext(_standard_context()):
        model = _modeled_boundary(monkeypatch)
        with pytest.raises(LookupError) as caught:
            _call_modeled(model)
        assert caught.value is model.dependency_stop
        _assert_dependency_boundary(model)
        assert model.substitute_calls == []


@pytest.mark.parametrize(
    "fail_at,prefix_length",
    [("configuration_sha256", 5), ("producer_map_sha256", 7)],
)
def test_modeled_original_argument_error_preserves_identity_and_stops_later_reads(
    monkeypatch, fail_at, prefix_length
):
    with localcontext(_standard_context()):
        model = _modeled_boundary(monkeypatch, fail_at=fail_at)
        with pytest.raises(LookupError) as caught:
            _call_modeled(model)
        assert caught.value is model.primary
        assert model.current_calls == [(model.genesis, model.owners, model.lease)]
        assert model.trace == list(_ARGUMENT_ORDER[:prefix_length])
        assert model.dependency_calls == []
        assert model.substitute_calls == []


def test_named_helper_substitution_denies_before_current_or_dependency_access(monkeypatch):
    calls = []

    def replacement(*args, **kwargs):
        calls.append("replacement")
        raise AssertionError("substitute must never be called")

    def current(*args, **kwargs):
        calls.append("current")
        raise AssertionError("binding denial must precede current owner validation")

    class Untouched:
        def __getattr__(self, name):
            calls.append("attribute")
            raise AssertionError("binding denial must precede graph access")

    monkeypatch.setattr(selection, "_default_synthetic_initial_assignment", replacement)
    monkeypatch.setattr(selection, "_current", current)
    with pytest.raises(RuntimeError, match=r"^SYNTHETIC_INITIAL_ASSIGNMENT_BINDING_CHANGED$"):
        selection.prepare_synthetic_initial_selection(
            Untouched(), owners=Untouched(), lease=Untouched()
        )
    assert calls == []


def test_alias_change_after_capture_does_not_redirect_original_constructor(monkeypatch):
    with localcontext(_standard_context()):
        model = _modeled_boundary(monkeypatch, change_alias=True)
        with pytest.raises(LookupError) as caught:
            _call_modeled(model)
        assert caught.value is model.dependency_stop
        _assert_dependency_boundary(model)
        assert model.substitute_calls == []
