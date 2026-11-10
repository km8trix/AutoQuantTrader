"""Real E/F/G preparation, without SQL, deadlines or physical-return freshness."""

import copy
import gc
import hashlib
import os
import stat
import sys
import weakref
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from http.cookies import SimpleCookie
from types import SimpleNamespace
from weakref import WeakValueDictionary

import pytest
from fastapi import HTTPException, Response

from apps.api import operational_control_operator_preparation as preparation
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.operational_control_operator_authentication import (
    LocalOperationalControlOperatorStatementAuthenticator,
)
from apps.trader.operational_control_operator_evidence import OperatorStatementEvidenceReader
from packages.adapters.research_artifacts_v2 import (
    LocalResearchArtifactStore,
    ResearchArtifactError,
)
from packages.application.operational_control_operator_authentication import (
    AuthenticatedOperationalControlOperatorStatement,
)
from packages.application.operational_control_operator_preparation import (
    PreparedOperationalControlOperatorStatementRecord,
)
from packages.domain import operational_control_operator_record as record_values
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)
from packages.domain.operational_control_operator_record import (
    OperationalControlOperatorStatementRecord,
    copy_operational_control_operator_statement_record,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.domain.research_job_contracts import ObjectRef

_NOW = datetime(2026, 10, 28, 14, tzinfo=UTC)
_EXPIRY = _NOW + timedelta(hours=8)
_OWNER = "preparation-component-operator"
_ACCOUNT = "preparation-component-account"
_AUTHORITY = "a" * 64
_SECRET = "synthetic-test-only-preparation-configuration"
_PAYLOAD = b"\x00synthetic preparation evidence\xff\n"
_UNSET = object()
_PREPARER = preparation.OperatorStatementRecordPreparer
_AUTH_CODE = LocalOperatorSecurity.authenticate_with_expiry.__code__
_F_CODE = OperatorStatementEvidenceReader.read.__code__
_READ_CODE = LocalResearchArtifactStore.read.__code__
_PUT_CODE = LocalResearchArtifactStore.put.__code__
_INSTALL_CODE = LocalResearchArtifactStore.install_file.__code__
_G_INIT_CODE = OperationalControlOperatorStatementRecord.__init__.__code__
_PREPARED_INIT_CODE = PreparedOperationalControlOperatorStatementRecord.__init__.__code__


class _Clock:
    def __init__(self, *values):
        self.values = list(
            values
            or (
                _NOW + timedelta(seconds=1),
                _NOW + timedelta(seconds=2),
                _NOW + timedelta(seconds=3),
            )
        )
        self.calls = 0
        self.action = None

    def __call__(self):
        self.calls += 1
        if self.action is not None:
            self.action(self.calls)
        if not self.values:
            raise AssertionError("preparer sampled an unselected extra clock value")
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _security():
    return LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id=_OWNER,
        configured_secret=_SECRET,
    )


def _session(security):
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=_NOW, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token


def _statement(digest):
    event = OperationalControlBlockingEvent(
        scope_id=_ACCOUNT,
        sequence_number=1,
        command_id="initial-halted-command",
        command_sha256="b" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=_NOW - timedelta(seconds=2),
    )
    return OperationalControlOperatorStatement(
        scope_id=_ACCOUNT,
        control_transition_id="declared-control-head",
        control_transition_sha256="c" * 64,
        control_sequence_number=1,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="declared-control-epoch",
        blocking_event=event,
        actor=OperationalControlActor(
            actor_id=_OWNER,
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256=_AUTHORITY,
            authenticated_at=_NOW,
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="operator-reviewed",
            resolution_evidence_sha256=digest,
            resolved_at=_NOW - timedelta(seconds=1),
        ),
        authentication_checked_at=_NOW,
        attested_at=_NOW,
        idempotency_key="preparation-component-0001",
    )


@pytest.fixture
def case(tmp_path):
    artifacts = LocalResearchArtifactStore(tmp_path / "objects")
    reference = artifacts.put(_PAYLOAD)
    security = _security()
    cookie, csrf = _session(security)
    issuer = LocalOperationalControlOperatorStatementAuthenticator(
        security, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY
    )
    authenticated = issuer.authenticate(
        _statement(reference.object_sha256), session_cookie=cookie, csrf_token=csrf, now=_NOW
    )
    reader = OperatorStatementEvidenceReader(artifacts, max_bytes=len(_PAYLOAD))
    clock = _Clock()
    return SimpleNamespace(
        artifacts=artifacts,
        reference=reference,
        security=security,
        cookie=cookie,
        csrf=csrf,
        issuer=issuer,
        authenticated=authenticated,
        reader=reader,
        clock=clock,
        preparer=_PREPARER(issuer, reader, clock=clock),
        root=tmp_path / "objects",
        path=tmp_path / "objects" / (reference.object_sha256 + ".json"),
        tmp_path=tmp_path,
    )


def _prepare(case, *, authenticated=_UNSET, reference=_UNSET, cookie=_UNSET, csrf=_UNSET):
    return case.preparer.prepare(
        case.authenticated if authenticated is _UNSET else authenticated,
        case.reference if reference is _UNSET else reference,
        session_cookie=case.cookie if cookie is _UNSET else cookie,
        csrf_token=case.csrf if csrf is _UNSET else csrf,
    )


def _require(case, prepared, *, cookie=_UNSET, csrf=_UNSET):
    return case.preparer.require_prepared(
        prepared,
        session_cookie=case.cookie if cookie is _UNSET else cookie,
        csrf_token=case.csrf if csrf is _UNSET else csrf,
    )


def _inventory(root):
    directory = root.lstat()
    entries = []
    for path in sorted(root.iterdir()):
        metadata = path.lstat()
        entries.append(
            (
                path.name,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None,
                os.readlink(path) if stat.S_ISLNK(metadata.st_mode) else None,
            )
        )
    return directory.st_mode, directory.st_uid, directory.st_ino, tuple(entries)


@contextmanager
def _observe(action=None, *, at=_AUTH_CODE, occurrence=1, constructed=None, prepared_action=None):
    monitor, tool = sys.monitoring, 3
    codes = (_AUTH_CODE, _F_CODE, _READ_CODE, _PUT_CODE, _INSTALL_CODE)
    entries, enabled = [], []
    owned = registered = return_registered = False

    def start(code, offset):
        entries.append(code)
        if action is not None and code is at and sum(item is at for item in entries) == occurrence:
            action()

    def finish(code, offset, returned):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code and returned is None
            value = frame.f_locals["self"]
            if code is _G_INIT_CODE:
                assert type(value) is OperationalControlOperatorStatementRecord
                constructed.append(value)
            else:
                assert code is _PREPARED_INIT_CODE
                assert type(value) is PreparedOperationalControlOperatorStatementRecord
                prepared_action(value)
        finally:
            del frame

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-operator-preparation-unit")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            monitor.set_local_events(tool, code, monitor.events.PY_START)
            enabled.append(code)
        if constructed is not None or prepared_action is not None:
            assert monitor.register_callback(tool, monitor.events.PY_RETURN, finish) is None
            return_registered = True
        if constructed is not None:
            assert monitor.get_local_events(tool, _G_INIT_CODE) == 0
            monitor.set_local_events(tool, _G_INIT_CODE, monitor.events.PY_RETURN)
            enabled.append(_G_INIT_CODE)
        if prepared_action is not None:
            assert monitor.get_local_events(tool, _PREPARED_INIT_CODE) == 0
            monitor.set_local_events(tool, _PREPARED_INIT_CODE, monitor.events.PY_RETURN)
            enabled.append(_PREPARED_INIT_CODE)
        yield entries
    finally:
        try:
            for code in enabled:
                monitor.set_local_events(tool, code, 0)
                assert monitor.get_local_events(tool, code) == 0
        finally:
            try:
                if registered:
                    monitor.register_callback(tool, monitor.events.PY_START, None)
                if return_registered:
                    monitor.register_callback(tool, monitor.events.PY_RETURN, None)
            finally:
                if owned:
                    assert monitor.get_events(tool) == 0
                    monitor.free_tool_id(tool)
                    assert monitor.get_tool(tool) is None


def _counts(entries):
    assert not any(code is _PUT_CODE or code is _INSTALL_CODE for code in entries)
    return tuple(
        sum(code is expected for code in entries) for expected in (_AUTH_CODE, _F_CODE, _READ_CODE)
    )


def test_real_preparation_brackets_original_bytes_with_auth_and_retains_original_operation(case):
    before = _inventory(case.root)
    with _observe() as entries:
        prepared = _prepare(case)
        assert _require(case, prepared) is None
    assert _counts(entries) == (3, 1, 1)
    assert case.clock.calls == 3
    assert type(prepared) is PreparedOperationalControlOperatorStatementRecord
    assert tuple(field.name for field in fields(prepared)) == (
        "record",
        "authenticated",
        "before_read_at",
        "checked_at",
        "seal",
    )
    assert not hasattr(prepared, "__dict__")
    assert prepared.authenticated is case.authenticated
    assert type(prepared.record) is OperationalControlOperatorStatementRecord
    assert type(prepared.record.statement) is OperationalControlOperatorStatement
    assert type(prepared.record.evidence) is ObjectRef
    assert prepared.record.statement is not case.authenticated.statement
    assert prepared.record.evidence is not case.reference
    assert prepared.record.statement.canonical_json == case.authenticated.statement.canonical_json
    assert prepared.record.evidence == case.reference
    assert prepared.record.session_expires_at == case.authenticated.session_expires_at == _EXPIRY
    assert prepared.record.statement.actor.authenticated_at == _NOW
    assert prepared.record.statement.authentication_checked_at == _NOW
    assert prepared.record.statement.attested_at == _NOW
    assert prepared.before_read_at == _NOW + timedelta(seconds=1)
    assert prepared.checked_at == _NOW + timedelta(seconds=2)
    assert prepared.record.statement.control_state is OperationalControlState.HALTED
    with pytest.raises(FrozenInstanceError):
        prepared.checked_at = _NOW
    assert _inventory(case.root) == before


@pytest.mark.parametrize("kind", ["missing", "csrf", "restart", "disabled"])
def test_real_current_auth_denials_happen_before_evidence_read(case, kind):
    cookie, csrf = case.cookie, case.csrf
    if kind == "missing":
        cookie = None
    elif kind == "csrf":
        csrf = "wrong-test-csrf"
    elif kind == "restart":
        case.security._key = _security()._key
    else:
        case.security._enabled = False
    with _observe() as entries, pytest.raises(HTTPException) as caught:
        _prepare(case, cookie=cookie, csrf=csrf)
    assert _counts(entries) == (1, 0, 0)
    assert caught.value.status_code == (403 if kind in ("csrf", "disabled") else 401)
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


@pytest.mark.parametrize("kind", ["copy", "foreign", "replaced-statement", "mutated-content"])
def test_only_original_issued_e_token_can_reach_evidence_io(case, kind):
    authenticated = case.authenticated
    if kind == "copy":
        authenticated = copy.copy(authenticated)
    elif kind == "foreign":
        issuer = LocalOperationalControlOperatorStatementAuthenticator(
            case.security, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY
        )
        authenticated = issuer.authenticate(
            _statement(case.reference.object_sha256),
            session_cookie=case.cookie,
            csrf_token=case.csrf,
            now=_NOW,
        )
    elif kind == "replaced-statement":
        object.__setattr__(authenticated, "statement", replace(authenticated.statement))
    else:
        object.__setattr__(authenticated.statement.resolution_claim, "resolution_code", "changed")
    with _observe() as entries, pytest.raises(ValueError):
        _prepare(case, authenticated=authenticated)
    assert _counts(entries) == (0, 0, 0)
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


@pytest.mark.parametrize(
    "kind", ["before-expiry", "before-operation", "after-expiry", "after-regression"]
)
def test_finite_clock_samples_preserve_expiry_equality_and_ordering(case, kind):
    if kind == "before-expiry":
        case.clock.values = [_EXPIRY]
    elif kind == "before-operation":
        case.clock.values = [_NOW - timedelta(microseconds=1)]
    elif kind == "after-expiry":
        case.clock.values = [_NOW + timedelta(seconds=1), _EXPIRY]
    else:
        case.clock.values = [_NOW + timedelta(seconds=2), _NOW + timedelta(seconds=1)]
    with _observe() as entries, pytest.raises(ValueError):
        _prepare(case)
    assert _counts(entries) == ((0, 0, 0) if kind.startswith("before") else (1, 1, 1))
    assert case.clock.calls == (1 if kind.startswith("before") else 2)
    assert case.authenticated.session_expires_at == _EXPIRY
    assert case.authenticated.statement.attested_at == _NOW
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


def test_expiry_observed_after_genuine_file_work_denies_prepared_delivery(case):
    def expire():
        case.clock.values[0] = _EXPIRY

    before = _inventory(case.root)
    with _observe(expire, at=_READ_CODE) as entries, pytest.raises(ValueError):
        _prepare(case)
    assert _counts(entries) == (1, 1, 1)
    assert case.clock.calls == 2
    assert len(case.preparer._owned) == len(case.preparer._original) == 0
    assert _inventory(case.root) == before


@pytest.mark.parametrize(
    "kind", ["missing", "hash", "length", "file-mode", "symlink", "reader-cap"]
)
def test_original_f_failures_are_preserved_without_writing_repairing_or_retrying(case, kind):
    expected = ResearchArtifactError
    raw_reads = 1
    if kind == "missing":
        case.path.unlink()
        expected = OSError
    elif kind == "hash":
        case.path.write_bytes(_PAYLOAD[::-1])
    elif kind == "length":
        case.reference = replace(case.reference, byte_count=len(_PAYLOAD) - 1)
    elif kind == "file-mode":
        case.path.chmod(0o640)
    elif kind == "symlink":
        target = case.tmp_path / "separate-private-fixture"
        target.write_bytes(_PAYLOAD)
        target.chmod(0o600)
        case.path.unlink()
        case.path.symlink_to(target)
        expected = OSError
    else:
        case.reader = OperatorStatementEvidenceReader(case.artifacts, max_bytes=len(_PAYLOAD) - 1)
        case.preparer = _PREPARER(case.issuer, case.reader, clock=case.clock)
        expected, raw_reads = ValueError, 0
    before = _inventory(case.root)
    with _observe() as entries, pytest.raises(expected):
        _prepare(case)
    assert _counts(entries) == (1, 1, raw_reads)
    assert case.clock.calls == 1
    assert len(case.preparer._owned) == len(case.preparer._original) == 0
    assert _inventory(case.root) == before


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("preparation native admission dispatched an input hook")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __len__ = __str__ = __repr__ = __hash__ = forbidden
            strip = encode = forbidden

        return PoisonString("native-looking")
    if kind == "int":

        class PoisonInteger(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            __int__ = __index__ = __hash__ = __repr__ = forbidden

        return PoisonInteger(1)
    if kind == "timezone":

        class PoisonTimezone(tzinfo):
            utcoffset = dst = tzname = forbidden

        return datetime(2026, 10, 28, 14, tzinfo=PoisonTimezone())
    raise AssertionError("unknown poison kind")


@pytest.mark.parametrize(
    "field,kind",
    [
        ("cookie", "str"),
        ("csrf", "str"),
        ("digest", "str"),
        ("count", "int"),
        ("codec", "str"),
        ("expiry", "timezone"),
    ],
)
def test_native_inputs_precede_the_clock_auth_and_evidence_callbacks(case, field, kind):
    calls = []
    poison = _poison(kind, calls)
    cookie, csrf = case.cookie, case.csrf
    if field == "cookie":
        cookie = poison
    elif field == "csrf":
        csrf = poison
    elif field == "expiry":
        object.__setattr__(case.authenticated, "session_expires_at", poison)
    else:
        name = {"digest": "object_sha256", "count": "byte_count", "codec": "codec_version"}[field]
        object.__setattr__(case.reference, name, poison)
    with _observe() as entries, pytest.raises(ValueError):
        _prepare(case, cookie=cookie, csrf=csrf)
    assert calls == [] and case.clock.calls == 0
    assert _counts(entries) == (0, 0, 0)


@pytest.mark.parametrize("target", ["token", "reference", "preparer"])
def test_foreign_outer_classes_are_rejected_without_borrowing_getters(case, target):
    original = {
        "token": AuthenticatedOperationalControlOperatorStatement,
        "reference": ObjectRef,
        "preparer": _PREPARER,
    }[target]
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign preparation record getter was dispatched")

    foreign = object.__new__(
        type("ForeignPreparationValue", (original,), {"__getattribute__": forbidden})
    )
    with _observe() as entries, pytest.raises(ValueError):
        if target == "preparer":
            _PREPARER.prepare(
                foreign,
                case.authenticated,
                case.reference,
                session_cookie=case.cookie,
                csrf_token=case.csrf,
            )
        else:
            _prepare(case, **{"authenticated" if target == "token" else "reference": foreign})
    assert calls == [] and case.clock.calls == 0
    assert _counts(entries) == (0, 0, 0)


@pytest.mark.parametrize("kind", ["poison", "exception"])
def test_clock_results_and_failures_are_checked_before_borrowed_authentication(case, kind):
    calls = []
    marker = RuntimeError("synthetic fixed clock failure")
    case.clock.values = [_poison("timezone", calls) if kind == "poison" else marker]
    with (
        _observe() as entries,
        pytest.raises(ValueError if kind == "poison" else RuntimeError) as caught,
    ):
        _prepare(case)
    if kind == "exception":
        assert caught.value is marker
    assert calls == [] and case.clock.calls == 1
    assert _counts(entries) == (0, 0, 0)


@pytest.mark.parametrize("field", ["issuer", "reader", "clock", "copy"])
def test_fixed_preparer_configuration_cannot_be_replaced_or_copied(case, field):
    if field == "copy":
        case.preparer = copy.copy(case.preparer)
    else:
        replacements = {
            "issuer": LocalOperationalControlOperatorStatementAuthenticator(
                case.security, scope_id=_ACCOUNT, actor_authority_sha256=_AUTHORITY
            ),
            "reader": OperatorStatementEvidenceReader(case.artifacts, max_bytes=len(_PAYLOAD)),
            "clock": _Clock(),
        }
        object.__setattr__(case.preparer, field, replacements[field])
    with _observe() as entries, pytest.raises(ValueError):
        _prepare(case)
    assert case.clock.calls == 0
    assert _counts(entries) == (0, 0, 0)


def test_original_reference_snapshot_is_retained_when_caller_mutates_it_during_read(case):
    expected = (
        case.reference.object_sha256,
        case.reference.byte_count,
        case.reference.codec_version,
    )

    def mutate():
        object.__setattr__(case.reference, "object_sha256", "f" * 64)
        object.__setattr__(case.reference, "byte_count", 1)
        object.__setattr__(case.reference, "codec_version", "personal-provider-json/1")

    with _observe(mutate, at=_READ_CODE) as entries:
        prepared = _prepare(case)
    actual = prepared.record.evidence
    assert (actual.object_sha256, actual.byte_count, actual.codec_version) == expected
    assert _counts(entries) == (2, 1, 1)
    assert prepared.authenticated is case.authenticated


@pytest.mark.parametrize("phase", ["prepare", "current"])
@pytest.mark.parametrize("component", ["issuer-method", "reader-method", "record-copy"])
def test_changed_original_component_bindings_are_denied_before_borrowed_callbacks(
    case, phase, component
):
    prepared = _prepare(case) if phase == "current" else None
    before_calls = case.clock.calls
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("preparation borrowed a substituted component")

    owner, name = {
        "issuer-method": (
            LocalOperationalControlOperatorStatementAuthenticator,
            "require_authenticated",
        ),
        "reader-method": (OperatorStatementEvidenceReader, "read"),
        "record-copy": (record_values, "copy_operational_control_operator_statement_record"),
    }[component]
    with pytest.MonkeyPatch.context() as local:
        local.setattr(owner, name, forbidden)
        with _observe() as entries, pytest.raises(ValueError):
            if phase == "prepare":
                _prepare(case)
            else:
                _require(case, prepared)
    assert called == []
    assert case.clock.calls == before_calls
    assert _counts(entries) == (0, 0, 0)


@pytest.mark.parametrize("when", ["read", "final-auth"])
def test_changed_owned_e_token_is_denied_after_genuine_callback_boundaries(case, when):
    def mutate():
        object.__setattr__(
            case.authenticated.statement.resolution_claim, "resolution_code", "changed-valid-claim"
        )

    with (
        _observe(
            mutate,
            at=_READ_CODE if when == "read" else _AUTH_CODE,
            occurrence=1 if when == "read" else 2,
        ) as entries,
        pytest.raises(ValueError),
    ):
        _prepare(case)
    assert _counts(entries) == ((1, 1, 1) if when == "read" else (2, 1, 1))
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


def test_preparer_binding_mutation_during_final_auth_denies_delivery(case):
    other = OperatorStatementEvidenceReader(case.artifacts, max_bytes=len(_PAYLOAD))

    def mutate():
        object.__setattr__(case.preparer, "reader", other)

    with _observe(mutate, occurrence=2) as entries, pytest.raises(ValueError):
        _prepare(case)
    assert _counts(entries) == (2, 1, 1)
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


@pytest.mark.parametrize("kind", ["equivalent-evidence", "valid-content"])
def test_genuinely_constructed_return_record_is_bound_before_final_authentication(case, kind):
    constructed, changed = [], []

    def mutate_returned_record():
        frame = sys._getframe()
        try:
            while frame is not None and frame.f_code is not _PREPARER.prepare.__code__:
                frame = frame.f_back
            assert frame is not None
            value = frame.f_locals["returned_record"]
            assert type(value) is OperationalControlOperatorStatementRecord
            assert value is not frame.f_locals["record"]
            assert any(value is original for original in constructed)
            if kind == "equivalent-evidence":
                object.__setattr__(value, "evidence", replace(value.evidence))
            else:
                object.__setattr__(value.evidence, "byte_count", value.evidence.byte_count + 1)
            changed.append(True)
        finally:
            del frame

    with (
        _observe(mutate_returned_record, occurrence=2, constructed=constructed) as entries,
        pytest.raises(ValueError),
    ):
        _prepare(case)
    assert changed == [True]
    assert _counts(entries) == (2, 1, 1)
    assert len(case.preparer._owned) == len(case.preparer._original) == 0


@pytest.mark.parametrize(
    "kind",
    [
        "copy",
        "replace",
        "foreign",
        "record",
        "authenticated",
        "nested",
        "evidence",
        "blocker",
        "actor",
        "expiry",
        "before",
        "checked",
        "seal",
    ],
)
def test_prepared_ownership_identity_and_complete_content_precede_current_callbacks(case, kind):
    prepared = _prepare(case)
    before_calls = case.clock.calls
    if kind == "copy":
        prepared = copy.copy(prepared)
    elif kind == "replace":
        prepared = replace(prepared)
    elif kind == "foreign":
        case.preparer = _PREPARER(case.issuer, case.reader, clock=case.clock)
    elif kind == "record":
        object.__setattr__(
            prepared, "record", copy_operational_control_operator_statement_record(prepared.record)
        )
    elif kind == "authenticated":
        object.__setattr__(prepared, "authenticated", copy.copy(case.authenticated))
    elif kind == "nested":
        object.__setattr__(prepared.record.statement.actor, "actor_id", "changed-valid-actor")
    elif kind == "evidence":
        object.__setattr__(prepared.record, "evidence", replace(prepared.record.evidence))
    elif kind == "blocker":
        object.__setattr__(
            prepared.record.statement,
            "blocking_event",
            replace(prepared.record.statement.blocking_event),
        )
    elif kind == "actor":
        object.__setattr__(
            prepared.record.statement, "actor", replace(prepared.record.statement.actor)
        )
    elif kind == "expiry":
        object.__setattr__(prepared.record, "session_expires_at", _EXPIRY + timedelta(seconds=1))
    elif kind == "before":
        object.__setattr__(
            prepared, "before_read_at", prepared.before_read_at + timedelta(microseconds=1)
        )
    elif kind == "checked":
        object.__setattr__(prepared, "checked_at", prepared.checked_at + timedelta(microseconds=1))
    else:
        object.__setattr__(prepared, "seal", object())
    with _observe() as entries, pytest.raises(ValueError):
        _require(case, prepared)
    assert case.clock.calls == before_calls
    assert _counts(entries) == (0, 0, 0)


def test_current_use_keeps_historical_byte_observation_after_fixture_disappears(case):
    prepared = _prepare(case)
    original = prepared.record.semantic_sha256, prepared.checked_at
    case.path.unlink()
    with _observe() as entries:
        assert _require(case, prepared) is None
    assert _counts(entries) == (1, 0, 0)
    assert (prepared.record.semantic_sha256, prepared.checked_at) == original
    assert not case.path.exists()


@pytest.mark.parametrize("kind", ["expired", "regressed", "csrf", "disabled"])
def test_current_prepared_use_requires_fresh_sample_and_actual_auth_without_f_read(case, kind):
    prepared = _prepare(case)
    csrf = case.csrf
    if kind == "expired":
        case.clock.values = [_EXPIRY]
    elif kind == "regressed":
        case.clock.values = [prepared.checked_at - timedelta(microseconds=1)]
    elif kind == "csrf":
        csrf = "wrong-test-csrf"
    else:
        case.security._enabled = False
    with (
        _observe() as entries,
        pytest.raises(HTTPException if kind in ("csrf", "disabled") else ValueError),
    ):
        _require(case, prepared, csrf=csrf)
    assert _counts(entries) == ((1, 0, 0) if kind in ("csrf", "disabled") else (0, 0, 0))
    assert prepared.record.session_expires_at == _EXPIRY


def test_owned_prepared_content_is_rechecked_after_current_actual_auth(case):
    prepared = _prepare(case)

    def mutate():
        object.__setattr__(prepared.record.evidence, "byte_count", len(_PAYLOAD) + 1)

    with _observe(mutate) as entries, pytest.raises(ValueError):
        _require(case, prepared)
    assert _counts(entries) == (1, 0, 0)


def _retained_leaves(value, excluded, seen=None):
    seen = set() if seen is None else seen
    if any(value is original for original in excluded) or id(value) in seen:
        return []
    seen.add(id(value))
    if type(value) in (str, bytes):
        return [value]
    if isinstance(value, WeakValueDictionary):
        children = tuple(value.values())
    elif type(value) is dict:
        children = (*value.keys(), *value.values())
    elif type(value) in (tuple, list):
        children = value
    elif is_dataclass(value) and not isinstance(value, type):
        children = tuple(getattr(value, field.name) for field in fields(value))
    elif type(value) is _PREPARER:
        children = tuple(getattr(value, name) for name in _PREPARER.__slots__)
    else:
        return []
    result = []
    for child in children:
        result.extend(_retained_leaves(child, excluded, seen))
    return result


def test_prepared_registry_retains_no_credentials_or_raw_bytes_and_releases_collected_values(case):
    prepared = _prepare(case)
    leaves = _retained_leaves(case.preparer, (case.issuer, case.reader, case.clock))
    leaves.extend(_retained_leaves(prepared, (case.issuer, case.reader, case.clock)))
    forbidden = [_PAYLOAD]
    for secret in (case.cookie, case.csrf, _SECRET, case.security._key):
        encoded = secret.encode() if type(secret) is str else secret
        forbidden.extend((secret, encoded, hashlib.sha256(encoded).hexdigest()))
    assert not any(leaf == secret for leaf in leaves for secret in forbidden)
    identity, reference = id(prepared), weakref.ref(prepared)
    assert case.preparer._owned[identity] is prepared
    assert identity in case.preparer._original
    del prepared
    gc.collect()
    assert reference() is None
    assert identity not in case.preparer._owned and identity not in case.preparer._original


@pytest.mark.parametrize(
    "kind", ["equivalent-record", "copied-authenticated", "changed-valid-time"]
)
def test_actual_prepared_constructor_return_cannot_replace_original_issuance_inputs(case, kind):
    changed = []

    def mutate_constructed(value):
        if kind == "equivalent-record":
            object.__setattr__(
                value, "record", copy_operational_control_operator_statement_record(value.record)
            )
        elif kind == "copied-authenticated":
            object.__setattr__(value, "authenticated", copy.copy(value.authenticated))
        else:
            object.__setattr__(value, "checked_at", value.checked_at + timedelta(microseconds=1))
        changed.append(True)

    with _observe(prepared_action=mutate_constructed) as entries, pytest.raises(ValueError):
        _prepare(case)
    assert changed == [True]
    assert _counts(entries) == (2, 1, 1)
    assert case.clock.calls == 2
    assert len(case.preparer._owned) == len(case.preparer._original) == 0
