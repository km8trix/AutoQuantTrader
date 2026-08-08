from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import sqlalchemy as sa

import scripts.diagnose_trusted_time_runtime as diagnostic
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorAuthenticationError,
    SupabaseStorageAnchorAuthenticationResponseError,
    SupabaseStorageAnchorAuthPasswordTokenRequestTargetError,
    SupabaseStorageAnchorAuthPasswordTokenResponseBoundError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError,
    SupabaseStorageAnchorAuthPasswordTokenResponseError,
    SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError,
    SupabaseStorageAnchorAuthUserVerificationResponseError,
    SupabaseStorageAnchorBoundedListResponseError,
    SupabaseStorageAnchorError,
    SupabaseStorageAnchorResponseError,
    SupabaseStorageAnchorStorageAccessError,
    SupabaseStorageAnchorUnavailable,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TrustedTimeHeadAnchorProviderIdentity,
    trusted_time_head_anchor_object_prefix,
)
from scripts.start_trusted_time_supervisor import (
    TrustedTimeHeadAnchorSourcePayloads,
    TrustedTimeRuntimeConfiguration,
)

ROOT = Path(__file__).resolve().parents[2]
SECRET_DSN = "postgresql+psycopg://secret-user:secret-password@secret.invalid/postgres"
SECRET_TOKEN = "secret-provider-token-sentinel"


def _authority() -> SimpleNamespace:
    return SimpleNamespace(
        anchor_authority_sha256="c" * 64,
        anchor_project_identity_sha256="a" * 64,
        anchor_project_ref="abcdefghijklmnopqrst",
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        deployment_identity_sha256="b" * 64,
        host_id="local-paper-docker-primary-v1",
        principal_id="12345678-1234-4234-9234-123456789abc",
        runtime_database_identity_sha256="d" * 64,
        signing_key_id="phase6d.test.signing-key-v1",
        signing_public_key_bytes=b"p" * 32,
        signing_public_key_sha256="e" * 64,
    )


def _runtime() -> SimpleNamespace:
    return SimpleNamespace(
        authority=_authority(),
        credentials=SimpleNamespace(secret=SECRET_TOKEN),
        database_url=SECRET_DSN,
        verifier=object(),
    )


def _aggregate(*, evaluations: int = 8) -> diagnostic.LocalAggregate:
    return diagnostic.LocalAggregate(
        epoch_count=8,
        latest_epoch_evaluation_count=evaluations,
        intent_count=0,
        receipt_count=0,
    )


def _snapshot() -> diagnostic.LocalSnapshotSummary:
    return diagnostic.LocalSnapshotSummary(
        local_transition_count=23,
        confirmed_anchor_count=0,
        pending_intent=False,
    )


def test_success_runs_local_gates_before_provider_and_emits_only_aggregates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    dispose = Mock(side_effect=lambda: calls.append("dispose"))
    monkeypatch.setattr(engine, "dispose", dispose)
    runtime = _runtime()

    def configured(_: Path) -> object:
        calls.append("configuration")
        return runtime

    def created_engine(_: str) -> sa.Engine:
        calls.append("engine")
        return engine

    def read_aggregate(*_args: object, **_kwargs: object) -> diagnostic.LocalAggregate:
        calls.append("aggregate")
        return _aggregate()

    def authenticated_snapshot(
        *_args: object, **_kwargs: object
    ) -> diagnostic.LocalSnapshotSummary:
        calls.append("snapshot")
        return _snapshot()

    monkeypatch.setattr(
        diagnostic,
        "_decode_runtime_configuration",
        configured,
    )
    monkeypatch.setattr(
        diagnostic,
        "create_read_only_qualification_engine",
        created_engine,
    )
    monkeypatch.setattr(
        diagnostic,
        "_verify_database_connection",
        lambda _: calls.append("connection"),
    )
    monkeypatch.setattr(
        diagnostic,
        "verify_operational_schema",
        lambda *_args, **_kwargs: calls.append("schema"),
    )
    monkeypatch.setattr(
        diagnostic,
        "verify_trusted_time_integrity",
        lambda _: calls.append("integrity"),
    )
    monkeypatch.setattr(
        diagnostic,
        "_read_local_aggregate",
        read_aggregate,
    )
    monkeypatch.setattr(
        diagnostic,
        "_authenticate_local_startup_snapshot",
        authenticated_snapshot,
    )
    monkeypatch.setattr(
        diagnostic,
        "_verify_provider_stable_zero",
        lambda **_kwargs: calls.append("provider"),
    )

    payload = diagnostic.diagnose_trusted_time_runtime(
        env_file=Path("/not-opened/exact-four-launch.env")
    )
    encoded = diagnostic.canonical_json_bytes(payload)

    assert calls == [
        "configuration",
        "engine",
        "connection",
        "schema",
        "integrity",
        "aggregate",
        "snapshot",
        "aggregate",
        "provider",
        "dispose",
    ]
    assert encoded.endswith(b"\n")
    assert encoded == diagnostic.canonical_json_bytes(json.loads(encoded))
    assert SECRET_DSN.encode() not in encoded
    assert SECRET_TOKEN.encode() not in encoded
    assert payload == {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "contract_version": diagnostic.CONTRACT_VERSION,
        "database_secret_disclosed": False,
        "database": {
            "exact_schema": True,
            "integrity_verified": True,
            "schema_revision_current": True,
        },
        "exposure_authorized": False,
        "external_head_anchor_authorized": False,
        "head_anchor": {
            "authenticated_startup_snapshot": True,
            "intent_count": 0,
            "provider_identity_authenticated": True,
            "provider_prefix_stable_zero": True,
            "receipt_count": 0,
        },
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "outcome_code": diagnostic.OUTCOME_PASSED,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "status": "passed",
        "trusted_time": {
            "epoch_count": 8,
            "latest_epoch_evaluation_count": 8,
            "local_transition_count": 23,
        },
    }


def test_local_failure_is_sanitized_and_provider_is_never_constructed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    provider = Mock(side_effect=AssertionError("provider must remain untouched"))
    monkeypatch.setattr(diagnostic, "_decode_runtime_configuration", lambda _: _runtime())
    monkeypatch.setattr(diagnostic, "create_read_only_qualification_engine", lambda _: engine)
    monkeypatch.setattr(diagnostic, "_verify_database_connection", lambda _: None)
    monkeypatch.setattr(
        diagnostic,
        "verify_operational_schema",
        Mock(side_effect=RuntimeError(f"failure {SECRET_DSN} {SECRET_TOKEN}")),
    )
    monkeypatch.setattr(diagnostic, "_verify_provider_stable_zero", provider)

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic.diagnose_trusted_time_runtime(env_file=Path("/not-opened/exact-four-launch.env"))

    assert raised.value.outcome_code == diagnostic.OUTCOME_DATABASE_SCHEMA_REJECTED
    encoded = diagnostic.canonical_json_bytes(diagnostic.failure_payload(raised.value.outcome_code))
    assert SECRET_DSN.encode() not in encoded
    assert SECRET_TOKEN.encode() not in encoded
    assert all(
        encoded_value is False
        for key, encoded_value in json.loads(encoded).items()
        if key.endswith("_authorized") or key == "database_secret_disclosed"
    )
    provider.assert_not_called()


@pytest.mark.parametrize(
    ("stage", "expected_code"),
    [
        ("configuration", diagnostic.OUTCOME_DATABASE_CONFIGURATION_REJECTED),
        ("connection", diagnostic.OUTCOME_DATABASE_CONNECTION_REJECTED),
        ("schema", diagnostic.OUTCOME_DATABASE_SCHEMA_REJECTED),
        ("integrity", diagnostic.OUTCOME_TRUSTED_TIME_INTEGRITY_REJECTED),
        ("aggregate", diagnostic.OUTCOME_LOCAL_AGGREGATE_REJECTED),
        ("snapshot", diagnostic.OUTCOME_LOCAL_SNAPSHOT_REJECTED),
    ],
)
def test_each_local_stage_has_one_fixed_outcome_and_provider_remains_untouched(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    expected_code: str,
) -> None:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    provider = Mock(side_effect=AssertionError("provider must remain untouched"))
    monkeypatch.setattr(diagnostic, "_decode_runtime_configuration", lambda _: _runtime())
    monkeypatch.setattr(diagnostic, "create_read_only_qualification_engine", lambda _: engine)
    monkeypatch.setattr(diagnostic, "_verify_database_connection", lambda _: None)
    monkeypatch.setattr(diagnostic, "verify_operational_schema", lambda *_a, **_k: None)
    monkeypatch.setattr(diagnostic, "verify_trusted_time_integrity", lambda _: None)
    monkeypatch.setattr(
        diagnostic,
        "_read_local_aggregate",
        lambda *_args, **_kwargs: _aggregate(),
    )
    monkeypatch.setattr(
        diagnostic,
        "_authenticate_local_startup_snapshot",
        lambda *_args, **_kwargs: _snapshot(),
    )
    monkeypatch.setattr(diagnostic, "_verify_provider_stable_zero", provider)

    failure = RuntimeError(f"{stage} {SECRET_DSN} {SECRET_TOKEN}")
    if stage == "configuration":
        monkeypatch.setattr(
            diagnostic,
            "create_read_only_qualification_engine",
            Mock(side_effect=failure),
        )
    elif stage == "connection":
        monkeypatch.setattr(
            diagnostic,
            "_verify_database_connection",
            Mock(side_effect=diagnostic.TrustedTimeRuntimeDiagnosticError(expected_code)),
        )
    elif stage == "schema":
        monkeypatch.setattr(diagnostic, "verify_operational_schema", Mock(side_effect=failure))
    elif stage == "integrity":
        monkeypatch.setattr(diagnostic, "verify_trusted_time_integrity", Mock(side_effect=failure))
    elif stage == "aggregate":
        monkeypatch.setattr(
            diagnostic,
            "_read_local_aggregate",
            Mock(side_effect=diagnostic.TrustedTimeRuntimeDiagnosticError(expected_code)),
        )
    else:
        monkeypatch.setattr(
            diagnostic,
            "_authenticate_local_startup_snapshot",
            Mock(side_effect=diagnostic.TrustedTimeRuntimeDiagnosticError(expected_code)),
        )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic.diagnose_trusted_time_runtime(env_file=Path("/not-opened/exact-four-launch.env"))

    assert raised.value.outcome_code == expected_code
    provider.assert_not_called()


def test_local_aggregate_drift_fails_closed_before_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    aggregates = iter((_aggregate(evaluations=8), _aggregate(evaluations=9)))
    provider = Mock(side_effect=AssertionError("provider must remain untouched"))
    monkeypatch.setattr(diagnostic, "_decode_runtime_configuration", lambda _: _runtime())
    monkeypatch.setattr(diagnostic, "create_read_only_qualification_engine", lambda _: engine)
    monkeypatch.setattr(diagnostic, "_verify_database_connection", lambda _: None)
    monkeypatch.setattr(diagnostic, "verify_operational_schema", lambda *_a, **_k: None)
    monkeypatch.setattr(diagnostic, "verify_trusted_time_integrity", lambda _: None)
    monkeypatch.setattr(
        diagnostic,
        "_read_local_aggregate",
        lambda *_args, **_kwargs: next(aggregates),
    )
    monkeypatch.setattr(
        diagnostic,
        "_authenticate_local_startup_snapshot",
        lambda *_args, **_kwargs: _snapshot(),
    )
    monkeypatch.setattr(diagnostic, "_verify_provider_stable_zero", provider)

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic.diagnose_trusted_time_runtime(env_file=Path("/not-opened/exact-four-launch.env"))

    assert raised.value.outcome_code == diagnostic.OUTCOME_LOCAL_AGGREGATE_REJECTED
    provider.assert_not_called()


@pytest.mark.parametrize(
    ("aggregate", "snapshot"),
    [
        (
            diagnostic.LocalAggregate(
                epoch_count=8,
                latest_epoch_evaluation_count=8,
                intent_count=1,
                receipt_count=1,
            ),
            diagnostic.LocalSnapshotSummary(
                local_transition_count=23,
                confirmed_anchor_count=1,
                pending_intent=False,
            ),
        ),
        (
            diagnostic.LocalAggregate(
                epoch_count=8,
                latest_epoch_evaluation_count=8,
                intent_count=1,
                receipt_count=0,
            ),
            diagnostic.LocalSnapshotSummary(
                local_transition_count=23,
                confirmed_anchor_count=0,
                pending_intent=True,
            ),
        ),
    ],
)
def test_local_confirmed_or_pending_anchor_state_rejects_unenrolled_stable_zero(
    aggregate: diagnostic.LocalAggregate,
    snapshot: diagnostic.LocalSnapshotSummary,
) -> None:
    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._require_local_snapshot_consistency(aggregate, snapshot)

    assert raised.value.outcome_code == diagnostic.OUTCOME_LOCAL_ANCHOR_HISTORY_PRESENT


def test_local_snapshot_count_mismatch_has_distinct_fixed_outcome() -> None:
    aggregate = diagnostic.LocalAggregate(
        epoch_count=8,
        latest_epoch_evaluation_count=8,
        intent_count=1,
        receipt_count=1,
    )
    snapshot = diagnostic.LocalSnapshotSummary(
        local_transition_count=23,
        confirmed_anchor_count=0,
        pending_intent=False,
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._require_local_snapshot_consistency(aggregate, snapshot)

    assert raised.value.outcome_code == diagnostic.OUTCOME_LOCAL_SNAPSHOT_REJECTED


def test_consistent_local_anchor_history_blocks_provider_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    aggregate = diagnostic.LocalAggregate(
        epoch_count=8,
        latest_epoch_evaluation_count=8,
        intent_count=1,
        receipt_count=1,
    )
    snapshot = diagnostic.LocalSnapshotSummary(
        local_transition_count=23,
        confirmed_anchor_count=1,
        pending_intent=False,
    )
    provider = Mock(side_effect=AssertionError("provider must remain untouched"))
    monkeypatch.setattr(diagnostic, "_decode_runtime_configuration", lambda _: _runtime())
    monkeypatch.setattr(diagnostic, "create_read_only_qualification_engine", lambda _: engine)
    monkeypatch.setattr(diagnostic, "_verify_database_connection", lambda _: None)
    monkeypatch.setattr(diagnostic, "verify_operational_schema", lambda *_a, **_k: None)
    monkeypatch.setattr(diagnostic, "verify_trusted_time_integrity", lambda _: None)
    monkeypatch.setattr(
        diagnostic,
        "_read_local_aggregate",
        lambda *_args, **_kwargs: aggregate,
    )
    monkeypatch.setattr(
        diagnostic,
        "_authenticate_local_startup_snapshot",
        lambda *_args, **_kwargs: snapshot,
    )
    monkeypatch.setattr(diagnostic, "_verify_provider_stable_zero", provider)

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic.diagnose_trusted_time_runtime(env_file=Path("/not-opened/exact-four-launch.env"))

    assert raised.value.outcome_code == diagnostic.OUTCOME_LOCAL_ANCHOR_HISTORY_PRESENT
    provider.assert_not_called()


def test_exact_four_loader_is_used_once_and_private_key_only_validates_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = TrustedTimeHeadAnchorSourcePayloads(
        authority=b"authority",
        auth_secret=b"auth-secret",
        signing_key=b"s" * 32,
    )
    loaded = TrustedTimeRuntimeConfiguration(
        database_url=SECRET_DSN,
        head_anchor_payloads=payloads,
    )
    load = Mock(return_value=loaded)
    authority = _authority()
    credentials = object()
    verifier = object()
    signer = Mock()
    signer_type = SimpleNamespace(from_private_key_bytes=Mock(return_value=signer))
    verifier_type = SimpleNamespace(from_public_key_bytes=Mock(return_value=verifier))
    monkeypatch.setattr(diagnostic, "load_trusted_time_runtime_configuration", load)
    monkeypatch.setattr(
        diagnostic,
        "load_checked_in_authority",
        lambda: SimpleNamespace(
            deployment=SimpleNamespace(
                host_id=authority.host_id,
                source_authority_sha256="f" * 64,
            )
        ),
    )
    decode_authority = Mock(return_value=authority)
    decode_auth = Mock(return_value=credentials)
    monkeypatch.setattr(diagnostic, "decode_trusted_time_head_anchor_authority", decode_authority)
    monkeypatch.setattr(diagnostic, "decode_trusted_time_head_anchor_auth_secret", decode_auth)
    monkeypatch.setattr(diagnostic, "Ed25519TrustedTimeAnchorSigner", signer_type)
    monkeypatch.setattr(diagnostic, "Ed25519TrustedTimeAnchorVerifier", verifier_type)

    decoded = diagnostic._decode_runtime_configuration(Path("/not-opened/exact-four-launch.env"))

    load.assert_called_once_with(Path("/not-opened/exact-four-launch.env"))
    decode_authority.assert_called_once_with(
        b"authority",
        database_url=SECRET_DSN,
        expected_host_id=authority.host_id,
        expected_source_authority_sha256="f" * 64,
    )
    decode_auth.assert_called_once_with(b"auth-secret", authority=authority)
    signer_type.from_private_key_bytes.assert_called_once_with(
        signing_key_id=authority.signing_key_id,
        expected_signing_public_key_sha256=authority.signing_public_key_sha256,
        private_key_bytes=b"s" * 32,
    )
    assert decoded.database_url == SECRET_DSN
    assert decoded.credentials is credentials
    assert decoded.verifier is verifier


def test_startup_snapshot_uses_only_load_and_discard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    snapshot = SimpleNamespace(
        complete_replay=True,
        local_transition_count=23,
        confirmed_anchor_count=0,
        pending_intent=None,
    )

    class ReadOnlyRepository:
        def load_head_anchor_startup_snapshot(self, **kwargs: object) -> object:
            calls.append(("load", kwargs))
            return snapshot

        def discard_head_anchor_snapshot(self, value: object) -> None:
            calls.append(("discard", value))

    repository = ReadOnlyRepository()
    constructor = Mock(return_value=repository)
    monkeypatch.setattr(diagnostic, "SqlTrustedTimeHeadAnchorRepository", constructor)
    runtime = _runtime()

    summary = diagnostic._authenticate_local_startup_snapshot(
        object(),  # type: ignore[arg-type]
        runtime=runtime,  # type: ignore[arg-type]
    )

    constructor.assert_called_once()
    assert calls[0][0] == "load"  # type: ignore[index]
    assert calls[1] == ("discard", snapshot)
    assert summary == _snapshot()


def test_startup_snapshot_is_discarded_when_summary_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = SimpleNamespace(
        complete_replay=True,
        local_transition_count=0,
        confirmed_anchor_count=0,
        pending_intent=None,
    )
    discard = Mock()
    repository = SimpleNamespace(
        load_head_anchor_startup_snapshot=Mock(return_value=snapshot),
        discard_head_anchor_snapshot=discard,
    )
    monkeypatch.setattr(
        diagnostic,
        "SqlTrustedTimeHeadAnchorRepository",
        Mock(return_value=repository),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._authenticate_local_startup_snapshot(
            object(),  # type: ignore[arg-type]
            runtime=_runtime(),  # type: ignore[arg-type]
        )

    assert raised.value.outcome_code == diagnostic.OUTCOME_LOCAL_SNAPSHOT_REJECTED
    discard.assert_called_once_with(snapshot)


def test_provider_attests_identity_and_performs_exactly_two_one_item_zero_lists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    expected_identity = TrustedTimeHeadAnchorProviderIdentity(
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        anchor_project_ref=authority.anchor_project_ref,
        principal_id=authority.principal_id,
        bucket_name=authority.bucket_name,
    )
    calls: list[tuple[str, object]] = []

    class ReadOnlyProvider:
        def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity:
            calls.append(("identity", None))
            return expected_identity

        def list_object_names_page(self, **kwargs: object) -> tuple[str, ...]:
            calls.append(("list", kwargs))
            return ()

        def close(self) -> None:
            calls.append(("close", None))

    provider = ReadOnlyProvider()
    constructor = Mock(return_value=provider)
    monkeypatch.setattr(diagnostic, "SupabaseStorageTrustedTimeAnchorProvider", constructor)

    diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    constructor.assert_called_once()
    listing_calls = [value for kind, value in calls if kind == "list"]
    assert len(listing_calls) == 2
    assert listing_calls[0] == listing_calls[1]
    assert listing_calls[0]["offset"] == 0  # type: ignore[index]
    assert listing_calls[0]["limit"] == 1  # type: ignore[index]
    assert listing_calls[0]["bucket_name"] == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME  # type: ignore[index]
    assert listing_calls[0]["prefix"] == trusted_time_head_anchor_object_prefix(  # type: ignore[index]
        deployment_identity_sha256=authority.deployment_identity_sha256,
        host_id=authority.host_id,
    )
    assert calls[-1] == ("close", None)


@pytest.mark.parametrize(
    ("error_type", "expected_code"),
    [
        (
            SupabaseStorageAnchorAuthPasswordTokenRequestTargetError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_REQUEST_TARGET_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENCODING_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthPasswordTokenResponseBoundError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_BOUND_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENVELOPE_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_SESSION_SCHEMA_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthPasswordTokenResponseError,
            diagnostic.OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthUserVerificationResponseError,
            diagnostic.OUTCOME_PROVIDER_AUTH_USER_VERIFICATION_RESPONSE_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthenticationResponseError,
            diagnostic.OUTCOME_PROVIDER_AUTHENTICATION_RESPONSE_REJECTED,
        ),
        (
            SupabaseStorageAnchorBoundedListResponseError,
            diagnostic.OUTCOME_PROVIDER_STORAGE_LIST_RESPONSE_REJECTED,
        ),
        (
            SupabaseStorageAnchorAuthenticationError,
            diagnostic.OUTCOME_PROVIDER_AUTHENTICATION_REJECTED,
        ),
        (
            SupabaseStorageAnchorStorageAccessError,
            diagnostic.OUTCOME_PROVIDER_STORAGE_ACCESS_REJECTED,
        ),
        (
            SupabaseStorageAnchorUnavailable,
            diagnostic.OUTCOME_PROVIDER_UNAVAILABLE,
        ),
        (
            SupabaseStorageAnchorResponseError,
            diagnostic.OUTCOME_PROVIDER_RESPONSE_REJECTED,
        ),
        (
            SupabaseStorageAnchorError,
            diagnostic.OUTCOME_PROVIDER_ACCESS_REJECTED,
        ),
    ],
)
def test_provider_typed_failures_map_without_inspecting_secret_text(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    expected_code: str,
) -> None:
    authority = _authority()
    close = Mock()
    provider = SimpleNamespace(
        attest_identity=lambda: TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            principal_id=authority.principal_id,
            bucket_name=authority.bucket_name,
        ),
        list_object_names_page=Mock(side_effect=error_type(SECRET_TOKEN)),
        close=close,
    )
    monkeypatch.setattr(
        diagnostic,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    encoded = diagnostic.canonical_json_bytes(diagnostic.failure_payload(raised.value.outcome_code))
    assert diagnostic.CONTRACT_VERSION == "phase6d-bounded-read-only-runtime-diagnostic-v5"
    assert raised.value.outcome_code == expected_code
    assert SECRET_TOKEN not in str(raised.value)
    assert SECRET_TOKEN.encode("ascii") not in encoded
    close.assert_called_once_with()


def test_provider_cleanup_failure_has_fixed_sanitized_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    provider = SimpleNamespace(
        attest_identity=lambda: TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            principal_id=authority.principal_id,
            bucket_name=authority.bucket_name,
        ),
        list_object_names_page=lambda **_kwargs: (),
        close=Mock(side_effect=RuntimeError(SECRET_TOKEN)),
    )
    monkeypatch.setattr(
        diagnostic,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    encoded = diagnostic.canonical_json_bytes(diagnostic.failure_payload(raised.value.outcome_code))
    assert raised.value.outcome_code == diagnostic.OUTCOME_PROVIDER_CLEANUP_REJECTED
    assert SECRET_TOKEN not in str(raised.value)
    assert SECRET_TOKEN.encode("ascii") not in encoded


def test_provider_cleanup_failure_overrides_in_flight_failure_without_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    provider = SimpleNamespace(
        attest_identity=lambda: TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            principal_id=authority.principal_id,
            bucket_name=authority.bucket_name,
        ),
        list_object_names_page=Mock(
            side_effect=SupabaseStorageAnchorAuthenticationError(SECRET_TOKEN)
        ),
        close=Mock(side_effect=RuntimeError(f"cleanup-{SECRET_TOKEN}")),
    )
    monkeypatch.setattr(
        diagnostic,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    encoded = diagnostic.canonical_json_bytes(diagnostic.failure_payload(raised.value.outcome_code))
    assert raised.value.outcome_code == diagnostic.OUTCOME_PROVIDER_CLEANUP_REJECTED
    assert SECRET_TOKEN not in str(raised.value)
    assert SECRET_TOKEN.encode("ascii") not in encoded


@pytest.mark.parametrize("stage", ["identity", "list"])
def test_provider_is_closed_after_identity_or_access_failure(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    authority = _authority()
    expected = TrustedTimeHeadAnchorProviderIdentity(
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        anchor_project_ref=authority.anchor_project_ref,
        principal_id=authority.principal_id,
        bucket_name=authority.bucket_name,
    )
    close = Mock()
    provider = SimpleNamespace(
        attest_identity=(
            Mock(side_effect=RuntimeError(SECRET_TOKEN))
            if stage == "identity"
            else Mock(return_value=expected)
        ),
        list_object_names_page=Mock(side_effect=RuntimeError(SECRET_TOKEN)),
        close=close,
    )
    monkeypatch.setattr(
        diagnostic,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    expected_code = (
        diagnostic.OUTCOME_PROVIDER_IDENTITY_REJECTED
        if stage == "identity"
        else diagnostic.OUTCOME_PROVIDER_ACCESS_REJECTED
    )
    assert raised.value.outcome_code == expected_code
    close.assert_called_once_with()


@pytest.mark.parametrize("pages", [(("contaminant",), ()), ((), ("contaminant",))])
def test_provider_nonzero_or_drifting_prefix_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    pages: tuple[tuple[str, ...], tuple[str, ...]],
) -> None:
    authority = _authority()
    observed = iter(pages)
    provider = SimpleNamespace(
        attest_identity=lambda: TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            principal_id=authority.principal_id,
            bucket_name=authority.bucket_name,
        ),
        list_object_names_page=lambda **_kwargs: next(observed),
        close=lambda: None,
    )
    monkeypatch.setattr(
        diagnostic,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )

    with pytest.raises(diagnostic.TrustedTimeRuntimeDiagnosticError) as raised:
        diagnostic._verify_provider_stable_zero(runtime=_runtime())  # type: ignore[arg-type]

    assert raised.value.outcome_code == diagnostic.OUTCOME_PROVIDER_PREFIX_NOT_STABLE_ZERO


def test_cli_never_renders_exception_text_or_sensitive_values(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        diagnostic,
        "diagnose_trusted_time_runtime",
        Mock(side_effect=RuntimeError(f"{SECRET_DSN} {SECRET_TOKEN} /private/path object-name")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["diagnose_trusted_time_runtime.py", "--env-file", "/not-opened/launch.env"],
    )

    with pytest.raises(SystemExit) as raised:
        diagnostic.main()

    stdout, stderr = capfd.readouterr()
    assert raised.value.code == 2
    assert stderr == ""
    assert json.loads(stdout) == diagnostic.failure_payload(diagnostic.OUTCOME_DIAGNOSTIC_FAILED)
    for sentinel in (SECRET_DSN, SECRET_TOKEN, "/private/path", "object-name"):
        assert sentinel not in stdout


def _configure_attested_test_runtime(
    *,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path]:
    repository = tmp_path / "canonical-repository"
    source = repository / "scripts" / "diagnose_trusted_time_runtime.py"
    source.parent.mkdir(parents=True)
    source.write_text("# attested test source\n", encoding="utf-8")
    runtime_prefix = tmp_path / "isolated-runtime"
    base_prefix = tmp_path / "base-runtime"
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(repository)
    monkeypatch.setattr(sys, "prefix", str(runtime_prefix))
    monkeypatch.setattr(sys, "base_prefix", str(base_prefix))
    monkeypatch.setattr(
        sys,
        "flags",
        SimpleNamespace(isolated=1, dont_write_bytecode=1),
    )
    monkeypatch.setattr(sys, "pycache_prefix", "/dev/null")
    monkeypatch.setattr(sys, "path", [str(runtime_prefix / "site-packages")])
    return repository, source


def test_isolated_cli_source_runtime_accepts_exact_canonical_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, source = _configure_attested_test_runtime(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )

    result = diagnostic._require_isolated_cli_source_runtime(
        expected_relative_path=Path("scripts/diagnose_trusted_time_runtime.py"),
        module_file=str(source),
    )

    assert result == repository
    assert sys.path[0] == str(repository)


@pytest.mark.parametrize("rejection", ["not_isolated", "bytecode", "cache", "reused_venv"])
def test_isolated_cli_source_runtime_rejects_untrusted_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    rejection: str,
) -> None:
    repository, source = _configure_attested_test_runtime(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    if rejection == "not_isolated":
        monkeypatch.setattr(sys, "flags", SimpleNamespace(isolated=0, dont_write_bytecode=1))
    elif rejection == "bytecode":
        monkeypatch.setattr(sys, "flags", SimpleNamespace(isolated=1, dont_write_bytecode=0))
    elif rejection == "cache":
        monkeypatch.setattr(sys, "pycache_prefix", None)
    else:
        reused_venv = repository / ".venv"
        reused_venv.mkdir()
        monkeypatch.setattr(sys, "prefix", str(reused_venv))

    with pytest.raises(RuntimeError, match="runtime attestation failed"):
        diagnostic._require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/diagnose_trusted_time_runtime.py"),
            module_file=str(source),
        )


def test_first_party_source_attestation_accepts_repository_and_rejects_foreign_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostic._require_repository_first_party_sources(ROOT)
    monkeypatch.setitem(
        sys.modules,
        "scripts.foreign_runtime_sentinel",
        SimpleNamespace(__file__="/private/foreign/runtime.py"),
    )

    with pytest.raises(RuntimeError, match="source attestation failed"):
        diagnostic._require_repository_first_party_sources(ROOT)


def test_nonisolated_subprocess_bootstrap_failure_is_one_sanitized_json_object() -> None:
    secret_path = f"/private/{SECRET_TOKEN}/trusted-time-launch.env"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts" / "diagnose_trusted_time_runtime.py"),
            "--env-file",
            secret_path,
        ],
        cwd=ROOT,
        env={},
        check=False,
        capture_output=True,
        timeout=10,
    )

    assert completed.returncode == 2
    assert completed.stderr == b""
    assert completed.stdout.count(b"\n") == 1
    assert json.loads(completed.stdout) == diagnostic.failure_payload(
        diagnostic.OUTCOME_DIAGNOSTIC_FAILED
    )
    assert SECRET_TOKEN.encode("ascii") not in completed.stdout
    assert b"Traceback" not in completed.stdout


def test_diagnostic_has_no_durable_or_provider_mutation_calls_and_make_is_isolated() -> None:
    script = ROOT / "scripts" / "diagnose_trusted_time_runtime.py"
    tree = ast.parse(script.read_text(encoding="utf-8"))
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert called_attributes.isdisjoint(
        {
            "append_probe",
            "commit_prepared_intent",
            "confirm_remote_readback",
            "confirm_remote_readback_from_snapshot",
            "prepare_or_read_pending",
            "register_new_epoch",
            "upload_object_no_overwrite",
        }
    )

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.partition("\ntrusted-time-runtime-diagnostic:")[2].partition("\n\n")[0]
    assert "$(TRUSTED_TIME_PYTHON)" in target
    assert "\t@$(TRUSTED_TIME_PYTHON) \\\n" in target
    assert "scripts/diagnose_trusted_time_runtime.py" in target
    assert '--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)"' in target
    assert "--env-file .env" not in target
    assert 'exec_driver_sql("SET TRANSACTION READ ONLY")' in script.read_text(encoding="utf-8")
