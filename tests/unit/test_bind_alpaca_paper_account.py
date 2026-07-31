from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

import pytest
import sqlalchemy as sa

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    _observe_authenticated_alpaca_paper_account_with_transport,
)
from packages.domain.clock import SystemClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_request_heads,
    phase4_broker_request_permits,
)
from scripts import bind_alpaca_paper_account as binding_cli
from tests.unit.test_alpaca_paper_account_runtime import (
    API_KEY_ID as FIXTURE_API_KEY_ID,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    PROVIDER_ACCOUNT_ID as FIXTURE_PROVIDER_ACCOUNT_ID,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    SECRET_KEY as FIXTURE_SECRET_KEY,
)
from tests.unit.test_alpaca_paper_account_runtime import FixedTransport

RUNTIME_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:runtime-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
OPERATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
RECOVERY_OPERATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
THIRD_OPERATION_ID = "cccccccc-dddd-4eee-8fff-000000000000"
PROVIDER_ACCOUNT_ID = "11111111-2222-4333-8444-555555555555"
API_KEY = "HOSTILE_API_KEY_MARKER"
API_SECRET = "HOSTILE_API_SECRET_MARKER"

_BASE_ENVIRONMENT = {
    "AQT_DATABASE_URL": RUNTIME_URL,
    "ALPACA_PAPER_API_KEY": API_KEY,
    "ALPACA_PAPER_API_SECRET": API_SECRET,
    "ALPACA_PAPER_BASE_URL": "https://paper-api.alpaca.markets",
    "AQT_PAPER_ACCOUNT_ID": "owner-paper-smoke",
    "AQT_PAPER_PROVIDER_ACCOUNT_ID": PROVIDER_ACCOUNT_ID,
    "AQT_PAPER_BROKER_SECRET_REF": "secret://paper/alpaca/owner-paper-smoke",
    "AQT_PAPER_BROKER_SECRET_VERSION": "v1",
}
_NONSECRET_PIN_FIELDS = (
    "AQT_PAPER_ACCOUNT_ID",
    "AQT_PAPER_PROVIDER_ACCOUNT_ID",
    "AQT_PAPER_BROKER_SECRET_REF",
    "AQT_PAPER_BROKER_SECRET_VERSION",
)


class _SqliteUtcDateTime(sa.TypeDecorator[datetime]):
    """Make SQLite head timestamps resemble PostgreSQL timestamptz readback."""

    impl = sa.DateTime
    cache_ok = True

    def process_result_value(
        self,
        value: datetime | None,
        dialect: sa.Dialect,
    ) -> datetime | None:
        del dialect
        if value is None or value.tzinfo is not None:
            return value
        return value.replace(tzinfo=UTC)


def _write_owner_environment(
    path: Path,
    *,
    overrides: dict[str, str] | None = None,
    omitted: frozenset[str] = frozenset(),
    suffix: str = "",
) -> Path:
    environment = dict(_BASE_ENVIRONMENT)
    environment.update(overrides or {})
    payload = "\n".join(
        f"{name}={value}" for name, value in environment.items() if name not in omitted
    )
    path.write_text(f"{payload}\n{suffix}", encoding="utf-8")
    path.chmod(0o600)
    return path


def _reference(
    *,
    account_id: str = "owner-paper-smoke",
    provider_account_id: str = PROVIDER_ACCOUNT_ID,
) -> AlpacaPaperCredentialReference:
    return AlpacaPaperCredentialReference(
        account_id=account_id,
        expected_provider_account_id=provider_account_id,
        secret_ref="secret://paper/alpaca/owner-paper-smoke",
        secret_version="v1",
    )


def _resolver_retains_credentials(
    resolver: binding_cli._OwnerEnvironmentCredentialResolver,
) -> bool:
    return resolver.credential_values_present


def _resolver_consumed(
    resolver: binding_cli._OwnerEnvironmentCredentialResolver,
) -> bool:
    return resolver.consumed


def _envelope_closed(envelope: Any) -> bool:
    return bool(envelope.closed)


def _fixture_configuration() -> tuple[
    binding_cli._BindingEnvironment,
    binding_cli._OwnerEnvironmentCredentialResolver,
]:
    reference = _reference(provider_account_id=FIXTURE_PROVIDER_ACCOUNT_ID)
    resolver = binding_cli._OwnerEnvironmentCredentialResolver(
        reference=reference,
        api_key_id=FIXTURE_API_KEY_ID,
        secret_key=FIXTURE_SECRET_KEY,
    )
    return (
        binding_cli._BindingEnvironment(
            database_url=RUNTIME_URL,
            reference=reference,
            credential_resolver=resolver,
        ),
        resolver,
    )


def _install_sqlite_preflight_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep production checkpoint logic while replacing PostgreSQL-only gates."""

    binding_preflight = binding_cli._verify_database_preconditions
    recovery_preflight = binding_cli._verify_recovery_database_preconditions
    for column in (
        phase2_account_lease_heads.c.updated_at,
        phase4_broker_request_heads.c.last_issued_at,
    ):
        monkeypatch.setattr(
            column,
            "type",
            _SqliteUtcDateTime(timezone=True),
        )

    def sqlite_binding_preflight(
        engine: sa.Engine,
        reference: AlpacaPaperCredentialReference,
    ) -> binding_cli._ControlSnapshot:
        dialect_name = engine.dialect.name
        engine.dialect.name = "postgresql"
        try:
            return binding_preflight(engine, reference)
        finally:
            engine.dialect.name = dialect_name

    def sqlite_recovery_preflight(
        engine: sa.Engine,
        reference: AlpacaPaperCredentialReference,
        recovery_from_operation_id: str,
    ) -> binding_cli._RecoveryCheckpoint:
        dialect_name = engine.dialect.name
        engine.dialect.name = "postgresql"
        try:
            return recovery_preflight(
                engine,
                reference,
                recovery_from_operation_id,
            )
        finally:
            engine.dialect.name = dialect_name

    monkeypatch.setattr(
        binding_cli,
        "_verify_database_preconditions",
        sqlite_binding_preflight,
    )
    monkeypatch.setattr(
        binding_cli,
        "_verify_recovery_database_preconditions",
        sqlite_recovery_preflight,
    )
    monkeypatch.setattr(
        binding_cli,
        "verify_operational_schema",
        lambda candidate, require_phase_zero_facts: None,
    )
    monkeypatch.setattr(
        binding_cli,
        "_client_tls_active",
        lambda candidate: True,
    )
    for verifier_name in (
        "verify_broker_request_budget_integrity",
        "verify_broker_ingress_integrity",
        "verify_alpaca_paper_account_binding_integrity",
        "verify_operational_control_integrity",
    ):
        monkeypatch.setattr(
            binding_cli,
            verifier_name,
            lambda candidate: None,
        )


def _track_credential_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> list[binding_cli._OwnerEnvironmentCredentialResolver]:
    calls: list[binding_cli._OwnerEnvironmentCredentialResolver] = []
    resolver_method = (
        binding_cli._OwnerEnvironmentCredentialResolver._resolve_for_account_observation
    )

    def track(
        resolver: binding_cli._OwnerEnvironmentCredentialResolver,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        calls.append(resolver)
        return resolver_method(resolver, reference)

    monkeypatch.setattr(
        binding_cli._OwnerEnvironmentCredentialResolver,
        "_resolve_for_account_observation",
        track,
    )
    return calls


def _account_row_count(
    engine: sa.Engine,
    table: sa.Table,
    account_id: str,
) -> int:
    with engine.connect() as connection:
        return int(
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(table)
                .where(table.c.account_id == account_id),
            )
            or 0
        )


def _assert_account_history_counts(
    engine: sa.Engine,
    account_id: str,
    *,
    leases: int,
    releases: int,
    permits: int,
    ingress: int,
    bindings: int,
) -> None:
    expected_counts = (
        (phase2_account_leases, leases),
        (phase2_account_lease_releases, releases),
        (phase4_broker_request_permits, permits),
        (phase4_broker_ingress_receipts, ingress),
        (phase4_alpaca_paper_account_bindings, bindings),
    )
    for table, expected in expected_counts:
        assert _account_row_count(engine, table, account_id) == expected


def _seed_recoverable_raw_only_checkpoint(
    engine: sa.Engine,
) -> None:
    configuration, resolver = _fixture_configuration()
    transport = FixedTransport()
    observer_calls = 0

    class RejectingBindingRecorder:
        def record(self, evidence: object) -> NoReturn:
            del evidence
            raise RuntimeError("fixture rejects only the terminal binding")

    def retain_valid_raw_response_without_binding(
        **kwargs: Any,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        nonlocal observer_calls
        observer_calls += 1
        kwargs["binding_recorder"] = RejectingBindingRecorder()
        return _observe_authenticated_alpaca_paper_account_with_transport(
            transport=transport,
            **kwargs,
        )

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="account_observation_failed",
    ):
        binding_cli.execute_binding(
            configuration,
            OPERATION_ID,
            engine_factory=lambda value: engine,
            observer=retain_valid_raw_response_without_binding,
        )

    assert observer_calls == 1
    assert len(transport.request_sha256s) == 1
    assert _resolver_consumed(resolver) is True
    assert not _resolver_retains_credentials(resolver)
    _assert_account_history_counts(
        engine,
        configuration.reference.account_id,
        leases=1,
        releases=1,
        permits=1,
        ingress=1,
        bindings=0,
    )
    for table in (
        phase2_account_lease_heads,
        phase4_broker_request_heads,
        phase4_broker_ingress_heads,
    ):
        assert (
            _account_row_count(
                engine,
                table,
                configuration.reference.account_id,
            )
            == 1
        )
    assert (
        _account_row_count(
            engine,
            phase4_alpaca_paper_account_binding_heads,
            configuration.reference.account_id,
        )
        == 0
    )


def _mutate_recovery_checkpoint(
    engine: sa.Engine,
    mutation: str,
) -> None:
    with engine.begin() as connection:
        if mutation == "missing_release":
            connection.execute(sa.delete(phase2_account_lease_releases))
            return
        if mutation in {"extra_lease", "active_lease"}:
            prior = connection.execute(sa.select(phase2_account_leases)).mappings().one()
            extra_lease_sha256 = "4" * 64
            connection.execute(
                sa.insert(phase2_account_leases).values(
                    lease_sha256=extra_lease_sha256,
                    account_id=prior["account_id"],
                    owner_id="unexpected-recovery-owner",
                    lease_id="5" * 64,
                    fencing_generation=2,
                    revision_number=1,
                    previous_lease_sha256=None,
                    acquired_at=prior["heartbeat_at"],
                    heartbeat_at=prior["heartbeat_at"],
                    expires_at=prior["expires_at"],
                    policy_sha256=prior["policy_sha256"],
                    canonical_payload="{}",
                ),
            )
            if mutation == "active_lease":
                connection.execute(
                    sa.update(phase2_account_lease_heads).values(
                        last_fencing_generation=2,
                        current_fencing_generation=2,
                        current_lease_sha256=extra_lease_sha256,
                        updated_at=prior["heartbeat_at"],
                    ),
                )
            return

        updates: dict[str, tuple[sa.Table, str, object]] = {
            "wrong_owner_key": (
                phase2_account_leases,
                "owner_id",
                "wrong-generation-one-owner",
            ),
            "wrong_request_key": (
                phase4_broker_request_permits,
                "idempotency_key",
                f"aqt.paper.account.request.{THIRD_OPERATION_ID}",
            ),
            "wrong_delivery_key": (
                phase4_broker_ingress_receipts,
                "delivery_idempotency_key",
                f"aqt.paper.account.delivery.{THIRD_OPERATION_ID}",
            ),
            "wrong_status": (
                phase4_broker_ingress_receipts,
                "transport_status",
                201,
            ),
            "wrong_request_id": (
                phase4_broker_ingress_receipts,
                "provider_request_id",
                "wrong-provider-request-id",
            ),
            "wrong_media_type": (
                phase4_broker_ingress_receipts,
                "media_type",
                "text/plain",
            ),
            "wrong_correlation": (
                phase4_broker_request_permits,
                "correlation_sha256",
                "0" * 64,
            ),
        }
        table, column_name, value = updates[mutation]
        connection.execute(sa.update(table).values({column_name: value}))


def test_canonical_operation_id_derives_exact_single_attempt_keys() -> None:
    assert binding_cli._canonical_operation_id(OPERATION_ID) == OPERATION_ID
    assert binding_cli._idempotency_keys(OPERATION_ID) == (
        f"aqt.paper.account.request.{OPERATION_ID}",
        f"aqt.paper.account.delivery.{OPERATION_ID}",
        f"aqt-paper-account-binding-{OPERATION_ID}",
    )


@pytest.mark.parametrize(
    "candidate",
    (
        "not-a-uuid",
        "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee",
    ),
)
def test_operation_id_must_be_a_canonical_lowercase_uuid(candidate: str) -> None:
    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="operation_id_invalid",
    ):
        binding_cli._idempotency_keys(candidate)


@pytest.mark.parametrize(
    ("operation_id", "recovery_from_operation_id", "authorized", "reason"),
    (
        (
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
            OPERATION_ID,
            True,
            "operation_id_invalid",
        ),
        (
            RECOVERY_OPERATION_ID,
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
            True,
            "operation_id_invalid",
        ),
        (
            OPERATION_ID,
            OPERATION_ID,
            True,
            "recovery_operation_id_conflict",
        ),
        (
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            False,
            "second_account_get_not_authorized",
        ),
        (
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            1,
            "second_account_get_not_authorized",
        ),
    ),
)
def test_recovery_requires_canonical_distinct_ids_and_exact_authorization(
    operation_id: str,
    recovery_from_operation_id: str,
    authorized: bool,
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration, resolver = _fixture_configuration()
    credential_resolution_calls = _track_credential_resolution(monkeypatch)
    engine_calls = 0

    def forbidden_engine_factory(database_url: str) -> NoReturn:
        del database_url
        nonlocal engine_calls
        engine_calls += 1
        pytest.fail("invalid recovery authority must fail before database access")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match=reason,
    ):
        binding_cli.execute_recovery_binding(
            configuration,
            operation_id,
            recovery_from_operation_id,
            authorize_second_account_get=authorized,
            engine_factory=forbidden_engine_factory,
        )

    assert engine_calls == 0
    assert credential_resolution_calls == []
    assert not _resolver_retains_credentials(resolver)


def test_binding_environment_requires_an_absolute_owner_only_file(
    tmp_path: Path,
) -> None:
    path = _write_owner_environment(tmp_path / "binding.env")

    configuration = binding_cli._load_binding_environment(path)

    assert configuration.database_url == RUNTIME_URL
    assert configuration.reference == _reference()
    assert configuration.credential_resolver.consumed is False
    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="env_file_path_not_absolute",
    ):
        binding_cli._load_binding_environment(Path("binding.env"))


@pytest.mark.parametrize("missing_field", _NONSECRET_PIN_FIELDS)
def test_each_nonsecret_binding_pin_is_mandatory(
    tmp_path: Path,
    missing_field: str,
) -> None:
    path = _write_owner_environment(
        tmp_path / "binding.env",
        omitted=frozenset((missing_field,)),
    )

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="binding_environment_incomplete",
    ):
        binding_cli._load_binding_environment(path)


@pytest.mark.parametrize(
    "base_url",
    (
        "https://api.alpaca.markets",
        "https://paper-api.alpaca.markets/",
    ),
)
def test_live_or_noncanonical_paper_base_url_is_rejected(
    tmp_path: Path,
    base_url: str,
) -> None:
    path = _write_owner_environment(
        tmp_path / "binding.env",
        overrides={"ALPACA_PAPER_BASE_URL": base_url},
    )

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="alpaca_paper_base_url_rejected",
    ):
        binding_cli._load_binding_environment(path)


def test_provider_account_pin_must_be_a_canonical_uuid(tmp_path: Path) -> None:
    path = _write_owner_environment(
        tmp_path / "binding.env",
        overrides={"AQT_PAPER_PROVIDER_ACCOUNT_ID": "provider-account-not-a-uuid"},
    )

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="credential_reference_invalid",
    ):
        binding_cli._load_binding_environment(path)


@pytest.mark.parametrize(
    ("mutation", "mode"),
    (
        ("duplicate", 0o600),
        ("oversize", 0o600),
        ("permissions", 0o640),
    ),
)
def test_dotenv_contract_rejects_duplicate_oversize_or_non_owner_only_input(
    tmp_path: Path,
    mutation: str,
    mode: int,
) -> None:
    suffix = ""
    if mutation == "duplicate":
        suffix = f"AQT_DATABASE_URL={RUNTIME_URL}\n"
    elif mutation == "oversize":
        suffix = "UNUSED_PADDING=" + ("x" * binding_cli._MAXIMUM_ENVIRONMENT_BYTES)
    path = _write_owner_environment(
        tmp_path / "binding.env",
        suffix=suffix,
    )
    path.chmod(mode)

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="owner_environment_invalid",
    ):
        binding_cli._load_binding_environment(path)


def test_dotenv_contract_rejects_a_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    _write_owner_environment(real_parent / "binding.env")
    symlinked_parent = tmp_path / "linked"
    symlinked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="owner_environment_invalid",
    ):
        binding_cli._load_binding_environment(symlinked_parent / "binding.env")


def test_owner_environment_resolver_is_exact_one_use_redacted_and_cleared() -> None:
    reference = _reference()
    resolver = binding_cli._OwnerEnvironmentCredentialResolver(
        reference=reference,
        api_key_id=API_KEY,
        secret_key=API_SECRET,
    )
    rendered = f"{resolver!r} {resolver!s}"

    assert "<redacted" in rendered
    assert API_KEY not in rendered
    assert API_SECRET not in rendered
    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="credential_reference_mismatch",
    ):
        resolver._resolve_for_account_observation(
            _reference(account_id="different-paper-alias"),
        )
    assert _resolver_consumed(resolver) is False

    envelope: Any = resolver._resolve_for_account_observation(reference)

    assert _resolver_consumed(resolver) is True
    assert not _resolver_retains_credentials(resolver)
    envelope_rendered = f"{envelope!r} {envelope!s}"
    assert API_KEY not in envelope_rendered
    assert API_SECRET not in envelope_rendered
    assert _envelope_closed(envelope) is False
    envelope.close()
    assert _envelope_closed(envelope) is True
    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="credential_resolution_replay_rejected",
    ):
        resolver._resolve_for_account_observation(reference)


def test_cli_failure_is_secret_free_and_keeps_every_authority_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_owner_environment(tmp_path / "binding.env")
    hostile_error = (
        f"provider failed with {API_KEY} {API_SECRET} {RUNTIME_URL} HOSTILE_EXCEPTION_MARKER"
    )

    def fail_binding(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError(hostile_error)

    monkeypatch.setattr(binding_cli, "execute_binding", fail_binding)

    assert (
        binding_cli.main(
            ["--env-file", str(path), "--operation-id", OPERATION_ID],
        )
        == 2
    )
    output = capsys.readouterr().out
    payload = json.loads(output)

    for forbidden in (
        API_KEY,
        API_SECRET,
        "runtime-password",
        RUNTIME_URL,
        "HOSTILE_EXCEPTION_MARKER",
        "postgresql+psycopg",
    ):
        assert forbidden not in output
    assert payload["reason"] == "binding_command_failed"
    authority_fields = {
        name: value for name, value in payload.items() if name.endswith("_authorized")
    }
    assert authority_fields
    assert set(authority_fields.values()) == {False}
    assert payload["account_binding_established"] == "not_asserted"
    assert payload["control_state_changed"] == "not_asserted"
    assert payload["paper_startup_ready"] is False


def test_main_never_executes_binding_when_owner_env_preflight_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_owner_environment(
        tmp_path / "binding.env",
        omitted=frozenset(("AQT_PAPER_PROVIDER_ACCOUNT_ID",)),
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("execute_binding must not run after invalid owner env preflight")

    monkeypatch.setattr(binding_cli, "execute_binding", forbidden)

    assert (
        binding_cli.main(
            ["--env-file", str(path), "--operation-id", OPERATION_ID],
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "binding_environment_incomplete"
    assert payload["broker_action_authorized"] is False
    assert payload["trading_effect_authorized"] is False


@pytest.mark.parametrize(
    "recovery_arguments",
    (
        ("--recovery-from-operation-id", OPERATION_ID),
        ("--authorize-second-account-get",),
    ),
)
def test_cli_requires_recovery_checkpoint_and_second_get_approval_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    recovery_arguments: tuple[str, ...],
) -> None:
    env_path = tmp_path / "must-not-be-read.env"

    def forbidden_environment_load(path: Path) -> NoReturn:
        del path
        pytest.fail("unpaired recovery arguments must fail before environment loading")

    monkeypatch.setattr(
        binding_cli,
        "_load_binding_environment",
        forbidden_environment_load,
    )

    assert (
        binding_cli.main(
            [
                "--env-file",
                str(env_path),
                "--operation-id",
                RECOVERY_OPERATION_ID,
                *recovery_arguments,
            ],
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "recovery_arguments_invalid"
    assert payload["broker_action_authorized"] is False
    assert payload["trading_effect_authorized"] is False


def test_cli_dispatches_only_the_explicitly_authorized_recovery_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configuration, _ = _fixture_configuration()
    env_path = tmp_path / "binding.env"
    calls: list[tuple[object, ...]] = []
    result = binding_cli.PaperAccountBindingResult(
        operation_id=RECOVERY_OPERATION_ID,
        binding_id="1" * 64,
        binding_sha256="2" * 64,
        provider_account_id_sha256="3" * 64,
        sequence_number=1,
        qualified_at="2026-07-30T00:00:00+00:00",
    )

    monkeypatch.setattr(
        binding_cli,
        "_load_binding_environment",
        lambda path: configuration,
    )

    def forbidden_default_binding(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        pytest.fail("recovery flags must not dispatch the default binding path")

    def capture_recovery(
        candidate: binding_cli._BindingEnvironment,
        operation_id: str,
        recovery_from_operation_id: str,
        *,
        authorize_second_account_get: bool,
    ) -> binding_cli.PaperAccountBindingResult:
        calls.append(
            (
                candidate,
                operation_id,
                recovery_from_operation_id,
                authorize_second_account_get,
            ),
        )
        return result

    monkeypatch.setattr(binding_cli, "execute_binding", forbidden_default_binding)
    monkeypatch.setattr(
        binding_cli,
        "execute_recovery_binding",
        capture_recovery,
    )

    assert (
        binding_cli.main(
            [
                "--env-file",
                str(env_path),
                "--operation-id",
                RECOVERY_OPERATION_ID,
                "--recovery-from-operation-id",
                OPERATION_ID,
                "--authorize-second-account-get",
            ],
        )
        == 0
    )
    assert calls == [
        (
            configuration,
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            True,
        ),
    ]
    assert json.loads(capsys.readouterr().out)["operation_id"] == (RECOVERY_OPERATION_ID)


def test_recovery_cli_failure_redacts_hostile_exception_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_owner_environment(tmp_path / "binding.env")
    hostile_error = (
        f"recovery failed with {API_KEY} {API_SECRET} {RUNTIME_URL} "
        "HOSTILE_RECOVERY_EXCEPTION_MARKER"
    )

    def fail_recovery(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise RuntimeError(hostile_error)

    monkeypatch.setattr(
        binding_cli,
        "execute_recovery_binding",
        fail_recovery,
    )

    assert (
        binding_cli.main(
            [
                "--env-file",
                str(path),
                "--operation-id",
                RECOVERY_OPERATION_ID,
                "--recovery-from-operation-id",
                OPERATION_ID,
                "--authorize-second-account-get",
            ],
        )
        == 2
    )
    output = capsys.readouterr().out
    payload = json.loads(output)
    for forbidden in (
        API_KEY,
        API_SECRET,
        "runtime-password",
        RUNTIME_URL,
        "HOSTILE_RECOVERY_EXCEPTION_MARKER",
        "postgresql+psycopg",
    ):
        assert forbidden not in output
    assert payload["reason"] == "binding_command_failed"
    assert payload["broker_action_authorized"] is False
    assert payload["trading_effect_authorized"] is False


def test_execute_calls_observer_once_and_releases_lease_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "binding-command.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    engine = sa.create_engine(database_url)
    metadata.create_all(engine)
    reference = _reference()
    resolver = binding_cli._OwnerEnvironmentCredentialResolver(
        reference=reference,
        api_key_id=API_KEY,
        secret_key=API_SECRET,
    )
    configuration = binding_cli._BindingEnvironment(
        database_url=RUNTIME_URL,
        reference=reference,
        credential_resolver=resolver,
    )
    control = binding_cli._control_snapshot(engine, reference.account_id)
    monkeypatch.setattr(
        binding_cli,
        "_verify_database_preconditions",
        lambda candidate, candidate_reference: control,
    )
    calls: list[dict[str, object]] = []

    def fail_observation(**kwargs: object) -> NoReturn:
        calls.append(kwargs)
        raise RuntimeError(f"hostile provider detail {API_SECRET}")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="account_observation_failed",
    ):
        binding_cli.execute_binding(
            configuration,
            OPERATION_ID,
            engine_factory=lambda value: engine,
            observer=fail_observation,
        )

    assert len(calls) == 1
    assert calls[0]["request_idempotency_key"] == (f"aqt.paper.account.request.{OPERATION_ID}")
    assert calls[0]["delivery_idempotency_key"] == (f"aqt.paper.account.delivery.{OPERATION_ID}")
    assert _resolver_consumed(resolver) is True

    readback_engine = sa.create_engine(database_url)
    try:
        with readback_engine.connect() as connection:
            head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
            assert head["current_lease_sha256"] is None
            assert head["last_fencing_generation"] == 1
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(phase2_account_leases),
                )
                == 1
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase2_account_lease_releases,
                    ),
                )
                == 1
            )
            for table in (
                phase4_broker_request_permits,
                phase4_broker_ingress_receipts,
                phase4_alpaca_paper_account_bindings,
            ):
                assert (
                    connection.scalar(
                        sa.select(sa.func.count()).select_from(table),
                    )
                    == 0
                )
    finally:
        readback_engine.dispose()


def test_execute_persists_and_authenticates_one_non_authorizing_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "successful-binding-command.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    engine = sa.create_engine(database_url)
    metadata.create_all(engine)
    reference = _reference(provider_account_id=FIXTURE_PROVIDER_ACCOUNT_ID)
    resolver = binding_cli._OwnerEnvironmentCredentialResolver(
        reference=reference,
        api_key_id=FIXTURE_API_KEY_ID,
        secret_key=FIXTURE_SECRET_KEY,
    )
    configuration = binding_cli._BindingEnvironment(
        database_url=RUNTIME_URL,
        reference=reference,
        credential_resolver=resolver,
    )
    observer_calls = 0

    def sqlite_preconditions(
        candidate: sa.Engine,
        candidate_reference: AlpacaPaperCredentialReference,
    ) -> binding_cli._ControlSnapshot:
        assert candidate is engine
        assert candidate_reference == reference
        return binding_cli._control_snapshot(candidate, reference.account_id)

    def observe_with_fixture_transport(
        **kwargs: Any,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        nonlocal observer_calls
        observer_calls += 1
        return _observe_authenticated_alpaca_paper_account_with_transport(
            transport=FixedTransport(),
            **kwargs,
        )

    monkeypatch.setattr(
        binding_cli,
        "_verify_database_preconditions",
        sqlite_preconditions,
    )
    monkeypatch.setattr(
        binding_cli,
        "verify_operational_schema",
        lambda candidate, require_phase_zero_facts: None,
    )

    result = binding_cli.execute_binding(
        configuration,
        OPERATION_ID,
        engine_factory=lambda value: engine,
        observer=observe_with_fixture_transport,
    )

    assert observer_calls == 1
    assert result.operation_id == OPERATION_ID
    assert result.sequence_number == 1
    assert result.public_payload["status"] == "paper_account_bound_non_authorizing"
    assert result.public_payload["raw_account_response_retained"] is True
    assert result.public_payload["submission_authorized"] is False
    assert result.public_payload["trading_effect_authorized"] is False
    assert result.public_payload["control_state_changed"] is False
    assert FIXTURE_PROVIDER_ACCOUNT_ID not in json.dumps(result.public_payload)
    assert _resolver_consumed(resolver) is True
    assert not _resolver_retains_credentials(resolver)


def test_under_lease_recheck_rejects_generation_two_before_observer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "raced-binding-command.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    engine = sa.create_engine(database_url)
    metadata.create_all(engine)
    reference = _reference()
    prior_coordinator = SqlAccountCoordinator(
        account_id=reference.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=binding_cli._LEASE_POLICY,
            clock=SystemClock(),
        ),
    )
    prior_lease = prior_coordinator.acquire("prior-owner")
    prior_coordinator.release(prior_lease.fence)
    control = binding_cli._control_snapshot(engine, reference.account_id)
    configuration = binding_cli._BindingEnvironment(
        database_url=RUNTIME_URL,
        reference=reference,
        credential_resolver=binding_cli._OwnerEnvironmentCredentialResolver(
            reference=reference,
            api_key_id=API_KEY,
            secret_key=API_SECRET,
        ),
    )
    monkeypatch.setattr(
        binding_cli,
        "_verify_database_preconditions",
        lambda candidate, candidate_reference: control,
    )
    observer_calls = 0

    def forbidden_observer(**kwargs: object) -> NoReturn:
        del kwargs
        nonlocal observer_calls
        observer_calls += 1
        pytest.fail("generation-two enrollment must stop before the provider call")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="concurrent_account_state_rejected",
    ):
        binding_cli.execute_binding(
            configuration,
            OPERATION_ID,
            engine_factory=lambda value: engine,
            observer=forbidden_observer,
        )

    assert observer_calls == 0
    readback_engine = sa.create_engine(database_url)
    try:
        with readback_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(phase2_account_leases),
                )
                == 2
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase2_account_lease_releases,
                    ),
                )
                == 2
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase4_broker_request_permits,
                    ),
                )
                == 0
            )
    finally:
        readback_engine.dispose()


def test_default_binding_still_rejects_the_raw_only_recovery_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'default-residual-rejected.sqlite3'}",
    )
    metadata.create_all(engine)
    _install_sqlite_preflight_adapter(monkeypatch)
    _seed_recoverable_raw_only_checkpoint(engine)
    configuration, resolver = _fixture_configuration()
    credential_resolution_calls = _track_credential_resolution(monkeypatch)
    observer_calls = 0

    def forbidden_observer(**kwargs: object) -> NoReturn:
        del kwargs
        nonlocal observer_calls
        observer_calls += 1
        pytest.fail("default enrollment must not resume a residual checkpoint")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="residual_account_state_rejected",
    ):
        binding_cli.execute_binding(
            configuration,
            RECOVERY_OPERATION_ID,
            engine_factory=lambda value: engine,
            observer=forbidden_observer,
        )

    assert observer_calls == 0
    assert credential_resolution_calls == []
    assert not _resolver_retains_credentials(resolver)
    _assert_account_history_counts(
        engine,
        configuration.reference.account_id,
        leases=1,
        releases=1,
        permits=1,
        ingress=1,
        bindings=0,
    )


def test_exact_raw_only_checkpoint_allows_one_append_only_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'successful-recovery.sqlite3'}",
    )
    metadata.create_all(engine)
    _install_sqlite_preflight_adapter(monkeypatch)
    _seed_recoverable_raw_only_checkpoint(engine)
    configuration, resolver = _fixture_configuration()
    account_id = configuration.reference.account_id
    control_before = binding_cli._control_snapshot(engine, account_id)
    prior_rows: dict[str, dict[str, object]] = {}
    prior_tables = (
        phase2_account_leases,
        phase2_account_lease_releases,
        phase4_broker_request_permits,
        phase4_broker_ingress_receipts,
    )
    with engine.connect() as connection:
        for table in prior_tables:
            prior_rows[table.name] = dict(
                connection.execute(
                    sa.select(table).where(table.c.account_id == account_id),
                )
                .mappings()
                .one(),
            )

    transport = FixedTransport()
    observer_calls: list[dict[str, Any]] = []

    def observe_second_account_get(
        **kwargs: Any,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        observer_calls.append(kwargs)
        return _observe_authenticated_alpaca_paper_account_with_transport(
            transport=transport,
            **kwargs,
        )

    result = binding_cli.execute_recovery_binding(
        configuration,
        RECOVERY_OPERATION_ID,
        OPERATION_ID,
        authorize_second_account_get=True,
        engine_factory=lambda value: engine,
        observer=observe_second_account_get,
    )

    assert result.operation_id == RECOVERY_OPERATION_ID
    assert result.sequence_number == 1
    assert result.public_payload["status"] == "paper_account_bound_non_authorizing"
    assert result.public_payload["raw_account_response_retained"] is True
    assert result.public_payload["submission_authorized"] is False
    assert result.public_payload["trading_effect_authorized"] is False
    assert len(observer_calls) == 1
    assert len(transport.request_sha256s) == 1
    assert observer_calls[0]["request_idempotency_key"] == (
        f"aqt.paper.account.request.{RECOVERY_OPERATION_ID}"
    )
    assert observer_calls[0]["delivery_idempotency_key"] == (
        f"aqt.paper.account.delivery.{RECOVERY_OPERATION_ID}"
    )
    assert _resolver_consumed(resolver) is True
    assert not _resolver_retains_credentials(resolver)

    _assert_account_history_counts(
        engine,
        account_id,
        leases=2,
        releases=2,
        permits=2,
        ingress=2,
        bindings=1,
    )
    for table in (
        phase2_account_lease_heads,
        phase4_broker_request_heads,
        phase4_broker_ingress_heads,
        phase4_alpaca_paper_account_binding_heads,
    ):
        assert _account_row_count(engine, table, account_id) == 1
    with engine.connect() as connection:
        for table in prior_tables:
            primary_key = next(iter(table.primary_key.columns))
            original = prior_rows[table.name]
            persisted = dict(
                connection.execute(
                    sa.select(table).where(
                        primary_key == original[primary_key.name],
                    ),
                )
                .mappings()
                .one(),
            )
            assert persisted == original
        permit_keys = tuple(
            connection.scalars(
                sa.select(phase4_broker_request_permits.c.idempotency_key)
                .where(phase4_broker_request_permits.c.account_id == account_id)
                .order_by(phase4_broker_request_permits.c.sequence_number),
            ),
        )
        delivery_keys = tuple(
            connection.scalars(
                sa.select(
                    phase4_broker_ingress_receipts.c.delivery_idempotency_key,
                )
                .where(phase4_broker_ingress_receipts.c.account_id == account_id)
                .order_by(phase4_broker_ingress_receipts.c.ingress_sequence),
            ),
        )
    assert permit_keys == (
        f"aqt.paper.account.request.{OPERATION_ID}",
        f"aqt.paper.account.request.{RECOVERY_OPERATION_ID}",
    )
    assert delivery_keys == (
        f"aqt.paper.account.delivery.{OPERATION_ID}",
        f"aqt.paper.account.delivery.{RECOVERY_OPERATION_ID}",
    )
    assert binding_cli._control_snapshot(engine, account_id) == control_before

    third_configuration, third_resolver = _fixture_configuration()
    credential_resolution_calls = _track_credential_resolution(monkeypatch)
    third_observer_calls = 0

    def forbidden_third_observer(**kwargs: object) -> NoReturn:
        del kwargs
        nonlocal third_observer_calls
        third_observer_calls += 1
        pytest.fail("the recovery contract must not generalize to generation three")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="recovery_checkpoint_rejected",
    ):
        binding_cli.execute_recovery_binding(
            third_configuration,
            THIRD_OPERATION_ID,
            RECOVERY_OPERATION_ID,
            authorize_second_account_get=True,
            engine_factory=lambda value: engine,
            observer=forbidden_third_observer,
        )

    assert third_observer_calls == 0
    assert credential_resolution_calls == []
    assert not _resolver_retains_credentials(third_resolver)
    _assert_account_history_counts(
        engine,
        account_id,
        leases=2,
        releases=2,
        permits=2,
        ingress=2,
        bindings=1,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_release",
        "extra_lease",
        "active_lease",
        "wrong_owner_key",
        "wrong_request_key",
        "wrong_delivery_key",
        "wrong_status",
        "wrong_request_id",
        "wrong_media_type",
        "wrong_correlation",
    ),
)
def test_malformed_recovery_checkpoint_fails_before_credentials_or_observer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / f'malformed-{mutation}.sqlite3'}",
    )
    metadata.create_all(engine)
    _install_sqlite_preflight_adapter(monkeypatch)
    _seed_recoverable_raw_only_checkpoint(engine)
    _mutate_recovery_checkpoint(engine, mutation)
    configuration, resolver = _fixture_configuration()
    credential_resolution_calls = _track_credential_resolution(monkeypatch)
    observer_calls = 0

    def forbidden_observer(**kwargs: object) -> NoReturn:
        del kwargs
        nonlocal observer_calls
        observer_calls += 1
        pytest.fail("malformed checkpoint must fail before the provider observer")

    with pytest.raises(binding_cli.PaperAccountBindingCommandError) as error:
        binding_cli.execute_recovery_binding(
            configuration,
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            authorize_second_account_get=True,
            engine_factory=lambda value: engine,
            observer=forbidden_observer,
        )

    assert error.value.reason_code in {
        "recovery_checkpoint_rejected",
        "recovery_database_preflight_rejected",
    }
    assert observer_calls == 0
    assert credential_resolution_calls == []
    assert not _resolver_retains_credentials(resolver)


@pytest.mark.parametrize(
    ("conflict", "reason"),
    (
        ("provider_alias", "provider_account_alias_conflict"),
        ("running_control", "running_control_rejected"),
    ),
)
def test_recovery_rejects_alias_or_control_conflict_before_provider_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict: str,
    reason: str,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / f'{conflict}-conflict.sqlite3'}",
    )
    metadata.create_all(engine)
    _install_sqlite_preflight_adapter(monkeypatch)
    _seed_recoverable_raw_only_checkpoint(engine)
    if conflict == "provider_alias":
        monkeypatch.setattr(
            binding_cli,
            "_provider_alias_count",
            lambda candidate, provider_account_id: 1,
        )
    else:
        control = binding_cli._control_snapshot(
            engine,
            _reference().account_id,
        )
        monkeypatch.setattr(
            binding_cli,
            "_control_snapshot",
            lambda candidate, account_id: binding_cli._ControlSnapshot(
                semantic_sha256=control.semantic_sha256,
                account_row_count=control.account_row_count,
                global_running_head_count=1,
            ),
        )
    configuration, resolver = _fixture_configuration()
    credential_resolution_calls = _track_credential_resolution(monkeypatch)
    observer_calls = 0

    def forbidden_observer(**kwargs: object) -> NoReturn:
        del kwargs
        nonlocal observer_calls
        observer_calls += 1
        pytest.fail("checkpoint conflict must fail before provider use")

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match=reason,
    ):
        binding_cli.execute_recovery_binding(
            configuration,
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            authorize_second_account_get=True,
            engine_factory=lambda value: engine,
            observer=forbidden_observer,
        )

    assert observer_calls == 0
    assert credential_resolution_calls == []
    assert not _resolver_retains_credentials(resolver)


def test_failed_second_observer_releases_generation_two_without_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'failed-second-observer.sqlite3'}",
    )
    metadata.create_all(engine)
    _install_sqlite_preflight_adapter(monkeypatch)
    _seed_recoverable_raw_only_checkpoint(engine)
    configuration, resolver = _fixture_configuration()
    account_id = configuration.reference.account_id
    control_before = binding_cli._control_snapshot(engine, account_id)
    transport = FixedTransport(fail=True)
    observer_calls = 0

    def fail_second_account_get(
        **kwargs: Any,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        nonlocal observer_calls
        observer_calls += 1
        return _observe_authenticated_alpaca_paper_account_with_transport(
            transport=transport,
            **kwargs,
        )

    with pytest.raises(
        binding_cli.PaperAccountBindingCommandError,
        match="account_observation_failed",
    ):
        binding_cli.execute_recovery_binding(
            configuration,
            RECOVERY_OPERATION_ID,
            OPERATION_ID,
            authorize_second_account_get=True,
            engine_factory=lambda value: engine,
            observer=fail_second_account_get,
        )

    assert observer_calls == 1
    assert len(transport.request_sha256s) == 1
    assert _resolver_consumed(resolver) is True
    assert not _resolver_retains_credentials(resolver)
    _assert_account_history_counts(
        engine,
        account_id,
        leases=2,
        releases=2,
        permits=2,
        ingress=1,
        bindings=0,
    )
    with engine.connect() as connection:
        lease_head = (
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == account_id,
                ),
            )
            .mappings()
            .one()
        )
    assert lease_head["last_fencing_generation"] == 2
    assert lease_head["current_fencing_generation"] is None
    assert lease_head["current_lease_sha256"] is None
    assert binding_cli._control_snapshot(engine, account_id) == control_before
