from __future__ import annotations

import json
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
    phase4_alpaca_paper_account_bindings,
    phase4_broker_ingress_receipts,
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
