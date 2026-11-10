"""Parent CLI denials before locking or launch; no account or financial mocks."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from apps.trader.continuous_recovery import _emit, _finish_probe, main
from apps.trader.continuous_simulation_factory import ContinuousSimulationConfiguration
from packages.application import personal_codec as codec
from packages.application.continuous_process import ContinuousProcessSupervisor
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import ObjectRef


def _private_file(path, payload=b"test-owned private placeholder"):
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


@pytest.fixture
def case(tmp_path):
    root = tmp_path.resolve()
    root.chmod(0o700)
    account = _private_file(root / "account.sqlite")
    venue = _private_file(root / "venue.sqlite")
    objects, venue_objects, artifacts = (
        root / name for name in ("objects", "venue-objects", "results")
    )
    for directory in (objects, venue_objects, artifacts):
        directory.mkdir(mode=0o700)

    def reference(schema):
        return ContinuousEvidenceRef(
            schema,
            ObjectRef(content_digest((schema, "object")), 1),
            content_digest((schema, "value")),
        )

    configuration = ContinuousSimulationConfiguration(
        schema_id="continuous-offline-configuration/1",
        operation="restore",
        owner_id="unit-owner",
        database_path=str(account),
        venue_database_path=str(venue),
        artifact_root=str(objects),
        venue_artifact_root=str(venue_objects),
        inputs=reference("continuous-account-request/1"),
        venue_model=reference("venue-model/1"),
        producer_map=reference("runtime-producer-map/1"),
        benchmark_instrument_id=None,
        capture_evidence_class="synthetic_fixture",
        clock_profile="explicit_simulation_time_model",
        lease_policy_id="unit-lease",
        lease_policy_version="v1",
        lease_ttl_microseconds=60_000_000,
        maximum_in_flight_microseconds=5_000_000,
        takeover_safety_microseconds=10_000_000,
    )
    path = _private_file(root / "configuration.json", codec.encode_record(configuration))
    lock = root / "instance.lock"
    arguments = [
        "--configuration",
        str(path),
        "--account-id",
        "synthetic-account",
        "--operation-id",
        "first-restore",
        "--instance-lock",
        str(lock),
        "--artifact-directory",
        str(artifacts),
    ]
    return SimpleNamespace(
        root=root,
        path=path,
        lock=lock,
        artifacts=artifacts,
        account=account,
        venue=venue,
        objects=objects,
        venue_objects=venue_objects,
        configuration=configuration,
        arguments=arguments,
    )


@pytest.fixture
def no_launch(monkeypatch):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preflight attempted locking or child supervision")

    monkeypatch.setattr(LocalInstanceGuard, "__enter__", forbidden)
    monkeypatch.setattr(ContinuousProcessSupervisor, "run", forbidden)
    return calls


def _summary(capsys, *, reason):
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert value["trading_authority"] is False
    assert value == {
        "schema": "continuous-synthetic-recovery-summary/1",
        "status": "failed",
        "reason": reason,
        "operation": "restore",
        "trading_authority": False,
    }
    assert captured.out == json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


@pytest.mark.parametrize(
    "option",
    (
        "--configuration",
        "--account-id",
        "--operation-id",
        "--instance-lock",
        "--artifact-directory",
    ),
)
def test_every_required_argument_is_explicit(case, no_launch, capsys, option):
    arguments = list(case.arguments)
    index = arguments.index(option)
    del arguments[index : index + 2]
    assert main(arguments) == 2
    _summary(capsys, reason="invalid_arguments")
    assert no_launch == [] and not case.lock.exists()


@pytest.mark.parametrize(
    "extra",
    (
        ["--worker"],
        ["--live"],
        ["--wall-seconds", "120"],
        ["--cpu-seconds", "120"],
        ["--memory-bytes", "1073741824"],
        ["--clock-profile", "host_unqualified"],
        ["--factory", "unreviewed.module"],
        ["--configuration=/private/secret.json"],
        ["--account-id", "other-account"],
        ["--account-id=other-account"],
        ["extra-positional"],
    ),
)
def test_unknown_overrides_or_duplicate_arguments_never_reach_recovery(
    case, no_launch, capsys, extra
):
    assert main([*case.arguments, *extra]) == 2
    _summary(capsys, reason="invalid_arguments")
    assert no_launch == [] and not case.lock.exists()


def test_option_abbreviations_are_not_an_alternate_launch_interface(case, no_launch, capsys):
    arguments = list(case.arguments)
    arguments[0] = "--conf"
    assert main(arguments) == 2
    _summary(capsys, reason="invalid_arguments")
    assert no_launch == []


@pytest.mark.parametrize(
    "option,value",
    (
        ("--account-id", "../private-account"),
        ("--account-id", " account"),
        ("--account-id", "x" * 129),
        ("--operation-id", "operation/escape"),
        ("--operation-id", ""),
        ("--operation-id", "_operation"),
    ),
)
def test_malformed_identities_fail_without_locking(case, no_launch, capsys, option, value):
    arguments = list(case.arguments)
    arguments[arguments.index(option) + 1] = value
    assert main(arguments) == 2
    _summary(capsys, reason="configuration_invalid")
    assert no_launch == [] and not case.lock.exists()


@pytest.mark.parametrize(
    "changes",
    (
        {"operation": "integrity"},
        {"capture_evidence_class": "provider_https_read"},
        {"clock_profile": "host_unqualified"},
        {"lease_ttl_microseconds": 61_000_000},
        {"maximum_in_flight_microseconds": 6_000_000},
        {"takeover_safety_microseconds": 11_000_000},
    ),
)
def test_nonselected_profiles_and_policy_changes_fail_before_lock_or_sql(
    case, no_launch, capsys, changes
):
    changed = replace(case.configuration, **changes)
    _private_file(case.path, codec.encode_record(changed))
    before = case.path.read_bytes(), case.account.read_bytes(), case.venue.read_bytes()
    assert main(case.arguments) == 2
    _summary(capsys, reason="configuration_invalid")
    assert (case.path.read_bytes(), case.account.read_bytes(), case.venue.read_bytes()) == before
    assert no_launch == [] and not case.lock.exists() and tuple(case.artifacts.iterdir()) == ()


@pytest.mark.parametrize(
    "damage",
    (
        "relative_configuration",
        "missing_configuration",
        "symlink_configuration",
        "hardlink_configuration",
        "public_configuration",
        "noncanonical_configuration",
        "oversized_configuration",
        "relative_lock",
        "missing_lock_parent",
        "public_lock_parent",
        "symlink_artifacts",
        "public_artifacts",
        "missing_artifacts",
        "lock_is_database",
        "lock_is_configuration",
        "lock_is_venue",
        "lock_inside_objects",
        "artifacts_are_objects",
        "artifacts_contain_stores",
        "artifacts_inside_objects",
        "configuration_is_env_path",
        "missing_account",
        "missing_venue",
        "missing_objects",
        "missing_venue_objects",
    ),
)
def test_private_path_and_storage_alias_denials_preserve_original_files(
    case, no_launch, capsys, damage
):
    arguments = list(case.arguments)

    def set_argument(option, value):
        arguments[arguments.index(option) + 1] = str(value)

    if damage == "relative_configuration":
        set_argument("--configuration", "configuration.json")
    elif damage == "missing_configuration":
        case.path.unlink()
    elif damage == "symlink_configuration":
        link = case.root / "configuration-link.json"
        link.symlink_to(case.path)
        set_argument("--configuration", link)
    elif damage == "hardlink_configuration":
        link = case.root / "configuration-copy.json"
        link.hardlink_to(case.path)
        set_argument("--configuration", link)
    elif damage == "public_configuration":
        case.path.chmod(0o644)
    elif damage == "noncanonical_configuration":
        _private_file(case.path, b" " + case.path.read_bytes())
    elif damage == "oversized_configuration":
        _private_file(case.path, b"x" * (65536 + 1))
    elif damage == "relative_lock":
        set_argument("--instance-lock", "instance.lock")
    elif damage == "missing_lock_parent":
        set_argument("--instance-lock", case.root / "missing" / "instance.lock")
    elif damage == "public_lock_parent":
        directory = case.root / "public"
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        set_argument("--instance-lock", directory / "instance.lock")
    elif damage == "symlink_artifacts":
        link = case.root / "results-link"
        link.symlink_to(case.artifacts, target_is_directory=True)
        set_argument("--artifact-directory", link)
    elif damage == "public_artifacts":
        case.artifacts.chmod(0o755)
    elif damage == "missing_artifacts":
        set_argument("--artifact-directory", case.root / "missing-results")
    elif damage == "lock_is_database":
        set_argument("--instance-lock", case.account)
    elif damage == "lock_is_configuration":
        set_argument("--instance-lock", case.path)
    elif damage == "lock_is_venue":
        set_argument("--instance-lock", case.venue)
    elif damage == "lock_inside_objects":
        set_argument("--instance-lock", case.objects / "instance.lock")
    elif damage == "artifacts_are_objects":
        set_argument("--artifact-directory", case.objects)
    elif damage == "artifacts_contain_stores":
        set_argument("--artifact-directory", case.root)
    elif damage == "artifacts_inside_objects":
        directory = case.objects / "child-results"
        directory.mkdir(mode=0o700)
        set_argument("--artifact-directory", directory)
    elif damage == "configuration_is_env_path":
        directory = case.root / ".env-test-owned"
        directory.mkdir(mode=0o700)
        path = _private_file(directory / "configuration.json", case.path.read_bytes())
        set_argument("--configuration", path)
    elif damage == "missing_account":
        case.account.unlink()
    elif damage == "missing_venue":
        case.venue.unlink()
    elif damage == "missing_objects":
        case.objects.rmdir()
    elif damage == "missing_venue_objects":
        case.venue_objects.rmdir()
    else:
        raise AssertionError("unknown adverse path case")

    def snapshot():
        return (
            tuple(
                path.read_bytes() if path.exists() else None
                for path in (case.path, case.account, case.venue)
            ),
            tuple(
                tuple(sorted(path.name for path in directory.iterdir()))
                if directory.exists()
                else None
                for directory in (case.artifacts, case.objects, case.venue_objects)
            ),
        )

    before = snapshot()
    assert main(arguments) == 2
    _summary(capsys, reason="configuration_invalid")
    assert snapshot() == before
    assert no_launch == [] and not case.lock.exists()
    assert not (case.root / "missing").exists() and not (case.root / "missing-results").exists()


def test_help_does_not_construct_an_operation(case, no_launch, capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    captured = capsys.readouterr()
    assert "--configuration" in captured.out and "--artifact-directory" in captured.out
    assert captured.err == "" and no_launch == [] and not case.lock.exists()


def test_otherwise_valid_unit_configuration_reaches_only_the_actual_held_lock_denial(
    case, monkeypatch, capsys
):
    launches = []

    def forbidden(*args, **kwargs):
        launches.append((args, kwargs))
        raise AssertionError("duplicate parent reached the supervisor")

    monkeypatch.setattr(ContinuousProcessSupervisor, "run", forbidden)
    before = case.path.read_bytes(), case.account.read_bytes(), case.venue.read_bytes()
    with LocalInstanceGuard(case.lock) as guard:
        identity = guard.fileno()
        assert main(case.arguments) == 2
        _summary(capsys, reason="instance_busy")
        assert guard.fileno() == identity
    assert (case.path.read_bytes(), case.account.read_bytes(), case.venue.read_bytes()) == before
    assert launches == [] and not tuple(case.artifacts.iterdir())


@pytest.mark.parametrize(
    "primary",
    (
        ("completed", "completed", 0),
        ("failed", "child_failed", 3),
        ("stopped", "stopped", 3),
    ),
)
def test_cleanup_failure_format_never_hides_the_declared_public_primary_result(capsys, primary):
    # Pure reporting contract only. These declared tuples are not process
    # outcomes and do not qualify any mocked recovery or cleanup as successful.
    assert _emit(primary, cleanup_complete=False) == 3
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert value["cleanup_complete"] is False and value["trading_authority"] is False
    assert value == {
        "schema": "continuous-synthetic-recovery-summary/1",
        "status": "failed",
        "reason": "cleanup_incomplete",
        "operation": "restore",
        "trading_authority": False,
        "cleanup_complete": False,
        "primary_status": primary[0],
        "primary_reason": primary[1],
    }
    assert captured.out.count("\n") == 1


def _probe_boundary(*, alive, disposal_error=None, complete=True):
    events = []

    class Thread:
        def is_alive(self):
            events.append("is_alive")
            return alive

        def join(self, *args, **kwargs):
            events.append("join")
            raise AssertionError("the CLI must not add a wait or cleanup grace")

    class Engine:
        def dispose(self):
            events.append("dispose")
            if disposal_error is not None:
                raise disposal_error("test-owned private disposal detail")

    def read_cleanup():
        events.append("cleanup")
        return complete

    return (
        SimpleNamespace(_probe_thread=Thread(), _read_cleanup_complete=read_cleanup),
        SimpleNamespace(_database=SimpleNamespace(engine=Engine())),
        events,
    )


def test_live_probe_cannot_be_waited_disposed_or_claimed_complete():
    supervisor, probe, events = _probe_boundary(alive=True)
    assert _finish_probe(supervisor, probe) is False
    assert events == ["is_alive"]


@pytest.mark.parametrize("disposal_error", (OSError, KeyboardInterrupt))
def test_ended_probe_disposal_failure_is_reported_incomplete(disposal_error):
    supervisor, probe, events = _probe_boundary(alive=False, disposal_error=disposal_error)
    assert _finish_probe(supervisor, probe) is False
    assert events == ["is_alive", "dispose"]


def test_ended_probe_disposal_cannot_turn_original_incomplete_cleanup_into_success():
    supervisor, probe, events = _probe_boundary(alive=False, complete=False)
    assert _finish_probe(supervisor, probe) is False
    assert events == ["is_alive", "dispose", "cleanup"]


def test_unexpected_supervisor_exception_never_prints_private_text(case, monkeypatch, capsys):
    calls = []

    def fail(supervisor, request, **kwargs):
        # New CLI exception classification only; no child has been launched and
        # no fake outcome is used as a recovery acceptance result.
        calls.append((supervisor, request, kwargs))
        raise RuntimeError("secret exception text including " + str(case.root))

    monkeypatch.setattr(ContinuousProcessSupervisor, "run", fail)
    assert main(case.arguments) == 3
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "schema": "continuous-synthetic-recovery-summary/1",
        "status": "failed",
        "reason": "recovery_failed",
        "operation": "restore",
        "trading_authority": False,
        "cleanup_complete": True,
    }
    assert str(case.root) not in captured.out and "secret" not in captured.out
    assert len(calls) == 1 and calls[0][2]["lifecycle"]._database is None
    assert not tuple(case.artifacts.iterdir())
    with LocalInstanceGuard(case.lock):
        pass


def test_summary_output_failure_returns_failure_without_secondary_private_output(
    monkeypatch, capsys
):
    calls = []

    def fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise OSError("private output failure")

    with monkeypatch.context() as patch:
        patch.setattr("builtins.print", fail)
        assert _emit(("completed", "completed", 0), cleanup_complete=True) == 3
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert len(calls) == 1
    assert json.loads(calls[0][0][0])["trading_authority"] is False
