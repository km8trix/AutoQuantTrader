from __future__ import annotations

import hashlib
import sys
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, localcontext
from pathlib import Path

import pytest

from packages.adapters.trusted_time.chrony_nts import (
    CHRONY_NTS_C_LOCALE_ENVIRONMENT,
    CHRONY_NTS_MAX_OUTPUT_BYTES,
    ChronycCommandResult,
    ChronyNtsAuthority,
    ChronyNtsError,
    ChronyNtsTrustedTimeSource,
    _run_bounded_chronyc,
)
from packages.application.trusted_time_monitor import TrustedTimeSourceReading

BASE = datetime(2026, 7, 31, 14, 0, tzinfo=UTC)
AUTHORITY_SHA256 = "a" * 64


def _base_python_executable() -> str:
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    assert candidate.is_file() and not candidate.is_symlink()
    return str(candidate)


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if not self.values:
            raise RuntimeError("secret clock detail")
        return self.values.pop(0)


class Runner:
    def __init__(
        self,
        result: object,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.result = result
        self.failure = failure
        self.calls = 0
        self.argv: tuple[str, ...] | None = None
        self.deadline_monotonic_ns: int | None = None
        self.monotonic_clock: Callable[[], int] | None = None
        self.max_output_bytes: int | None = None
        self.environment: tuple[tuple[str, str], ...] | None = None

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        monotonic_clock: Callable[[], int],
        max_output_bytes: int,
        environment: tuple[tuple[str, str], ...],
    ) -> object:
        self.calls += 1
        self.argv = argv
        self.deadline_monotonic_ns = deadline_monotonic_ns
        self.monotonic_clock = monotonic_clock
        self.max_output_bytes = max_output_bytes
        self.environment = environment
        if self.failure is not None:
            raise self.failure
        return self.result


def _authority(**overrides: object) -> ChronyNtsAuthority:
    values: dict[str, object] = {
        "source_id": "chrony-nts-composite-v2",
        "source_authority_sha256": AUTHORITY_SHA256,
        "chronyc_path": "/usr/bin/chronyc",
        "socket_path": "/run/chrony/chronyd.sock",
        "chrony_version": "4.8",
        "ordered_source_names": (
            "time.cloudflare.com",
            "virginia.time.system76.com",
        ),
        "ordered_ntp_ports": (123, 123),
        "maximum_reference_age_seconds": 30,
    }
    values.update(overrides)
    return ChronyNtsAuthority(**values)  # type: ignore[arg-type]


def _epoch(value: datetime) -> str:
    seconds = int(value.timestamp())
    return f"{seconds}.{value.microsecond * 1_000:09d}"


def _ntp_line(
    *,
    remote: str,
    remote_ref_id: str,
    port: int,
    stratum: int = 1,
    authenticated: str = "Yes",
    poll: str = "4",
    poll_seconds: str = "16",
    tests: tuple[str, str, str] = ("111", "111", "1111"),
    total_good: str = "22",
) -> str:
    fields = (
        remote,
        remote_ref_id,
        str(port),
        "172.17.0.2",
        "AC110002",
        "Normal",
        "4",
        "Server",
        str(stratum),
        poll,
        poll_seconds,
        "-24",
        "0.000000060",
        "0.000100",
        "0.000200",
        "47505300",
        "GPS",
        _epoch(BASE - timedelta(seconds=6)),
        "-0.000060878",
        "0.000175634",
        "0.000000681",
        "0.000053050",
        "0.00",
        *tests,
        "No",
        authenticated,
        "Kernel",
        "Kernel",
        "24",
        "24",
        "24",
        total_good,
        "24",
        "24",
        "0",
        "0",
    )
    assert len(fields) == 38
    return ",".join(fields)


def _payload(
    *,
    reference_at: datetime | None = None,
    correction: str = "0.002000000",
    root_delay: str = "0.020000000",
    root_dispersion: str = "0.010000000",
    tracking_leap: str = "Normal",
    tracking_stratum: str = "2",
    tracking_source: str = "time.cloudflare.com",
    tracking_ref_id: str = "A29FC801",
    select_states: tuple[str, str] = ("*", "+"),
    select_names: tuple[str, str] = (
        "time.cloudflare.com",
        "virginia.time.system76.com",
    ),
    select_auth: tuple[str, str] = ("Y", "Y"),
    select_leap: tuple[str, str] = ("Normal", "Normal"),
    select_last: tuple[str, str] = ("1", "1"),
    auth_modes: tuple[str, str] = ("NTS", "NTS"),
    auth_key_ids: tuple[str, str] = ("1", "1"),
    auth_key_types: tuple[str, str] = ("15", "15"),
    auth_key_lengths: tuple[str, str] = ("256", "256"),
    auth_attempts: tuple[str, str] = ("0", "0"),
    auth_naks: tuple[str, str] = ("0", "0"),
    auth_cookies: tuple[str, str] = ("8", "8"),
    ntp_lines: tuple[str, str] | None = None,
) -> bytes:
    reference = BASE - timedelta(seconds=5) if reference_at is None else reference_at
    tracking = ",".join(
        (
            tracking_ref_id,
            tracking_source,
            tracking_stratum,
            _epoch(reference),
            correction,
            "-0.000001000",
            "0.000002000",
            "1.000",
            "0.000",
            "0.100",
            root_delay,
            root_dispersion,
            "16.0",
            tracking_leap,
        )
    )
    selection = tuple(
        ",".join(
            (
                state,
                name,
                authentication,
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                last,
                "1.0",
                "-0.010000000",
                "0.010000000",
                leap,
            )
        )
        for state, name, authentication, last, leap in zip(
            select_states,
            select_names,
            select_auth,
            select_last,
            select_leap,
            strict=True,
        )
    )
    authentication = tuple(
        ",".join(
            (
                name,
                mode,
                key_id,
                key_type,
                key_length,
                "10",
                attempts,
                nak,
                cookies,
                "100",
            )
        )
        for name, mode, key_id, key_type, key_length, attempts, nak, cookies in zip(
            ("time.cloudflare.com", "virginia.time.system76.com"),
            auth_modes,
            auth_key_ids,
            auth_key_types,
            auth_key_lengths,
            auth_attempts,
            auth_naks,
            auth_cookies,
            strict=True,
        )
    )
    ntp = ntp_lines or (
        _ntp_line(remote="162.159.200.1", remote_ref_id="A29FC801", port=123),
        _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
    )
    lines = (
        ".",
        tracking,
        ".",
        *selection,
        ".",
        *authentication,
        ".",
        *ntp,
        ".",
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _source(
    payload: bytes | None = None,
    *,
    runner: Runner | None = None,
    utc_values: tuple[object, ...] = (BASE, BASE + timedelta(milliseconds=20)),
    monotonic_values: tuple[object, ...] = (1_000, 1_000, 20_001_000),
) -> tuple[ChronyNtsTrustedTimeSource, Runner]:
    actual_runner = runner or Runner(
        ChronycCommandResult(
            returncode=0, stdout=_payload() if payload is None else payload, stderr=b""
        )
    )
    source = ChronyNtsTrustedTimeSource(
        authority=_authority(),
        utc_clock=SequenceClock(*utc_values),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(*monotonic_values),  # type: ignore[arg-type]
        runner=actual_runner,  # type: ignore[arg-type]
    )
    return source, actual_runner


def _read(
    payload: bytes | None = None,
    *,
    runner: Runner | None = None,
    deadline_monotonic_ns: int = 1_000_001_000,
    utc_values: tuple[object, ...] = (BASE, BASE + timedelta(milliseconds=20)),
    monotonic_values: tuple[object, ...] = (1_000, 1_000, 20_001_000),
) -> TrustedTimeSourceReading:
    source, _ = _source(
        payload,
        runner=runner,
        utc_values=utc_values,
        monotonic_values=monotonic_values,
    )
    return source.read_trusted_time(deadline_monotonic_ns=deadline_monotonic_ns)


def test_admits_exact_composite_and_returns_v2_correlated_reading() -> None:
    source, runner = _source()

    reading = source.read_trusted_time(deadline_monotonic_ns=1_000_001_000)

    assert runner.calls == 1
    assert runner.argv == (
        "/usr/bin/chronyc",
        "-h",
        "/run/chrony/chronyd.sock",
        "-c",
        "-N",
        "-e",
        "-m",
        "retries 0",
        "tracking",
        "selectdata -a",
        "authdata -a",
        "ntpdata",
    )
    assert runner.deadline_monotonic_ns == 1_000_001_000
    assert runner.monotonic_clock is source.monotonic_clock
    assert runner.max_output_bytes == CHRONY_NTS_MAX_OUTPUT_BYTES
    assert runner.environment == CHRONY_NTS_C_LOCALE_ENVIRONMENT
    assert reading.source_id == "chrony-nts-composite-v2"
    assert reading.source_authority_sha256 == AUTHORITY_SHA256
    assert reading.local_observed_at_utc == BASE + timedelta(milliseconds=10)
    assert reading.trusted_at_utc == BASE + timedelta(milliseconds=12)
    assert reading.observed_at_monotonic_ns == 10_001_000
    assert reading.source_uncertainty_milliseconds == Decimal("30")
    assert len(reading.source_evidence_sha256) == 64
    assert reading.source_evidence_sha256 != hashlib.sha256(_payload()).hexdigest()


def test_admits_system76_as_selected_with_cloudflare_combined() -> None:
    reading = _read(
        _payload(
            tracking_source="virginia.time.system76.com",
            tracking_ref_id="03DC2A27",
            select_states=("+", "*"),
        )
    )

    assert reading.source_id == "chrony-nts-composite-v2"
    assert reading.source_uncertainty_milliseconds == Decimal("30")


def test_normalized_evidence_hash_is_deterministic_and_binds_semantics() -> None:
    first = _read()
    repeated = _read()
    changed = _read(_payload(auth_key_types=("30", "15"), auth_key_lengths=("128", "256")))

    assert first.source_evidence_sha256 == repeated.source_evidence_sha256
    assert first.source_evidence_sha256 != changed.source_evidence_sha256


def test_admission_arithmetic_does_not_depend_on_mutable_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        reading = _read()

    assert reading.source_uncertainty_milliseconds == Decimal("30")


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_id": " unsafe"},
        {"source_authority_sha256": "A" * 64},
        {"chronyc_path": "usr/bin/chronyc"},
        {"chronyc_path": "/usr/../bin/chronyc"},
        {"socket_path": "/run//chrony/chronyd.sock"},
        {"chrony_version": "4.9"},
        {"ordered_source_names": ("virginia.time.system76.com", "time.cloudflare.com")},
        {
            "ordered_source_names": (
                "time.cloudflare.com",
                "virginia.time.system76.com",
                "extra",
            )
        },
        {"ordered_ntp_ports": (123, 124)},
        {"maximum_reference_age_seconds": 31},
    ],
)
def test_authority_is_an_exact_closed_contract(overrides: dict[str, object]) -> None:
    with pytest.raises(ChronyNtsError):
        _authority(**overrides)


def test_authority_hash_binds_fixed_launch_and_non_authorizing_policy() -> None:
    authority = _authority()

    assert len(authority.semantic_sha256) == 64
    assert authority.semantic_sha256 != authority.source_authority_sha256
    assert "127.0.0.1" not in authority.argv
    assert "::1" not in authority.argv


def test_expired_deadline_fails_before_process_effect() -> None:
    source, runner = _source(monotonic_values=(1_000,))

    with pytest.raises(ChronyNtsError, match="already expired"):
        source.read_trusted_time(deadline_monotonic_ns=1_000)

    assert runner.calls == 0


def test_runner_receives_tighter_outer_deadline_as_absolute_boottime() -> None:
    source, runner = _source(monotonic_values=(1_000, 2_000, 3_000))

    source.read_trusted_time(deadline_monotonic_ns=4_000)

    assert runner.deadline_monotonic_ns == 4_000
    assert runner.monotonic_clock is source.monotonic_clock


def test_runner_exception_is_sanitized_and_never_retried() -> None:
    runner = Runner(None, failure=RuntimeError("secret socket and credential detail"))
    source, _ = _source(runner=runner)

    with pytest.raises(ChronyNtsError, match="process was unavailable") as captured:
        source.read_trusted_time(deadline_monotonic_ns=1_000_001_000)

    assert runner.calls == 1
    assert "secret" not in str(captured.value)
    assert "credential" not in str(captured.value)


@pytest.mark.parametrize(
    "result",
    [
        object(),
        ChronycCommandResult(returncode=1, stdout=_payload(), stderr=b""),
        ChronycCommandResult(returncode=0, stdout=_payload(), stderr=b"secret warning"),
        ChronycCommandResult(returncode=0, stdout=b"", stderr=b""),
        ChronycCommandResult(
            returncode=0,
            stdout=b"x" * (CHRONY_NTS_MAX_OUTPUT_BYTES + 1),
            stderr=b"",
        ),
    ],
)
def test_non_exact_process_results_fail_closed_without_disclosure(result: object) -> None:
    runner = Runner(result)

    with pytest.raises(ChronyNtsError, match="process result was rejected") as captured:
        _read(runner=runner)

    assert runner.calls == 1
    assert "warning" not in str(captured.value)


@pytest.mark.parametrize(
    "payload",
    [
        _payload().rstrip(b"\n"),
        _payload().replace(b"\n.\n", b"\r\n.\r\n", 1),
        _payload() + b".\n",
        _payload().replace(b"\n.\n", b"\nextra\n.\n", 1),
        _payload().replace(b"time.cloudflare.com", b'"time.cloudflare.com"', 1),
        _payload().replace(b"time.cloudflare.com", b"time.cloudfl\xffre.com", 1),
    ],
)
def test_csv_framing_and_ascii_contract_are_exact(payload: bytes) -> None:
    with pytest.raises(ChronyNtsError, match="evidence was rejected"):
        _read(payload)


@pytest.mark.parametrize(
    "payload",
    [
        _payload(select_states=("*", "*")),
        _payload(select_states=("+", "+")),
        _payload(select_names=("virginia.time.system76.com", "time.cloudflare.com")),
        _payload(select_auth=("N", "Y")),
        _payload(select_leap=("Insert second", "Normal")),
        _payload(select_last=("31", "1")),
        _payload(tracking_source="virginia.time.system76.com"),
        _payload(tracking_ref_id="03DC2A27"),
        _payload(tracking_stratum="16"),
        _payload(tracking_leap="Not synchronised"),
    ],
)
def test_selection_and_tracking_substitution_or_degradation_is_rejected(payload: bytes) -> None:
    with pytest.raises(ChronyNtsError, match="evidence was rejected"):
        _read(payload)


@pytest.mark.parametrize(
    "payload",
    [
        _payload(auth_modes=("SK", "NTS")),
        _payload(auth_key_ids=("0", "1")),
        _payload(auth_key_types=("14", "15")),
        _payload(auth_key_lengths=("128", "256")),
        _payload(auth_attempts=("1", "0")),
        _payload(auth_attempts=("2", "0")),
        _payload(auth_naks=("1", "0")),
        _payload(auth_cookies=("7", "8")),
    ],
)
def test_nts_key_cookie_and_nak_contract_is_fail_closed(payload: bytes) -> None:
    with pytest.raises(ChronyNtsError, match="evidence was rejected"):
        _read(payload)


def test_both_documented_nts_aead_key_shapes_are_admitted() -> None:
    reading = _read(
        _payload(
            auth_key_types=("15", "30"),
            auth_key_lengths=("256", "128"),
        )
    )

    assert reading.source_uncertainty_milliseconds == Decimal("30")


@pytest.mark.parametrize(
    "ntp_lines",
    [
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC801",
                port=124,
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC802",
                port=123,
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC801",
                port=123,
                authenticated="No",
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC801",
                port=123,
                poll="5",
                poll_seconds="32",
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC801",
                port=123,
                tests=("111", "110", "1111"),
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(
                remote="162.159.200.1",
                remote_ref_id="A29FC801",
                port=123,
                total_good="25",
            ),
            _ntp_line(remote="3.220.42.39", remote_ref_id="03DC2A27", port=123),
        ),
        (
            _ntp_line(remote="162.159.200.1", remote_ref_id="A29FC801", port=123),
            _ntp_line(remote="162.159.200.1", remote_ref_id="A29FC801", port=123),
        ),
    ],
)
def test_ntpdata_authentication_identity_poll_and_packet_invariants_are_exact(
    ntp_lines: tuple[str, str],
) -> None:
    with pytest.raises(ChronyNtsError, match="evidence was rejected"):
        _read(_payload(ntp_lines=ntp_lines))


def test_reference_freshness_admits_equality_and_rejects_future_or_stale() -> None:
    # The local inner midpoint is BASE+10ms and the correction is +2ms.
    exact_boundary = BASE + timedelta(milliseconds=12) - timedelta(seconds=30)
    admitted = _read(_payload(reference_at=exact_boundary))

    assert admitted.trusted_at_utc == BASE + timedelta(milliseconds=12)
    with pytest.raises(ChronyNtsError, match="tracking reference was stale"):
        _read(_payload(reference_at=exact_boundary - timedelta(microseconds=1)))
    with pytest.raises(ChronyNtsError, match="tracking reference was stale"):
        _read(_payload(reference_at=BASE + timedelta(milliseconds=13)))


def test_uncertainty_admits_exact_100ms_and_rejects_one_nanosecond_over() -> None:
    exact = _read(
        _payload(
            root_delay="0.020000000",
            root_dispersion="0.080000000",
        )
    )

    assert exact.source_uncertainty_milliseconds == Decimal("100")
    with pytest.raises(ChronyNtsError, match="uncertainty exceeded"):
        _read(
            _payload(
                root_delay="0.020000000",
                root_dispersion="0.080000001",
            )
        )


def test_uncertainty_includes_clock_divergence_and_microsecond_midpoint_residual() -> None:
    reading = _read(
        utc_values=(BASE, BASE + timedelta(microseconds=20_001)),
        monotonic_values=(1_000, 1_000, 20_001_000),
    )

    # 10ms dispersion + 10ms half-delay + 10ms half inner interval,
    # plus 1us clock divergence and a 0.5us midpoint residual.
    assert reading.source_uncertainty_milliseconds == Decimal("30.0015")
    assert reading.local_observed_at_utc == BASE + timedelta(milliseconds=10)


@pytest.mark.parametrize(
    ("utc_values", "monotonic_values", "deadline"),
    [
        ((BASE + timedelta(seconds=1), BASE), (1_000, 1_000, 2_000), 1_000_001_000),
        ((BASE, BASE), (2_000, 2_000, 1_000), 1_000_001_000),
        ((BASE, BASE), (1_000, 1_000, 1_000_001_001), 1_000_001_000),
    ],
)
def test_regressing_or_late_inner_observation_interval_is_rejected(
    utc_values: tuple[object, object],
    monotonic_values: tuple[object, object],
    deadline: int,
) -> None:
    with pytest.raises(ChronyNtsError, match="inner observation interval was invalid"):
        _read(
            utc_values=utc_values,
            monotonic_values=monotonic_values,
            deadline_monotonic_ns=deadline,
        )


def test_default_runner_captures_one_small_no_shell_process() -> None:
    monotonic_clock = time.monotonic_ns
    result = _run_bounded_chronyc(
        (
            _base_python_executable(),
            "-I",
            "-B",
            "-c",
            "import sys; sys.stdout.buffer.write(b'ok')",
        ),
        deadline_monotonic_ns=monotonic_clock() + 1_000_000_000,
        monotonic_clock=monotonic_clock,
        max_output_bytes=8,
        environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
    )

    assert result == ChronycCommandResult(returncode=0, stdout=b"ok", stderr=b"")


def test_default_runner_enforces_output_and_time_bounds() -> None:
    monotonic_clock = time.monotonic_ns
    with pytest.raises(ChronyNtsError, match="output exceeded"):
        _run_bounded_chronyc(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 10000)",
            ),
            deadline_monotonic_ns=monotonic_clock() + 1_000_000_000,
            monotonic_clock=monotonic_clock,
            max_output_bytes=16,
            environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
        )
    with pytest.raises(ChronyNtsError, match="exceeded its deadline"):
        _run_bounded_chronyc(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                "import time; time.sleep(1)",
            ),
            deadline_monotonic_ns=monotonic_clock() + 10_000_000,
            monotonic_clock=monotonic_clock,
            max_output_bytes=16,
            environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
        )


def test_default_runner_uses_injected_suspend_aware_deadline() -> None:
    monotonic_clock = SequenceClock(10, 10, 1_000_000_011)

    with pytest.raises(ChronyNtsError, match="exceeded its deadline"):
        _run_bounded_chronyc(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                "import time; time.sleep(10)",
            ),
            deadline_monotonic_ns=1_000_000_010,
            monotonic_clock=monotonic_clock,  # type: ignore[arg-type]
            max_output_bytes=16,
            environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
        )

    assert monotonic_clock.calls == 3


def test_default_runner_rejects_more_than_one_second_before_process_launch() -> None:
    monotonic_clock = SequenceClock(10)

    with pytest.raises(ChronyNtsError, match="process deadline is invalid"):
        _run_bounded_chronyc(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                "raise SystemExit('must not launch')",
            ),
            deadline_monotonic_ns=1_000_000_011,
            monotonic_clock=monotonic_clock,  # type: ignore[arg-type]
            max_output_bytes=16,
            environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
        )


def test_exact_dataclass_types_are_required() -> None:
    authority = _authority()

    class DerivedAuthority(ChronyNtsAuthority):
        pass

    derived = DerivedAuthority(
        source_id=authority.source_id,
        source_authority_sha256=authority.source_authority_sha256,
        chronyc_path=authority.chronyc_path,
        socket_path=authority.socket_path,
        chrony_version=authority.chrony_version,
        ordered_source_names=authority.ordered_source_names,
        ordered_ntp_ports=authority.ordered_ntp_ports,
        maximum_reference_age_seconds=authority.maximum_reference_age_seconds,
    )
    with pytest.raises(ChronyNtsError, match="exact authority"):
        ChronyNtsTrustedTimeSource(authority=derived)
    with pytest.raises(ChronyNtsError, match="deadline was invalid"):
        ChronyNtsTrustedTimeSource(authority=authority).read_trusted_time(
            deadline_monotonic_ns=True
        )


def test_authority_revalidation_detects_forged_frozen_instance() -> None:
    authority = _authority()
    object.__setattr__(authority, "chrony_version", "4.9")

    with pytest.raises(ChronyNtsError, match=r"pin Chrony 4\.8"):
        ChronyNtsTrustedTimeSource(authority=authority)


def test_result_dataclass_subclass_is_rejected() -> None:
    class DerivedResult(ChronycCommandResult):
        pass

    runner = Runner(DerivedResult(returncode=0, stdout=_payload(), stderr=b""))

    with pytest.raises(ChronyNtsError, match="process result was rejected"):
        _read(runner=runner)


def test_authority_dataclass_cannot_be_replaced_with_a_structural_object() -> None:
    authority = _authority()
    source = ChronyNtsTrustedTimeSource(authority=authority)

    with pytest.raises(ChronyNtsError, match="exact authority"):
        replace(source, authority=object())  # type: ignore[arg-type]
