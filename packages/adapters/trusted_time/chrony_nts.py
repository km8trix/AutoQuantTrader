"""Strict, evidence-only Chrony 4.8 NTS trusted-time source.

The adapter executes one fixed, read-only ``chronyc`` monitoring transaction
against one exact Unix-domain command socket.  It accepts only the Chrony 4.8
CSV report shape and the operator-pinned Cloudflare/System76 Virginia NTS
composite.  A
successful reading is local evidence only: this module has no scheduler,
persistence, operational-control, broker, alert, re-arm, or trading port.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Protocol

from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from packages.domain.canonical import canonical_decimal_text, canonical_json_bytes

CHRONY_NTS_ADAPTER_CONTRACT_VERSION = "phase6-chrony-4.8-nts-evidence-v2"
CHRONY_NTS_VERSION = "4.8"
CHRONY_NTS_ORDERED_SOURCE_NAMES = (
    "time.cloudflare.com",
    "virginia.time.system76.com",
)
CHRONY_NTS_ORDERED_NTP_PORTS = (123, 123)
CHRONY_NTS_MAX_REFERENCE_AGE_SECONDS = 30
CHRONY_NTS_MAX_UNCERTAINTY_MILLISECONDS = 100
CHRONY_NTS_MAX_OUTPUT_BYTES = 65_536
CHRONY_NTS_MAX_COMMAND_TIMEOUT_NS = 1_000_000_000
CHRONY_NTS_PIPE_CHUNK_BYTES = 4_096
_CHRONY_NTS_DEADLINE_POLL_SECONDS = 0.1
CHRONY_NTS_C_LOCALE_ENVIRONMENT = (
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("TZ", "UTC"),
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REF_ID = re.compile(r"^[0-9A-F]{8}$")
_UNSIGNED_INTEGER = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SIGNED_INTEGER = re.compile(r"^(?:0|-?[1-9][0-9]*)$")
_EPOCH_SECONDS = re.compile(r"^(?:0|[1-9][0-9]*)\.[0-9]{9}$")
_DECIMAL_FORMATS = {
    0: re.compile(r"^-?(?:0|[1-9][0-9]*)$"),
    1: re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]$"),
    2: re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$"),
    3: re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{3}$"),
    6: re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{6}$"),
    9: re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{9}$"),
}
_NTP_SOURCE_TESTS = ("111", "111", "1111")
_NTS_AEAD_KEY_LENGTHS = {15: 256, 30: 128}
_TIMESTAMP_SOURCES = {"Daemon", "Kernel", "Hardware"}

UtcClock = Callable[[], datetime]
MonotonicNanosecondClock = Callable[[], int]


class ChronyNtsError(RuntimeError):
    """Sanitized failure of the strict Chrony NTS evidence boundary."""


@dataclass(frozen=True, slots=True)
class ChronycCommandResult:
    """Bounded child-process result consumed by the adapter."""

    returncode: int
    stdout: bytes
    stderr: bytes


class ChronycRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        monotonic_clock: MonotonicNanosecondClock,
        max_output_bytes: int,
        environment: tuple[tuple[str, str], ...],
    ) -> ChronycCommandResult: ...


def _require_safe_id(value: object, field_name: str) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise ChronyNtsError(f"{field_name} must use the closed safe-text alphabet")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ChronyNtsError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_absolute_path(value: object, field_name: str) -> str:
    encoded_length = 0
    if type(value) is str:
        try:
            encoded_length = len(value.encode("utf-8"))
        except UnicodeError:
            raise ChronyNtsError(f"{field_name} must be a bounded absolute path") from None
    if (
        type(value) is not str
        or not value
        or encoded_length > 255
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ChronyNtsError(f"{field_name} must be a bounded absolute path")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ChronyNtsError(f"{field_name} must be a canonical absolute path")
    return value


@dataclass(frozen=True, slots=True)
class ChronyNtsAuthority:
    """Exact operator pin for one local Chrony 4.8 NTS authority."""

    source_id: str
    source_authority_sha256: str
    chronyc_path: str
    socket_path: str
    chrony_version: str
    ordered_source_names: tuple[str, str]
    ordered_ntp_ports: tuple[int, int]
    maximum_reference_age_seconds: int

    def __post_init__(self) -> None:
        _require_safe_id(self.source_id, "Chrony NTS source ID")
        _require_sha256(
            self.source_authority_sha256,
            "Chrony NTS source authority_sha256",
        )
        _require_absolute_path(self.chronyc_path, "chronyc executable path")
        _require_absolute_path(self.socket_path, "chronyd command socket path")
        if self.chronyc_path == self.socket_path:
            raise ChronyNtsError("chronyc executable and command socket paths must differ")
        if type(self.chrony_version) is not str or self.chrony_version != CHRONY_NTS_VERSION:
            raise ChronyNtsError("Chrony NTS authority must pin Chrony 4.8")
        if (
            type(self.ordered_source_names) is not tuple
            or self.ordered_source_names != CHRONY_NTS_ORDERED_SOURCE_NAMES
            or any(type(name) is not str for name in self.ordered_source_names)
        ):
            raise ChronyNtsError("Chrony NTS authority has an unsupported ordered source set")
        if (
            type(self.ordered_ntp_ports) is not tuple
            or self.ordered_ntp_ports != CHRONY_NTS_ORDERED_NTP_PORTS
            or any(type(port) is not int for port in self.ordered_ntp_ports)
        ):
            raise ChronyNtsError("Chrony NTS authority has an unsupported ordered port set")
        if (
            type(self.maximum_reference_age_seconds) is not int
            or self.maximum_reference_age_seconds != CHRONY_NTS_MAX_REFERENCE_AGE_SECONDS
        ):
            raise ChronyNtsError("Chrony NTS reference-age bound must be exactly 30 seconds")

    @property
    def argv(self) -> tuple[str, ...]:
        return (
            self.chronyc_path,
            "-h",
            self.socket_path,
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

    @property
    def semantic_sha256(self) -> str:
        material = (
            CHRONY_NTS_ADAPTER_CONTRACT_VERSION,
            "authority",
            self.source_id,
            self.source_authority_sha256,
            self.argv,
            self.chrony_version,
            self.ordered_source_names,
            self.ordered_ntp_ports,
            self.maximum_reference_age_seconds,
            CHRONY_NTS_MAX_UNCERTAINTY_MILLISECONDS,
            CHRONY_NTS_MAX_OUTPUT_BYTES,
            CHRONY_NTS_C_LOCALE_ENVIRONMENT,
            "shell_false",
            "one_attempt",
        )
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        with suppress(ProcessLookupError, OSError):
            process.kill()


def _run_bounded_chronyc(
    argv: tuple[str, ...],
    *,
    deadline_monotonic_ns: int,
    monotonic_clock: MonotonicNanosecondClock,
    max_output_bytes: int,
    environment: tuple[tuple[str, str], ...],
) -> ChronycCommandResult:
    """Run one no-shell child under an absolute, suspend-aware deadline."""

    if (
        type(argv) is not tuple
        or not argv
        or type(argv[0]) is not str
        or not os.path.isabs(argv[0])
        or type(deadline_monotonic_ns) is not int
        or deadline_monotonic_ns < 0
        or not callable(monotonic_clock)
        or type(max_output_bytes) is not int
        or max_output_bytes <= 0
        or type(environment) is not tuple
    ):
        raise ChronyNtsError("Chrony NTS process boundary is invalid")
    observed_monotonic_ns = _read_monotonic_ns(monotonic_clock)
    if (
        deadline_monotonic_ns <= observed_monotonic_ns
        or deadline_monotonic_ns - observed_monotonic_ns > CHRONY_NTS_MAX_COMMAND_TIMEOUT_NS
    ):
        raise ChronyNtsError("Chrony NTS process deadline is invalid")

    def remaining_deadline_ns() -> int:
        nonlocal observed_monotonic_ns
        next_monotonic_ns = _read_monotonic_ns(monotonic_clock)
        if next_monotonic_ns < observed_monotonic_ns:
            raise ChronyNtsError("Chrony NTS monotonic clock was invalid")
        observed_monotonic_ns = next_monotonic_ns
        return deadline_monotonic_ns - observed_monotonic_ns

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=dict(environment),
            bufsize=0,
        )
    except Exception:
        raise ChronyNtsError("Chrony NTS process was unavailable") from None
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        with suppress(Exception):
            process.wait(timeout=0.25)
        raise ChronyNtsError("Chrony NTS process pipes were unavailable")

    stdout = bytearray()
    stderr = bytearray()
    try:
        selector = selectors.DefaultSelector()
    except Exception:
        _kill_process_group(process)
        with suppress(Exception):
            process.wait(timeout=0.25)
        with suppress(OSError):
            process.stdout.close()
        with suppress(OSError):
            process.stderr.close()
        raise ChronyNtsError("Chrony NTS process I/O failed") from None
    exceeded = False
    timed_out = False
    try:
        selector.register(process.stdout, selectors.EVENT_READ, stdout)
        selector.register(process.stderr, selectors.EVENT_READ, stderr)
        while True:
            remaining_ns = remaining_deadline_ns()
            if remaining_ns <= 0:
                timed_out = True
                break

            if not selector.get_map():
                if process.poll() is not None:
                    break
                try:
                    process.wait(
                        timeout=min(
                            _CHRONY_NTS_DEADLINE_POLL_SECONDS,
                            remaining_ns / 1_000_000_000,
                        )
                    )
                except subprocess.TimeoutExpired:
                    continue
                break

            events = selector.select(
                min(
                    _CHRONY_NTS_DEADLINE_POLL_SECONDS,
                    remaining_ns / 1_000_000_000,
                )
            )
            if remaining_deadline_ns() <= 0:
                timed_out = True
                break
            if not events:
                continue
            for key, _ in events:
                target = key.data
                chunk = os.read(key.fd, CHRONY_NTS_PIPE_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(stdout) + len(stderr) > max_output_bytes:
                    exceeded = True
                    break
            if exceeded:
                break
        if timed_out or exceeded:
            _kill_process_group(process)
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                raise ChronyNtsError("Chrony NTS process cleanup failed") from None
    except ChronyNtsError:
        _kill_process_group(process)
        with suppress(Exception):
            process.wait(timeout=0.25)
        raise
    except Exception:
        _kill_process_group(process)
        with suppress(Exception):
            process.wait(timeout=0.25)
        raise ChronyNtsError("Chrony NTS process I/O failed") from None
    finally:
        selector.close()
        with suppress(OSError):
            process.stdout.close()
        with suppress(OSError):
            process.stderr.close()

    if timed_out:
        raise ChronyNtsError("Chrony NTS process exceeded its deadline")
    if exceeded:
        raise ChronyNtsError("Chrony NTS process output exceeded its bound")
    return ChronycCommandResult(
        returncode=process.returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )


def _parse_int(
    value: str,
    *,
    signed: bool = False,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    pattern = _SIGNED_INTEGER if signed else _UNSIGNED_INTEGER
    if len(value) > 20 or pattern.fullmatch(value) is None:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    parsed = int(value)
    if minimum is not None and parsed < minimum:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    if maximum is not None and parsed > maximum:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed


def _parse_decimal(value: str, precision: int) -> Decimal:
    pattern = _DECIMAL_FORMATS.get(precision)
    if len(value) > 32 or pattern is None or pattern.fullmatch(value) is None:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ChronyNtsError("Chrony NTS evidence was rejected") from None
    if not parsed.is_finite():
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed


def _parse_nonnegative_decimal(value: str, precision: int) -> Decimal:
    parsed = _parse_decimal(value, precision)
    if parsed < 0 or parsed.is_signed():
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed


def _parse_epoch_ns(value: str) -> int:
    if len(value) > 30 or _EPOCH_SECONDS.fullmatch(value) is None:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    seconds, nanoseconds = value.split(".", 1)
    parsed = int(seconds) * 1_000_000_000 + int(nanoseconds)
    if parsed <= 0:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed


def _split_csv(line: str, expected_fields: int) -> tuple[str, ...]:
    if (
        not line
        or '"' in line
        or "'" in line
        or any(ord(character) < 32 or ord(character) == 127 for character in line)
    ):
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    fields = tuple(line.split(","))
    if len(fields) != expected_fields:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return fields


def _parse_sections(payload: bytes) -> tuple[tuple[str, ...], ...]:
    if not payload or len(payload) > CHRONY_NTS_MAX_OUTPUT_BYTES:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise ChronyNtsError("Chrony NTS evidence was rejected") from None
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    sections: list[tuple[str, ...]] = []
    current: list[str] = []
    for line in text[:-1].split("\n"):
        if line == ".":
            sections.append(tuple(current))
            current = []
        else:
            current.append(line)
    if current or len(sections) != 5:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    if tuple(len(section) for section in sections) != (0, 1, 2, 2, 2):
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return tuple(sections)


@dataclass(frozen=True, slots=True)
class _TrackingEvidence:
    ref_id: str
    source_name: str
    stratum: int
    reference_time_ns: int
    current_correction: Decimal
    last_offset: Decimal
    rms_offset: Decimal
    frequency_ppm: Decimal
    residual_frequency_ppm: Decimal
    skew_ppm: Decimal
    root_delay: Decimal
    root_dispersion: Decimal
    update_interval: Decimal

    @property
    def normalized(self) -> tuple[object, ...]:
        return (
            self.ref_id,
            self.source_name,
            self.stratum,
            self.reference_time_ns,
            *(
                canonical_decimal_text(value)
                for value in (
                    self.current_correction,
                    self.last_offset,
                    self.rms_offset,
                    self.frequency_ppm,
                    self.residual_frequency_ppm,
                    self.skew_ppm,
                    self.root_delay,
                    self.root_dispersion,
                    self.update_interval,
                )
            ),
            "Normal",
        )


@dataclass(frozen=True, slots=True)
class _SelectEvidence:
    state: str
    source_name: str
    last_sample_ago: int
    score: Decimal
    lower_offset: Decimal
    upper_offset: Decimal

    @property
    def normalized(self) -> tuple[object, ...]:
        return (
            self.state,
            self.source_name,
            "Y",
            "-----",
            "-----",
            self.last_sample_ago,
            canonical_decimal_text(self.score),
            canonical_decimal_text(self.lower_offset),
            canonical_decimal_text(self.upper_offset),
            "Normal",
        )


@dataclass(frozen=True, slots=True)
class _AuthEvidence:
    source_name: str
    key_id: int
    key_type: int
    key_length: int
    last_key_establishment_ago: int
    key_establishment_attempts: int
    cookies: int
    cookie_length: int

    @property
    def normalized(self) -> tuple[object, ...]:
        return (
            self.source_name,
            "NTS",
            self.key_id,
            self.key_type,
            self.key_length,
            self.last_key_establishment_ago,
            self.key_establishment_attempts,
            0,
            self.cookies,
            self.cookie_length,
        )


@dataclass(frozen=True, slots=True)
class _NtpEvidence:
    values: tuple[object, ...]
    remote_address: str
    remote_ref_id: str
    port: int
    stratum: int

    @property
    def normalized(self) -> tuple[object, ...]:
        return self.values


@dataclass(frozen=True, slots=True)
class _AdmittedEvidence:
    tracking: _TrackingEvidence
    selection: tuple[_SelectEvidence, _SelectEvidence]
    authentication: tuple[_AuthEvidence, _AuthEvidence]
    ntp: tuple[_NtpEvidence, _NtpEvidence]


def _parse_tracking(line: str, authority: ChronyNtsAuthority) -> _TrackingEvidence:
    fields = _split_csv(line, 14)
    if _REF_ID.fullmatch(fields[0]) is None or fields[1] not in authority.ordered_source_names:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    stratum = _parse_int(fields[2], minimum=2, maximum=15)
    reference_time_ns = _parse_epoch_ns(fields[3])
    correction = _parse_decimal(fields[4], 9)
    last_offset = _parse_decimal(fields[5], 9)
    rms_offset = _parse_nonnegative_decimal(fields[6], 9)
    frequency = _parse_decimal(fields[7], 3)
    residual_frequency = _parse_decimal(fields[8], 3)
    skew = _parse_nonnegative_decimal(fields[9], 3)
    root_delay = _parse_decimal(fields[10], 9)
    root_dispersion = _parse_nonnegative_decimal(fields[11], 9)
    update_interval = _parse_nonnegative_decimal(fields[12], 1)
    if fields[13] != "Normal":
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return _TrackingEvidence(
        ref_id=fields[0],
        source_name=fields[1],
        stratum=stratum,
        reference_time_ns=reference_time_ns,
        current_correction=correction,
        last_offset=last_offset,
        rms_offset=rms_offset,
        frequency_ppm=frequency,
        residual_frequency_ppm=residual_frequency,
        skew_ppm=skew,
        root_delay=root_delay,
        root_dispersion=root_dispersion,
        update_interval=update_interval,
    )


def _parse_selection(
    lines: tuple[str, str],
    authority: ChronyNtsAuthority,
) -> tuple[_SelectEvidence, _SelectEvidence]:
    parsed: list[_SelectEvidence] = []
    for expected_name, line in zip(authority.ordered_source_names, lines, strict=True):
        fields = _split_csv(line, 18)
        if (
            fields[0] not in {"*", "+"}
            or fields[1] != expected_name
            or fields[2] != "Y"
            or fields[3:8] != ("-", "-", "-", "-", "-")
            or fields[8:13] != ("-", "-", "-", "-", "-")
            or fields[17] != "Normal"
        ):
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        last = _parse_int(
            fields[13],
            minimum=0,
            maximum=authority.maximum_reference_age_seconds,
        )
        score = _parse_nonnegative_decimal(fields[14], 1)
        lower = _parse_decimal(fields[15], 9)
        upper = _parse_decimal(fields[16], 9)
        if lower > upper:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        parsed.append(
            _SelectEvidence(
                state=fields[0],
                source_name=fields[1],
                last_sample_ago=last,
                score=score,
                lower_offset=lower,
                upper_offset=upper,
            )
        )
    if [item.state for item in parsed].count("*") != 1 or [item.state for item in parsed].count(
        "+"
    ) != 1:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed[0], parsed[1]


def _parse_authentication(
    lines: tuple[str, str],
    authority: ChronyNtsAuthority,
) -> tuple[_AuthEvidence, _AuthEvidence]:
    parsed: list[_AuthEvidence] = []
    for expected_name, line in zip(authority.ordered_source_names, lines, strict=True):
        fields = _split_csv(line, 10)
        if fields[0] != expected_name or fields[1] != "NTS":
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        key_id = _parse_int(fields[2], minimum=1, maximum=4_294_967_295)
        key_type = _parse_int(fields[3], minimum=0, maximum=65_535)
        key_length = _parse_int(fields[4], minimum=1, maximum=4_096)
        if _NTS_AEAD_KEY_LENGTHS.get(key_type) != key_length:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        last_ke = _parse_int(fields[5], minimum=0, maximum=4_294_967_294)
        attempts = _parse_int(fields[6], minimum=0, maximum=0)
        nak = _parse_int(fields[7], minimum=0, maximum=0)
        cookies = _parse_int(fields[8], minimum=8, maximum=64)
        cookie_length = _parse_int(fields[9], minimum=1, maximum=1_024)
        if nak != 0:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        parsed.append(
            _AuthEvidence(
                source_name=fields[0],
                key_id=key_id,
                key_type=key_type,
                key_length=key_length,
                last_key_establishment_ago=last_ke,
                key_establishment_attempts=attempts,
                cookies=cookies,
                cookie_length=cookie_length,
            )
        )
    return parsed[0], parsed[1]


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ChronyNtsError("Chrony NTS evidence was rejected") from None
    if str(address) != value or address.is_unspecified or address.is_multicast:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return address


def _parse_ntp(
    lines: tuple[str, str],
    authority: ChronyNtsAuthority,
) -> tuple[_NtpEvidence, _NtpEvidence]:
    parsed: list[_NtpEvidence] = []
    for expected_port, line in zip(authority.ordered_ntp_ports, lines, strict=True):
        fields = _split_csv(line, 38)
        remote = _parse_ip(fields[0])
        if _REF_ID.fullmatch(fields[1]) is None:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if isinstance(remote, ipaddress.IPv4Address) and f"{int(remote):08X}" != fields[1]:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        port = _parse_int(fields[2], minimum=1, maximum=65_535)
        if port != expected_port:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        local = _parse_ip(fields[3])
        if _REF_ID.fullmatch(fields[4]) is None:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if isinstance(local, ipaddress.IPv4Address) and f"{int(local):08X}" != fields[4]:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if fields[5:8] != ("Normal", "4", "Server"):
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        stratum = _parse_int(fields[8], minimum=1, maximum=14)
        poll = _parse_int(fields[9], signed=True, minimum=4, maximum=4)
        poll_seconds = _parse_decimal(fields[10], 0)
        if poll != 4 or poll_seconds != Decimal(16):
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        precision = _parse_int(fields[11], signed=True, minimum=-40, maximum=0)
        precision_seconds = _parse_nonnegative_decimal(fields[12], 9)
        if precision_seconds <= 0 or precision >= 0:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        root_delay = _parse_nonnegative_decimal(fields[13], 6)
        root_dispersion = _parse_nonnegative_decimal(fields[14], 6)
        if _REF_ID.fullmatch(fields[15]) is None:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if fields[16] and _SAFE_ID.fullmatch(fields[16]) is None:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        reference_time_ns = _parse_epoch_ns(fields[17])
        offset = _parse_decimal(fields[18], 9)
        peer_delay = _parse_nonnegative_decimal(fields[19], 9)
        peer_dispersion = _parse_nonnegative_decimal(fields[20], 9)
        response_time = _parse_nonnegative_decimal(fields[21], 9)
        jitter = _parse_decimal(fields[22], 2)
        if jitter < Decimal("-0.50") or jitter > Decimal("0.50"):
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if fields[23:26] != _NTP_SOURCE_TESTS:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if fields[26] not in {"Yes", "No"} or fields[27] != "Yes":
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        if fields[28] not in _TIMESTAMP_SOURCES or fields[29] not in _TIMESTAMP_SOURCES:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        counts = tuple(_parse_int(value, minimum=0, maximum=4_294_967_295) for value in fields[30:])
        total_tx, total_rx, total_valid, total_good, kernel_tx, kernel_rx, hw_tx, hw_rx = counts
        if (
            total_tx <= 0
            or total_rx <= 0
            or total_good <= 0
            or total_good > total_valid
            or total_valid > total_rx
            or kernel_tx > total_tx
            or hw_tx > total_tx
            or kernel_rx > total_rx
            or hw_rx > total_rx
        ):
            raise ChronyNtsError("Chrony NTS evidence was rejected")
        normalized: tuple[object, ...] = (
            str(remote),
            fields[1],
            port,
            str(local),
            fields[4],
            "Normal",
            4,
            "Server",
            stratum,
            poll,
            canonical_decimal_text(poll_seconds),
            precision,
            canonical_decimal_text(precision_seconds),
            canonical_decimal_text(root_delay),
            canonical_decimal_text(root_dispersion),
            fields[15],
            fields[16],
            reference_time_ns,
            canonical_decimal_text(offset),
            canonical_decimal_text(peer_delay),
            canonical_decimal_text(peer_dispersion),
            canonical_decimal_text(response_time),
            canonical_decimal_text(jitter),
            *_NTP_SOURCE_TESTS,
            fields[26],
            "Yes",
            fields[28],
            fields[29],
            *counts,
        )
        parsed.append(
            _NtpEvidence(
                values=normalized,
                remote_address=str(remote),
                remote_ref_id=fields[1],
                port=port,
                stratum=stratum,
            )
        )
    if parsed[0].remote_address == parsed[1].remote_address:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return parsed[0], parsed[1]


def _parse_and_admit(payload: bytes, authority: ChronyNtsAuthority) -> _AdmittedEvidence:
    sections = _parse_sections(payload)
    tracking = _parse_tracking(sections[1][0], authority)
    selection = _parse_selection((sections[2][0], sections[2][1]), authority)
    authentication = _parse_authentication((sections[3][0], sections[3][1]), authority)
    ntp = _parse_ntp((sections[4][0], sections[4][1]), authority)
    selected_index = 0 if selection[0].state == "*" else 1
    if (
        tracking.source_name != authority.ordered_source_names[selected_index]
        or tracking.ref_id != ntp[selected_index].remote_ref_id
        or tracking.stratum != ntp[selected_index].stratum + 1
    ):
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    return _AdmittedEvidence(
        tracking=tracking,
        selection=selection,
        authentication=authentication,
        ntp=ntp,
    )


def _read_utc(clock: UtcClock) -> datetime:
    try:
        value = clock()
    except Exception:
        raise ChronyNtsError("Chrony NTS UTC clock was unavailable") from None
    if type(value) is not datetime or value.tzinfo is None:
        raise ChronyNtsError("Chrony NTS UTC clock was invalid")
    try:
        offset = value.utcoffset()
    except Exception:
        raise ChronyNtsError("Chrony NTS UTC clock was invalid") from None
    if offset is None or offset != UTC.utcoffset(value):
        raise ChronyNtsError("Chrony NTS UTC clock was invalid")
    return value.replace(tzinfo=UTC)


def _read_monotonic_ns(clock: MonotonicNanosecondClock) -> int:
    try:
        value = clock()
    except Exception:
        raise ChronyNtsError("Chrony NTS monotonic clock was unavailable") from None
    if type(value) is not int or value < 0:
        raise ChronyNtsError("Chrony NTS monotonic clock was invalid")
    return value


def _datetime_epoch_ns(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = value - epoch
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def _decimal_seconds_to_ns(value: Decimal) -> int:
    sign, digits, raw_exponent = value.as_tuple()
    if type(raw_exponent) is not int:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    coefficient = int("".join(str(digit) for digit in digits)) if digits else 0
    exponent = raw_exponent + 9
    scaled: int
    if exponent >= 0:
        scaled = coefficient * 10**exponent
    else:
        divisor = 10 ** (-exponent)
        scaled, remainder = divmod(coefficient, divisor)
        if remainder:
            raise ChronyNtsError("Chrony NTS evidence was rejected")
    if sign:
        scaled = -scaled
    return scaled


def _round_nanoseconds_to_microseconds(value: int) -> int:
    sign = -1 if value < 0 else 1
    quotient, remainder = divmod(abs(value), 1_000)
    if remainder > 500 or (remainder == 500 and quotient % 2 == 1):
        quotient += 1
    return sign * quotient


def _decimal_milliseconds_from_ns(value: int) -> Decimal:
    if value < 0:
        raise ChronyNtsError("Chrony NTS evidence was rejected")
    digits = tuple(int(character) for character in str(value))
    return Decimal((0, digits, -6))


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


@dataclass(frozen=True, slots=True)
class ChronyNtsTrustedTimeSource:
    """One-attempt Chrony 4.8 NTS source implementing the application port."""

    authority: ChronyNtsAuthority
    utc_clock: UtcClock = field(default=lambda: datetime.now(UTC), repr=False, compare=False)
    monotonic_clock: MonotonicNanosecondClock = field(
        default=time.monotonic_ns,
        repr=False,
        compare=False,
    )
    runner: ChronycRunner = field(default=_run_bounded_chronyc, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.authority) is not ChronyNtsAuthority:
            raise ChronyNtsError("Chrony NTS source requires an exact authority")
        self.authority.__post_init__()
        if (
            not callable(self.utc_clock)
            or not callable(self.monotonic_clock)
            or not callable(self.runner)
        ):
            raise ChronyNtsError("Chrony NTS source dependencies are unavailable")

    def read_trusted_time(self, *, deadline_monotonic_ns: int) -> TrustedTimeSourceReading:
        if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns < 0:
            raise ChronyNtsError("Chrony NTS deadline was invalid")
        started_monotonic_ns = _read_monotonic_ns(self.monotonic_clock)
        if deadline_monotonic_ns <= started_monotonic_ns:
            raise ChronyNtsError("Chrony NTS deadline had already expired")
        started_at_utc = _read_utc(self.utc_clock)
        launch_monotonic_ns = _read_monotonic_ns(self.monotonic_clock)
        if (
            launch_monotonic_ns < started_monotonic_ns
            or launch_monotonic_ns >= deadline_monotonic_ns
        ):
            raise ChronyNtsError("Chrony NTS deadline expired before process launch")
        command_deadline_monotonic_ns = min(
            deadline_monotonic_ns,
            launch_monotonic_ns + CHRONY_NTS_MAX_COMMAND_TIMEOUT_NS,
        )
        try:
            result = self.runner(
                self.authority.argv,
                deadline_monotonic_ns=command_deadline_monotonic_ns,
                monotonic_clock=self.monotonic_clock,
                max_output_bytes=CHRONY_NTS_MAX_OUTPUT_BYTES,
                environment=CHRONY_NTS_C_LOCALE_ENVIRONMENT,
            )
        except Exception:
            raise ChronyNtsError("Chrony NTS process was unavailable") from None
        completed_at_utc = _read_utc(self.utc_clock)
        completed_monotonic_ns = _read_monotonic_ns(self.monotonic_clock)
        if (
            completed_monotonic_ns < started_monotonic_ns
            or completed_monotonic_ns > deadline_monotonic_ns
            or completed_at_utc < started_at_utc
        ):
            raise ChronyNtsError("Chrony NTS inner observation interval was invalid")
        if (
            type(result) is not ChronycCommandResult
            or type(result.returncode) is not int
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or result.returncode != 0
            or result.stderr
            or not result.stdout
            or len(result.stdout) > CHRONY_NTS_MAX_OUTPUT_BYTES
        ):
            raise ChronyNtsError("Chrony NTS process result was rejected")
        try:
            admitted = _parse_and_admit(result.stdout, self.authority)
        except ChronyNtsError:
            raise ChronyNtsError("Chrony NTS evidence was rejected") from None

        monotonic_duration_ns = completed_monotonic_ns - started_monotonic_ns
        wall_duration = completed_at_utc - started_at_utc
        wall_duration_ns = (
            (wall_duration.days * 86_400 + wall_duration.seconds) * 1_000_000
            + wall_duration.microseconds
        ) * 1_000
        observed_at_monotonic_ns = started_monotonic_ns + monotonic_duration_ns // 2
        wall_midpoint_microseconds = wall_duration_ns // 2_000
        midpoint_rounding_residual_ns = (wall_duration_ns // 2) - (
            wall_midpoint_microseconds * 1_000
        )
        local_observed_at_utc = started_at_utc + timedelta(microseconds=wall_midpoint_microseconds)

        correction_ns = _decimal_seconds_to_ns(admitted.tracking.current_correction)
        correction_microseconds = _round_nanoseconds_to_microseconds(correction_ns)
        correction_rounding_residual_ns = abs(correction_ns - correction_microseconds * 1_000)
        try:
            trusted_at_utc = local_observed_at_utc + timedelta(microseconds=correction_microseconds)
        except OverflowError:
            raise ChronyNtsError("Chrony NTS trusted instant was invalid") from None

        trusted_epoch_ns = _datetime_epoch_ns(trusted_at_utc)
        reference_age_ns = trusted_epoch_ns - admitted.tracking.reference_time_ns
        if (
            reference_age_ns < 0
            or reference_age_ns > self.authority.maximum_reference_age_seconds * 1_000_000_000
        ):
            raise ChronyNtsError("Chrony NTS tracking reference was stale")

        root_dispersion_ns = _decimal_seconds_to_ns(admitted.tracking.root_dispersion)
        root_delay_ns = abs(_decimal_seconds_to_ns(admitted.tracking.root_delay))
        half_root_delay_ns = _ceil_div(root_delay_ns, 2)
        inner_timing_ns = _ceil_div(monotonic_duration_ns, 2)
        clock_divergence_ns = abs(wall_duration_ns - monotonic_duration_ns)
        uncertainty_ns = (
            root_dispersion_ns
            + half_root_delay_ns
            + inner_timing_ns
            + clock_divergence_ns
            + midpoint_rounding_residual_ns
            + correction_rounding_residual_ns
        )
        if uncertainty_ns > CHRONY_NTS_MAX_UNCERTAINTY_MILLISECONDS * 1_000_000:
            raise ChronyNtsError("Chrony NTS uncertainty exceeded its admission bound")
        uncertainty_milliseconds = _decimal_milliseconds_from_ns(uncertainty_ns)

        evidence_material = (
            CHRONY_NTS_ADAPTER_CONTRACT_VERSION,
            "admitted_reading",
            self.authority.semantic_sha256,
            admitted.tracking.normalized,
            tuple(item.normalized for item in admitted.selection),
            tuple(item.normalized for item in admitted.authentication),
            tuple(item.normalized for item in admitted.ntp),
            local_observed_at_utc,
            trusted_at_utc,
            observed_at_monotonic_ns,
            uncertainty_milliseconds,
            uncertainty_ns,
            monotonic_duration_ns,
            wall_duration_ns,
            midpoint_rounding_residual_ns,
            correction_rounding_residual_ns,
            "evidence_only",
            False,
        )
        evidence_sha256 = hashlib.sha256(canonical_json_bytes(evidence_material)).hexdigest()
        return TrustedTimeSourceReading(
            source_id=self.authority.source_id,
            source_authority_sha256=self.authority.source_authority_sha256,
            local_observed_at_utc=local_observed_at_utc,
            trusted_at_utc=trusted_at_utc,
            observed_at_monotonic_ns=observed_at_monotonic_ns,
            source_uncertainty_milliseconds=uncertainty_milliseconds,
            source_evidence_sha256=evidence_sha256,
        )


__all__ = [
    "CHRONY_NTS_ADAPTER_CONTRACT_VERSION",
    "CHRONY_NTS_C_LOCALE_ENVIRONMENT",
    "CHRONY_NTS_MAX_OUTPUT_BYTES",
    "CHRONY_NTS_MAX_UNCERTAINTY_MILLISECONDS",
    "ChronyNtsAuthority",
    "ChronyNtsError",
    "ChronyNtsTrustedTimeSource",
    "ChronycCommandResult",
]
