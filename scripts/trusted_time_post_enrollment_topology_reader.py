"""Dormant raw-first Docker observation issuer for post-enrollment topology.

The issuer owns one global launcher lock and one pinned local Docker daemon
session.  It can issue only the two already-frozen, non-authorizing topology
snapshot contracts.  It has no start, release, claim, persistence, provider,
or controller surface, and it retains no raw Docker response or staged path.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Never, Protocol, SupportsIndex, cast
from urllib.parse import unquote, urlsplit

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.bounded_subprocess import run_bounded_subprocess
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
    DATABASE_SECRET_CONSUMED_PATH,
    DATABASE_SECRET_DIRECTORY_PATTERN,
    DATABASE_SECRET_FILE_NAME,
    HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
    HEAD_ANCHOR_AUTHORITY_FILE_NAME,
    HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN,
    HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
    TRUSTED_TIME_LAUNCH_LOCK_PATH,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
    _acquire_trusted_time_launch_lock,
    _release_trusted_time_launch_lock,
    _stable_volume_identity_sha256,
    validate_chrony_state_volume_inspection,
    validate_exact_never_started_created_container,
    validate_exact_staged_running_container,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
    TrustedTimePostEnrollmentAbsentPathCandidate,
    TrustedTimePostEnrollmentConsumedMarkerCandidate,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    validate_post_enrollment_start_staged_unreleased_topology,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
    POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    _valid_daemon_identity,
    validate_post_enrollment_start_created_topology,
)
from scripts.verify_trusted_time_images import (
    IGNORED_ARTIFACT_ROOT,
    validate_socket_volume_inspection,
)

ROOT = Path(__file__).resolve().parents[1]

POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION = (
    "phase6d-post-enrollment-topology-observation-reader-v1"
)
POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS = "created_topology_observation_unqualified"
POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS = (
    "staged_unreleased_topology_observation_unqualified"
)

_CREATED_OBSERVATION_COUNT = 14
_STAGED_OBSERVATION_COUNT = 16
_COMMAND_TIMEOUT_SECONDS = 2.0
_MAXIMUM_DAEMON_STDOUT_BYTES = 512
_MAXIMUM_INVENTORY_STDOUT_BYTES = 512
_MAXIMUM_NETWORK_STDOUT_BYTES = 512 * 1_024
_MAXIMUM_VOLUME_STDOUT_BYTES = 256 * 1_024
_MAXIMUM_IMAGE_CONFIGURATION_STDOUT_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_CONTAINER_STDOUT_BYTES = 4 * 1_024 * 1_024
_MAXIMUM_BARRIER_STDOUT_BYTES = 4 * 1_024
_MAXIMUM_STDERR_BYTES = 4 * 1_024
_MAXIMUM_JSON_DEPTH = 64
_MAXIMUM_JSON_NODES = 131_072
_MAXIMUM_JSON_INTEGER_BITS = 256
_FULL_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_NETWORK_SAFE_APPARMOR_PROFILE = "docker-default"
_NETWORK_ATTACHMENT_REQUIRED_KEYS = frozenset(
    {
        "Aliases",
        "DNSNames",
        "DriverOpts",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "GlobalIPv6PrefixLen",
        "GwPriority",
        "IPAddress",
        "IPAMConfig",
        "IPPrefixLen",
        "IPv6Gateway",
        "Links",
        "MacAddress",
        "NetworkID",
    }
)
_NETWORK_ATTACHMENT_ALLOWED_KEYS = _NETWORK_ATTACHMENT_REQUIRED_KEYS
_NETWORK_SETTINGS_REQUIRED_KEYS = frozenset(
    {
        "Bridge",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "GlobalIPv6PrefixLen",
        "HairpinMode",
        "IPAddress",
        "IPPrefixLen",
        "IPv6Gateway",
        "LinkLocalIPv6Address",
        "LinkLocalIPv6PrefixLen",
        "MacAddress",
        "Networks",
        "Ports",
        "SandboxID",
        "SandboxKey",
        "SecondaryIPAddresses",
        "SecondaryIPv6Addresses",
    }
)
_NEUTRAL_NETWORK_SETTINGS_STRING_FIELDS = frozenset(
    {
        "Bridge",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "IPAddress",
        "IPv6Gateway",
        "LinkLocalIPv6Address",
        "MacAddress",
    }
)
_NEUTRAL_NETWORK_SETTINGS_INTEGER_FIELDS = frozenset(
    {"GlobalIPv6PrefixLen", "IPPrefixLen", "LinkLocalIPv6PrefixLen"}
)
_DOCKER_NETNS_KEY_PATTERN = re.compile(r"/var/run/docker/netns/[0-9a-f]{12,64}")
_NETWORK_IDENTITY_REQUIRED_KEYS = frozenset(
    {
        "Attachable",
        "ConfigOnly",
        "ConfigFrom",
        "Containers",
        "Created",
        "Driver",
        "EnableIPv6",
        "IPAM",
        "Id",
        "Ingress",
        "Internal",
        "Labels",
        "Name",
        "Options",
        "Scope",
    }
)
_NETWORK_IDENTITY_ALLOWED_KEYS = _NETWORK_IDENTITY_REQUIRED_KEYS
_NETWORK_CONTAINER_REQUIRED_KEYS = frozenset(
    {"EndpointID", "IPv4Address", "IPv6Address", "MacAddress", "Name"}
)
_MAC_ADDRESS_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_MINIMAL_ENVIRONMENT_KEYS = frozenset({"LANG", "LC_ALL", "NO_COLOR", "PATH", "TERM", "TMPDIR"})
_FIXED_SUBPROCESS_PATH = "/usr/bin:/bin"
_TRUSTED_DOCKER_EXECUTABLE_CANDIDATES = (
    Path("/Applications/Docker.app/Contents/Resources/bin/docker"),
    Path("/opt/homebrew/bin/docker"),
    Path("/usr/local/bin/docker"),
    Path("/usr/bin/docker"),
)
_RELEASE_PATHS = (
    "/tmp/.post-enrollment-start-release-staging",
    "/tmp/post-enrollment-start-release",
)
_BARRIER_PROBE_CONTRACT_VERSION = "phase6d-post-enrollment-barrier-read-probe-v1"
_PRODUCTION_OPEN_PROOF = object()


def _authority_is_never_granted(_: object) -> bool:
    return False


def _observation_is_authenticated(_: object) -> bool:
    return True


class TrustedTimePostEnrollmentTopologyReaderError(RuntimeError):
    """A bounded topology observation could not be issued safely."""


class _AuthenticatedIssuerCapability:
    __slots__ = ()

    def __new__(cls) -> _AuthenticatedIssuerCapability:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time observation capability is unavailable"
        )


def _new_authenticated_issuer_capability() -> _AuthenticatedIssuerCapability:
    return object.__new__(_AuthenticatedIssuerCapability)


def _build_observation_sealer() -> tuple[
    Callable[[object, Mapping[str, object]], bytes],
    Callable[[object, Mapping[str, object]], bool],
]:
    process_private_key = secrets.token_bytes(32)

    def seal(capability: object, material: Mapping[str, object]) -> bytes:
        if type(capability) is not _AuthenticatedIssuerCapability:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time observation seal is unavailable"
            )
        return hmac.digest(
            process_private_key,
            canonical_first_enrollment_json_bytes(dict(material)),
            "sha256",
        )

    def valid(candidate: object, material: Mapping[str, object]) -> bool:
        if type(candidate) is not bytes or len(candidate) != 32:
            return False
        expected = hmac.digest(
            process_private_key,
            canonical_first_enrollment_json_bytes(dict(material)),
            "sha256",
        )
        return hmac.compare_digest(candidate, expected)

    return seal, valid


_seal_observation, _valid_observation_seal = _build_observation_sealer()


class _DuplicateJsonKey(ValueError):
    pass


class _BoundedRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        maximum_stdout_bytes: int,
        maximum_stderr_bytes: int,
        stdin_bytes: bytes | None = None,
        maximum_stdin_bytes: int = 0,
    ) -> subprocess.CompletedProcess[bytes]: ...


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _bounded_json_integer(token: str) -> int:
    if len(token) > 80:
        raise ValueError
    value = int(token)
    if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
        raise ValueError
    return value


def _require_bounded_json_tree(root: object) -> None:
    remaining = _MAXIMUM_JSON_NODES
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > _MAXIMUM_JSON_DEPTH:
            raise ValueError
        if value is None or type(value) in {bool, str}:
            if type(value) is str and any(
                0xD800 <= ord(character) <= 0xDFFF for character in value
            ):
                raise ValueError
            continue
        if type(value) is int:
            if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
                raise ValueError
            continue
        if type(value) is list:
            items = cast(list[object], value)
            if len(items) > remaining:
                raise ValueError
            stack.extend((item, depth + 1) for item in reversed(items))
            continue
        if type(value) is dict:
            mapping = cast(dict[object, object], value)
            if 2 * len(mapping) > remaining:
                raise ValueError
            for key, item in reversed(tuple(mapping.items())):
                if type(key) is not str:
                    raise ValueError
                stack.append((item, depth + 1))
                stack.append((key, depth + 1))
            continue
        raise ValueError


def _contains_unquoted_json_whitespace(raw: bytes) -> bool:
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in {0x09, 0x0A, 0x0D, 0x20}:
            return True
    return False


def _decode_strict_json[JsonRoot: (dict[str, object], list[object], str)](
    raw: bytes,
    *,
    expected_type: type[JsonRoot],
    maximum_bytes: int,
) -> JsonRoot:
    """Decode one bounded unique-key JSON value from raw Docker bytes."""

    if type(raw) is not bytes:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    framed = raw[:-1] if raw.endswith(b"\n") else raw
    if (
        not raw
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
        or len(raw) > maximum_bytes
        or b"\0" in raw
        or b"\r" in raw
        or raw.startswith(b"\xef\xbb\xbf")
        or not framed
        or framed[:1] in b" \t\n\r"
        or framed[-1:] in b" \t\n\r"
        or _contains_unquoted_json_whitespace(framed)
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    try:
        decoded: Any = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_int=_bounded_json_integer,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        _require_bounded_json_tree(decoded)
    except (
        _DuplicateJsonKey,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        ) from None
    if type(decoded) is not expected_type:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    return decoded


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _build_barrier_probe_source(
    marker_path: str,
    release_paths: tuple[str, str],
) -> str:
    """Build the one frozen descriptor-held, read-only in-container probe."""

    if (
        type(marker_path) is not str
        or not marker_path.startswith("/")
        or type(release_paths) is not tuple
        or len(release_paths) != 2
        or any(type(path) is not str or not path.startswith("/") for path in release_paths)
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time barrier probe contract is invalid"
        )
    template = r"""import hashlib,json,os,stat,sys
MARKER=__MARKER__
RELEASES=__RELEASES__
CONTRACT=__CONTRACT__
def absent():
    for path in RELEASES:
        try:
            os.stat(path,follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise OSError
def identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,
            value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,
            value.st_ctime_ns)
def main():
    absent()
    descriptor=os.open(MARKER,os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0))
    try:
        before=os.fstat(descriptor)
        chunks=[]
        observed=0
        while True:
            chunk=os.read(descriptor,min(4097-observed,4096))
            if not chunk:
                break
            chunks.append(chunk)
            observed+=len(chunk)
            if observed>4096:
                raise OSError
        after=os.fstat(descriptor)
    finally:
        os.close(descriptor)
    absent()
    if identity(before)!=identity(after) or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
        raise OSError
    payload=b"".join(chunks)
    marker={"byte_sha256":hashlib.sha256(payload).hexdigest(),
            "changed_time_ns":before.st_ctime_ns,"device":before.st_dev,
            "inode":before.st_ino,"link_count":before.st_nlink,
            "mode":stat.S_IMODE(before.st_mode),
            "modified_time_ns":before.st_mtime_ns,"owner_gid":before.st_gid,
            "owner_uid":before.st_uid,"path":MARKER,"regular":True,
            "size":len(payload)}
    result={"contract_version":CONTRACT,"marker":marker,
            "release_absences":[{"path":path,"status":"absent"}
                                for path in RELEASES]}
    sys.stdout.write(json.dumps(result,allow_nan=False,ensure_ascii=True,separators=(",",":"),sort_keys=True)+"\n")
try:
    main()
except BaseException:
    sys.stderr.write("trusted-time topology probe failed\n")
    raise SystemExit(2)
"""
    return (
        template.replace("__MARKER__", repr(marker_path))
        .replace("__RELEASES__", repr(release_paths))
        .replace("__CONTRACT__", repr(_BARRIER_PROBE_CONTRACT_VERSION))
    )


_BARRIER_PROBE_SOURCE = _build_barrier_probe_source(
    DATABASE_SECRET_CONSUMED_PATH,
    _RELEASE_PATHS,
)


@dataclass(frozen=True, slots=True)
class _ReadReceipt:
    ordinal: int
    label: str
    argv: tuple[str, ...]
    maximum_stdout_bytes: int
    stdout_size: int
    stdout_sha256: str

    def payload(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "label": self.label,
            "maximum_stdout_bytes": self.maximum_stdout_bytes,
            "ordinal": self.ordinal,
            "stdout_sha256": self.stdout_sha256,
            "stdout_size": self.stdout_size,
            "timeout_milliseconds": 2_000,
        }


def _observation_payload(
    *,
    kind: str,
    status: str,
    session_sha256: str,
    transcript_sha256: str,
    observation_count: int,
    snapshot_contract_version: str,
    snapshot_sha256: str,
    created_observation_sha256: str | None = None,
    staged_observation_ordinal: int | None = None,
    predecessor_observation_sha256: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update(
        {
            "authority_granted": False,
            "claim_retention_authorized": False,
            "contract_version": POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION,
            "daemon_session_authenticated": True,
            "database_secret_disclosed": False,
            "kind": kind,
            "lock_session_authenticated": True,
            "observation_count": observation_count,
            "observation_provenance_authenticated": True,
            "persistent_start_authorized": False,
            "release_authorized": False,
            "sequence_2_authorized": False,
            "session_sha256": session_sha256,
            "shutdown_authorized": False,
            "snapshot_contract_version": snapshot_contract_version,
            "snapshot_sha256": snapshot_sha256,
            "source_start_authorized": False,
            "start_order_authenticated": False,
            "status": status,
            "supervisor_start_authorized": False,
            "topology_authenticated": False,
            "topology_mutation_authorized": False,
            "transcript_sha256": transcript_sha256,
        }
    )
    if created_observation_sha256 is not None:
        payload["created_observation_sha256"] = created_observation_sha256
    if staged_observation_ordinal is not None:
        payload["staged_observation_ordinal"] = staged_observation_ordinal
    if predecessor_observation_sha256 is not None:
        payload["predecessor_observation_sha256"] = predecessor_observation_sha256
    return payload


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentCreatedTopologyObservation:
    """Session-bound provenance envelope for an unchanged created snapshot."""

    session_sha256: str
    transcript_sha256: str
    observation_count: int
    snapshot: TrustedTimePostEnrollmentCreatedTopologySnapshot = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self.snapshot) is not TrustedTimePostEnrollmentCreatedTopologySnapshot:
                raise ValueError
            self.snapshot.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time created observation envelope is invalid"
            ) from None
        if (
            type(self.session_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.session_sha256) is None
            or type(self.transcript_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.transcript_sha256) is None
            or type(self.observation_count) is not int
            or self.observation_count != _CREATED_OBSERVATION_COUNT
            or not _valid_observation_seal(self._seal, self.payload())
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time created observation envelope is invalid"
            )

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS

    def payload(self) -> dict[str, object]:
        return _observation_payload(
            kind="created",
            status=self.status,
            session_sha256=self.session_sha256,
            transcript_sha256=self.transcript_sha256,
            observation_count=self.observation_count,
            snapshot_contract_version=POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
            snapshot_sha256=self.snapshot.snapshot_sha256,
        )

    @property
    def observation_sha256(self) -> str:
        return _canonical_sha256(self.payload())

    observation_provenance_authenticated = property(_observation_is_authenticated)
    lock_session_authenticated = property(_observation_is_authenticated)
    daemon_session_authenticated = property(_observation_is_authenticated)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStagedTopologyObservation:
    """Session-bound provenance envelope for an unchanged staged snapshot."""

    session_sha256: str
    transcript_sha256: str
    observation_count: int
    created_observation_sha256: str
    staged_observation_ordinal: int
    predecessor_observation_sha256: str
    snapshot: TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self.snapshot) is not TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
                raise ValueError
            self.snapshot.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged observation envelope is invalid"
            ) from None
        if (
            type(self.session_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.session_sha256) is None
            or type(self.transcript_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.transcript_sha256) is None
            or type(self.created_observation_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.created_observation_sha256) is None
            or type(self.staged_observation_ordinal) is not int
            or self.staged_observation_ordinal not in {1, 2}
            or type(self.predecessor_observation_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.predecessor_observation_sha256) is None
            or type(self.observation_count) is not int
            or self.observation_count != _STAGED_OBSERVATION_COUNT
            or not _valid_observation_seal(self._seal, self.payload())
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged observation envelope is invalid"
            )

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS

    def payload(self) -> dict[str, object]:
        return _observation_payload(
            kind="staged_unreleased",
            status=self.status,
            session_sha256=self.session_sha256,
            transcript_sha256=self.transcript_sha256,
            observation_count=self.observation_count,
            snapshot_contract_version=POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
            snapshot_sha256=self.snapshot.snapshot_sha256,
            created_observation_sha256=self.created_observation_sha256,
            staged_observation_ordinal=self.staged_observation_ordinal,
            predecessor_observation_sha256=self.predecessor_observation_sha256,
        )

    @property
    def observation_sha256(self) -> str:
        return _canonical_sha256(self.payload())

    observation_provenance_authenticated = property(_observation_is_authenticated)
    lock_session_authenticated = property(_observation_is_authenticated)
    daemon_session_authenticated = property(_observation_is_authenticated)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)


def _minimal_docker_environment(
    submitted: Mapping[str, str],
    *,
    endpoint: str,
) -> dict[str, str]:
    if type(submitted) is not dict or set(submitted) - _MINIMAL_ENVIRONMENT_KEYS:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation environment is invalid"
        )
    if any(
        type(key) is not str
        or type(value) is not str
        or not key
        or "=" in key
        or "\0" in key
        or "\0" in value
        for key, value in submitted.items()
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation environment is invalid"
        )
    result = dict(submitted)
    result["PATH"] = _FIXED_SUBPROCESS_PATH
    result["DOCKER_HOST"] = endpoint
    return result


def _docker_executable_identity(path: Path) -> tuple[int, ...]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker executable is unavailable"
        ) from None
    if (
        type(path) is not type(Path())
        or not path.is_absolute()
        or Path(os.path.abspath(path)) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        or metadata.st_nlink != 1
        or not os.access(path, os.X_OK, effective_ids=True)
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker executable is unavailable"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _resolve_trusted_docker_executable() -> tuple[Path, tuple[int, ...]]:
    for candidate in _TRUSTED_DOCKER_EXECUTABLE_CANDIDATES:
        try:
            resolved = candidate.resolve(strict=True)
            identity = _docker_executable_identity(resolved)
        except (OSError, TrustedTimePostEnrollmentTopologyReaderError):
            continue
        return resolved, identity
    raise TrustedTimePostEnrollmentTopologyReaderError(
        "trusted-time Docker executable is unavailable"
    )


def _socket_path(identity: LocalDockerDaemonIdentity) -> Path:
    if not _valid_daemon_identity(identity):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation session is invalid"
        )
    try:
        parsed = urlsplit(identity.endpoint)
        decoded = unquote(parsed.path)
        path = Path(decoded)
    except (TypeError, ValueError):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation session is invalid"
        ) from None
    if parsed.scheme != "unix" or str(path) != decoded:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation session is invalid"
        )
    return path


def _socket_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation session is unavailable"
        ) from None
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation session is unavailable"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


@dataclass(frozen=True, slots=True)
class _ContainerNetworkAttachment:
    network_id: str
    endpoint_id: str
    mac_address: str
    ipv4_address: str
    ipv4_prefix_length: int
    ipv6_address: str
    aliases: tuple[str, ...]
    dns_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _NetworkObservation:
    network_id: str
    identity_sha256: str
    containers: dict[str, dict[str, object]] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _AnchoredRetirementObservation:
    root_identity: tuple[int, int, int, int, int, int]
    candidates: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...]


def _exact_string_tuple(
    value: object,
    *,
    minimum_size: int,
    required_value: str,
) -> tuple[str, ...]:
    if (
        type(value) is not list
        or len(value) < minimum_size
        or len(value) > 8
        or any(
            type(item) is not str
            or not item
            or len(item) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        )
        or len(set(value)) != len(value)
        or required_value not in value
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    return tuple(cast(list[str], value))


def _ipv4_address(value: object) -> str:
    if type(value) is not str or not value or len(value) > 15 or "%" in value:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        ) from None
    if parsed.version != 4 or str(parsed) != value or parsed.is_unspecified or parsed.is_multicast:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    return value


def _ipv4_interface(value: object) -> str:
    if type(value) is not str or not value or len(value) > 18 or "%" in value:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker network observation is unavailable"
        )
    try:
        parsed = ipaddress.ip_interface(value)
    except ValueError:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker network observation is unavailable"
        ) from None
    if parsed.version != 4 or str(parsed) != value:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker network observation is unavailable"
        )
    return value


def _validate_container_reader_boundary(
    container: dict[str, object],
    *,
    expected_container_id: str,
    expected_service: Literal["chrony-nts", "trusted-time-supervisor"],
    expected_state: Literal["created", "staged_unreleased"],
) -> _ContainerNetworkAttachment:
    if (
        container.get("Id") != expected_container_id
        or container.get("Platform") != "linux"
        or type(container.get("Platform")) is not str
        or "ExecIDs" not in container
        or "AppArmorProfile" not in container
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    exec_ids = container["ExecIDs"]
    host = container.get("HostConfig")
    network_settings = container.get("NetworkSettings")
    if (
        (exec_ids is not None and (type(exec_ids) is not list or exec_ids != []))
        or type(host) is not dict
        or "Runtime" not in host
        or type(host["Runtime"]) is not str
        or host["Runtime"] != "runc"
        or type(container["AppArmorProfile"]) is not str
        or container["AppArmorProfile"] != _NETWORK_SAFE_APPARMOR_PROFILE
        or type(network_settings) is not dict
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    networks = network_settings.get("Networks")
    if (
        set(network_settings) != _NETWORK_SETTINGS_REQUIRED_KEYS
        or type(networks) is not dict
        or set(networks) != {COMPOSE_NETWORK_NAME}
        or network_settings.get("HairpinMode") is not False
        or network_settings.get("Ports") != {}
        or type(network_settings.get("Ports")) is not dict
        or network_settings.get("SecondaryIPAddresses") is not None
        or network_settings.get("SecondaryIPv6Addresses") is not None
        or any(
            network_settings.get(field_name) != ""
            for field_name in _NEUTRAL_NETWORK_SETTINGS_STRING_FIELDS
        )
        or any(
            type(network_settings.get(field_name)) is not int
            or network_settings.get(field_name) != 0
            for field_name in _NEUTRAL_NETWORK_SETTINGS_INTEGER_FIELDS
        )
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    attachment = networks.get(COMPOSE_NETWORK_NAME)
    if (
        type(attachment) is not dict
        or set(attachment) != _NETWORK_ATTACHMENT_REQUIRED_KEYS
        or attachment.get("IPAMConfig") not in (None, {})
        or type(attachment.get("IPAMConfig")) not in (type(None), dict)
        or attachment.get("Links") not in (None, [])
        or type(attachment.get("Links")) not in (type(None), list)
        or attachment.get("DriverOpts") not in (None, {})
        or type(attachment.get("DriverOpts")) not in (type(None), dict)
        or type(attachment.get("GwPriority")) is not int
        or attachment.get("GwPriority") != 0
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    aliases = _exact_string_tuple(
        attachment.get("Aliases"),
        minimum_size=2,
        required_value=expected_service,
    )
    network_id = attachment.get("NetworkID")
    if type(network_id) is not str or _FULL_ID_PATTERN.fullmatch(network_id) is None:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    if expected_state == "created":
        dns_value = attachment.get("DNSNames")
        dns_names = (
            ()
            if dns_value is None
            else _exact_string_tuple(
                dns_value,
                minimum_size=1,
                required_value=expected_service,
            )
        )
        if (
            type(network_settings.get("SandboxID")) is not str
            or network_settings.get("SandboxID") != ""
            or type(network_settings.get("SandboxKey")) is not str
            or network_settings.get("SandboxKey") != ""
            or attachment.get("EndpointID") != ""
            or attachment.get("Gateway") != ""
            or attachment.get("IPAddress") != ""
            or type(attachment.get("IPPrefixLen")) is not int
            or attachment.get("IPPrefixLen") != 0
            or attachment.get("IPv6Gateway") != ""
            or attachment.get("GlobalIPv6Address") != ""
            or type(attachment.get("GlobalIPv6PrefixLen")) is not int
            or attachment.get("GlobalIPv6PrefixLen") != 0
            or attachment.get("MacAddress") != ""
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return _ContainerNetworkAttachment(
            network_id=network_id,
            endpoint_id="",
            mac_address="",
            ipv4_address="",
            ipv4_prefix_length=0,
            ipv6_address="",
            aliases=aliases,
            dns_names=dns_names,
        )
    if expected_state != "staged_unreleased":
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    endpoint_id = attachment.get("EndpointID")
    mac_address = attachment.get("MacAddress")
    prefix_length = attachment.get("IPPrefixLen")
    dns_names = _exact_string_tuple(
        attachment.get("DNSNames"),
        minimum_size=2,
        required_value=expected_service,
    )
    ipv4 = _ipv4_address(attachment.get("IPAddress"))
    _ipv4_address(attachment.get("Gateway"))
    if (
        type(endpoint_id) is not str
        or _FULL_ID_PATTERN.fullmatch(endpoint_id) is None
        or type(mac_address) is not str
        or _MAC_ADDRESS_PATTERN.fullmatch(mac_address) is None
        or type(prefix_length) is not int
        or not 1 <= prefix_length <= 32
        or attachment.get("IPv6Gateway") != ""
        or attachment.get("GlobalIPv6Address") != ""
        or type(attachment.get("GlobalIPv6PrefixLen")) is not int
        or attachment.get("GlobalIPv6PrefixLen") != 0
        or type(network_settings.get("SandboxID")) is not str
        or _FULL_ID_PATTERN.fullmatch(cast(str, network_settings.get("SandboxID"))) is None
        or type(network_settings.get("SandboxKey")) is not str
        or len(cast(str, network_settings.get("SandboxKey"))) > 96
        or _DOCKER_NETNS_KEY_PATTERN.fullmatch(cast(str, network_settings.get("SandboxKey")))
        is None
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker observation is unavailable"
        )
    return _ContainerNetworkAttachment(
        network_id=network_id,
        endpoint_id=endpoint_id,
        mac_address=mac_address,
        ipv4_address=ipv4,
        ipv4_prefix_length=prefix_length,
        ipv6_address="",
        aliases=aliases,
        dns_names=dns_names,
    )


def _network_identity(
    network: dict[str, object],
    *,
    expected_inventory: frozenset[str],
    expected_state: Literal["created", "staged_unreleased"],
) -> _NetworkObservation:
    network_id = network.get("Id")
    labels = network.get("Labels")
    containers = network.get("Containers")
    config_from = network.get("ConfigFrom")
    if (
        set(network) != _NETWORK_IDENTITY_ALLOWED_KEYS
        or type(network_id) is not str
        or _FULL_ID_PATTERN.fullmatch(network_id) is None
        or network.get("Name") != COMPOSE_NETWORK_NAME
        or network.get("Driver") != "bridge"
        or network.get("Scope") != "local"
        or network.get("Internal") is not False
        or network.get("Attachable") is not False
        or network.get("Ingress") is not False
        or network.get("ConfigOnly") is not False
        or type(config_from) is not dict
        or config_from != {"Network": ""}
        or type(network.get("Created")) is not str
        or not network.get("Created")
        or network.get("EnableIPv6") is not False
        or type(network.get("IPAM")) is not dict
        or type(network.get("Options")) is not dict
        or type(labels) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in labels.items())
        or labels.get("com.docker.compose.project")
        != POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
        or labels.get("com.docker.compose.network") != "default"
        or type(containers) is not dict
        or any(type(key) is not str for key in containers)
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker network observation is unavailable"
        )
    typed_containers = cast(dict[str, object], containers)
    if expected_state == "created":
        if typed_containers:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker network observation is unavailable"
            )
    elif expected_state == "staged_unreleased":
        if frozenset(typed_containers) != expected_inventory:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker network observation is unavailable"
            )
        for value in typed_containers.values():
            if (
                type(value) is not dict
                or set(value) != _NETWORK_CONTAINER_REQUIRED_KEYS
                or type(value.get("Name")) is not str
                or not value.get("Name")
                or type(value.get("EndpointID")) is not str
                or _FULL_ID_PATTERN.fullmatch(cast(str, value.get("EndpointID"))) is None
                or type(value.get("MacAddress")) is not str
                or _MAC_ADDRESS_PATTERN.fullmatch(cast(str, value.get("MacAddress"))) is None
                or type(value.get("IPv4Address")) is not str
                or type(value.get("IPv6Address")) is not str
                or value.get("IPv6Address") != ""
            ):
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time Docker network observation is unavailable"
                )
            _ipv4_interface(value["IPv4Address"])
    else:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time Docker network observation is unavailable"
        )
    return _NetworkObservation(
        network_id=network_id,
        identity_sha256=_canonical_sha256(network),
        containers={
            container_id: cast(dict[str, object], value)
            for container_id, value in typed_containers.items()
        },
    )


def _validate_staged_paths(paths: tuple[Path, Path, Path, Path]) -> Path:
    if (
        type(paths) is not tuple
        or len(paths) != 4
        or any(type(path) is not type(Path()) or not path.is_absolute() for path in paths)
        or len(set(paths)) != 4
    ):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time staged input retirement observation is invalid"
        )
    root = paths[0].parent.parent
    expected = (
        (DATABASE_SECRET_DIRECTORY_PATTERN, None, DATABASE_SECRET_FILE_NAME),
        (HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN, "authority", HEAD_ANCHOR_AUTHORITY_FILE_NAME),
        (HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN, "auth", HEAD_ANCHOR_AUTH_SECRET_FILE_NAME),
        (
            HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN,
            "signing-key",
            HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
        ),
    )
    for path, (pattern, kind, file_name) in zip(paths, expected, strict=True):
        match = pattern.fullmatch(path.parent.name)
        if (
            path != Path(os.path.abspath(path))
            or path.parent.parent != root
            or path.name != file_name
            or match is None
            or (kind is not None and match.group(1) != kind)
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged input retirement observation is invalid"
            )
    return root


def _observe_host_retirements(
    paths: tuple[Path, Path, Path, Path],
) -> _AnchoredRetirementObservation:
    root = _validate_staged_paths(paths)
    descriptor: int | None = None
    parent_descriptors: dict[str, int] = {}
    absent_parents: set[str] = set()
    try:
        descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            raise OSError
        for path in paths:
            parent_name = path.parent.name
            try:
                parent_descriptor = os.open(
                    parent_name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise OSError from error
                absent_parents.add(parent_name)
                continue
            parent_descriptors[parent_name] = parent_descriptor
            parent_before = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent_before.st_mode)
                or parent_before.st_uid != os.geteuid()
                or stat.S_IMODE(parent_before.st_mode) != 0o700
            ):
                raise OSError
            try:
                os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise OSError from error
            else:
                raise OSError
        for parent_name in absent_parents:
            try:
                os.stat(parent_name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise OSError from error
            else:
                raise OSError
        for path in paths:
            held_parent_descriptor = parent_descriptors.get(path.parent.name)
            if held_parent_descriptor is None:
                continue
            held = os.fstat(held_parent_descriptor)
            named = os.stat(path.parent.name, dir_fd=descriptor, follow_symlinks=False)
            if (
                held.st_dev != named.st_dev
                or held.st_ino != named.st_ino
                or held.st_mode != named.st_mode
                or held.st_uid != named.st_uid
                or held.st_gid != named.st_gid
            ):
                raise OSError
            try:
                os.stat(path.name, dir_fd=held_parent_descriptor, follow_symlinks=False)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise OSError from error
            else:
                raise OSError
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_gid != after.st_gid
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise OSError
    except (OSError, ValueError):
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time staged input retirement observation is unavailable"
        ) from None
    finally:
        for parent_descriptor in parent_descriptors.values():
            with suppress(OSError):
                os.close(parent_descriptor)
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    candidates = tuple(
        TrustedTimePostEnrollmentAbsentPathCandidate(path=os.fspath(path)) for path in paths
    )
    return _AnchoredRetirementObservation(
        root_identity=(
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_ctime_ns,
        ),
        candidates=candidates,
    )


class TrustedTimePostEnrollmentTopologyObservationIssuer:
    """Closeable single-lock issuer for bounded read-only topology snapshots."""

    _authentication_capability: _AuthenticatedIssuerCapability | None
    _busy: bool
    _closed: bool
    _daemon_identity: LocalDockerDaemonIdentity
    _docker_executable_identity_value: tuple[int, ...]
    _docker_executable_path: Path
    _environment: dict[str, str]
    _first_staged_snapshot_sha256: str | None
    _ignored_root: Path
    _issued_created_observation_sha256: str | None
    _last_observation_sha256: str | None
    _lifecycle_lock: Any
    _lock_descriptor: int
    _lock_identity: tuple[int, int, int, int, int]
    _lock_path: Path
    _owner_pid: int
    _poisoned: bool
    _runner: _BoundedRunner
    _session_sha256: str
    _socket_identity_value: tuple[int, int, int, int, int]
    _socket_path_value: Path
    _staged_observation_count: int

    __slots__ = (
        "_authentication_capability",
        "_busy",
        "_closed",
        "_daemon_identity",
        "_docker_executable_identity_value",
        "_docker_executable_path",
        "_environment",
        "_first_staged_snapshot_sha256",
        "_ignored_root",
        "_issued_created_observation_sha256",
        "_last_observation_sha256",
        "_lifecycle_lock",
        "_lock_descriptor",
        "_lock_identity",
        "_lock_path",
        "_owner_pid",
        "_poisoned",
        "_runner",
        "_session_sha256",
        "_socket_identity_value",
        "_socket_path_value",
        "_staged_observation_count",
    )

    def __init__(self) -> None:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time topology observation issuer must be opened"
        )

    @classmethod
    def open(
        cls,
        *,
        expected_daemon_identity: LocalDockerDaemonIdentity,
        docker_environment: Mapping[str, str],
    ) -> TrustedTimePostEnrollmentTopologyObservationIssuer:
        if cls is not TrustedTimePostEnrollmentTopologyObservationIssuer:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation issuer type is invalid"
            )
        docker_executable, _ = _resolve_trusted_docker_executable()
        return TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies(
            expected_daemon_identity=expected_daemon_identity,
            docker_environment=docker_environment,
            docker_executable=docker_executable,
            lock_path=TRUSTED_TIME_LAUNCH_LOCK_PATH,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            runner=run_bounded_subprocess,
            session_token_factory=lambda: secrets.token_bytes(32),
            _production_open_proof=_PRODUCTION_OPEN_PROOF,
        )

    @classmethod
    def _open_with_dependencies(
        cls,
        *,
        expected_daemon_identity: LocalDockerDaemonIdentity,
        docker_environment: Mapping[str, str],
        docker_executable: Path,
        lock_path: Path,
        ignored_root: Path,
        runner: _BoundedRunner,
        session_token_factory: Callable[[], bytes],
        _production_open_proof: object | None = None,
    ) -> TrustedTimePostEnrollmentTopologyObservationIssuer:
        if (
            cls is not TrustedTimePostEnrollmentTopologyObservationIssuer
            or type(expected_daemon_identity) is not LocalDockerDaemonIdentity
            or type(docker_executable) is not type(Path())
            or type(lock_path) is not type(Path())
            or type(ignored_root) is not type(Path())
            or not callable(runner)
            or not callable(session_token_factory)
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation session is invalid"
            )
        socket_path = _socket_path(expected_daemon_identity)
        docker_executable_identity = _docker_executable_identity(docker_executable)
        environment = _minimal_docker_environment(
            docker_environment,
            endpoint=expected_daemon_identity.endpoint,
        )
        lock_descriptor: int | None = None
        instance = object.__new__(cls)
        authenticated_open = _production_open_proof is _PRODUCTION_OPEN_PROOF
        try:
            lock_descriptor = _acquire_trusted_time_launch_lock(
                path=lock_path,
                ignored_root=ignored_root,
            )
            lock_metadata = os.fstat(lock_descriptor)
            token = session_token_factory()
            if type(token) is not bytes or len(token) != 32:
                raise ValueError
            instance._authentication_capability = (
                _new_authenticated_issuer_capability() if authenticated_open else None
            )
            instance._busy = False
            instance._closed = False
            instance._daemon_identity = expected_daemon_identity
            instance._docker_executable_identity_value = docker_executable_identity
            instance._docker_executable_path = docker_executable
            instance._environment = environment
            instance._first_staged_snapshot_sha256 = None
            instance._ignored_root = ignored_root
            instance._issued_created_observation_sha256 = None
            instance._last_observation_sha256 = None
            instance._lifecycle_lock = threading.RLock()
            instance._lock_descriptor = lock_descriptor
            instance._lock_identity = (
                lock_metadata.st_dev,
                lock_metadata.st_ino,
                lock_metadata.st_mode,
                lock_metadata.st_uid,
                lock_metadata.st_gid,
            )
            instance._lock_path = lock_path
            instance._owner_pid = os.getpid()
            instance._poisoned = False
            instance._runner = runner
            instance._socket_identity_value = _socket_identity(socket_path)
            instance._socket_path_value = socket_path
            instance._staged_observation_count = 0
            instance._session_sha256 = "0" * 64
            instance._validate_session()
            receipts: list[_ReadReceipt] = []
            instance._observe_daemon(receipts)
            instance._session_sha256 = _canonical_sha256(
                {
                    "contract_version": POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION,
                    "authenticated_observation_issuer": authenticated_open,
                    "daemon_identity": {
                        "context_name": expected_daemon_identity.context_name,
                        "daemon_id": expected_daemon_identity.daemon_id,
                        "endpoint": expected_daemon_identity.endpoint,
                    },
                    "environment_sha256": _canonical_sha256(environment),
                    "docker_executable_identity": list(docker_executable_identity),
                    "docker_executable_path": os.fspath(docker_executable),
                    "lock_identity": list(instance._lock_identity),
                    "owner_pid": instance._owner_pid,
                    "open_transcript_sha256": _canonical_sha256(
                        [receipt.payload() for receipt in receipts]
                    ),
                    "session_nonce_sha256": hashlib.sha256(token).hexdigest(),
                    "socket_identity": list(instance._socket_identity_value),
                }
            )
            return instance
        except BaseException:
            if lock_descriptor is not None:
                with suppress(BaseException):
                    _release_trusted_time_launch_lock(lock_descriptor)
                with suppress(OSError):
                    os.close(lock_descriptor)
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation session is unavailable"
            ) from None

    def __enter__(self) -> TrustedTimePostEnrollmentTopologyObservationIssuer:
        self._require_usable()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "poisoned" if self._poisoned else "open"
        return f"{type(self).__name__}(state={state!r})"

    def __copy__(self) -> TrustedTimePostEnrollmentTopologyObservationIssuer:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time topology observation issuer cannot be copied"
        )

    def __deepcopy__(
        self,
        _: object,
    ) -> TrustedTimePostEnrollmentTopologyObservationIssuer:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time topology observation issuer cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time topology observation issuer cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time topology observation issuer cannot be serialized"
        )

    def _validate_lock(self) -> None:
        descriptor = self._lock_descriptor
        if type(descriptor) is not int or descriptor < 0:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation session is unavailable"
            )
        guard: int | None = None
        try:
            held = os.fstat(descriptor)
            named = os.stat(self._lock_path, follow_symlinks=False)
            identity = (
                held.st_dev,
                held.st_ino,
                held.st_mode,
                held.st_uid,
                held.st_gid,
            )
            if (
                identity != self._lock_identity
                or held.st_dev != named.st_dev
                or held.st_ino != named.st_ino
                or not stat.S_ISREG(held.st_mode)
                or held.st_uid != os.geteuid()
                or stat.S_IMODE(held.st_mode) != 0o600
                or held.st_nlink != 1
                or held.st_size != 0
            ):
                raise OSError
            guard = os.open(
                self._lock_path,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(guard, fcntl.LOCK_UN)
                raise OSError
        except OSError:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation session is unavailable"
            ) from None
        finally:
            if guard is not None:
                with suppress(OSError):
                    os.close(guard)

    def _validate_session(self) -> None:
        if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation process is unavailable"
            )
        self._validate_lock()
        if (
            _socket_identity(self._socket_path_value) != self._socket_identity_value
            or _docker_executable_identity(self._docker_executable_path)
            != self._docker_executable_identity_value
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation session is unavailable"
            )

    def _require_usable(self) -> None:
        if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation process is unavailable"
            )
        if type(self._authentication_capability) is not _AuthenticatedIssuerCapability:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time authenticated observation issuer is unavailable"
            )
        with self._lifecycle_lock:
            if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation process is unavailable"
                )
            if self._closed or self._poisoned:
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation issuer is unavailable"
                )
            if self._busy:
                self._poisoned = True
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation issuer is unavailable"
                )

    def _run_bytes(
        self,
        receipts: list[_ReadReceipt],
        *,
        label: str,
        argv: tuple[str, ...],
        maximum_stdout_bytes: int,
    ) -> bytes:
        self._validate_session()
        try:
            completed = self._runner(
                argv,
                cwd=ROOT,
                environment=self._environment,
                timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
                maximum_stdout_bytes=maximum_stdout_bytes,
                maximum_stderr_bytes=_MAXIMUM_STDERR_BYTES,
                stdin_bytes=None,
                maximum_stdin_bytes=0,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            ) from None
        with self._lifecycle_lock:
            if self._poisoned:
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation issuer is unavailable"
                )
        self._validate_session()
        if (
            type(completed) is not subprocess.CompletedProcess
            or completed.args != argv
            or type(completed.returncode) is not int
            or completed.returncode != 0
            or type(completed.stdout) is not bytes
            or not completed.stdout
            or len(completed.stdout) > maximum_stdout_bytes
            or type(completed.stderr) is not bytes
            or completed.stderr
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        receipts.append(
            _ReadReceipt(
                ordinal=len(receipts) + 1,
                label=label,
                argv=argv,
                maximum_stdout_bytes=maximum_stdout_bytes,
                stdout_size=len(completed.stdout),
                stdout_sha256=hashlib.sha256(completed.stdout).hexdigest(),
            )
        )
        return completed.stdout

    def _run_json[JsonRoot: (dict[str, object], list[object], str)](
        self,
        receipts: list[_ReadReceipt],
        *,
        label: str,
        argv: tuple[str, ...],
        maximum_stdout_bytes: int,
        expected_type: type[JsonRoot],
    ) -> JsonRoot:
        raw = self._run_bytes(
            receipts,
            label=label,
            argv=argv,
            maximum_stdout_bytes=maximum_stdout_bytes,
        )
        if not raw.endswith(b"\n"):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return _decode_strict_json(
            raw,
            expected_type=expected_type,
            maximum_bytes=maximum_stdout_bytes,
        )

    def _observe_daemon(self, receipts: list[_ReadReceipt]) -> LocalDockerDaemonIdentity:
        observed = self._run_json(
            receipts,
            label="daemon_identity",
            argv=(
                os.fspath(self._docker_executable_path),
                "info",
                "--format",
                "{{json .ID}}",
            ),
            maximum_stdout_bytes=_MAXIMUM_DAEMON_STDOUT_BYTES,
            expected_type=str,
        )
        if observed != self._daemon_identity.daemon_id:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return self._daemon_identity

    def _observe_inventory(self, receipts: list[_ReadReceipt]) -> tuple[str, str]:
        raw = self._run_bytes(
            receipts,
            label="project_inventory",
            argv=(
                os.fspath(self._docker_executable_path),
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                (
                    "label=com.docker.compose.project="
                    + POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
                ),
                "--format",
                "{{json .ID}}",
            ),
            maximum_stdout_bytes=_MAXIMUM_INVENTORY_STDOUT_BYTES,
        )
        if not raw.endswith(b"\n") or b"\r" in raw:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        lines = raw.splitlines()
        if len(lines) != 2 or any(not line for line in lines):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        ids = tuple(
            _decode_strict_json(
                line,
                expected_type=str,
                maximum_bytes=_MAXIMUM_INVENTORY_STDOUT_BYTES,
            )
            for line in lines
        )
        if len(set(ids)) != 2 or any(
            _FULL_ID_PATTERN.fullmatch(container_id) is None for container_id in ids
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return cast(tuple[str, str], ids)

    def _observe_volumes(self, receipts: list[_ReadReceipt]) -> TrustedTimeVolumeIdentities:
        inspections: dict[str, list[object]] = {}
        for label, name in (
            ("socket_volume", COMPOSE_SOCKET_VOLUME_NAME),
            ("state_volume", COMPOSE_STATE_VOLUME_NAME),
        ):
            observed = self._run_json(
                receipts,
                label=label,
                argv=(
                    os.fspath(self._docker_executable_path),
                    "volume",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    name,
                ),
                maximum_stdout_bytes=_MAXIMUM_VOLUME_STDOUT_BYTES,
                expected_type=dict,
            )
            inspections[name] = [observed]
        validate_socket_volume_inspection(
            inspections[COMPOSE_SOCKET_VOLUME_NAME],
            expected_name=COMPOSE_SOCKET_VOLUME_NAME,
        )
        validate_chrony_state_volume_inspection(
            inspections[COMPOSE_STATE_VOLUME_NAME],
        )
        return TrustedTimeVolumeIdentities(
            socket_sha256=_stable_volume_identity_sha256(
                inspections[COMPOSE_SOCKET_VOLUME_NAME],
                expected_name=COMPOSE_SOCKET_VOLUME_NAME,
            ),
            state_sha256=_stable_volume_identity_sha256(
                inspections[COMPOSE_STATE_VOLUME_NAME],
                expected_name=COMPOSE_STATE_VOLUME_NAME,
            ),
        )

    def _observe_network(
        self,
        receipts: list[_ReadReceipt],
        *,
        inventory: tuple[str, str],
        expected_state: Literal["created", "staged_unreleased"],
    ) -> _NetworkObservation:
        observed = self._run_json(
            receipts,
            label="project_network",
            argv=(
                os.fspath(self._docker_executable_path),
                "network",
                "inspect",
                "--format",
                "{{json .}}",
                COMPOSE_NETWORK_NAME,
            ),
            maximum_stdout_bytes=_MAXIMUM_NETWORK_STDOUT_BYTES,
            expected_type=dict,
        )
        return _network_identity(
            observed,
            expected_inventory=frozenset(inventory),
            expected_state=expected_state,
        )

    def _observe_image_configurations(
        self,
        receipts: list[_ReadReceipt],
        *,
        approved_launch: TrustedTimeApprovedLaunch,
    ) -> tuple[dict[str, object], dict[str, object]]:
        values: list[dict[str, object]] = []
        for label, image_id in (
            ("source_image_configuration", approved_launch.source_image_id),
            ("supervisor_image_configuration", approved_launch.supervisor_image_id),
        ):
            observed = self._run_json(
                receipts,
                label=label,
                argv=(
                    os.fspath(self._docker_executable_path),
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    image_id,
                ),
                maximum_stdout_bytes=_MAXIMUM_IMAGE_CONFIGURATION_STDOUT_BYTES,
                expected_type=dict,
            )
            image = observed
            configuration = image.get("Config")
            if (
                image.get("Id") != image_id
                or type(image.get("Id")) is not str
                or type(configuration) is not dict
            ):
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time Docker image observation is unavailable"
                )
            values.append(cast(dict[str, object], configuration))
        return values[0], values[1]

    def _observe_containers(
        self,
        receipts: list[_ReadReceipt],
        *,
        inventory: tuple[str, str],
        network: _NetworkObservation,
        expected_state: Literal["created", "staged_unreleased"],
        approved_launch: TrustedTimeApprovedLaunch,
        source_configuration: dict[str, object],
        supervisor_configuration: dict[str, object],
        staged_paths: tuple[Path, Path, Path, Path],
    ) -> dict[str, object]:
        inspections: dict[str, object] = {}
        observed_roles: set[str] = set()
        staged_endpoint_ids: set[str] = set()
        staged_ipv4_addresses: set[str] = set()
        staged_mac_addresses: set[str] = set()
        for container_id in sorted(inventory):
            observed = self._run_json(
                receipts,
                label="container_inspection",
                argv=(
                    os.fspath(self._docker_executable_path),
                    "container",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    container_id,
                ),
                maximum_stdout_bytes=_MAXIMUM_CONTAINER_STDOUT_BYTES,
                expected_type=dict,
            )
            container = observed
            configuration = container.get("Config")
            labels = configuration.get("Labels") if type(configuration) is dict else None
            service = labels.get("com.docker.compose.service") if type(labels) is dict else None
            if service not in {"chrony-nts", "trusted-time-supervisor"}:
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time Docker observation is unavailable"
                )
            typed_service = cast(Literal["chrony-nts", "trusted-time-supervisor"], service)
            if typed_service in observed_roles:
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time Docker observation is unavailable"
                )
            observed_roles.add(typed_service)
            attachment = _validate_container_reader_boundary(
                container,
                expected_container_id=container_id,
                expected_service=typed_service,
                expected_state=expected_state,
            )
            if attachment.network_id != network.network_id:
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time Docker observation is unavailable"
                )
            if expected_state == "staged_unreleased":
                endpoint = network.containers.get(container_id)
                if (
                    type(endpoint) is not dict
                    or endpoint.get("EndpointID") != attachment.endpoint_id
                    or endpoint.get("MacAddress") != attachment.mac_address
                    or endpoint.get("IPv4Address")
                    != f"{attachment.ipv4_address}/{attachment.ipv4_prefix_length}"
                    or endpoint.get("IPv6Address") != attachment.ipv6_address
                    or endpoint.get("Name") not in attachment.aliases
                    or endpoint.get("Name") not in attachment.dns_names
                ):
                    raise TrustedTimePostEnrollmentTopologyReaderError(
                        "trusted-time Docker observation is unavailable"
                    )
                staged_endpoint_ids.add(attachment.endpoint_id)
                staged_ipv4_addresses.add(attachment.ipv4_address)
                staged_mac_addresses.add(attachment.mac_address)
            image_id = (
                approved_launch.source_image_id
                if typed_service == "chrony-nts"
                else approved_launch.supervisor_image_id
            )
            image_configuration = (
                source_configuration if typed_service == "chrony-nts" else supervisor_configuration
            )
            path_arguments: dict[str, Path | None] = {
                "expected_database_secret_file": None,
                "expected_head_anchor_authority_file": None,
                "expected_head_anchor_auth_secret_file": None,
                "expected_head_anchor_signing_key_secret_file": None,
            }
            if typed_service == "trusted-time-supervisor":
                path_arguments = {
                    "expected_database_secret_file": staged_paths[0],
                    "expected_head_anchor_authority_file": staged_paths[1],
                    "expected_head_anchor_auth_secret_file": staged_paths[2],
                    "expected_head_anchor_signing_key_secret_file": staged_paths[3],
                }
            validator = (
                validate_exact_never_started_created_container
                if expected_state == "created"
                else validate_exact_staged_running_container
            )
            validator(
                [container],
                expected_container_id=container_id,
                expected_image_id=image_id,
                expected_image_configuration=image_configuration,
                expected_service=typed_service,
                require_live_observation_fields=True,
                **path_arguments,
            )
            inspections[container_id] = [container]
        if observed_roles != {"chrony-nts", "trusted-time-supervisor"} or (
            expected_state == "staged_unreleased"
            and (
                len(staged_endpoint_ids) != 2
                or len(staged_ipv4_addresses) != 2
                or len(staged_mac_addresses) != 2
            )
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return inspections

    def _observe_barrier(
        self,
        receipts: list[_ReadReceipt],
        *,
        supervisor_container_id: str,
    ) -> tuple[
        TrustedTimePostEnrollmentConsumedMarkerCandidate,
        tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    ]:
        observed = self._run_json(
            receipts,
            label="staged_barrier",
            argv=(
                os.fspath(self._docker_executable_path),
                "container",
                "exec",
                "--user",
                "10001:10001",
                supervisor_container_id,
                "/opt/venv/bin/python",
                "-I",
                "-S",
                "-c",
                _BARRIER_PROBE_SOURCE,
            ),
            maximum_stdout_bytes=_MAXIMUM_BARRIER_STDOUT_BYTES,
            expected_type=dict,
        )
        root = observed
        if (
            set(root) != {"contract_version", "marker", "release_absences"}
            or root.get("contract_version") != _BARRIER_PROBE_CONTRACT_VERSION
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged barrier observation is unavailable"
            )
        marker = root.get("marker")
        absences = root.get("release_absences")
        marker_keys = {
            "byte_sha256",
            "changed_time_ns",
            "device",
            "inode",
            "link_count",
            "mode",
            "modified_time_ns",
            "owner_gid",
            "owner_uid",
            "path",
            "regular",
            "size",
        }
        absence_keys = {"path", "status"}
        if (
            type(marker) is not dict
            or set(marker) != marker_keys
            or type(absences) is not list
            or len(absences) != 2
            or any(type(item) is not dict or set(item) != absence_keys for item in absences)
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged barrier observation is unavailable"
            )
        try:
            marker_candidate = TrustedTimePostEnrollmentConsumedMarkerCandidate(
                **cast(dict[str, Any], marker)
            )
            absence_candidates = tuple(
                TrustedTimePostEnrollmentAbsentPathCandidate(**cast(dict[str, Any], item))
                for item in absences
            )
        except Exception:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged barrier observation is unavailable"
            ) from None
        if (
            len(absence_candidates) != 2
            or tuple(candidate.path for candidate in absence_candidates) != _RELEASE_PATHS
        ):
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged barrier observation is unavailable"
            )
        return marker_candidate, absence_candidates

    def _transcript_sha256(
        self,
        receipts: list[_ReadReceipt],
        *,
        kind: Literal["created", "staged_unreleased"],
        expected_count: int,
    ) -> str:
        if len(receipts) != expected_count:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time Docker observation is unavailable"
            )
        return _canonical_sha256(
            {
                "contract_version": POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION,
                "kind": kind,
                "reads": [receipt.payload() for receipt in receipts],
                "session_sha256": self._session_sha256,
            }
        )

    def _begin_observation(self) -> None:
        if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation process is unavailable"
            )
        with self._lifecycle_lock:
            if self._owner_pid != os.getpid():
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation process is unavailable"
                )
            self._require_usable()
            self._busy = True

    def _finish_observation(self) -> None:
        with self._lifecycle_lock:
            self._busy = False

    def _fail_observation(self) -> None:
        with self._lifecycle_lock:
            self._poisoned = True

    def issue_created_snapshot(
        self,
        *,
        approval: TrustedTimePostEnrollmentStartApproval,
        approved_launch: TrustedTimeApprovedLaunch,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> TrustedTimePostEnrollmentCreatedTopologyObservation:
        """Observe a created topology without starting or mutating it."""

        self._begin_observation()
        try:
            if (
                type(approval) is not TrustedTimePostEnrollmentStartApproval
                or type(approved_launch) is not TrustedTimeApprovedLaunch
                or self._issued_created_observation_sha256 is not None
                or self._staged_observation_count != 0
            ):
                raise ValueError
            approved_launch.__post_init__()
            receipts: list[_ReadReceipt] = []
            daemon_before = self._observe_daemon(receipts)
            volumes_before = self._observe_volumes(receipts)
            inventory_before = self._observe_inventory(receipts)
            network_before = self._observe_network(
                receipts,
                inventory=inventory_before,
                expected_state="created",
            )
            source_configuration, supervisor_configuration = self._observe_image_configurations(
                receipts,
                approved_launch=approved_launch,
            )
            inspections = self._observe_containers(
                receipts,
                inventory=inventory_before,
                network=network_before,
                expected_state="created",
                approved_launch=approved_launch,
                source_configuration=source_configuration,
                supervisor_configuration=supervisor_configuration,
                staged_paths=(
                    expected_database_secret_file,
                    expected_head_anchor_authority_file,
                    expected_head_anchor_auth_secret_file,
                    expected_head_anchor_signing_key_secret_file,
                ),
            )
            inventory_after = self._observe_inventory(receipts)
            network_after = self._observe_network(
                receipts,
                inventory=inventory_after,
                expected_state="created",
            )
            volumes_after = self._observe_volumes(receipts)
            daemon_after = self._observe_daemon(receipts)
            if (
                network_after.network_id != network_before.network_id
                or network_after.identity_sha256 != network_before.identity_sha256
            ):
                raise ValueError
            snapshot = validate_post_enrollment_start_created_topology(
                approval=approval,
                approved_launch=approved_launch,
                daemon_identity_before=daemon_before,
                daemon_identity_after=daemon_after,
                volume_identities_before=volumes_before,
                volume_identities_after=volumes_after,
                project_container_ids_before=inventory_before,
                project_container_ids_after=inventory_after,
                container_inspections=inspections,
                source_image_configuration=source_configuration,
                supervisor_image_configuration=supervisor_configuration,
                expected_database_secret_file=expected_database_secret_file,
                expected_head_anchor_authority_file=expected_head_anchor_authority_file,
                expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
                expected_head_anchor_signing_key_secret_file=(
                    expected_head_anchor_signing_key_secret_file
                ),
            )
            transcript_sha256 = self._transcript_sha256(
                receipts,
                kind="created",
                expected_count=_CREATED_OBSERVATION_COUNT,
            )
            self._validate_session()
            observation_payload = _observation_payload(
                kind="created",
                status=POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS,
                session_sha256=self._session_sha256,
                transcript_sha256=transcript_sha256,
                observation_count=len(receipts),
                snapshot_contract_version=POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
                snapshot_sha256=snapshot.snapshot_sha256,
            )
            observation = TrustedTimePostEnrollmentCreatedTopologyObservation(
                session_sha256=self._session_sha256,
                transcript_sha256=transcript_sha256,
                observation_count=len(receipts),
                snapshot=snapshot,
                _seal=_seal_observation(
                    self._authentication_capability,
                    observation_payload,
                ),
            )
            with self._lifecycle_lock:
                self._issued_created_observation_sha256 = observation.observation_sha256
                self._last_observation_sha256 = observation.observation_sha256
            return observation
        except BaseException:
            self._fail_observation()
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time created topology observation is unavailable"
            ) from None
        finally:
            self._finish_observation()

    def issue_staged_unreleased_snapshot(
        self,
        *,
        created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
        approval: TrustedTimePostEnrollmentStartApproval,
        approved_launch: TrustedTimeApprovedLaunch,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> TrustedTimePostEnrollmentStagedTopologyObservation:
        """Observe staged state using one exact read-only in-container probe."""

        self._begin_observation()
        try:
            if (
                type(created_observation) is not TrustedTimePostEnrollmentCreatedTopologyObservation
                or created_observation.session_sha256 != self._session_sha256
                or type(approval) is not TrustedTimePostEnrollmentStartApproval
                or type(approved_launch) is not TrustedTimeApprovedLaunch
                or self._issued_created_observation_sha256 is None
                or self._last_observation_sha256 is None
                or self._staged_observation_count >= 2
            ):
                raise ValueError
            created_observation.__post_init__()
            if created_observation.observation_sha256 != self._issued_created_observation_sha256:
                raise ValueError
            approved_launch.__post_init__()
            staged_paths = (
                expected_database_secret_file,
                expected_head_anchor_authority_file,
                expected_head_anchor_auth_secret_file,
                expected_head_anchor_signing_key_secret_file,
            )
            receipts: list[_ReadReceipt] = []
            daemon_before = self._observe_daemon(receipts)
            volumes_before = self._observe_volumes(receipts)
            inventory_before = self._observe_inventory(receipts)
            created_inventory = {
                created_observation.snapshot.source.container_id,
                created_observation.snapshot.supervisor.container_id,
            }
            if set(inventory_before) != created_inventory:
                raise ValueError
            network_before = self._observe_network(
                receipts,
                inventory=inventory_before,
                expected_state="staged_unreleased",
            )
            retirements_before = _observe_host_retirements(staged_paths)
            marker_before, release_before = self._observe_barrier(
                receipts,
                supervisor_container_id=(created_observation.snapshot.supervisor.container_id),
            )
            source_configuration, supervisor_configuration = self._observe_image_configurations(
                receipts,
                approved_launch=approved_launch,
            )
            marker_after, release_after = self._observe_barrier(
                receipts,
                supervisor_container_id=(created_observation.snapshot.supervisor.container_id),
            )
            inspections = self._observe_containers(
                receipts,
                inventory=inventory_before,
                network=network_before,
                expected_state="staged_unreleased",
                approved_launch=approved_launch,
                source_configuration=source_configuration,
                supervisor_configuration=supervisor_configuration,
                staged_paths=staged_paths,
            )
            retirements_after = _observe_host_retirements(staged_paths)
            if retirements_after.root_identity != retirements_before.root_identity:
                raise ValueError
            inventory_after = self._observe_inventory(receipts)
            network_after = self._observe_network(
                receipts,
                inventory=inventory_after,
                expected_state="staged_unreleased",
            )
            volumes_after = self._observe_volumes(receipts)
            daemon_after = self._observe_daemon(receipts)
            if (
                network_after.network_id != network_before.network_id
                or network_after.identity_sha256 != network_before.identity_sha256
            ):
                raise ValueError
            snapshot = validate_post_enrollment_start_staged_unreleased_topology(
                approval=approval,
                approved_launch=approved_launch,
                created_topology=created_observation.snapshot,
                daemon_identity_before=daemon_before,
                daemon_identity_after=daemon_after,
                volume_identities_before=volumes_before,
                volume_identities_after=volumes_after,
                project_container_ids_before=inventory_before,
                project_container_ids_after=inventory_after,
                container_inspections=inspections,
                source_image_configuration=source_configuration,
                supervisor_image_configuration=supervisor_configuration,
                expected_database_secret_file=expected_database_secret_file,
                expected_head_anchor_authority_file=expected_head_anchor_authority_file,
                expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
                expected_head_anchor_signing_key_secret_file=(
                    expected_head_anchor_signing_key_secret_file
                ),
                database_secret_consumed_before=marker_before,
                database_secret_consumed_after=marker_after,
                release_path_absences_before=release_before,
                release_path_absences_after=release_after,
                staged_input_retirements_before=retirements_before.candidates,
                staged_input_retirements_after=retirements_after.candidates,
            )
            if (
                self._staged_observation_count == 1
                and snapshot.snapshot_sha256 != self._first_staged_snapshot_sha256
            ):
                raise ValueError
            transcript_sha256 = self._transcript_sha256(
                receipts,
                kind="staged_unreleased",
                expected_count=_STAGED_OBSERVATION_COUNT,
            )
            self._validate_session()
            ordinal = self._staged_observation_count + 1
            observation_payload = _observation_payload(
                kind="staged_unreleased",
                status=POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS,
                session_sha256=self._session_sha256,
                transcript_sha256=transcript_sha256,
                observation_count=len(receipts),
                snapshot_contract_version=POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
                snapshot_sha256=snapshot.snapshot_sha256,
                created_observation_sha256=created_observation.observation_sha256,
                staged_observation_ordinal=ordinal,
                predecessor_observation_sha256=self._last_observation_sha256,
            )
            observation = TrustedTimePostEnrollmentStagedTopologyObservation(
                session_sha256=self._session_sha256,
                transcript_sha256=transcript_sha256,
                observation_count=len(receipts),
                created_observation_sha256=created_observation.observation_sha256,
                staged_observation_ordinal=ordinal,
                predecessor_observation_sha256=self._last_observation_sha256,
                snapshot=snapshot,
                _seal=_seal_observation(
                    self._authentication_capability,
                    observation_payload,
                ),
            )
            with self._lifecycle_lock:
                self._staged_observation_count = ordinal
                if ordinal == 1:
                    self._first_staged_snapshot_sha256 = snapshot.snapshot_sha256
                self._last_observation_sha256 = observation.observation_sha256
            return observation
        except BaseException:
            self._fail_observation()
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time staged topology observation is unavailable"
            ) from None
        finally:
            self._finish_observation()

    def close(self) -> None:
        """Close the one lock session exactly once."""

        if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation issuer close is unavailable"
            )
        with self._lifecycle_lock:
            if type(self._owner_pid) is not int or self._owner_pid != os.getpid():
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation issuer close is unavailable"
                )
            if self._closed or self._busy:
                if self._busy:
                    self._poisoned = True
                raise TrustedTimePostEnrollmentTopologyReaderError(
                    "trusted-time topology observation issuer close is unavailable"
                )
            descriptor = self._lock_descriptor
            validation_failed = False
            try:
                self._validate_lock()
            except BaseException:
                validation_failed = True
            self._closed = True
            self._poisoned = True
            self._authentication_capability = None
            self._lock_descriptor = -1
            self._environment = {}
            self._first_staged_snapshot_sha256 = None
            self._issued_created_observation_sha256 = None
            self._last_observation_sha256 = None
        try:
            _release_trusted_time_launch_lock(descriptor)
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation issuer close is unavailable"
            ) from None
        if validation_failed:
            raise TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time topology observation issuer close is unavailable"
            )


__all__ = [
    "POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS",
    "POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS",
    "POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION",
    "TrustedTimePostEnrollmentCreatedTopologyObservation",
    "TrustedTimePostEnrollmentStagedTopologyObservation",
    "TrustedTimePostEnrollmentTopologyObservationIssuer",
    "TrustedTimePostEnrollmentTopologyReaderError",
]
