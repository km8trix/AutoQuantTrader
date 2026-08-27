"""Closed Docker HTTP evidence vocabulary for ADR 0121 milestone one.

This module is deliberately transport-free.  It builds and validates the
literal HTTP bytes, bounded response bytes, typed Docker projections, and the
ordinal 0..17 evidence chain.  It has no socket, generic request, retry, volume
delete, subprocess, or production caller.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Never, Self, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    MAXIMUM_SIGNED_INTEGER,
    FrozenJsonObject,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
)

DOCKER_API_VERSION = "v1.45"
DOCKER_SERVICE = "trusted-time-graceful-stop-docker-v2"
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
COMMAND_SOCKET_VOLUME = "autoquanttrader-trusted-time_chrony_command_socket"
STATE_VOLUME = "autoquanttrader-trusted-time_chrony_state"
VOLUME_NAMES = (COMMAND_SOCKET_VOLUME, STATE_VOLUME)
EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()

_FULL_ID = re.compile(r"[0-9a-f]{64}\Z")
_CANONICAL_DECIMAL = re.compile(r"0|[1-9][0-9]*\Z")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HTTP_LINE_LIMIT = 1_024
_HTTP_HEADER_BLOCK_LIMIT = 16_384
_HTTP_HEADER_LINE_LIMIT = 64
_JSON_DEPTH_LIMIT = 16
_JSON_NODE_LIMIT = 16_384
_JSON_STRING_LIMIT = 65_536

_GET_HEADERS = (
    ("Host", "docker"),
    ("Accept", "application/json"),
    ("Connection", "close"),
)
_MUTATION_HEADERS = (*_GET_HEADERS, ("Content-Length", "0"))
_CALL_SPEC_CAPABILITY = object()
_RESPONSE_CAPTURE_CAPABILITY = object()
_ADMISSION_ROOTED_TRACE_PREFIX_CAPABILITY = object()


class TrustedTimeDockerEvidenceRejected(TrustedTimeGracefulStopV2Rejected):
    """A Docker request, response, projection, or evidence chain is invalid."""


def _reject(message: str) -> Never:
    raise TrustedTimeDockerEvidenceRejected(message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_sha256(domain: str, value: object, *, maximum_bytes: int = 256 * 1_024) -> str:
    encoded = canonical_v2_json_bytes(value, maximum_bytes=maximum_bytes)
    return _sha256(domain.encode("ascii") + b"\0" + encoded)


def _require_fields(value: dict[str, object], fields: frozenset[str], label: str) -> None:
    if frozenset(value) != fields:
        _reject(f"{label} field set is not exact")


def _require_text(
    value: object,
    name: str,
    *,
    maximum_bytes: int = 65_536,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not value and not allow_empty):
        _reject(f"{name} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _reject(f"{name} contains an invalid Unicode scalar")
    if len(encoded) > maximum_bytes or "\0" in value:
        _reject(f"{name} exceeds its text bound")
    return value


def _require_ascii(
    value: object,
    name: str,
    *,
    maximum_bytes: int = 128,
    allow_empty: bool = False,
) -> str:
    text = _require_text(value, name, maximum_bytes=maximum_bytes, allow_empty=allow_empty)
    if not text.isascii():
        _reject(f"{name} must be ASCII")
    return text


def _require_sha256(value: object, name: str) -> str:
    text = _require_ascii(value, name, maximum_bytes=64)
    if _FULL_ID.fullmatch(text) is None:
        _reject(f"{name} must be lowercase SHA-256")
    return text


def _require_full_id(value: object, name: str) -> str:
    text = _require_ascii(value, name, maximum_bytes=64)
    if _FULL_ID.fullmatch(text) is None:
        _reject(f"{name} must be one full lowercase hexadecimal ID")
    return text


def _require_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAXIMUM_SIGNED_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _reject(f"{name} is outside its integer bounds")
    return value


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        _reject(f"{name} must be a boolean")
    return value


def _require_object(value: object, name: str) -> dict[str, object]:
    if type(value) is not dict:
        _reject(f"{name} must be an object")
    return value


def _require_list(value: object, name: str) -> list[object]:
    if type(value) is not list:
        _reject(f"{name} must be a list")
    return value


def _require_sorted_unique_strings(
    value: object,
    name: str,
    *,
    nullable: bool = False,
) -> list[str] | None:
    if value is None and nullable:
        return None
    items = _require_list(value, name)
    result = [_require_text(item, name, allow_empty=True) for item in items]
    if result != sorted(set(result)):
        _reject(f"{name} must be sorted and duplicate-free")
    return result


def _sorted_string_list(value: object, name: str, *, nullable: bool = False) -> list[str] | None:
    if value is None and nullable:
        return None
    items = _require_list(value, name)
    result = [_require_text(item, name, allow_empty=True) for item in items]
    if len(result) != len(set(result)):
        _reject(f"{name} contains a duplicate")
    return sorted(result)


def _map_pairs(value: object, name: str, *, nullable: bool = False) -> list[list[str]] | None:
    if value is None and nullable:
        return None
    mapping = _require_object(value, name)
    pairs: list[list[str]] = []
    for key in sorted(mapping):
        pairs.append(
            [
                _require_text(key, f"{name}.key", allow_empty=True),
                _require_text(mapping[key], f"{name}.value", allow_empty=True),
            ]
        )
    return pairs


@dataclass(frozen=True, slots=True)
class DockerPlanIdentity:
    supervisor_container_id: str
    source_container_id: str
    project_network_id: str

    def __post_init__(self) -> None:
        _require_full_id(self.supervisor_container_id, "supervisor_container_id")
        _require_full_id(self.source_container_id, "source_container_id")
        _require_full_id(self.project_network_id, "project_network_id")
        if self.supervisor_container_id == self.source_container_id:
            _reject("the two admitted container IDs must be distinct")


@dataclass(frozen=True, slots=True, init=False)
class DockerCallSpec:
    ordinal: int
    exchange_kind: str
    target_kind: str
    target_identity: str
    method: str
    path: str
    ordered_query: tuple[tuple[str, str], ...]
    request_headers: tuple[tuple[str, str], ...]
    expected_status: int
    projection_kind: str
    body_ceiling: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker call specs require the closed ordinal plan")

    @classmethod
    def _capture(
        cls,
        *,
        ordinal: int,
        exchange_kind: str,
        target_kind: str,
        target_identity: str,
        method: str,
        path: str,
        ordered_query: tuple[tuple[str, str], ...],
        request_headers: tuple[tuple[str, str], ...],
        expected_status: int,
        projection_kind: str,
        body_ceiling: int,
        capability: object,
    ) -> Self:
        if capability is not _CALL_SPEC_CAPABILITY:
            _reject("Docker call spec capability is invalid")
        result = object.__new__(cls)
        for name, value in (
            ("ordinal", ordinal),
            ("exchange_kind", exchange_kind),
            ("target_kind", target_kind),
            ("target_identity", target_identity),
            ("method", method),
            ("path", path),
            ("ordered_query", ordered_query),
            ("request_headers", request_headers),
            ("expected_status", expected_status),
            ("projection_kind", projection_kind),
            ("body_ceiling", body_ceiling),
        ):
            object.__setattr__(result, name, value)
        result._validate()
        return result

    def _validate(self) -> None:
        _require_int(self.ordinal, "ordinal", maximum=17)
        _require_int(self.expected_status, "expected_status", minimum=100, maximum=599)
        _require_int(self.body_ceiling, "body_ceiling")
        if self.exchange_kind not in {"admission_read", "mutation", "post_inspect", "volume_proof"}:
            _reject("exchange kind is outside the closed set")
        if self.target_kind not in {"daemon", "container", "network", "volume"}:
            _reject("target kind is outside the closed set")
        if self.method not in {"GET", "POST", "DELETE"}:
            _reject("Docker method is outside the closed set")
        if self.request_headers != (_GET_HEADERS if self.method == "GET" else _MUTATION_HEADERS):
            _reject("Docker header profile is not exact")
        if self.expected_status not in {200, 204, 404}:
            _reject("Docker expected status is outside the closed set")

    @property
    def request_target(self) -> str:
        if not self.ordered_query:
            return self.path
        query = "&".join(f"{key}={value}" for key, value in self.ordered_query)
        return f"{self.path}?{query}"


def docker_call_spec(ordinal: int, identity: DockerPlanIdentity) -> DockerCallSpec:
    """Return the one literal ADR-0121 call assigned to an ordinal."""

    if type(identity) is not DockerPlanIdentity:
        _reject("Docker plan identity type is not exact")
    supervisor = identity.supervisor_container_id
    source = identity.source_container_id
    network = identity.project_network_id
    plans = (
        (
            "admission_read",
            "daemon",
            "docker-daemon",
            "GET",
            "/v1.45/info",
            (),
            200,
            "info",
            1_048_576,
        ),
        (
            "admission_read",
            "container",
            supervisor,
            "GET",
            f"/v1.45/containers/{supervisor}/json",
            (),
            200,
            "container_present",
            524_288,
        ),
        (
            "admission_read",
            "container",
            source,
            "GET",
            f"/v1.45/containers/{source}/json",
            (),
            200,
            "container_present",
            524_288,
        ),
        (
            "admission_read",
            "network",
            network,
            "GET",
            f"/v1.45/networks/{network}",
            (),
            200,
            "network_present",
            262_144,
        ),
        (
            "admission_read",
            "volume",
            COMMAND_SOCKET_VOLUME,
            "GET",
            f"/v1.45/volumes/{COMMAND_SOCKET_VOLUME}",
            (),
            200,
            "volume_present",
            131_072,
        ),
        (
            "admission_read",
            "volume",
            STATE_VOLUME,
            "GET",
            f"/v1.45/volumes/{STATE_VOLUME}",
            (),
            200,
            "volume_present",
            131_072,
        ),
        (
            "mutation",
            "container",
            supervisor,
            "POST",
            f"/v1.45/containers/{supervisor}/stop",
            (("t", "30"),),
            204,
            "mutation",
            0,
        ),
        (
            "post_inspect",
            "container",
            supervisor,
            "GET",
            f"/v1.45/containers/{supervisor}/json",
            (),
            200,
            "container_stopped",
            524_288,
        ),
        (
            "mutation",
            "container",
            source,
            "POST",
            f"/v1.45/containers/{source}/stop",
            (("t", "30"),),
            204,
            "mutation",
            0,
        ),
        (
            "post_inspect",
            "container",
            source,
            "GET",
            f"/v1.45/containers/{source}/json",
            (),
            200,
            "container_stopped",
            524_288,
        ),
        (
            "mutation",
            "container",
            supervisor,
            "DELETE",
            f"/v1.45/containers/{supervisor}",
            (("v", "false"), ("force", "false"), ("link", "false")),
            204,
            "mutation",
            0,
        ),
        (
            "post_inspect",
            "container",
            supervisor,
            "GET",
            f"/v1.45/containers/{supervisor}/json",
            (),
            404,
            "container_absent",
            4_096,
        ),
        (
            "mutation",
            "container",
            source,
            "DELETE",
            f"/v1.45/containers/{source}",
            (("v", "false"), ("force", "false"), ("link", "false")),
            204,
            "mutation",
            0,
        ),
        (
            "post_inspect",
            "container",
            source,
            "GET",
            f"/v1.45/containers/{source}/json",
            (),
            404,
            "container_absent",
            4_096,
        ),
        (
            "mutation",
            "network",
            network,
            "DELETE",
            f"/v1.45/networks/{network}",
            (),
            204,
            "mutation",
            0,
        ),
        (
            "post_inspect",
            "network",
            network,
            "GET",
            f"/v1.45/networks/{network}",
            (),
            404,
            "network_absent",
            4_096,
        ),
        (
            "volume_proof",
            "volume",
            COMMAND_SOCKET_VOLUME,
            "GET",
            f"/v1.45/volumes/{COMMAND_SOCKET_VOLUME}",
            (),
            200,
            "volume_present",
            131_072,
        ),
        (
            "volume_proof",
            "volume",
            STATE_VOLUME,
            "GET",
            f"/v1.45/volumes/{STATE_VOLUME}",
            (),
            200,
            "volume_present",
            131_072,
        ),
    )
    if type(ordinal) is not int or ordinal < 0 or ordinal >= len(plans):
        _reject("Docker connection ordinal is outside 0..17")
    (
        exchange_kind,
        target_kind,
        target_identity,
        method,
        path,
        query,
        expected_status,
        projection_kind,
        body_ceiling,
    ) = plans[ordinal]
    return DockerCallSpec._capture(
        ordinal=ordinal,
        exchange_kind=exchange_kind,
        target_kind=target_kind,
        target_identity=target_identity,
        method=method,
        path=path,
        ordered_query=query,
        request_headers=_GET_HEADERS if method == "GET" else _MUTATION_HEADERS,
        expected_status=expected_status,
        projection_kind=projection_kind,
        body_ceiling=body_ceiling,
        capability=_CALL_SPEC_CAPABILITY,
    )


_REQUEST_FIELDS = frozenset(
    {
        "api_version",
        "method",
        "path",
        "ordered_query",
        "request_headers",
        "body_presence",
        "body_length",
        "body_sha256",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class DockerRequestSemantic:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker request semantics require one closed call spec")

    @classmethod
    def from_spec(cls, spec: DockerCallSpec) -> Self:
        if type(spec) is not DockerCallSpec:
            _reject("Docker request spec type is not exact")
        result = object.__new__(cls)
        object.__setattr__(
            result,
            "fields",
            FrozenJsonObject.capture(
                {
                    "api_version": DOCKER_API_VERSION,
                    "method": spec.method,
                    "path": spec.path,
                    "ordered_query": [list(pair) for pair in spec.ordered_query],
                    "request_headers": [list(pair) for pair in spec.request_headers],
                    "body_presence": "absent",
                    "body_length": 0,
                    "body_sha256": EMPTY_BODY_SHA256,
                }
            ),
        )
        result._validate(spec)
        return result

    @classmethod
    def capture(cls, value: object, *, spec: DockerCallSpec) -> Self:
        result = object.__new__(cls)
        object.__setattr__(result, "fields", FrozenJsonObject.capture(value))
        result._validate(spec)
        return result

    def _validate(self, spec: DockerCallSpec) -> None:
        fields = self.to_dict()
        _require_fields(fields, _REQUEST_FIELDS, "Docker request semantic")
        if not _same_spec_fields(fields, spec):
            _reject("Docker request semantic is not the exact closed call")

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=16 * 1_024)

    @property
    def sha256(self) -> str:
        return _domain_sha256("autoquant.trusted-time.docker-request.v2", self.to_dict())

    def request_bytes(self, spec: DockerCallSpec) -> bytes:
        self._validate(spec)
        lines = [f"{spec.method} {spec.request_target} HTTP/1.1"]
        lines.extend(f"{name}: {value}" for name, value in spec.request_headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _same_spec_fields(fields: dict[str, object], spec: DockerCallSpec) -> bool:
    return fields == {
        "api_version": DOCKER_API_VERSION,
        "method": spec.method,
        "path": spec.path,
        "ordered_query": [list(pair) for pair in spec.ordered_query],
        "request_headers": [list(pair) for pair in spec.request_headers],
        "body_presence": "absent",
        "body_length": 0,
        "body_sha256": EMPTY_BODY_SHA256,
    }


def validate_docker_request_bytes(
    encoded: object,
    *,
    spec: DockerCallSpec,
) -> DockerRequestSemantic:
    semantic = DockerRequestSemantic.from_spec(spec)
    if type(encoded) is not bytes or encoded != semantic.request_bytes(spec):
        _reject("Docker HTTP request bytes are not literal and body-absent")
    return semantic


def _json_unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject("Docker JSON contains a duplicate key")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    try:
        value = int(text)
    except (ValueError, OverflowError):
        _reject("Docker JSON integer is malformed")
    if value < -(2**63) or value > MAXIMUM_SIGNED_INTEGER:
        _reject("Docker JSON integer exceeds signed 64-bit bounds")
    return value


def _reject_float(_: str) -> Never:
    _reject("Docker JSON floats are forbidden")


def _reject_constant(_: str) -> Never:
    _reject("Docker JSON non-finite values are forbidden")


def _bound_json_tree(value: object) -> None:
    nodes = 0

    def visit(node: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _JSON_NODE_LIMIT or depth > _JSON_DEPTH_LIMIT:
            _reject("Docker JSON tree exceeds its bounds")
        if node is None or type(node) in (bool, int):
            return
        if type(node) is str:
            _require_text(
                node,
                "Docker JSON string",
                maximum_bytes=_JSON_STRING_LIMIT,
                allow_empty=True,
            )
            return
        if type(node) is list:
            for item in node:
                visit(item, depth + 1)
            return
        if type(node) is dict:
            for key, item in node.items():
                _require_text(key, "Docker JSON key", allow_empty=True)
                visit(item, depth + 1)
            return
        _reject("Docker JSON contains an unsupported value")

    visit(value, 0)


def _decode_docker_json(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_json_unique_object,
            parse_int=_json_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except TrustedTimeDockerEvidenceRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise TrustedTimeDockerEvidenceRejected("Docker JSON is malformed") from error
    if type(value) is not dict:
        _reject("Docker JSON response must be one object")
    _bound_json_tree(value)
    return value


@dataclass(frozen=True, slots=True, init=False)
class DockerResponseEvidence:
    http_status: int
    response_framing_sha256: str
    response_body_sha256: str
    projection: FrozenJsonObject
    response_projection_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker response evidence requires bounded byte parsing")

    @classmethod
    def _capture(
        cls,
        *,
        http_status: int,
        framing: bytes,
        body: bytes,
        projection: dict[str, object],
        projection_domain: str,
        capability: object,
    ) -> Self:
        if capability is not _RESPONSE_CAPTURE_CAPABILITY:
            _reject("Docker response capture capability is invalid")
        result = object.__new__(cls)
        object.__setattr__(
            result,
            "http_status",
            _require_int(http_status, "http_status", minimum=100, maximum=599),
        )
        object.__setattr__(
            result,
            "response_framing_sha256",
            _sha256(
                b"AutoQuantTrader/trusted-time/graceful-stop/docker-response-framing/v2"
                + b"\0"
                + framing
            ),
        )
        object.__setattr__(result, "response_body_sha256", _sha256(body))
        object.__setattr__(result, "projection", FrozenJsonObject.capture(projection))
        object.__setattr__(
            result,
            "response_projection_sha256",
            _domain_sha256(projection_domain, projection),
        )
        return result


def _validate_header_octets(line: bytes) -> None:
    if len(line) > _HTTP_LINE_LIMIT or b"\0" in line:
        _reject("Docker HTTP header line exceeds its byte grammar")
    for value in line:
        if value == 9:
            continue
        if value < 32 or value == 127:
            _reject("Docker HTTP header contains a control byte")


def parse_docker_response(
    encoded: object,
    *,
    spec: DockerCallSpec,
    volume_host_identity: tuple[int, int] | None = None,
) -> DockerResponseEvidence:
    """Parse one complete close-delimited response under the exact endpoint schema."""

    if type(encoded) is not bytes:
        _reject("Docker response must be complete bytes")
    marker = encoded.find(b"\r\n\r\n")
    if marker < 0 or marker + 4 > _HTTP_HEADER_BLOCK_LIMIT:
        _reject("Docker response header block is absent or oversized")
    framing = encoded[: marker + 4]
    body = encoded[marker + 4 :]
    if b"\n" in framing.replace(b"\r\n", b""):
        _reject("Docker response header contains bare LF")
    lines = framing[:-4].split(b"\r\n")
    if not lines or len(lines) > _HTTP_HEADER_LINE_LIMIT:
        _reject("Docker response has an invalid line count")
    for line in lines:
        _validate_header_octets(line)
    status_parts = lines[0].split(b" ", 2)
    if len(status_parts) < 2 or status_parts[0] != b"HTTP/1.1":
        _reject("Docker response is not HTTP/1.1")
    if len(status_parts[1]) != 3 or not status_parts[1].isdigit():
        _reject("Docker response status code is malformed")
    status = int(status_parts[1])
    if 100 <= status < 200:
        _reject("Docker informational responses are forbidden")
    if len(status_parts) == 3 and (
        len(status_parts[2]) > 64 or any(value < 32 or value > 126 for value in status_parts[2])
    ):
        _reject("Docker reason phrase is not bounded visible ASCII")
    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        if raw_line.startswith((b" ", b"\t")) or b":" not in raw_line:
            _reject("Docker response has obs-fold or malformed header")
        raw_name, raw_value = raw_line.split(b":", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None:
            _reject("Docker response header name is invalid")
        name = raw_name.decode("ascii").lower()
        if name in headers:
            _reject("Docker response header name is duplicated")
        try:
            value = raw_value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as error:
            raise TrustedTimeDockerEvidenceRejected("Docker header value is not ASCII") from error
        headers[name] = value
    if any(
        name in headers for name in ("transfer-encoding", "upgrade", "content-encoding", "trailer")
    ):
        _reject("Docker response uses prohibited framing")
    if "connection" in headers and headers["connection"].lower() != "close":
        _reject("Docker response does not close its connection")
    if status != spec.expected_status:
        _reject("Docker response status is not the ordinal's exact status")
    if status == 204:
        if headers.get("content-length") not in {None, "0"}:
            _reject("Docker 204 Content-Length is not absent or zero")
        if headers.get("content-type") not in {None, "application/json"}:
            _reject("Docker 204 Content-Type is invalid")
        if body:
            _reject("Docker 204 response carries body bytes")
    else:
        length = headers.get("content-length")
        if length is None or _CANONICAL_DECIMAL.fullmatch(length) is None:
            _reject("Docker JSON response lacks canonical Content-Length")
        if int(length) > spec.body_ceiling or int(length) != len(body):
            _reject("Docker JSON body is truncated, surplus, or oversized")
        if headers.get("content-type") != "application/json":
            _reject("Docker JSON response Content-Type is not exact")
    projection, projection_domain = _project_response(
        spec,
        body,
        volume_host_identity=volume_host_identity,
    )
    return DockerResponseEvidence._capture(
        http_status=status,
        framing=framing,
        body=body,
        projection=projection,
        projection_domain=projection_domain,
        capability=_RESPONSE_CAPTURE_CAPABILITY,
    )


def _project_response(
    spec: DockerCallSpec,
    body: bytes,
    *,
    volume_host_identity: tuple[int, int] | None,
) -> tuple[dict[str, object], str]:
    if spec.projection_kind == "mutation":
        return (
            {"disposition": "accepted", "http_status": 204},
            "AutoQuantTrader/trusted-time/graceful-stop/docker-mutation-projection/v2",
        )
    if spec.projection_kind in {"container_absent", "network_absent"}:
        return _project_not_found(spec, body)
    raw = _decode_docker_json(body)
    if spec.projection_kind == "info":
        return (
            _project_info(raw),
            "AutoQuantTrader/trusted-time/graceful-stop/docker-info-projection/v2",
        )
    if spec.projection_kind in {"container_present", "container_stopped"}:
        projection = _project_container(raw, expected_id=spec.target_identity)
        if spec.projection_kind == "container_stopped":
            state = _require_object(projection["state"], "state")
            if (
                state["running"] is not False
                or state["paused"] is not False
                or state["restarting"] is not False
                or state["dead"] is not False
                or state["status"] != "exited"
            ):
                _reject("post-stop container projection is not exited")
        return (
            projection,
            "AutoQuantTrader/trusted-time/graceful-stop/docker-container-projection/v2",
        )
    if spec.projection_kind == "network_present":
        return (
            _project_network(raw, expected_id=spec.target_identity),
            "AutoQuantTrader/trusted-time/graceful-stop/docker-network-projection/v2",
        )
    if spec.projection_kind == "volume_present":
        if volume_host_identity is None:
            _reject("volume projection requires stable host mount identity")
        return (
            _project_volume(
                raw,
                expected_name=spec.target_identity,
                host_mount_device=volume_host_identity[0],
                host_mount_inode=volume_host_identity[1],
            ),
            "AutoQuantTrader/trusted-time/graceful-stop/docker-volume-projection/v2",
        )
    _reject("Docker response projection kind is unknown")


def _project_info(raw: dict[str, object]) -> dict[str, object]:
    mapping = {
        "daemon_id": "ID",
        "docker_root_dir": "DockerRootDir",
        "name": "Name",
        "server_version": "ServerVersion",
        "operating_system": "OperatingSystem",
        "os_type": "OSType",
        "architecture": "Architecture",
        "storage_driver": "Driver",
    }
    projection: dict[str, object] = {
        projected: _require_text(raw[source], source, allow_empty=True)
        for projected, source in mapping.items()
        if source in raw
    }
    if len(projection) != len(mapping):
        _reject("Docker info is missing a projected path")
    projection["security_options"] = _sorted_string_list(
        raw.get("SecurityOptions"), "SecurityOptions"
    )
    return projection


def _project_container(raw: dict[str, object], *, expected_id: str) -> dict[str, object]:
    container_id = _require_full_id(raw.get("Id"), "Id")
    image_id = _require_text(raw.get("Image"), "Image")
    if container_id != expected_id or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        _reject("container inspect identity disagrees")
    state_raw = _require_object(raw.get("State"), "State")
    state_names = {
        "status": ("Status", str),
        "running": ("Running", bool),
        "paused": ("Paused", bool),
        "restarting": ("Restarting", bool),
        "oom_killed": ("OOMKilled", bool),
        "dead": ("Dead", bool),
        "pid": ("Pid", int),
        "exit_code": ("ExitCode", int),
        "started_at": ("StartedAt", str),
        "finished_at": ("FinishedAt", str),
    }
    state: dict[str, object] = {}
    for projected, (source, expected_type) in state_names.items():
        if source not in state_raw or type(state_raw[source]) is not expected_type:
            _reject(f"container State.{source} has the wrong type")
        state[projected] = state_raw[source]
    _require_int(state["pid"], "State.Pid")
    _require_int(state["exit_code"], "State.ExitCode")
    config_raw = _require_object(raw.get("Config"), "Config")
    for required in ("Image", "User", "Labels"):
        if required not in config_raw:
            _reject(f"container Config.{required} is missing")
    stop_signal_raw = config_raw.get("StopSignal")
    stop_signal = (
        None
        if stop_signal_raw is None or stop_signal_raw == ""
        else _require_text(stop_signal_raw, "Config.StopSignal")
    )
    labels = _map_pairs(config_raw["Labels"], "Config.Labels", nullable=True)
    config = {
        "image": _require_text(config_raw["Image"], "Config.Image"),
        "stop_signal": stop_signal,
        "user": _require_text(config_raw["User"], "Config.User", allow_empty=True),
        "labels_sha256": _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-container-projection/v2/labels",
            labels,
        ),
    }
    host_raw = _require_object(raw.get("HostConfig"), "HostConfig")
    required_host = (
        "NetworkMode",
        "ReadonlyRootfs",
        "Privileged",
        "NanoCpus",
        "Memory",
    )
    if any(name not in host_raw for name in required_host):
        _reject("container HostConfig is missing a projected path")
    host_config = {
        "network_mode": _require_text(host_raw["NetworkMode"], "HostConfig.NetworkMode"),
        "readonly_rootfs": _require_bool(host_raw["ReadonlyRootfs"], "HostConfig.ReadonlyRootfs"),
        "privileged": _require_bool(host_raw["Privileged"], "HostConfig.Privileged"),
        "cap_add": _sorted_string_list(host_raw.get("CapAdd"), "HostConfig.CapAdd", nullable=True),
        "cap_drop": _sorted_string_list(
            host_raw.get("CapDrop"), "HostConfig.CapDrop", nullable=True
        ),
        "security_opt": _sorted_string_list(
            host_raw.get("SecurityOpt"), "HostConfig.SecurityOpt", nullable=True
        ),
        "pids_limit": (
            None
            if host_raw.get("PidsLimit") is None
            else _require_int(host_raw["PidsLimit"], "HostConfig.PidsLimit")
        ),
        "nano_cpus": _require_int(host_raw["NanoCpus"], "HostConfig.NanoCpus"),
        "memory": _require_int(host_raw["Memory"], "HostConfig.Memory"),
    }
    mounts_raw = _require_list(raw.get("Mounts"), "Mounts")
    mounts: list[dict[str, object]] = []
    mount_map = {
        "type": "Type",
        "name": "Name",
        "source": "Source",
        "destination": "Destination",
        "driver": "Driver",
        "mode": "Mode",
        "rw": "RW",
        "propagation": "Propagation",
    }
    for raw_mount_value in mounts_raw:
        raw_mount = _require_object(raw_mount_value, "Mounts entry")
        if any(name not in raw_mount for name in mount_map.values()):
            _reject("container mount is missing a projected path")
        mount: dict[str, object] = {}
        for projected, source in mount_map.items():
            if projected == "rw":
                mount[projected] = _require_bool(raw_mount[source], f"Mounts.{source}")
            else:
                mount[projected] = _require_text(
                    raw_mount[source], f"Mounts.{source}", allow_empty=True
                )
        mounts.append(mount)
    mounts.sort(key=lambda item: canonical_v2_json_bytes(item, maximum_bytes=16 * 1_024))
    network_settings = _require_object(raw.get("NetworkSettings"), "NetworkSettings")
    networks_raw = _require_object(network_settings.get("Networks"), "NetworkSettings.Networks")
    networks: list[dict[str, object]] = []
    network_map = {
        "network_id": "NetworkID",
        "endpoint_id": "EndpointID",
        "gateway": "Gateway",
        "ip_address": "IPAddress",
        "global_ipv6_address": "GlobalIPv6Address",
        "mac_address": "MacAddress",
    }
    for name in sorted(networks_raw):
        raw_network = _require_object(networks_raw[name], f"Networks.{name}")
        if any(field not in raw_network for field in network_map.values()):
            _reject("container network attachment is missing a projected path")
        networks.append(
            {
                "name": _require_text(name, "network name"),
                **{
                    projected: _require_text(
                        raw_network[source], f"Networks.{name}.{source}", allow_empty=True
                    )
                    for projected, source in network_map.items()
                },
            }
        )
    return {
        "container_id": container_id,
        "image_id": image_id,
        "name": _require_text(raw.get("Name"), "Name"),
        "state": state,
        "config": config,
        "host_config": host_config,
        "mounts": mounts,
        "networks": networks,
    }


def _project_network(raw: dict[str, object], *, expected_id: str) -> dict[str, object]:
    network_id = _require_full_id(raw.get("Id"), "Id")
    if network_id != expected_id:
        _reject("network inspect identity disagrees")
    ipam_raw = _require_object(raw.get("IPAM"), "IPAM")
    for name in ("Driver", "Options", "Config"):
        if name not in ipam_raw:
            _reject(f"network IPAM.{name} is missing")
    config_raw = _require_list(ipam_raw["Config"], "IPAM.Config")
    ipam_config: list[dict[str, object]] = []
    for raw_entry_value in config_raw:
        raw_entry = _require_object(raw_entry_value, "IPAM.Config entry")
        required = ("Subnet", "IPRange", "Gateway", "AuxiliaryAddresses")
        if any(name not in raw_entry for name in required):
            _reject("network IPAM config entry is not exact")
        ipam_config.append(
            {
                "subnet": _nullable_text(raw_entry["Subnet"], "IPAM.Config.Subnet"),
                "ip_range": _nullable_text(raw_entry["IPRange"], "IPAM.Config.IPRange"),
                "gateway": _nullable_text(raw_entry["Gateway"], "IPAM.Config.Gateway"),
                "auxiliary_addresses": _map_pairs(
                    raw_entry["AuxiliaryAddresses"],
                    "IPAM.Config.AuxiliaryAddresses",
                    nullable=True,
                ),
            }
        )
    ipam = {
        "driver": _require_text(ipam_raw["Driver"], "IPAM.Driver"),
        "options": _map_pairs(ipam_raw["Options"], "IPAM.Options", nullable=True),
        "config": ipam_config,
    }
    containers_raw = _require_object(raw.get("Containers"), "Containers")
    container_ids = sorted(_require_full_id(key, "Containers key") for key in containers_raw)
    required_names = (
        "Name",
        "Created",
        "Scope",
        "Driver",
        "EnableIPv6",
        "Internal",
        "Attachable",
        "Ingress",
        "Options",
        "Labels",
    )
    if any(name not in raw for name in required_names):
        _reject("network inspect is missing a projected path")
    return {
        "network_id": network_id,
        "name": _require_text(raw["Name"], "Name"),
        "created": _require_text(raw["Created"], "Created"),
        "scope": _require_text(raw["Scope"], "Scope"),
        "driver": _require_text(raw["Driver"], "Driver"),
        "enable_ipv6": _require_bool(raw["EnableIPv6"], "EnableIPv6"),
        "internal": _require_bool(raw["Internal"], "Internal"),
        "attachable": _require_bool(raw["Attachable"], "Attachable"),
        "ingress": _require_bool(raw["Ingress"], "Ingress"),
        "ipam_sha256": _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-network-ipam-projection/v2",
            ipam,
        ),
        "options_sha256": _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-network-projection/v2/options",
            _map_pairs(raw["Options"], "Options", nullable=True),
        ),
        "labels_sha256": _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-network-projection/v2/labels",
            _map_pairs(raw["Labels"], "Labels", nullable=True),
        ),
        "container_ids": container_ids,
    }


def _nullable_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, name, allow_empty=True)


def _project_volume(
    raw: dict[str, object],
    *,
    expected_name: str,
    host_mount_device: int,
    host_mount_inode: int,
) -> dict[str, object]:
    for name in ("Name", "Driver", "Mountpoint", "Labels", "Scope"):
        if name not in raw:
            _reject(f"volume inspect {name} is missing")
    name = _require_text(raw["Name"], "Name")
    if name != expected_name:
        _reject("volume inspect identity disagrees")
    _require_int(host_mount_device, "host_mount_device", minimum=1)
    _require_int(host_mount_inode, "host_mount_inode", minimum=1)
    return {
        "name": name,
        "driver": _require_text(raw["Driver"], "Driver"),
        "mountpoint": _require_text(raw["Mountpoint"], "Mountpoint"),
        "created_at": _nullable_text(raw.get("CreatedAt"), "CreatedAt"),
        "status_sha256": (
            None
            if raw.get("Status") is None
            else _domain_sha256(
                "AutoQuantTrader/trusted-time/graceful-stop/docker-volume-projection/v2/status",
                _map_pairs(raw["Status"], "Status"),
            )
        ),
        "labels_sha256": _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-volume-projection/v2/labels",
            _map_pairs(raw["Labels"], "Labels", nullable=True),
        ),
        "scope": _require_text(raw["Scope"], "Scope"),
        "options_sha256": (
            None
            if raw.get("Options") is None
            else _domain_sha256(
                "AutoQuantTrader/trusted-time/graceful-stop/docker-volume-projection/v2/options",
                _map_pairs(raw["Options"], "Options"),
            )
        ),
        "host_mount_device": host_mount_device,
        "host_mount_inode": host_mount_inode,
    }


def _project_not_found(
    spec: DockerCallSpec,
    body: bytes,
) -> tuple[dict[str, object], str]:
    expected_message = (
        f"No such container: {spec.target_identity}"
        if spec.target_kind == "container"
        else f"network {spec.target_identity} not found"
    )
    expected = json.dumps(
        {"message": expected_message},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if body not in {expected, expected + b"\n"}:
        _reject("Docker 404 body is not the exact compact object")
    raw = _decode_docker_json(body.rstrip(b"\n"))
    _require_fields(raw, frozenset({"message"}), "Docker 404")
    return (
        {
            "entity_kind": spec.target_kind,
            "entity_id": spec.target_identity,
            "http_status": 404,
            "message": expected_message,
        },
        "AutoQuantTrader/trusted-time/graceful-stop/docker-not-found-projection/v2",
    )


_CONNECTION_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "channel_id",
        "api_version",
        "connection_ordinal",
        "docker_socket_path",
        "socket_mount_id",
        "socket_mount_parent_id",
        "socket_mount_major_minor",
        "socket_mount_root",
        "socket_mount_point",
        "socket_mount_filesystem_type",
        "socket_mount_source",
        "socket_mount_options",
        "socket_mount_super_options",
        "socket_path_device",
        "socket_path_inode",
        "socket_path_uid",
        "socket_path_gid",
        "socket_path_mode",
        "peer_uid",
        "peer_gid",
        "peer_pid",
        "daemon_start_time_ticks",
        "daemon_proc_device",
        "daemon_proc_inode",
        "daemon_pid_namespace_inode",
        "daemon_executable_device",
        "daemon_executable_inode",
        "daemon_executable_size",
        "daemon_executable_uid",
        "daemon_executable_gid",
        "daemon_executable_mode",
        "daemon_executable_nlink",
        "daemon_executable_sha256",
        "daemon_cgroup_sha256",
        "local_socket_device",
        "local_socket_inode",
        "local_socket_cookie",
        "admitted_daemon_info_projection_sha256",
        "path_preconnect_validated_boottime_ns",
        "opened_boottime_ns",
        "pre_request_revalidated_boottime_ns",
        "response_headers_revalidated_boottime_ns",
        "response_complete_revalidated_boottime_ns",
        "call_deadline_boottime_ns",
    }
)

_POSIX_FILE_TYPE_MASK = 0o170000
_POSIX_REGULAR_FILE = 0o100000
_POSIX_SOCKET = 0o140000
_POSIX_GROUP_OR_WORLD_WRITE = 0o022
_MAXIMUM_DAEMON_EXECUTABLE_BYTES = 268_435_456
_MOUNT_MAJOR_MINOR = re.compile(r"(?:0|[1-9][0-9]{0,9}):(?:0|[1-9][0-9]{0,9})\Z")

_IMMUTABLE_DAEMON_SOCKET_CORE_FIELDS = (
    "docker_socket_path",
    "socket_mount_id",
    "socket_mount_parent_id",
    "socket_mount_major_minor",
    "socket_mount_root",
    "socket_mount_point",
    "socket_mount_filesystem_type",
    "socket_mount_source",
    "socket_mount_options",
    "socket_mount_super_options",
    "socket_path_device",
    "socket_path_inode",
    "socket_path_uid",
    "socket_path_gid",
    "socket_path_mode",
    "peer_uid",
    "peer_gid",
    "peer_pid",
    "daemon_start_time_ticks",
    "daemon_proc_device",
    "daemon_proc_inode",
    "daemon_pid_namespace_inode",
    "daemon_executable_device",
    "daemon_executable_inode",
    "daemon_executable_size",
    "daemon_executable_uid",
    "daemon_executable_gid",
    "daemon_executable_mode",
    "daemon_executable_nlink",
    "daemon_executable_sha256",
    "daemon_cgroup_sha256",
)

_LOCAL_SOCKET_IDENTITY_FIELDS = (
    "local_socket_device",
    "local_socket_inode",
    "local_socket_cookie",
)


def _daemon_socket_core(fields: dict[str, object]) -> tuple[object, ...]:
    return tuple(fields[name] for name in _IMMUTABLE_DAEMON_SOCKET_CORE_FIELDS)


def _local_socket_identity(fields: dict[str, object]) -> tuple[int, int, int]:
    return cast(
        tuple[int, int, int], tuple(fields[name] for name in _LOCAL_SOCKET_IDENTITY_FIELDS)
    )


def _connection_started(fields: dict[str, object]) -> int:
    return _require_int(
        fields["path_preconnect_validated_boottime_ns"],
        "path_preconnect_validated_boottime_ns",
    )


def _connection_completed(fields: dict[str, object]) -> int:
    return _require_int(
        fields["response_complete_revalidated_boottime_ns"],
        "response_complete_revalidated_boottime_ns",
    )


@dataclass(frozen=True, slots=True, init=False)
class DockerConnectionIdentity:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker connection identities require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _CONNECTION_FIELDS, "Docker connection identity")
        peer_uid = _require_int(fields["peer_uid"], "peer_uid", maximum=2**32 - 2)
        peer_gid = _require_int(fields["peer_gid"], "peer_gid", maximum=2**32 - 2)
        socket_uid = _require_int(
            fields["socket_path_uid"], "socket_path_uid", maximum=2**32 - 2
        )
        socket_gid = _require_int(
            fields["socket_path_gid"], "socket_path_gid", maximum=2**32 - 2
        )
        executable_uid = _require_int(
            fields["daemon_executable_uid"],
            "daemon_executable_uid",
            maximum=2**32 - 2,
        )
        executable_gid = _require_int(
            fields["daemon_executable_gid"],
            "daemon_executable_gid",
            maximum=2**32 - 2,
        )
        if (
            fields["contract_version"]
            != "phase6d-trusted-time-graceful-stop-docker-connection-identity-v2"
            or fields["service"] != DOCKER_SERVICE
            or fields["status"] != "docker_connection_bound"
            or fields["api_version"] != DOCKER_API_VERSION
            or fields["docker_socket_path"] != DOCKER_SOCKET_PATH
            or peer_uid != 0
            or peer_gid != 0
            or socket_uid != 0
            or socket_gid != 0
            or executable_uid != 0
            or executable_gid != 0
        ):
            _reject("Docker connection discriminator or root-owned identity is invalid")
        ordinal = _require_int(fields["connection_ordinal"], "connection_ordinal", maximum=17)
        for name in ("environment", "graceful_stop_operation_id"):
            _require_ascii(fields[name], name)
        _require_sha256(fields["channel_id"], "channel_id")
        for name in ("daemon_executable_sha256", "daemon_cgroup_sha256"):
            _require_sha256(fields[name], name)
        admitted = fields["admitted_daemon_info_projection_sha256"]
        if ordinal == 0:
            if admitted is not None:
                _reject("ordinal-zero connection cannot pre-admit daemon info")
        else:
            _require_sha256(admitted, "admitted_daemon_info_projection_sha256")
        for name in ("socket_mount_options", "socket_mount_super_options"):
            options = _require_sorted_unique_strings(fields[name], name)
            if options is None or len(options) > 128:
                _reject(f"{name} exceeds its item bound")
            for option in options:
                _require_ascii(option, name, maximum_bytes=255, allow_empty=True)
        major_minor = _require_ascii(
            fields["socket_mount_major_minor"],
            "socket_mount_major_minor",
            maximum_bytes=21,
        )
        if _MOUNT_MAJOR_MINOR.fullmatch(major_minor) is None:
            _reject("socket_mount_major_minor is not canonical")
        for name in ("socket_mount_root", "socket_mount_point"):
            path = _require_ascii(fields[name], name, maximum_bytes=4_096)
            if (
                not path.startswith("/")
                or "//" in path
                or "/./" in path
                or "/../" in path
                or path.endswith("/.")
                or path.endswith("/..")
            ):
                _reject(f"{name} is not a stable absolute path")
        for name in ("socket_mount_filesystem_type", "socket_mount_source"):
            _require_ascii(fields[name], name, maximum_bytes=255)
        positive_names = (
            "socket_mount_id",
            "socket_mount_parent_id",
            "socket_path_device",
            "socket_path_inode",
            "peer_pid",
            "daemon_start_time_ticks",
            "daemon_proc_device",
            "daemon_proc_inode",
            "daemon_pid_namespace_inode",
            "daemon_executable_device",
            "daemon_executable_inode",
            "daemon_executable_size",
            "daemon_executable_nlink",
            "local_socket_device",
            "local_socket_inode",
            "local_socket_cookie",
        )
        for name in positive_names:
            _require_int(fields[name], name, minimum=1)
        socket_mode = _require_int(
            fields["socket_path_mode"], "socket_path_mode", maximum=0o177777
        )
        executable_mode = _require_int(
            fields["daemon_executable_mode"],
            "daemon_executable_mode",
            minimum=1,
            maximum=0o177777,
        )
        executable_size = _require_int(
            fields["daemon_executable_size"],
            "daemon_executable_size",
            minimum=1,
            maximum=_MAXIMUM_DAEMON_EXECUTABLE_BYTES,
        )
        if socket_mode & _POSIX_FILE_TYPE_MASK != _POSIX_SOCKET:
            _reject("Docker socket path is not a socket")
        if (
            executable_mode & _POSIX_FILE_TYPE_MASK != _POSIX_REGULAR_FILE
            or executable_mode & _POSIX_GROUP_OR_WORLD_WRITE
            or executable_size > _MAXIMUM_DAEMON_EXECUTABLE_BYTES
        ):
            _reject("Docker daemon executable identity is unsafe")
        times = [
            _require_int(fields[name], name)
            for name in (
                "path_preconnect_validated_boottime_ns",
                "opened_boottime_ns",
                "pre_request_revalidated_boottime_ns",
                "response_headers_revalidated_boottime_ns",
                "response_complete_revalidated_boottime_ns",
            )
        ]
        deadline = _require_int(fields["call_deadline_boottime_ns"], "call_deadline_boottime_ns")
        if times != sorted(times) or times[-1] >= deadline:
            _reject("Docker connection checkpoints are out of order or expired")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-connection-identity/v2",
            self.to_dict(),
        )

    @property
    def ordinal(self) -> int:
        return _require_int(self.to_dict()["connection_ordinal"], "connection_ordinal", maximum=17)


def _require_connection_sequence(
    connections: tuple[DockerConnectionIdentity, ...] | list[DockerConnectionIdentity],
    *,
    environment: str,
    graceful_stop_operation_id: str,
    channel_id: str,
    expected_core: tuple[object, ...] | None = None,
    previous_completed_boottime_ns: int | None = None,
    prior_connection_sha256s: frozenset[str] = frozenset(),
    prior_local_socket_identities: frozenset[tuple[int, int, int]] = frozenset(),
) -> tuple[tuple[object, ...], int]:
    if not connections:
        _reject("Docker connection sequence cannot be empty")
    exact_environment = _require_ascii(environment, "environment")
    exact_operation = _require_ascii(
        graceful_stop_operation_id, "graceful_stop_operation_id"
    )
    exact_channel = _require_sha256(channel_id, "channel_id")
    core = expected_core
    previous_completed = previous_completed_boottime_ns
    seen_sha256s = set(prior_connection_sha256s)
    seen_local = set(prior_local_socket_identities)
    for connection in connections:
        if type(connection) is not DockerConnectionIdentity:
            _reject("Docker connection sequence contains an inexact value")
        fields = connection.to_dict()
        candidate_core = _daemon_socket_core(fields)
        if core is None:
            core = candidate_core
        if (
            candidate_core != core
            or fields["environment"] != exact_environment
            or fields["graceful_stop_operation_id"] != exact_operation
            or fields["channel_id"] != exact_channel
        ):
            _reject("Docker connection crossed daemon, socket, or lifecycle context")
        local_identity = _local_socket_identity(fields)
        if connection.sha256 in seen_sha256s or local_identity in seen_local:
            _reject("Docker connection identity was reused")
        started = _connection_started(fields)
        completed = _connection_completed(fields)
        if previous_completed is not None and started < previous_completed:
            _reject("Docker connections overlap or move backward in time")
        seen_sha256s.add(connection.sha256)
        seen_local.add(local_identity)
        previous_completed = completed
    if core is None or previous_completed is None:
        _reject("Docker connection sequence was not established")
    return core, previous_completed


_TRACE_FIELDS = frozenset(
    {
        "trace_ordinal",
        "request_semantic_sha256",
        "http_status",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "connection_identity_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "previous_trace_entry_sha256",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class DockerTraceEntry:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker trace entries require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _TRACE_FIELDS, "Docker trace entry")
        ordinal = _require_int(fields["trace_ordinal"], "trace_ordinal", maximum=17)
        for name in (
            "request_semantic_sha256",
            "response_framing_sha256",
            "response_body_sha256",
            "response_projection_sha256",
            "connection_identity_sha256",
        ):
            _require_sha256(fields[name], name)
        predecessor = fields["previous_trace_entry_sha256"]
        if ordinal == 0:
            if predecessor is not None:
                _reject("ordinal-zero trace predecessor must be null")
        else:
            _require_sha256(predecessor, "previous_trace_entry_sha256")
        _require_int(fields["http_status"], "http_status", minimum=100, maximum=599)
        started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(fields["call_completed_boottime_ns"], "call_completed_boottime_ns")
        if completed < started:
            _reject("Docker trace completion precedes its start")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256("autoquant.trusted-time.docker-trace-entry.v2", self.to_dict())

    @property
    def ordinal(self) -> int:
        return _require_int(self.to_dict()["trace_ordinal"], "trace_ordinal", maximum=17)


_EXCHANGE_FIELDS = frozenset(
    {
        "exchange_kind",
        "target_kind",
        "target_identity",
        "request_semantic_sha256",
        "connection_identity_sha256",
        "http_status",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "trace_entry_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class DockerHttpExchange:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker HTTP exchanges require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _EXCHANGE_FIELDS, "Docker HTTP exchange")
        if fields["exchange_kind"] not in {
            "admission_read",
            "mutation",
            "post_inspect",
            "volume_proof",
        } or fields["target_kind"] not in {"daemon", "container", "network", "volume"}:
            _reject("Docker exchange discriminator is invalid")
        _require_ascii(fields["target_identity"], "target_identity", maximum_bytes=255)
        for name in (
            "request_semantic_sha256",
            "connection_identity_sha256",
            "response_framing_sha256",
            "response_body_sha256",
            "response_projection_sha256",
            "trace_entry_sha256",
        ):
            _require_sha256(fields[name], name)
        _require_int(fields["http_status"], "http_status", minimum=100, maximum=599)
        started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(fields["call_completed_boottime_ns"], "call_completed_boottime_ns")
        if completed < started:
            _reject("Docker exchange completion precedes its start")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-http-exchange/v2",
            self.to_dict(),
        )


@dataclass(frozen=True, slots=True, init=False)
class DockerOrdinalEvidence:
    """One typed, internally correlated member of the global ordinal chain."""

    spec: DockerCallSpec
    request: DockerRequestSemantic
    connection: DockerConnectionIdentity
    response: DockerResponseEvidence
    trace: DockerTraceEntry
    exchange: DockerHttpExchange

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker ordinal evidence requires correlated construction")

    @classmethod
    def construct(
        cls,
        *,
        spec: DockerCallSpec,
        request: DockerRequestSemantic,
        connection: DockerConnectionIdentity,
        response: DockerResponseEvidence,
        previous_trace_entry_sha256: str | None,
    ) -> Self:
        if (
            type(spec) is not DockerCallSpec
            or type(request) is not DockerRequestSemantic
            or type(connection) is not DockerConnectionIdentity
            or type(response) is not DockerResponseEvidence
        ):
            _reject("Docker ordinal evidence inputs are not exact types")
        request._validate(spec)
        connection_fields = connection.to_dict()
        if connection.ordinal != spec.ordinal:
            _reject("Docker connection ordinal disagrees with the plan")
        started = _require_int(
            connection_fields["path_preconnect_validated_boottime_ns"],
            "path_preconnect_validated_boottime_ns",
        )
        completed = _require_int(
            connection_fields["response_complete_revalidated_boottime_ns"],
            "response_complete_revalidated_boottime_ns",
        )
        trace = DockerTraceEntry.capture(
            {
                "trace_ordinal": spec.ordinal,
                "request_semantic_sha256": request.sha256,
                "http_status": response.http_status,
                "response_framing_sha256": response.response_framing_sha256,
                "response_body_sha256": response.response_body_sha256,
                "response_projection_sha256": response.response_projection_sha256,
                "connection_identity_sha256": connection.sha256,
                "call_started_boottime_ns": started,
                "call_completed_boottime_ns": completed,
                "previous_trace_entry_sha256": previous_trace_entry_sha256,
            }
        )
        exchange = DockerHttpExchange.capture(
            {
                "exchange_kind": spec.exchange_kind,
                "target_kind": spec.target_kind,
                "target_identity": spec.target_identity,
                "request_semantic_sha256": request.sha256,
                "connection_identity_sha256": connection.sha256,
                "http_status": response.http_status,
                "response_framing_sha256": response.response_framing_sha256,
                "response_body_sha256": response.response_body_sha256,
                "response_projection_sha256": response.response_projection_sha256,
                "trace_entry_sha256": trace.sha256,
                "call_started_boottime_ns": started,
                "call_completed_boottime_ns": completed,
            }
        )
        result = object.__new__(cls)
        for name, item in (
            ("spec", spec),
            ("request", request),
            ("connection", connection),
            ("response", response),
            ("trace", trace),
            ("exchange", exchange),
        ):
            object.__setattr__(result, name, item)
        result._validate()
        return result

    def _validate(self) -> None:
        self.request._validate(self.spec)
        if self.trace.ordinal != self.spec.ordinal or self.connection.ordinal != self.spec.ordinal:
            _reject("Docker ordinal evidence objects disagree")
        trace = self.trace.to_dict()
        exchange = self.exchange.to_dict()
        expected = {
            "request_semantic_sha256": self.request.sha256,
            "connection_identity_sha256": self.connection.sha256,
            "http_status": self.response.http_status,
            "response_framing_sha256": self.response.response_framing_sha256,
            "response_body_sha256": self.response.response_body_sha256,
            "response_projection_sha256": self.response.response_projection_sha256,
        }
        if any(trace[name] != value or exchange[name] != value for name, value in expected.items()):
            _reject("Docker trace/exchange correlators disagree")
        if (
            exchange["trace_entry_sha256"] != self.trace.sha256
            or exchange["exchange_kind"] != self.spec.exchange_kind
            or exchange["target_kind"] != self.spec.target_kind
            or exchange["target_identity"] != self.spec.target_identity
            or self.response.http_status != self.spec.expected_status
        ):
            _reject("Docker exchange does not bind its trace entry")


def validate_complete_docker_trace(entries: object) -> tuple[DockerOrdinalEvidence, ...]:
    if type(entries) not in {list, tuple}:
        _reject("Docker evidence must be a concrete sequence")
    sequence = cast(list[object] | tuple[object, ...], entries)
    if len(sequence) != 18:
        _reject("Docker evidence must contain every ordinal 0..17")
    typed = tuple(cast(DockerOrdinalEvidence, candidate) for candidate in sequence)
    if any(type(candidate) is not DockerOrdinalEvidence for candidate in typed):
        _reject("Docker evidence contains an inexact ordinal value")
    plan_identity = DockerPlanIdentity(
        typed[1].spec.target_identity,
        typed[2].spec.target_identity,
        typed[3].spec.target_identity,
    )
    first_connection_fields = typed[0].connection.to_dict()
    environment = _require_ascii(first_connection_fields["environment"], "environment")
    operation = _require_ascii(
        first_connection_fields["graceful_stop_operation_id"],
        "graceful_stop_operation_id",
    )
    channel = _require_sha256(first_connection_fields["channel_id"], "channel_id")
    _require_connection_sequence(
        [entry.connection for entry in typed],
        environment=environment,
        graceful_stop_operation_id=operation,
        channel_id=channel,
    )
    result: list[DockerOrdinalEvidence] = []
    previous: str | None = None
    daemon_projection: str | None = None
    for ordinal, entry in enumerate(typed):
        expected_spec = docker_call_spec(ordinal, plan_identity)
        if entry.spec != expected_spec:
            _reject("Docker evidence is reordered or has an ordinal gap")
        entry._validate()
        trace_fields = entry.trace.to_dict()
        if trace_fields["previous_trace_entry_sha256"] != previous:
            _reject("Docker trace predecessor chain is broken")
        connection_fields = entry.connection.to_dict()
        admitted = connection_fields["admitted_daemon_info_projection_sha256"]
        if ordinal == 0:
            daemon_projection = entry.response.response_projection_sha256
            if admitted is not None:
                _reject("ordinal zero unexpectedly pre-admits daemon info")
        elif admitted != daemon_projection:
            _reject("Docker connection changes its admitted daemon projection")
        previous = entry.trace.sha256
        result.append(entry)
    return tuple(result)


_ADMISSION_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "channel_id",
        "first_connection_ordinal",
        "last_connection_ordinal",
        "ordered_request_semantic_sha256_list",
        "ordered_connection_identity_list",
        "ordered_connection_identity_sha256_list",
        "ordered_http_exchange_list",
        "ordered_http_exchange_sha256_list",
        "ordered_trace_entry_list",
        "ordered_trace_entry_sha256_list",
        "daemon_info_projection_sha256",
        "supervisor_container_projection_sha256",
        "source_container_projection_sha256",
        "project_network_projection_sha256",
        "command_socket_volume_projection_sha256",
        "state_volume_projection_sha256",
        "capture_started_boottime_ns",
        "capture_completed_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class DockerAdmissionCapture:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker admission captures require the exact six-read prefix")

    @classmethod
    def from_prefix(
        cls,
        *,
        environment: str,
        graceful_stop_operation_id: str,
        channel_id: str,
        entries: tuple[DockerOrdinalEvidence, ...],
    ) -> Self:
        if len(entries) != 6 or any(
            entry.spec.ordinal != index for index, entry in enumerate(entries)
        ):
            _reject("Docker admission capture must be ordinals 0..5")
        previous: str | None = None
        daemon_projection = entries[0].response.response_projection_sha256
        for index, entry in enumerate(entries):
            if entry.trace.to_dict()["previous_trace_entry_sha256"] != previous:
                _reject("Docker admission trace prefix is not gap-free")
            admitted = entry.connection.to_dict()["admitted_daemon_info_projection_sha256"]
            if (index == 0 and admitted is not None) or (
                index > 0 and admitted != daemon_projection
            ):
                _reject("Docker admission daemon identity is inconsistent")
            previous = entry.trace.sha256
        value = {
            "contract_version": "phase6d-trusted-time-graceful-stop-docker-admission-capture-v2",
            "service": DOCKER_SERVICE,
            "status": "docker_admission_captured",
            "environment": environment,
            "graceful_stop_operation_id": graceful_stop_operation_id,
            "channel_id": channel_id,
            "first_connection_ordinal": 0,
            "last_connection_ordinal": 5,
            "ordered_request_semantic_sha256_list": [entry.request.sha256 for entry in entries],
            "ordered_connection_identity_list": [entry.connection.to_dict() for entry in entries],
            "ordered_connection_identity_sha256_list": [
                entry.connection.sha256 for entry in entries
            ],
            "ordered_http_exchange_list": [entry.exchange.to_dict() for entry in entries],
            "ordered_http_exchange_sha256_list": [entry.exchange.sha256 for entry in entries],
            "ordered_trace_entry_list": [entry.trace.to_dict() for entry in entries],
            "ordered_trace_entry_sha256_list": [entry.trace.sha256 for entry in entries],
            "daemon_info_projection_sha256": entries[0].response.response_projection_sha256,
            "supervisor_container_projection_sha256": entries[
                1
            ].response.response_projection_sha256,
            "source_container_projection_sha256": entries[2].response.response_projection_sha256,
            "project_network_projection_sha256": entries[3].response.response_projection_sha256,
            "command_socket_volume_projection_sha256": entries[
                4
            ].response.response_projection_sha256,
            "state_volume_projection_sha256": entries[5].response.response_projection_sha256,
            "capture_started_boottime_ns": entries[0].exchange.to_dict()[
                "call_started_boottime_ns"
            ],
            "capture_completed_boottime_ns": entries[5].exchange.to_dict()[
                "call_completed_boottime_ns"
            ],
        }
        return cls.capture(value)

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _ADMISSION_FIELDS, "Docker admission capture")
        first_ordinal = _require_int(
            fields["first_connection_ordinal"], "first_connection_ordinal", maximum=17
        )
        last_ordinal = _require_int(
            fields["last_connection_ordinal"], "last_connection_ordinal", maximum=17
        )
        if (
            fields["contract_version"]
            != "phase6d-trusted-time-graceful-stop-docker-admission-capture-v2"
            or fields["service"] != DOCKER_SERVICE
            or fields["status"] != "docker_admission_captured"
            or first_ordinal != 0
            or last_ordinal != 5
        ):
            _reject("Docker admission capture discriminator is invalid")
        environment = _require_ascii(fields["environment"], "environment")
        operation = _require_ascii(
            fields["graceful_stop_operation_id"], "graceful_stop_operation_id"
        )
        channel = _require_sha256(fields["channel_id"], "channel_id")
        requests = _digest_list(fields["ordered_request_semantic_sha256_list"], 6)
        connections = _object_list(fields["ordered_connection_identity_list"], 6)
        connection_digests = _digest_list(fields["ordered_connection_identity_sha256_list"], 6)
        exchanges = _object_list(fields["ordered_http_exchange_list"], 6)
        exchange_digests = _digest_list(fields["ordered_http_exchange_sha256_list"], 6)
        traces = _object_list(fields["ordered_trace_entry_list"], 6)
        trace_digests = _digest_list(fields["ordered_trace_entry_sha256_list"], 6)
        parsed_connections = [DockerConnectionIdentity.capture(item) for item in connections]
        parsed_exchanges = [DockerHttpExchange.capture(item) for item in exchanges]
        _require_connection_sequence(
            parsed_connections,
            environment=environment,
            graceful_stop_operation_id=operation,
            channel_id=channel,
        )
        plan_identity = DockerPlanIdentity(
            _require_full_id(
                parsed_exchanges[1].to_dict()["target_identity"],
                "supervisor_container_id",
            ),
            _require_full_id(
                parsed_exchanges[2].to_dict()["target_identity"],
                "source_container_id",
            ),
            _require_full_id(
                parsed_exchanges[3].to_dict()["target_identity"],
                "project_network_id",
            ),
        )
        previous: str | None = None
        for index in range(6):
            connection = parsed_connections[index]
            exchange = parsed_exchanges[index]
            trace = DockerTraceEntry.capture(traces[index])
            connection_fields = connection.to_dict()
            exchange_fields = exchange.to_dict()
            trace_fields = trace.to_dict()
            spec = docker_call_spec(index, plan_identity)
            expected_request_sha256 = DockerRequestSemantic.from_spec(spec).sha256
            if (
                connection.ordinal != index
                or trace.ordinal != index
                or connection.sha256 != connection_digests[index]
                or exchange.sha256 != exchange_digests[index]
                or trace.sha256 != trace_digests[index]
                or exchange.to_dict()["request_semantic_sha256"] != requests[index]
                or exchange.to_dict()["connection_identity_sha256"] != connection.sha256
                or exchange.to_dict()["trace_entry_sha256"] != trace.sha256
                or trace.to_dict()["previous_trace_entry_sha256"] != previous
                or requests[index] != expected_request_sha256
                or exchange_fields["request_semantic_sha256"] != expected_request_sha256
                or exchange_fields["exchange_kind"] != spec.exchange_kind
                or exchange_fields["target_kind"] != spec.target_kind
                or exchange_fields["target_identity"] != spec.target_identity
                or exchange_fields["http_status"] != spec.expected_status
                or connection_fields["environment"] != fields["environment"]
                or connection_fields["graceful_stop_operation_id"]
                != fields["graceful_stop_operation_id"]
                or connection_fields["channel_id"] != fields["channel_id"]
                or (
                    index == 0
                    and connection_fields["admitted_daemon_info_projection_sha256"] is not None
                )
                or (
                    index > 0
                    and connection_fields["admitted_daemon_info_projection_sha256"]
                    != fields["daemon_info_projection_sha256"]
                )
                or trace_fields["request_semantic_sha256"]
                != exchange_fields["request_semantic_sha256"]
                or trace_fields["connection_identity_sha256"]
                != exchange_fields["connection_identity_sha256"]
                or trace_fields["http_status"] != exchange_fields["http_status"]
                or trace_fields["response_framing_sha256"]
                != exchange_fields["response_framing_sha256"]
                or trace_fields["response_body_sha256"] != exchange_fields["response_body_sha256"]
                or trace_fields["response_projection_sha256"]
                != exchange_fields["response_projection_sha256"]
                or trace_fields["call_started_boottime_ns"]
                != exchange_fields["call_started_boottime_ns"]
                or trace_fields["call_completed_boottime_ns"]
                != exchange_fields["call_completed_boottime_ns"]
                or connection_fields["path_preconnect_validated_boottime_ns"]
                != exchange_fields["call_started_boottime_ns"]
                or connection_fields["response_complete_revalidated_boottime_ns"]
                != exchange_fields["call_completed_boottime_ns"]
            ):
                _reject("Docker admission ordered evidence disagrees")
            previous = trace.sha256
        projection_names = (
            "daemon_info_projection_sha256",
            "supervisor_container_projection_sha256",
            "source_container_projection_sha256",
            "project_network_projection_sha256",
            "command_socket_volume_projection_sha256",
            "state_volume_projection_sha256",
        )
        for index, name in enumerate(projection_names):
            digest = _require_sha256(fields[name], name)
            if (
                digest
                != DockerHttpExchange.capture(exchanges[index]).to_dict()[
                    "response_projection_sha256"
                ]
            ):
                _reject("Docker admission named projection disagrees")
        started = _require_int(fields["capture_started_boottime_ns"], "capture_started_boottime_ns")
        completed = _require_int(
            fields["capture_completed_boottime_ns"], "capture_completed_boottime_ns"
        )
        if (
            started
            != DockerHttpExchange.capture(exchanges[0]).to_dict()["call_started_boottime_ns"]
            or completed
            != DockerHttpExchange.capture(exchanges[5]).to_dict()["call_completed_boottime_ns"]
            or completed < started
        ):
            _reject("Docker admission capture timestamps disagree")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-admission-capture/v2",
            self.to_dict(),
        )


def _admission_connections(admission: DockerAdmissionCapture) -> list[DockerConnectionIdentity]:
    return [
        DockerConnectionIdentity.capture(item)
        for item in _object_list(
            admission.to_dict()["ordered_connection_identity_list"], 6
        )
    ]


def _admission_exchanges(admission: DockerAdmissionCapture) -> list[DockerHttpExchange]:
    return [
        DockerHttpExchange.capture(item)
        for item in _object_list(admission.to_dict()["ordered_http_exchange_list"], 6)
    ]


def _admission_traces(admission: DockerAdmissionCapture) -> list[DockerTraceEntry]:
    return [
        DockerTraceEntry.capture(item)
        for item in _object_list(admission.to_dict()["ordered_trace_entry_list"], 6)
    ]


def _admission_plan_identity(admission: DockerAdmissionCapture) -> DockerPlanIdentity:
    exchanges = _admission_exchanges(admission)
    return DockerPlanIdentity(
        exchanges[1].to_dict()["target_identity"],  # type: ignore[arg-type]
        exchanges[2].to_dict()["target_identity"],  # type: ignore[arg-type]
        exchanges[3].to_dict()["target_identity"],  # type: ignore[arg-type]
    )


def _same_ordinal_evidence(
    left: DockerOrdinalEvidence,
    right: DockerOrdinalEvidence,
) -> bool:
    return (
        left.spec == right.spec
        and left.request.sha256 == right.request.sha256
        and left.connection.sha256 == right.connection.sha256
        and left.exchange.sha256 == right.exchange.sha256
        and left.trace.sha256 == right.trace.sha256
    )


@dataclass(frozen=True, slots=True, init=False)
class DockerAdmissionRootedTracePrefix:
    """A sealed, gap-free Docker trace prefix rooted in exact admission evidence."""

    _admission: DockerAdmissionCapture
    _entries: tuple[DockerOrdinalEvidence, ...]
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker trace prefixes require validated admission-rooted construction")

    @classmethod
    def from_admission(
        cls,
        *,
        admission: DockerAdmissionCapture,
        entries: object,
    ) -> Self:
        if type(admission) is not DockerAdmissionCapture:
            _reject("Docker trace prefix requires one exact admission capture")
        if type(entries) not in {list, tuple}:
            _reject("Docker trace prefix must be a concrete evidence sequence")
        sequence = cast(list[object] | tuple[object, ...], entries)
        if len(sequence) < 6 or len(sequence) > 18:
            _reject("Docker trace prefix must contain admission and at most ordinal 17")
        typed = tuple(cast(DockerOrdinalEvidence, candidate) for candidate in sequence)
        if any(type(candidate) is not DockerOrdinalEvidence for candidate in typed):
            _reject("Docker trace prefix contains an inexact ordinal value")

        admission_fields = admission.to_dict()
        plan_identity = _admission_plan_identity(admission)
        environment = cast(str, admission_fields["environment"])
        operation = cast(str, admission_fields["graceful_stop_operation_id"])
        channel = cast(str, admission_fields["channel_id"])
        admission_request_sha256s = _digest_list(
            admission_fields["ordered_request_semantic_sha256_list"], 6
        )
        admission_connection_sha256s = _digest_list(
            admission_fields["ordered_connection_identity_sha256_list"], 6
        )
        admission_exchange_sha256s = _digest_list(
            admission_fields["ordered_http_exchange_sha256_list"], 6
        )
        admission_trace_sha256s = _digest_list(
            admission_fields["ordered_trace_entry_sha256_list"], 6
        )

        _require_connection_sequence(
            [entry.connection for entry in typed],
            environment=environment,
            graceful_stop_operation_id=operation,
            channel_id=channel,
        )
        daemon_projection = cast(str, admission_fields["daemon_info_projection_sha256"])
        previous_trace_sha256: str | None = None
        for ordinal, entry in enumerate(typed):
            if entry.spec != docker_call_spec(ordinal, plan_identity):
                _reject("Docker trace prefix is reordered or has an ordinal gap")
            entry._validate()
            trace_fields = entry.trace.to_dict()
            connection_fields = entry.connection.to_dict()
            if trace_fields["previous_trace_entry_sha256"] != previous_trace_sha256:
                _reject("Docker trace prefix predecessor chain is broken")
            admitted = connection_fields["admitted_daemon_info_projection_sha256"]
            if (ordinal == 0 and admitted is not None) or (
                ordinal > 0 and admitted != daemon_projection
            ):
                _reject("Docker trace prefix changes its admitted daemon projection")
            if ordinal < 6 and (
                entry.request.sha256 != admission_request_sha256s[ordinal]
                or entry.connection.sha256 != admission_connection_sha256s[ordinal]
                or entry.exchange.sha256 != admission_exchange_sha256s[ordinal]
                or entry.trace.sha256 != admission_trace_sha256s[ordinal]
            ):
                _reject("Docker trace prefix is not rooted in the exact admission capture")
            previous_trace_sha256 = entry.trace.sha256

        result = object.__new__(cls)
        object.__setattr__(result, "_admission", admission)
        object.__setattr__(result, "_entries", typed)
        object.__setattr__(
            result,
            "_capability",
            _ADMISSION_ROOTED_TRACE_PREFIX_CAPABILITY,
        )
        return result

    def append(self, entry: DockerOrdinalEvidence) -> Self:
        self._require_sealed()
        if type(entry) is not DockerOrdinalEvidence:
            _reject("Docker trace prefix append requires exact ordinal evidence")
        return type(self).from_admission(
            admission=self._admission,
            entries=(*self._entries, entry),
        )

    @property
    def last_ordinal(self) -> int:
        self._require_sealed()
        return len(self._entries) - 1

    @property
    def trace_head_sha256(self) -> str:
        self._require_sealed()
        return self._entries[-1].trace.sha256

    def _require_sealed(self) -> None:
        if (
            getattr(self, "_capability", None)
            is not _ADMISSION_ROOTED_TRACE_PREFIX_CAPABILITY
        ):
            _reject("Docker trace prefix is not sealed")

    def _require_result_suffix(
        self,
        *,
        admission: DockerAdmissionCapture,
        expected: tuple[DockerOrdinalEvidence, ...],
    ) -> None:
        self._require_sealed()
        if (
            type(admission) is not DockerAdmissionCapture
            or admission.sha256 != self._admission.sha256
            or not expected
            or any(type(entry) is not DockerOrdinalEvidence for entry in expected)
        ):
            _reject("Docker result trace prefix crossed its admission context")
        final_ordinal = expected[-1].spec.ordinal
        first_ordinal = final_ordinal - len(expected) + 1
        if (
            first_ordinal < 0
            or len(self._entries) != final_ordinal + 1
            or any(
                not _same_ordinal_evidence(self._entries[first_ordinal + index], entry)
                for index, entry in enumerate(expected)
            )
        ):
            _reject("Docker result is not the exact suffix of its admission-rooted trace")


def _require_exact_admitted_target(
    admission: DockerAdmissionCapture,
    admitted_target: DockerOrdinalEvidence,
    *,
    expected_ordinal: int,
) -> None:
    if type(admitted_target) is not DockerOrdinalEvidence:
        _reject("Docker result requires exact admitted target evidence")
    admission_fields = admission.to_dict()
    request_digests = _digest_list(
        admission_fields["ordered_request_semantic_sha256_list"], 6
    )
    connection_digests = _digest_list(
        admission_fields["ordered_connection_identity_sha256_list"], 6
    )
    exchange_digests = _digest_list(
        admission_fields["ordered_http_exchange_sha256_list"], 6
    )
    trace_digests = _digest_list(
        admission_fields["ordered_trace_entry_sha256_list"], 6
    )
    projection_name = {
        1: "supervisor_container_projection_sha256",
        2: "source_container_projection_sha256",
        3: "project_network_projection_sha256",
    }.get(expected_ordinal)
    if (
        projection_name is None
        or admitted_target.spec.ordinal != expected_ordinal
        or admitted_target.request.sha256 != request_digests[expected_ordinal]
        or admitted_target.connection.sha256 != connection_digests[expected_ordinal]
        or admitted_target.exchange.sha256 != exchange_digests[expected_ordinal]
        or admitted_target.trace.sha256 != trace_digests[expected_ordinal]
        or admitted_target.response.response_projection_sha256
        != admission_fields[projection_name]
    ):
        _reject("Docker result target is not the exact admitted projection")


def _require_result_connection_sequence(
    *,
    admission: DockerAdmissionCapture,
    previous: DockerOrdinalEvidence,
    current: tuple[DockerOrdinalEvidence, DockerOrdinalEvidence],
) -> None:
    admission_fields = admission.to_dict()
    admission_connections = _admission_connections(admission)
    expected_core = _daemon_socket_core(admission_connections[0].to_dict())
    previous_is_admission = previous.spec.ordinal < 6
    prior_sha256s = {
        connection.sha256
        for connection in admission_connections
        if not (previous_is_admission and connection.sha256 == previous.connection.sha256)
    }
    prior_local = {
        _local_socket_identity(connection.to_dict())
        for connection in admission_connections
        if not (previous_is_admission and connection.sha256 == previous.connection.sha256)
    }
    _require_connection_sequence(
        [previous.connection, current[0].connection, current[1].connection],
        environment=cast(str, admission_fields["environment"]),
        graceful_stop_operation_id=cast(
            str, admission_fields["graceful_stop_operation_id"]
        ),
        channel_id=cast(str, admission_fields["channel_id"]),
        expected_core=expected_core,
        prior_connection_sha256s=frozenset(prior_sha256s),
        prior_local_socket_identities=frozenset(prior_local),
    )


def _digest_list(value: object, exact_length: int) -> list[str]:
    items = _require_list(value, "digest list")
    if len(items) != exact_length:
        _reject("digest list length is not exact")
    return [_require_sha256(item, "digest list item") for item in items]


def _object_list(value: object, exact_length: int) -> list[dict[str, object]]:
    items = _require_list(value, "object list")
    if len(items) != exact_length:
        _reject("object list length is not exact")
    return [_require_object(item, "object list item") for item in items]


_MUTATION_RESULT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "result_kind",
        "target_kind",
        "target_id",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
        "primary_request_semantic_sha256",
        "primary_connection_identity",
        "primary_connection_identity_sha256",
        "primary_exchange",
        "primary_exchange_sha256",
        "post_inspect_request_semantic_sha256",
        "post_inspect_connection_identity",
        "post_inspect_connection_identity_sha256",
        "post_inspect_exchange",
        "post_inspect_exchange_sha256",
        "ordered_connection_identity_sha256_list",
        "ordered_trace_entry_list",
        "ordered_trace_entry_sha256_list",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "outcome",
    }
)

_MUTATION_RESULT_RULES = {
    "container_stop": (
        "phase6d-trusted-time-graceful-stop-docker-container-stop-result-v2",
        "container_stop_confirmed",
        "container",
        "stopped",
        "AutoQuantTrader/trusted-time/graceful-stop/docker-container-stop-result/v2",
        frozenset({6, 8}),
    ),
    "container_remove": (
        "phase6d-trusted-time-graceful-stop-docker-container-remove-result-v2",
        "container_removal_confirmed",
        "container",
        "absent",
        "AutoQuantTrader/trusted-time/graceful-stop/docker-container-remove-result/v2",
        frozenset({10, 12}),
    ),
    "network_remove": (
        "phase6d-trusted-time-graceful-stop-docker-network-remove-result-v2",
        "network_removal_confirmed",
        "network",
        "absent",
        "AutoQuantTrader/trusted-time/graceful-stop/docker-network-remove-result/v2",
        frozenset({14}),
    ),
}


def _trace_matches_exchange(
    trace: DockerTraceEntry,
    exchange_fields: dict[str, object],
) -> bool:
    trace_fields = trace.to_dict()
    return all(
        trace_fields[name] == exchange_fields[name]
        for name in (
            "request_semantic_sha256",
            "connection_identity_sha256",
            "http_status",
            "response_framing_sha256",
            "response_body_sha256",
            "response_projection_sha256",
            "call_started_boottime_ns",
            "call_completed_boottime_ns",
        )
    )


def _admitted_target_ordinal(primary_ordinal: int) -> int:
    try:
        return {6: 1, 8: 2, 10: 1, 12: 2, 14: 3}[primary_ordinal]
    except KeyError:
        _reject("Docker mutation ordinal has no admitted target")


def _require_unchanged_stopped_container(
    admitted_target: DockerOrdinalEvidence,
    post_inspect: DockerOrdinalEvidence,
) -> None:
    admitted = admitted_target.response.projection.to_dict()
    stopped = post_inspect.response.projection.to_dict()
    for name in ("container_id", "image_id", "name", "config"):
        if admitted.get(name) != stopped.get(name):
            _reject(
                "post-stop container identity, image, or configured stop signal changed"
            )


@dataclass(frozen=True, slots=True, init=False)
class DockerMutationResultSemantic:
    fields: FrozenJsonObject
    digest_domain: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker mutation results require exact paired ordinal evidence")

    @classmethod
    def from_pair(
        cls,
        *,
        result_kind: str,
        environment: str,
        graceful_stop_operation_id: str,
        root_sha256: str,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        admitted_target: DockerOrdinalEvidence,
        previous: DockerOrdinalEvidence,
        primary: DockerOrdinalEvidence,
        post_inspect: DockerOrdinalEvidence,
    ) -> Self:
        if result_kind not in _MUTATION_RESULT_RULES:
            _reject("Docker mutation result kind is outside the closed set")
        contract, status, target_kind, outcome, _domain, primary_ordinals = _MUTATION_RESULT_RULES[
            result_kind
        ]
        if (
            type(admission) is not DockerAdmissionCapture
            or type(trace_prefix) is not DockerAdmissionRootedTracePrefix
            or type(admitted_target) is not DockerOrdinalEvidence
            or type(previous) is not DockerOrdinalEvidence
            or type(primary) is not DockerOrdinalEvidence
            or type(post_inspect) is not DockerOrdinalEvidence
            or previous.spec.ordinal != primary.spec.ordinal - 1
            or primary.spec.ordinal not in primary_ordinals
            or post_inspect.spec.ordinal != primary.spec.ordinal + 1
            or primary.spec.exchange_kind != "mutation"
            or post_inspect.spec.exchange_kind != "post_inspect"
            or primary.spec.target_kind != target_kind
            or post_inspect.spec.target_kind != target_kind
            or primary.spec.target_identity != post_inspect.spec.target_identity
            or primary.response.http_status != 204
        ):
            _reject("Docker mutation result evidence is not the exact ordinal pair")
        trace_prefix._require_result_suffix(
            admission=admission,
            expected=(previous, primary, post_inspect),
        )
        expected_post_status = 200 if result_kind == "container_stop" else 404
        if post_inspect.response.http_status != expected_post_status:
            _reject("Docker post-inspect status does not prove the required outcome")
        if (
            primary.trace.to_dict()["previous_trace_entry_sha256"] != previous.trace.sha256
            or post_inspect.trace.to_dict()["previous_trace_entry_sha256"]
            != primary.trace.sha256
        ):
            _reject("Docker mutation pair is not adjacent in the trace")
        admission_fields = admission.to_dict()
        value = {
            "contract_version": contract,
            "service": DOCKER_SERVICE,
            "status": status,
            "environment": environment,
            "graceful_stop_operation_id": graceful_stop_operation_id,
            "root_sha256": root_sha256,
            "result_kind": result_kind,
            "target_kind": target_kind,
            "target_id": primary.spec.target_identity,
            "docker_admission_capture_sha256": admission.sha256,
            "admitted_daemon_info_projection_sha256": admission_fields[
                "daemon_info_projection_sha256"
            ],
            "primary_request_semantic_sha256": primary.request.sha256,
            "primary_connection_identity": primary.connection.to_dict(),
            "primary_connection_identity_sha256": primary.connection.sha256,
            "primary_exchange": primary.exchange.to_dict(),
            "primary_exchange_sha256": primary.exchange.sha256,
            "post_inspect_request_semantic_sha256": post_inspect.request.sha256,
            "post_inspect_connection_identity": post_inspect.connection.to_dict(),
            "post_inspect_connection_identity_sha256": post_inspect.connection.sha256,
            "post_inspect_exchange": post_inspect.exchange.to_dict(),
            "post_inspect_exchange_sha256": post_inspect.exchange.sha256,
            "ordered_connection_identity_sha256_list": [
                primary.connection.sha256,
                post_inspect.connection.sha256,
            ],
            "ordered_trace_entry_list": [
                primary.trace.to_dict(),
                post_inspect.trace.to_dict(),
            ],
            "ordered_trace_entry_sha256_list": [
                primary.trace.sha256,
                post_inspect.trace.sha256,
            ],
            "call_started_boottime_ns": primary.exchange.to_dict()["call_started_boottime_ns"],
            "call_completed_boottime_ns": post_inspect.exchange.to_dict()[
                "call_completed_boottime_ns"
            ],
            "outcome": outcome,
        }
        return cls.capture(
            value,
            admission=admission,
            trace_prefix=trace_prefix,
            admitted_target=admitted_target,
            previous=previous,
            primary=primary,
            post_inspect=post_inspect,
        )

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        admitted_target: DockerOrdinalEvidence,
        previous: DockerOrdinalEvidence,
        primary: DockerOrdinalEvidence,
        post_inspect: DockerOrdinalEvidence,
    ) -> Self:
        if (
            type(admission) is not DockerAdmissionCapture
            or type(trace_prefix) is not DockerAdmissionRootedTracePrefix
            or type(admitted_target) is not DockerOrdinalEvidence
            or type(previous) is not DockerOrdinalEvidence
            or type(primary) is not DockerOrdinalEvidence
            or type(post_inspect) is not DockerOrdinalEvidence
        ):
            _reject("Docker mutation result requires exact contextual evidence")
        trace_prefix._require_result_suffix(
            admission=admission,
            expected=(previous, primary, post_inspect),
        )
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _MUTATION_RESULT_FIELDS, "Docker mutation result")
        result_kind = fields["result_kind"]
        if type(result_kind) is not str or result_kind not in _MUTATION_RESULT_RULES:
            _reject("Docker mutation result kind is invalid")
        contract, status, target_kind, outcome, domain, ordinals = _MUTATION_RESULT_RULES[
            result_kind
        ]
        if (
            fields["contract_version"] != contract
            or fields["service"] != DOCKER_SERVICE
            or fields["status"] != status
            or fields["target_kind"] != target_kind
            or fields["outcome"] != outcome
        ):
            _reject("Docker mutation result discriminator is invalid")
        expected_admitted_ordinal = _admitted_target_ordinal(primary.spec.ordinal)
        _require_exact_admitted_target(
            admission,
            admitted_target,
            expected_ordinal=expected_admitted_ordinal,
        )
        plan_identity = _admission_plan_identity(admission)
        expected_primary_spec = docker_call_spec(primary.spec.ordinal, plan_identity)
        expected_post_spec = docker_call_spec(primary.spec.ordinal + 1, plan_identity)
        if (
            primary.spec.ordinal not in ordinals
            or primary.spec != expected_primary_spec
            or post_inspect.spec != expected_post_spec
            or previous.spec.ordinal != primary.spec.ordinal - 1
            or previous.spec != docker_call_spec(previous.spec.ordinal, plan_identity)
            or primary.trace.to_dict()["previous_trace_entry_sha256"]
            != previous.trace.sha256
            or post_inspect.trace.to_dict()["previous_trace_entry_sha256"]
            != primary.trace.sha256
        ):
            _reject("Docker mutation context is not the exact global plan prefix")
        if previous.spec.ordinal < 6:
            admission_fields_for_previous = admission.to_dict()
            previous_ordinal = previous.spec.ordinal
            if (
                previous.request.sha256
                != _digest_list(
                    admission_fields_for_previous["ordered_request_semantic_sha256_list"],
                    6,
                )[previous_ordinal]
                or previous.connection.sha256
                != _digest_list(
                    admission_fields_for_previous[
                        "ordered_connection_identity_sha256_list"
                    ],
                    6,
                )[previous_ordinal]
                or previous.exchange.sha256
                != _digest_list(
                    admission_fields_for_previous["ordered_http_exchange_sha256_list"],
                    6,
                )[previous_ordinal]
                or previous.trace.sha256
                != _digest_list(
                    admission_fields_for_previous["ordered_trace_entry_sha256_list"], 6
                )[previous_ordinal]
            ):
                _reject("Docker mutation prior trace head crossed admission")
        _require_result_connection_sequence(
            admission=admission,
            previous=previous,
            current=(primary, post_inspect),
        )
        if result_kind == "container_stop":
            _require_unchanged_stopped_container(admitted_target, post_inspect)
        for name in ("environment", "graceful_stop_operation_id"):
            _require_ascii(fields[name], name)
        target_id = _require_full_id(fields["target_id"], "target_id")
        for name in (
            "root_sha256",
            "docker_admission_capture_sha256",
            "admitted_daemon_info_projection_sha256",
            "primary_request_semantic_sha256",
            "primary_connection_identity_sha256",
            "primary_exchange_sha256",
            "post_inspect_request_semantic_sha256",
            "post_inspect_connection_identity_sha256",
            "post_inspect_exchange_sha256",
        ):
            _require_sha256(fields[name], name)
        primary_connection = DockerConnectionIdentity.capture(fields["primary_connection_identity"])
        post_connection = DockerConnectionIdentity.capture(
            fields["post_inspect_connection_identity"]
        )
        primary_exchange = DockerHttpExchange.capture(fields["primary_exchange"])
        post_exchange = DockerHttpExchange.capture(fields["post_inspect_exchange"])
        traces = _object_list(fields["ordered_trace_entry_list"], 2)
        trace_digests = _digest_list(fields["ordered_trace_entry_sha256_list"], 2)
        trace_values = [DockerTraceEntry.capture(item) for item in traces]
        connection_digests = _digest_list(fields["ordered_connection_identity_sha256_list"], 2)
        expected_post_status = 200 if result_kind == "container_stop" else 404
        primary_spec = docker_call_spec(primary_connection.ordinal, plan_identity)
        post_spec = docker_call_spec(primary_connection.ordinal + 1, plan_identity)
        primary_connection_fields = primary_connection.to_dict()
        post_connection_fields = post_connection.to_dict()
        primary_exchange_fields = primary_exchange.to_dict()
        post_exchange_fields = post_exchange.to_dict()
        admission_fields = admission.to_dict()
        if (
            primary_connection.ordinal not in ordinals
            or fields["docker_admission_capture_sha256"] != admission.sha256
            or fields["admitted_daemon_info_projection_sha256"]
            != admission_fields["daemon_info_projection_sha256"]
            or fields["environment"] != admission_fields["environment"]
            or fields["graceful_stop_operation_id"]
            != admission_fields["graceful_stop_operation_id"]
            or fields["target_id"] != primary.spec.target_identity
            or fields["primary_request_semantic_sha256"] != primary.request.sha256
            or fields["post_inspect_request_semantic_sha256"]
            != post_inspect.request.sha256
            or primary_connection.sha256 != primary.connection.sha256
            or post_connection.sha256 != post_inspect.connection.sha256
            or primary_exchange.sha256 != primary.exchange.sha256
            or post_exchange.sha256 != post_inspect.exchange.sha256
            or trace_values[0].sha256 != primary.trace.sha256
            or trace_values[1].sha256 != post_inspect.trace.sha256
            or trace_values[0].to_dict()["previous_trace_entry_sha256"]
            != previous.trace.sha256
            or post_connection.ordinal != primary_connection.ordinal + 1
            or primary_connection.sha256 != fields["primary_connection_identity_sha256"]
            or post_connection.sha256 != fields["post_inspect_connection_identity_sha256"]
            or connection_digests != [primary_connection.sha256, post_connection.sha256]
            or primary_exchange.sha256 != fields["primary_exchange_sha256"]
            or post_exchange.sha256 != fields["post_inspect_exchange_sha256"]
            or trace_values[0].sha256 != trace_digests[0]
            or trace_values[1].sha256 != trace_digests[1]
            or trace_values[0].ordinal != primary_connection.ordinal
            or trace_values[1].ordinal != post_connection.ordinal
            or trace_values[1].to_dict()["previous_trace_entry_sha256"] != trace_values[0].sha256
            or primary_exchange.to_dict()["trace_entry_sha256"] != trace_values[0].sha256
            or post_exchange.to_dict()["trace_entry_sha256"] != trace_values[1].sha256
            or primary_exchange.to_dict()["exchange_kind"] != "mutation"
            or post_exchange.to_dict()["exchange_kind"] != "post_inspect"
            or primary_exchange.to_dict()["target_kind"] != target_kind
            or post_exchange.to_dict()["target_kind"] != target_kind
            or primary_exchange.to_dict()["target_identity"] != target_id
            or post_exchange.to_dict()["target_identity"] != target_id
            or primary_exchange.to_dict()["http_status"] != 204
            or post_exchange.to_dict()["http_status"] != expected_post_status
            or primary_exchange.to_dict()["request_semantic_sha256"]
            != fields["primary_request_semantic_sha256"]
            or post_exchange.to_dict()["request_semantic_sha256"]
            != fields["post_inspect_request_semantic_sha256"]
            or fields["primary_request_semantic_sha256"]
            != DockerRequestSemantic.from_spec(primary_spec).sha256
            or fields["post_inspect_request_semantic_sha256"]
            != DockerRequestSemantic.from_spec(post_spec).sha256
            or primary_connection_fields["environment"] != fields["environment"]
            or post_connection_fields["environment"] != fields["environment"]
            or primary_connection_fields["graceful_stop_operation_id"]
            != fields["graceful_stop_operation_id"]
            or post_connection_fields["graceful_stop_operation_id"]
            != fields["graceful_stop_operation_id"]
            or primary_connection_fields["admitted_daemon_info_projection_sha256"]
            != fields["admitted_daemon_info_projection_sha256"]
            or post_connection_fields["admitted_daemon_info_projection_sha256"]
            != fields["admitted_daemon_info_projection_sha256"]
            or not _trace_matches_exchange(trace_values[0], primary_exchange_fields)
            or not _trace_matches_exchange(trace_values[1], post_exchange_fields)
            or primary_connection_fields["path_preconnect_validated_boottime_ns"]
            != primary_exchange_fields["call_started_boottime_ns"]
            or primary_connection_fields["response_complete_revalidated_boottime_ns"]
            != primary_exchange_fields["call_completed_boottime_ns"]
            or post_connection_fields["path_preconnect_validated_boottime_ns"]
            != post_exchange_fields["call_started_boottime_ns"]
            or post_connection_fields["response_complete_revalidated_boottime_ns"]
            != post_exchange_fields["call_completed_boottime_ns"]
        ):
            _reject("Docker mutation result nesting disagrees")
        started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(fields["call_completed_boottime_ns"], "call_completed_boottime_ns")
        if (
            started != primary_exchange.to_dict()["call_started_boottime_ns"]
            or completed != post_exchange.to_dict()["call_completed_boottime_ns"]
            or completed < started
        ):
            _reject("Docker mutation result timestamps disagree")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "digest_domain", domain)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256(self.digest_domain, self.to_dict())


_VOLUME_RESULT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "result_kind",
        "target_kind",
        "target_names",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
        "admission_volume_projection_sha256_list",
        "ordered_request_semantic_sha256_list",
        "ordered_connection_identity_list",
        "ordered_connection_identity_sha256_list",
        "ordered_http_exchange_list",
        "ordered_http_exchange_sha256_list",
        "ordered_trace_entry_list",
        "ordered_trace_entry_sha256_list",
        "post_volume_projection_sha256_list",
        "volume_delete_call_count",
        "proof_started_boottime_ns",
        "proof_completed_boottime_ns",
        "outcome",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class DockerVolumePreservationResult:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Docker volume preservation requires exact ordinal evidence")

    @classmethod
    def from_pair(
        cls,
        *,
        environment: str,
        graceful_stop_operation_id: str,
        root_sha256: str,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        previous: DockerOrdinalEvidence,
        command_socket: DockerOrdinalEvidence,
        state: DockerOrdinalEvidence,
        volume_delete_call_count: int,
    ) -> Self:
        if (
            type(admission) is not DockerAdmissionCapture
            or type(trace_prefix) is not DockerAdmissionRootedTracePrefix
            or type(previous) is not DockerOrdinalEvidence
            or type(command_socket) is not DockerOrdinalEvidence
            or type(state) is not DockerOrdinalEvidence
            or previous.spec.ordinal != 15
            or command_socket.spec.ordinal != 16
            or state.spec.ordinal != 17
            or command_socket.spec.target_identity != COMMAND_SOCKET_VOLUME
            or state.spec.target_identity != STATE_VOLUME
            or command_socket.spec.exchange_kind != "volume_proof"
            or state.spec.exchange_kind != "volume_proof"
            or command_socket.trace.to_dict()["previous_trace_entry_sha256"]
            != previous.trace.sha256
            or state.trace.to_dict()["previous_trace_entry_sha256"] != command_socket.trace.sha256
        ):
            _reject("Docker volume proof is not the exact ordinal pair")
        trace_prefix._require_result_suffix(
            admission=admission,
            expected=(previous, command_socket, state),
        )
        admission_fields = admission.to_dict()
        admission_volumes = [
            admission_fields["command_socket_volume_projection_sha256"],
            admission_fields["state_volume_projection_sha256"],
        ]
        post_volumes = [
            command_socket.response.response_projection_sha256,
            state.response.response_projection_sha256,
        ]
        value = {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-docker-volume-preservation-result-v2"
            ),
            "service": DOCKER_SERVICE,
            "status": "named_volumes_preserved",
            "environment": environment,
            "graceful_stop_operation_id": graceful_stop_operation_id,
            "root_sha256": root_sha256,
            "result_kind": "volume_preservation",
            "target_kind": "named_volume_set",
            "target_names": list(VOLUME_NAMES),
            "docker_admission_capture_sha256": admission.sha256,
            "admitted_daemon_info_projection_sha256": admission_fields[
                "daemon_info_projection_sha256"
            ],
            "admission_volume_projection_sha256_list": admission_volumes,
            "ordered_request_semantic_sha256_list": [
                command_socket.request.sha256,
                state.request.sha256,
            ],
            "ordered_connection_identity_list": [
                command_socket.connection.to_dict(),
                state.connection.to_dict(),
            ],
            "ordered_connection_identity_sha256_list": [
                command_socket.connection.sha256,
                state.connection.sha256,
            ],
            "ordered_http_exchange_list": [
                command_socket.exchange.to_dict(),
                state.exchange.to_dict(),
            ],
            "ordered_http_exchange_sha256_list": [
                command_socket.exchange.sha256,
                state.exchange.sha256,
            ],
            "ordered_trace_entry_list": [
                command_socket.trace.to_dict(),
                state.trace.to_dict(),
            ],
            "ordered_trace_entry_sha256_list": [
                command_socket.trace.sha256,
                state.trace.sha256,
            ],
            "post_volume_projection_sha256_list": post_volumes,
            "volume_delete_call_count": volume_delete_call_count,
            "proof_started_boottime_ns": command_socket.exchange.to_dict()[
                "call_started_boottime_ns"
            ],
            "proof_completed_boottime_ns": state.exchange.to_dict()["call_completed_boottime_ns"],
            "outcome": "volumes_preserved",
        }
        return cls.capture(
            value,
            admission=admission,
            trace_prefix=trace_prefix,
            previous=previous,
            command_socket=command_socket,
            state=state,
        )

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        previous: DockerOrdinalEvidence,
        command_socket: DockerOrdinalEvidence,
        state: DockerOrdinalEvidence,
    ) -> Self:
        if (
            type(admission) is not DockerAdmissionCapture
            or type(trace_prefix) is not DockerAdmissionRootedTracePrefix
            or type(previous) is not DockerOrdinalEvidence
            or type(command_socket) is not DockerOrdinalEvidence
            or type(state) is not DockerOrdinalEvidence
        ):
            _reject("Docker volume result requires exact contextual evidence")
        trace_prefix._require_result_suffix(
            admission=admission,
            expected=(previous, command_socket, state),
        )
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _VOLUME_RESULT_FIELDS, "Docker volume preservation")
        volume_delete_call_count = _require_int(
            fields["volume_delete_call_count"], "volume_delete_call_count"
        )
        if (
            fields["contract_version"]
            != "phase6d-trusted-time-graceful-stop-docker-volume-preservation-result-v2"
            or fields["service"] != DOCKER_SERVICE
            or fields["status"] != "named_volumes_preserved"
            or fields["result_kind"] != "volume_preservation"
            or fields["target_kind"] != "named_volume_set"
            or fields["target_names"] != list(VOLUME_NAMES)
            or fields["outcome"] != "volumes_preserved"
            or volume_delete_call_count != 0
        ):
            _reject("Docker volume preservation discriminator is invalid")
        plan_identity = _admission_plan_identity(admission)
        if (
            previous.spec != docker_call_spec(15, plan_identity)
            or command_socket.spec != docker_call_spec(16, plan_identity)
            or state.spec != docker_call_spec(17, plan_identity)
            or command_socket.trace.to_dict()["previous_trace_entry_sha256"]
            != previous.trace.sha256
            or state.trace.to_dict()["previous_trace_entry_sha256"]
            != command_socket.trace.sha256
        ):
            _reject("Docker volume proof is not the exact global plan suffix")
        _require_result_connection_sequence(
            admission=admission,
            previous=previous,
            current=(command_socket, state),
        )
        for name in ("environment", "graceful_stop_operation_id"):
            _require_ascii(fields[name], name)
        for name in (
            "root_sha256",
            "docker_admission_capture_sha256",
            "admitted_daemon_info_projection_sha256",
        ):
            _require_sha256(fields[name], name)
        admission_volumes = _digest_list(fields["admission_volume_projection_sha256_list"], 2)
        post_volumes = _digest_list(fields["post_volume_projection_sha256_list"], 2)
        if admission_volumes != post_volumes:
            _reject("Docker volume projection changed since admission")
        request_digests = _digest_list(fields["ordered_request_semantic_sha256_list"], 2)
        connections = [
            DockerConnectionIdentity.capture(item)
            for item in _object_list(fields["ordered_connection_identity_list"], 2)
        ]
        connection_digests = _digest_list(fields["ordered_connection_identity_sha256_list"], 2)
        exchanges = [
            DockerHttpExchange.capture(item)
            for item in _object_list(fields["ordered_http_exchange_list"], 2)
        ]
        exchange_digests = _digest_list(fields["ordered_http_exchange_sha256_list"], 2)
        traces = [
            DockerTraceEntry.capture(item)
            for item in _object_list(fields["ordered_trace_entry_list"], 2)
        ]
        trace_digests = _digest_list(fields["ordered_trace_entry_sha256_list"], 2)
        if [connection.ordinal for connection in connections] != [16, 17]:
            _reject("Docker volume proof connection ordinals are not 16 and 17")
        admission_fields = admission.to_dict()
        if (
            fields["docker_admission_capture_sha256"] != admission.sha256
            or fields["admitted_daemon_info_projection_sha256"]
            != admission_fields["daemon_info_projection_sha256"]
            or fields["environment"] != admission_fields["environment"]
            or fields["graceful_stop_operation_id"]
            != admission_fields["graceful_stop_operation_id"]
            or admission_volumes
            != [
                admission_fields["command_socket_volume_projection_sha256"],
                admission_fields["state_volume_projection_sha256"],
            ]
            or post_volumes
            != [
                command_socket.response.response_projection_sha256,
                state.response.response_projection_sha256,
            ]
        ):
            _reject("Docker volume proof crossed its admitted context")
        for index in range(2):
            exchange_fields = exchanges[index].to_dict()
            connection_fields = connections[index].to_dict()
            spec = docker_call_spec(16 + index, plan_identity)
            if (
                connections[index].sha256 != connection_digests[index]
                or connections[index].sha256
                != (command_socket, state)[index].connection.sha256
                or exchanges[index].sha256 != exchange_digests[index]
                or exchanges[index].sha256 != (command_socket, state)[index].exchange.sha256
                or traces[index].sha256 != trace_digests[index]
                or traces[index].sha256 != (command_socket, state)[index].trace.sha256
                or traces[index].ordinal != 16 + index
                or request_digests[index] != (command_socket, state)[index].request.sha256
                or exchange_fields["request_semantic_sha256"] != request_digests[index]
                or exchange_fields["connection_identity_sha256"] != connections[index].sha256
                or exchange_fields["trace_entry_sha256"] != traces[index].sha256
                or exchange_fields["exchange_kind"] != "volume_proof"
                or exchange_fields["target_kind"] != "volume"
                or exchange_fields["target_identity"] != VOLUME_NAMES[index]
                or exchange_fields["http_status"] != 200
                or exchange_fields["response_projection_sha256"] != post_volumes[index]
                or request_digests[index] != DockerRequestSemantic.from_spec(spec).sha256
                or connection_fields["environment"] != fields["environment"]
                or connection_fields["graceful_stop_operation_id"]
                != fields["graceful_stop_operation_id"]
                or connection_fields["admitted_daemon_info_projection_sha256"]
                != fields["admitted_daemon_info_projection_sha256"]
                or not _trace_matches_exchange(traces[index], exchange_fields)
                or connection_fields["path_preconnect_validated_boottime_ns"]
                != exchange_fields["call_started_boottime_ns"]
                or connection_fields["response_complete_revalidated_boottime_ns"]
                != exchange_fields["call_completed_boottime_ns"]
            ):
                _reject("Docker volume proof nested evidence disagrees")
        if traces[1].to_dict()["previous_trace_entry_sha256"] != traces[0].sha256:
            _reject("Docker volume proof trace pair is not adjacent")
        if traces[0].to_dict()["previous_trace_entry_sha256"] != previous.trace.sha256:
            _reject("Docker volume proof prior trace head disagrees")
        started = _require_int(fields["proof_started_boottime_ns"], "proof_started_boottime_ns")
        completed = _require_int(
            fields["proof_completed_boottime_ns"], "proof_completed_boottime_ns"
        )
        if (
            started != exchanges[0].to_dict()["call_started_boottime_ns"]
            or completed != exchanges[1].to_dict()["call_completed_boottime_ns"]
            or completed < started
        ):
            _reject("Docker volume proof timestamps disagree")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/docker-volume-preservation-result/v2",
            self.to_dict(),
        )


def docker_evidence_non_authority_facts() -> dict[str, bool]:
    return {
        "socket_imported": False,
        "http_client_imported": False,
        "docker_sdk_imported": False,
        "generic_request_method_present": False,
        "volume_delete_method_present": False,
        "production_caller_present": False,
    }


__all__ = [
    "COMMAND_SOCKET_VOLUME",
    "DOCKER_API_VERSION",
    "DOCKER_SERVICE",
    "DOCKER_SOCKET_PATH",
    "EMPTY_BODY_SHA256",
    "STATE_VOLUME",
    "VOLUME_NAMES",
    "DockerAdmissionCapture",
    "DockerAdmissionRootedTracePrefix",
    "DockerCallSpec",
    "DockerConnectionIdentity",
    "DockerHttpExchange",
    "DockerMutationResultSemantic",
    "DockerOrdinalEvidence",
    "DockerPlanIdentity",
    "DockerRequestSemantic",
    "DockerResponseEvidence",
    "DockerTraceEntry",
    "DockerVolumePreservationResult",
    "TrustedTimeDockerEvidenceRejected",
    "docker_call_spec",
    "docker_evidence_non_authority_facts",
    "parse_docker_response",
    "validate_complete_docker_trace",
    "validate_docker_request_bytes",
]
