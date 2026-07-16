"""Bounded, secret-safe acquisition for immutable Sharadar SFP snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode, urlsplit, urlunsplit

from packages.adapters.market_data.sharadar_sfp import (
    MAX_PAGE_BYTES,
    PHASE1_SFP_SYMBOLS,
    SFP_COLUMNS,
    SfpCaptureAuthorization,
    SfpCaptureManifest,
    SfpCaptureScope,
    SfpPageReceipt,
    SharadarSfpError,
    sfp_page_contract,
)
from packages.market_data.models import require_text, require_utc

MAX_PAGES = 10
_CAPTURE_RELATIVE_ROOT = Path(".local/vendor-snapshots/sharadar-sfp")
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


class SharadarSfpCaptureError(RuntimeError):
    """A sanitized acquisition or immutable-storage operation failed."""


@dataclass(frozen=True, slots=True)
class SfpApiRequest:
    scope: SfpCaptureScope
    cursor_id: str | None
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return "SfpApiRequest(table='SHARADAR/SFP', redacted=True)"


@dataclass(frozen=True, slots=True)
class SfpApiResponse:
    status: int
    payload: bytes = field(repr=False)


class SfpApiTransport(Protocol):
    def __call__(
        self,
        request: SfpApiRequest,
        *,
        timeout_seconds: float,
    ) -> SfpApiResponse: ...


def _https_get(request: SfpApiRequest, *, timeout_seconds: float) -> SfpApiResponse:
    target = urlsplit(request.url)
    if target.scheme != "https" or not target.hostname or target.username or target.password:
        raise SharadarSfpCaptureError("Sharadar request target is not a valid HTTPS authority")
    path = urlunsplit(("", "", target.path or "/", target.query, ""))
    connection = HTTPSConnection(target.hostname, target.port, timeout=timeout_seconds)
    try:
        connection.request("GET", path, headers=dict(request.headers))
        response = connection.getresponse()
        payload = response.read(MAX_PAGE_BYTES + 1)
    except (HTTPException, OSError, TimeoutError, ValueError) as error:
        raise SharadarSfpCaptureError("Sharadar request failed") from error
    finally:
        connection.close()
    if len(payload) > MAX_PAGE_BYTES:
        raise SharadarSfpCaptureError("Sharadar response exceeded the capture limit")
    return SfpApiResponse(status=response.status, payload=payload)


def _request(
    *,
    api_key: str,
    scope: SfpCaptureScope,
    cursor_id: str | None,
) -> SfpApiRequest:
    query: dict[str, str] = {
        "api_key": api_key,
        "date.gte": scope.start_date.isoformat(),
        "date.lte": scope.end_date.isoformat(),
        "qopts.columns": ",".join(SFP_COLUMNS),
        "qopts.per_page": "10000",
        "ticker": ",".join(scope.symbols),
    }
    if cursor_id is not None:
        query["qopts.cursor_id"] = cursor_id
    return SfpApiRequest(
        scope=scope,
        cursor_id=cursor_id,
        url=("https://data.nasdaq.com/api/v3/datatables/SHARADAR/SFP.json?" + urlencode(query)),
        headers={"Accept": "application/json", "User-Agent": "AutoQuantTrader/0.1"},
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    try:
        require_utc(value, "capture clock")
    except ValueError as error:
        raise SharadarSfpCaptureError("capture clock must return UTC") from error
    return value


def _capture_destination(repository_root: Path, output_root: Path) -> tuple[Path, Path]:
    repository = Path(os.path.abspath(repository_root))
    output = Path(os.path.abspath(output_root))
    if output != repository / _CAPTURE_RELATIVE_ROOT:
        raise SharadarSfpCaptureError(
            "capture output must use the repository's fixed ignored SFP snapshot root"
        )
    return repository, output


def _open_existing_directory(path: Path, *, kind: str) -> int:
    try:
        descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    except OSError as error:
        raise SharadarSfpCaptureError(f"cannot open the {kind}") from error
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise SharadarSfpCaptureError(
            f"the {kind} path cannot contain symlinks or non-directories"
        ) from error
    return descriptor


def _open_capture_root(repository_root: Path) -> int:
    descriptor = _open_existing_directory(repository_root, kind="repository root")
    try:
        for part in _CAPTURE_RELATIVE_ROOT.parts:
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                os.close(next_descriptor)
                raise SharadarSfpCaptureError(
                    "capture root directories must be owner-only (chmod 700)"
                )
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise SharadarSfpCaptureError(
            "cannot prepare the capture root without following symlinks"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _write_exclusive(directory_descriptor: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory_descriptor)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise SharadarSfpCaptureError("cannot write an immutable capture object") from error


def _capture_id(started_at: datetime, page_hashes: tuple[str, ...]) -> str:
    material = json.dumps(
        {"page_hashes": page_hashes, "started_at": started_at.isoformat()},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    timestamp = started_at.strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{hashlib.sha256(material).hexdigest()[:16]}"


@dataclass(frozen=True, slots=True)
class _CapturedPage:
    cursor_id: str | None
    next_cursor_id: str | None
    requested_at: datetime
    received_at: datetime
    payload: bytes = field(repr=False)


def capture_sharadar_sfp(
    output_root: Path,
    *,
    repository_root: Path,
    api_key: str,
    scope: SfpCaptureScope,
    authorization_bytes: bytes,
    timeout_seconds: float = 15.0,
    transport: SfpApiTransport = _https_get,
    clock: Callable[[], datetime] = _utc_now,
) -> Path:
    """Fetch a bounded cursor chain and archive exact bytes plus a safe receipt."""

    try:
        require_text(api_key, "api_key")
    except ValueError as error:
        raise SharadarSfpCaptureError("NASDAQ_DATA_LINK_API_KEY is not configured") from error
    if not set(scope.symbols).issubset(PHASE1_SFP_SYMBOLS):
        raise SharadarSfpCaptureError("capture scope exceeds the Phase 1 SFP allow-list")
    if timeout_seconds <= 0 or timeout_seconds > 30:
        raise SharadarSfpCaptureError("timeout must be greater than zero and at most 30 seconds")
    repository_root, output_root = _capture_destination(repository_root, output_root)
    try:
        authorization = SfpCaptureAuthorization.from_json_bytes(authorization_bytes)
    except (TypeError, SharadarSfpError, ValueError) as error:
        raise SharadarSfpCaptureError("capture authorization artifact is invalid") from error
    authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()

    captured: list[_CapturedPage] = []
    cursor_id: str | None = None
    seen_cursors: set[str] = set()
    column_schema_sha256: str | None = None
    for _ in range(MAX_PAGES):
        requested_at = _clock_value(clock)
        if not captured:
            try:
                authorization.authorize(scope, requested_at=requested_at)
            except ValueError as error:
                raise SharadarSfpCaptureError(str(error)) from error
        request = _request(api_key=api_key, scope=scope, cursor_id=cursor_id)
        response = transport(request, timeout_seconds=timeout_seconds)
        received_at = _clock_value(clock)
        if not 200 <= response.status < 300:
            raise SharadarSfpCaptureError(
                f"Sharadar returned non-success HTTP status {response.status}"
            )
        try:
            next_cursor_id, observed_schema_sha256 = sfp_page_contract(response.payload)
        except SharadarSfpError as error:
            raise SharadarSfpCaptureError("Sharadar returned an invalid response page") from error
        if column_schema_sha256 is None:
            column_schema_sha256 = observed_schema_sha256
        elif observed_schema_sha256 != column_schema_sha256:
            raise SharadarSfpCaptureError("Sharadar changed column schema during pagination")
        captured.append(
            _CapturedPage(
                cursor_id=cursor_id,
                next_cursor_id=next_cursor_id,
                requested_at=requested_at,
                received_at=received_at,
                payload=response.payload,
            )
        )
        if next_cursor_id is None:
            break
        if next_cursor_id in seen_cursors:
            raise SharadarSfpCaptureError("Sharadar cursor chain contains a cycle")
        seen_cursors.add(next_cursor_id)
        cursor_id = next_cursor_id
    else:
        raise SharadarSfpCaptureError("Sharadar cursor chain exceeded the page limit")
    if column_schema_sha256 is None:  # pragma: no cover - a successful page always sets it
        raise AssertionError("capture has no observed column schema")

    page_hashes = tuple(hashlib.sha256(page.payload).hexdigest() for page in captured)
    capture_name = _capture_id(captured[0].requested_at, page_hashes)
    capture_dir = output_root / capture_name
    root_descriptor = _open_capture_root(repository_root)
    capture_descriptor: int | None = None
    objects_descriptor: int | None = None
    try:
        os.mkdir(capture_name, mode=0o700, dir_fd=root_descriptor)
        capture_descriptor = os.open(capture_name, _DIRECTORY_FLAGS, dir_fd=root_descriptor)
        os.mkdir("objects", mode=0o700, dir_fd=capture_descriptor)
        objects_descriptor = os.open("objects", _DIRECTORY_FLAGS, dir_fd=capture_descriptor)

        receipts: list[SfpPageReceipt] = []
        written_payloads: dict[str, bytes] = {}
        for page, digest in zip(captured, page_hashes, strict=True):
            object_name = f"{digest}.json"
            previous_payload = written_payloads.get(digest)
            if previous_payload is None:
                _write_exclusive(objects_descriptor, object_name, page.payload)
                written_payloads[digest] = page.payload
            elif previous_payload != page.payload:  # pragma: no cover - SHA-256 collision guard
                raise SharadarSfpCaptureError("capture digest collision detected")
            receipts.append(
                SfpPageReceipt(
                    object_path=f"objects/{object_name}",
                    sha256=digest,
                    byte_count=len(page.payload),
                    cursor_id=page.cursor_id,
                    next_cursor_id=page.next_cursor_id,
                    requested_at=page.requested_at,
                    received_at=page.received_at,
                )
            )

        manifest = SfpCaptureManifest(
            scope=scope,
            pages=tuple(receipts),
            requested_at=receipts[0].requested_at,
            received_at=receipts[-1].received_at,
            authorization_sha256=authorization_sha256,
            terms_sha256=authorization.terms_sha256,
            column_schema_sha256=column_schema_sha256,
        )
        _write_exclusive(capture_descriptor, "manifest.json", manifest.to_json_bytes())
        os.fchmod(objects_descriptor, 0o500)
        os.fchmod(capture_descriptor, 0o500)
        os.fsync(objects_descriptor)
        os.fsync(capture_descriptor)
        os.fsync(root_descriptor)
    except OSError as error:
        raise SharadarSfpCaptureError("cannot create an immutable capture directory") from error
    finally:
        if objects_descriptor is not None:
            os.close(objects_descriptor)
        if capture_descriptor is not None:
            os.close(capture_descriptor)
        os.close(root_descriptor)
    return capture_dir / "manifest.json"
