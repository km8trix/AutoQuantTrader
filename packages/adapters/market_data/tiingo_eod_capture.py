"""Authorization-gated, exact-byte acquisition for Tiingo EOD responses.

This module archives bounded provider responses for later offline qualification.
It does not load captures, infer vendor publication times, create revision
lineage, emit canonical bars, or grant admission or trading authority.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_MANIFEST_BYTES,
    MAX_TIINGO_RESPONSE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodCaptureManifest,
    TiingoEodCaptureReceipt,
    TiingoEodError,
    tiingo_eod_response_contract,
)
from packages.adapters.market_data.tiingo_eod_capture_identity import (
    tiingo_eod_capture_name,
)
from packages.market_data.models import require_text, require_utc

TIINGO_EOD_CAPTURE_RELATIVE_ROOT = Path(".local/vendor-snapshots/tiingo-eod")

_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


class TiingoEodCaptureError(RuntimeError):
    """A sanitized transport or immutable-storage operation failed."""


@dataclass(frozen=True, slots=True)
class TiingoEodApiRequest:
    symbol: str
    profile_contract_sha256: str
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return f"TiingoEodApiRequest(symbol={self.symbol!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class TiingoEodApiResponse:
    status: int
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("status must be a valid HTTP status")
        if type(self.payload) is not bytes:
            raise ValueError("payload must be immutable bytes")


class TiingoEodApiTransport(Protocol):
    def __call__(
        self,
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse: ...


def _https_get(
    request: TiingoEodApiRequest,
    *,
    timeout_seconds: float,
) -> TiingoEodApiResponse:
    target = urlsplit(request.url)
    if (
        target.scheme != "https"
        or target.hostname != "api.tiingo.com"
        or target.port not in {None, 443}
        or target.username
        or target.password
    ):
        raise TiingoEodCaptureError("Tiingo request target is not the frozen HTTPS authority")
    path = urlunsplit(("", "", target.path or "/", target.query, ""))
    connection = HTTPSConnection(target.hostname, target.port, timeout=timeout_seconds)
    try:
        connection.request("GET", path, headers=dict(request.headers))
        response = connection.getresponse()
        payload = response.read(MAX_TIINGO_RESPONSE_BYTES + 1)
    except (HTTPException, OSError, TimeoutError, ValueError):
        raise TiingoEodCaptureError("Tiingo request failed") from None
    finally:
        connection.close()
    if len(payload) > MAX_TIINGO_RESPONSE_BYTES:
        raise TiingoEodCaptureError("Tiingo response exceeded the capture limit")
    return TiingoEodApiResponse(status=response.status, payload=payload)


def _request(
    *,
    token: str,
    profile: TiingoEodAcquisitionProfile,
    symbol: str,
) -> TiingoEodApiRequest:
    url = profile.endpoint_template.format(symbol=quote(symbol, safe=""))
    query = urlencode(
        {
            "endDate": profile.scope.end_date.isoformat(),
            "format": "json",
            "startDate": profile.scope.start_date.isoformat(),
        }
    )
    return TiingoEodApiRequest(
        symbol=symbol,
        profile_contract_sha256=profile.contract_sha256,
        url=f"{url}?{query}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Token {token}",
            "User-Agent": "AutoQuantTrader/0.1",
        },
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    try:
        require_utc(value, "capture clock")
    except ValueError as error:
        raise TiingoEodCaptureError("capture clock must return UTC") from error
    return value


def _repository_path(repository_root: Path) -> Path:
    repository = Path(os.path.abspath(repository_root))
    descriptor = _open_existing_directory(repository, kind="repository root")
    os.close(descriptor)
    _validate_existing_capture_prefix(repository)
    return repository


def _open_existing_directory(path: Path, *, kind: str) -> int:
    try:
        descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    except OSError as error:
        raise TiingoEodCaptureError(f"cannot open the {kind}") from error
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise TiingoEodCaptureError(
            f"the {kind} path cannot contain symlinks or non-directories"
        ) from error
    return descriptor


def _validate_existing_capture_prefix(repository_root: Path) -> None:
    """Reject an unsafe existing fixed-root prefix without creating directories."""

    descriptor = _open_existing_directory(repository_root, kind="repository root")
    try:
        for part in TIINGO_EOD_CAPTURE_RELATIVE_ROOT.parts:
            try:
                next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                return
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                os.close(next_descriptor)
                raise TiingoEodCaptureError("existing capture root directories must be owner-only")
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        raise TiingoEodCaptureError(
            "the fixed capture root cannot contain symlinks or non-directories"
        ) from error
    finally:
        os.close(descriptor)


def _open_capture_root(repository_root: Path) -> int:
    descriptor = _open_existing_directory(repository_root, kind="repository root")
    try:
        for part in TIINGO_EOD_CAPTURE_RELATIVE_ROOT.parts:
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                os.close(next_descriptor)
                raise TiingoEodCaptureError(
                    "capture root directories must be owner-only (chmod 700)"
                )
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise TiingoEodCaptureError(
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
        raise TiingoEodCaptureError("cannot write an immutable capture object") from error


@dataclass(frozen=True, slots=True)
class _CapturedResponse:
    symbol: str
    requested_at: datetime
    received_at: datetime
    payload: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _PreparedCapture:
    objects: tuple[tuple[str, bytes], ...]
    manifest_bytes: bytes


def _prepare_capture(
    responses: tuple[_CapturedResponse, ...],
    *,
    profile: TiingoEodAcquisitionProfile,
    authorization_sha256: str,
    terms_sha256: str,
) -> _PreparedCapture:
    receipts: list[TiingoEodCaptureReceipt] = []
    objects: dict[str, bytes] = {}
    for response in responses:
        digest = hashlib.sha256(response.payload).hexdigest()
        object_name = f"{digest}.json"
        previous_payload = objects.get(object_name)
        if previous_payload is None:
            objects[object_name] = response.payload
        elif previous_payload != response.payload:  # pragma: no cover - SHA-256 collision guard
            raise TiingoEodCaptureError("capture digest collision detected")
        receipts.append(
            TiingoEodCaptureReceipt(
                symbol=response.symbol,
                object_path=f"objects/{object_name}",
                sha256=digest,
                byte_count=len(response.payload),
                requested_at=response.requested_at,
                received_at=response.received_at,
            )
        )
    manifest = TiingoEodCaptureManifest(
        profile=profile,
        profile_contract_sha256=profile.contract_sha256,
        responses=tuple(receipts),
        requested_at=receipts[0].requested_at,
        received_at=receipts[-1].received_at,
        authorization_sha256=authorization_sha256,
        terms_sha256=terms_sha256,
    )
    manifest_bytes = manifest.to_json_bytes()
    if len(manifest_bytes) > MAX_TIINGO_MANIFEST_BYTES:
        raise TiingoEodCaptureError("capture manifest exceeds the size limit")
    return _PreparedCapture(objects=tuple(objects.items()), manifest_bytes=manifest_bytes)


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is not None:
        with suppress(OSError):
            os.close(descriptor)


def _best_effort_remove_staging(
    root_descriptor: int,
    staging_name: str,
    *,
    object_names: tuple[str, ...],
) -> None:
    """Remove only the known staging tree without following path-component symlinks."""

    staging_descriptor: int | None = None
    objects_descriptor: int | None = None
    try:
        staging_descriptor = os.open(staging_name, _DIRECTORY_FLAGS, dir_fd=root_descriptor)
    except OSError:
        return
    try:
        with suppress(OSError):
            os.fchmod(staging_descriptor, 0o700)
        try:
            objects_descriptor = os.open("objects", _DIRECTORY_FLAGS, dir_fd=staging_descriptor)
        except OSError:
            objects_descriptor = None
        if objects_descriptor is not None:
            with suppress(OSError):
                os.fchmod(objects_descriptor, 0o700)
            for object_name in object_names:
                with suppress(OSError):
                    os.unlink(object_name, dir_fd=objects_descriptor)
            _close_descriptor(objects_descriptor)
            objects_descriptor = None
            with suppress(OSError):
                os.rmdir("objects", dir_fd=staging_descriptor)
        with suppress(OSError):
            os.unlink("manifest.json", dir_fd=staging_descriptor)
    finally:
        _close_descriptor(objects_descriptor)
        _close_descriptor(staging_descriptor)
    with suppress(OSError):
        os.rmdir(staging_name, dir_fd=root_descriptor)


def _final_entry_exists(root_descriptor: int, capture_name: str) -> bool:
    try:
        os.stat(capture_name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise TiingoEodCaptureError("cannot inspect the final capture destination") from error
    return True


def _acquire_publish_lock(root_descriptor: int, capture_name: str) -> tuple[int, str]:
    lock_name = f".publish-{capture_name}.lock"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_name, flags, 0o400, dir_fd=root_descriptor)
    except FileExistsError:
        raise TiingoEodCaptureError(
            "another capture owns the immutable final-name reservation"
        ) from None
    except OSError as error:
        raise TiingoEodCaptureError("cannot reserve the immutable final capture name") from error
    return descriptor, lock_name


def _best_effort_release_publish_lock(
    root_descriptor: int,
    lock_descriptor: int | None,
    lock_name: str | None,
) -> None:
    _close_descriptor(lock_descriptor)
    if lock_name is not None:
        with suppress(OSError):
            os.unlink(lock_name, dir_fd=root_descriptor)


def _publish_capture(
    repository: Path,
    *,
    capture_name: str,
    prepared: _PreparedCapture,
) -> None:
    staging_name = f".staging-{capture_name}-{secrets.token_hex(8)}"
    root_descriptor = _open_capture_root(repository)
    lock_descriptor: int | None = None
    lock_name: str | None = None
    staging_descriptor: int | None = None
    objects_descriptor: int | None = None
    staging_created = False
    object_names = tuple(name for name, _ in prepared.objects)
    try:
        lock_descriptor, lock_name = _acquire_publish_lock(root_descriptor, capture_name)
        if _final_entry_exists(root_descriptor, capture_name):
            raise TiingoEodCaptureError("an immutable capture already uses the final name")
        os.mkdir(staging_name, mode=0o700, dir_fd=root_descriptor)
        staging_created = True
        staging_descriptor = os.open(staging_name, _DIRECTORY_FLAGS, dir_fd=root_descriptor)
        os.mkdir("objects", mode=0o700, dir_fd=staging_descriptor)
        objects_descriptor = os.open("objects", _DIRECTORY_FLAGS, dir_fd=staging_descriptor)

        for object_name, payload in prepared.objects:
            _write_exclusive(objects_descriptor, object_name, payload)
        _write_exclusive(staging_descriptor, "manifest.json", prepared.manifest_bytes)

        os.fchmod(objects_descriptor, 0o500)
        os.fchmod(staging_descriptor, 0o500)
        os.fsync(objects_descriptor)
        os.fsync(staging_descriptor)
        os.fsync(root_descriptor)

        if _final_entry_exists(root_descriptor, capture_name):
            raise TiingoEodCaptureError("an immutable capture already uses the final name")
        try:
            os.rename(
                staging_name,
                capture_name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
        except OSError:
            committed = not _final_entry_exists(
                root_descriptor,
                staging_name,
            ) and _final_entry_exists(root_descriptor, capture_name)
            if not committed:
                raise
        staging_created = False
        # Rename is the commit point. Request directory-entry durability without
        # reporting a post-commit failure that would misrepresent the published state.
        with suppress(OSError):
            os.fsync(root_descriptor)
    except BaseException as error:
        _close_descriptor(objects_descriptor)
        objects_descriptor = None
        _close_descriptor(staging_descriptor)
        staging_descriptor = None
        if staging_created:
            _best_effort_remove_staging(
                root_descriptor,
                staging_name,
                object_names=object_names,
            )
        _best_effort_release_publish_lock(root_descriptor, lock_descriptor, lock_name)
        lock_descriptor = None
        lock_name = None
        if not isinstance(error, Exception):
            raise
        if isinstance(error, TiingoEodCaptureError):
            raise
        raise TiingoEodCaptureError("cannot atomically publish the immutable capture") from error
    finally:
        _close_descriptor(objects_descriptor)
        _close_descriptor(staging_descriptor)
        _best_effort_release_publish_lock(root_descriptor, lock_descriptor, lock_name)
        _close_descriptor(root_descriptor)


def capture_tiingo_eod(
    *,
    repository_root: Path,
    token: str,
    profile: TiingoEodAcquisitionProfile,
    authorization_bytes: bytes,
    timeout_seconds: float = 15.0,
    transport: TiingoEodApiTransport = _https_get,
    clock: Callable[[], datetime] = _utc_now,
) -> Path:
    """Archive exact responses after profile-bound authorization succeeds."""

    if not isinstance(profile, TiingoEodAcquisitionProfile):
        raise TiingoEodCaptureError("Tiingo acquisition profile is invalid")
    try:
        authorization = TiingoEodCaptureAuthorization.from_json_bytes(authorization_bytes)
    except (TypeError, TiingoEodError, ValueError):
        raise TiingoEodCaptureError("capture authorization artifact is invalid") from None
    authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
    repository = _repository_path(repository_root)
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30:
        raise TiingoEodCaptureError(
            "timeout must be finite, greater than zero, and at most 30 seconds"
        )

    first_requested_at = _clock_value(clock)
    try:
        authorization.authorize(profile, requested_at=first_requested_at)
    except ValueError as error:
        raise TiingoEodCaptureError(str(error)) from error
    try:
        require_text(token, "token")
    except ValueError:
        raise TiingoEodCaptureError("TIINGO_TOKEN is not configured") from None

    captured: list[_CapturedResponse] = []
    for index, symbol in enumerate(profile.scope.symbols):
        requested_at = first_requested_at if index == 0 else _clock_value(clock)
        if captured and requested_at < captured[-1].received_at:
            raise TiingoEodCaptureError("capture clock is not monotonic")
        request = _request(token=token, profile=profile, symbol=symbol)
        try:
            api_response = transport(request, timeout_seconds=timeout_seconds)
        except Exception:
            raise TiingoEodCaptureError("Tiingo request failed") from None
        received_at = _clock_value(clock)
        if received_at < requested_at:
            raise TiingoEodCaptureError("capture clock is not monotonic")
        if not isinstance(api_response, TiingoEodApiResponse):
            raise TiingoEodCaptureError("Tiingo transport returned an invalid response")
        if not 200 <= api_response.status < 300:
            raise TiingoEodCaptureError(
                f"Tiingo returned non-success HTTP status {api_response.status}"
            )
        try:
            contract = tiingo_eod_response_contract(
                api_response.payload,
                scope=profile.scope,
            )
        except (TypeError, TiingoEodError, ValueError):
            raise TiingoEodCaptureError("Tiingo returned an invalid EOD response") from None
        if contract.schema_sha256 != profile.schema_sha256:
            raise TiingoEodCaptureError("Tiingo response does not match the acquisition profile")
        captured.append(
            _CapturedResponse(
                symbol=symbol,
                requested_at=requested_at,
                received_at=received_at,
                payload=api_response.payload,
            )
        )

    immutable_responses = tuple(captured)
    prepared = _prepare_capture(
        immutable_responses,
        profile=profile,
        authorization_sha256=authorization_sha256,
        terms_sha256=authorization.terms_sha256,
    )
    capture_name = tiingo_eod_capture_name(prepared.manifest_bytes)
    capture_dir = repository / TIINGO_EOD_CAPTURE_RELATIVE_ROOT / capture_name
    _publish_capture(repository, capture_name=capture_name, prepared=prepared)
    return capture_dir / "manifest.json"
