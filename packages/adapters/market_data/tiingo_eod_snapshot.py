"""Descriptor-safe, offline verification of immutable Tiingo EOD captures.

The verifier reads only a named, finalized capture beneath the repository's
fixed ignored capture root. It never reads credentials, performs network I/O,
assigns vendor publication timestamps, or constructs revision lineage.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_MANIFEST_BYTES,
    MAX_TIINGO_RESPONSE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodCaptureManifest,
    TiingoEodError,
    TiingoEodResponseObservation,
    TiingoEodRow,
    _parse_response,
    tiingo_eod_response_contract,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    TiingoEodPinnedCalendarArtifact,
)
from packages.adapters.market_data.tiingo_eod_capture_identity import (
    TIINGO_EOD_FINAL_CAPTURE_NAME_PATTERN,
    tiingo_eod_capture_name,
)
from packages.market_data import ExchangeCalendar, ExchangeSession
from packages.market_data.models import require_digest, require_text

TIINGO_EOD_VERIFIED_RESEARCH_SCHEMA_VERSION = "tiingo-eod-verified-research-v2"
TIINGO_EOD_CAPTURE_RELATIVE_PARTS = (".local", "vendor-snapshots", "tiingo-eod")

_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_CAPTURE_DIRECTORY_MODE = 0o500
_CAPTURE_FILE_MODE = 0o400


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _calendar_binding_material(
    *,
    symbol: str,
    authority: str,
    calendar_id: str,
    calendar_version: str,
    venue: str,
    timezone: str,
    sessions: tuple[ExchangeSession, ...],
) -> dict[str, object]:
    return {
        "authority": authority,
        "calendar_id": calendar_id,
        "sessions": [
            {
                "closes_at": session.closes_at.isoformat(),
                "kind": session.kind.value,
                "opens_at": session.opens_at.isoformat(),
                "session_label": session.session_label.isoformat(),
                "venue": session.venue,
            }
            for session in sessions
        ],
        "symbol": symbol,
        "timezone": timezone,
        "venue": venue,
        "version": calendar_version,
    }


@dataclass(frozen=True, slots=True)
class TiingoEodCalendarBinding:
    """One symbol's explicit, reviewed-artifact calendar identity."""

    symbol: str
    authority: str
    calendar_id: str
    calendar_version: str
    venue: str
    timezone: str
    calendar_sha256: str
    sessions: tuple[ExchangeSession, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.symbol, "symbol"),
            (self.authority, "authority"),
            (self.calendar_id, "calendar_id"),
            (self.calendar_version, "calendar_version"),
            (self.venue, "venue"),
            (self.timezone, "timezone"),
        ):
            require_text(value, field_name)
        require_digest(self.calendar_sha256, "calendar_sha256")
        if type(self.sessions) is not tuple or not self.sessions:
            raise ValueError("calendar binding sessions must be an immutable non-empty tuple")
        try:
            ExchangeCalendar(
                calendar_id=self.calendar_id,
                version=self.calendar_version,
                venue=self.venue,
                timezone=self.timezone,
                sessions=self.sessions,
            )
        except ValueError as error:
            raise ValueError(f"calendar binding sessions are invalid: {error}") from error
        expected_sha256 = _digest(
            _calendar_binding_material(
                symbol=self.symbol,
                authority=self.authority,
                calendar_id=self.calendar_id,
                calendar_version=self.calendar_version,
                venue=self.venue,
                timezone=self.timezone,
                sessions=self.sessions,
            )
        )
        if self.calendar_sha256 != expected_sha256:
            raise ValueError("calendar binding digest does not match its exact sessions")

    @property
    def session_dates(self) -> tuple[date, ...]:
        return tuple(session.session_label for session in self.sessions)


def _verified_research_semantic_sha256(
    *,
    manifest: TiingoEodCaptureManifest,
    capture_sha256: str,
    calendar_artifact_sha256: str,
    calendar_bindings: tuple[TiingoEodCalendarBinding, ...],
) -> str:
    return _digest(
        {
            "calendar_bindings": [
                {
                    "authority": binding.authority,
                    "calendar_id": binding.calendar_id,
                    "calendar_sha256": binding.calendar_sha256,
                    "calendar_version": binding.calendar_version,
                    "symbol": binding.symbol,
                    "timezone": binding.timezone,
                    "venue": binding.venue,
                }
                for binding in calendar_bindings
            ],
            "calendar_artifact_sha256": calendar_artifact_sha256,
            "capture_sha256": capture_sha256,
            "profile_contract_sha256": manifest.profile_contract_sha256,
            "schema_version": TIINGO_EOD_VERIFIED_RESEARCH_SCHEMA_VERSION,
        }
    )


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodVerifiedResearchSnapshot:
    """Verified provider observations that are permanently non-admitting."""

    manifest: TiingoEodCaptureManifest
    capture_sha256: str
    calendar_artifact_sha256: str
    calendar_artifact: TiingoEodPinnedCalendarArtifact
    calendar_bindings: tuple[TiingoEodCalendarBinding, ...]
    semantic_sha256: str
    observations: tuple[TiingoEodResponseObservation, ...]
    rows: tuple[TiingoEodRow, ...]
    schema_version: str = TIINGO_EOD_VERIFIED_RESEARCH_SCHEMA_VERSION

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "verified Tiingo EOD research snapshots can only be created by the verifier"
        )

    @classmethod
    def _from_verified_components(
        cls,
        *,
        manifest: TiingoEodCaptureManifest,
        capture_sha256: str,
        calendar_artifact: TiingoEodPinnedCalendarArtifact,
        calendar_bindings: tuple[TiingoEodCalendarBinding, ...],
        semantic_sha256: str,
        observations: tuple[TiingoEodResponseObservation, ...],
        rows: tuple[TiingoEodRow, ...],
        schema_version: str = TIINGO_EOD_VERIFIED_RESEARCH_SCHEMA_VERSION,
    ) -> TiingoEodVerifiedResearchSnapshot:
        if cls is not TiingoEodVerifiedResearchSnapshot:
            raise TypeError("verified snapshot subclasses are not supported")
        if type(calendar_artifact) is not TiingoEodPinnedCalendarArtifact:
            raise ValueError("verified snapshot requires the exact pinned calendar artifact")
        snapshot = object.__new__(cls)
        for field_name, value in (
            ("manifest", manifest),
            ("capture_sha256", capture_sha256),
            ("calendar_artifact_sha256", calendar_artifact.artifact_sha256),
            ("calendar_artifact", calendar_artifact),
            ("calendar_bindings", calendar_bindings),
            ("semantic_sha256", semantic_sha256),
            ("observations", observations),
            ("rows", rows),
            ("schema_version", schema_version),
        ):
            object.__setattr__(snapshot, field_name, value)
        snapshot.__post_init__()
        return snapshot

    def __post_init__(self) -> None:
        if type(self.manifest) is not TiingoEodCaptureManifest:
            raise ValueError("verified snapshot requires an exact Tiingo capture manifest")
        require_digest(self.capture_sha256, "capture_sha256")
        require_digest(self.calendar_artifact_sha256, "calendar_artifact_sha256")
        require_digest(self.semantic_sha256, "semantic_sha256")
        if type(self.calendar_artifact) is not TiingoEodPinnedCalendarArtifact:
            raise ValueError("verified snapshot requires the exact pinned calendar artifact")
        if self.schema_version != TIINGO_EOD_VERIFIED_RESEARCH_SCHEMA_VERSION:
            raise ValueError("unsupported verified Tiingo EOD research schema")
        expected_capture_sha256 = hashlib.sha256(self.manifest.to_json_bytes()).hexdigest()
        if self.capture_sha256 != expected_capture_sha256:
            raise ValueError("capture digest does not match the canonical manifest")
        if self.calendar_artifact_sha256 != self.manifest.calendar_artifact_sha256:
            raise ValueError("calendar artifact digest does not match the capture manifest")
        if self.calendar_artifact.artifact_sha256 != self.calendar_artifact_sha256:
            raise ValueError("calendar artifact digest does not match its exact canonical bytes")
        try:
            self.calendar_artifact.authorize(
                self.manifest.profile,
                requested_at=self.manifest.requested_at,
            )
        except ValueError as error:
            raise ValueError(
                f"calendar artifact is not authorized for the snapshot: {error}"
            ) from error
        expected_symbols = self.manifest.profile.scope.symbols
        if (
            type(self.calendar_bindings) is not tuple
            or any(
                type(binding) is not TiingoEodCalendarBinding for binding in self.calendar_bindings
            )
            or tuple(binding.symbol for binding in self.calendar_bindings) != expected_symbols
        ):
            raise ValueError("calendar bindings must exactly match sorted profile symbols")
        if any(
            binding.authority != self.manifest.profile.calendar_authority
            for binding in self.calendar_bindings
        ):
            raise ValueError("calendar binding authority does not match the capture profile")
        expected_bindings = tuple(
            _calendar_binding(
                symbol=symbol,
                authority=self.manifest.profile.calendar_authority,
                calendar=self.calendar_artifact.calendars_by_symbol[symbol],
            )[0]
            for symbol in expected_symbols
        )
        if self.calendar_bindings != expected_bindings:
            raise ValueError("calendar bindings are not exactly derived from the pinned artifact")
        if (
            type(self.observations) is not tuple
            or any(
                type(observation) is not TiingoEodResponseObservation
                for observation in self.observations
            )
            or tuple(observation.symbol for observation in self.observations) != expected_symbols
        ):
            raise ValueError("response observations must exactly match sorted profile symbols")
        for observation, receipt in zip(
            self.observations,
            self.manifest.responses,
            strict=True,
        ):
            if (
                observation.requested_at != receipt.requested_at
                or observation.received_at != receipt.received_at
                or len(observation.payload) != receipt.byte_count
                or hashlib.sha256(observation.payload).hexdigest() != receipt.sha256
            ):
                raise ValueError("response observation does not match its manifest receipt")
        if type(self.rows) is not tuple or any(type(row) is not TiingoEodRow for row in self.rows):
            raise ValueError("verified snapshot rows must be an immutable exact Tiingo row tuple")
        expected_rows: list[TiingoEodRow] = []
        for binding, observation in zip(
            self.calendar_bindings,
            self.observations,
            strict=True,
        ):
            calendar = ExchangeCalendar(
                calendar_id=binding.calendar_id,
                version=binding.calendar_version,
                venue=binding.venue,
                timezone=binding.timezone,
                sessions=binding.sessions,
            )
            parsed_rows = _parse_response(
                observation,
                scope=self.manifest.profile.scope,
                calendar=calendar,
            )
            if tuple(sorted(row.session_label for row in parsed_rows)) != binding.session_dates:
                raise ValueError(
                    "response observations do not exactly cover their bound calendar sessions"
                )
            expected_rows.extend(parsed_rows)
        expected_rows.sort(key=lambda row: (row.symbol, row.session_label))
        if self.rows != tuple(expected_rows):
            raise ValueError(
                "verified rows must be exactly derived from the response observations "
                "and bound calendar sessions"
            )
        expected_semantic_sha256 = _verified_research_semantic_sha256(
            manifest=self.manifest,
            capture_sha256=self.capture_sha256,
            calendar_artifact_sha256=self.calendar_artifact_sha256,
            calendar_bindings=self.calendar_bindings,
        )
        if self.semantic_sha256 != expected_semantic_sha256:
            raise ValueError("semantic digest does not match the verified snapshot proofs")

    @property
    def manifest_sha256(self) -> str:
        return self.capture_sha256

    def raw_bar_records(self) -> NoReturn:
        raise TiingoEodError(
            "verified Tiingo captures contain receipt-time research observations, not "
            "vendor publication timestamps or historical revisions; canonical bar "
            "conversion is unavailable"
        )

    def canonical_bar_records(self) -> NoReturn:
        raise TiingoEodError("verified Tiingo research observations cannot become canonical bars")

    def admission_evidence(self) -> NoReturn:
        raise TiingoEodError(
            "verified Tiingo research snapshots are permanently non-admitting and have "
            "no trading effect"
        )

    def revision_lineage(self) -> NoReturn:
        raise TiingoEodError(
            "one Tiingo capture cannot establish vendor publication or revision lineage"
        )

    def historical_bar_source(self) -> NoReturn:
        raise TiingoEodError(
            "verified Tiingo research snapshots cannot become a HistoricalBarSource"
        )


def _validate_capture_name(capture_name: str) -> None:
    if not isinstance(capture_name, str):
        raise TiingoEodError("capture_name must be a string")
    if (
        capture_name.startswith((".staging-", ".publish-"))
        or capture_name.endswith(".lock")
        or TIINGO_EOD_FINAL_CAPTURE_NAME_PATTERN.fullmatch(capture_name) is None
    ):
        raise TiingoEodError("capture_name must identify one finalized Tiingo capture")


def _open_directory_chain(path: Path, *, kind: str) -> int:
    absolute = Path(os.path.abspath(path))
    try:
        descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    except OSError as error:
        raise TiingoEodError(f"cannot open the {kind}") from error
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise TiingoEodError(
            f"the {kind} path cannot contain symlinks or non-directories"
        ) from error
    return descriptor


def _require_owned_directory(
    descriptor: int,
    *,
    kind: str,
    exact_mode: int | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode):
        raise TiingoEodError(f"{kind} must be a directory")
    if metadata.st_uid != os.geteuid() or mode & 0o077:
        raise TiingoEodError(f"{kind} permissions must use an owner-only mode")
    if exact_mode is not None and mode != exact_mode:
        raise TiingoEodError(f"{kind} must use immutable mode {exact_mode:04o}")
    return metadata


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
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


def _require_directory_name_binding(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    kind: str,
) -> None:
    try:
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise TiingoEodError(f"{kind} changed after it was opened") from error
    if not stat.S_ISDIR(linked.st_mode) or _metadata_fingerprint(linked) != _metadata_fingerprint(
        expected
    ):
        raise TiingoEodError(f"{kind} name no longer identifies the opened directory")


def _require_unchanged_directory(
    descriptor: int,
    expected: os.stat_result,
    *,
    kind: str,
) -> None:
    current = _require_owned_directory(
        descriptor,
        kind=kind,
        exact_mode=_CAPTURE_DIRECTORY_MODE,
    )
    if _metadata_fingerprint(current) != _metadata_fingerprint(expected):
        raise TiingoEodError(f"{kind} changed during verification")


def _require_file_name_binding(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    kind: str,
) -> None:
    try:
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise TiingoEodError(f"{kind} changed after it was read") from error
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) != _CAPTURE_FILE_MODE
        or linked.st_nlink != 1
        or _metadata_fingerprint(linked) != _metadata_fingerprint(expected)
    ):
        raise TiingoEodError(f"{kind} name or metadata changed after it was read")


@dataclass(frozen=True, slots=True)
class _OpenedCaptureDirectory:
    root_descriptor: int
    root_metadata: os.stat_result
    capture_descriptor: int
    capture_metadata: os.stat_result


def _open_fixed_capture_root(repository_root: Path) -> tuple[int, os.stat_result]:
    descriptor = _open_directory_chain(repository_root, kind="repository root")
    metadata: os.stat_result | None = None
    try:
        for part in TIINGO_EOD_CAPTURE_RELATIVE_PARTS:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                metadata = _require_owned_directory(
                    next_descriptor,
                    kind="fixed capture root",
                )
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise TiingoEodError(
            "cannot open the fixed Tiingo capture root without following symlinks"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    if metadata is None:  # pragma: no cover - the fixed root has three components
        os.close(descriptor)
        raise AssertionError("fixed Tiingo capture root was not opened")
    return descriptor, metadata


def _require_fixed_root_path_binding(
    repository_root: Path,
    expected: os.stat_result,
) -> None:
    descriptor, current = _open_fixed_capture_root(repository_root)
    try:
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise TiingoEodError("fixed Tiingo capture root changed during verification")
    finally:
        os.close(descriptor)


def _open_capture_directory(
    repository_root: Path,
    capture_name: str,
) -> _OpenedCaptureDirectory:
    descriptor, root_metadata = _open_fixed_capture_root(repository_root)
    capture_descriptor: int | None = None
    try:
        capture_descriptor = os.open(capture_name, _DIRECTORY_FLAGS, dir_fd=descriptor)
        capture_metadata = _require_owned_directory(
            capture_descriptor,
            kind="final capture directory",
            exact_mode=_CAPTURE_DIRECTORY_MODE,
        )
        _require_directory_name_binding(
            descriptor,
            capture_name,
            capture_metadata,
            kind="final capture directory",
        )
    except OSError as error:
        if capture_descriptor is not None:
            os.close(capture_descriptor)
        os.close(descriptor)
        raise TiingoEodError(
            "cannot open a finalized capture beneath the fixed Tiingo root"
        ) from error
    except Exception:
        if capture_descriptor is not None:
            os.close(capture_descriptor)
        os.close(descriptor)
        raise
    if capture_descriptor is None:  # pragma: no cover - successful open assigns it
        raise AssertionError("capture directory was not opened")
    return _OpenedCaptureDirectory(
        root_descriptor=descriptor,
        root_metadata=root_metadata,
        capture_descriptor=capture_descriptor,
        capture_metadata=capture_metadata,
    )


def _require_exact_entries(descriptor: int, expected: set[str], *, kind: str) -> None:
    try:
        entries = os.listdir(descriptor)
    except OSError as error:
        raise TiingoEodError(f"cannot inspect {kind}") from error
    if len(entries) != len(set(entries)) or set(entries) != expected:
        raise TiingoEodError(f"{kind} contains missing, duplicate, or unknown entries")


@dataclass(frozen=True, slots=True)
class _ReadImmutableFile:
    payload: bytes
    metadata: os.stat_result


def _read_immutable_file(
    directory_descriptor: int,
    name: str,
    *,
    limit: int,
    kind: str,
) -> _ReadImmutableFile:
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TiingoEodError(f"{kind} must be a regular file")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != _CAPTURE_FILE_MODE:
            raise TiingoEodError(f"{kind} permissions must use immutable owner-only mode 0400")
        if before.st_nlink != 1:
            raise TiingoEodError(f"{kind} cannot have additional hard links")
        if before.st_size < 1 or before.st_size > limit:
            raise TiingoEodError(f"{kind} size is outside the verification limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(limit + 1)
        after = os.fstat(descriptor)
    except OSError as error:
        raise TiingoEodError(f"cannot read {kind} without following symlinks") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(payload) > limit:
        raise TiingoEodError(f"{kind} exceeds the verification limit")
    if len(payload) != before.st_size:
        raise TiingoEodError(f"{kind} changed while it was read")
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise TiingoEodError(f"{kind} changed while it was read")
    _require_file_name_binding(
        directory_descriptor,
        name,
        before,
        kind=kind,
    )
    return _ReadImmutableFile(payload=payload, metadata=before)


def _calendar_binding(
    *,
    symbol: str,
    authority: str,
    calendar: ExchangeCalendar,
) -> tuple[TiingoEodCalendarBinding, tuple[ExchangeSession, ...]]:
    sessions = calendar.sessions
    if not sessions:
        raise TiingoEodError(f"profile scope contains no pinned sessions for {symbol}")
    binding = TiingoEodCalendarBinding(
        symbol=symbol,
        authority=authority,
        calendar_id=calendar.calendar_id,
        calendar_version=calendar.version,
        venue=calendar.venue,
        timezone=calendar.timezone,
        calendar_sha256=_digest(
            _calendar_binding_material(
                symbol=symbol,
                authority=authority,
                calendar_id=calendar.calendar_id,
                calendar_version=calendar.version,
                venue=calendar.venue,
                timezone=calendar.timezone,
                sessions=sessions,
            )
        ),
        sessions=sessions,
    )
    return binding, sessions


def _verify_expectations(
    *,
    manifest: TiingoEodCaptureManifest,
    expected_profile: TiingoEodAcquisitionProfile,
    authorization_bytes: bytes,
    calendar_artifact_bytes: bytes,
) -> tuple[TiingoEodPinnedCalendarArtifact, dict[str, ExchangeCalendar]]:
    if not isinstance(expected_profile, TiingoEodAcquisitionProfile):
        raise TiingoEodError("expected_profile must be a Tiingo acquisition profile")
    if manifest.profile != expected_profile:
        raise TiingoEodError("capture profile does not exactly match the caller-pinned profile")
    if manifest.profile_contract_sha256 != expected_profile.contract_sha256:
        raise TiingoEodError("capture profile digest does not match the caller expectation")
    try:
        authorization = TiingoEodCaptureAuthorization.from_json_bytes(authorization_bytes)
    except (TypeError, ValueError) as error:
        raise TiingoEodError("expected capture authorization is invalid") from error
    if hashlib.sha256(authorization_bytes).hexdigest() != manifest.authorization_sha256:
        raise TiingoEodError("authorization artifact digest does not match the capture manifest")
    if authorization.terms_sha256 != manifest.terms_sha256:
        raise TiingoEodError("authorization terms digest does not match the capture manifest")
    try:
        authorization.authorize(expected_profile, requested_at=manifest.requested_at)
    except ValueError as error:
        raise TiingoEodError(str(error)) from error

    try:
        calendar_artifact = TiingoEodPinnedCalendarArtifact.from_json_bytes(calendar_artifact_bytes)
    except (TypeError, TiingoEodError, ValueError) as error:
        raise TiingoEodError("expected pinned calendar artifact is invalid") from error
    exact_calendar_sha256 = hashlib.sha256(calendar_artifact_bytes).hexdigest()
    if exact_calendar_sha256 != calendar_artifact.artifact_sha256:
        raise TiingoEodError("pinned calendar artifact must use its exact canonical bytes")
    if exact_calendar_sha256 != manifest.calendar_artifact_sha256:
        raise TiingoEodError("calendar artifact digest does not match the capture manifest")
    try:
        calendar_artifact.authorize(expected_profile, requested_at=manifest.requested_at)
    except ValueError as error:
        raise TiingoEodError(str(error)) from error
    calendars = dict(calendar_artifact.calendars_by_symbol)
    if tuple(sorted(calendars)) != expected_profile.scope.symbols:
        raise TiingoEodError("calendar artifact must exactly cover the pinned profile symbols")
    if any(not isinstance(calendar, ExchangeCalendar) for calendar in calendars.values()):
        raise TiingoEodError("calendar artifact contains an invalid pinned exchange calendar")
    return calendar_artifact, calendars


def _revalidate_capture_tree(
    *,
    repository_root: Path,
    capture_name: str,
    opened_capture: _OpenedCaptureDirectory,
    capture_entries: set[str],
    manifest_metadata: os.stat_result,
    objects_descriptor: int,
    objects_metadata: os.stat_result,
    expected_object_names: set[str],
    object_metadata_by_name: Mapping[str, os.stat_result],
) -> None:
    for object_name in sorted(expected_object_names):
        _require_file_name_binding(
            objects_descriptor,
            object_name,
            object_metadata_by_name[object_name],
            kind=f"capture response object {object_name}",
        )
    _require_file_name_binding(
        opened_capture.capture_descriptor,
        "manifest.json",
        manifest_metadata,
        kind="capture manifest",
    )
    _require_exact_entries(
        objects_descriptor,
        expected_object_names,
        kind="capture objects directory",
    )
    _require_unchanged_directory(
        objects_descriptor,
        objects_metadata,
        kind="capture objects directory",
    )
    _require_directory_name_binding(
        opened_capture.capture_descriptor,
        "objects",
        objects_metadata,
        kind="capture objects directory",
    )
    _require_exact_entries(
        opened_capture.capture_descriptor,
        capture_entries,
        kind="final capture directory",
    )
    _require_unchanged_directory(
        opened_capture.capture_descriptor,
        opened_capture.capture_metadata,
        kind="final capture directory",
    )
    _require_directory_name_binding(
        opened_capture.root_descriptor,
        capture_name,
        opened_capture.capture_metadata,
        kind="final capture directory",
    )
    _require_fixed_root_path_binding(repository_root, opened_capture.root_metadata)


def verify_tiingo_eod_capture(
    *,
    repository_root: Path,
    capture_name: str,
    expected_profile: TiingoEodAcquisitionProfile,
    authorization_bytes: bytes,
    calendar_artifact_bytes: bytes,
) -> TiingoEodVerifiedResearchSnapshot:
    """Verify one final exact-byte capture entirely offline and fail closed."""

    _validate_capture_name(capture_name)
    opened_capture = _open_capture_directory(repository_root, capture_name)
    root_descriptor = opened_capture.root_descriptor
    capture_descriptor = opened_capture.capture_descriptor
    objects_descriptor: int | None = None
    capture_entries = {"manifest.json", "objects"}
    try:
        _require_exact_entries(
            capture_descriptor,
            capture_entries,
            kind="final capture directory",
        )
        manifest_read = _read_immutable_file(
            capture_descriptor,
            "manifest.json",
            limit=MAX_TIINGO_MANIFEST_BYTES,
            kind="capture manifest",
        )
        manifest_bytes = manifest_read.payload
        manifest = TiingoEodCaptureManifest.from_json_bytes(manifest_bytes)
        if manifest.to_json_bytes() != manifest_bytes:
            raise TiingoEodError("capture manifest is not in the canonical frozen encoding")
        if tiingo_eod_capture_name(manifest_bytes) != capture_name:
            raise TiingoEodError("final capture name does not match its immutable manifest")
        calendar_artifact, calendars = _verify_expectations(
            manifest=manifest,
            expected_profile=expected_profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_artifact_bytes,
        )

        objects_descriptor = os.open("objects", _DIRECTORY_FLAGS, dir_fd=capture_descriptor)
        objects_metadata = _require_owned_directory(
            objects_descriptor,
            kind="capture objects directory",
            exact_mode=_CAPTURE_DIRECTORY_MODE,
        )
        _require_directory_name_binding(
            capture_descriptor,
            "objects",
            objects_metadata,
            kind="capture objects directory",
        )
        expected_object_names = {Path(receipt.object_path).name for receipt in manifest.responses}
        _require_exact_entries(
            objects_descriptor,
            expected_object_names,
            kind="capture objects directory",
        )

        bindings: list[TiingoEodCalendarBinding] = []
        response_observations: list[TiingoEodResponseObservation] = []
        rows: list[TiingoEodRow] = []
        keys: set[tuple[str, date]] = set()
        object_metadata_by_name: dict[str, os.stat_result] = {}
        for receipt in manifest.responses:
            object_name = Path(receipt.object_path).name
            object_read = _read_immutable_file(
                objects_descriptor,
                object_name,
                limit=MAX_TIINGO_RESPONSE_BYTES,
                kind=f"response object for {receipt.symbol}",
            )
            payload = object_read.payload
            previous_metadata = object_metadata_by_name.setdefault(
                object_name,
                object_read.metadata,
            )
            if _metadata_fingerprint(previous_metadata) != _metadata_fingerprint(
                object_read.metadata
            ):
                raise TiingoEodError("shared response object changed between receipt reads")
            if len(payload) != receipt.byte_count:
                raise TiingoEodError("response byte count does not match its manifest receipt")
            if hashlib.sha256(payload).hexdigest() != receipt.sha256:
                raise TiingoEodError("response digest does not match its manifest receipt")
            contract = tiingo_eod_response_contract(payload, scope=manifest.profile.scope)
            if (
                contract.response_sha256 != receipt.sha256
                or contract.byte_count != receipt.byte_count
                or contract.schema_sha256 != manifest.profile.schema_sha256
            ):
                raise TiingoEodError("response contract does not match its capture profile")

            calendar = calendars[receipt.symbol]
            binding, sessions = _calendar_binding(
                symbol=receipt.symbol,
                authority=expected_profile.calendar_authority,
                calendar=calendar,
            )
            expected_dates = tuple(session.session_label for session in sessions)
            if contract.session_dates != expected_dates:
                raise TiingoEodError(
                    f"response for {receipt.symbol} does not have required session coverage "
                    "from its pinned calendar"
                )
            bindings.append(binding)
            response_observation = TiingoEodResponseObservation(
                symbol=receipt.symbol,
                requested_at=receipt.requested_at,
                received_at=receipt.received_at,
                payload=payload,
            )
            response_observations.append(response_observation)
            for row in _parse_response(
                response_observation,
                scope=manifest.profile.scope,
                calendar=calendar,
            ):
                key = (row.symbol, row.session_label)
                if key in keys:
                    raise TiingoEodError(
                        "verified capture contains a duplicate symbol/session observation"
                    )
                keys.add(key)
                rows.append(row)

        rows.sort(key=lambda row: (row.symbol, row.session_label))
        capture_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        calendar_bindings = tuple(bindings)
        semantic_sha256 = _verified_research_semantic_sha256(
            manifest=manifest,
            capture_sha256=capture_sha256,
            calendar_artifact_sha256=calendar_artifact.artifact_sha256,
            calendar_bindings=calendar_bindings,
        )
        verified_snapshot = TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=manifest,
            capture_sha256=capture_sha256,
            calendar_artifact=calendar_artifact,
            calendar_bindings=calendar_bindings,
            semantic_sha256=semantic_sha256,
            observations=tuple(response_observations),
            rows=tuple(rows),
        )

        _revalidate_capture_tree(
            repository_root=repository_root,
            capture_name=capture_name,
            opened_capture=opened_capture,
            capture_entries=capture_entries,
            manifest_metadata=manifest_read.metadata,
            objects_descriptor=objects_descriptor,
            objects_metadata=objects_metadata,
            expected_object_names=expected_object_names,
            object_metadata_by_name=object_metadata_by_name,
        )
    except OSError as error:
        raise TiingoEodError("capture tree changed or contains an unsafe entry") from error
    finally:
        if objects_descriptor is not None:
            os.close(objects_descriptor)
        os.close(capture_descriptor)
        os.close(root_descriptor)

    return verified_snapshot


class RecordedTiingoEodResearchSnapshot:
    """Reusable configuration for strict offline verification of one capture."""

    def __init__(
        self,
        repository_root: Path,
        capture_name: str,
        *,
        expected_profile: TiingoEodAcquisitionProfile,
        authorization_bytes: bytes,
        calendar_artifact_bytes: bytes,
    ) -> None:
        self._repository_root = repository_root
        self._capture_name = capture_name
        self._expected_profile = expected_profile
        self._authorization_bytes = authorization_bytes
        self._calendar_artifact_bytes = calendar_artifact_bytes

    def verify(self) -> TiingoEodVerifiedResearchSnapshot:
        return verify_tiingo_eod_capture(
            repository_root=self._repository_root,
            capture_name=self._capture_name,
            expected_profile=self._expected_profile,
            authorization_bytes=self._authorization_bytes,
            calendar_artifact_bytes=self._calendar_artifact_bytes,
        )
