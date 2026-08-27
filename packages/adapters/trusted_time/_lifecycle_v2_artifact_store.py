"""Descriptor-safe injected lifecycle-v2 artifact storage.

This adapter owns only a caller-admitted, already-existing ``trusted-time``
directory.  It has no default path, creates no directory, and is not wired to
any production caller.  Every filesystem operation remains behind opaque
native descriptor owners so fork-child invalidation happens before Python can
reuse inherited authority.
"""

from __future__ import annotations

import os
import stat
import threading

from packages.adapters.trusted_time._owned_file_descriptor import (
    _create_child_regular_exclusive,
    _fchmod_0600,
    _finalize_read_child_noreplace,
    _fstat,
    _fsync,
    _list_snapshot,
    _open_child_directory,
    _open_child_regular,
    _open_root_directory,
    _OwnedFileDescriptor,
    _read_snapshot,
    _rename_child_noreplace,
    _statat,
    _write_all,
)
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
)
from packages.persistence.trusted_time_graceful_stop_v2 import (
    LifecycleV2ArtifactAlreadyExists,
    LifecycleV2ArtifactInventorySnapshot,
    LifecycleV2ArtifactPublicationReceipt,
    LifecycleV2ArtifactPublicationUncertain,
    LifecycleV2ArtifactReadback,
    LifecycleV2ArtifactStoreIdentity,
)

__all__: tuple[()] = ()

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_MAXIMUM_INVENTORY_ENTRIES = 128
_MAXIMUM_INVENTORY_NAME_BYTES = 32 * 1_024
_ROOT_MAXIMUM_BYTES = 64 * 1_024
_RECORD_MAXIMUM_BYTES = 256 * 1_024
_WIRE_MAXIMUM_BYTES = 262_144
_FIXED_MARKER_STAGING_NAME = ".post-enrollment-graceful-stop-v2-outcome-commit-staging"
_Stat9 = tuple[int, int, int, int, int, int, int, int, int]


def _exact_nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError(f"{name} must be an exact nonnegative signed-64 integer")
    return value


def _exact_owner_id(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**32 - 2:
        raise ValueError(f"{name} must be an exact native owner identifier")
    return value


def _exact_artifact_directory_path(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or not value.endswith("/trusted-time")
        or value == "/trusted-time"
        or "//" in value
        or "/./" in value
        or "/../" in value
        or "\0" in value
        or len(value.encode("utf-8")) > 4_096
    ):
        raise ValueError("artifact directory path is not one exact injected trusted-time path")
    components = value.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError("artifact directory path contains an invalid component")
    return value


def _exact_component(value: object) -> str:
    if (
        type(value) is not str
        or value in {"", ".", ".."}
        or "/" in value
        or "\0" in value
        or len(value.encode("utf-8")) > 255
    ):
        raise LifecycleV2ArtifactPublicationUncertain(
            "artifact name is not one exact bounded relative component"
        )
    return value


def _exact_stat9(value: object) -> _Stat9:
    if (
        type(value) is not tuple
        or len(value) != 9
        or any(type(field) is not int for field in value)
    ):
        raise LifecycleV2ArtifactPublicationUncertain("native identity is malformed")
    return value


def _stable_identity_core(identity: _Stat9) -> tuple[int, int, int, int, int]:
    return identity[:5]


def _maximum_bytes_for_name(file_name: str) -> int:
    if file_name == LIFECYCLE_ROOT_FILE_NAME:
        return _ROOT_MAXIMUM_BYTES
    if file_name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-"):
        return _WIRE_MAXIMUM_BYTES
    return _RECORD_MAXIMUM_BYTES


def _open_directory_path(path: str) -> _OwnedFileDescriptor:
    owner = _open_root_directory()
    try:
        for component in path.split("/")[1:]:
            next_owner = _open_child_directory(owner, component)
            owner.close()
            owner = next_owner
    except BaseException:
        owner.close()
        raise
    return owner


class _LifecycleV2PhysicalArtifactStore:
    """One process/thread-bound physical implementation of the store seam."""

    __slots__ = (
        "_artifact_directory_path",
        "_closed",
        "_directory_identity_core",
        "_directory_owner",
        "_expected_gid",
        "_expected_uid",
        "_identity",
        "_origin_pid",
        "_origin_thread",
    )

    def __init__(
        self,
        *,
        artifact_directory_path: str,
        expected_directory_device: int,
        expected_directory_inode: int,
        expected_owner_uid: int,
        expected_owner_gid: int,
    ) -> None:
        exact_path = _exact_artifact_directory_path(artifact_directory_path)
        exact_device = _exact_nonnegative_int(
            expected_directory_device,
            "expected_directory_device",
        )
        exact_inode = _exact_nonnegative_int(
            expected_directory_inode,
            "expected_directory_inode",
        )
        exact_uid = _exact_owner_id(expected_owner_uid, "expected_owner_uid")
        exact_gid = _exact_owner_id(expected_owner_gid, "expected_owner_gid")
        if exact_device == 0 or exact_inode == 0:
            raise ValueError("artifact directory device and inode must be positive")

        directory_owner = _open_directory_path(exact_path)
        try:
            identity = _exact_stat9(_fstat(directory_owner))
            if (
                not stat.S_ISDIR(identity[2])
                or stat.S_IMODE(identity[2]) != _DIRECTORY_MODE
                or identity[0] != exact_device
                or identity[1] != exact_inode
                or identity[3] != exact_uid
                or identity[4] != exact_gid
                or identity[5] < 1
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact directory identity, owner, or mode is not admitted"
                )
        except BaseException:
            directory_owner.close()
            raise

        self._artifact_directory_path = exact_path
        self._directory_owner = directory_owner
        self._directory_identity_core = _stable_identity_core(identity)
        self._expected_uid = exact_uid
        self._expected_gid = exact_gid
        self._identity = LifecycleV2ArtifactStoreIdentity(
            artifact_directory_path=exact_path,
            directory_device=identity[0],
            directory_inode=identity[1],
            owner_uid=identity[3],
            owner_gid=identity[4],
            directory_mode=stat.S_IMODE(identity[2]),
        )
        self._origin_pid = os.getpid()
        self._origin_thread = threading.current_thread()
        self._closed = False

    @property
    def identity(self) -> LifecycleV2ArtifactStoreIdentity:
        return self._identity

    @property
    def artifact_directory_path(self) -> str:
        return self._identity.artifact_directory_path

    @property
    def directory_device(self) -> int:
        return self._identity.directory_device

    @property
    def directory_inode(self) -> int:
        return self._identity.directory_inode

    @property
    def closed(self) -> bool:
        return self._closed or self._directory_owner.closed

    def _require_owner(self) -> None:
        if self._closed or os.getpid() != self._origin_pid or self._directory_owner.closed:
            self._closed = True
            raise LifecycleV2ArtifactPublicationUncertain(
                "physical artifact-store owner is invalid, closed, or forked"
            )
        if threading.current_thread() is not self._origin_thread:
            raise LifecycleV2ArtifactPublicationUncertain(
                "physical artifact-store owner thread is invalid"
            )

    def _directory_identity(self) -> _Stat9:
        held_identity = _exact_stat9(_fstat(self._directory_owner))
        rebound_owner = _open_directory_path(self._artifact_directory_path)
        try:
            rebound_identity = _exact_stat9(_fstat(rebound_owner))
        finally:
            rebound_owner.close()
        if held_identity != rebound_identity:
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact directory changed while rebinding its current path"
            )
        for identity in (held_identity, rebound_identity):
            if (
                _stable_identity_core(identity) != self._directory_identity_core
                or not stat.S_ISDIR(identity[2])
                or stat.S_IMODE(identity[2]) != _DIRECTORY_MODE
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact directory path, identity, owner, or mode drifted"
                )
        return held_identity

    def _validate_file_identity(
        self,
        identity: object,
        *,
        expected_size: int | None = None,
    ) -> _Stat9:
        exact = _exact_stat9(identity)
        if (
            exact[0] == 0
            or exact[1] == 0
            or not stat.S_ISREG(exact[2])
            or stat.S_IMODE(exact[2]) != _FILE_MODE
            or exact[3] != self._expected_uid
            or exact[4] != self._expected_gid
            or exact[5] != 1
            or exact[6] < 0
            or (expected_size is not None and exact[6] != expected_size)
        ):
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact inode, owner, mode, link count, or size is invalid"
            )
        return exact

    def _close_after_failure(self) -> None:
        self._closed = True
        if os.getpid() == self._origin_pid and not self._directory_owner.closed:
            self._directory_owner.close()

    def close(self) -> None:
        if self._closed:
            return
        if os.getpid() != self._origin_pid:
            self._closed = True
            return
        if threading.current_thread() is not self._origin_thread:
            raise LifecycleV2ArtifactPublicationUncertain(
                "physical artifact-store cleanup thread is invalid"
            )
        self._directory_owner.close()
        self._closed = True

    def inventory(self) -> LifecycleV2ArtifactInventorySnapshot:
        self._require_owner()
        try:
            names, before, after = _list_snapshot(self._directory_owner)
            exact_before = _exact_stat9(before)
            exact_after = _exact_stat9(after)
            current_identity = self._directory_identity()
            if exact_before != exact_after or exact_after != current_identity:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact directory changed during inventory"
                )
            if (
                type(names) is not tuple
                or names != tuple(sorted(names))
                or len(names) != len(frozenset(names))
                or len(names) > _MAXIMUM_INVENTORY_ENTRIES
                or sum(len(name.encode("utf-8")) for name in names) > _MAXIMUM_INVENTORY_NAME_BYTES
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact directory inventory is invalid or exceeds its bound"
                )
            for name in names:
                _exact_component(name)
            return LifecycleV2ArtifactInventorySnapshot(
                names=names,
                directory_token=exact_after,
            )
        except BaseException as error:
            self._close_after_failure()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                raise
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact directory inventory is unconfirmed"
            ) from None

    def _read_existing(self, file_name: str) -> LifecycleV2ArtifactReadback:
        maximum_bytes = _maximum_bytes_for_name(file_name)
        directory_before = self._directory_identity()
        owner = _open_child_regular(self._directory_owner, file_name)
        try:
            held_before = self._validate_file_identity(_fstat(owner))
            payload, read_before, read_after = _read_snapshot(owner, maximum_bytes)
            exact_read_before = self._validate_file_identity(
                read_before,
                expected_size=len(payload),
            )
            exact_read_after = self._validate_file_identity(
                read_after,
                expected_size=len(payload),
            )
            held_after = self._validate_file_identity(
                _fstat(owner),
                expected_size=len(payload),
            )
            named_after = self._validate_file_identity(
                _statat(self._directory_owner, file_name),
                expected_size=len(payload),
            )
            directory_after = self._directory_identity()
            if not (
                held_before == exact_read_before == exact_read_after == held_after == named_after
                and directory_before == directory_after
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact stable readback identity drifted"
                )
            return LifecycleV2ArtifactReadback(
                encoded=payload,
                file_device=held_after[0],
                file_inode=held_after[1],
                file_mode=stat.S_IMODE(held_after[2]),
                file_size=held_after[6],
                stable_readback_completed=True,
            )
        finally:
            owner.close()

    def _read_existing_or_absent(
        self,
        file_name: str,
    ) -> LifecycleV2ArtifactReadback | None:
        directory_before = self._directory_identity()
        try:
            return self._read_existing(file_name)
        except FileNotFoundError:
            directory_after = self._directory_identity()
            if directory_before != directory_after:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact absence raced with directory mutation"
                ) from None
            return None

    def _durably_revalidate_existing(
        self,
        *,
        final_name: str,
        encoded: bytes,
        initial_readback: LifecycleV2ArtifactReadback,
    ) -> LifecycleV2ArtifactReadback:
        """Fsync and revalidate one byte-identical final without replacing it."""

        if initial_readback.encoded != encoded:
            raise LifecycleV2ArtifactPublicationUncertain(
                "existing final bytes disagree before durability revalidation"
            )
        directory_before = self._directory_identity()
        owner = _open_child_regular(self._directory_owner, final_name)
        try:
            held = self._validate_file_identity(
                _fstat(owner),
                expected_size=len(encoded),
            )
            if (
                held[0] != initial_readback.file_device
                or held[1] != initial_readback.file_inode
                or stat.S_IMODE(held[2]) != initial_readback.file_mode
                or held[6] != initial_readback.file_size
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "existing final identity changed before durability revalidation"
                )
            payload, read_before, read_after = _read_snapshot(owner, len(encoded))
            named = self._validate_file_identity(
                _statat(self._directory_owner, final_name),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(
                    read_before,
                    expected_size=len(encoded),
                )
                != held
                or self._validate_file_identity(
                    read_after,
                    expected_size=len(encoded),
                )
                != held
                or named != held
                or self._directory_identity() != directory_before
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "existing final bytes or identity changed before durability fsync"
                )

            _fsync(owner)
            _fsync(self._directory_owner)

            payload, read_before, read_after = _read_snapshot(owner, len(encoded))
            held_after = self._validate_file_identity(
                _fstat(owner),
                expected_size=len(encoded),
            )
            named_after = self._validate_file_identity(
                _statat(self._directory_owner, final_name),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(
                    read_before,
                    expected_size=len(encoded),
                )
                != held
                or self._validate_file_identity(
                    read_after,
                    expected_size=len(encoded),
                )
                != held
                or held_after != held
                or named_after != held
                or self._directory_identity() != directory_before
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "existing final bytes or identity changed after durability fsync"
                )
        finally:
            owner.close()

        reopened = self._read_existing(final_name)
        if reopened != initial_readback or reopened.encoded != encoded:
            raise LifecycleV2ArtifactPublicationUncertain(
                "existing final changed during durable reopened readback"
            )
        return reopened

    def read_stable(self, file_name: str) -> LifecycleV2ArtifactReadback:
        self._require_owner()
        exact_name = _exact_component(file_name)
        try:
            return self._read_existing(exact_name)
        except BaseException as error:
            self._close_after_failure()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                raise
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact stable readback is unconfirmed"
            ) from None

    def _write_staging(
        self,
        *,
        staging_name: str,
        encoded: bytes,
    ) -> _OwnedFileDescriptor:
        if type(encoded) is not bytes or len(encoded) > _maximum_bytes_for_name(staging_name):
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact bytes are not exact or exceed their bound"
            )
        owner = _create_child_regular_exclusive(self._directory_owner, staging_name)
        try:
            _fchmod_0600(owner)
            _write_all(owner, encoded)
            self._validate_file_identity(_fstat(owner), expected_size=len(encoded))
            _fsync(owner)
            payload, before, after = _read_snapshot(owner, len(encoded))
            held = self._validate_file_identity(_fstat(owner), expected_size=len(encoded))
            named = self._validate_file_identity(
                _statat(self._directory_owner, staging_name),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(before, expected_size=len(encoded)) != held
                or self._validate_file_identity(after, expected_size=len(encoded)) != held
                or named != held
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "staging artifact write or identity is unstable"
                )
            return owner
        except BaseException:
            owner.close()
            raise

    @staticmethod
    def _publication_receipt(
        *,
        final_name: str,
        readback: LifecycleV2ArtifactReadback,
        file_fsync_completed: bool,
        no_replace_rename_completed: bool,
        directory_fsync_completed: bool,
        existing_final_revalidated: bool,
    ) -> LifecycleV2ArtifactPublicationReceipt:
        return LifecycleV2ArtifactPublicationReceipt(
            final_name=final_name,
            final_device=readback.file_device,
            final_inode=readback.file_inode,
            final_mode=readback.file_mode,
            final_size=readback.file_size,
            file_fsync_completed=file_fsync_completed,
            no_replace_rename_completed=no_replace_rename_completed,
            directory_fsync_completed=directory_fsync_completed,
            stable_readback_completed=readback.stable_readback_completed,
            existing_final_revalidated=existing_final_revalidated,
        )

    def create_root_exclusive(
        self,
        file_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt:
        self._require_owner()
        exact_name = _exact_component(file_name)
        if exact_name != LIFECYCLE_ROOT_FILE_NAME:
            raise LifecycleV2ArtifactPublicationUncertain("root name is not exact")
        owner: _OwnedFileDescriptor | None = None
        try:
            self._directory_identity()
            owner = self._write_staging(staging_name=exact_name, encoded=encoded)
            _fsync(self._directory_owner)
            owner.close()
            owner = None
            readback = self._read_existing(exact_name)
            if readback.encoded != encoded:
                raise LifecycleV2ArtifactPublicationUncertain("root stable readback bytes disagree")
            return self._publication_receipt(
                final_name=exact_name,
                readback=readback,
                file_fsync_completed=True,
                no_replace_rename_completed=False,
                directory_fsync_completed=True,
                existing_final_revalidated=False,
            )
        except FileExistsError as error:
            raise LifecycleV2ArtifactAlreadyExists(exact_name) from error
        except BaseException as error:
            self._close_after_failure()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactAlreadyExists):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                raise
            raise LifecycleV2ArtifactPublicationUncertain(
                "root publication is unconfirmed"
            ) from None
        finally:
            if owner is not None:
                owner.close()

    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt:
        self._require_owner()
        exact_staging = _exact_component(staging_name)
        exact_final = _exact_component(final_name)
        if exact_staging == exact_final or type(encoded) is not bytes:
            raise LifecycleV2ArtifactPublicationUncertain(
                "immutable publication arguments are not exact"
            )
        owner: _OwnedFileDescriptor | None = None
        try:
            if self._read_existing_or_absent(exact_staging) is not None:
                raise LifecycleV2ArtifactAlreadyExists(exact_staging)
            existing = self._read_existing_or_absent(exact_final)
            if existing is not None:
                if existing.encoded == encoded:
                    if self._read_existing_or_absent(exact_staging) is not None:
                        raise LifecycleV2ArtifactPublicationUncertain(
                            "staging appeared during existing-final revalidation"
                        )
                    revalidated = self._durably_revalidate_existing(
                        final_name=exact_final,
                        encoded=encoded,
                        initial_readback=existing,
                    )
                    if self._read_existing_or_absent(exact_staging) is not None:
                        raise LifecycleV2ArtifactPublicationUncertain(
                            "staging appeared during durable existing-final revalidation"
                        )
                    return self._publication_receipt(
                        final_name=exact_final,
                        readback=revalidated,
                        file_fsync_completed=True,
                        no_replace_rename_completed=False,
                        directory_fsync_completed=True,
                        existing_final_revalidated=True,
                    )
                raise LifecycleV2ArtifactAlreadyExists(exact_final)

            owner = self._write_staging(staging_name=exact_staging, encoded=encoded)
            try:
                _rename_child_noreplace(
                    self._directory_owner,
                    owner,
                    exact_staging,
                    exact_final,
                )
            except FileExistsError as error:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "no-replace publication raced with an existing final artifact"
                ) from error
            _fsync(self._directory_owner)
            payload, before, after = _read_snapshot(owner, len(encoded))
            held = self._validate_file_identity(_fstat(owner), expected_size=len(encoded))
            named = self._validate_file_identity(
                _statat(self._directory_owner, exact_final),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(before, expected_size=len(encoded)) != held
                or self._validate_file_identity(after, expected_size=len(encoded)) != held
                or named != held
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "renamed artifact readback is unstable"
                )
            owner.close()
            owner = None
            readback = self._read_existing(exact_final)
            if readback.encoded != encoded:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "immutable publication stable readback bytes disagree"
                )
            return self._publication_receipt(
                final_name=exact_final,
                readback=readback,
                file_fsync_completed=True,
                no_replace_rename_completed=True,
                directory_fsync_completed=True,
                existing_final_revalidated=False,
            )
        except LifecycleV2ArtifactAlreadyExists:
            raise
        except BaseException as error:
            self._close_after_failure()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                raise
            raise LifecycleV2ArtifactPublicationUncertain(
                "immutable publication is unconfirmed"
            ) from None
        finally:
            if owner is not None:
                owner.close()

    def finalize_preallocated_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt:
        """Revalidate and finish only one exact pre-existing staging preimage."""

        self._require_owner()
        exact_staging = _exact_component(staging_name)
        exact_final = _exact_component(final_name)
        if (
            exact_staging != _FIXED_MARKER_STAGING_NAME
            or exact_final != LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME
            or type(encoded) is not bytes
        ):
            raise LifecycleV2ArtifactPublicationUncertain(
                "preallocated finalization is not the exact fixed-marker protocol"
            )
        owner: _OwnedFileDescriptor | None = None
        try:
            existing_final = self._read_existing_or_absent(exact_final)
            existing_staging = self._read_existing_or_absent(exact_staging)
            if existing_final is not None:
                if existing_final.encoded != encoded or (
                    existing_staging is not None and existing_staging.encoded != encoded
                ):
                    raise LifecycleV2ArtifactPublicationUncertain(
                        "preallocated staging/final bytes conflict"
                    )
                if (
                    existing_staging is not None
                    and self._read_existing(exact_staging) != existing_staging
                ):
                    raise LifecycleV2ArtifactPublicationUncertain(
                        "preallocated staging changed during revalidation"
                    )
                revalidated = self._durably_revalidate_existing(
                    final_name=exact_final,
                    encoded=encoded,
                    initial_readback=existing_final,
                )
                if (
                    existing_staging is not None
                    and self._read_existing(exact_staging) != existing_staging
                ):
                    raise LifecycleV2ArtifactPublicationUncertain(
                        "preallocated staging changed during durable revalidation"
                    )
                return self._publication_receipt(
                    final_name=exact_final,
                    readback=revalidated,
                    file_fsync_completed=True,
                    no_replace_rename_completed=False,
                    directory_fsync_completed=True,
                    existing_final_revalidated=True,
                )
            if existing_staging is None or existing_staging.encoded != encoded:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "exact preallocated staging bytes are absent"
                )
            owner = _open_child_regular(self._directory_owner, exact_staging)
            held = self._validate_file_identity(
                _fstat(owner),
                expected_size=len(encoded),
            )
            if held[0] != existing_staging.file_device or held[1] != existing_staging.file_inode:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "preallocated staging identity changed"
                )
            _fsync(owner)
            payload, before, after = _read_snapshot(owner, len(encoded))
            named = self._validate_file_identity(
                _statat(self._directory_owner, exact_staging),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(before, expected_size=len(encoded)) != held
                or self._validate_file_identity(after, expected_size=len(encoded)) != held
                or named != held
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "preallocated staging bytes or identity changed"
                )
            try:
                _finalize_read_child_noreplace(
                    self._directory_owner,
                    owner,
                    exact_staging,
                    exact_final,
                )
            except FileExistsError as error:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "preallocated finalization raced with an existing marker"
                ) from error
            _fsync(self._directory_owner)
            payload, before, after = _read_snapshot(owner, len(encoded))
            held = self._validate_file_identity(
                _fstat(owner),
                expected_size=len(encoded),
            )
            named = self._validate_file_identity(
                _statat(self._directory_owner, exact_final),
                expected_size=len(encoded),
            )
            if (
                payload != encoded
                or self._validate_file_identity(before, expected_size=len(encoded)) != held
                or self._validate_file_identity(after, expected_size=len(encoded)) != held
                or named != held
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "finalized preallocated artifact is unstable"
                )
            owner.close()
            owner = None
            readback = self._read_existing(exact_final)
            if readback.encoded != encoded:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "finalized preallocated bytes disagree"
                )
            return self._publication_receipt(
                final_name=exact_final,
                readback=readback,
                file_fsync_completed=True,
                no_replace_rename_completed=True,
                directory_fsync_completed=True,
                existing_final_revalidated=False,
            )
        except BaseException as error:
            self._close_after_failure()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                raise
            raise LifecycleV2ArtifactPublicationUncertain(
                "preallocated immutable finalization is unconfirmed"
            ) from None
        finally:
            if owner is not None:
                owner.close()


def _open_injected_lifecycle_v2_physical_artifact_store(
    *,
    artifact_directory_path: str,
    expected_directory_device: int,
    expected_directory_inode: int,
    expected_owner_uid: int,
    expected_owner_gid: int,
) -> _LifecycleV2PhysicalArtifactStore:
    """Open one caller-admitted directory; there is deliberately no default root."""

    return _LifecycleV2PhysicalArtifactStore(
        artifact_directory_path=artifact_directory_path,
        expected_directory_device=expected_directory_device,
        expected_directory_inode=expected_directory_inode,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )


def lifecycle_v2_physical_store_non_authority_facts() -> dict[str, bool]:
    return {
        "default_artifact_root_present": False,
        "production_caller_present": False,
        "effect_authority_present": False,
        "recovery_signer_present": False,
        "confirmed_success_writer_present": False,
    }
