"""Private bounded byte objects, installed durably without overwriting."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from packages.domain.research_job_contracts import MAX_OBJECT_BYTES, ObjectCodec, ObjectRef


class ResearchArtifactError(ValueError):
    """A private object failed its storage boundary; no paths are exposed."""


class LocalResearchArtifactStore:
    def __init__(self, root: Path) -> None:
        self._root = root.absolute()
        self._root.mkdir(mode=0o700, exist_ok=True)
        descriptor = self._directory()
        os.close(descriptor)

    def _directory(self) -> int:
        descriptor = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise ResearchArtifactError("artifact root must be private and owner-controlled")
        return descriptor

    @staticmethod
    def _limit(max_bytes: int) -> None:
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OBJECT_BYTES:
            raise ResearchArtifactError("invalid artifact size limit")

    @staticmethod
    def _read(directory: int, reference: ObjectRef, maximum: int) -> bytes:
        if reference.byte_count > maximum:
            raise ResearchArtifactError("object exceeds the requested byte bound")
        descriptor = os.open(
            reference.object_sha256 + ".json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != reference.byte_count
            ):
                raise ResearchArtifactError("object is not an exact private regular file")
            payload = stream.read(maximum + 1)
        if (
            len(payload) != reference.byte_count
            or hashlib.sha256(payload).hexdigest() != reference.object_sha256
        ):
            raise ResearchArtifactError("object bytes differ from the retained identity")
        return payload

    def read(self, reference: ObjectRef, *, max_bytes: int = MAX_OBJECT_BYTES) -> bytes:
        self._limit(max_bytes)
        if type(reference) is not ObjectRef:
            raise ResearchArtifactError("read requires an exact object reference")
        directory = self._directory()
        try:
            return self._read(directory, reference, max_bytes)
        finally:
            os.close(directory)

    def install_file(
        self,
        path: Path,
        reference: ObjectRef,
        *,
        max_bytes: int = MAX_OBJECT_BYTES,
        checkpoint: Callable[[], None],
    ) -> ObjectRef:
        """Hash/copy fixed-size chunks with control checks, then install without clobbering.

        This bounds user-space work and memory, not a stalled kernel filesystem call.
        The caller supplies its wall/lease/cancellation checks and may abort by raising.
        No report is visible to a job until the separate fenced SQL publication.
        """
        self._limit(max_bytes)
        if type(reference) is not ObjectRef or reference.byte_count > max_bytes:
            raise ResearchArtifactError("object exceeds the requested byte bound")

        def copy_checked(source: int, target: int | None) -> None:
            metadata = os.fstat(source)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != reference.byte_count
            ):
                raise ResearchArtifactError("object is not an exact private regular file")
            digest, count = hashlib.sha256(), 0
            while True:
                checkpoint()
                chunk = os.read(source, min(64 * 1024, reference.byte_count - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                if count > reference.byte_count:
                    raise ResearchArtifactError("object grew beyond its retained byte identity")
                digest.update(chunk)
                if target is not None:
                    remaining = memoryview(chunk)
                    while remaining:
                        checkpoint()
                        written = os.write(target, remaining)
                        if written <= 0:
                            raise ResearchArtifactError("object write did not progress")
                        remaining = remaining[written:]
            if count != reference.byte_count or digest.hexdigest() != reference.object_sha256:
                raise ResearchArtifactError("object bytes differ from the retained identity")

        checkpoint()
        directory = self._directory()
        temporary = ".staged-" + uuid4().hex
        created = False
        source = target = None
        try:
            source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            target = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            created = True
            copy_checked(source, target)
            checkpoint()
            os.fsync(target)
            checkpoint()
            try:
                os.link(
                    temporary,
                    reference.object_sha256 + ".json",
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = os.open(
                    reference.object_sha256 + ".json",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    copy_checked(existing, None)
                finally:
                    os.close(existing)
            checkpoint()
            os.fsync(directory)
            checkpoint()
            return reference
        finally:
            if source is not None:
                os.close(source)
            if target is not None:
                os.close(target)
            if created:
                os.unlink(temporary, dir_fd=directory)
            os.close(directory)

    def put(
        self,
        payload: bytes,
        *,
        codec_version: ObjectCodec = "personal-record/1",
        max_bytes: int = MAX_OBJECT_BYTES,
    ) -> ObjectRef:
        self._limit(max_bytes)
        if type(payload) is not bytes or not 0 < len(payload) <= max_bytes:
            raise ResearchArtifactError("object payload exceeds the byte bound")
        reference = ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload), codec_version)
        directory = self._directory()
        temporary = ".staged-" + uuid4().hex
        created = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            created = True
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(
                    temporary,
                    reference.object_sha256 + ".json",
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError:
                self._read(directory, reference, max_bytes)
            os.fsync(directory)
            return reference
        finally:
            if created:
                os.unlink(temporary, dir_fd=directory)
            os.close(directory)
