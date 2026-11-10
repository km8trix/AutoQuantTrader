from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import scripts.local_artifact as local_artifact_module
from scripts.local_artifact import read_owner_only_artifact


def write_artifact(path: Path, payload: bytes = b"reviewed\n", *, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_reader_accepts_only_supported_owner_modes(tmp_path: Path, mode: int) -> None:
    path = write_artifact(tmp_path / "artifact.json", mode=mode)

    assert read_owner_only_artifact(path, limit=64, label="review artifact") == b"reviewed\n"


@pytest.mark.parametrize("mode", [0o700, 0o640, 0o604])
def test_reader_rejects_other_modes(tmp_path: Path, mode: int) -> None:
    path = write_artifact(tmp_path / "artifact.json", mode=mode)

    with pytest.raises(ValueError, match="permissions must be owner-only"):
        read_owner_only_artifact(path, limit=64, label="review artifact")


def test_reader_rejects_hard_link_aliases(tmp_path: Path) -> None:
    path = write_artifact(tmp_path / "artifact.json")
    os.link(path, tmp_path / "artifact-alias.json")

    with pytest.raises(ValueError, match="exactly one hard link"):
        read_owner_only_artifact(path, limit=64, label="review artifact")


def test_reader_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    file_flags = vars(local_artifact_module)["_FILE_FLAGS"]
    assert nonblocking and isinstance(file_flags, int) and file_flags & nonblocking
    path = tmp_path / "artifact.json"
    os.mkfifo(path, mode=0o600)

    with pytest.raises(ValueError, match="regular file"):
        read_owner_only_artifact(path, limit=64, label="review artifact")


@pytest.mark.parametrize(
    ("payload", "limit", "message"),
    [(b"", 64, "must be non-empty"), (b"x" * 65, 64, "exceeds the size limit")],
)
def test_reader_rejects_empty_and_oversized_files(
    tmp_path: Path,
    payload: bytes,
    limit: int,
    message: str,
) -> None:
    path = write_artifact(tmp_path / "artifact.json", payload)

    with pytest.raises(ValueError, match=message):
        read_owner_only_artifact(path, limit=limit, label="review artifact")


def test_reader_rejects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_artifact(tmp_path / "artifact.json")
    actual_fstat = os.fstat
    call_count = 0

    class ChangedMetadata:
        def __init__(self, original: os.stat_result) -> None:
            self._original = original

        def __getattr__(self, name: str) -> Any:
            value = getattr(self._original, name)
            return value + 1 if name == "st_mtime_ns" else value

    def changing_fstat(descriptor: int) -> os.stat_result:
        nonlocal call_count
        call_count += 1
        metadata = actual_fstat(descriptor)
        if call_count == 2:
            return ChangedMetadata(metadata)  # type: ignore[return-value]
        return metadata

    monkeypatch.setattr("scripts.local_artifact.os.fstat", changing_fstat)

    with pytest.raises(ValueError, match="changed while it was being read"):
        read_owner_only_artifact(path, limit=64, label="review artifact")


def test_reader_validates_api_types_before_filesystem_access(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"path must be a pathlib\.Path"):
        read_owner_only_artifact(str(tmp_path), limit=64, label="review artifact")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        read_owner_only_artifact(tmp_path, limit=True, label="review artifact")
