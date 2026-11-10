from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from packages.adapters.research_artifacts_v2 import (
    LocalResearchArtifactStore,
    ResearchArtifactError,
)
from packages.domain.research_job_contracts import ObjectRef


def test_private_store_is_content_addressed_no_clobber_and_restartable(tmp_path: Path) -> None:
    root = tmp_path / "objects"
    store = LocalResearchArtifactStore(root)
    reference = store.put(b'{"fixture":true}')
    assert store.put(b'{"fixture":true}') == reference
    assert LocalResearchArtifactStore(root).read(reference) == b'{"fixture":true}'
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / (reference.object_sha256 + ".json")).stat().st_mode & 0o777 == 0o600
    assert len(tuple(root.iterdir())) == 1


def test_store_rejects_size_tampering_permissions_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "objects"
    store = LocalResearchArtifactStore(root)
    reference = store.put(b"12345")
    path = root / (reference.object_sha256 + ".json")
    with pytest.raises(ResearchArtifactError):
        store.read(reference, max_bytes=4)
    with pytest.raises(ResearchArtifactError):
        store.read(replace(reference, byte_count=4))
    path.write_bytes(b"54321")
    with pytest.raises(ResearchArtifactError):
        store.read(reference)
    with pytest.raises(ResearchArtifactError):
        store.put(b"12345")
    path.unlink()
    path.symlink_to(tmp_path / "absent")
    with pytest.raises(OSError):
        store.read(reference)
    os.chmod(root, 0o755)
    with pytest.raises(ResearchArtifactError):
        store.read(reference)


def test_store_failure_cleans_staging_and_does_not_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "objects"
    store = LocalResearchArtifactStore(root)

    def failed_link(*args: object, **kwargs: object) -> None:
        raise OSError("injected link failure")

    monkeypatch.setattr(os, "link", failed_link)
    with pytest.raises(OSError):
        store.put(b"safe-fixture")
    assert tuple(root.iterdir()) == ()
    with pytest.raises(ResearchArtifactError):
        store.put(b"oversize", max_bytes=1)


def test_stream_install_checks_chunks_and_existing_bytes_without_whole_object_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalResearchArtifactStore(tmp_path / "objects")
    payload = b"bounded-fixture" * 20000
    reference = ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload))
    source = tmp_path / "child-output"
    source.write_bytes(payload)
    source.chmod(0o600)
    sizes = []
    original = os.read

    def bounded_read(descriptor, amount):
        sizes.append(amount)
        assert amount <= 65536
        return original(descriptor, amount)

    checkpoints = []
    monkeypatch.setattr(os, "read", bounded_read)
    for _ in range(2):
        assert (
            store.install_file(source, reference, checkpoint=lambda: checkpoints.append(True))
            == reference
        )
    assert len(sizes) > 10 and len(checkpoints) > len(sizes)
    assert store.read(reference) == payload
    assert len(tuple((tmp_path / "objects").iterdir())) == 1


@pytest.mark.parametrize("fault", ["cancel", "hash", "symlink", "existing-corrupt"])
def test_stream_install_failure_preserves_no_clobber_and_cleans_staging(
    tmp_path: Path,
    fault: str,
) -> None:
    root = tmp_path / "objects"
    store = LocalResearchArtifactStore(root)
    payload = b"bounded-fixture" * 20000
    reference = ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload))
    source = tmp_path / "child-output"
    source.write_bytes(payload if fault != "hash" else payload[::-1])
    source.chmod(0o600)
    if fault == "symlink":
        link = tmp_path / "link"
        link.symlink_to(source)
        source = link
    if fault == "existing-corrupt":
        store.put(payload)
        (root / (reference.object_sha256 + ".json")).write_bytes(payload[::-1])
    count = 0

    def checkpoint():
        nonlocal count
        count += 1
        if fault == "cancel" and count == 5:
            raise RuntimeError("injected cancellation between chunks")

    with pytest.raises((RuntimeError, ValueError, OSError)):
        store.install_file(source, reference, checkpoint=checkpoint)
    assert not tuple(root.glob(".staged-*"))
    assert len(tuple(root.iterdir())) == (1 if fault == "existing-corrupt" else 0)
