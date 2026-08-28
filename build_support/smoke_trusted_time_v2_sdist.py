"""Extract and validate the Wave 7 evidence closure from an sdist."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_REQUIRED_SYSTEMD = (
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "autoquant-trusted-time-graceful-stop-v2-host-provision.service"
    ),
    "infra/trusted-time/graceful-stop-v2/systemd/autoquant-trusted-time-graceful-stop-v2-host.service",
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "autoquant-trusted-time-graceful-stop-v2-recovery-provision.service"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "autoquant-trusted-time-graceful-stop-v2-recovery.service"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "autoquant-trusted-time-graceful-stop-v2-supervisor-provision.service"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "autoquant-trusted-time-graceful-stop-v2-supervisor.service"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "run-autoquant-trusted\\x2dtime-graceful\\x2dstop\\x2dv2-host\\x2dsecrets.mount"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "run-autoquant-trusted\\x2dtime-graceful\\x2dstop\\x2dv2-recovery\\x2dsecrets.mount"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "run-autoquant-trusted\\x2dtime-graceful\\x2dstop\\x2dv2-supervisor\\x2dsecrets.mount"
    ),
    (
        "infra/trusted-time/graceful-stop-v2/systemd/"
        "run-autoquant-trusted\\x2dtime-graceful\\x2dstop\\x2dv2-transport.mount"
    ),
)
_REQUIRED = (
    "build_support/build_trusted_time_v2_candidates.py",
    "build_support/build_trusted_time_v2_linked_role_test.py",
    "build_support/exercise_trusted_time_v2_exact_candidates.py",
    "build_support/qualify_trusted_time_v2_candidates.py",
    "build_support/trusted_time_v2_candidate_execution.Dockerfile",
    (
        "build_support/trusted_time_v2_candidate_import_roots/host/"
        "autoquant_trusted_time_v2_host_entry.py"
    ),
    (
        "build_support/trusted_time_v2_candidate_import_roots/recovery/"
        "autoquant_trusted_time_v2_recovery_entry.py"
    ),
    (
        "build_support/trusted_time_v2_candidate_import_roots/supervisor/"
        "autoquant_trusted_time_v2_supervisor_entry.py"
    ),
    "build_support/trusted_time_v2_seccomp_manifests.py",
    "infra/trusted-time/graceful-stop-v2/seccomp/host.json",
    "infra/trusted-time/graceful-stop-v2/seccomp/provisioner.json",
    "infra/trusted-time/graceful-stop-v2/seccomp/recovery.json",
    "infra/trusted-time/graceful-stop-v2/seccomp/supervisor.json",
    "tests/native/trusted_time_v2_seccomp_manifest_harness.c",
    *_REQUIRED_SYSTEMD,
)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _archive_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _validated_absent_output_root(path: Path) -> Path:
    if not path.is_absolute() or path.exists():
        raise RuntimeError("the extracted-sdist output must be one absent absolute path")
    parent = path.parent.resolve(strict=True)
    canonical = parent / path.name
    if path != canonical or not path.name:
        raise RuntimeError("the extracted-sdist output path is not canonical")
    return canonical


def _tree_manifest(root: Path) -> tuple[list[dict[str, object]], str]:
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError("the extracted sdist root is not one real directory")
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda entry: entry.relative_to(root).as_posix()):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise RuntimeError(f"the extracted sdist contains a hard link: {relative}")
            records.append(
                {
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": relative,
                    "sha256": _sha256(path),
                    "size": metadata.st_size,
                    "type": "file",
                }
            )
        elif stat.S_ISDIR(metadata.st_mode):
            records.append(
                {
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": relative,
                    "type": "directory",
                }
            )
        else:
            raise RuntimeError(f"the extracted sdist contains a link or special file: {relative}")
    serialized = json.dumps(records, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return records, hashlib.sha256(serialized.encode("ascii")).hexdigest()


def smoke(archive: Path, output_root: Path) -> dict[str, object]:
    archive = archive.resolve(strict=True)
    archive_metadata = archive.lstat()
    if (
        not stat.S_ISREG(archive_metadata.st_mode)
        or archive_metadata.st_nlink != 1
        or archive_metadata.st_size <= 0
        or archive_metadata.st_size > 128 * 1024 * 1024
    ):
        raise RuntimeError("the source archive must be one regular non-linked file")
    with archive.open("rb") as archive_stream:
        opened_before = os.fstat(archive_stream.fileno())
        if _archive_identity(opened_before) != _archive_identity(archive_metadata):
            raise RuntimeError("the opened source archive differs from its path identity")
        archive_payload = archive_stream.read(128 * 1024 * 1024 + 1)
        opened_after = os.fstat(archive_stream.fileno())
    path_after = archive.lstat()
    if (
        len(archive_payload) != archive_metadata.st_size
        or _archive_identity(opened_after) != _archive_identity(opened_before)
        or _archive_identity(path_after) != _archive_identity(opened_before)
    ):
        raise RuntimeError("the source archive changed while its bytes were captured")
    archive_sha256 = hashlib.sha256(archive_payload).hexdigest()
    output_root = _validated_absent_output_root(output_root)
    temporary_parent = output_root.parent
    with tempfile.TemporaryDirectory(prefix="aqt-wave7-sdist-", dir=temporary_parent) as directory:
        extraction = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz") as source:
            source.extractall(extraction, filter="data")
        entries = tuple(extraction.iterdir())
        if len(entries) != 1 or not entries[0].is_dir() or entries[0].is_symlink():
            raise RuntimeError("the built sdist does not contain one real root")
        root = entries[0]
        if any(not root.joinpath(relative).is_file() for relative in _REQUIRED):
            raise RuntimeError("the built sdist omits a Wave 7 evidence input")
        systemd_root = root / "infra/trusted-time/graceful-stop-v2/systemd"
        observed_systemd = {
            path.relative_to(root).as_posix() for path in systemd_root.iterdir() if path.is_file()
        }
        if observed_systemd != set(_REQUIRED_SYSTEMD):
            raise RuntimeError("the built sdist systemd topology is not exact")
        tree_records, tree_sha256 = _tree_manifest(root)
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": tempfile.gettempdir(),
        }
        subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                str(root / "build_support/trusted_time_v2_seccomp_manifests.py"),
                "--check",
            ),
            cwd=extraction,
            env=environment,
            check=True,
        )
        subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                str(root / "build_support/build_trusted_time_v2_candidates.py"),
                "--help",
            ),
            cwd=extraction,
            env=environment,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        root.replace(output_root)
    result: dict[str, object] = {
        "activation_authorized": False,
        "archive": {
            "captured_bytes_used_for_extraction": True,
            "path": str(archive),
            "sha256": archive_sha256,
            "size": len(archive_payload),
            "stable_opened_file_identity": True,
        },
        "extracted_root": {
            "directory_count": sum(record["type"] == "directory" for record in tree_records),
            "file_count": sum(record["type"] == "file" for record in tree_records),
            "path": str(output_root),
            "tree_sha256": tree_sha256,
        },
        "full_candidate_build_deferred_to_locked_container": True,
        "schema": "autoquant-trusted-time-graceful-stop-v2-sdist-extraction-v1",
        "status": "validated_for_locked_container_qualification",
    }
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return result


def main(argument_values: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output_root", type=Path)
    arguments = parser.parse_args(argument_values)
    smoke(arguments.archive, arguments.output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
