"""Read-only content provenance for a local or installed historical runner."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from importlib import resources
from pathlib import Path
from zoneinfo import TZPATH

from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.report_contracts import ReportConventions


def current_build_pins() -> tuple[VersionPin, ...]:
    """Identify actual code/clock/build inputs; do not inspect operational configuration."""
    root = Path(__file__).resolve().parents[2]
    files: list[tuple[str, str]] = []
    for subtree in ("packages",):
        for source in sorted((root / subtree).rglob("*.py")):
            if source.is_symlink():
                raise ValueError("source provenance rejects symlinked implementation files")
            files.append(
                (
                    source.relative_to(root).as_posix(),
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            )
    for relative in (
        "apps/__init__.py",
        "apps/worker/__init__.py",
        "apps/worker/personal_research.py",
        "apps/worker/main.py",
        "apps/worker/research_runner.py",
        "apps/worker/research_jobs.py",
    ):
        source = root / relative
        if source.exists():
            files.append((relative, hashlib.sha256(source.read_bytes()).hexdigest()))
    metadata_path = root / "packages/datasets/personal_build.json"
    metadata = json.loads(metadata_path.read_bytes())
    if metadata.get("schema") != "personal-build-metadata/1":
        raise ValueError("unsupported personal build metadata")
    lock_hash = metadata["dependency_lock_sha256"]
    lock = root / "uv.lock"
    if lock.exists() and hashlib.sha256(lock.read_bytes()).hexdigest() != lock_hash:
        raise ValueError("dependency lock changed without refreshing packaged build metadata")
    constraints = root / "build_support/native_build_constraints.txt"
    if (
        constraints.exists()
        and hashlib.sha256(constraints.read_bytes()).hexdigest()
        != metadata["build_constraints_sha256"]
    ):
        raise ValueError("build constraints changed without refreshing packaged metadata")
    zone_bytes: bytes | None = None
    for tzroot in TZPATH:
        candidate = Path(tzroot) / "America/New_York"
        if candidate.is_file():
            zone_bytes = candidate.read_bytes()
            break
    if zone_bytes is None:
        zone_bytes = resources.files("tzdata.zoneinfo").joinpath("America/New_York").read_bytes()
    definitions = {
        "source_base_revision": (
            metadata["base_revision"],
            content_digest(metadata["base_revision"]),
        ),
        "engine": ("personal-causal-engine/1", content_digest("personal-causal-engine/1")),
        "source": ("actual-python-source-content/1", content_digest(tuple(sorted(files)))),
        "dependency_lock": ("uv-lock/1", lock_hash),
        "tzdata": ("America-New_York-TZif-content/1", hashlib.sha256(zone_bytes).hexdigest()),
        "availability": (
            "modeled-daily-and-retrospective-open/1",
            content_digest(
                (
                    "assumed-session-2000-america-new-york-v1",
                    "retrospective-raw-open-available-at-open-model/1",
                )
            ),
        ),
        "actions": (
            "explicit-canonical-facts-only/1",
            content_digest("explicit-canonical-facts-only/1"),
        ),
        "numeric": (
            "exact-ledger-and-decimal64-derived/1",
            content_digest(("numeric-28-10", "personal-derived-decimal64-half-even-v1")),
        ),
        "benchmark": (
            "SPY-matched-flow-fractional-TR/1",
            content_digest("SPY-matched-flow-fractional-TR/1"),
        ),
        "report": ("personal-report/2", content_digest("personal-report/2")),
        "report_conventions": ("personal-report/2", ReportConventions().semantic_sha256),
        # Source is actual complete content rather than a clean-commit claim.
        "dirty_patch": (
            "subsumed-by-actual-source-content/1",
            content_digest(tuple(sorted(files))),
        ),
        "python_runtime": (
            platform.python_implementation(),
            content_digest((sys.version, platform.machine(), metadata["build_constraints_sha256"])),
        ),
        "resources": (
            "posix-cpu-file-wall-sampled-resident/2",
            content_digest(
                (
                    sys.platform,
                    "resident-sample-100ms-final-high-water",
                    "linux-post-exec-VmHWM-darwin-process-getrusage",
                    "linux-extra-RLIMIT_AS",
                )
            ),
        ),
    }
    return tuple(
        VersionPin(name, version, digest) for name, (version, digest) in sorted(definitions.items())
    )
