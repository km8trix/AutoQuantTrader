"""Require one ordinary wheel containing the standalone simulation entry point."""

from __future__ import annotations

import argparse
import configparser
import zipfile
from pathlib import Path, PurePosixPath


def verify(directory: Path) -> str:
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one wheel")
    wheel = wheels[0]
    if not wheel.name.endswith("-py3-none-any.whl"):
        raise ValueError("personal wheel must be pure Python and platform independent")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        required = {
            "apps/trader/personal_simulation.py",
            "packages/adapters/standard_clock.py",
            "packages/application/personal_runtime.py",
            "apps/worker/personal_research.py",
            "apps/worker/main.py",
            "apps/worker/legacy_golden.py",
            "packages/application/causal_engine.py",
            "packages/application/run_report.py",
            "packages/backtest/personal_accounting.py",
            "packages/datasets/personal_build.json",
        }
        if not required.issubset(names):
            raise ValueError("personal runtime is missing from the wheel")
        for name in names:
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.suffix in {".so", ".dylib", ".dll"}
                or any(part in {".env", "node_modules", "artifacts"} for part in path.parts)
                or ".data/" in name
            ):
                raise ValueError("wheel includes native/private/non-package payload")
        metadata = [name for name in names if name.endswith(".dist-info/WHEEL")]
        entries = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata) != 1 or len(entries) != 1:
            raise ValueError("wheel metadata is ambiguous")
        if "Root-Is-Purelib: true" not in archive.read(metadata[0]).decode():
            raise ValueError("wheel does not declare a pure Python installation")
        scripts = configparser.ConfigParser()
        scripts.read_string(archive.read(entries[0]).decode())
        if scripts["console_scripts"].get("autoquant-personal-simulation") != (
            "apps.trader.personal_simulation:main"
        ):
            raise ValueError("personal runtime console script is not installed")
        if (
            scripts["console_scripts"].get("autoquant-research")
            != "apps.worker.personal_research:main"
        ):
            raise ValueError("general historical research console script is not installed")
        if scripts["console_scripts"].get("autoquant-worker") != "apps.worker.main:main":
            raise ValueError("general research worker is not the default worker")
        if (
            scripts["console_scripts"].get("autoquant-golden-oracle")
            != "apps.worker.legacy_golden:main"
        ):
            raise ValueError("legacy fixture worker lacks its explicit oracle entry point")
    return wheel.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        name = verify(args.directory)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"Wheel verification failed: {exc}\n")
    print(f"Personal wheel verified: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
