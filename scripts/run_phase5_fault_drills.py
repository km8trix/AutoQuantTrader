"""Run the exact deterministic evidence nodes in the Phase 5 fault-drill catalog."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load_node_ids(matrix_path: Path) -> tuple[str, ...]:
    value: Any = json.loads(matrix_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("local_drills"), list):
        raise SystemExit(f"Invalid Phase 5 fault-drill matrix: {matrix_path}")
    node_ids: set[str] = set()
    for drill in value["local_drills"]:
        if not isinstance(drill, dict) or not isinstance(drill.get("evidence"), list):
            raise SystemExit(f"Invalid local drill in Phase 5 fault-drill matrix: {matrix_path}")
        for node_id in drill["evidence"]:
            if not isinstance(node_id, str):
                raise SystemExit(f"Invalid evidence node ID in Phase 5 matrix: {node_id!r}")
            node_ids.add(node_id)
    return tuple(sorted(node_ids))


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    matrix_path = repository / "tests/fixtures/phase5_fault_drills.json"
    node_ids = _load_node_ids(matrix_path)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/integration/test_phase5_fault_drill_matrix.py",
        *node_ids,
    ]
    return subprocess.run(command, cwd=repository, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
