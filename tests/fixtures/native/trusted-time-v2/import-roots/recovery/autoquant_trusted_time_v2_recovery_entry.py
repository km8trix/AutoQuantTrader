"""Closed candidate entry for the structurally narrow recovery launcher."""

import sys


def run() -> None:
    """Prove the isolated recovery import without operational authority."""

    if sys.path[-1] != __file__.rsplit("/", 1)[0]:
        raise RuntimeError("the fixed recovery import root was not installed")
    if any(path.endswith("lib-dynload") for path in sys.path):
        raise RuntimeError("the recovery candidate exposed dynamic extensions")
