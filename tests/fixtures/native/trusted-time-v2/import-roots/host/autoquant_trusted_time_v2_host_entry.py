"""Closed candidate entry for the fixed host launcher build."""

import sys


def run() -> None:
    """Prove the isolated fixed import, without exercising host authority."""

    if sys.path[-1] != __file__.rsplit("/", 1)[0]:
        raise RuntimeError("the fixed host import root was not installed")
