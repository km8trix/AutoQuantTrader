"""Closed candidate entry for the fixed supervisor launcher build."""

import sys


def run() -> None:
    """Prove the isolated fixed import, without exercising supervisor authority."""

    if sys.path[-1] != __file__.rsplit("/", 1)[0]:
        raise RuntimeError("the fixed supervisor import root was not installed")
