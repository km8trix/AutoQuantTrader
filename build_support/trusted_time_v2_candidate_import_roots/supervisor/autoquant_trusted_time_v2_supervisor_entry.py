"""Inert entry for the unactivated lifecycle-v2 supervisor candidate."""


def run() -> None:
    """Refuse use until a later milestone supplies operational composition."""

    print("AQT_WAVE7_INERT_SUPERVISOR_ENTRY_REACHED", flush=True)
    raise RuntimeError("the lifecycle-v2 supervisor candidate is unactivated")
