"""Default worker runs explicitly selected general offline research inputs."""

from apps.worker.personal_research import main

if __name__ == "__main__":
    raise SystemExit(main())
