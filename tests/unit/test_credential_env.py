from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts.credential_env import load_owner_only_environment


def _owner_only_env(tmp_path: Path, payload: str) -> Path:
    path = tmp_path / "narrow.env"
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_strict_allowlist_rejects_unknown_assignment_before_dotenv_parsing(
    tmp_path: Path,
) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\nUNKNOWN=secret-canary\n")

    with (
        patch("scripts.credential_env.dotenv_values") as parse,
        pytest.raises(ValueError, match="unknown variable assignments"),
    ):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
        )

    parse.assert_not_called()


def test_strict_allowlist_rejects_unknown_name_recognized_by_dotenv_parser(
    tmp_path: Path,
) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\nUNKNOWN\n")

    with pytest.raises(ValueError, match="unknown variable assignments"):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
        )


@pytest.mark.parametrize(
    "invalid_line",
    (
        "RETURNED",
        "export RETURNED",
        "export RETURNED value",
        "'RETURNED'=value",
        'RETURNED="unterminated',
        'RETURNED="value" trailing-text',
        "malformed ignored text",
    ),
)
def test_strict_allowlist_rejects_nonassignment_lines_without_dotenv_warnings(
    tmp_path: Path,
    invalid_line: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _owner_only_env(tmp_path, f"{invalid_line}\n")

    with (
        patch("scripts.credential_env.dotenv_values") as warning_parser,
        pytest.raises(ValueError, match="only explicit variable assignments"),
    ):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
        )

    warning_parser.assert_not_called()
    assert capsys.readouterr().err == ""


def test_strict_allowlist_rejects_duplicates_without_duplicate_opt_in(tmp_path: Path) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=first\nexport RETURNED=second\n")

    with pytest.raises(ValueError, match="duplicate variable assignments"):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
        )


def test_strict_allowlist_accepts_only_comments_blanks_and_explicit_assignments(
    tmp_path: Path,
) -> None:
    path = _owner_only_env(
        tmp_path,
        "# dedicated credentials\n\nexport RETURNED='value with spaces' # retained\n",
    )

    environment = load_owner_only_environment(
        path,
        variables=("RETURNED",),
        allowed_variables=("RETURNED",),
    )

    assert environment == {"RETURNED": "value with spaces"}


def test_strict_allowlist_can_exceed_returned_variable_set(tmp_path: Path) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\nALLOWED_TOO=retained\n")

    environment = load_owner_only_environment(
        path,
        variables=("RETURNED",),
        allowed_variables=("RETURNED", "ALLOWED_TOO"),
    )

    assert environment == {"RETURNED": "value"}


def test_unknown_assignments_remain_ignored_without_opt_in_allowlist(tmp_path: Path) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\nUNKNOWN=secret-canary\n")

    environment = load_owner_only_environment(path, variables=("RETURNED",))

    assert environment == {"RETURNED": "value"}


def test_returned_variables_must_be_within_strict_allowlist(tmp_path: Path) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\n")

    with pytest.raises(ValueError, match="returned env variables must be allowed"):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("DIFFERENT",),
        )


def test_strict_allowlist_cannot_fall_back_to_the_ambient_environment() -> None:
    with pytest.raises(ValueError, match="requires an owner-only file"):
        load_owner_only_environment(
            None,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
        )


def test_secure_path_rejects_relative_path_before_open() -> None:
    with (
        patch("scripts.credential_env.os.open") as open_file,
        pytest.raises(ValueError, match="absolute and canonical"),
    ):
        load_owner_only_environment(
            Path("relative.env"),
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
            require_secure_path=True,
            required_mode=0o600,
        )

    open_file.assert_not_called()


def test_secure_path_rejects_hardlinked_file(tmp_path: Path) -> None:
    original = _owner_only_env(tmp_path, "RETURNED=value\n")
    hardlink = tmp_path / "hardlinked.env"
    os.link(original, hardlink)

    with pytest.raises(ValueError, match="exactly one link"):
        load_owner_only_environment(
            hardlink,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
        )


def test_secure_path_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    path = _owner_only_env(real_parent, "RETURNED=value\n")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="readable, non-symlinked regular file"):
        load_owner_only_environment(
            linked_parent / path.name,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
        )


def test_secure_path_rejects_metadata_drift_during_read(tmp_path: Path) -> None:
    path = _owner_only_env(tmp_path, "RETURNED=value\n")
    before = path.stat()
    after = SimpleNamespace(
        st_mode=before.st_mode,
        st_uid=before.st_uid,
        st_nlink=before.st_nlink,
        st_size=before.st_size,
        st_dev=before.st_dev,
        st_ino=before.st_ino,
        st_mtime_ns=before.st_mtime_ns + 1,
        st_ctime_ns=before.st_ctime_ns,
    )

    with (
        patch("scripts.credential_env.os.fstat", side_effect=(before, after)),
        pytest.raises(ValueError, match="changed during read"),
    ):
        load_owner_only_environment(
            path,
            variables=("RETURNED",),
            allowed_variables=("RETURNED",),
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
        )
