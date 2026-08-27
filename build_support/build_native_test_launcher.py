"""Build the isolated, source-checkout-only trusted-time test launcher."""

from __future__ import annotations

import hashlib
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Never

_LAUNCHER_BASENAME = "autoquant-trusted-time-python-test"
_EXPECTED_SOURCES = (
    (
        "native/owned_file_descriptor.c",
        "b41b39f0bd814315d879ea598e4cbd04758a7001faad96809df6eba2043e4427",
    ),
    (
        "native/bounded_process.c",
        "be08d5c95a2a5ce6aa9b06a4434c09473ee74ad941a417b8022885a7ef1f5cbd",
    ),
    (
        "native/trusted_time_python_launcher.c",
        "8f21c008571b4ed04166ae120cea9be2da73955c891a7c026833779dca3381f8",
    ),
    (
        "packages/adapters/trusted_time/_owned_file_descriptor.py",
        "1c6f540c9922b1a4bfc1c218d216c8045d18e7688014046fcf424f874961d2e2",
    ),
    (
        "packages/adapters/trusted_time/_bounded_process.py",
        "0bdf6cda1f0ab75d08df768d0d75bb40f2c8ef0cb490d09a18d843fb96a2a006",
    ),
)


class NativeTestLauncherBuildError(RuntimeError):
    """The exact test-only native launcher could not be built."""


def _fail(message: str) -> Never:
    raise NativeTestLauncherBuildError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(131_072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_tool(name: str) -> Path:
    candidate = shutil.which(name)
    if candidate is None:
        _fail(f"native test launcher tool is unavailable: {name}")
    path = Path(candidate).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _fail("native test launcher tool metadata is invalid")
    return path


def _run(command: tuple[str, ...]) -> None:
    completed = subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
        },
    )
    if completed.returncode != 0:
        output = completed.stdout[:262_144].decode("utf-8", errors="replace")
        _fail(f"native test launcher command failed:\n{output}")


def _write_embedded_header(source: Path, output: Path, symbol: str) -> None:
    payload = source.read_bytes()
    if not payload or b"\0" in payload:
        _fail("native test launcher wrapper bytes are invalid")
    values = (*payload, 0)
    rows = tuple(
        ", ".join(f"0x{value:02x}" for value in values[index : index + 16])
        for index in range(0, len(values), 16)
    )
    output.write_text(
        f"static const unsigned char {symbol}[] = {{\n"
        + "\n".join(f"    {row}," for row in rows)
        + "\n};\n",
        encoding="ascii",
    )


def _quoted_definition(name: str, value: str) -> str:
    if any(character in value for character in ('"', "\\", "\n", "\r")):
        _fail("native test launcher path cannot be represented exactly")
    return f'-D{name}="{value}"'


def _build_launcher() -> Path:
    if sys.implementation.name != "cpython" or sys.version_info[:2] not in (
        (3, 12),
        (3, 13),
    ):
        _fail("native test launcher requires CPython 3.12 or 3.13")
    if sys.platform not in ("darwin", "linux"):
        _fail("native test launcher platform is unsupported")

    repository_root = Path(__file__).resolve(strict=True).parents[1]
    sources = tuple(
        (repository_root / relative).resolve(strict=True) for relative, _ in _EXPECTED_SOURCES
    )
    if tuple(_sha256(source) for source in sources) != tuple(
        expected for _relative, expected in _EXPECTED_SOURCES
    ):
        _fail("native test launcher source identity is unreviewed")
    core_source, process_source, launcher_source, owner_wrapper, process_wrapper = sources

    configured_compiler = sysconfig.get_config_var("CC")
    if type(configured_compiler) is not str or not configured_compiler:
        _fail("Python did not declare a C compiler")
    compiler_words = shlex.split(configured_compiler)
    if not compiler_words:
        _fail("Python declared an empty C compiler command")
    compiler = _canonical_tool(compiler_words[0])
    include_value = sysconfig.get_path("include")
    library_directory_value = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    stdlib_value = sysconfig.get_path("stdlib")
    dynload_value = sysconfig.get_config_var("DESTSHARED")
    if not all(
        type(value) is str and value
        for value in (
            include_value,
            library_directory_value,
            library_name,
            extension_suffix,
            stdlib_value,
            dynload_value,
        )
    ):
        _fail("Python runtime build paths are incomplete")
    include = Path(include_value).resolve(strict=True)
    library_directory = Path(library_directory_value).resolve(strict=True)
    python_library = (library_directory / library_name).resolve(strict=True)
    python_home = Path(sys.base_prefix).resolve(strict=True)
    python_stdlib = Path(stdlib_value).resolve(strict=True)
    python_dynload = Path(dynload_value).resolve(strict=True)
    output_directory = Path(sys.prefix).resolve(strict=True) / "bin"
    output_path = output_directory / _LAUNCHER_BASENAME
    if not output_directory.is_dir() or output_directory.is_symlink():
        _fail("native test launcher output directory is invalid")

    common = (
        str(compiler),
        "-std=c11",
        "-O2",
        "-fPIE",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type",
        f"-I{include}",
    )
    platform_flags: tuple[str, ...]
    link_security_flags: tuple[str, ...]
    if sys.platform == "darwin":
        machine = platform.machine()
        if machine not in ("arm64", "x86_64"):
            _fail("native test launcher Darwin architecture is unsupported")
        xcrun = _canonical_tool("xcrun")
        sdk = subprocess.run(
            (str(xcrun), "--show-sdk-path"),
            check=True,
            capture_output=True,
            text=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        ).stdout.strip()
        sdk_path = Path(sdk).resolve(strict=True)
        platform_flags = (
            "-arch",
            machine,
            "-isysroot",
            str(sdk_path),
            "-mmacosx-version-min=11.0",
        )
        link_security_flags = ("-Wl,-dead_strip",)
    else:
        if platform.machine() not in ("aarch64", "x86_64"):
            _fail("native test launcher Linux architecture is unsupported")
        platform_flags = ("-pthread",)
        link_security_flags = ("-Wl,-z,relro,-z,now,-z,noexecstack",)

    with tempfile.TemporaryDirectory(prefix="autoquant-native-test-launcher-") as temporary:
        temporary_root = Path(temporary)
        _write_embedded_header(
            owner_wrapper,
            temporary_root / "embedded_owned_file_descriptor_wrapper.h",
            "aqt_embedded_owned_file_descriptor_wrapper",
        )
        _write_embedded_header(
            process_wrapper,
            temporary_root / "embedded_bounded_process_wrapper.h",
            "aqt_embedded_bounded_process_wrapper",
        )
        core_object = temporary_root / "owned_file_descriptor.o"
        process_object = temporary_root / "bounded_process.o"
        launcher_object = temporary_root / "trusted_time_python_launcher.o"
        staged_launcher = temporary_root / _LAUNCHER_BASENAME
        core_definitions = (
            _quoted_definition("AQT_NATIVE_EXTENSION_SUFFIX", extension_suffix),
            _quoted_definition(
                "AQT_NATIVE_MODULE_NAME",
                "_autoquant_native_owned_file_descriptor",
            ),
            _quoted_definition("AQT_NATIVE_LAUNCHER_BASENAME", _LAUNCHER_BASENAME),
            "-DAQT_NATIVE_EMBEDDED_LAUNCHER=1",
        )
        process_definitions = (
            _quoted_definition(
                "AQT_NATIVE_PROCESS_MODULE_NAME",
                "_autoquant_native_bounded_process",
            ),
            _quoted_definition("AQT_NATIVE_PROCESS_LAUNCHER_BASENAME", _LAUNCHER_BASENAME),
            "-DAQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE=1",
        )
        launcher_definitions = (
            "-DAQT_NATIVE_LAUNCHER_TEST_PROFILE=1",
            _quoted_definition(
                "AQT_TRUSTED_TIME_PREFIX",
                str(Path(sys.prefix).resolve(strict=True)),
            ),
            _quoted_definition("AQT_PYTHON_HOME", str(python_home)),
            _quoted_definition("AQT_PYTHON_STDLIB", str(python_stdlib)),
            _quoted_definition("AQT_PYTHON_DYNLOAD", str(python_dynload)),
            _quoted_definition("AQT_TEST_SOURCE_ROOT", str(repository_root)),
        )
        for source, object_path, definitions in (
            (core_source, core_object, core_definitions),
            (process_source, process_object, process_definitions),
            (launcher_source, launcher_object, launcher_definitions),
        ):
            generated_include = (f"-I{temporary_root}",) if source == launcher_source else ()
            _run(
                (
                    *common,
                    *definitions,
                    *platform_flags,
                    *generated_include,
                    "-c",
                    str(source),
                    "-o",
                    str(object_path),
                )
            )

        python_link_name = (
            python_library.name.removeprefix("lib").split(".so", 1)[0].split(".dylib", 1)[0]
        )
        configured_libraries = sysconfig.get_config_var("LIBS")
        configured_system_libraries = sysconfig.get_config_var("SYSLIBS")
        if type(configured_libraries) is not str or type(configured_system_libraries) is not str:
            _fail("Python embedding libraries are incomplete")
        _run(
            (
                str(compiler),
                *platform_flags,
                *link_security_flags,
                f"-Wl,-rpath,{library_directory}",
                str(core_object),
                str(process_object),
                str(launcher_object),
                f"-L{library_directory}",
                f"-l{python_link_name}",
                *shlex.split(configured_libraries),
                *shlex.split(configured_system_libraries),
                "-o",
                str(staged_launcher),
            )
        )
        staged_launcher.chmod(0o755)
        os.replace(staged_launcher, output_path)
    output_path.chmod(0o755)
    return output_path


def main() -> int:
    print(str(_build_launcher()))
    return 0


def _validated_policy_arguments(argument_values: tuple[str, ...]) -> tuple[str, ...]:
    repository_root = Path(__file__).resolve(strict=True).parents[1]
    artifact_root = repository_root / "artifacts"
    if (
        len(argument_values) != 3
        or argument_values[0] != "verify-images-build"
        or argument_values[1] != "--artifact"
        or not argument_values[2].startswith("/")
        or os.path.normpath(argument_values[2]) != argument_values[2]
    ):
        _fail("native test launcher execution arguments are not admitted")
    artifact = Path(argument_values[2])
    try:
        canonical_artifact = artifact.resolve(strict=False)
        canonical_artifact.relative_to(artifact_root)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _fail("native test launcher execution arguments are not admitted")
    if canonical_artifact != artifact or canonical_artifact == artifact_root:
        _fail("native test launcher execution arguments are not admitted")
    if (
        runtime_prefix in (base_prefix, repository_root)
        or runtime_prefix.is_relative_to(repository_root)
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
    ):
        _fail("native test launcher execution runtime is not isolated")
    return argument_values


def _exec_policy_target(argument_values: tuple[str, ...]) -> Never:
    exact_arguments = _validated_policy_arguments(argument_values)
    launcher = _build_launcher().resolve(strict=True)
    try:
        os.execv(str(launcher), (str(launcher), *exact_arguments))
    except OSError:
        _fail("native test launcher execution failed")


if __name__ == "__main__":
    policy_arguments = tuple(sys.argv[1:])
    if policy_arguments:
        _exec_policy_target(policy_arguments)
    raise SystemExit(main())
