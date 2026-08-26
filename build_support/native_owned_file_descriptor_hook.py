"""Build the reviewed static trusted-time Python launcher outside import roots."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
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
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_CORE_SOURCE_RELATIVE_PATH = Path("native/owned_file_descriptor.c")
_LAUNCHER_SOURCE_RELATIVE_PATH = Path("native/trusted_time_python_launcher.c")
_WRAPPER_SOURCE_RELATIVE_PATH = Path("packages/adapters/trusted_time/_owned_file_descriptor.py")
_SHARED_NATIVE_DIRECTORY = Path("share/autoquant-trader/native")
_LAUNCHER_BASENAME = "autoquant-trusted-time-python"
_ATTESTATION_BASENAME = "native_owned_file_descriptor_launcher.json"
_PRODUCTION_PREFIX = "/opt/autoquant/trusted-time"
_OPERATIONAL_TARGET_IDS = (
    "first-enrollment",
    "first-enrollment-recovery-release",
    "first-enrollment-release",
    "image-schema-contract",
    "post-enrollment-persistent-barrier-read",
    "post-enrollment-pre-effect-runtime-absence",
    "post-enrollment-release",
    "post-enrollment-runtime-state",
    "post-enrollment-staged-barrier-read",
    "supervisor",
)
_SUPPORTED_PLATFORMS = frozenset({"darwin", "linux"})
_SUPPORTED_PYTHON_MINORS = frozenset({(3, 12), (3, 13)})
_MAX_TOOL_OUTPUT_BYTES = 262_144
_EXPECTED_CORE_SOURCE_SHA256 = "01b9834c343f4b173198ac7bfb22df37c6da6fb3093e7a93875aef56410b9fd9"
_EXPECTED_LAUNCHER_SOURCE_SHA256 = (
    "8f21c008571b4ed04166ae120cea9be2da73955c891a7c026833779dca3381f8"
)
_EXPECTED_WRAPPER_SOURCE_SHA256 = "a5c3a0f1ec32ae95d6a058cdf52f8530fe505c5a97f1a2cf61106d94c2baa9ab"
_EXPECTED_HATCHLING_VERSION = "1.32.0"
_EXPECTED_BUILD_DEPENDENCIES = (
    ("hatchling", "1.32.0"),
    ("packaging", "26.3"),
    ("pathspec", "1.1.1"),
    ("pluggy", "1.6.0"),
    ("tomlkit", "0.15.1"),
    ("trove-classifiers", "2026.6.1.19"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(131_072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH", "0"),
        },
    )
    if len(completed.stdout) > _MAX_TOOL_OUTPUT_BYTES:
        raise RuntimeError("native build tool output exceeded its bound")
    return completed.stdout.decode("utf-8", errors="strict")


def _canonical_tool(command_name: str) -> Path:
    located = shutil.which(command_name)
    if located is None:
        raise RuntimeError(f"required native build tool is unavailable: {command_name}")
    path = Path(located).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"native build tool is not a regular file: {path}")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"native build tool is group/world writable: {path}")
    return path


def _compiler() -> Path:
    configured = sysconfig.get_config_var("CC")
    if type(configured) is not str or not configured:
        raise RuntimeError("Python did not declare a native C compiler")
    words = shlex.split(configured)
    if not words:
        raise RuntimeError("Python declared an empty native C compiler")
    return _canonical_tool(words[0])


def _python_include() -> Path:
    configured = sysconfig.get_path("include")
    path = Path(configured).resolve(strict=True)
    if not (path / "Python.h").is_file():
        raise RuntimeError("the exact Python development headers are unavailable")
    return path


def _extension_suffix() -> str:
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if type(suffix) is not str or not suffix.startswith(".cpython-") or not suffix.endswith(".so"):
        raise RuntimeError("Python declared an unsupported native extension suffix")
    return suffix


def _python_library() -> Path:
    library_directory = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    if type(library_directory) is not str or type(library_name) is not str:
        raise RuntimeError("Python did not declare its shared runtime library")
    path = (Path(library_directory) / library_name).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("the Python shared runtime library is not admitted")
    return path


def _python_library_link_name(path: Path) -> str:
    name = path.name
    if not name.startswith("lib"):
        raise RuntimeError("the Python shared runtime library name is invalid")
    if ".dylib" in name:
        return name.removeprefix("lib").split(".dylib", maxsplit=1)[0]
    if ".so" in name:
        return name.removeprefix("lib").split(".so", maxsplit=1)[0]
    raise RuntimeError("the Python shared runtime library suffix is invalid")


def _python_runtime_paths() -> tuple[Path, Path, Path]:
    home = Path(sys.base_prefix).resolve(strict=True)
    stdlib_value = sysconfig.get_path("stdlib")
    dynload_value = sysconfig.get_config_var("DESTSHARED")
    if type(stdlib_value) is not str or type(dynload_value) is not str:
        raise RuntimeError("Python did not declare its exact runtime search paths")
    stdlib = Path(stdlib_value).resolve(strict=True)
    dynload = Path(dynload_value).resolve(strict=True)
    for path in (home, stdlib, dynload):
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("a Python runtime search path is not a directory")
        if any(character in str(path) for character in ('"', "\\", "\n", "\r")):
            raise RuntimeError("a Python runtime search path cannot be compiled exactly")
    return home, stdlib, dynload


def _write_embedded_wrapper_header(wrapper_source: Path, header_path: Path) -> None:
    encoded = wrapper_source.read_bytes()
    if not encoded or b"\0" in encoded:
        raise RuntimeError("the embedded native wrapper source is invalid")
    values = [*encoded, 0]
    rows = tuple(
        ", ".join(f"0x{value:02x}" for value in values[index : index + 16])
        for index in range(0, len(values), 16)
    )
    header_path.write_text(
        "static const unsigned char aqt_embedded_owned_file_descriptor_wrapper[] = {\n"
        + "\n".join(f"    {row}," for row in rows)
        + "\n};\n",
        encoding="ascii",
    )


def _compile_commands(
    *,
    compiler: Path,
    core_source: Path,
    launcher_source: Path,
    include: Path,
    generated_include: Path,
    core_object_path: Path,
    launcher_object_path: Path,
    launcher_path: Path,
    extension_suffix: str,
    python_library: Path,
    python_home: Path,
    python_stdlib: Path,
    python_dynload: Path,
) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    source_root = core_source.parents[1]
    if launcher_source.parents[1] != source_root:
        raise RuntimeError("native launcher sources do not share one build root")
    common = [
        str(compiler),
        "-std=c11",
        "-O2",
        f"-ffile-prefix-map={source_root}=.",
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
    ]
    core_definitions = [
        f'-DAQT_NATIVE_EXTENSION_SUFFIX="{extension_suffix}"',
        '-DAQT_NATIVE_MODULE_NAME="_autoquant_native_owned_file_descriptor"',
        "-DAQT_NATIVE_EMBEDDED_LAUNCHER=1",
    ]
    launcher_definitions = [
        "-DAQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE=1",
        f'-DAQT_TRUSTED_TIME_PREFIX="{_PRODUCTION_PREFIX}"',
        f'-DAQT_PYTHON_HOME="{python_home}"',
        f'-DAQT_PYTHON_STDLIB="{python_stdlib}"',
        f'-DAQT_PYTHON_DYNLOAD="{python_dynload}"',
    ]
    platform_attestation: dict[str, str]
    library_name = _python_library_link_name(python_library)
    library_directory = python_library.parent
    python_libs = sysconfig.get_config_var("LIBS")
    python_system_libs = sysconfig.get_config_var("SYSLIBS")
    if type(python_libs) is not str or type(python_system_libs) is not str:
        raise RuntimeError("Python did not declare exact embedding link flags")
    runtime_link_flags = [*shlex.split(python_libs), *shlex.split(python_system_libs)]

    if sys.platform == "darwin":
        machine = platform.machine()
        if machine not in {"arm64", "x86_64"}:
            raise RuntimeError(f"unsupported Darwin architecture: {machine}")
        xcrun = _canonical_tool("xcrun")
        sdk_path = Path(_run([str(xcrun), "--show-sdk-path"]).strip()).resolve(strict=True)
        deployment_target = "11.0"
        platform_flags = [
            "-arch",
            machine,
            "-isysroot",
            str(sdk_path),
            f"-mmacosx-version-min={deployment_target}",
        ]
        core_compile_command = [
            *common,
            *core_definitions,
            *platform_flags,
            "-c",
            str(core_source),
            "-o",
            str(core_object_path),
        ]
        launcher_compile_command = [
            *common,
            *launcher_definitions,
            *platform_flags,
            f"-I{generated_include}",
            "-c",
            str(launcher_source),
            "-o",
            str(launcher_object_path),
        ]
        link_command = [
            str(compiler),
            *platform_flags,
            "-Wl,-dead_strip",
            f"-Wl,-rpath,{library_directory}",
            str(core_object_path),
            str(launcher_object_path),
            f"-L{library_directory}",
            f"-l{library_name}",
            *runtime_link_flags,
            "-o",
            str(launcher_path),
        ]
        sdk_settings = sdk_path / "SDKSettings.json"
        if not sdk_settings.is_file():
            raise RuntimeError("the exact Darwin SDK settings are unavailable")
        platform_attestation = {
            "architecture": machine,
            "deployment_target": deployment_target,
            "sdk": sdk_path.name,
            "sdk_settings_sha256": _sha256(sdk_settings),
        }
    elif sys.platform == "linux":
        machine = platform.machine()
        if machine not in {"aarch64", "x86_64"}:
            raise RuntimeError(f"unsupported Linux architecture: {machine}")
        core_compile_command = [
            *common,
            *core_definitions,
            "-pthread",
            "-c",
            str(core_source),
            "-o",
            str(core_object_path),
        ]
        launcher_compile_command = [
            *common,
            *launcher_definitions,
            "-pthread",
            f"-I{generated_include}",
            "-c",
            str(launcher_source),
            "-o",
            str(launcher_object_path),
        ]
        link_command = [
            str(compiler),
            "-pthread",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            f"-Wl,-rpath,{library_directory}",
            str(core_object_path),
            str(launcher_object_path),
            f"-L{library_directory}",
            f"-l{library_name}",
            *runtime_link_flags,
            "-o",
            str(launcher_path),
        ]
        platform_attestation = {"architecture": machine}
    else:
        raise RuntimeError(f"unsupported native build platform: {sys.platform}")

    return core_compile_command, launcher_compile_command, link_command, platform_attestation


def _normalized_command(
    command: list[str],
    *,
    compiler: Path,
    core_source: Path,
    launcher_source: Path,
    include: Path,
    generated_include: Path,
    core_object_path: Path,
    launcher_object_path: Path,
    launcher_path: Path,
    python_library: Path,
    python_home: Path,
    python_stdlib: Path,
    python_dynload: Path,
    extension_suffix: str,
    platform_attestation: dict[str, str],
) -> list[str]:
    source_root = core_source.parents[1]
    library_directory = python_library.parent
    replacements = {
        str(compiler): "$COMPILER",
        str(core_source): "$CORE_SOURCE",
        str(launcher_source): "$LAUNCHER_SOURCE",
        str(core_object_path): "$CORE_OBJECT",
        str(launcher_object_path): "$LAUNCHER_OBJECT",
        str(launcher_path): "$LAUNCHER_OUTPUT",
        f"-ffile-prefix-map={source_root}=.": "-ffile-prefix-map=$SOURCE_ROOT=.",
        f"-I{include}": "-I$PYTHON_INCLUDE",
        f"-I{generated_include}": "-I$GENERATED_INCLUDE",
        f"-L{library_directory}": "-L$PYTHON_LIBDIR",
        f"-Wl,-rpath,{library_directory}": "-Wl,-rpath,$PYTHON_LIBDIR",
        f'-DAQT_NATIVE_EXTENSION_SUFFIX="{extension_suffix}"': (
            "-DAQT_NATIVE_EXTENSION_SUFFIX=$EXT_SUFFIX"
        ),
        f'-DAQT_TRUSTED_TIME_PREFIX="{_PRODUCTION_PREFIX}"': (
            "-DAQT_TRUSTED_TIME_PREFIX=$TRUSTED_TIME_PREFIX"
        ),
        f'-DAQT_PYTHON_HOME="{python_home}"': "-DAQT_PYTHON_HOME=$PYTHON_HOME",
        f'-DAQT_PYTHON_STDLIB="{python_stdlib}"': ("-DAQT_PYTHON_STDLIB=$PYTHON_STDLIB"),
        f'-DAQT_PYTHON_DYNLOAD="{python_dynload}"': ("-DAQT_PYTHON_DYNLOAD=$PYTHON_DYNLOAD"),
    }
    if sys.platform == "darwin":
        sdk_name = platform_attestation["sdk"]
        for index, argument in enumerate(command[:-1]):
            if argument == "-isysroot":
                replacements[command[index + 1]] = f"$SDK/{sdk_name}"
    return [replacements.get(argument, argument) for argument in command]


def _wheel_tag(platform_attestation: dict[str, str]) -> str:
    python_abi = f"cp{sys.version_info.major}{sys.version_info.minor}"
    architecture = platform_attestation["architecture"]
    if sys.platform == "darwin":
        platform_tag = f"macosx_11_0_{architecture}"
    else:
        platform_tag = f"linux_{architecture}"
    return f"{python_abi}-{python_abi}-{platform_tag}"


def _audit_dynamic_binary(launcher_path: Path, python_library: Path) -> dict[str, Any]:
    if sys.platform == "darwin":
        otool = _canonical_tool("otool")
        dependencies = _run([str(otool), "-L", str(launcher_path)])
        load_commands = _run([str(otool), "-l", str(launcher_path)])
        admitted_dependencies = {
            line.strip().split(" ", maxsplit=1)[0]
            for line in dependencies.splitlines()[1:]
            if line.startswith("\t")
        }
        expected_dependencies = {
            str(python_library),
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        }
        if admitted_dependencies != expected_dependencies:
            raise RuntimeError(
                f"native launcher has unexpected dynamic dependencies: {admitted_dependencies}"
            )
        load_lines = load_commands.splitlines()
        rpaths = tuple(
            load_lines[index + 2].strip().split(" ", maxsplit=2)[1]
            for index, line in enumerate(load_lines[:-2])
            if line.strip() == "cmd LC_RPATH" and load_lines[index + 2].strip().startswith("path ")
        )
        if rpaths != (str(python_library.parent),):
            raise RuntimeError(f"native launcher has unexpected runtime paths: {rpaths}")
        return {
            "dependencies": sorted(admitted_dependencies),
            "rpath": rpaths,
            "tool": str(otool),
            "tool_sha256": _sha256(otool),
        }

    readelf = _canonical_tool("readelf")
    dynamic = _run([str(readelf), "-d", str(launcher_path)])
    if any(marker in dynamic for marker in ("(RPATH)", "(TEXTREL)")):
        raise RuntimeError("native launcher contains a forbidden ELF dynamic tag")
    dependencies = sorted(
        line.split("[", maxsplit=1)[1].split("]", maxsplit=1)[0]
        for line in dynamic.splitlines()
        if "(NEEDED)" in line and "[" in line and "]" in line
    )
    machine = platform.machine()
    architecture_dependencies = {
        "aarch64": ("ld-linux-aarch64.so.1", "libc.so.6", python_library.name),
        "x86_64": ("libc.so.6", python_library.name),
    }.get(machine)
    if architecture_dependencies is None:
        raise RuntimeError(f"unsupported Linux architecture: {machine}")
    expected_dependencies = sorted(architecture_dependencies)
    if dependencies != expected_dependencies:
        raise RuntimeError(f"native launcher has unexpected dynamic dependencies: {dependencies}")
    runpaths = tuple(
        line.split("[", maxsplit=1)[1].split("]", maxsplit=1)[0]
        for line in dynamic.splitlines()
        if "(RUNPATH)" in line and "[" in line and "]" in line
    )
    if runpaths != (str(python_library.parent),):
        raise RuntimeError(f"native launcher has unexpected runtime paths: {runpaths}")
    return {
        "dependencies": dependencies,
        "rpath": runpaths,
        "tool": str(readelf),
        "tool_sha256": _sha256(readelf),
    }


class CustomBuildHook(BuildHookInterface):
    """Compile the static launcher externally and include only reviewed artifacts."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        if sys.platform not in _SUPPORTED_PLATFORMS:
            raise RuntimeError(f"unsupported native build platform: {sys.platform}")
        if sys.version_info[:2] not in _SUPPORTED_PYTHON_MINORS:
            raise RuntimeError(f"unsupported native build Python: {sys.version_info[:2]}")
        build_dependencies = tuple(
            f"{distribution}=={importlib.metadata.version(distribution)}"
            for distribution, _version in _EXPECTED_BUILD_DEPENDENCIES
        )
        expected_build_dependencies = tuple(
            f"{distribution}=={version}" for distribution, version in _EXPECTED_BUILD_DEPENDENCIES
        )
        if build_dependencies != expected_build_dependencies:
            raise RuntimeError(f"unreviewed native build dependency closure: {build_dependencies}")
        hatchling_version = importlib.metadata.version("hatchling")
        if hatchling_version != _EXPECTED_HATCHLING_VERSION:
            raise RuntimeError(f"unreviewed Hatchling build backend: {hatchling_version}")

        core_source = (Path(self.root) / _CORE_SOURCE_RELATIVE_PATH).resolve(strict=True)
        launcher_source = (Path(self.root) / _LAUNCHER_SOURCE_RELATIVE_PATH).resolve(strict=True)
        wrapper_source = (Path(self.root) / _WRAPPER_SOURCE_RELATIVE_PATH).resolve(strict=True)
        source_sha256 = {
            "core": _sha256(core_source),
            "launcher": _sha256(launcher_source),
            "wrapper": _sha256(wrapper_source),
        }
        if source_sha256 != {
            "core": _EXPECTED_CORE_SOURCE_SHA256,
            "launcher": _EXPECTED_LAUNCHER_SOURCE_SHA256,
            "wrapper": _EXPECTED_WRAPPER_SOURCE_SHA256,
        }:
            raise RuntimeError("native launcher source identity is unreviewed")
        compiler = _compiler()
        include = _python_include()
        suffix = _extension_suffix()
        python_library = _python_library()
        python_home, python_stdlib, python_dynload = _python_runtime_paths()
        temporary_directory = Path(tempfile.mkdtemp(prefix="autoquant-native-launcher-"))
        generated_header = temporary_directory / "embedded_owned_file_descriptor_wrapper.h"
        core_object_path = temporary_directory / "owned_file_descriptor.o"
        launcher_object_path = temporary_directory / "trusted_time_python_launcher.o"
        launcher_path = temporary_directory / _LAUNCHER_BASENAME
        attestation_path = temporary_directory / _ATTESTATION_BASENAME
        _write_embedded_wrapper_header(wrapper_source, generated_header)

        (
            core_compile_command,
            launcher_compile_command,
            link_command,
            platform_attestation,
        ) = _compile_commands(
            compiler=compiler,
            core_source=core_source,
            launcher_source=launcher_source,
            include=include,
            generated_include=temporary_directory,
            core_object_path=core_object_path,
            launcher_object_path=launcher_object_path,
            launcher_path=launcher_path,
            extension_suffix=suffix,
            python_library=python_library,
            python_home=python_home,
            python_stdlib=python_stdlib,
            python_dynload=python_dynload,
        )
        _run(core_compile_command)
        _run(launcher_compile_command)
        _run(link_command)
        os.chmod(launcher_path, 0o555)
        dynamic_audit = _audit_dynamic_binary(launcher_path, python_library)
        compiler_version = _run([str(compiler), "--version"])
        wheel_tag = _wheel_tag(platform_attestation)
        attestation = {
            "build_backend": f"hatchling=={hatchling_version}",
            "build_dependencies": build_dependencies,
            "build_mode": version,
            "compiler": str(compiler),
            "compiler_sha256": _sha256(compiler),
            "compiler_version_sha256": hashlib.sha256(compiler_version.encode()).hexdigest(),
            "core_compile_command": _normalized_command(
                core_compile_command,
                compiler=compiler,
                core_source=core_source,
                launcher_source=launcher_source,
                include=include,
                generated_include=temporary_directory,
                core_object_path=core_object_path,
                launcher_object_path=launcher_object_path,
                launcher_path=launcher_path,
                python_library=python_library,
                python_home=python_home,
                python_stdlib=python_stdlib,
                python_dynload=python_dynload,
                extension_suffix=suffix,
                platform_attestation=platform_attestation,
            ),
            "dynamic": dynamic_audit,
            "extension_suffix": suffix,
            "launcher": {
                "basename": _LAUNCHER_BASENAME,
                "profile": "operational",
                "sha256": _sha256(launcher_path),
                "size": launcher_path.stat().st_size,
                "target_ids": _OPERATIONAL_TARGET_IDS,
            },
            "launcher_compile_command": _normalized_command(
                launcher_compile_command,
                compiler=compiler,
                core_source=core_source,
                launcher_source=launcher_source,
                include=include,
                generated_include=temporary_directory,
                core_object_path=core_object_path,
                launcher_object_path=launcher_object_path,
                launcher_path=launcher_path,
                python_library=python_library,
                python_home=python_home,
                python_stdlib=python_stdlib,
                python_dynload=python_dynload,
                extension_suffix=suffix,
                platform_attestation=platform_attestation,
            ),
            "link_command": _normalized_command(
                link_command,
                compiler=compiler,
                core_source=core_source,
                launcher_source=launcher_source,
                include=include,
                generated_include=temporary_directory,
                core_object_path=core_object_path,
                launcher_object_path=launcher_object_path,
                launcher_path=launcher_path,
                python_library=python_library,
                python_home=python_home,
                python_stdlib=python_stdlib,
                python_dynload=python_dynload,
                extension_suffix=suffix,
                platform_attestation=platform_attestation,
            ),
            "platform": sys.platform,
            "platform_attestation": platform_attestation,
            "python_header_sha256": _sha256(include / "Python.h"),
            "python_implementation": sys.implementation.name,
            "python_library": {
                "path": str(python_library),
                "sha256": _sha256(python_library),
                "size": python_library.stat().st_size,
            },
            "python_runtime": {
                "dynload": str(python_dynload),
                "home": str(python_home),
                "stdlib": str(python_stdlib),
                "trusted_time_prefix": _PRODUCTION_PREFIX,
            },
            "python_version": platform.python_version(),
            "project_version": str(self.metadata.version),
            "schema": "autoquant-native-owned-file-descriptor-launcher-build-v1",
            "sources": source_sha256,
            "wheel_tag": wheel_tag,
        }
        attestation_path.write_text(
            json.dumps(attestation, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(attestation_path, 0o444)

        shared_scripts = build_data.setdefault("shared_scripts", {})
        shared_scripts[str(launcher_path)] = _LAUNCHER_BASENAME
        shared_data = build_data.setdefault("shared_data", {})
        shared_data[str(attestation_path)] = str(_SHARED_NATIVE_DIRECTORY / attestation_path.name)
        build_data["pure_python"] = False
        build_data["infer_tag"] = False
        build_data["tag"] = wheel_tag
        build_data["_aqt_native_temporary_directory"] = str(temporary_directory)

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        del version, artifact_path
        temporary_directory = build_data.get("_aqt_native_temporary_directory")
        if type(temporary_directory) is str:
            shutil.rmtree(temporary_directory)
