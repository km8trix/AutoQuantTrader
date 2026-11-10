"""Verified binding for the checked-in no-exposure smoke strategy artifact."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from packages.application.supervised_strategy import StrategySubprocessSpec
from packages.domain.canonical import canonical_json_bytes
from packages.domain.strategy_supervision import (
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyInvocation,
    StrategyProtocolResponse,
    StrategySupervisionConflict,
    StrategySupervisionError,
)

NO_EXPOSURE_SMOKE_ARTIFACT_FORMAT = "aqt-no-exposure-smoke-artifact-v1"
NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION = "aqt-no-exposure-smoke-result-v1"
NO_EXPOSURE_SMOKE_STRATEGY_ID = "no-exposure-smoke"
NO_EXPOSURE_SMOKE_STRATEGY_VERSION = "1.0.0"
NO_EXPOSURE_SMOKE_ENTRYPOINT = "strategy.py"
NO_EXPOSURE_SMOKE_RUNTIME_ID = "cpython-isolated-no-exposure-smoke"
NO_EXPOSURE_SMOKE_ARTIFACT_SHA256 = (
    "4aff3d9b40d4ff180898fea61e936f36679c117b19b16adf322a9f96cc2248e1"
)
NO_EXPOSURE_SMOKE_MANIFEST_SHA256 = (
    "ef1321b35743d941a7c93ed86f39710b43eec75f6fb1b0efc3156e088f140344"
)
MAX_NO_EXPOSURE_MANIFEST_BYTES = 16_384
MAX_NO_EXPOSURE_ARTIFACT_BYTES = 65_536

NO_EXPOSURE_SMOKE_BOOTSTRAP = (
    "import hashlib,sys\n"
    "def fail():\n"
    ' sys.stderr.write("no-exposure smoke artifact rejected\\n")\n'
    " raise SystemExit(2)\n"
    "try:\n"
    ' stream=open(sys.argv[1],"rb")\n'
    f" source=stream.read({MAX_NO_EXPOSURE_ARTIFACT_BYTES + 1})\n"
    " stream.close()\n"
    "except OSError:\n"
    " fail()\n"
    "if not source or len(source)>65536 or hashlib.sha256(source).hexdigest()!=sys.argv[2]:\n"
    " fail()\n"
    'namespace={"__file__":sys.argv[1],"__name__":"__main__","__package__":None}\n'
    'exec(compile(source,sys.argv[1],"exec"),namespace,namespace)\n'
)

NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            NO_EXPOSURE_SMOKE_ARTIFACT_FORMAT,
            "configuration",
            "no-configurable-values",
        )
    )
).hexdigest()

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NO_EXPOSURE_SMOKE_MANIFEST = (
    _REPOSITORY_ROOT / "strategy_artifacts/no_exposure_smoke_v1/manifest.json"
)
_MANIFEST_KEYS = {
    "artifact_format",
    "artifact_sha256",
    "entrypoint",
    "protocol_version",
    "result_contract_version",
    "strategy_configuration_sha256",
    "strategy_id",
    "strategy_version",
}


class NoExposureSmokeArtifactError(StrategySupervisionError):
    """The smoke artifact or its checked-in manifest is invalid."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise NoExposureSmokeArtifactError(f"{field_name} must be a lowercase SHA-256 digest")


def _plain_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise NoExposureSmokeArtifactError("smoke manifest is not canonically encodable") from error


def _read_stable_regular_file(path: Path, *, limit: int, label: str) -> bytes:
    if not isinstance(path, Path):
        raise NoExposureSmokeArtifactError(f"{label} path must be a pathlib.Path")
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise NoExposureSmokeArtifactError(f"{label} must be a regular non-symlink file")
        if before.st_size < 1 or before.st_size > limit:
            raise NoExposureSmokeArtifactError(f"{label} size is outside the fixed bound")
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise NoExposureSmokeArtifactError(f"{label} cannot be read") from error
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(payload) != before.st_size:
        raise NoExposureSmokeArtifactError(f"{label} changed while it was read")
    return payload


def _reject_float(_value: str) -> object:
    raise NoExposureSmokeArtifactError("smoke manifest does not permit floating-point numbers")


def _reject_constant(_value: str) -> object:
    raise NoExposureSmokeArtifactError("smoke manifest does not permit non-finite numbers")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NoExposureSmokeArtifactError(f"smoke manifest repeats key {key!r}")
        result[key] = value
    return result


def _decode_manifest(payload: bytes) -> dict[str, object]:
    body = payload[:-1] if payload.endswith(b"\n") else payload
    try:
        decoded = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except NoExposureSmokeArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise NoExposureSmokeArtifactError("smoke manifest is not valid UTF-8 JSON") from error
    if type(decoded) is not dict or set(decoded) != _MANIFEST_KEYS:
        raise NoExposureSmokeArtifactError("smoke manifest has missing or unsupported fields")
    if _plain_json_bytes(decoded) != body:
        raise NoExposureSmokeArtifactError("smoke manifest must use canonical JSON encoding")
    return decoded


def _artifact_material(
    *,
    manifest_sha256: str,
    strategy_configuration_sha256: str,
    subprocess_spec: StrategySubprocessSpec,
    strategy_id: str,
    strategy_version: str,
    result_contract_version: str,
) -> tuple[object, ...]:
    return (
        NO_EXPOSURE_SMOKE_ARTIFACT_FORMAT,
        "verified_artifact",
        manifest_sha256,
        strategy_configuration_sha256,
        subprocess_spec.argv,
        subprocess_spec.runtime_id,
        subprocess_spec.runtime_version,
        subprocess_spec.artifact_sha256,
        subprocess_spec.launch_spec_sha256,
        strategy_id,
        strategy_version,
        result_contract_version,
    )


@dataclass(frozen=True, slots=True)
class _NoExposureSmokeArtifactSeal:
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class NoExposureSmokeArtifact:
    """Sealed verified metadata and exact strict-subprocess binding."""

    manifest_sha256: str
    strategy_configuration_sha256: str
    subprocess_spec: StrategySubprocessSpec
    strategy_id: str
    strategy_version: str
    result_contract_version: str
    _seal: _NoExposureSmokeArtifactSeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_sha256, "smoke artifact manifest_sha256")
        if self.manifest_sha256 != NO_EXPOSURE_SMOKE_MANIFEST_SHA256:
            raise NoExposureSmokeArtifactError("smoke artifact manifest digest is unsupported")
        if self.strategy_id != NO_EXPOSURE_SMOKE_STRATEGY_ID:
            raise NoExposureSmokeArtifactError("smoke artifact strategy ID is unsupported")
        if self.strategy_version != NO_EXPOSURE_SMOKE_STRATEGY_VERSION:
            raise NoExposureSmokeArtifactError("smoke artifact strategy version is unsupported")
        if self.result_contract_version != NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION:
            raise NoExposureSmokeArtifactError("smoke artifact result contract is unsupported")
        if self.strategy_configuration_sha256 != NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256:
            raise NoExposureSmokeArtifactError("smoke artifact configuration digest is unsupported")
        if type(self.subprocess_spec) is not StrategySubprocessSpec:
            raise NoExposureSmokeArtifactError("smoke artifact requires an exact subprocess spec")
        self.subprocess_spec.__post_init__()
        if self.subprocess_spec.runtime_id != NO_EXPOSURE_SMOKE_RUNTIME_ID:
            raise NoExposureSmokeArtifactError("smoke artifact runtime ID is unsupported")
        if self.subprocess_spec.artifact_sha256 != NO_EXPOSURE_SMOKE_ARTIFACT_SHA256:
            raise NoExposureSmokeArtifactError("smoke artifact source digest is unsupported")
        if (
            len(self.subprocess_spec.argv) != 7
            or self.subprocess_spec.argv[1:5] != ("-I", "-S", "-c", NO_EXPOSURE_SMOKE_BOOTSTRAP)
            or Path(self.subprocess_spec.argv[5]).name != NO_EXPOSURE_SMOKE_ENTRYPOINT
            or self.subprocess_spec.argv[6] != NO_EXPOSURE_SMOKE_ARTIFACT_SHA256
        ):
            raise NoExposureSmokeArtifactError("smoke artifact launch bootstrap is unsupported")
        if type(self._seal) is not _NoExposureSmokeArtifactSeal:
            raise NoExposureSmokeArtifactError("smoke artifact requires loader verification")
        expected_seal = _sha256(
            canonical_json_bytes(
                _artifact_material(
                    manifest_sha256=self.manifest_sha256,
                    strategy_configuration_sha256=self.strategy_configuration_sha256,
                    subprocess_spec=self.subprocess_spec,
                    strategy_id=self.strategy_id,
                    strategy_version=self.strategy_version,
                    result_contract_version=self.result_contract_version,
                )
            )
        )
        if self._seal.payload_sha256 != expected_seal:
            raise NoExposureSmokeArtifactError("smoke artifact verification seal is invalid")


def _make_verified_artifact(
    *,
    manifest_sha256: str,
    subprocess_spec: StrategySubprocessSpec,
) -> NoExposureSmokeArtifact:
    material = _artifact_material(
        manifest_sha256=manifest_sha256,
        strategy_configuration_sha256=NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
        subprocess_spec=subprocess_spec,
        strategy_id=NO_EXPOSURE_SMOKE_STRATEGY_ID,
        strategy_version=NO_EXPOSURE_SMOKE_STRATEGY_VERSION,
        result_contract_version=NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
    )
    return NoExposureSmokeArtifact(
        manifest_sha256=manifest_sha256,
        strategy_configuration_sha256=NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
        subprocess_spec=subprocess_spec,
        strategy_id=NO_EXPOSURE_SMOKE_STRATEGY_ID,
        strategy_version=NO_EXPOSURE_SMOKE_STRATEGY_VERSION,
        result_contract_version=NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
        _seal=_NoExposureSmokeArtifactSeal(payload_sha256=_sha256(canonical_json_bytes(material))),
    )


def _evidence_material(
    *,
    invocation_id: str,
    invocation_sha256: str,
    market_batch_id: str,
    market_batch_sha256: str,
    result_sha256: str,
    proposed_intent_count: int,
    exposure_authorized: bool,
) -> tuple[object, ...]:
    return (
        NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
        "evidence",
        invocation_id,
        invocation_sha256,
        market_batch_id,
        market_batch_sha256,
        result_sha256,
        proposed_intent_count,
        exposure_authorized,
    )


@dataclass(frozen=True, slots=True)
class _NoExposureSmokeEvidenceSeal:
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class NoExposureSmokeEvidence:
    """Non-authorizing proof that the exact smoke child proposed no intents."""

    invocation_id: str
    invocation_sha256: str
    market_batch_id: str
    market_batch_sha256: str
    result_sha256: str
    proposed_intent_count: int
    exposure_authorized: bool
    _seal: _NoExposureSmokeEvidenceSeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.invocation_id, "smoke evidence invocation ID"),
            (self.market_batch_id, "smoke evidence market batch ID"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise NoExposureSmokeArtifactError(f"{field_name} must be non-empty trimmed text")
        _require_sha256(
            self.invocation_sha256,
            "smoke evidence invocation_sha256",
        )
        _require_sha256(
            self.market_batch_sha256,
            "smoke evidence market_batch_sha256",
        )
        _require_sha256(self.result_sha256, "smoke evidence result_sha256")
        if (
            type(self.proposed_intent_count) is not int
            or self.proposed_intent_count != 0
            or self.exposure_authorized is not False
        ):
            raise NoExposureSmokeArtifactError(
                "no-exposure smoke evidence cannot contain or authorize exposure"
            )
        if type(self._seal) is not _NoExposureSmokeEvidenceSeal:
            raise NoExposureSmokeArtifactError(
                "no-exposure smoke evidence requires verified response construction"
            )
        if self._seal.payload_sha256 != _sha256(
            canonical_json_bytes(
                _evidence_material(
                    invocation_id=self.invocation_id,
                    invocation_sha256=self.invocation_sha256,
                    market_batch_id=self.market_batch_id,
                    market_batch_sha256=self.market_batch_sha256,
                    result_sha256=self.result_sha256,
                    proposed_intent_count=self.proposed_intent_count,
                    exposure_authorized=self.exposure_authorized,
                )
            )
        ):
            raise NoExposureSmokeArtifactError(
                "no-exposure smoke evidence verification seal is invalid"
            )

    @property
    def semantic_sha256(self) -> str:
        return self._seal.payload_sha256


def verify_no_exposure_smoke_artifact(
    manifest_path: Path,
) -> NoExposureSmokeArtifact:
    """Verify a manifest and artifact before creating the launch spec."""

    manifest_bytes = _read_stable_regular_file(
        manifest_path,
        limit=MAX_NO_EXPOSURE_MANIFEST_BYTES,
        label="no-exposure smoke manifest",
    )
    if _sha256(manifest_bytes) != NO_EXPOSURE_SMOKE_MANIFEST_SHA256:
        raise NoExposureSmokeArtifactError(
            "no-exposure smoke manifest does not match the reviewed digest"
        )
    manifest = _decode_manifest(manifest_bytes)
    expected = {
        "artifact_format": NO_EXPOSURE_SMOKE_ARTIFACT_FORMAT,
        "entrypoint": NO_EXPOSURE_SMOKE_ENTRYPOINT,
        "protocol_version": STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
        "result_contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
        "strategy_configuration_sha256": NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
        "strategy_id": NO_EXPOSURE_SMOKE_STRATEGY_ID,
        "strategy_version": NO_EXPOSURE_SMOKE_STRATEGY_VERSION,
    }
    for field_name, expected_value in expected.items():
        if manifest[field_name] != expected_value:
            raise NoExposureSmokeArtifactError(f"smoke manifest {field_name} is unsupported")
    artifact_sha256 = manifest["artifact_sha256"]
    _require_sha256(artifact_sha256, "smoke manifest artifact_sha256")
    assert type(artifact_sha256) is str
    if artifact_sha256 != NO_EXPOSURE_SMOKE_ARTIFACT_SHA256:
        raise NoExposureSmokeArtifactError("smoke manifest artifact digest is unsupported")

    artifact_path = manifest_path.parent / NO_EXPOSURE_SMOKE_ENTRYPOINT
    artifact_bytes = _read_stable_regular_file(
        artifact_path,
        limit=MAX_NO_EXPOSURE_ARTIFACT_BYTES,
        label="no-exposure smoke artifact",
    )
    if _sha256(artifact_bytes) != artifact_sha256:
        raise NoExposureSmokeArtifactError(
            "no-exposure smoke artifact does not match its manifest digest"
        )

    executable_path = Path(sys.executable).resolve(strict=True)
    spec = StrategySubprocessSpec(
        argv=(
            str(executable_path),
            "-I",
            "-S",
            "-c",
            NO_EXPOSURE_SMOKE_BOOTSTRAP,
            str(artifact_path.resolve(strict=True)),
            artifact_sha256,
        ),
        runtime_id=NO_EXPOSURE_SMOKE_RUNTIME_ID,
        runtime_version=platform.python_version(),
        artifact_sha256=artifact_sha256,
    )
    return _make_verified_artifact(
        manifest_sha256=_sha256(manifest_bytes),
        subprocess_spec=spec,
    )


def load_no_exposure_smoke_artifact() -> NoExposureSmokeArtifact:
    """Load the one repository-owned smoke artifact; this does not execute it."""

    return verify_no_exposure_smoke_artifact(NO_EXPOSURE_SMOKE_MANIFEST)


def verify_no_exposure_smoke_response(
    response: StrategyProtocolResponse,
    invocation: StrategyInvocation,
    artifact: NoExposureSmokeArtifact,
) -> NoExposureSmokeEvidence:
    """Accept only the exact empty-intent result for its bound invocation."""

    if type(response) is not StrategyProtocolResponse:
        raise NoExposureSmokeArtifactError("smoke verification requires an exact protocol response")
    if type(invocation) is not StrategyInvocation:
        raise NoExposureSmokeArtifactError(
            "smoke verification requires an exact strategy invocation"
        )
    if type(artifact) is not NoExposureSmokeArtifact:
        raise NoExposureSmokeArtifactError("smoke verification requires an exact verified artifact")
    artifact.__post_init__()
    if (
        invocation.strategy_id != artifact.strategy_id
        or invocation.strategy_version != artifact.strategy_version
        or invocation.strategy_configuration_sha256 != artifact.strategy_configuration_sha256
        or invocation.runtime != artifact.subprocess_spec.runtime_binding
    ):
        raise StrategySupervisionConflict(
            "no-exposure smoke invocation is not bound to the verified artifact"
        )
    if (
        response.invocation_id != invocation.invocation_id
        or response.invocation_sha256 != invocation.semantic_sha256
    ):
        raise StrategySupervisionConflict(
            "no-exposure smoke response crosses invocation identities"
        )
    try:
        result = json.loads(response.result_json)
    except (json.JSONDecodeError, ValueError) as error:
        raise NoExposureSmokeArtifactError("no-exposure smoke result is not valid JSON") from error
    expected = {
        "contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
        "decision": "NO_EXPOSURE",
        "market_batch_id": invocation.market_batch_id,
        "market_batch_sha256": invocation.market_batch_sha256,
        "proposed_intents": [],
    }
    if result != expected:
        raise NoExposureSmokeArtifactError(
            "no-exposure smoke result is not the exact empty-intent observation"
        )
    material = _evidence_material(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        market_batch_id=invocation.market_batch_id,
        market_batch_sha256=invocation.market_batch_sha256,
        result_sha256=response.result_sha256,
        proposed_intent_count=0,
        exposure_authorized=False,
    )
    return NoExposureSmokeEvidence(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        market_batch_id=invocation.market_batch_id,
        market_batch_sha256=invocation.market_batch_sha256,
        result_sha256=response.result_sha256,
        proposed_intent_count=0,
        exposure_authorized=False,
        _seal=_NoExposureSmokeEvidenceSeal(payload_sha256=_sha256(canonical_json_bytes(material))),
    )


__all__ = [
    "NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256",
    "NO_EXPOSURE_SMOKE_MANIFEST",
    "NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION",
    "NO_EXPOSURE_SMOKE_RUNTIME_ID",
    "NO_EXPOSURE_SMOKE_STRATEGY_ID",
    "NO_EXPOSURE_SMOKE_STRATEGY_VERSION",
    "NoExposureSmokeArtifact",
    "NoExposureSmokeArtifactError",
    "NoExposureSmokeEvidence",
    "load_no_exposure_smoke_artifact",
    "verify_no_exposure_smoke_artifact",
    "verify_no_exposure_smoke_response",
]
