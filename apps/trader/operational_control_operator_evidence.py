"""Read retained statement evidence bytes, never authenticate or resolve claims.

The new profile binds the claim to raw object bytes. Codec labels remain metadata;
neither file checks nor detached results prove semantic truth or control authority.
"""

from __future__ import annotations

import hashlib
import os
import stat
from os import name as platform_name
from pathlib import PosixPath, WindowsPath

from packages.adapters import research_artifacts_v2 as artifact_store
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.domain import operational_control_operator_statement as statements
from packages.domain import research_job_contracts as object_contracts
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.domain.research_job_contracts import MAX_OBJECT_BYTES, ObjectRef

_INVALID = "OPERATOR_STATEMENT_EVIDENCE_INVALID"
_CHANGED = "OPERATOR_STATEMENT_EVIDENCE_BINDING_CHANGED"
_STORE = LocalResearchArtifactStore
_READ = LocalResearchArtifactStore.read
_REFERENCE = ObjectRef
_STATEMENT = OperationalControlOperatorStatement
_COPY = statements.copy_operational_control_operator_statement
_SHA256 = hashlib.sha256
_MAXIMUM = MAX_OBJECT_BYTES
_PATH = PosixPath if platform_name == "posix" else WindowsPath
_CODECS = ("personal-record/1", "personal-research-dataset-v1", "personal-provider-json/1")
_STORE_METHODS = ("read", "_directory", "_limit", "_read")


def _bindings() -> None:
    for module, name, expected in _REFERENCES:
        if vars(module).get(name) is not expected:
            raise ValueError(_CHANGED)
    for owner, name, expected in _METHODS:
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for name, expected in _HELPERS:
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _store_root(artifacts: LocalResearchArtifactStore) -> PosixPath | WindowsPath:
    if type(artifacts) is not _STORE:
        raise ValueError(_INVALID)
    attributes = object.__getattribute__(artifacts, "__dict__")
    if type(attributes) is not dict or len(attributes) != 1:
        raise ValueError(_CHANGED)
    key = next(iter(attributes))
    if type(key) is not str or key != "_root":
        raise ValueError(_CHANGED)
    root = attributes.get("_root")
    if type(root) is not _PATH:
        raise ValueError(_INVALID)
    return root


def _native_reference_fields(digest: object, count: object, codec: object) -> bool:
    return type(digest) is str and type(count) is int and type(codec) is str


def _entry(reader: OperatorStatementEvidenceReader) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    if type(reader) is not _READER or reader._self is not reader:
        raise ValueError(_INVALID)
    artifacts, root, bound, original = (
        reader._artifacts,
        reader._root,
        reader._max_bytes,
        reader._configuration,
    )
    if (
        type(original) is not tuple
        or len(original) != 3
        or type(bound) is not int
        or not 0 < bound <= _MAXIMUM
        or artifacts is not original[0]
        or root is not original[1]
        or bound is not original[2]
        or _STORE_ROOT(artifacts) is not root
    ):
        raise ValueError(_CHANGED)


class OperatorStatementEvidenceReader:
    """A fixed existing store and byte bound; configuration grants no authority."""

    __slots__ = ("_artifacts", "_configuration", "_max_bytes", "_root", "_self")

    def __init__(self, artifacts: LocalResearchArtifactStore, *, max_bytes: int) -> None:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        if type(self) is not _READER or type(max_bytes) is not int:
            raise ValueError(_INVALID)
        root = _STORE_ROOT(artifacts)
        if not 0 < max_bytes <= _MAXIMUM:
            raise ValueError(_INVALID)
        self._artifacts = artifacts
        self._root = root
        self._max_bytes = max_bytes
        self._self = self
        self._configuration = (artifacts, root, max_bytes)
        _ENTRY(self)

    def read(
        self,
        statement: OperationalControlOperatorStatement,
        reference: ObjectRef,
    ) -> tuple[OperationalControlOperatorStatement, ObjectRef, bytes]:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        _ENTRY(self)
        artifacts, bound = self._artifacts, self._max_bytes
        if type(reference) is not _REFERENCE:
            raise ValueError(_INVALID)
        digest, count, codec = (
            reference.object_sha256,
            reference.byte_count,
            reference.codec_version,
        )
        if not _NATIVE_REFERENCE_FIELDS(digest, count, codec):
            raise ValueError(_INVALID)
        # All reference leaves are frozen before D admission can run any helper.
        copied_statement = _COPY(statement)
        copied_reference = _REFERENCE(digest, count, codec)
        if (
            codec not in _CODECS
            or count > bound
            or copied_statement.resolution_claim.resolution_evidence_sha256 != digest
        ):
            raise ValueError(_INVALID)
        _ENTRY(self)
        payload = _READ(artifacts, copied_reference, max_bytes=bound)
        # Configured path metadata is not inode custody or physical-return presence.
        _ENTRY(self)
        if (
            type(payload) is not bytes
            or len(payload) != count
            or _SHA256(payload).hexdigest() != digest
        ):
            raise ValueError(_INVALID)
        returned_reference = _REFERENCE(digest, count, codec)
        _ENTRY(self)
        return copied_statement, returned_reference, payload


_READER = OperatorStatementEvidenceReader
_BINDINGS = _bindings
_STORE_ROOT = _store_root
_NATIVE_REFERENCE_FIELDS = _native_reference_fields
_ENTRY = _entry
_METHODS = (
    *((_STORE, name, vars(_STORE)[name]) for name in _STORE_METHODS),
    (_STORE, "__getattribute__", vars(_STORE).get("__getattribute__")),
    (_STORE, "__getattr__", vars(_STORE).get("__getattr__")),
    (_REFERENCE, "__init__", _REFERENCE.__init__),
    (_REFERENCE, "__post_init__", _REFERENCE.__post_init__),
    (_STATEMENT, "__init__", _STATEMENT.__init__),
    (_STATEMENT, "__post_init__", _STATEMENT.__post_init__),
    (_STATEMENT, "canonical_json", vars(_STATEMENT)["canonical_json"]),
    (_STATEMENT, "semantic_sha256", vars(_STATEMENT)["semantic_sha256"]),
    (_READER, "read", _READER.read),
    *(
        (original, name, vars(original)[name])
        for original in (
            OperationalControlActor,
            OperationalControlBlockingEvent,
            OperationalControlIncidentDisposition,
        )
        for name in ("__init__", "__post_init__", "semantic_sha256")
    ),
    (
        OperationalControlBlockingEvent,
        "event_id",
        vars(OperationalControlBlockingEvent)["event_id"],
    ),
)
_REFERENCES = (
    (artifact_store, "LocalResearchArtifactStore", _STORE),
    (artifact_store, "ObjectRef", _REFERENCE),
    (artifact_store, "os", os),
    (artifact_store, "stat", stat),
    (artifact_store, "hashlib", hashlib),
    (object_contracts, "ObjectRef", _REFERENCE),
    (object_contracts, "MAX_OBJECT_BYTES", _MAXIMUM),
    (hashlib, "sha256", _SHA256),
    *(
        (module, name, vars(module)[name])
        for module, names in (
            (os, ("open", "fstat", "getuid", "close", "fdopen")),
            (stat, ("S_ISDIR", "S_ISREG", "S_IMODE")),
        )
        for name in names
    ),
    (artifact_store, "MAX_OBJECT_BYTES", _MAXIMUM),
    *(
        (statements, name, vars(statements)[name])
        for name in (
            "OperationalControlOperatorStatement",
            "copy_operational_control_operator_statement",
            "_validated_values",
            "_non_running_state",
            "_statement_id",
            "_semantic_material",
            "OperationalControlActor",
            "OperationalControlActorKind",
            "OperationalControlBlockingEvent",
            "OperationalControlIncidentDisposition",
            "OperationalControlState",
            "_require_text",
            "_require_sha256",
            "_require_idempotency_key",
            "_require_utc",
            "canonical_id",
            "canonical_json_bytes",
            "canonical_json_text",
            "UTC",
            "datetime",
            "_FIELDS",
        )
    ),
)
_HELPERS = tuple(
    (name, globals()[name])
    for name in (
        "_bindings",
        "_BINDINGS",
        "_store_root",
        "_STORE_ROOT",
        "_native_reference_fields",
        "_NATIVE_REFERENCE_FIELDS",
        "_entry",
        "_ENTRY",
        "_STORE",
        "_READ",
        "_REFERENCE",
        "_STATEMENT",
        "_COPY",
        "_SHA256",
        "_MAXIMUM",
        "_PATH",
        "_CODECS",
        "_STORE_METHODS",
        "_READER",
    )
)
