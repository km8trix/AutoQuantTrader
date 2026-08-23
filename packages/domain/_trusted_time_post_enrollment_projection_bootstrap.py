"""One-shot, non-authorizing type staging for topology projection sealing.

The staged objects are public evidence types and their original slot descriptors;
they are not issuer, filesystem, choreography, or outcome-retention authority.
Definitions are staged by an outer decorator before ``STORE_NAME`` and are made
consumable only after a no-argument module finalizer confirms the exact published
class identities.  The topology reader consumes the complete start family once
during its own import and then retires every bootstrap cell.
"""

from __future__ import annotations

import hashlib
import marshal
import sys
from collections.abc import Callable
from types import CodeType, MappingProxyType, MemberDescriptorType
from typing import Any, Never


class _ProjectionBootstrapError(ImportError):
    pass


_EXACT_SHA256_OWNER_TYPE = type(hashlib.sha256())
_EXACT_MODULE_TYPE = type(sys)
_EXACT_FRAME_TYPE = type(sys._getframe())
_EXACT_BOOTSTRAP_MODULE_GLOBALS = sys._getframe().f_globals


type _StagedType = tuple[
    str,
    type[object],
    tuple[tuple[str, MemberDescriptorType], ...],
]
type _StartProjectionRecipe = tuple[
    str,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
    _StagedType,
]


def _build_start_projection_bootstrap(
    *,
    _getframe: Callable[[int], object] = sys._getframe,
    _sha256: Callable[..., Any] = hashlib.sha256,
    _hexdigest: Callable[..., str] = _EXACT_SHA256_OWNER_TYPE.hexdigest,
    _marshal_dumps: Callable[..., bytes] = marshal.dumps,
    _code_type: type[CodeType] = CodeType,
    _member_descriptor_type: type[MemberDescriptorType] = MemberDescriptorType,
    _member_descriptor_get: Callable[..., object] = MemberDescriptorType.__get__,
    _member_objclass_descriptor: MemberDescriptorType = (
        MemberDescriptorType.__dict__["__objclass__"]
    ),
    _member_name_descriptor: MemberDescriptorType = MemberDescriptorType.__dict__["__name__"],
    _error_type: type[_ProjectionBootstrapError] = _ProjectionBootstrapError,
    _sys_modules: dict[str, Any] = sys.modules,
    _module_type: type[object] = _EXACT_MODULE_TYPE,
    _mappingproxy_type: type[MappingProxyType[Any, Any]] = MappingProxyType,
    _mappingproxy_get: Callable[..., Any] = MappingProxyType.get,
    _frame_type: type[object] = _EXACT_FRAME_TYPE,
    _frame_getattribute: Callable[..., Any] = _EXACT_FRAME_TYPE.__getattribute__,
    _object_getattribute: Callable[..., Any] = object.__getattribute__,
    _type: Callable[[object], type[Any]] = type,
    _type_type: type[object] = type,
    _tuple_type: type[tuple[object, ...]] = tuple,
    _dict_type: type[dict[object, object]] = dict,
    _frozenset_type: type[frozenset[object]] = frozenset,
    _str_type: type[str] = str,
    _type_getattribute: Callable[..., Any] = type.__getattribute__,
    _tuple: Callable[..., tuple[Any, ...]] = tuple,
    _len: Callable[[Any], int] = len,
    _dict_get: Callable[..., Any] = dict.get,
    _dict_pop: Callable[..., Any] = dict.pop,
    _tuple_getitem: Callable[..., Any] = tuple.__getitem__,
    _any: Callable[..., bool] = any,
    _zip: Callable[..., Any] = zip,
    _sorted: Callable[..., list[Any]] = sorted,
    _immutable_scalar_types: frozenset[type[object]] = frozenset((bool, int, float, str, bytes)),
    _ellipsis: object = Ellipsis,
    _str_endswith: Callable[..., bool] = str.endswith,
    _str_replace: Callable[..., str] = str.replace,
    _python_minor: tuple[int, int] = (sys.version_info[0], sys.version_info[1]),
    _bootstrap_globals: dict[str, Any] = _EXACT_BOOTSTRAP_MODULE_GLOBALS,
) -> tuple[
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[], None],
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[type[object]], type[object]],
    Callable[[], None],
    Callable[[type[object]], type[object]],
    Callable[[], None],
    Callable[[], _StartProjectionRecipe],
    Callable[[], None],
]:
    immutable_launch: _StagedType | None = None
    first_enrollment_identities: _StagedType | None = None
    sequence_one: _StagedType | None = None
    confirmed_first_enrollment: _StagedType | None = None
    post_enrollment_review: _StagedType | None = None
    approval: _StagedType | None = None
    reauthentication: _StagedType | None = None
    claim: _StagedType | None = None
    retained_claim: _StagedType | None = None
    evidence_finalized = False
    domain_finalized = False
    retained_finalized = False
    consumed = False

    def fail() -> Never:
        raise _error_type("trusted-time projection bootstrap is unavailable")

    evidence_module_name = "packages.domain.trusted_time_enrollment_evidence"
    domain_module_name = "packages.domain.trusted_time_post_enrollment_start"
    retained_module_name = "scripts.trusted_time_post_enrollment_start"
    reader_module_name = "scripts.trusted_time_post_enrollment_topology_reader"
    if _python_minor == (3, 12):
        expected_evidence_module_sha256 = (
            "6a8e102cc0520a584d5261f16854ccf1b493b5533af51c3ab57655dcaa19db1d"
        )
        evidence_immutable_launch_stage_calls: tuple[tuple[int, int], ...] = ((294, 804),)
        evidence_identities_stage_calls: tuple[tuple[int, int], ...] = ((328, 860),)
        evidence_sequence_one_stage_calls: tuple[tuple[int, int], ...] = ((356, 916),)
        evidence_confirmed_stage_calls: tuple[tuple[int, int], ...] = ((418, 972),)
        evidence_review_stage_calls: tuple[tuple[int, int], ...] = ((472, 1028),)
        evidence_finalize_calls: tuple[tuple[int, int], ...] = ((527, 1042),)
        expected_domain_module_sha256 = (
            "952deee3eac278407f86b024f5ef5d3a4ae0e3a59d53516b670759fdcc1f1c12"
        )
        expected_retained_module_sha256 = (
            "bdce96aa738923250294cb09dacbc60362aca25c885d88039fcb7754f6302aa5"
        )
        domain_approval_stage_calls = ((87, 252),)
        domain_reauthentication_stage_calls = ((148, 308),)
        domain_claim_stage_calls = ((302, 384),)
        domain_finalize_calls = ((500, 512),)
        retained_claim_stage_calls = ((74, 516),)
        retained_finalize_calls = ((859, 866),)
        expected_reader_module_sha256 = (
            "e7c6076c15105c0fa823ca4cac7008562134abfd2d098dd243a5f3e5a2e0a0e8"
        )
        reader_take_calls = ((1608, 2428),)
        reader_retire_calls = (
            (1809, 2994),
            (1814, 3010),
            (1819, 3026),
            (1824, 3042),
            (1824, 20274),
            (1819, 20354),
            (1824, 20426),
            (1824, 20500),
            (1814, 20586),
            (1819, 20658),
            (1824, 20730),
            (1824, 20804),
            (1819, 20884),
            (1824, 20956),
            (1824, 21030),
        )
    elif _python_minor == (3, 13):
        expected_evidence_module_sha256 = (
            "1a3ab3c3ff2ed594a99bdc2909a24b9e648e248794a55bb376f64fdaa719dc52"
        )
        evidence_immutable_launch_stage_calls = ((294, 810),)
        evidence_identities_stage_calls = ((328, 860),)
        evidence_sequence_one_stage_calls = ((356, 910),)
        evidence_confirmed_stage_calls = ((418, 960),)
        evidence_review_stage_calls = ((472, 1010),)
        evidence_finalize_calls = ((527, 1024),)
        expected_domain_module_sha256 = (
            "845faddab43d252133f78e9b68ff06d11855f8b30fa27a39e9f0279c6aaed225"
        )
        expected_retained_module_sha256 = (
            "96ca1e14a1c064e98c11f41ce2db187d31d6b29dec291c093991a7aa6bf4d26f"
        )
        domain_approval_stage_calls = ((87, 248),)
        domain_reauthentication_stage_calls = ((148, 298),)
        domain_claim_stage_calls = ((302, 370),)
        domain_finalize_calls = ((500, 486),)
        retained_claim_stage_calls = ((74, 504),)
        retained_finalize_calls = ((859, 892),)
        expected_reader_module_sha256 = (
            "453d13bfcc005ece1d768a6b63c11cd4eeeb8e76a6dcc309458be1a89fb8cc5a"
        )
        reader_take_calls = ((1608, 2484),)
        reader_retire_calls = (
            (1809, 3006),
            (1814, 3022),
            (1819, 3038),
            (1824, 3054),
            (1824, 21292),
            (1819, 21374),
            (1824, 21448),
            (1824, 21524),
            (1814, 21612),
            (1819, 21686),
            (1824, 21760),
            (1824, 21836),
            (1819, 21918),
            (1824, 21992),
            (1824, 22068),
        )
    else:
        fail()

    immutable_launch_slots = (
        "git_revision",
        "image_admission_sha256",
        "source_image_id",
        "supervisor_image_id",
    )
    first_enrollment_identities_slots = (
        "anchor_authority_sha256",
        "anchor_project_identity_sha256",
        "bucket_identity_sha256",
        "deployment_identity_sha256",
        "host_identity_sha256",
        "principal_identity_sha256",
        "runtime_database_identity_sha256",
        "signing_public_key_sha256",
        "source_authority_sha256",
    )
    sequence_one_slots = (
        "completion_disposition",
        "uploaded_anchor_count",
        "idempotent_duplicate_count",
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "current_anchor_semantic_sha256",
        "current_anchor_sha256",
        "current_host_head_sha256",
        "receipt_semantic_sha256",
        "remote_namespace_sha256",
    )
    confirmed_first_enrollment_slots = (
        "operation_id",
        "approval_sha256",
        "claim_sha256",
        "outcome_sha256",
        "unenrolled_admission_sha256",
        "enrollment_launch",
        "identities",
        "sequence_one",
    )
    post_enrollment_review_slots = (
        "confirmed_enrollment",
        "proposed_launch",
    )
    approval_slots = ("operation_id", "review")
    reauthentication_slots = (
        "operation_id",
        "approval_sha256",
        "confirmed_enrollment_evidence_sha256",
        "review_projection_sha256",
        "identities",
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_highest_anchor_sequence",
        "remote_highest_anchor_sequence",
        "remote_object_count",
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "current_anchor_semantic_sha256",
        "current_anchor_sha256",
        "current_host_head_sha256",
        "receipt_semantic_sha256",
        "remote_namespace_sha256",
        "full_audit_completed",
        "pending_intent_present",
        "higher_sequence_present",
    )
    claim_slots = ("approval", "reauthentication")
    retained_claim_slots = (
        "claim",
        "operation_id",
        "claim_projection_sha256",
        "artifact_sha256",
        "artifact_path",
        "encoded",
        "file_identity",
        "__weakref__",
    )
    exported_sink_names = (
        "_stage_trusted_time_immutable_launch_projection_type",
        "_stage_trusted_time_first_enrollment_identities_projection_type",
        "_stage_trusted_time_sequence_one_projection_type",
        "_stage_trusted_time_confirmed_first_enrollment_projection_type",
        "_stage_trusted_time_post_enrollment_start_review_projection_type",
        "_finalize_trusted_time_enrollment_evidence_projection_types",
        "_stage_post_enrollment_start_approval_projection_type",
        "_stage_post_enrollment_runtime_reauthentication_projection_type",
        "_stage_post_enrollment_start_claim_projection_type",
        "_finalize_post_enrollment_start_domain_projection_types",
        "_stage_retained_post_enrollment_start_claim_projection_type",
        "_finalize_retained_post_enrollment_start_claim_projection_type",
        "_take_finalized_start_projection_recipe",
        "_retire_finalized_start_projection_recipe",
    )

    def immutable_code_material(value: Any) -> object:
        if _type(value) is _code_type:
            code = value
            return (
                "code-v1",
                _object_getattribute(code, "co_argcount"),
                _object_getattribute(code, "co_posonlyargcount"),
                _object_getattribute(code, "co_kwonlyargcount"),
                _object_getattribute(code, "co_nlocals"),
                _object_getattribute(code, "co_stacksize"),
                _object_getattribute(code, "co_flags"),
                _object_getattribute(code, "co_code"),
                _tuple(
                    immutable_code_material(item)
                    for item in _object_getattribute(code, "co_consts")
                ),
                _object_getattribute(code, "co_names"),
                _object_getattribute(code, "co_varnames"),
                _object_getattribute(code, "co_freevars"),
                _object_getattribute(code, "co_cellvars"),
                _object_getattribute(code, "co_name"),
                _object_getattribute(code, "co_qualname"),
                _object_getattribute(code, "co_firstlineno"),
                _object_getattribute(code, "co_linetable"),
                _object_getattribute(code, "co_exceptiontable"),
            )
        if value is None or value is _ellipsis or _type(value) in _immutable_scalar_types:
            return value
        if _type(value) is _tuple_type:
            return _tuple(immutable_code_material(item) for item in value)
        if _type(value) is _frozenset_type:
            encoded = _tuple(
                _sorted(_marshal_dumps(immutable_code_material(item)) for item in value)
            )
            return ("frozenset-v1", encoded)
        fail()

    def caller_module_sha256(
        frame: object,
    ) -> tuple[str, str, int, int, dict[str, Any]]:
        if _type(frame) is not _frame_type:
            fail()
        code = _frame_getattribute(frame, "f_code")
        digest = _sha256(_marshal_dumps(immutable_code_material(code)))
        globals_value = _frame_getattribute(frame, "f_globals")
        if _type(globals_value) is not _dict_type:
            fail()
        return (
            _hexdigest(digest),
            _object_getattribute(code, "co_filename"),
            _frame_getattribute(frame, "f_lineno"),
            _frame_getattribute(frame, "f_lasti"),
            globals_value,
        )

    def require_caller(
        *,
        module_name: str,
        module_sha256: str,
        expected_calls: tuple[tuple[int, int], ...],
        caller_depth: int = 2,
    ) -> dict[str, Any]:
        frame = _getframe(caller_depth)
        caller_projection = caller_module_sha256(frame)
        digest = caller_projection[0]
        filename = caller_projection[1]
        line = caller_projection[2]
        instruction = caller_projection[3]
        globals_value: dict[str, Any] = caller_projection[4]
        module = _dict_get(_sys_modules, module_name)
        expected_suffix = _str_replace(module_name, ".", "/") + ".py"
        if (
            _type(module_sha256) is not _str_type
            or _len(module_sha256) != 64
            or digest != module_sha256
            or _type(filename) is not _str_type
            or not _str_endswith(filename, expected_suffix)
            or _type(module) is not _module_type
            or _object_getattribute(module, "__dict__") is not globals_value
            or _dict_get(globals_value, "__name__") != module_name
            or (line, instruction) not in expected_calls
        ):
            fail()
        return globals_value  # type: ignore[no-any-return]

    def stage_type(
        candidate: type[object],
        *,
        module_name: str,
        module_sha256: str,
        expected_calls: tuple[tuple[int, int], ...],
        expected_name: str,
        expected_slots: tuple[str, ...],
    ) -> _StagedType:
        require_caller(
            module_name=module_name,
            module_sha256=module_sha256,
            expected_calls=expected_calls,
            caller_depth=3,
        )
        if _type(candidate) is not _type_type:
            fail()
        namespace = _type_getattribute(candidate, "__dict__")
        slots = _type_getattribute(candidate, "__slots__")
        if (
            _type_getattribute(candidate, "__module__") != module_name
            or _type_getattribute(candidate, "__name__") != expected_name
            or _type_getattribute(candidate, "__qualname__") != expected_name
            or _type(slots) is not _tuple_type
            or slots != expected_slots
            or _type_getattribute(candidate, "__dictoffset__") != 0
        ):
            fail()
        descriptors: tuple[tuple[str, MemberDescriptorType], ...] = ()
        for field_name in expected_slots:
            if _type(namespace) is not _mappingproxy_type:
                fail()
            descriptor = _mappingproxy_get(namespace, field_name)
            if field_name == "__weakref__":
                if descriptor is None:
                    fail()
                continue
            if (
                _type(descriptor) is not _member_descriptor_type
                or _member_descriptor_get(
                    _member_objclass_descriptor,
                    descriptor,
                    _member_descriptor_type,
                )
                is not candidate
                or _member_descriptor_get(
                    _member_name_descriptor,
                    descriptor,
                    _member_descriptor_type,
                )
                != field_name
            ):
                fail()
            descriptors += ((field_name, descriptor),)
        return (
            "trusted-time-staged-projection-type-v1",
            candidate,
            descriptors,
        )

    def stage_immutable_launch(candidate: type[object]) -> type[object]:
        nonlocal immutable_launch
        if immutable_launch is not None or evidence_finalized or consumed:
            fail()
        immutable_launch = stage_type(
            candidate,
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_immutable_launch_stage_calls,
            expected_name="TrustedTimeImmutableLaunchEvidence",
            expected_slots=immutable_launch_slots,
        )
        return candidate

    def stage_first_enrollment_identities(candidate: type[object]) -> type[object]:
        nonlocal first_enrollment_identities
        if first_enrollment_identities is not None or evidence_finalized or consumed:
            fail()
        first_enrollment_identities = stage_type(
            candidate,
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_identities_stage_calls,
            expected_name="TrustedTimeFirstEnrollmentIdentities",
            expected_slots=first_enrollment_identities_slots,
        )
        return candidate

    def stage_sequence_one(candidate: type[object]) -> type[object]:
        nonlocal sequence_one
        if sequence_one is not None or evidence_finalized or consumed:
            fail()
        sequence_one = stage_type(
            candidate,
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_sequence_one_stage_calls,
            expected_name="TrustedTimeSequenceOneEvidence",
            expected_slots=sequence_one_slots,
        )
        return candidate

    def stage_confirmed_first_enrollment(candidate: type[object]) -> type[object]:
        nonlocal confirmed_first_enrollment
        if confirmed_first_enrollment is not None or evidence_finalized or consumed:
            fail()
        confirmed_first_enrollment = stage_type(
            candidate,
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_confirmed_stage_calls,
            expected_name="TrustedTimeConfirmedFirstEnrollment",
            expected_slots=confirmed_first_enrollment_slots,
        )
        return candidate

    def stage_post_enrollment_review(candidate: type[object]) -> type[object]:
        nonlocal post_enrollment_review
        if post_enrollment_review is not None or evidence_finalized or consumed:
            fail()
        post_enrollment_review = stage_type(
            candidate,
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_review_stage_calls,
            expected_name="TrustedTimePostEnrollmentStartReview",
            expected_slots=post_enrollment_review_slots,
        )
        return candidate

    def finalize_evidence() -> None:
        nonlocal evidence_finalized
        globals_value = require_caller(
            module_name=evidence_module_name,
            module_sha256=expected_evidence_module_sha256,
            expected_calls=evidence_finalize_calls,
        )
        exact = (
            ("TrustedTimeImmutableLaunchEvidence", immutable_launch),
            ("TrustedTimeFirstEnrollmentIdentities", first_enrollment_identities),
            ("TrustedTimeSequenceOneEvidence", sequence_one),
            ("TrustedTimeConfirmedFirstEnrollment", confirmed_first_enrollment),
            ("TrustedTimePostEnrollmentStartReview", post_enrollment_review),
        )
        if _any(
            value is None or _dict_get(globals_value, name) is not _tuple_getitem(value, 1)
            for name, value in exact
        ):
            fail()
        evidence_finalized = True

    def stage_approval(candidate: type[object]) -> type[object]:
        nonlocal approval
        if approval is not None or domain_finalized or consumed:
            fail()
        approval = stage_type(
            candidate,
            module_name=domain_module_name,
            module_sha256=expected_domain_module_sha256,
            expected_calls=domain_approval_stage_calls,
            expected_name="TrustedTimePostEnrollmentStartApproval",
            expected_slots=approval_slots,
        )
        return candidate

    def stage_reauthentication(candidate: type[object]) -> type[object]:
        nonlocal reauthentication
        if reauthentication is not None or domain_finalized or consumed:
            fail()
        reauthentication = stage_type(
            candidate,
            module_name=domain_module_name,
            module_sha256=expected_domain_module_sha256,
            expected_calls=domain_reauthentication_stage_calls,
            expected_name="TrustedTimePostEnrollmentRuntimeReauthentication",
            expected_slots=reauthentication_slots,
        )
        return candidate

    def stage_claim(candidate: type[object]) -> type[object]:
        nonlocal claim
        if claim is not None or domain_finalized or consumed:
            fail()
        claim = stage_type(
            candidate,
            module_name=domain_module_name,
            module_sha256=expected_domain_module_sha256,
            expected_calls=domain_claim_stage_calls,
            expected_name="TrustedTimePostEnrollmentStartClaim",
            expected_slots=claim_slots,
        )
        return candidate

    def finalize_domain() -> None:
        nonlocal domain_finalized
        globals_value = require_caller(
            module_name=domain_module_name,
            module_sha256=expected_domain_module_sha256,
            expected_calls=domain_finalize_calls,
        )
        if approval is None or reauthentication is None or claim is None:
            fail()
        exact = (
            ("TrustedTimePostEnrollmentStartApproval", approval),
            ("TrustedTimePostEnrollmentRuntimeReauthentication", reauthentication),
            ("TrustedTimePostEnrollmentStartClaim", claim),
        )
        if _any(
            _dict_get(globals_value, name) is not _tuple_getitem(value, 1) for name, value in exact
        ):
            fail()
        domain_finalized = True

    def stage_retained_claim(candidate: type[object]) -> type[object]:
        nonlocal retained_claim
        if retained_claim is not None or retained_finalized or consumed:
            fail()
        retained_claim = stage_type(
            candidate,
            module_name=retained_module_name,
            module_sha256=expected_retained_module_sha256,
            expected_calls=retained_claim_stage_calls,
            expected_name="RetainedTrustedTimePostEnrollmentStartClaim",
            expected_slots=retained_claim_slots,
        )
        return candidate

    def finalize_retained_claim() -> None:
        nonlocal retained_finalized
        globals_value = require_caller(
            module_name=retained_module_name,
            module_sha256=expected_retained_module_sha256,
            expected_calls=retained_finalize_calls,
        )
        if retained_claim is None or _dict_get(
            globals_value, "RetainedTrustedTimePostEnrollmentStartClaim"
        ) is not _tuple_getitem(retained_claim, 1):
            fail()
        retained_finalized = True

    def take_start_recipe() -> _StartProjectionRecipe:
        require_caller(
            module_name=reader_module_name,
            module_sha256=expected_reader_module_sha256,
            expected_calls=reader_take_calls,
        )
        if (
            consumed
            or not evidence_finalized
            or not domain_finalized
            or not retained_finalized
            or immutable_launch is None
            or first_enrollment_identities is None
            or sequence_one is None
            or confirmed_first_enrollment is None
            or post_enrollment_review is None
            or approval is None
            or reauthentication is None
            or claim is None
            or retained_claim is None
        ):
            fail()
        return (
            "trusted-time-start-projection-recipe-v2",
            immutable_launch,
            first_enrollment_identities,
            sequence_one,
            confirmed_first_enrollment,
            post_enrollment_review,
            approval,
            reauthentication,
            claim,
            retained_claim,
        )

    def retire_start_recipe() -> None:
        nonlocal approval, claim, consumed, domain_finalized, evidence_finalized
        nonlocal confirmed_first_enrollment, first_enrollment_identities
        nonlocal immutable_launch, post_enrollment_review, sequence_one
        nonlocal reauthentication, retained_claim, retained_finalized
        require_caller(
            module_name=reader_module_name,
            module_sha256=expected_reader_module_sha256,
            expected_calls=reader_retire_calls,
        )
        consumed = True
        immutable_launch = None
        first_enrollment_identities = None
        sequence_one = None
        confirmed_first_enrollment = None
        post_enrollment_review = None
        approval = None
        reauthentication = None
        claim = None
        retained_claim = None
        domain_finalized = False
        evidence_finalized = False
        retained_finalized = False
        for sink_name in exported_sink_names:
            _dict_pop(_bootstrap_globals, sink_name, None)
        if _any(
            _dict_get(_bootstrap_globals, sink_name) is not None
            for sink_name in exported_sink_names
        ):
            fail()

    return (
        stage_immutable_launch,
        stage_first_enrollment_identities,
        stage_sequence_one,
        stage_confirmed_first_enrollment,
        stage_post_enrollment_review,
        finalize_evidence,
        stage_approval,
        stage_reauthentication,
        stage_claim,
        finalize_domain,
        stage_retained_claim,
        finalize_retained_claim,
        take_start_recipe,
        retire_start_recipe,
    )


(
    _stage_trusted_time_immutable_launch_projection_type,
    _stage_trusted_time_first_enrollment_identities_projection_type,
    _stage_trusted_time_sequence_one_projection_type,
    _stage_trusted_time_confirmed_first_enrollment_projection_type,
    _stage_trusted_time_post_enrollment_start_review_projection_type,
    _finalize_trusted_time_enrollment_evidence_projection_types,
    _stage_post_enrollment_start_approval_projection_type,
    _stage_post_enrollment_runtime_reauthentication_projection_type,
    _stage_post_enrollment_start_claim_projection_type,
    _finalize_post_enrollment_start_domain_projection_types,
    _stage_retained_post_enrollment_start_claim_projection_type,
    _finalize_retained_post_enrollment_start_claim_projection_type,
    _take_finalized_start_projection_recipe,
    _retire_finalized_start_projection_recipe,
) = _build_start_projection_bootstrap()

del _build_start_projection_bootstrap
del _EXACT_BOOTSTRAP_MODULE_GLOBALS
del _EXACT_FRAME_TYPE
del _EXACT_MODULE_TYPE
del _EXACT_SHA256_OWNER_TYPE

__all__: tuple[()] = ()
