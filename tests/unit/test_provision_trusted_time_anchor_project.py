from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from typing import Any, cast

import pytest

from scripts.provision_trusted_time_anchor_project import (
    ANCHOR_ALLOWED_MIME_TYPES,
    ANCHOR_BUCKET_ID,
    ANCHOR_FILE_SIZE_LIMIT_BYTES,
    ANCHOR_OBJECT_PATH_REGEX,
    ANCHOR_OBJECT_PREFIX,
    AnchorProjectProvisioningContract,
    AnchorProjectProvisioningError,
    audit_provisioning_sql,
    build_provisioning_contract,
    generate_provisioning_sql,
    main,
    provisioning_sql_sha256,
    validate_object_contract,
    validate_principal_uuid,
    validate_project_ref,
    validate_project_url,
    validate_publishable_key,
)

ANCHOR_REF = "abcdefghijklmnopqrst"
RUNTIME_REF = "bcdefghijklmnopqrstu"
TEST_REF = "cdefghijklmnopqrstuv"
ANCHOR_URL = f"https://{ANCHOR_REF}.supabase.co"
PUBLISHABLE_KEY = f"sb_publishable_{'A' * 22}_{'b' * 8}"
WRITER_ID = "11111111-1111-4111-8111-111111111111"
READER_ID = "22222222-2222-4222-8222-222222222222"


def _contract(*, reader: bool = True) -> AnchorProjectProvisioningContract:
    return build_provisioning_contract(
        anchor_project_url=ANCHOR_URL,
        anchor_project_ref=ANCHOR_REF,
        runtime_project_ref=RUNTIME_REF,
        test_project_ref=TEST_REF,
        publishable_key=PUBLISHABLE_KEY,
        writer_principal_id=WRITER_ID,
        reader_principal_id=READER_ID if reader else None,
    )


def test_valid_contract_pins_separate_project_private_bucket_and_public_key_hash() -> None:
    contract = _contract()

    assert contract.anchor_project_url == ANCHOR_URL
    assert contract.anchor_project_ref == ANCHOR_REF
    assert (
        len({contract.anchor_project_ref, contract.runtime_project_ref, contract.test_project_ref})
        == 3
    )
    assert contract.bucket_id == ANCHOR_BUCKET_ID
    assert contract.bucket_public is False
    assert contract.file_size_limit_bytes == 4096
    assert contract.allowed_mime_types == ("application/json",)
    assert contract.object_prefix == "v1/"
    assert contract.object_path_regex == ANCHOR_OBJECT_PATH_REGEX
    assert (
        contract.publishable_key_sha256
        == hashlib.sha256(PUBLISHABLE_KEY.encode("ascii")).hexdigest()
    )
    assert PUBLISHABLE_KEY not in repr(contract)


@pytest.mark.parametrize(
    "value",
    [
        "abcdefghijklmnopqrs",
        "abcdefghijklmnopqrstu",
        "ABCDEFGHIJKLMNOPQRST",
        "abcdefghijklmnopqrs-",
        "abcdefghijklmnopqrs'",
        "abcdefghijklmnopqrs ",
        "abcdefghijklmnopqr\x00",
        1,
        None,
    ],
)
def test_project_ref_rejects_noncanonical_or_injectable_values(value: object) -> None:
    with pytest.raises(AnchorProjectProvisioningError, match="project_ref_invalid"):
        validate_project_ref(value)


@pytest.mark.parametrize(
    "url",
    [
        f"http://{ANCHOR_REF}.supabase.co",
        f"https://{ANCHOR_REF}.supabase.co/",
        f"https://{ANCHOR_REF}.supabase.co?x=1",
        f"https://user@{ANCHOR_REF}.supabase.co",
        f"https://{RUNTIME_REF}.supabase.co",
        f"https://{ANCHOR_REF}.supabase.co';select 1;--",
    ],
)
def test_project_url_requires_exact_ref_bound_https_origin(url: str) -> None:
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_project_url_invalid"):
        validate_project_url(url, project_ref=ANCHOR_REF)


@pytest.mark.parametrize(
    ("runtime_ref", "test_ref"),
    [
        (ANCHOR_REF, TEST_REF),
        (RUNTIME_REF, ANCHOR_REF),
        (RUNTIME_REF, RUNTIME_REF),
    ],
)
def test_anchor_runtime_and_test_projects_must_all_be_distinct(
    runtime_ref: str,
    test_ref: str,
) -> None:
    with pytest.raises(
        AnchorProjectProvisioningError,
        match="anchor_runtime_test_projects_not_distinct",
    ):
        build_provisioning_contract(
            anchor_project_url=ANCHOR_URL,
            anchor_project_ref=ANCHOR_REF,
            runtime_project_ref=runtime_ref,
            test_project_ref=test_ref,
            publishable_key=PUBLISHABLE_KEY,
            writer_principal_id=WRITER_ID,
        )


def test_publishable_key_accepts_only_exact_modern_low_privilege_shape() -> None:
    assert validate_publishable_key(PUBLISHABLE_KEY) == PUBLISHABLE_KEY

    with pytest.raises(AnchorProjectProvisioningError, match="anchor_secret_key_rejected"):
        validate_publishable_key(f"sb_secret_{'A' * 22}_{'b' * 8}")
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_legacy_jwt_key_rejected"):
        validate_publishable_key("eyJhbGciOiJIUzI1NiJ9.service_role.signature")
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_publishable_key_invalid"):
        validate_publishable_key("service_role")
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_publishable_key_invalid"):
        validate_publishable_key(f"sb_publishable_{'A' * 21}_{'b' * 8}")


@pytest.mark.parametrize(
    "value",
    [
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
        "{11111111-1111-4111-8111-111111111111}",
        "11111111-1111-4111-8111-11111111111A",
        "11111111-1111-4111-8111-111111111111'::uuid OR true--",
        1,
    ],
)
def test_principal_uuid_rejects_noncanonical_nil_and_injection(value: object) -> None:
    with pytest.raises(AnchorProjectProvisioningError, match="writer_principal_id_invalid"):
        validate_principal_uuid(value, field_name="writer_principal_id")


def test_writer_and_reader_principals_must_be_distinct() -> None:
    with pytest.raises(
        AnchorProjectProvisioningError,
        match="anchor_writer_reader_must_be_distinct",
    ):
        build_provisioning_contract(
            anchor_project_url=ANCHOR_URL,
            anchor_project_ref=ANCHOR_REF,
            runtime_project_ref=RUNTIME_REF,
            test_project_ref=TEST_REF,
            publishable_key=PUBLISHABLE_KEY,
            writer_principal_id=WRITER_ID,
            reader_principal_id=WRITER_ID,
        )


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        ({"bucket_id": "anchor';drop table storage.objects;--"}, "anchor_bucket_id_invalid"),
        ({"bucket_public": True}, "anchor_bucket_must_be_private"),
        ({"file_size_limit_bytes": 4097}, "anchor_file_size_limit_invalid"),
        ({"file_size_limit_bytes": True}, "anchor_file_size_limit_invalid"),
        ({"allowed_mime_types": ("application/json", "text/plain")}, "anchor_mime_types_invalid"),
        ({"allowed_mime_types": ["application/json"]}, "anchor_mime_types_invalid"),
        ({"object_prefix": "../v1/"}, "anchor_object_prefix_invalid"),
        ({"object_path_regex": r"^v1/.*$"}, "anchor_object_path_regex_invalid"),
        (
            {"object_path_regex": ANCHOR_OBJECT_PATH_REGEX + "';select true;--"},
            "anchor_object_path_regex_invalid",
        ),
    ],
)
def test_object_contract_rejects_every_unreviewed_bucket_or_path_shape(
    replacement: dict[str, object],
    reason: str,
) -> None:
    values: dict[str, object] = {
        "bucket_id": ANCHOR_BUCKET_ID,
        "bucket_public": False,
        "file_size_limit_bytes": ANCHOR_FILE_SIZE_LIMIT_BYTES,
        "allowed_mime_types": ANCHOR_ALLOWED_MIME_TYPES,
        "object_prefix": ANCHOR_OBJECT_PREFIX,
        "object_path_regex": ANCHOR_OBJECT_PATH_REGEX,
    }
    values.update(replacement)

    with pytest.raises(AnchorProjectProvisioningError, match=reason):
        validate_object_contract(**values)


def test_object_regex_accepts_only_exact_content_addressed_v1_paths() -> None:
    first_hash = "a" * 64
    second_hash = "b" * 64
    object_hash = "c" * 64
    valid = f"v1/{first_hash}/{second_hash}/00000000000000000042-{object_hash}.json"

    assert re.fullmatch(ANCHOR_OBJECT_PATH_REGEX, valid)
    assert re.fullmatch(ANCHOR_OBJECT_PATH_REGEX, f"/{valid}") is None
    assert re.fullmatch(ANCHOR_OBJECT_PATH_REGEX, valid.replace(".json", ".JSON")) is None
    assert re.fullmatch(ANCHOR_OBJECT_PATH_REGEX, valid.replace("42-", "4-")) is None
    assert re.fullmatch(ANCHOR_OBJECT_PATH_REGEX, valid.replace("a", "g", 1)) is None


def test_sql_generation_is_deterministic_bound_and_does_not_emit_publishable_key() -> None:
    contract = _contract()

    first = generate_provisioning_sql(contract)
    second = generate_provisioning_sql(contract)

    assert first == second
    assert first.endswith("COMMIT;\n")
    assert PUBLISHABLE_KEY not in first
    assert contract.publishable_key_sha256 in first
    assert contract.runtime_project_identity_sha256 in first
    assert contract.test_project_identity_sha256 in first
    assert ANCHOR_REF in first
    assert RUNTIME_REF not in first
    assert TEST_REF not in first
    assert provisioning_sql_sha256(contract) == hashlib.sha256(first.encode()).hexdigest()
    assert audit_provisioning_sql(first, contract) == provisioning_sql_sha256(contract)


def test_sql_pins_bucket_owner_path_size_mime_and_exact_principals() -> None:
    sql = generate_provisioning_sql(_contract())

    assert "INSERT INTO storage.buckets" not in sql
    assert "anchor_bucket_missing_create_via_storage_api" in sql
    assert "'aqt-trusted-time-anchors-v1'::text" in sql
    assert "4096::bigint" in sql
    assert "ARRAY['application/json']::text[]" in sql
    assert ANCHOR_OBJECT_PATH_REGEX in sql
    assert "owner_id = '11111111-1111-4111-8111-111111111111'::text" in sql
    assert "(SELECT auth.uid()) = '11111111-1111-4111-8111-111111111111'::uuid" in sql
    assert "(SELECT auth.uid()) = '22222222-2222-4222-8222-222222222222'::uuid" in sql


def test_select_policies_are_operation_scoped_for_upload_get_list_and_list_v2() -> None:
    sql = generate_provisioning_sql(_contract())

    assert "storage.allow_only_operation('storage.object.upload'::text)" in sql
    for operation in (
        "storage.object.upload",
        "storage.object.get_authenticated",
        "storage.object.list",
        "storage.object.list_v2",
    ):
        assert f"'{operation}'::text" in sql
    assert "storage.allow_any_operation(ARRAY[" in sql
    assert "aqt_tt_anchor_v1_writer_select" in sql
    assert "aqt_tt_anchor_v1_reader_select" in sql


def test_reader_is_select_only_and_optional() -> None:
    with_reader = generate_provisioning_sql(_contract())
    without_reader = generate_provisioning_sql(_contract(reader=False))

    assert "aqt_tt_anchor_v1_reader_select" in with_reader
    assert READER_ID in with_reader
    assert "aqt_tt_anchor_v1_reader_insert" not in with_reader
    assert "aqt_tt_anchor_v1_reader_select" not in without_reader
    assert READER_ID not in without_reader
    assert with_reader != without_reader


def test_restrictive_guards_confine_broader_policies_without_blocking_other_buckets() -> None:
    sql = generate_provisioning_sql(_contract())

    outside_bucket = "bucket_id IS DISTINCT FROM 'aqt-trusted-time-anchors-v1'::text"
    assert sql.count(outside_bucket) >= 8
    assert "aqt_tt_anchor_v1_guard_insert" in sql
    assert "aqt_tt_anchor_v1_guard_select" in sql
    assert "aqt_tt_anchor_v1_guard_update" in sql
    assert "aqt_tt_anchor_v1_guard_delete" in sql
    assert "AS RESTRICTIVE\nFOR UPDATE\nTO public" in sql
    assert "AS RESTRICTIVE\nFOR DELETE\nTO public" in sql
    assert "AS PERMISSIVE\nFOR UPDATE" not in sql
    assert "AS PERMISSIVE\nFOR DELETE" not in sql
    assert "p.polpermissive\n          AND p.polcmd IN ('w', 'd', '*')" in sql


def test_sql_is_transactional_advisory_locked_and_fail_closed_on_drift() -> None:
    sql = generate_provisioning_sql(_contract())

    assert sql.count("BEGIN;") == 1
    assert sql.count("COMMIT;") == 1
    assert "pg_catalog.pg_advisory_xact_lock" in sql
    assert "SET LOCAL lock_timeout" in sql
    assert "install_mode := 'fresh'" in sql
    assert "install_mode := 'existing'" in sql
    assert "anchor_bucket_definition_drift" in sql
    assert "anchor_policy_set_drift" in sql
    assert "anchor_policy_definition_drift" in sql
    assert "ON CONFLICT" not in sql
    assert "UPDATE storage.buckets" not in sql
    assert "DELETE FROM storage.buckets" not in sql


def test_sql_never_mutates_any_storage_table_rows() -> None:
    sql = generate_provisioning_sql(_contract())

    forbidden_storage_dml = re.compile(
        r"(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+storage[.]",
        re.IGNORECASE,
    )
    assert forbidden_storage_dml.search(sql) is None
    assert "Create the exact private bucket through the Supabase Storage API first" in sql


def test_sql_never_mutates_storage_object_rows() -> None:
    sql = generate_provisioning_sql(_contract())

    forbidden_object_dml = re.compile(
        r"(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+storage[.]objects",
        re.IGNORECASE,
    )
    assert forbidden_object_dml.search(sql) is None
    assert "ON storage.objects" in sql  # policy DDL is expected


def test_preflight_requires_operation_helpers_and_complete_exact_policy_set() -> None:
    contract = _contract()
    sql = generate_provisioning_sql(contract)

    assert "to_regproc('storage.allow_only_operation')" in sql
    assert "to_regproc('storage.allow_any_operation')" in sql
    assert "anchor_storage_operation_helpers_missing" in sql
    assert "actual_policy_names IS DISTINCT FROM expected_policy_names" in sql
    assert "anchor_bucket_missing_create_via_storage_api" in sql
    assert "left(p.polname" not in sql
    assert sql.count("WHERE p.polrelid = 'storage.objects'::regclass;") == 2

    missing_helper = sql.replace("to_regproc('storage.allow_any_operation')", "true")
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_provisioning_sql_drift"):
        audit_provisioning_sql(missing_helper, contract)

    missing_policy = sql.replace("aqt_tt_anchor_v1_writer_insert", "removed_writer_policy")
    with pytest.raises(AnchorProjectProvisioningError, match="anchor_provisioning_sql_drift"):
        audit_provisioning_sql(missing_policy, contract)


def test_postflight_asserts_exact_bucket_and_pg_policy_parse_trees() -> None:
    sql = generate_provisioning_sql(_contract())

    assert "FROM storage.buckets AS b" in sql
    assert "FROM pg_catalog.pg_policy AS p" in sql
    assert "p.polqual::text AS polqual" in sql
    assert "p.polwithcheck::text AS polwithcheck" in sql
    assert "anchor_bucket_postflight_failed" in sql
    assert "anchor_policy_postflight_failed" in sql
    assert "anchor_mutation_policy_postflight_failed" in sql
    assert "Audit policies are dropped before commit" in sql


@pytest.mark.parametrize(
    "changed",
    [
        {"bucket_id": "different"},
        {"bucket_public": True},
        {"file_size_limit_bytes": 8192},
        {"allowed_mime_types": ("text/plain",)},
        {"object_prefix": "unsafe/"},
        {"object_path_regex": r".*"},
        {"contract_version": "v2"},
    ],
)
def test_direct_dataclass_replacement_cannot_bypass_revalidation(
    changed: dict[str, object],
) -> None:
    contract = replace(_contract(), **cast(Any, changed))

    with pytest.raises(AnchorProjectProvisioningError):
        generate_provisioning_sql(contract)


def test_sql_identity_changes_with_each_authority_input() -> None:
    baseline = _contract()
    variants = (
        replace(
            baseline,
            anchor_project_ref="defghijklmnopqrstuvw",
            anchor_project_url="https://defghijklmnopqrstuvw.supabase.co",
        ),
        replace(baseline, runtime_project_ref="defghijklmnopqrstuvw"),
        replace(baseline, test_project_ref="efghijklmnopqrstuvwx"),
        replace(baseline, publishable_key=f"sb_publishable_{'C' * 22}_{'d' * 8}"),
        replace(baseline, writer_principal_id="33333333-3333-4333-8333-333333333333"),
        replace(baseline, reader_principal_id=None),
    )

    baseline_digest = provisioning_sql_sha256(baseline)
    assert all(provisioning_sql_sha256(variant) != baseline_digest for variant in variants)


def test_cli_renders_sql_without_echoing_key(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(
        [
            "--anchor-project-url",
            ANCHOR_URL,
            "--anchor-project-ref",
            ANCHOR_REF,
            "--runtime-project-ref",
            RUNTIME_REF,
            "--test-project-ref",
            TEST_REF,
            "--publishable-key",
            PUBLISHABLE_KEY,
            "--writer-principal-id",
            WRITER_ID,
            "--reader-principal-id",
            READER_ID,
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out.startswith("-- aqt-trusted-time-supabase-anchor-project-v1")
    assert PUBLISHABLE_KEY not in captured.out


def test_cli_failure_is_secret_free(capsys: pytest.CaptureFixture[str]) -> None:
    secret_key = f"sb_secret_{'A' * 22}_{'b' * 8}"
    result = main(
        [
            "--anchor-project-url",
            ANCHOR_URL,
            "--anchor-project-ref",
            ANCHOR_REF,
            "--runtime-project-ref",
            RUNTIME_REF,
            "--test-project-ref",
            TEST_REF,
            "--publishable-key",
            secret_key,
            "--writer-principal-id",
            WRITER_ID,
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "anchor_secret_key_rejected\n"
    assert secret_key not in captured.err
