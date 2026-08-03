"""Render the reviewed SQL for a separate Supabase trusted-time anchor project.

This module is deliberately offline.  It validates an operator-supplied project
identity, low-privilege publishable key, and authenticated principal UUIDs, then
returns deterministic SQL.  It never opens a network connection and never
creates Auth users or Storage buckets.  The private bucket must first be created
through the supported Supabase Storage API or dashboard; the SQL verifies that
exact bucket and installs an exact RLS policy set without modifying rows in any
``storage`` table.

The generated transaction is fail-closed on drift.  An absent or changed bucket
is rejected.  A completely absent policy set is installed; an existing policy
installation must match byte-for-byte at the parsed ``pg_policy`` expression
level.  A partial or changed installation is rejected rather than repaired in
place.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import uuid
from dataclasses import dataclass, field

CONTRACT_VERSION = "aqt-trusted-time-supabase-anchor-project-v1"
ANCHOR_BUCKET_ID = "aqt-trusted-time-anchors-v1"
ANCHOR_BUCKET_PUBLIC = False
ANCHOR_FILE_SIZE_LIMIT_BYTES = 4096
ANCHOR_ALLOWED_MIME_TYPES = ("application/json",)
ANCHOR_OBJECT_PREFIX = "v1/"
ANCHOR_OBJECT_PATH_REGEX = r"^v1/[0-9a-f]{64}/[0-9a-f]{64}/[0-9]{20}-[0-9a-f]{64}[.]json$"

WRITER_SELECT_OPERATIONS = (
    "storage.object.upload",
    "storage.object.get_authenticated",
    "storage.object.list",
    "storage.object.list_v2",
)
READER_SELECT_OPERATIONS = (
    "storage.object.get_authenticated",
    "storage.object.list",
    "storage.object.list_v2",
)
WRITER_INSERT_OPERATION = "storage.object.upload"

_PROJECT_REF = re.compile(r"[a-z0-9]{20}\Z", re.ASCII)
_PUBLISHABLE_KEY = re.compile(
    r"sb_publishable_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}\Z",
    re.ASCII,
)
_POLICY_PREFIX = "aqt_tt_anchor_v1_"
_ADVISORY_LOCK_KEY = 6_483_515_921_681_925_897
_PROJECT_IDENTITY_DOMAIN = "aqt-trusted-time-anchor-project-ref-identity-v1"


class AnchorProjectProvisioningError(ValueError):
    """An offline provisioning input or generated contract is unsafe."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class AnchorProjectProvisioningContract:
    """Validated inputs for one separate Supabase anchor project."""

    anchor_project_url: str
    anchor_project_ref: str
    runtime_project_ref: str
    test_project_ref: str
    publishable_key: str = field(repr=False)
    writer_principal_id: str
    reader_principal_id: str | None = None
    bucket_id: str = ANCHOR_BUCKET_ID
    bucket_public: bool = ANCHOR_BUCKET_PUBLIC
    file_size_limit_bytes: int = ANCHOR_FILE_SIZE_LIMIT_BYTES
    allowed_mime_types: tuple[str, ...] = ANCHOR_ALLOWED_MIME_TYPES
    object_prefix: str = ANCHOR_OBJECT_PREFIX
    object_path_regex: str = ANCHOR_OBJECT_PATH_REGEX
    contract_version: str = CONTRACT_VERSION

    @property
    def publishable_key_sha256(self) -> str:
        """Return an opaque binding without exposing even a public client key."""

        return hashlib.sha256(self.publishable_key.encode("ascii")).hexdigest()

    @property
    def runtime_project_identity_sha256(self) -> str:
        """Bind the validated runtime ref without rendering that ref into SQL."""

        return _project_ref_identity_sha256(
            role="runtime_database",
            project_ref=self.runtime_project_ref,
        )

    @property
    def test_project_identity_sha256(self) -> str:
        """Bind the validated destructive-test ref without rendering it into SQL."""

        return _project_ref_identity_sha256(
            role="destructive_test_database",
            project_ref=self.test_project_ref,
        )


@dataclass(frozen=True, slots=True)
class _PolicyContract:
    name: str
    permissive: bool
    command: str
    roles: tuple[str, ...]
    using_expression: str | None = None
    check_expression: str | None = None


def _require_exact_string(value: object, reason_code: str) -> str:
    if type(value) is not str or not value:
        raise AnchorProjectProvisioningError(reason_code)
    if value != value.strip() or "\x00" in value:
        raise AnchorProjectProvisioningError(reason_code)
    return value


def _project_ref_identity_sha256(*, role: str, project_ref: str) -> str:
    """Return one unambiguous domain-separated project-reference binding."""

    payload = "\x00".join((_PROJECT_IDENTITY_DOMAIN, role, project_ref)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def validate_project_ref(value: object, *, field_name: str = "project") -> str:
    """Require one canonical hosted-Supabase 20-character project reference."""

    reason = f"{field_name}_ref_invalid"
    candidate = _require_exact_string(value, reason)
    if _PROJECT_REF.fullmatch(candidate) is None:
        raise AnchorProjectProvisioningError(reason)
    return candidate


def validate_project_url(value: object, *, project_ref: str) -> str:
    """Require the exact HTTPS API origin belonging to ``project_ref``."""

    candidate = _require_exact_string(value, "anchor_project_url_invalid")
    validated_ref = validate_project_ref(project_ref, field_name="anchor_project")
    expected = f"https://{validated_ref}.supabase.co"
    if candidate != expected:
        raise AnchorProjectProvisioningError("anchor_project_url_invalid")
    return candidate


def validate_publishable_key(value: object) -> str:
    """Accept only the modern low-privilege ``sb_publishable`` key shape.

    Legacy JWT keys are rejected even when they represent the ``anon`` role so
    the provisioning contract cannot accidentally accept a ``service_role`` JWT.
    """

    candidate = _require_exact_string(value, "anchor_publishable_key_invalid")
    if candidate.startswith("sb_secret_"):
        raise AnchorProjectProvisioningError("anchor_secret_key_rejected")
    if candidate.count(".") == 2 or candidate.startswith("eyJ"):
        raise AnchorProjectProvisioningError("anchor_legacy_jwt_key_rejected")
    if _PUBLISHABLE_KEY.fullmatch(candidate) is None:
        raise AnchorProjectProvisioningError("anchor_publishable_key_invalid")
    return candidate


def validate_principal_uuid(value: object, *, field_name: str) -> str:
    """Require an exact lowercase, hyphenated, non-nil UUID."""

    reason = f"{field_name}_invalid"
    candidate = _require_exact_string(value, reason)
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError) as exc:
        raise AnchorProjectProvisioningError(reason) from exc
    if str(parsed) != candidate or parsed.int == 0:
        raise AnchorProjectProvisioningError(reason)
    return candidate


def validate_object_contract(
    *,
    bucket_id: object,
    bucket_public: object,
    file_size_limit_bytes: object,
    allowed_mime_types: object,
    object_prefix: object,
    object_path_regex: object,
) -> None:
    """Reject every bucket or object-name contract other than the reviewed one."""

    if type(bucket_id) is not str or bucket_id != ANCHOR_BUCKET_ID:
        raise AnchorProjectProvisioningError("anchor_bucket_id_invalid")
    if type(bucket_public) is not bool or bucket_public is not ANCHOR_BUCKET_PUBLIC:
        raise AnchorProjectProvisioningError("anchor_bucket_must_be_private")
    if (
        type(file_size_limit_bytes) is not int
        or file_size_limit_bytes != ANCHOR_FILE_SIZE_LIMIT_BYTES
    ):
        raise AnchorProjectProvisioningError("anchor_file_size_limit_invalid")
    if type(allowed_mime_types) is not tuple or allowed_mime_types != ANCHOR_ALLOWED_MIME_TYPES:
        raise AnchorProjectProvisioningError("anchor_mime_types_invalid")
    if type(object_prefix) is not str or object_prefix != ANCHOR_OBJECT_PREFIX:
        raise AnchorProjectProvisioningError("anchor_object_prefix_invalid")
    if type(object_path_regex) is not str or object_path_regex != ANCHOR_OBJECT_PATH_REGEX:
        raise AnchorProjectProvisioningError("anchor_object_path_regex_invalid")


def build_provisioning_contract(
    *,
    anchor_project_url: object,
    anchor_project_ref: object,
    runtime_project_ref: object,
    test_project_ref: object,
    publishable_key: object,
    writer_principal_id: object,
    reader_principal_id: object | None = None,
    bucket_id: object = ANCHOR_BUCKET_ID,
    bucket_public: object = ANCHOR_BUCKET_PUBLIC,
    file_size_limit_bytes: object = ANCHOR_FILE_SIZE_LIMIT_BYTES,
    allowed_mime_types: object = ANCHOR_ALLOWED_MIME_TYPES,
    object_prefix: object = ANCHOR_OBJECT_PREFIX,
    object_path_regex: object = ANCHOR_OBJECT_PATH_REGEX,
) -> AnchorProjectProvisioningContract:
    """Validate all offline authority inputs and return an immutable contract."""

    anchor_ref = validate_project_ref(anchor_project_ref, field_name="anchor_project")
    runtime_ref = validate_project_ref(runtime_project_ref, field_name="runtime_project")
    test_ref = validate_project_ref(test_project_ref, field_name="test_project")
    if len({anchor_ref, runtime_ref, test_ref}) != 3:
        raise AnchorProjectProvisioningError("anchor_runtime_test_projects_not_distinct")

    anchor_url = validate_project_url(anchor_project_url, project_ref=anchor_ref)
    key = validate_publishable_key(publishable_key)
    writer_id = validate_principal_uuid(writer_principal_id, field_name="writer_principal_id")
    reader_id = None
    if reader_principal_id is not None:
        reader_id = validate_principal_uuid(
            reader_principal_id,
            field_name="reader_principal_id",
        )
        if reader_id == writer_id:
            raise AnchorProjectProvisioningError("anchor_writer_reader_must_be_distinct")

    validate_object_contract(
        bucket_id=bucket_id,
        bucket_public=bucket_public,
        file_size_limit_bytes=file_size_limit_bytes,
        allowed_mime_types=allowed_mime_types,
        object_prefix=object_prefix,
        object_path_regex=object_path_regex,
    )
    return AnchorProjectProvisioningContract(
        anchor_project_url=anchor_url,
        anchor_project_ref=anchor_ref,
        runtime_project_ref=runtime_ref,
        test_project_ref=test_ref,
        publishable_key=key,
        writer_principal_id=writer_id,
        reader_principal_id=reader_id,
        bucket_id=ANCHOR_BUCKET_ID,
        bucket_public=ANCHOR_BUCKET_PUBLIC,
        file_size_limit_bytes=ANCHOR_FILE_SIZE_LIMIT_BYTES,
        allowed_mime_types=ANCHOR_ALLOWED_MIME_TYPES,
        object_prefix=ANCHOR_OBJECT_PREFIX,
        object_path_regex=ANCHOR_OBJECT_PATH_REGEX,
    )


def validate_provisioning_contract(
    contract: object,
) -> AnchorProjectProvisioningContract:
    """Revalidate a contract so direct dataclass construction cannot bypass checks."""

    if type(contract) is not AnchorProjectProvisioningContract:
        raise AnchorProjectProvisioningError("anchor_provisioning_contract_invalid")
    if contract.contract_version != CONTRACT_VERSION:
        raise AnchorProjectProvisioningError("anchor_provisioning_contract_version_invalid")
    return build_provisioning_contract(
        anchor_project_url=contract.anchor_project_url,
        anchor_project_ref=contract.anchor_project_ref,
        runtime_project_ref=contract.runtime_project_ref,
        test_project_ref=contract.test_project_ref,
        publishable_key=contract.publishable_key,
        writer_principal_id=contract.writer_principal_id,
        reader_principal_id=contract.reader_principal_id,
        bucket_id=contract.bucket_id,
        bucket_public=contract.bucket_public,
        file_size_limit_bytes=contract.file_size_limit_bytes,
        allowed_mime_types=contract.allowed_mime_types,
        object_prefix=contract.object_prefix,
        object_path_regex=contract.object_path_regex,
    )


def _sql_text(value: str) -> str:
    """Quote a previously validated literal defensively."""

    return "'" + value.replace("'", "''") + "'"


def _operation_expression(operations: tuple[str, ...]) -> str:
    operation_literals = ", ".join(f"{_sql_text(value)}::text" for value in operations)
    return f"storage.allow_any_operation(ARRAY[{operation_literals}]::text[])"


def _object_expression(contract: AnchorProjectProvisioningContract) -> str:
    return (
        f"bucket_id = {_sql_text(contract.bucket_id)}::text\n"
        f"    AND owner_id = {_sql_text(contract.writer_principal_id)}::text\n"
        f"    AND name ~ {_sql_text(contract.object_path_regex)}::text"
    )


def _writer_identity_expression(contract: AnchorProjectProvisioningContract) -> str:
    return f"(SELECT auth.uid()) = {_sql_text(contract.writer_principal_id)}::uuid"


def _reader_identity_expression(contract: AnchorProjectProvisioningContract) -> str:
    if contract.reader_principal_id is None:
        raise AssertionError("reader identity requested without a reader principal")
    return f"(SELECT auth.uid()) = {_sql_text(contract.reader_principal_id)}::uuid"


def _anchor_policy_contracts(
    contract: AnchorProjectProvisioningContract,
) -> tuple[_PolicyContract, ...]:
    object_expression = _object_expression(contract)
    writer_identity = _writer_identity_expression(contract)
    upload_operation = f"storage.allow_only_operation({_sql_text(WRITER_INSERT_OPERATION)}::text)"
    writer_select_operations = _operation_expression(WRITER_SELECT_OPERATIONS)

    policies = [
        _PolicyContract(
            name=f"{_POLICY_PREFIX}writer_insert",
            permissive=True,
            command="INSERT",
            roles=("authenticated",),
            check_expression=(
                f"{object_expression}\n    AND {writer_identity}\n    AND {upload_operation}"
            ),
        ),
        _PolicyContract(
            name=f"{_POLICY_PREFIX}writer_select",
            permissive=True,
            command="SELECT",
            roles=("authenticated",),
            using_expression=(
                f"{object_expression}\n"
                f"    AND {writer_identity}\n"
                f"    AND {writer_select_operations}"
            ),
        ),
    ]
    if contract.reader_principal_id is not None:
        policies.append(
            _PolicyContract(
                name=f"{_POLICY_PREFIX}reader_select",
                permissive=True,
                command="SELECT",
                roles=("authenticated",),
                using_expression=(
                    f"{object_expression}\n"
                    f"    AND {_reader_identity_expression(contract)}\n"
                    f"    AND {_operation_expression(READER_SELECT_OPERATIONS)}"
                ),
            )
        )

    allowed_select = (
        f"({writer_identity} AND {writer_select_operations})"
        if contract.reader_principal_id is None
        else (
            f"({writer_identity} AND {writer_select_operations})\n"
            f"        OR ({_reader_identity_expression(contract)} "
            f"AND {_operation_expression(READER_SELECT_OPERATIONS)})"
        )
    )
    outside_bucket = f"bucket_id IS DISTINCT FROM {_sql_text(contract.bucket_id)}::text"
    policies.extend(
        (
            _PolicyContract(
                name=f"{_POLICY_PREFIX}guard_insert",
                permissive=False,
                command="INSERT",
                roles=("public",),
                check_expression=(
                    f"{outside_bucket}\n"
                    "    OR (\n"
                    f"        {object_expression.replace(chr(10), chr(10) + '        ')}\n"
                    f"        AND {writer_identity}\n"
                    f"        AND {upload_operation}\n"
                    "    )"
                ),
            ),
            _PolicyContract(
                name=f"{_POLICY_PREFIX}guard_select",
                permissive=False,
                command="SELECT",
                roles=("public",),
                using_expression=(
                    f"{outside_bucket}\n"
                    "    OR (\n"
                    f"        {object_expression.replace(chr(10), chr(10) + '        ')}\n"
                    "        AND (\n"
                    f"            {allowed_select.replace(chr(10), chr(10) + '            ')}\n"
                    "        )\n"
                    "    )"
                ),
            ),
            _PolicyContract(
                name=f"{_POLICY_PREFIX}guard_update",
                permissive=False,
                command="UPDATE",
                roles=("public",),
                using_expression=outside_bucket,
                check_expression=outside_bucket,
            ),
            _PolicyContract(
                name=f"{_POLICY_PREFIX}guard_delete",
                permissive=False,
                command="DELETE",
                roles=("public",),
                using_expression=outside_bucket,
            ),
        )
    )
    return tuple(policies)


def _render_create_policy(policy: _PolicyContract, *, name: str) -> str:
    mode = "PERMISSIVE" if policy.permissive else "RESTRICTIVE"
    roles = ", ".join(policy.roles)
    statements = [
        f"CREATE POLICY {name}",
        "ON storage.objects",
        f"AS {mode}",
        f"FOR {policy.command}",
        f"TO {roles}",
    ]
    if policy.using_expression is not None:
        statements.append(f"USING (\n    {policy.using_expression}\n)")
    if policy.check_expression is not None:
        statements.append(f"WITH CHECK (\n    {policy.check_expression}\n)")
    return "\n".join(statements) + ";"


def _render_exact_policy_install(policy: _PolicyContract) -> str:
    template_name = f"{_POLICY_PREFIX}expected_{policy.name.removeprefix(_POLICY_PREFIX)}"
    create_template = _render_create_policy(policy, name=template_name)
    return f"""{create_template}

DO $aqt_install_{policy.name}$
DECLARE
    expected_policy record;
    actual_policy record;
    target_found boolean;
    install_mode text := current_setting('aqt.anchor_install_mode', true);
BEGIN
    SELECT
        p.polpermissive,
        p.polroles,
        p.polcmd,
        p.polqual::text AS polqual,
        p.polwithcheck::text AS polwithcheck
    INTO STRICT expected_policy
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass
      AND p.polname = {_sql_text(template_name)};

    SELECT
        p.polpermissive,
        p.polroles,
        p.polcmd,
        p.polqual::text AS polqual,
        p.polwithcheck::text AS polwithcheck
    INTO actual_policy
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass
      AND p.polname = {_sql_text(policy.name)};
    target_found := FOUND;

    IF target_found THEN
        IF install_mode <> 'existing' THEN
            RAISE EXCEPTION 'anchor_policy_set_drift';
        END IF;
        IF actual_policy.polpermissive IS DISTINCT FROM expected_policy.polpermissive
           OR actual_policy.polroles IS DISTINCT FROM expected_policy.polroles
           OR actual_policy.polcmd IS DISTINCT FROM expected_policy.polcmd
           OR actual_policy.polqual IS DISTINCT FROM expected_policy.polqual
           OR actual_policy.polwithcheck IS DISTINCT FROM expected_policy.polwithcheck THEN
            RAISE EXCEPTION 'anchor_policy_definition_drift';
        END IF;
        EXECUTE 'DROP POLICY {template_name} ON storage.objects';
    ELSE
        IF install_mode <> 'fresh' THEN
            RAISE EXCEPTION 'anchor_policy_set_drift';
        END IF;
        EXECUTE 'ALTER POLICY {template_name} ON storage.objects RENAME TO {policy.name}';
    END IF;
END
$aqt_install_{policy.name}$;
"""


def _render_exact_policy_postflight(policy: _PolicyContract) -> str:
    audit_name = f"{_POLICY_PREFIX}audit_{policy.name.removeprefix(_POLICY_PREFIX)}"
    create_audit = _render_create_policy(policy, name=audit_name)
    return f"""{create_audit}

DO $aqt_audit_{policy.name}$
DECLARE
    expected_policy record;
    actual_policy record;
BEGIN
    SELECT
        p.polpermissive,
        p.polroles,
        p.polcmd,
        p.polqual::text AS polqual,
        p.polwithcheck::text AS polwithcheck
    INTO STRICT expected_policy
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass
      AND p.polname = {_sql_text(audit_name)};

    SELECT
        p.polpermissive,
        p.polroles,
        p.polcmd,
        p.polqual::text AS polqual,
        p.polwithcheck::text AS polwithcheck
    INTO STRICT actual_policy
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass
      AND p.polname = {_sql_text(policy.name)};

    IF actual_policy.polpermissive IS DISTINCT FROM expected_policy.polpermissive
       OR actual_policy.polroles IS DISTINCT FROM expected_policy.polroles
       OR actual_policy.polcmd IS DISTINCT FROM expected_policy.polcmd
       OR actual_policy.polqual IS DISTINCT FROM expected_policy.polqual
       OR actual_policy.polwithcheck IS DISTINCT FROM expected_policy.polwithcheck THEN
        RAISE EXCEPTION 'anchor_policy_postflight_failed';
    END IF;
    EXECUTE 'DROP POLICY {audit_name} ON storage.objects';
END
$aqt_audit_{policy.name}$;
"""


def _render_preflight(
    contract: AnchorProjectProvisioningContract,
    policies: tuple[_PolicyContract, ...],
) -> str:
    expected_names = tuple(sorted(policy.name for policy in policies))
    expected_names_sql = ", ".join(_sql_text(name) for name in expected_names)
    return f"""DO $aqt_anchor_preflight$
DECLARE
    bucket_row record;
    bucket_match_count integer;
    actual_policy_names text[];
    expected_policy_names constant text[] := ARRAY[{expected_names_sql}]::text[];
    install_mode text;
BEGIN
    IF to_regclass('storage.buckets') IS NULL
       OR to_regclass('storage.objects') IS NULL THEN
        RAISE EXCEPTION 'anchor_storage_schema_missing';
    END IF;
    IF to_regrole('authenticated') IS NULL OR to_regrole('anon') IS NULL THEN
        RAISE EXCEPTION 'anchor_auth_roles_missing';
    END IF;
    IF to_regprocedure('auth.uid()') IS NULL
       OR to_regproc('storage.allow_only_operation') IS NULL
       OR to_regproc('storage.allow_any_operation') IS NULL THEN
        RAISE EXCEPTION 'anchor_storage_operation_helpers_missing';
    END IF;
    IF NOT (
        SELECT c.relrowsecurity
        FROM pg_catalog.pg_class AS c
        WHERE c.oid = 'storage.objects'::regclass
    ) THEN
        RAISE EXCEPTION 'anchor_storage_objects_rls_disabled';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS a
        WHERE a.attrelid = 'storage.objects'::regclass
          AND a.attname = 'owner_id'
          AND a.atttypid = 'text'::regtype
          AND a.attnum > 0
          AND NOT a.attisdropped
    ) THEN
        RAISE EXCEPTION 'anchor_storage_owner_id_contract_missing';
    END IF;

    SELECT count(*)
    INTO STRICT bucket_match_count
    FROM storage.buckets AS b
    WHERE b.id = {_sql_text(contract.bucket_id)}::text
       OR b.name = {_sql_text(contract.bucket_id)}::text;

    SELECT coalesce(array_agg(p.polname::text ORDER BY p.polname::text), ARRAY[]::text[])
    INTO STRICT actual_policy_names
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass;

    IF bucket_match_count = 0 THEN
        RAISE EXCEPTION 'anchor_bucket_missing_create_via_storage_api';
    ELSIF bucket_match_count = 1 THEN
        SELECT b.id, b.name, b.public, b.file_size_limit, b.allowed_mime_types
        INTO STRICT bucket_row
        FROM storage.buckets AS b
        WHERE b.id = {_sql_text(contract.bucket_id)}::text
           OR b.name = {_sql_text(contract.bucket_id)}::text;
        IF bucket_row.id IS DISTINCT FROM {_sql_text(contract.bucket_id)}::text
           OR bucket_row.name IS DISTINCT FROM {_sql_text(contract.bucket_id)}::text
           OR bucket_row.public IS DISTINCT FROM false
           OR bucket_row.file_size_limit IS DISTINCT FROM {contract.file_size_limit_bytes}::bigint
           OR bucket_row.allowed_mime_types IS DISTINCT FROM ARRAY['application/json']::text[] THEN
            RAISE EXCEPTION 'anchor_bucket_definition_drift';
        END IF;
        IF actual_policy_names = ARRAY[]::text[] THEN
            install_mode := 'fresh';
        ELSIF actual_policy_names = expected_policy_names THEN
            install_mode := 'existing';
        ELSE
            RAISE EXCEPTION 'anchor_policy_set_drift';
        END IF;
    ELSE
        RAISE EXCEPTION 'anchor_bucket_identity_drift';
    END IF;

    PERFORM set_config('aqt.anchor_install_mode', install_mode, true);
END
$aqt_anchor_preflight$;
"""


def _render_final_postflight(
    contract: AnchorProjectProvisioningContract,
    policies: tuple[_PolicyContract, ...],
) -> str:
    expected_names = tuple(sorted(policy.name for policy in policies))
    expected_names_sql = ", ".join(_sql_text(name) for name in expected_names)
    return f"""DO $aqt_anchor_postflight$
DECLARE
    actual_policy_names text[];
    expected_policy_names constant text[] := ARRAY[{expected_names_sql}]::text[];
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM storage.buckets AS b
        WHERE b.id = {_sql_text(contract.bucket_id)}::text
          AND b.name = {_sql_text(contract.bucket_id)}::text
          AND b.public = false
          AND b.file_size_limit = {contract.file_size_limit_bytes}::bigint
          AND b.allowed_mime_types = ARRAY['application/json']::text[]
    ) THEN
        RAISE EXCEPTION 'anchor_bucket_postflight_failed';
    END IF;

    SELECT coalesce(array_agg(p.polname::text ORDER BY p.polname::text), ARRAY[]::text[])
    INTO STRICT actual_policy_names
    FROM pg_catalog.pg_policy AS p
    WHERE p.polrelid = 'storage.objects'::regclass;
    IF actual_policy_names IS DISTINCT FROM expected_policy_names THEN
        RAISE EXCEPTION 'anchor_policy_postflight_failed';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_policy AS p
        WHERE p.polrelid = 'storage.objects'::regclass
          AND p.polname = ANY(expected_policy_names)
          AND p.polpermissive
          AND p.polcmd IN ('w', 'd', '*')
    ) THEN
        RAISE EXCEPTION 'anchor_mutation_policy_postflight_failed';
    END IF;
END
$aqt_anchor_postflight$;
"""


def generate_provisioning_sql(contract: object) -> str:
    """Return deterministic transaction-safe bucket and RLS provisioning SQL."""

    validated = validate_provisioning_contract(contract)
    policies = _anchor_policy_contracts(validated)
    install_sections = "\n".join(_render_exact_policy_install(policy) for policy in policies)
    audit_sections = "\n".join(_render_exact_policy_postflight(policy) for policy in policies)
    return f"""-- {CONTRACT_VERSION}
-- Target Supabase project ref: {validated.anchor_project_ref}
-- Runtime-project identity SHA-256: {validated.runtime_project_identity_sha256}
-- Destructive-test-project identity SHA-256: {validated.test_project_identity_sha256}
-- Publishable-key SHA-256: {validated.publishable_key_sha256}
-- Create the exact private bucket through the Supabase Storage API first.
-- This transaction never inserts, updates, or deletes any storage table row.
-- SELECT is limited to upload RETURNING, authenticated GET, list, and list_v2.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL idle_in_transaction_session_timeout = '30s';
SET LOCAL standard_conforming_strings = on;
SELECT pg_catalog.pg_advisory_xact_lock({_ADVISORY_LOCK_KEY}::bigint);

{_render_preflight(validated, policies)}
{install_sections}
-- Recreate each expected policy under a transaction-local audit name and
-- compare pg_policy parse trees.  Audit policies are dropped before commit.
{audit_sections}
{_render_final_postflight(validated, policies)}
COMMIT;
"""


def audit_provisioning_sql(sql: object, contract: object) -> str:
    """Require exact generator output and return its SHA-256 audit identity."""

    if type(sql) is not str:
        raise AnchorProjectProvisioningError("anchor_provisioning_sql_invalid")
    expected = generate_provisioning_sql(contract)
    if sql != expected:
        raise AnchorProjectProvisioningError("anchor_provisioning_sql_drift")
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def provisioning_sql_sha256(contract: object) -> str:
    """Return the digest of the deterministic reviewed SQL bytes."""

    return hashlib.sha256(generate_provisioning_sql(contract).encode("utf-8")).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render offline SQL for a separate trusted-time anchor project."
    )
    parser.add_argument("--anchor-project-url", required=True)
    parser.add_argument("--anchor-project-ref", required=True)
    parser.add_argument("--runtime-project-ref", required=True)
    parser.add_argument("--test-project-ref", required=True)
    parser.add_argument("--publishable-key", required=True)
    parser.add_argument("--writer-principal-id", required=True)
    parser.add_argument("--reader-principal-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Validate arguments and write SQL to stdout without external I/O."""

    arguments = _parser().parse_args(argv)
    try:
        contract = build_provisioning_contract(
            anchor_project_url=arguments.anchor_project_url,
            anchor_project_ref=arguments.anchor_project_ref,
            runtime_project_ref=arguments.runtime_project_ref,
            test_project_ref=arguments.test_project_ref,
            publishable_key=arguments.publishable_key,
            writer_principal_id=arguments.writer_principal_id,
            reader_principal_id=arguments.reader_principal_id,
        )
        sql = generate_provisioning_sql(contract)
    except AnchorProjectProvisioningError as exc:
        print(exc.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(sql)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
