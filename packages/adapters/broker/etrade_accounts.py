"""Bounded offline E*TRADE Accounts List caller-declared response evidence.

This module retains one exact supplied response body before a separate strict
decode.  The evidence is bound to the Phase 4AJ provider, environment,
endpoint, request, media, charset, unauthenticated origin declaration,
response-profile, and schema identities.  Those bindings prove only internal
consistency of caller-supplied bytes and metadata: they do not authenticate
provider origin or detect a fixture relabeled by its caller.  The module
performs no I/O and grants no provider, account, reconciliation,
canonical-fact, or trading authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, cast

from packages.adapters.broker.etrade import (
    ETRADE_ACCOUNTS_LIST_PATH,
    ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256,
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_PROVIDER,
    ETRADE_RECORDED_OFFLINE_CAPABILITIES,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    EtradeAccountIdKey,
    EtradeAccountsListRequestDescription,
    EtradeEndpointIsolationProfile,
    EtradeEnvironment,
    EtradeNumericAccountId,
    EtradeProviderIdentity,
    EtradeReadOnlyOperation,
)
from packages.domain.canonical import canonical_json_bytes

ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION = (
    "phase4ak-etrade-accounts-list-unauthenticated-origin-declaration-v1"
)
ETRADE_ACCOUNTS_LIST_RESPONSE_REVIEWED_ON = "2026-08-24"
ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_ID = (
    "etrade-accounts-list-unauthenticated-declared-json-utf8-v1"
)
ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_ID = "etrade-accounts-list-response-schema-v1"
ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES = 262_144
ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS = 128

_ACCOUNT_TEXT_MAX_UTF8_BYTES = 256
_ROOT_KEYS = ("AccountListResponse",)
_RESPONSE_KEYS = ("Accounts",)
_ACCOUNTS_KEYS = ("Account",)
_ACCOUNT_KEYS = (
    "accountDesc",
    "accountId",
    "accountIdKey",
    "accountMode",
    "accountName",
    "accountStatus",
    "accountType",
    "closedDate",
    "institutionType",
)
_ACCOUNT_NONEMPTY_TEXT_FIELDS = (
    "accountMode",
    "accountStatus",
    "accountType",
    "institutionType",
)
_ACCOUNT_OPTIONALLY_EMPTY_TEXT_FIELDS = ("accountDesc", "accountName")
_DECLARATION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}")

_OPERATION_SUPPORT_FIELDS = (
    "accounts_list_response_supported",
    "balance_response_supported",
    "portfolio_response_supported",
    "orders_response_supported",
    "transactions_response_supported",
    "preview_supported",
    "place_supported",
    "cancel_supported",
    "submission_supported",
)
_AUTHORITY_FIELDS = (
    "credential_resolution_authorized",
    "oauth_session_acquisition_authorized",
    "oauth_token_renewal_authorized",
    "oauth_token_revocation_authorized",
    "authorization_redirect_authorized",
    "callback_handling_authorized",
    "provider_network_authorized",
    "read_only_transport_authorized",
    "request_budget_issuance_authorized",
    "raw_response_persistence_authorized",
    "account_discovery_authorized",
    "account_binding_authorized",
    "lifecycle_evidence_authorized",
    "reconciliation_evidence_authorized",
    "timing_evidence_authorized",
    "economic_evidence_authorized",
    "paper_soak_evidence_authorized",
    "preview_authorized",
    "place_authorized",
    "cancel_authorized",
    "submission_authorized",
    "broker_mutation_authorized",
    "reconciliation_application_authorized",
    "canonical_fact_application_authorized",
    "paper_startup_authorized",
    "live_startup_authorized",
    "trading_effect_authorized",
)


class EtradeAccountsListResponseError(ValueError):
    """Caller-declared Accounts List evidence is outside the frozen profile."""


class EtradeAccountsListOriginDeclarationKind(StrEnum):
    """The sole non-authenticating origin label this offline boundary can establish."""

    UNAUTHENTICATED_CALLER_DECLARATION = "unauthenticated_caller_declaration"


class EtradeAccountsListMediaType(StrEnum):
    """The sole response media type admitted by this offline profile."""

    JSON = "application/json"


class EtradeAccountsListCharset(StrEnum):
    """The sole character encoding admitted by this offline profile."""

    UTF_8 = "utf-8"


def _semantic_sha256(material: object) -> str:
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _require_exact_type(value: object, expected_type: type[object], field_name: str) -> None:
    if type(value) is not expected_type:
        raise EtradeAccountsListResponseError(
            f"{field_name} must use the exact E*TRADE Accounts List response type"
        )


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EtradeAccountsListResponseError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_declaration_id(value: object) -> str:
    if type(value) is not str or _DECLARATION_ID_PATTERN.fullmatch(value) is None:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List declaration ID must contain 8-128 safe visible characters"
        )
    return value


def _require_response_body(value: object) -> bytes:
    if type(value) is not bytes:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List response body must be exact bytes"
        )
    body = value
    if not 1 <= len(body) <= ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List response size is outside the caller-declared offline bound"
        )
    return body


def _response_schema_sha256() -> str:
    return _semantic_sha256(
        (
            ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION,
            ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_ID,
            _ROOT_KEYS,
            _RESPONSE_KEYS,
            _ACCOUNTS_KEYS,
            _ACCOUNT_KEYS,
            _ACCOUNT_NONEMPTY_TEXT_FIELDS,
            _ACCOUNT_OPTIONALLY_EMPTY_TEXT_FIELDS,
            (
                "container_types",
                ("root", "object"),
                ("AccountListResponse", "object"),
                ("Accounts", "object"),
                ("Account", "array"),
                ("account_item", "object"),
            ),
            ("accountId", "exact_digit_text_1_to_32"),
            ("accountIdKey", "exact_safe_opaque_text_1_to_128"),
            (
                "metadata_text",
                "trimmed_valid_utf8_without_ascii_control_characters",
                _ACCOUNT_TEXT_MAX_UTF8_BYTES,
            ),
            ("closedDate", "exact_integer_0_to_99991231"),
            ("duplicate_json_keys", "reject_at_every_depth"),
            ("duplicate_or_ambiguous_account_identity", "reject"),
            ("unknown_or_missing_keys", "reject_at_every_depth"),
            ("json_constants", "reject_nonstandard"),
            ("minimum_accounts", 1),
            ("maximum_accounts", ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS),
        )
    )


ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256 = _response_schema_sha256()


class _NoAccountsListResponseAuthority:
    __slots__ = ()

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({field_name: False for field_name in _AUTHORITY_FIELDS})

    @property
    def credential_resolution_authorized(self) -> bool:
        return False

    @property
    def oauth_session_acquisition_authorized(self) -> bool:
        return False

    @property
    def oauth_token_renewal_authorized(self) -> bool:
        return False

    @property
    def oauth_token_revocation_authorized(self) -> bool:
        return False

    @property
    def authorization_redirect_authorized(self) -> bool:
        return False

    @property
    def callback_handling_authorized(self) -> bool:
        return False

    @property
    def provider_network_authorized(self) -> bool:
        return False

    @property
    def read_only_transport_authorized(self) -> bool:
        return False

    @property
    def request_budget_issuance_authorized(self) -> bool:
        return False

    @property
    def raw_response_persistence_authorized(self) -> bool:
        return False

    @property
    def account_discovery_authorized(self) -> bool:
        return False

    @property
    def account_binding_authorized(self) -> bool:
        return False

    @property
    def lifecycle_evidence_authorized(self) -> bool:
        return False

    @property
    def reconciliation_evidence_authorized(self) -> bool:
        return False

    @property
    def timing_evidence_authorized(self) -> bool:
        return False

    @property
    def economic_evidence_authorized(self) -> bool:
        return False

    @property
    def paper_soak_evidence_authorized(self) -> bool:
        return False

    @property
    def preview_authorized(self) -> bool:
        return False

    @property
    def place_authorized(self) -> bool:
        return False

    @property
    def cancel_authorized(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def broker_mutation_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def canonical_fact_application_authorized(self) -> bool:
        return False

    @property
    def paper_startup_authorized(self) -> bool:
        return False

    @property
    def live_startup_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def sandbox_economic_evidence(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class EtradeAccountsListResponseProfile(_NoAccountsListResponseAuthority):
    """Deterministic caller-declared response contract with closed authority."""

    provider: EtradeProviderIdentity = ETRADE_PROVIDER
    operation: EtradeReadOnlyOperation = EtradeReadOnlyOperation.ACCOUNTS_LIST
    media_type: EtradeAccountsListMediaType = EtradeAccountsListMediaType.JSON
    charset: EtradeAccountsListCharset = EtradeAccountsListCharset.UTF_8
    request_profile_sha256: str = ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256
    schema_profile_sha256: str = ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256
    maximum_response_bytes: int = ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES
    maximum_accounts: int = ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS
    offline_only: bool = True
    raw_first_required: bool = True
    unauthenticated_origin_declaration_required: Literal[True] = True
    provider_origin_authentication_supported: Literal[False] = False
    fixture_relabeling_detection_supported: Literal[False] = False
    accounts_list_response_supported: bool = True
    balance_response_supported: bool = False
    portfolio_response_supported: bool = False
    orders_response_supported: bool = False
    transactions_response_supported: bool = False
    preview_supported: bool = False
    place_supported: bool = False
    cancel_supported: bool = False
    submission_supported: bool = False

    def __post_init__(self) -> None:
        _require_exact_type(self.provider, EtradeProviderIdentity, "response-profile provider")
        self.provider.__post_init__()
        _require_exact_type(self.operation, EtradeReadOnlyOperation, "response-profile operation")
        if self.operation is not EtradeReadOnlyOperation.ACCOUNTS_LIST:
            raise EtradeAccountsListResponseError(
                "E*TRADE response profile supports only Accounts List"
            )
        _require_exact_type(self.media_type, EtradeAccountsListMediaType, "response media type")
        if self.media_type is not EtradeAccountsListMediaType.JSON:
            raise EtradeAccountsListResponseError("E*TRADE response media profile was altered")
        _require_exact_type(self.charset, EtradeAccountsListCharset, "response charset")
        if self.charset is not EtradeAccountsListCharset.UTF_8:
            raise EtradeAccountsListResponseError("E*TRADE response charset profile was altered")
        expected_values: tuple[tuple[str, object], ...] = (
            ("request_profile_sha256", ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256),
            ("schema_profile_sha256", ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256),
            ("maximum_response_bytes", ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES),
            ("maximum_accounts", ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS),
            ("offline_only", True),
            ("raw_first_required", True),
            ("unauthenticated_origin_declaration_required", True),
            ("provider_origin_authentication_supported", False),
            ("fixture_relabeling_detection_supported", False),
            ("accounts_list_response_supported", True),
            ("balance_response_supported", False),
            ("portfolio_response_supported", False),
            ("orders_response_supported", False),
            ("transactions_response_supported", False),
            ("preview_supported", False),
            ("place_supported", False),
            ("cancel_supported", False),
            ("submission_supported", False),
        )
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise EtradeAccountsListResponseError(
                    f"E*TRADE Accounts List response profile {field_name} was altered"
                )
        ETRADE_RECORDED_OFFLINE_CAPABILITIES.__post_init__()

    @property
    def contract_version(self) -> str:
        return ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION

    @property
    def profile_id(self) -> str:
        return ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_ID

    @property
    def schema_profile_id(self) -> str:
        return ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_ID

    @property
    def operation_support(self) -> Mapping[str, bool]:
        return MappingProxyType(
            {
                field_name: cast(bool, getattr(self, field_name))
                for field_name in _OPERATION_SUPPORT_FIELDS
            }
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                self.contract_version,
                self.profile_id,
                self.provider.value,
                self.operation,
                self.media_type,
                self.charset,
                self.request_profile_sha256,
                self.schema_profile_id,
                self.schema_profile_sha256,
                self.maximum_response_bytes,
                self.maximum_accounts,
                self.offline_only,
                self.raw_first_required,
                self.unauthenticated_origin_declaration_required,
                self.provider_origin_authentication_supported,
                self.fixture_relabeling_detection_supported,
                tuple(self.operation_support.items()),
                ETRADE_RECORDED_OFFLINE_CAPABILITIES.semantic_sha256,
                tuple(self.authority.items()),
            )
        )


ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE = EtradeAccountsListResponseProfile()
ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256 = ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE.semantic_sha256


def _endpoint_profile(environment: EtradeEnvironment) -> EtradeEndpointIsolationProfile:
    _require_exact_type(environment, EtradeEnvironment, "declared environment")
    if environment is EtradeEnvironment.SANDBOX:
        return ETRADE_SANDBOX_ENDPOINT_PROFILE
    return ETRADE_PRODUCTION_ENDPOINT_PROFILE


@dataclass(frozen=True, slots=True)
class EtradeAccountsListUnauthenticatedOriginDeclaration(_NoAccountsListResponseAuthority):
    """Caller-attributed response metadata that proves no provider origin.

    The sole declaration kind is intentionally unauthenticated.  Exact local
    bindings cannot distinguish genuine provider bytes from a fixture that a
    caller relabeled before invoking this API.
    """

    declaration_id: str
    declaration_kind: EtradeAccountsListOriginDeclarationKind
    declared_provider: EtradeProviderIdentity
    declared_environment: EtradeEnvironment
    declared_endpoint_profile_sha256: str
    declared_response_origin: str
    declared_response_api_root: str
    declared_response_url: str
    declared_request_method: str
    declared_request_target: str
    declared_request_description_sha256: str
    bound_request_profile_sha256: str
    bound_response_profile_sha256: str
    bound_schema_profile_sha256: str
    declared_http_status: int
    declared_media_type: EtradeAccountsListMediaType
    declared_charset: EtradeAccountsListCharset
    supplied_response_size_bytes: int
    supplied_response_body_sha256: str
    provider_origin_authenticated: Literal[False]
    fixture_relabeling_detection_supported: Literal[False]

    def __post_init__(self) -> None:
        _require_declaration_id(self.declaration_id)
        _require_exact_type(
            self.declaration_kind,
            EtradeAccountsListOriginDeclarationKind,
            "origin declaration kind",
        )
        if (
            self.declaration_kind
            is not EtradeAccountsListOriginDeclarationKind.UNAUTHENTICATED_CALLER_DECLARATION
        ):
            raise EtradeAccountsListResponseError(
                "E*TRADE origin must remain an unauthenticated caller declaration"
            )
        _require_exact_type(
            self.declared_provider,
            EtradeProviderIdentity,
            "declared provider",
        )
        self.declared_provider.__post_init__()
        _require_exact_type(
            self.declared_environment,
            EtradeEnvironment,
            "declared environment",
        )
        expected_endpoint = _endpoint_profile(self.declared_environment)
        expected_endpoint.__post_init__()
        expected_values: tuple[tuple[str, object], ...] = (
            ("declared_endpoint_profile_sha256", expected_endpoint.semantic_sha256),
            ("declared_response_origin", expected_endpoint.data_api_origin),
            ("declared_response_api_root", expected_endpoint.data_api_root),
            (
                "declared_response_url",
                f"{expected_endpoint.data_api_root}{ETRADE_ACCOUNTS_LIST_PATH}",
            ),
            ("declared_request_method", "GET"),
            ("declared_request_target", ETRADE_ACCOUNTS_LIST_PATH),
            ("bound_request_profile_sha256", ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256),
            ("bound_response_profile_sha256", ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256),
            ("bound_schema_profile_sha256", ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256),
            ("declared_http_status", 200),
            ("provider_origin_authenticated", False),
            ("fixture_relabeling_detection_supported", False),
        )
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise EtradeAccountsListResponseError(
                    "E*TRADE Accounts List unauthenticated origin declaration "
                    f"{field_name} conflicts with its profile"
                )
        _require_sha256(
            self.declared_request_description_sha256,
            "declared E*TRADE Accounts List request-description identity",
        )
        _require_exact_type(
            self.declared_media_type,
            EtradeAccountsListMediaType,
            "declared media type",
        )
        if self.declared_media_type is not EtradeAccountsListMediaType.JSON:
            raise EtradeAccountsListResponseError("declared E*TRADE media type was altered")
        _require_exact_type(
            self.declared_charset,
            EtradeAccountsListCharset,
            "declared charset",
        )
        if self.declared_charset is not EtradeAccountsListCharset.UTF_8:
            raise EtradeAccountsListResponseError("declared E*TRADE charset was altered")
        if (
            type(self.supplied_response_size_bytes) is not int
            or not 1 <= self.supplied_response_size_bytes <= ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES
        ):
            raise EtradeAccountsListResponseError(
                "supplied E*TRADE response size is outside the offline bound"
            )
        _require_sha256(
            self.supplied_response_body_sha256,
            "supplied E*TRADE Accounts List response-body identity",
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION,
                "unauthenticated_origin_declaration",
                self.declaration_id,
                self.declaration_kind,
                self.declared_provider.value,
                self.declared_environment,
                self.declared_endpoint_profile_sha256,
                self.declared_response_origin,
                self.declared_response_api_root,
                self.declared_response_url,
                self.declared_request_method,
                self.declared_request_target,
                self.declared_request_description_sha256,
                self.bound_request_profile_sha256,
                self.bound_response_profile_sha256,
                self.bound_schema_profile_sha256,
                self.declared_http_status,
                self.declared_media_type,
                self.declared_charset,
                self.supplied_response_size_bytes,
                self.supplied_response_body_sha256,
                self.provider_origin_authenticated,
                self.fixture_relabeling_detection_supported,
                tuple(self.authority.items()),
            )
        )


def create_etrade_accounts_list_unauthenticated_origin_declaration(
    description: EtradeAccountsListRequestDescription,
    *,
    profile: EtradeAccountsListResponseProfile,
    declaration_id: str,
    declared_http_status: int,
    declared_media_type: EtradeAccountsListMediaType,
    declared_charset: EtradeAccountsListCharset,
    response_body: bytes,
) -> EtradeAccountsListUnauthenticatedOriginDeclaration:
    """Bind caller-attributed metadata and bytes without authenticating their origin.

    This declaration cannot distinguish provider bytes from a relabeled fixture.
    """

    _require_exact_type(
        description,
        EtradeAccountsListRequestDescription,
        "declared request description",
    )
    description.__post_init__()
    _require_exact_type(profile, EtradeAccountsListResponseProfile, "declared response profile")
    profile.__post_init__()
    body = _require_response_body(response_body)
    return EtradeAccountsListUnauthenticatedOriginDeclaration(
        declaration_id=declaration_id,
        declaration_kind=(
            EtradeAccountsListOriginDeclarationKind.UNAUTHENTICATED_CALLER_DECLARATION
        ),
        declared_provider=description.provider,
        declared_environment=description.environment,
        declared_endpoint_profile_sha256=description.endpoint_profile.semantic_sha256,
        declared_response_origin=description.endpoint_profile.data_api_origin,
        declared_response_api_root=description.base_url,
        declared_response_url=description.url,
        declared_request_method=description.method,
        declared_request_target=description.request_target,
        declared_request_description_sha256=description.semantic_sha256,
        bound_request_profile_sha256=description.request_profile_sha256,
        bound_response_profile_sha256=profile.semantic_sha256,
        bound_schema_profile_sha256=profile.schema_profile_sha256,
        declared_http_status=declared_http_status,
        declared_media_type=declared_media_type,
        declared_charset=declared_charset,
        supplied_response_size_bytes=len(body),
        supplied_response_body_sha256=hashlib.sha256(body).hexdigest(),
        provider_origin_authenticated=False,
        fixture_relabeling_detection_supported=False,
    )


@dataclass(frozen=True, slots=True, init=False)
class EtradeAccountsListCallerDeclaredResponse(_NoAccountsListResponseAuthority):
    """Immutable caller-declared raw bytes; this type does not prove provider origin."""

    description: EtradeAccountsListRequestDescription
    profile: EtradeAccountsListResponseProfile
    origin_declaration: EtradeAccountsListUnauthenticatedOriginDeclaration
    response_body: bytes = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EtradeAccountsListCallerDeclaredResponse must be proof-constructed")

    def _validate(self) -> None:
        _require_exact_type(
            self.description,
            EtradeAccountsListRequestDescription,
            "caller-declared response request description",
        )
        self.description.__post_init__()
        _require_exact_type(
            self.profile,
            EtradeAccountsListResponseProfile,
            "caller-declared response profile",
        )
        self.profile.__post_init__()
        _require_exact_type(
            self.origin_declaration,
            EtradeAccountsListUnauthenticatedOriginDeclaration,
            "unauthenticated origin declaration",
        )
        self.origin_declaration.__post_init__()
        body = _require_response_body(self.response_body)
        expected_values: tuple[tuple[str, object, object], ...] = (
            (
                "declared provider",
                self.origin_declaration.declared_provider.value,
                self.description.provider.value,
            ),
            (
                "declared environment",
                self.origin_declaration.declared_environment,
                self.description.environment,
            ),
            (
                "declared endpoint profile",
                self.origin_declaration.declared_endpoint_profile_sha256,
                self.description.endpoint_profile.semantic_sha256,
            ),
            (
                "declared response origin",
                self.origin_declaration.declared_response_origin,
                self.description.endpoint_profile.data_api_origin,
            ),
            (
                "declared response API root",
                self.origin_declaration.declared_response_api_root,
                self.description.base_url,
            ),
            (
                "declared response URL",
                self.origin_declaration.declared_response_url,
                self.description.url,
            ),
            (
                "declared request method",
                self.origin_declaration.declared_request_method,
                self.description.method,
            ),
            (
                "declared request target",
                self.origin_declaration.declared_request_target,
                self.description.request_target,
            ),
            (
                "declared request description",
                self.origin_declaration.declared_request_description_sha256,
                self.description.semantic_sha256,
            ),
            (
                "request profile",
                self.origin_declaration.bound_request_profile_sha256,
                self.description.request_profile_sha256,
            ),
            (
                "response profile",
                self.origin_declaration.bound_response_profile_sha256,
                self.profile.semantic_sha256,
            ),
            (
                "schema profile",
                self.origin_declaration.bound_schema_profile_sha256,
                self.profile.schema_profile_sha256,
            ),
            (
                "declared media type",
                self.origin_declaration.declared_media_type,
                self.profile.media_type,
            ),
            (
                "declared charset",
                self.origin_declaration.declared_charset,
                self.profile.charset,
            ),
            (
                "supplied response size",
                self.origin_declaration.supplied_response_size_bytes,
                len(body),
            ),
            (
                "supplied response body",
                self.origin_declaration.supplied_response_body_sha256,
                hashlib.sha256(body).hexdigest(),
            ),
            (
                "provider-origin authentication",
                self.origin_declaration.provider_origin_authenticated,
                False,
            ),
            (
                "fixture-relabeling detection",
                self.origin_declaration.fixture_relabeling_detection_supported,
                False,
            ),
        )
        for field_name, actual, expected in expected_values:
            if type(actual) is not type(expected) or actual != expected:
                raise EtradeAccountsListResponseError(
                    f"caller-declared E*TRADE Accounts List {field_name} binding was altered"
                )

    @property
    def provider(self) -> EtradeProviderIdentity:
        self._validate()
        return self.description.provider

    @property
    def environment(self) -> EtradeEnvironment:
        self._validate()
        return self.description.environment

    @property
    def response_size_bytes(self) -> int:
        self._validate()
        return len(self.response_body)

    @property
    def response_body_sha256(self) -> str:
        self._validate()
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def provider_origin_authenticated(self) -> bool:
        self._validate()
        return self.origin_declaration.provider_origin_authenticated

    @property
    def fixture_relabeling_detection_supported(self) -> bool:
        self._validate()
        return self.origin_declaration.fixture_relabeling_detection_supported

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION,
                "caller_declared_response",
                self.description.semantic_sha256,
                self.profile.semantic_sha256,
                self.origin_declaration.semantic_sha256,
                self.response_size_bytes,
                self.response_body_sha256,
                tuple(self.authority.items()),
            )
        )


def create_etrade_accounts_list_caller_declared_response(
    description: EtradeAccountsListRequestDescription,
    *,
    profile: EtradeAccountsListResponseProfile,
    origin_declaration: EtradeAccountsListUnauthenticatedOriginDeclaration,
    response_body: bytes,
) -> EtradeAccountsListCallerDeclaredResponse:
    """Retain caller-declared bytes without authenticating origin or decoding."""

    response = object.__new__(EtradeAccountsListCallerDeclaredResponse)
    object.__setattr__(response, "description", description)
    object.__setattr__(response, "profile", profile)
    object.__setattr__(response, "origin_declaration", origin_declaration)
    object.__setattr__(response, "response_body", response_body)
    response._validate()
    return response


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EtradeAccountsListResponseError(
                "E*TRADE Accounts List response contains a duplicate JSON key"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise EtradeAccountsListResponseError(
        "E*TRADE Accounts List response contains a non-standard JSON constant"
    )


def _require_exact_keys(value: Mapping[str, object], expected: tuple[str, ...], name: str) -> None:
    if frozenset(value) != frozenset(expected) or len(value) != len(expected):
        raise EtradeAccountsListResponseError(
            f"E*TRADE Accounts List {name} keys do not match the response schema"
        )


def _require_object(value: object, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EtradeAccountsListResponseError(
            f"E*TRADE Accounts List {name} must be one exact JSON object"
        )
    return cast(dict[str, Any], value)


def _require_bounded_text(
    value: object,
    field_name: str,
    *,
    allow_empty: bool,
) -> str:
    if type(value) is not str:
        raise EtradeAccountsListResponseError(
            f"E*TRADE Accounts List {field_name} must be an exact string"
        )
    text = value
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EtradeAccountsListResponseError(
            f"E*TRADE Accounts List {field_name} contains invalid Unicode"
        ) from error
    if (
        len(encoded) > _ACCOUNT_TEXT_MAX_UTF8_BYTES
        or (not allow_empty and not text)
        or text != text.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise EtradeAccountsListResponseError(
            f"E*TRADE Accounts List {field_name} is outside the bounded text profile"
        )
    return text


@dataclass(frozen=True, slots=True)
class _DecodedAccountPair:
    numeric_account_id: EtradeNumericAccountId
    account_id_key: EtradeAccountIdKey


def _decode_account_pairs(response_body: bytes) -> tuple[_DecodedAccountPair, ...]:
    body = _require_response_body(response_body)
    try:
        text = body.decode(EtradeAccountsListCharset.UTF_8.value)
    except UnicodeDecodeError as error:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List response must be strict UTF-8"
        ) from error
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except EtradeAccountsListResponseError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List response is invalid JSON"
        ) from error

    root = _require_object(decoded, "root")
    _require_exact_keys(root, _ROOT_KEYS, "root")
    response = _require_object(root["AccountListResponse"], "response envelope")
    _require_exact_keys(response, _RESPONSE_KEYS, "response envelope")
    accounts_envelope = _require_object(response["Accounts"], "accounts envelope")
    _require_exact_keys(accounts_envelope, _ACCOUNTS_KEYS, "accounts envelope")
    account_values = accounts_envelope["Account"]
    if type(account_values) is not list:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List Account must be one exact JSON array"
        )
    accounts = account_values
    if not 1 <= len(accounts) <= ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS:
        raise EtradeAccountsListResponseError(
            "E*TRADE Accounts List account count is outside the response-profile bound"
        )

    result: list[_DecodedAccountPair] = []
    numeric_to_key: dict[str, str] = {}
    key_to_numeric: dict[str, str] = {}
    seen_pairs: set[tuple[str, str]] = set()
    for index, item in enumerate(accounts):
        account = _require_object(item, f"account item {index}")
        _require_exact_keys(account, _ACCOUNT_KEYS, f"account item {index}")
        for field_name in _ACCOUNT_NONEMPTY_TEXT_FIELDS:
            _require_bounded_text(account[field_name], field_name, allow_empty=False)
        for field_name in _ACCOUNT_OPTIONALLY_EMPTY_TEXT_FIELDS:
            _require_bounded_text(account[field_name], field_name, allow_empty=True)
        closed_date = account["closedDate"]
        if type(closed_date) is not int or not 0 <= closed_date <= 99_991_231:
            raise EtradeAccountsListResponseError(
                "E*TRADE Accounts List closedDate must be an exact bounded integer"
            )
        try:
            numeric_account_id = EtradeNumericAccountId(account["accountId"])
            account_id_key = EtradeAccountIdKey(account["accountIdKey"])
        except ValueError as error:
            raise EtradeAccountsListResponseError(
                f"E*TRADE Accounts List account item {index} has malformed provider identity"
            ) from error
        pair = (numeric_account_id.value, account_id_key.value)
        if pair in seen_pairs:
            raise EtradeAccountsListResponseError(
                "E*TRADE Accounts List repeats an exact account identity"
            )
        previous_key = numeric_to_key.get(numeric_account_id.value)
        if previous_key is not None and previous_key != account_id_key.value:
            raise EtradeAccountsListResponseError(
                "E*TRADE Accounts List maps one numeric account ID to multiple accountIdKeys"
            )
        previous_numeric = key_to_numeric.get(account_id_key.value)
        if previous_numeric is not None and previous_numeric != numeric_account_id.value:
            raise EtradeAccountsListResponseError(
                "E*TRADE Accounts List maps one accountIdKey to multiple numeric account IDs"
            )
        seen_pairs.add(pair)
        numeric_to_key[numeric_account_id.value] = account_id_key.value
        key_to_numeric[account_id_key.value] = numeric_account_id.value
        result.append(
            _DecodedAccountPair(
                numeric_account_id=numeric_account_id,
                account_id_key=account_id_key,
            )
        )
    return tuple(result)


@dataclass(frozen=True, slots=True, init=False)
class EtradeAccountsListAccountIdentity(_NoAccountsListResponseAuthority):
    """One unqualified identity bound to exact caller-declared raw evidence."""

    caller_declared_response: EtradeAccountsListCallerDeclaredResponse = field(repr=False)
    provider: EtradeProviderIdentity
    environment: EtradeEnvironment
    account_index: int
    numeric_account_id: EtradeNumericAccountId = field(repr=False)
    account_id_key: EtradeAccountIdKey = field(repr=False)
    endpoint_profile_sha256: str
    request_description_sha256: str
    origin_declaration_sha256: str
    response_profile_sha256: str
    schema_profile_sha256: str
    response_body_sha256: str
    caller_declared_response_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EtradeAccountsListAccountIdentity must be proof-constructed")

    def _validate(self) -> None:
        _require_exact_type(
            self.caller_declared_response,
            EtradeAccountsListCallerDeclaredResponse,
            "decoded account raw evidence",
        )
        self.caller_declared_response._validate()
        _require_exact_type(self.provider, EtradeProviderIdentity, "decoded account provider")
        self.provider.__post_init__()
        _require_exact_type(self.environment, EtradeEnvironment, "decoded account environment")
        if type(self.account_index) is not int or self.account_index < 0:
            raise EtradeAccountsListResponseError(
                "decoded E*TRADE account index must be a nonnegative exact integer"
            )
        _require_exact_type(
            self.numeric_account_id,
            EtradeNumericAccountId,
            "decoded numeric account ID",
        )
        _require_exact_type(self.account_id_key, EtradeAccountIdKey, "decoded accountIdKey")
        self.numeric_account_id.__post_init__()
        self.account_id_key.__post_init__()
        for field_name in (
            "endpoint_profile_sha256",
            "request_description_sha256",
            "origin_declaration_sha256",
            "response_profile_sha256",
            "schema_profile_sha256",
            "response_body_sha256",
            "caller_declared_response_sha256",
        ):
            _require_sha256(getattr(self, field_name), f"decoded account {field_name}")
        if self.response_profile_sha256 != ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256:
            raise EtradeAccountsListResponseError("decoded account response profile was altered")
        if self.schema_profile_sha256 != ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256:
            raise EtradeAccountsListResponseError("decoded account schema profile was altered")
        decoded_pairs = _decode_account_pairs(self.caller_declared_response.response_body)
        if self.account_index >= len(decoded_pairs):
            raise EtradeAccountsListResponseError(
                "decoded E*TRADE account index is outside its exact raw response"
            )
        expected_pair = decoded_pairs[self.account_index]
        expected_values: tuple[tuple[str, object, object], ...] = (
            (
                "provider",
                self.provider.value,
                self.caller_declared_response.description.provider.value,
            ),
            (
                "environment",
                self.environment,
                self.caller_declared_response.description.environment,
            ),
            (
                "numeric account ID",
                self.numeric_account_id.value,
                expected_pair.numeric_account_id.value,
            ),
            (
                "accountIdKey",
                self.account_id_key.value,
                expected_pair.account_id_key.value,
            ),
            (
                "endpoint profile",
                self.endpoint_profile_sha256,
                self.caller_declared_response.description.endpoint_profile.semantic_sha256,
            ),
            (
                "request description",
                self.request_description_sha256,
                self.caller_declared_response.description.semantic_sha256,
            ),
            (
                "unauthenticated origin declaration",
                self.origin_declaration_sha256,
                self.caller_declared_response.origin_declaration.semantic_sha256,
            ),
            (
                "response profile",
                self.response_profile_sha256,
                self.caller_declared_response.profile.semantic_sha256,
            ),
            (
                "schema profile",
                self.schema_profile_sha256,
                self.caller_declared_response.profile.schema_profile_sha256,
            ),
            (
                "response body",
                self.response_body_sha256,
                self.caller_declared_response.response_body_sha256,
            ),
            (
                "caller-declared response",
                self.caller_declared_response_sha256,
                self.caller_declared_response.semantic_sha256,
            ),
        )
        for field_name, actual, expected in expected_values:
            if type(actual) is not type(expected) or actual != expected:
                raise EtradeAccountsListResponseError(
                    f"decoded E*TRADE account {field_name} conflicts with its exact raw response"
                )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION,
                "decoded_account_identity",
                self.caller_declared_response.semantic_sha256,
                self.provider.value,
                self.environment,
                self.account_index,
                self.numeric_account_id.value,
                self.account_id_key.value,
                self.endpoint_profile_sha256,
                self.request_description_sha256,
                self.origin_declaration_sha256,
                self.response_profile_sha256,
                self.schema_profile_sha256,
                self.response_body_sha256,
                self.caller_declared_response_sha256,
                tuple(self.authority.items()),
            )
        )

    @property
    def provider_origin_authenticated(self) -> bool:
        self._validate()
        return self.caller_declared_response.provider_origin_authenticated

    @property
    def fixture_relabeling_detection_supported(self) -> bool:
        self._validate()
        return self.caller_declared_response.fixture_relabeling_detection_supported


def _account_identity(
    caller_declared_response: EtradeAccountsListCallerDeclaredResponse,
    pair: _DecodedAccountPair,
    index: int,
) -> EtradeAccountsListAccountIdentity:
    identity = object.__new__(EtradeAccountsListAccountIdentity)
    object.__setattr__(identity, "caller_declared_response", caller_declared_response)
    object.__setattr__(identity, "provider", caller_declared_response.description.provider)
    object.__setattr__(identity, "environment", caller_declared_response.description.environment)
    object.__setattr__(identity, "account_index", index)
    object.__setattr__(identity, "numeric_account_id", pair.numeric_account_id)
    object.__setattr__(identity, "account_id_key", pair.account_id_key)
    object.__setattr__(
        identity,
        "endpoint_profile_sha256",
        caller_declared_response.description.endpoint_profile.semantic_sha256,
    )
    object.__setattr__(
        identity,
        "request_description_sha256",
        caller_declared_response.description.semantic_sha256,
    )
    object.__setattr__(
        identity,
        "origin_declaration_sha256",
        caller_declared_response.origin_declaration.semantic_sha256,
    )
    object.__setattr__(
        identity,
        "response_profile_sha256",
        caller_declared_response.profile.semantic_sha256,
    )
    object.__setattr__(
        identity,
        "schema_profile_sha256",
        caller_declared_response.profile.schema_profile_sha256,
    )
    object.__setattr__(
        identity,
        "response_body_sha256",
        caller_declared_response.response_body_sha256,
    )
    object.__setattr__(
        identity,
        "caller_declared_response_sha256",
        caller_declared_response.semantic_sha256,
    )
    identity._validate()
    return identity


@dataclass(frozen=True, slots=True, init=False)
class EtradeAccountsListObservation(_NoAccountsListResponseAuthority):
    """Strict decode of caller-declared bytes, never authenticated provider evidence."""

    caller_declared_response: EtradeAccountsListCallerDeclaredResponse
    accounts: tuple[EtradeAccountsListAccountIdentity, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EtradeAccountsListObservation must be proof-constructed")

    def _validate(self) -> None:
        _require_exact_type(
            self.caller_declared_response,
            EtradeAccountsListCallerDeclaredResponse,
            "decoded Accounts List raw evidence",
        )
        self.caller_declared_response._validate()
        if type(self.accounts) is not tuple or any(
            type(account) is not EtradeAccountsListAccountIdentity for account in self.accounts
        ):
            raise EtradeAccountsListResponseError(
                "decoded E*TRADE accounts must be an exact tuple of exact identities"
            )
        for account in self.accounts:
            account._validate()
        pairs = _decode_account_pairs(self.caller_declared_response.response_body)
        expected = tuple(
            _account_identity(self.caller_declared_response, pair, index)
            for index, pair in enumerate(pairs)
        )
        if self.accounts != expected:
            raise EtradeAccountsListResponseError(
                "decoded E*TRADE account identities conflict with the exact raw response"
            )

    @property
    def account_count(self) -> int:
        self._validate()
        return len(self.accounts)

    @property
    def provider(self) -> EtradeProviderIdentity:
        self._validate()
        return self.caller_declared_response.provider

    @property
    def environment(self) -> EtradeEnvironment:
        self._validate()
        return self.caller_declared_response.environment

    @property
    def provider_origin_authenticated(self) -> bool:
        self._validate()
        return self.caller_declared_response.provider_origin_authenticated

    @property
    def fixture_relabeling_detection_supported(self) -> bool:
        self._validate()
        return self.caller_declared_response.fixture_relabeling_detection_supported

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION,
                "accounts_list_observation",
                self.caller_declared_response.semantic_sha256,
                tuple(account.semantic_sha256 for account in self.accounts),
                tuple(self.authority.items()),
            )
        )


def decode_etrade_accounts_list_caller_declared_response(
    caller_declared_response: EtradeAccountsListCallerDeclaredResponse,
) -> EtradeAccountsListObservation:
    """Decode caller-declared bytes without authenticating their provider origin."""

    _require_exact_type(
        caller_declared_response,
        EtradeAccountsListCallerDeclaredResponse,
        "Accounts List decoder input",
    )
    caller_declared_response._validate()
    pairs = _decode_account_pairs(caller_declared_response.response_body)
    observation = object.__new__(EtradeAccountsListObservation)
    object.__setattr__(observation, "caller_declared_response", caller_declared_response)
    object.__setattr__(
        observation,
        "accounts",
        tuple(
            _account_identity(caller_declared_response, pair, index)
            for index, pair in enumerate(pairs)
        ),
    )
    observation._validate()
    return observation


__all__ = [
    "ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS",
    "ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_CONTRACT_VERSION",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_ID",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_REVIEWED_ON",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_ID",
    "ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256",
    "EtradeAccountsListAccountIdentity",
    "EtradeAccountsListCallerDeclaredResponse",
    "EtradeAccountsListCharset",
    "EtradeAccountsListMediaType",
    "EtradeAccountsListObservation",
    "EtradeAccountsListOriginDeclarationKind",
    "EtradeAccountsListResponseError",
    "EtradeAccountsListResponseProfile",
    "EtradeAccountsListUnauthenticatedOriginDeclaration",
    "create_etrade_accounts_list_caller_declared_response",
    "create_etrade_accounts_list_unauthenticated_origin_declaration",
    "decode_etrade_accounts_list_caller_declared_response",
]
