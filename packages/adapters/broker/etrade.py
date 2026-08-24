"""Recorded-offline, non-authorizing E*TRADE provider foundation.

This module freezes provider-specific endpoint, callback, secret-scope, and
account-identifier contracts plus one deterministic Accounts List request
description.  It owns no credentials, OAuth flow, clock, randomness,
filesystem, persistence, transport, decoder, canonical broker fact, or trading
authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from packages.domain.canonical import canonical_json_bytes

ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION = "phase4aj-etrade-recorded-offline-foundation-v1"
ETRADE_RECORDED_OFFLINE_REVIEWED_ON = "2026-08-23"
ETRADE_PROVIDER_ID = "etrade"
ETRADE_RECORDED_OFFLINE_ADAPTER_ID = "etrade-recorded-offline"
ETRADE_RECORDED_OFFLINE_ADAPTER_VERSION = "1.0.0"
ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_ID = "etrade-accounts-list-json-v1"

ETRADE_SANDBOX_DATA_API_ORIGIN = "https://apisb.etrade.com"
ETRADE_SANDBOX_ORDER_API_ORIGIN = "https://apisb.etrade.com"
ETRADE_SANDBOX_DATA_API_ROOT = "https://apisb.etrade.com/v1"
ETRADE_SANDBOX_ORDER_API_ROOT = "https://apisb.etrade.com/v1"
ETRADE_PRODUCTION_DATA_API_ORIGIN = "https://api.etrade.com"
ETRADE_PRODUCTION_ORDER_API_ORIGIN = "https://api.etrade.com"
ETRADE_PRODUCTION_DATA_API_ROOT = "https://api.etrade.com/v1"
ETRADE_PRODUCTION_ORDER_API_ROOT = "https://api.etrade.com/v1"

ETRADE_SHARED_TOKEN_ORIGIN = "https://api.etrade.com"
ETRADE_SHARED_TOKEN_ROOT = "https://api.etrade.com/oauth/"
ETRADE_SHARED_REQUEST_TOKEN_URL = "https://api.etrade.com/oauth/request_token"
ETRADE_SHARED_ACCESS_TOKEN_URL = "https://api.etrade.com/oauth/access_token"
ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL = "https://api.etrade.com/oauth/renew_access_token"
ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL = "https://api.etrade.com/oauth/revoke_access_token"
ETRADE_SHARED_AUTHORIZATION_ORIGIN = "https://us.etrade.com"
ETRADE_SHARED_AUTHORIZATION_PATH = "/e/t/etws/authorize"
ETRADE_SHARED_AUTHORIZATION_PAGE = (
    f"{ETRADE_SHARED_AUTHORIZATION_ORIGIN}{ETRADE_SHARED_AUTHORIZATION_PATH}"
)

ETRADE_ACCOUNTS_LIST_PATH = "/accounts/list"
ETRADE_JSON_ACCEPT_HEADER = ("Accept", "application/json")
ETRADE_SANDBOX_EVIDENCE_SCOPE = "protocol_shape_only"
ETRADE_OAUTH_CALLBACK_PARAMETER = "oob"

_LOCAL_ACCOUNT_ALIAS_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_NUMERIC_ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{1,32}")
_ACCOUNT_ID_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")

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

_SANDBOX_QUALIFICATION_FIELDS = (
    "sandbox_traversal_semantics_qualified",
    "sandbox_completeness_qualified",
    "sandbox_lifecycle_qualified",
    "sandbox_reconciliation_qualified",
    "sandbox_timing_qualified",
    "sandbox_economic_qualified",
    "sandbox_paper_soak_qualified",
    "sandbox_live_readiness_qualified",
)


class EtradeRecordedOfflineContractError(ValueError):
    """The bounded E*TRADE contract or a request description drifted."""


class EtradeEnvironment(StrEnum):
    """Closed E*TRADE REST and credential environments."""

    SANDBOX = "sandbox"
    PRODUCTION = "production"


class EtradeSecretScope(StrEnum):
    """Nonsecret scope identifiers; these values are never secret material."""

    SANDBOX_CONSUMER = "etrade-sandbox-oauth1-consumer-v1"
    SANDBOX_TOKEN = "etrade-sandbox-oauth1-token-v1"
    PRODUCTION_CONSUMER = "etrade-production-oauth1-consumer-v1"
    PRODUCTION_TOKEN = "etrade-production-oauth1-token-v1"


class EtradeOAuthCallbackMode(StrEnum):
    """The sole request-token callback shape admitted by this first slice."""

    OUT_OF_BAND = "out_of_band"


class EtradeRestSurface(StrEnum):
    """REST origins that remain independently pinned per environment."""

    DATA = "data"
    ORDER = "order"


class EtradeReadOnlyOperation(StrEnum):
    """The one read operation implemented by this first bounded slice."""

    ACCOUNTS_LIST = "accounts_list"


def _sha256(material: object) -> str:
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _require_exact_type(value: object, expected_type: type[object], field_name: str) -> None:
    if type(value) is not expected_type:
        raise EtradeRecordedOfflineContractError(
            f"{field_name} must use the exact E*TRADE provider-specific type"
        )


def _require_exact_enum_tuple(
    value: object,
    *,
    expected: tuple[object, ...],
    member_type: type[object],
    field_name: str,
) -> None:
    """Require one exact tuple of exact enum members in canonical order."""

    if type(value) is not tuple:
        raise EtradeRecordedOfflineContractError(f"E*TRADE capability {field_name} was altered")
    members = cast(tuple[object, ...], value)
    if len(members) != len(expected):
        raise EtradeRecordedOfflineContractError(f"E*TRADE capability {field_name} was altered")
    for member, expected_member in zip(members, expected, strict=True):
        if type(member) is not member_type or member is not expected_member:
            raise EtradeRecordedOfflineContractError(f"E*TRADE capability {field_name} was altered")


@dataclass(frozen=True, slots=True)
class EtradeProviderIdentity:
    """The exact provider identity; it is not a canonical broker fact."""

    value: str = ETRADE_PROVIDER_ID

    def __post_init__(self) -> None:
        if type(self.value) is not str or self.value != ETRADE_PROVIDER_ID:
            raise EtradeRecordedOfflineContractError(
                f"E*TRADE provider identity must be exactly {ETRADE_PROVIDER_ID!r}"
            )


ETRADE_PROVIDER = EtradeProviderIdentity()


@dataclass(frozen=True, slots=True)
class EtradeLocalAccountAlias:
    """A strict local alias; it never substitutes for provider identity."""

    value: str

    def __post_init__(self) -> None:
        if (
            type(self.value) is not str
            or _LOCAL_ACCOUNT_ALIAS_PATTERN.fullmatch(self.value) is None
        ):
            raise EtradeRecordedOfflineContractError(
                "E*TRADE local account alias must be a lowercase canonical slug"
            )


@dataclass(frozen=True, slots=True)
class EtradeNumericAccountId:
    """Exact provider numeric account ID text, without integer normalization."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.value) is not str or _NUMERIC_ACCOUNT_ID_PATTERN.fullmatch(self.value) is None:
            raise EtradeRecordedOfflineContractError(
                "E*TRADE numeric account ID must contain only 1-32 ASCII digits"
            )


@dataclass(frozen=True, slots=True)
class EtradeAccountIdKey:
    """Exact opaque provider ``accountIdKey`` with no identity inference."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.value) is not str or _ACCOUNT_ID_KEY_PATTERN.fullmatch(self.value) is None:
            raise EtradeRecordedOfflineContractError(
                "E*TRADE accountIdKey must be bounded canonical opaque text"
            )


@dataclass(frozen=True, slots=True)
class EtradeAccountIdentifiers:
    """Provider-specific account identifiers, not an authenticated binding."""

    provider: EtradeProviderIdentity
    environment: EtradeEnvironment
    local_alias: EtradeLocalAccountAlias
    numeric_account_id: EtradeNumericAccountId
    account_id_key: EtradeAccountIdKey

    def __post_init__(self) -> None:
        _require_exact_type(self.provider, EtradeProviderIdentity, "account provider")
        self.provider.__post_init__()
        _require_exact_type(self.environment, EtradeEnvironment, "account environment")
        _require_exact_type(self.local_alias, EtradeLocalAccountAlias, "local account alias")
        _require_exact_type(
            self.numeric_account_id,
            EtradeNumericAccountId,
            "numeric account ID",
        )
        _require_exact_type(self.account_id_key, EtradeAccountIdKey, "accountIdKey")
        self.local_alias.__post_init__()
        self.numeric_account_id.__post_init__()
        self.account_id_key.__post_init__()

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION,
                "account_identifiers",
                self.provider.value,
                self.environment,
                self.local_alias.value,
                self.numeric_account_id.value,
                self.account_id_key.value,
            )
        )

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({field_name: False for field_name in _AUTHORITY_FIELDS})

    @property
    def account_binding_authorized(self) -> bool:
        return False

    @property
    def canonical_fact_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class EtradeOAuthCallbackPolicy:
    """Exact request-token callback policy with no OAuth or redirect authority.

    E*TRADE's request-token parameter remains the literal ``oob`` even when a
    callback has been preconfigured with the provider.  This slice therefore
    accepts no caller-supplied callback URL, origin, path, or redirect target.
    """

    mode: EtradeOAuthCallbackMode = EtradeOAuthCallbackMode.OUT_OF_BAND
    oauth_callback_parameter: str = ETRADE_OAUTH_CALLBACK_PARAMETER
    registered_origin: str | None = None
    registered_path: str | None = None
    dynamic_callback_authorized: bool = False
    verifier_replay_authorized: bool = False

    def __post_init__(self) -> None:
        _require_exact_type(self.mode, EtradeOAuthCallbackMode, "OAuth callback mode")
        if type(self.oauth_callback_parameter) is not str or (
            self.oauth_callback_parameter != ETRADE_OAUTH_CALLBACK_PARAMETER
        ):
            raise EtradeRecordedOfflineContractError(
                "E*TRADE request-token oauth_callback must remain exactly 'oob'"
            )
        if self.registered_origin is not None or self.registered_path is not None:
            raise EtradeRecordedOfflineContractError(
                "recorded-offline callback policy cannot retain a dynamic origin or path"
            )
        for field_name in ("dynamic_callback_authorized", "verifier_replay_authorized"):
            if (
                type(getattr(self, field_name)) is not bool
                or getattr(self, field_name) is not False
            ):
                raise EtradeRecordedOfflineContractError(
                    f"E*TRADE callback authority {field_name} must remain false"
                )

    @classmethod
    def out_of_band(cls) -> EtradeOAuthCallbackPolicy:
        return cls()

    @property
    def registered_callback_url(self) -> str | None:
        return None

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION,
                "oauth_callback_policy",
                self.mode,
                self.oauth_callback_parameter,
                self.registered_origin,
                self.registered_path,
                self.dynamic_callback_authorized,
                self.verifier_replay_authorized,
            )
        )

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({field_name: False for field_name in _AUTHORITY_FIELDS})

    @property
    def authorization_redirect_authorized(self) -> bool:
        return False

    @property
    def oauth_session_acquisition_authorized(self) -> bool:
        return False


ETRADE_OUT_OF_BAND_CALLBACK_POLICY = EtradeOAuthCallbackPolicy.out_of_band()


@dataclass(frozen=True, slots=True)
class _EtradeEnvironmentPins:
    data_api_origin: str
    order_api_origin: str
    data_api_root: str
    order_api_root: str
    consumer_secret_scope: EtradeSecretScope
    token_secret_scope: EtradeSecretScope
    account_scope: str
    request_budget_scope: str
    persistence_scope: str
    audit_scope: str
    visual_banner: str


_ETRADE_ENVIRONMENT_PINS: Mapping[EtradeEnvironment, _EtradeEnvironmentPins] = MappingProxyType(
    {
        EtradeEnvironment.SANDBOX: _EtradeEnvironmentPins(
            data_api_origin=ETRADE_SANDBOX_DATA_API_ORIGIN,
            order_api_origin=ETRADE_SANDBOX_ORDER_API_ORIGIN,
            data_api_root=ETRADE_SANDBOX_DATA_API_ROOT,
            order_api_root=ETRADE_SANDBOX_ORDER_API_ROOT,
            consumer_secret_scope=EtradeSecretScope.SANDBOX_CONSUMER,
            token_secret_scope=EtradeSecretScope.SANDBOX_TOKEN,
            account_scope="etrade-sandbox-accounts-v1",
            request_budget_scope="etrade-sandbox-request-budget-v1",
            persistence_scope="etrade-sandbox-recorded-evidence-v1",
            audit_scope="etrade-sandbox-audit-v1",
            visual_banner="E*TRADE SANDBOX - PROTOCOL ONLY",
        ),
        EtradeEnvironment.PRODUCTION: _EtradeEnvironmentPins(
            data_api_origin=ETRADE_PRODUCTION_DATA_API_ORIGIN,
            order_api_origin=ETRADE_PRODUCTION_ORDER_API_ORIGIN,
            data_api_root=ETRADE_PRODUCTION_DATA_API_ROOT,
            order_api_root=ETRADE_PRODUCTION_ORDER_API_ROOT,
            consumer_secret_scope=EtradeSecretScope.PRODUCTION_CONSUMER,
            token_secret_scope=EtradeSecretScope.PRODUCTION_TOKEN,
            account_scope="etrade-production-accounts-v1",
            request_budget_scope="etrade-production-request-budget-v1",
            persistence_scope="etrade-production-recorded-evidence-v1",
            audit_scope="etrade-production-audit-v1",
            visual_banner="E*TRADE PRODUCTION - LIVE DISABLED",
        ),
    }
)


@dataclass(frozen=True, slots=True)
class EtradeEndpointIsolationProfile:
    """Exact environment pins; arbitrary roots and cross-scope mixing fail closed."""

    environment: EtradeEnvironment
    data_api_origin: str
    order_api_origin: str
    data_api_root: str
    order_api_root: str
    consumer_secret_scope: EtradeSecretScope
    token_secret_scope: EtradeSecretScope
    account_scope: str
    request_budget_scope: str
    persistence_scope: str
    audit_scope: str
    visual_banner: str
    callback_policy: EtradeOAuthCallbackPolicy
    token_origin: str = ETRADE_SHARED_TOKEN_ORIGIN
    token_root: str = ETRADE_SHARED_TOKEN_ROOT
    request_token_url: str = ETRADE_SHARED_REQUEST_TOKEN_URL
    access_token_url: str = ETRADE_SHARED_ACCESS_TOKEN_URL
    renew_access_token_url: str = ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL
    revoke_access_token_url: str = ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL
    authorization_origin: str = ETRADE_SHARED_AUTHORIZATION_ORIGIN
    authorization_path: str = ETRADE_SHARED_AUTHORIZATION_PATH
    authorization_page: str = ETRADE_SHARED_AUTHORIZATION_PAGE

    def __post_init__(self) -> None:
        _require_exact_type(self.environment, EtradeEnvironment, "endpoint environment")
        _require_exact_type(
            self.consumer_secret_scope,
            EtradeSecretScope,
            "consumer secret scope",
        )
        _require_exact_type(
            self.token_secret_scope,
            EtradeSecretScope,
            "token secret scope",
        )
        _require_exact_type(
            self.callback_policy,
            EtradeOAuthCallbackPolicy,
            "OAuth callback policy",
        )
        self.callback_policy.__post_init__()
        expected = _ETRADE_ENVIRONMENT_PINS[self.environment]
        for field_name in (
            "data_api_origin",
            "order_api_origin",
            "data_api_root",
            "order_api_root",
            "consumer_secret_scope",
            "token_secret_scope",
            "account_scope",
            "request_budget_scope",
            "persistence_scope",
            "audit_scope",
            "visual_banner",
        ):
            actual = getattr(self, field_name)
            expected_value = getattr(expected, field_name)
            if type(actual) is not type(expected_value) or actual != expected_value:
                raise EtradeRecordedOfflineContractError(
                    f"E*TRADE {field_name} does not match the typed environment"
                )
        shared_values = (
            ("token_origin", self.token_origin, ETRADE_SHARED_TOKEN_ORIGIN),
            ("token_root", self.token_root, ETRADE_SHARED_TOKEN_ROOT),
            (
                "request_token_url",
                self.request_token_url,
                ETRADE_SHARED_REQUEST_TOKEN_URL,
            ),
            ("access_token_url", self.access_token_url, ETRADE_SHARED_ACCESS_TOKEN_URL),
            (
                "renew_access_token_url",
                self.renew_access_token_url,
                ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
            ),
            (
                "revoke_access_token_url",
                self.revoke_access_token_url,
                ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
            ),
            (
                "authorization_origin",
                self.authorization_origin,
                ETRADE_SHARED_AUTHORIZATION_ORIGIN,
            ),
            (
                "authorization_path",
                self.authorization_path,
                ETRADE_SHARED_AUTHORIZATION_PATH,
            ),
            (
                "authorization_page",
                self.authorization_page,
                ETRADE_SHARED_AUTHORIZATION_PAGE,
            ),
        )
        for field_name, actual, expected_value in shared_values:
            if type(actual) is not str or actual != expected_value:
                raise EtradeRecordedOfflineContractError(f"E*TRADE shared {field_name} was altered")

    @property
    def profile_id(self) -> str:
        return f"etrade-{self.environment.value}-endpoint-isolation-v1"

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION,
                "endpoint_isolation_profile",
                ETRADE_PROVIDER_ID,
                self.profile_id,
                self.environment,
                self.data_api_origin,
                self.order_api_origin,
                self.data_api_root,
                self.order_api_root,
                self.consumer_secret_scope,
                self.token_secret_scope,
                self.account_scope,
                self.request_budget_scope,
                self.persistence_scope,
                self.audit_scope,
                self.visual_banner,
                self.token_origin,
                self.token_root,
                self.request_token_url,
                self.access_token_url,
                self.renew_access_token_url,
                self.revoke_access_token_url,
                self.authorization_origin,
                self.authorization_path,
                self.authorization_page,
                self.callback_policy.semantic_sha256,
            )
        )

    def require_rest_root(self, *, surface: EtradeRestSurface, root: object) -> str:
        """Return an exact matching root or reject substitution without echoing it."""

        _require_exact_type(surface, EtradeRestSurface, "REST surface")
        expected = self.data_api_root if surface is EtradeRestSurface.DATA else self.order_api_root
        if type(root) is not str or root != expected:
            raise EtradeRecordedOfflineContractError(
                "E*TRADE REST root does not match the typed environment and surface"
            )
        return root

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({field_name: False for field_name in _AUTHORITY_FIELDS})


def create_etrade_endpoint_isolation_profile(
    *,
    environment: EtradeEnvironment,
    callback_policy: EtradeOAuthCallbackPolicy,
) -> EtradeEndpointIsolationProfile:
    """Create a complete profile from closed typed environment pins only."""

    _require_exact_type(environment, EtradeEnvironment, "endpoint environment")
    _require_exact_type(callback_policy, EtradeOAuthCallbackPolicy, "OAuth callback policy")
    pins = _ETRADE_ENVIRONMENT_PINS[environment]
    return EtradeEndpointIsolationProfile(
        environment=environment,
        data_api_origin=pins.data_api_origin,
        order_api_origin=pins.order_api_origin,
        data_api_root=pins.data_api_root,
        order_api_root=pins.order_api_root,
        consumer_secret_scope=pins.consumer_secret_scope,
        token_secret_scope=pins.token_secret_scope,
        account_scope=pins.account_scope,
        request_budget_scope=pins.request_budget_scope,
        persistence_scope=pins.persistence_scope,
        audit_scope=pins.audit_scope,
        visual_banner=pins.visual_banner,
        callback_policy=callback_policy,
    )


ETRADE_SANDBOX_ENDPOINT_PROFILE = create_etrade_endpoint_isolation_profile(
    environment=EtradeEnvironment.SANDBOX,
    callback_policy=ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
)
ETRADE_PRODUCTION_ENDPOINT_PROFILE = create_etrade_endpoint_isolation_profile(
    environment=EtradeEnvironment.PRODUCTION,
    callback_policy=ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
)


@dataclass(frozen=True, slots=True)
class EtradeRecordedOfflineCapabilityMatrix:
    """Exact implemented breadth and an exhaustive set of closed authorities."""

    contract_version: str = ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION
    reviewed_on: str = ETRADE_RECORDED_OFFLINE_REVIEWED_ON
    provider: EtradeProviderIdentity = ETRADE_PROVIDER
    environments: tuple[EtradeEnvironment, ...] = tuple(EtradeEnvironment)
    read_only_operations: tuple[EtradeReadOnlyOperation, ...] = (
        EtradeReadOnlyOperation.ACCOUNTS_LIST,
    )
    callback_modes: tuple[EtradeOAuthCallbackMode, ...] = tuple(EtradeOAuthCallbackMode)
    sandbox_evidence_scope: str = ETRADE_SANDBOX_EVIDENCE_SCOPE
    offline_contract_only: bool = True
    sandbox_protocol_only: bool = True
    credential_resolution_authorized: bool = False
    oauth_session_acquisition_authorized: bool = False
    oauth_token_renewal_authorized: bool = False
    oauth_token_revocation_authorized: bool = False
    authorization_redirect_authorized: bool = False
    callback_handling_authorized: bool = False
    provider_network_authorized: bool = False
    read_only_transport_authorized: bool = False
    request_budget_issuance_authorized: bool = False
    raw_response_persistence_authorized: bool = False
    account_discovery_authorized: bool = False
    account_binding_authorized: bool = False
    lifecycle_evidence_authorized: bool = False
    reconciliation_evidence_authorized: bool = False
    timing_evidence_authorized: bool = False
    economic_evidence_authorized: bool = False
    paper_soak_evidence_authorized: bool = False
    preview_authorized: bool = False
    place_authorized: bool = False
    cancel_authorized: bool = False
    submission_authorized: bool = False
    broker_mutation_authorized: bool = False
    reconciliation_application_authorized: bool = False
    canonical_fact_application_authorized: bool = False
    paper_startup_authorized: bool = False
    live_startup_authorized: bool = False
    trading_effect_authorized: bool = False
    sandbox_traversal_semantics_qualified: bool = False
    sandbox_completeness_qualified: bool = False
    sandbox_lifecycle_qualified: bool = False
    sandbox_reconciliation_qualified: bool = False
    sandbox_timing_qualified: bool = False
    sandbox_economic_qualified: bool = False
    sandbox_paper_soak_qualified: bool = False
    sandbox_live_readiness_qualified: bool = False

    def __post_init__(self) -> None:
        expected_values: tuple[tuple[str, object], ...] = (
            ("contract_version", ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION),
            ("reviewed_on", ETRADE_RECORDED_OFFLINE_REVIEWED_ON),
            ("sandbox_evidence_scope", ETRADE_SANDBOX_EVIDENCE_SCOPE),
            ("offline_contract_only", True),
            ("sandbox_protocol_only", True),
        )
        _require_exact_type(self.provider, EtradeProviderIdentity, "capability provider")
        self.provider.__post_init__()
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise EtradeRecordedOfflineContractError(
                    f"E*TRADE capability {field_name} was altered"
                )
        _require_exact_enum_tuple(
            self.environments,
            expected=tuple(EtradeEnvironment),
            member_type=EtradeEnvironment,
            field_name="environments",
        )
        _require_exact_enum_tuple(
            self.read_only_operations,
            expected=(EtradeReadOnlyOperation.ACCOUNTS_LIST,),
            member_type=EtradeReadOnlyOperation,
            field_name="read_only_operations",
        )
        _require_exact_enum_tuple(
            self.callback_modes,
            expected=tuple(EtradeOAuthCallbackMode),
            member_type=EtradeOAuthCallbackMode,
            field_name="callback_modes",
        )
        for field_name in _AUTHORITY_FIELDS:
            if (
                type(getattr(self, field_name)) is not bool
                or getattr(self, field_name) is not False
            ):
                raise EtradeRecordedOfflineContractError(
                    f"E*TRADE authority {field_name} must remain false"
                )
        for field_name in _SANDBOX_QUALIFICATION_FIELDS:
            if (
                type(getattr(self, field_name)) is not bool
                or getattr(self, field_name) is not False
            ):
                raise EtradeRecordedOfflineContractError(
                    f"E*TRADE sandbox qualification {field_name} must remain false"
                )

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType(
            {field_name: cast(bool, getattr(self, field_name)) for field_name in _AUTHORITY_FIELDS}
        )

    @property
    def sandbox_qualification(self) -> Mapping[str, bool]:
        return MappingProxyType(
            {
                field_name: cast(bool, getattr(self, field_name))
                for field_name in _SANDBOX_QUALIFICATION_FIELDS
            }
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                self.contract_version,
                "capability_matrix",
                self.reviewed_on,
                self.provider.value,
                self.environments,
                self.read_only_operations,
                self.callback_modes,
                self.sandbox_evidence_scope,
                self.offline_contract_only,
                self.sandbox_protocol_only,
                tuple(self.authority.items()),
                tuple(self.sandbox_qualification.items()),
            )
        )


ETRADE_RECORDED_OFFLINE_CAPABILITIES = EtradeRecordedOfflineCapabilityMatrix()


def _accounts_list_request_profile_sha256() -> str:
    return _sha256(
        (
            ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION,
            ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_ID,
            ETRADE_PROVIDER_ID,
            EtradeReadOnlyOperation.ACCOUNTS_LIST,
            "GET",
            ETRADE_ACCOUNTS_LIST_PATH,
            (ETRADE_JSON_ACCEPT_HEADER,),
            (),
            None,
        )
    )


ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256 = _accounts_list_request_profile_sha256()


@dataclass(frozen=True, slots=True)
class EtradeAccountsListRequestDescription:
    """Deterministic Accounts List evidence with no headers carrying secrets."""

    environment: EtradeEnvironment
    endpoint_profile: EtradeEndpointIsolationProfile
    operation: EtradeReadOnlyOperation
    capability_sha256: str
    request_profile_sha256: str

    def __post_init__(self) -> None:
        _require_exact_type(self.environment, EtradeEnvironment, "request environment")
        _require_exact_type(
            self.endpoint_profile,
            EtradeEndpointIsolationProfile,
            "request endpoint profile",
        )
        self.endpoint_profile.__post_init__()
        if self.endpoint_profile.environment is not self.environment:
            raise EtradeRecordedOfflineContractError(
                "E*TRADE request environment conflicts with its endpoint profile"
            )
        _require_exact_type(self.operation, EtradeReadOnlyOperation, "read-only operation")
        if self.operation is not EtradeReadOnlyOperation.ACCOUNTS_LIST:
            raise EtradeRecordedOfflineContractError(
                "unsupported E*TRADE recorded-offline read-only operation"
            )
        if (
            type(self.capability_sha256) is not str
            or self.capability_sha256 != ETRADE_RECORDED_OFFLINE_CAPABILITIES.semantic_sha256
        ):
            raise EtradeRecordedOfflineContractError(
                "E*TRADE request capability identity was altered"
            )
        if (
            type(self.request_profile_sha256) is not str
            or self.request_profile_sha256 != ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256
        ):
            raise EtradeRecordedOfflineContractError(
                "E*TRADE Accounts List request profile identity was altered"
            )

    @property
    def contract_version(self) -> str:
        return ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION

    @property
    def adapter_id(self) -> str:
        return ETRADE_RECORDED_OFFLINE_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return ETRADE_RECORDED_OFFLINE_ADAPTER_VERSION

    @property
    def provider(self) -> EtradeProviderIdentity:
        return ETRADE_PROVIDER

    @property
    def request_profile_id(self) -> str:
        return ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_ID

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return self.endpoint_profile.data_api_root

    @property
    def path(self) -> str:
        return ETRADE_ACCOUNTS_LIST_PATH

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"

    @property
    def headers(self) -> Mapping[str, str]:
        return MappingProxyType(dict((ETRADE_JSON_ACCEPT_HEADER,)))

    @property
    def query(self) -> Mapping[str, str]:
        return MappingProxyType({})

    @property
    def body(self) -> None:
        return None

    @property
    def request_target(self) -> str:
        return self.path

    def to_record_bytes(self) -> bytes:
        """Return a deterministic, explicitly nonsecret request record."""

        return json.dumps(
            {
                "adapter_id": self.adapter_id,
                "adapter_version": self.adapter_version,
                "base_url": self.base_url,
                "body": self.body,
                "capability_sha256": self.capability_sha256,
                "contract_version": self.contract_version,
                "endpoint_profile_sha256": self.endpoint_profile.semantic_sha256,
                "environment": self.environment.value,
                "headers": dict(self.headers),
                "method": self.method,
                "operation": self.operation.value,
                "path": self.path,
                "provider_id": self.provider.value,
                "query": dict(self.query),
                "request_profile_id": self.request_profile_id,
                "request_profile_sha256": self.request_profile_sha256,
                "request_target": self.request_target,
                "consumer_secret_scope_id": (self.endpoint_profile.consumer_secret_scope.value),
                "token_secret_scope_id": self.endpoint_profile.token_secret_scope.value,
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                self.contract_version,
                "accounts_list_request_description",
                self.adapter_id,
                self.adapter_version,
                self.provider.value,
                self.environment,
                self.endpoint_profile.semantic_sha256,
                self.operation,
                self.capability_sha256,
                self.request_profile_id,
                self.request_profile_sha256,
                self.method,
                self.base_url,
                self.path,
                tuple(self.headers.items()),
                tuple(self.query.items()),
                self.body,
            )
        )

    @property
    def authority(self) -> Mapping[str, bool]:
        return ETRADE_RECORDED_OFFLINE_CAPABILITIES.authority

    @property
    def credential_resolution_authorized(self) -> bool:
        return False

    @property
    def oauth_session_acquisition_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def runtime_request_ready(self) -> bool:
        return False

    @property
    def account_binding_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def create_etrade_read_only_request_description(
    *,
    operation: EtradeReadOnlyOperation,
    environment: EtradeEnvironment,
    endpoint_profile: EtradeEndpointIsolationProfile,
) -> EtradeAccountsListRequestDescription:
    """Describe one supported read request; all other operations fail closed."""

    _require_exact_type(operation, EtradeReadOnlyOperation, "read-only operation")
    if operation is not EtradeReadOnlyOperation.ACCOUNTS_LIST:
        raise EtradeRecordedOfflineContractError(
            "unsupported E*TRADE recorded-offline read-only operation"
        )
    return EtradeAccountsListRequestDescription(
        environment=environment,
        endpoint_profile=endpoint_profile,
        operation=operation,
        capability_sha256=ETRADE_RECORDED_OFFLINE_CAPABILITIES.semantic_sha256,
        request_profile_sha256=ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256,
    )


def create_etrade_accounts_list_request_description(
    *,
    environment: EtradeEnvironment,
    endpoint_profile: EtradeEndpointIsolationProfile,
) -> EtradeAccountsListRequestDescription:
    """Describe the exact first read-only surface without performing I/O."""

    return create_etrade_read_only_request_description(
        operation=EtradeReadOnlyOperation.ACCOUNTS_LIST,
        environment=environment,
        endpoint_profile=endpoint_profile,
    )


__all__ = [
    "ETRADE_ACCOUNTS_LIST_PATH",
    "ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_ID",
    "ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256",
    "ETRADE_OUT_OF_BAND_CALLBACK_POLICY",
    "ETRADE_PRODUCTION_DATA_API_ORIGIN",
    "ETRADE_PRODUCTION_DATA_API_ROOT",
    "ETRADE_PRODUCTION_ENDPOINT_PROFILE",
    "ETRADE_PRODUCTION_ORDER_API_ORIGIN",
    "ETRADE_PRODUCTION_ORDER_API_ROOT",
    "ETRADE_PROVIDER",
    "ETRADE_PROVIDER_ID",
    "ETRADE_RECORDED_OFFLINE_ADAPTER_ID",
    "ETRADE_RECORDED_OFFLINE_ADAPTER_VERSION",
    "ETRADE_RECORDED_OFFLINE_CAPABILITIES",
    "ETRADE_RECORDED_OFFLINE_CONTRACT_VERSION",
    "ETRADE_RECORDED_OFFLINE_REVIEWED_ON",
    "ETRADE_SANDBOX_DATA_API_ORIGIN",
    "ETRADE_SANDBOX_DATA_API_ROOT",
    "ETRADE_SANDBOX_ENDPOINT_PROFILE",
    "ETRADE_SANDBOX_EVIDENCE_SCOPE",
    "ETRADE_SANDBOX_ORDER_API_ORIGIN",
    "ETRADE_SANDBOX_ORDER_API_ROOT",
    "ETRADE_SHARED_ACCESS_TOKEN_URL",
    "ETRADE_SHARED_AUTHORIZATION_ORIGIN",
    "ETRADE_SHARED_AUTHORIZATION_PAGE",
    "ETRADE_SHARED_AUTHORIZATION_PATH",
    "ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL",
    "ETRADE_SHARED_REQUEST_TOKEN_URL",
    "ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL",
    "ETRADE_SHARED_TOKEN_ORIGIN",
    "ETRADE_SHARED_TOKEN_ROOT",
    "EtradeAccountIdKey",
    "EtradeAccountIdentifiers",
    "EtradeAccountsListRequestDescription",
    "EtradeEndpointIsolationProfile",
    "EtradeEnvironment",
    "EtradeLocalAccountAlias",
    "EtradeNumericAccountId",
    "EtradeOAuthCallbackMode",
    "EtradeOAuthCallbackPolicy",
    "EtradeProviderIdentity",
    "EtradeReadOnlyOperation",
    "EtradeRecordedOfflineCapabilityMatrix",
    "EtradeRecordedOfflineContractError",
    "EtradeRestSurface",
    "EtradeSecretScope",
    "create_etrade_accounts_list_request_description",
    "create_etrade_endpoint_isolation_profile",
    "create_etrade_read_only_request_description",
]
