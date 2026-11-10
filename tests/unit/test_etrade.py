from __future__ import annotations

import json
import tomllib
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import packages.adapters.broker as broker_exports
import packages.adapters.broker.etrade as etrade_module
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaPaperAccountObservationDescription,
)
from packages.adapters.broker.etrade import (
    ETRADE_ACCOUNTS_LIST_PATH,
    ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256,
    ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
    ETRADE_PRODUCTION_DATA_API_ROOT,
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_PRODUCTION_ORDER_API_ROOT,
    ETRADE_PROVIDER,
    ETRADE_RECORDED_OFFLINE_CAPABILITIES,
    ETRADE_SANDBOX_DATA_API_ROOT,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    ETRADE_SANDBOX_ORDER_API_ROOT,
    ETRADE_SHARED_ACCESS_TOKEN_URL,
    ETRADE_SHARED_AUTHORIZATION_PAGE,
    ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
    ETRADE_SHARED_REQUEST_TOKEN_URL,
    ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
    ETRADE_SHARED_TOKEN_ROOT,
    EtradeAccountIdentifiers,
    EtradeAccountIdKey,
    EtradeAccountsListRequestDescription,
    EtradeEnvironment,
    EtradeLocalAccountAlias,
    EtradeNumericAccountId,
    EtradeOAuthCallbackMode,
    EtradeProviderIdentity,
    EtradeReadOnlyOperation,
    EtradeRecordedOfflineCapabilityMatrix,
    EtradeRecordedOfflineContractError,
    EtradeRestSurface,
    EtradeSecretScope,
    create_etrade_accounts_list_request_description,
    create_etrade_endpoint_isolation_profile,
    create_etrade_read_only_request_description,
)

CAPABILITY_SHA256 = "3430e39afc6c694b891691848eba6f74babdf2853c568b203d2116b0de9743e2"
SANDBOX_PROFILE_SHA256 = "40422cb69206fb972063d91f0eaf8ac3d5e50e360ce7ecfa4af8439e65352f3a"
PRODUCTION_PROFILE_SHA256 = "052b4a1fac5fe07c8332c6d8586a2a414eeb62506e29effbf9123016451c3950"
REQUEST_PROFILE_SHA256 = "97e93a931078a86b0931291f26535a5f840732963a75b7bda0dfa86d439ecd38"
SANDBOX_REQUEST_SHA256 = "f69d09c250a2b7dcbb8544e79f7a4c07bbd14c61c755230d1387e13a48f56581"
PRODUCTION_REQUEST_SHA256 = "2347f0294b6426e4c8da51c67432a9c048de613b7ebe6dfa8cd13a1ebcf16497"


def _description(
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
) -> EtradeAccountsListRequestDescription:
    profile = (
        ETRADE_SANDBOX_ENDPOINT_PROFILE
        if environment is EtradeEnvironment.SANDBOX
        else ETRADE_PRODUCTION_ENDPOINT_PROFILE
    )
    return create_etrade_accounts_list_request_description(
        environment=environment,
        endpoint_profile=profile,
    )


def _account_identifiers() -> EtradeAccountIdentifiers:
    return EtradeAccountIdentifiers(
        provider=ETRADE_PROVIDER,
        environment=EtradeEnvironment.PRODUCTION,
        local_alias=EtradeLocalAccountAlias("primary"),
        numeric_account_id=EtradeNumericAccountId("00123456"),
        account_id_key=EtradeAccountIdKey("AbCdEf0123_-"),
    )


def test_endpoint_profiles_pin_disjoint_rest_and_secret_scopes() -> None:
    sandbox = ETRADE_SANDBOX_ENDPOINT_PROFILE
    production = ETRADE_PRODUCTION_ENDPOINT_PROFILE

    assert sandbox.environment is EtradeEnvironment.SANDBOX
    assert sandbox.data_api_root == "https://apisb.etrade.com/v1"
    assert sandbox.order_api_root == "https://apisb.etrade.com/v1"
    assert sandbox.consumer_secret_scope is EtradeSecretScope.SANDBOX_CONSUMER
    assert sandbox.token_secret_scope is EtradeSecretScope.SANDBOX_TOKEN
    assert production.environment is EtradeEnvironment.PRODUCTION
    assert production.data_api_root == "https://api.etrade.com/v1"
    assert production.order_api_root == "https://api.etrade.com/v1"
    assert production.consumer_secret_scope is EtradeSecretScope.PRODUCTION_CONSUMER
    assert production.token_secret_scope is EtradeSecretScope.PRODUCTION_TOKEN
    assert sandbox.data_api_root != production.data_api_root
    assert sandbox.order_api_root != production.order_api_root
    assert sandbox.consumer_secret_scope is not production.consumer_secret_scope
    assert sandbox.token_secret_scope is not production.token_secret_scope
    assert sandbox.account_scope != production.account_scope
    assert sandbox.request_budget_scope != production.request_budget_scope
    assert sandbox.persistence_scope != production.persistence_scope
    assert sandbox.audit_scope != production.audit_scope
    assert sandbox.visual_banner != production.visual_banner
    assert sandbox.semantic_sha256 != production.semantic_sha256
    assert sandbox.semantic_sha256 == SANDBOX_PROFILE_SHA256
    assert production.semantic_sha256 == PRODUCTION_PROFILE_SHA256


def test_shared_oauth_service_and_exact_oob_callback_are_environment_invariant() -> None:
    for profile in (ETRADE_SANDBOX_ENDPOINT_PROFILE, ETRADE_PRODUCTION_ENDPOINT_PROFILE):
        assert profile.token_root == "https://api.etrade.com/oauth/"
        assert profile.request_token_url == "https://api.etrade.com/oauth/request_token"
        assert profile.access_token_url == "https://api.etrade.com/oauth/access_token"
        assert profile.renew_access_token_url == ("https://api.etrade.com/oauth/renew_access_token")
        assert profile.revoke_access_token_url == (
            "https://api.etrade.com/oauth/revoke_access_token"
        )
        assert profile.authorization_page == "https://us.etrade.com/e/t/etws/authorize"
        assert profile.callback_policy == ETRADE_OUT_OF_BAND_CALLBACK_POLICY
        assert profile.callback_policy.mode is EtradeOAuthCallbackMode.OUT_OF_BAND
        assert profile.callback_policy.oauth_callback_parameter == "oob"
        assert profile.callback_policy.registered_origin is None
        assert profile.callback_policy.registered_path is None
        assert profile.callback_policy.registered_callback_url is None

    assert ETRADE_SHARED_TOKEN_ROOT.endswith("/oauth/")
    assert ETRADE_SHARED_REQUEST_TOKEN_URL.startswith(ETRADE_SHARED_TOKEN_ROOT)
    assert ETRADE_SHARED_ACCESS_TOKEN_URL.startswith(ETRADE_SHARED_TOKEN_ROOT)
    assert ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL.startswith(ETRADE_SHARED_TOKEN_ROOT)
    assert ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL.startswith(ETRADE_SHARED_TOKEN_ROOT)
    assert ETRADE_SHARED_AUTHORIZATION_PAGE == ("https://us.etrade.com/e/t/etws/authorize")


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"oauth_callback_parameter": "https://callback.invalid"}, "exactly 'oob'"),
        ({"registered_origin": "https://callback.example"}, "dynamic origin or path"),
        ({"registered_path": "/oauth/callback"}, "dynamic origin or path"),
        ({"dynamic_callback_authorized": True}, "must remain false"),
        ({"verifier_replay_authorized": True}, "must remain false"),
    ),
)
def test_callback_policy_rejects_dynamic_callback_and_replay(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match=message):
        replace(ETRADE_OUT_OF_BAND_CALLBACK_POLICY, **changes)


@pytest.mark.parametrize(
    "changes",
    (
        {"environment": EtradeEnvironment.PRODUCTION},
        {"data_api_origin": "https://api.etrade.com"},
        {"order_api_origin": "https://api.etrade.com"},
        {"data_api_root": ETRADE_PRODUCTION_DATA_API_ROOT},
        {"order_api_root": ETRADE_PRODUCTION_ORDER_API_ROOT},
        {"consumer_secret_scope": EtradeSecretScope.PRODUCTION_CONSUMER},
        {"token_secret_scope": EtradeSecretScope.PRODUCTION_TOKEN},
        {"account_scope": ETRADE_PRODUCTION_ENDPOINT_PROFILE.account_scope},
        {"request_budget_scope": ETRADE_PRODUCTION_ENDPOINT_PROFILE.request_budget_scope},
        {"persistence_scope": ETRADE_PRODUCTION_ENDPOINT_PROFILE.persistence_scope},
        {"audit_scope": ETRADE_PRODUCTION_ENDPOINT_PROFILE.audit_scope},
        {"token_root": "https://apisb.etrade.com/oauth/"},
        {"request_token_url": "https://apisb.etrade.com/oauth/request_token"},
        {"authorization_page": "https://us.etrade.com/e/t/etws/authorize/"},
    ),
)
def test_sandbox_profile_rejects_cross_environment_and_shared_origin_drift(
    changes: dict[str, object],
) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError):
        replace(ETRADE_SANDBOX_ENDPOINT_PROFILE, **changes)


@pytest.mark.parametrize(
    "changes",
    (
        {"environment": EtradeEnvironment.SANDBOX},
        {"data_api_root": ETRADE_SANDBOX_DATA_API_ROOT},
        {"order_api_root": ETRADE_SANDBOX_ORDER_API_ROOT},
        {"consumer_secret_scope": EtradeSecretScope.SANDBOX_CONSUMER},
        {"token_secret_scope": EtradeSecretScope.SANDBOX_TOKEN},
    ),
)
def test_production_profile_rejects_sandbox_substitution(
    changes: dict[str, object],
) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError):
        replace(ETRADE_PRODUCTION_ENDPOINT_PROFILE, **changes)


def test_endpoint_profile_factory_requires_exact_typed_inputs() -> None:
    assert (
        create_etrade_endpoint_isolation_profile(
            environment=EtradeEnvironment.SANDBOX,
            callback_policy=ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
        )
        == ETRADE_SANDBOX_ENDPOINT_PROFILE
    )
    with pytest.raises(EtradeRecordedOfflineContractError, match="exact E\\*TRADE"):
        create_etrade_endpoint_isolation_profile(
            environment="sandbox",  # type: ignore[arg-type]
            callback_policy=ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
        )
    with pytest.raises(EtradeRecordedOfflineContractError, match="exact E\\*TRADE"):
        create_etrade_endpoint_isolation_profile(
            environment=EtradeEnvironment.SANDBOX,
            callback_policy=object(),  # type: ignore[arg-type]
        )


def test_rest_root_provenance_is_exact_and_does_not_echo_substitution() -> None:
    sandbox = ETRADE_SANDBOX_ENDPOINT_PROFILE
    assert (
        sandbox.require_rest_root(
            surface=EtradeRestSurface.DATA,
            root=ETRADE_SANDBOX_DATA_API_ROOT,
        )
        == ETRADE_SANDBOX_DATA_API_ROOT
    )
    assert (
        sandbox.require_rest_root(
            surface=EtradeRestSurface.ORDER,
            root=ETRADE_SANDBOX_ORDER_API_ROOT,
        )
        == ETRADE_SANDBOX_ORDER_API_ROOT
    )

    secret_bearing_substitution = "https://api.etrade.com/v1?token=do-not-log"
    with pytest.raises(EtradeRecordedOfflineContractError) as caught:
        sandbox.require_rest_root(
            surface=EtradeRestSurface.DATA,
            root=secret_bearing_substitution,
        )
    assert secret_bearing_substitution not in str(caught.value)


def test_account_identifiers_are_provider_specific_exact_and_non_authorizing() -> None:
    identifiers = _account_identifiers()

    assert type(identifiers) is EtradeAccountIdentifiers
    assert type(identifiers.provider) is EtradeProviderIdentity
    assert type(identifiers.local_alias) is EtradeLocalAccountAlias
    assert type(identifiers.numeric_account_id) is EtradeNumericAccountId
    assert type(identifiers.account_id_key) is EtradeAccountIdKey
    assert identifiers.provider.value == "etrade"
    assert identifiers.numeric_account_id.value == "00123456"
    assert identifiers.account_id_key.value == "AbCdEf0123_-"
    assert len(identifiers.semantic_sha256) == 64
    assert "00123456" not in repr(identifiers)
    assert "AbCdEf0123_-" not in repr(identifiers)
    assert identifiers.account_binding_authorized is False
    assert identifiers.canonical_fact_authorized is False
    assert identifiers.trading_effect_authorized is False

    with pytest.raises(EtradeRecordedOfflineContractError, match="account environment"):
        replace(identifiers, environment="production")  # type: ignore[arg-type]
    with pytest.raises(EtradeRecordedOfflineContractError, match="numeric account ID"):
        replace(identifiers, numeric_account_id="00123456")  # type: ignore[arg-type]
    with pytest.raises(EtradeRecordedOfflineContractError, match="accountIdKey"):
        replace(identifiers, account_id_key="AbCdEf0123_-")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (None, True, 1234, "", " 1234", "1234 ", "+1234", "12.34", "1" * 33),
)
def test_numeric_account_id_rejects_malformed_values(value: object) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match="numeric account ID"):
        EtradeNumericAccountId(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (
        None,
        True,
        1234,
        "",
        " key",
        "key ",
        "key/value",
        "key?x",
        "key#x",
        "key%2Fx",
        "é",
        "a" * 129,
    ),
)
def test_account_id_key_rejects_malformed_or_path_active_values(value: object) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match="accountIdKey"):
        EtradeAccountIdKey(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (None, True, "", "Primary", "primary account", "-primary", "a" * 65),
)
def test_local_alias_rejects_malformed_values(value: object) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match="local account alias"):
        EtradeLocalAccountAlias(value)  # type: ignore[arg-type]


def test_accounts_list_request_is_exact_deterministic_and_environment_bound() -> None:
    first = _description()
    second = _description()
    production = _description(EtradeEnvironment.PRODUCTION)

    assert first == second
    assert first.semantic_sha256 == second.semantic_sha256
    assert first.semantic_sha256 != production.semantic_sha256
    assert first.endpoint_profile.semantic_sha256 != production.endpoint_profile.semantic_sha256
    assert len(first.semantic_sha256) == 64
    assert len(first.request_profile_sha256) == 64
    assert first.request_profile_sha256 == ETRADE_ACCOUNTS_LIST_REQUEST_PROFILE_SHA256
    assert ETRADE_RECORDED_OFFLINE_CAPABILITIES.semantic_sha256 == CAPABILITY_SHA256
    assert first.request_profile_sha256 == REQUEST_PROFILE_SHA256
    assert first.semantic_sha256 == SANDBOX_REQUEST_SHA256
    assert production.semantic_sha256 == PRODUCTION_REQUEST_SHA256
    assert first.provider.value == "etrade"
    assert first.operation is EtradeReadOnlyOperation.ACCOUNTS_LIST
    assert first.method == "GET"
    assert first.base_url == "https://apisb.etrade.com/v1"
    assert first.path == "/accounts/list"
    assert first.path == ETRADE_ACCOUNTS_LIST_PATH
    assert first.url == "https://apisb.etrade.com/v1/accounts/list"
    assert first.request_target == "/accounts/list"
    assert first.headers == {"Accept": "application/json"}
    assert first.query == {}
    assert first.body is None
    record_bytes = first.to_record_bytes()
    record = json.loads(record_bytes)
    assert record["body"] is None
    assert record["request_target"] == "/accounts/list"
    assert b".json" not in record_bytes
    assert b"Authorization" not in record_bytes

    with pytest.raises(TypeError):
        first.headers["Authorization"] = "secret"  # type: ignore[index]
    with pytest.raises(TypeError):
        first.query["token"] = "secret"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        first.environment = EtradeEnvironment.PRODUCTION  # type: ignore[misc]


def test_request_rejects_cross_environment_substitution_and_identity_drift() -> None:
    sandbox = _description()

    with pytest.raises(EtradeRecordedOfflineContractError, match="environment conflicts"):
        replace(sandbox, endpoint_profile=ETRADE_PRODUCTION_ENDPOINT_PROFILE)
    with pytest.raises(EtradeRecordedOfflineContractError, match="environment conflicts"):
        replace(sandbox, environment=EtradeEnvironment.PRODUCTION)
    with pytest.raises(EtradeRecordedOfflineContractError, match="capability identity"):
        replace(sandbox, capability_sha256="0" * 64)
    with pytest.raises(EtradeRecordedOfflineContractError, match="profile identity"):
        replace(sandbox, request_profile_sha256="0" * 64)


@pytest.mark.parametrize(
    "operation",
    (
        "accounts_list",
        "balance",
        "portfolio",
        "orders",
        "transactions",
        "preview",
        "place",
        "cancel",
        "submit_order",
    ),
)
def test_unsupported_and_untyped_operations_fail_closed(operation: object) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match="read-only operation"):
        create_etrade_read_only_request_description(
            operation=operation,  # type: ignore[arg-type]
            environment=EtradeEnvironment.SANDBOX,
            endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        )


def test_alpaca_description_cannot_substitute_for_etrade_profile() -> None:
    alpaca = AlpacaPaperAccountObservationDescription(account_id="local-paper")
    with pytest.raises(EtradeRecordedOfflineContractError, match="endpoint profile"):
        create_etrade_accounts_list_request_description(
            environment=EtradeEnvironment.SANDBOX,
            endpoint_profile=alpaca,  # type: ignore[arg-type]
        )


def test_request_records_no_secret_material(monkeypatch: pytest.MonkeyPatch) -> None:
    canaries = (
        "sandbox-consumer-secret-canary",
        "sandbox-token-secret-canary",
        "production-consumer-secret-canary",
        "production-token-secret-canary",
        "oauth-verifier-canary",
        "oauth-signature-canary",
    )
    for index, canary in enumerate(canaries):
        monkeypatch.setenv(f"ETRADE_TEST_SECRET_{index}", canary)

    for value in (
        ETRADE_RECORDED_OFFLINE_CAPABILITIES,
        ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
        ETRADE_SANDBOX_ENDPOINT_PROFILE,
        ETRADE_PRODUCTION_ENDPOINT_PROFILE,
        _account_identifiers(),
        _description(),
        _description().to_record_bytes(),
    ):
        rendered = repr(value)
        for canary in canaries:
            assert canary not in rendered
    record = _description().to_record_bytes()
    assert b"oauth_token" not in record
    assert b"oauth_verifier" not in record
    assert b"oauth_signature" not in record
    assert b"consumer_secret_value" not in record
    assert b"Authorization" not in record


def test_every_authority_and_sandbox_evidence_gate_remains_false() -> None:
    capability = ETRADE_RECORDED_OFFLINE_CAPABILITIES
    description = _description()
    identifiers = _account_identifiers()

    assert type(capability) is EtradeRecordedOfflineCapabilityMatrix
    assert capability.offline_contract_only is True
    assert capability.sandbox_protocol_only is True
    assert capability.authority
    assert set(capability.authority.values()) == {False}
    assert capability.sandbox_qualification
    assert set(capability.sandbox_qualification.values()) == {False}
    assert set(ETRADE_SANDBOX_ENDPOINT_PROFILE.authority.values()) == {False}
    assert set(ETRADE_PRODUCTION_ENDPOINT_PROFILE.authority.values()) == {False}
    assert set(ETRADE_OUT_OF_BAND_CALLBACK_POLICY.authority.values()) == {False}
    assert set(identifiers.authority.values()) == {False}
    assert set(description.authority.values()) == {False}
    assert description.credential_resolution_authorized is False
    assert description.oauth_session_acquisition_authorized is False
    assert description.transport_authorized is False
    assert description.runtime_request_ready is False
    assert description.account_binding_authorized is False
    assert description.trading_effect_authorized is False
    assert ETRADE_OUT_OF_BAND_CALLBACK_POLICY.authorization_redirect_authorized is False
    assert ETRADE_OUT_OF_BAND_CALLBACK_POLICY.oauth_session_acquisition_authorized is False

    for field_name in capability.authority:
        with pytest.raises(EtradeRecordedOfflineContractError, match=field_name):
            replace(capability, **{field_name: True})
    for field_name in capability.sandbox_qualification:
        with pytest.raises(EtradeRecordedOfflineContractError, match=field_name):
            replace(capability, **{field_name: True})


@pytest.mark.parametrize("via_replace", [False, True])
@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("environments", ("sandbox", "production")),
        ("environments", (EtradeEnvironment.SANDBOX, "production")),
        (
            "environments",
            (EtradeEnvironment.PRODUCTION, EtradeEnvironment.SANDBOX),
        ),
        (
            "environments",
            (EtradeEnvironment.SANDBOX, EtradeEnvironment.SANDBOX),
        ),
        (
            "environments",
            (
                EtradeEnvironment.SANDBOX,
                EtradeEnvironment.PRODUCTION,
                EtradeEnvironment.SANDBOX,
            ),
        ),
        (
            "environments",
            [EtradeEnvironment.SANDBOX, EtradeEnvironment.PRODUCTION],
        ),
        ("read_only_operations", ("accounts_list",)),
        (
            "read_only_operations",
            (EtradeReadOnlyOperation.ACCOUNTS_LIST, "accounts_list"),
        ),
        (
            "read_only_operations",
            (
                EtradeReadOnlyOperation.ACCOUNTS_LIST,
                EtradeReadOnlyOperation.ACCOUNTS_LIST,
            ),
        ),
        ("callback_modes", ("out_of_band",)),
        (
            "callback_modes",
            (EtradeOAuthCallbackMode.OUT_OF_BAND, "out_of_band"),
        ),
        (
            "callback_modes",
            (
                EtradeOAuthCallbackMode.OUT_OF_BAND,
                EtradeOAuthCallbackMode.OUT_OF_BAND,
            ),
        ),
    ],
)
def test_capability_typed_tuples_reject_noncanonical_members_and_shape(
    field_name: str,
    value: object,
    via_replace: bool,
) -> None:
    with pytest.raises(EtradeRecordedOfflineContractError, match=field_name):
        if via_replace:
            replace(ETRADE_RECORDED_OFFLINE_CAPABILITIES, **{field_name: value})
        else:
            EtradeRecordedOfflineCapabilityMatrix(**{field_name: value})


def test_etrade_module_is_enrolled_as_side_effect_free() -> None:
    repository = Path(__file__).resolve().parents[2]
    with (repository / "infra" / "architecture-boundaries.toml").open("rb") as stream:
        config = tomllib.load(stream)

    assert config["scan"]["side_effect_free_roots"].count("packages/adapters/broker/etrade.py") == 1


def test_public_exports_are_provider_specific_and_non_effecting() -> None:
    assert broker_exports.EtradeEnvironment is EtradeEnvironment
    assert broker_exports.ETRADE_PROVIDER is ETRADE_PROVIDER
    assert set(etrade_module.__all__) <= set(broker_exports.__all__)
    assert {
        "resolve_etrade_credentials",
        "acquire_etrade_oauth_session",
        "send_etrade_request",
        "preview_etrade_order",
        "place_etrade_order",
        "cancel_etrade_order",
    }.isdisjoint(etrade_module.__all__)
