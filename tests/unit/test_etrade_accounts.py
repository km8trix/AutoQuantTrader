from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from typing import Any, cast

import pytest

import packages.adapters.broker as broker_exports
import packages.adapters.broker.etrade_accounts as etrade_accounts_module
from packages.adapters.broker.etrade import (
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_PROVIDER,
    ETRADE_RECORDED_OFFLINE_CAPABILITIES,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    EtradeAccountsListRequestDescription,
    EtradeEnvironment,
    create_etrade_accounts_list_request_description,
)
from packages.adapters.broker.etrade_accounts import (
    ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS,
    ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES,
    ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
    ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256,
    ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256,
    EtradeAccountsListAccountIdentity,
    EtradeAccountsListCallerDeclaredResponse,
    EtradeAccountsListCharset,
    EtradeAccountsListMediaType,
    EtradeAccountsListObservation,
    EtradeAccountsListOriginDeclarationKind,
    EtradeAccountsListResponseError,
    EtradeAccountsListUnauthenticatedOriginDeclaration,
    create_etrade_accounts_list_caller_declared_response,
    create_etrade_accounts_list_unauthenticated_origin_declaration,
    decode_etrade_accounts_list_caller_declared_response,
)

# This is a local mechanical contract vector. It is not authentic or current
# E*TRADE provider evidence; this boundary can only retain a caller declaration.
MECHANICAL_CONTRACT_BYTES = (
    b'{"AccountListResponse":{"Accounts":{"Account":['
    b'{"accountDesc":"Mechanical primary","accountId":"00123456",'
    b'"accountIdKey":"MechanicalKeyA_01","accountMode":"CASH",'
    b'"accountName":"Example one","accountStatus":"ACTIVE",'
    b'"accountType":"INDIVIDUAL","closedDate":0,"institutionType":"BROKERAGE"},'
    b'{"accountDesc":"Mechanical secondary","accountId":"87654321",'
    b'"accountIdKey":"MechanicalKeyB_02","accountMode":"MARGIN",'
    b'"accountName":"Example two","accountStatus":"ACTIVE",'
    b'"accountType":"INDIVIDUAL","closedDate":0,"institutionType":"BROKERAGE"}'
    b"]}}}"
)


class _EqualitySpoof:
    def __eq__(self, other: object) -> bool:
        del other
        return True

    def __ne__(self, other: object) -> bool:
        del other
        return False


def _description(
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
) -> EtradeAccountsListRequestDescription:
    endpoint = (
        ETRADE_SANDBOX_ENDPOINT_PROFILE
        if environment is EtradeEnvironment.SANDBOX
        else ETRADE_PRODUCTION_ENDPOINT_PROFILE
    )
    return create_etrade_accounts_list_request_description(
        environment=environment,
        endpoint_profile=endpoint,
    )


def _origin_declaration(
    description: EtradeAccountsListRequestDescription,
    response_body: bytes,
    *,
    declaration_id: str = "mechanical-declaration-0001",
) -> EtradeAccountsListUnauthenticatedOriginDeclaration:
    return create_etrade_accounts_list_unauthenticated_origin_declaration(
        description,
        profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
        declaration_id=declaration_id,
        declared_http_status=200,
        declared_media_type=EtradeAccountsListMediaType.JSON,
        declared_charset=EtradeAccountsListCharset.UTF_8,
        response_body=response_body,
    )


def _caller_declared(
    response_body: bytes = MECHANICAL_CONTRACT_BYTES,
    *,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    declaration_id: str = "mechanical-declaration-0001",
) -> EtradeAccountsListCallerDeclaredResponse:
    description = _description(environment)
    return create_etrade_accounts_list_caller_declared_response(
        description,
        profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
        origin_declaration=_origin_declaration(
            description,
            response_body,
            declaration_id=declaration_id,
        ),
        response_body=response_body,
    )


def _payload() -> dict[str, Any]:
    value = json.loads(MECHANICAL_CONTRACT_BYTES)
    assert type(value) is dict
    return value


def _account(
    numeric_account_id: object = "00123456",
    account_id_key: object = "MechanicalKeyA_01",
    **changes: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "accountDesc": "Mechanical account",
        "accountId": numeric_account_id,
        "accountIdKey": account_id_key,
        "accountMode": "CASH",
        "accountName": "Example account",
        "accountStatus": "ACTIVE",
        "accountType": "INDIVIDUAL",
        "closedDate": 0,
        "institutionType": "BROKERAGE",
    }
    value.update(changes)
    return value


def _body(*accounts: dict[str, object]) -> bytes:
    return json.dumps(
        {"AccountListResponse": {"Accounts": {"Account": list(accounts)}}},
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_response_schema_and_profile_identities_are_pinned() -> None:
    assert ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256 == (
        "0f4f134a52af8e5e4df3feab93aec7b5123ea4ff9cfe838f428797f57f5098c9"
    )
    assert ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256 == (
        "658174521573d60be9cb11ec7da76e0487cf37ec703b31c1db2472befed4e314"
    )
    assert (
        ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE.semantic_sha256
        == ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256
    )


def test_raw_evidence_construction_precedes_strict_decode() -> None:
    body = b'{"mechanical":"schema drift retained before decode"}'
    description = _description()
    origin_declaration = _origin_declaration(description, body)

    caller_declared = create_etrade_accounts_list_caller_declared_response(
        description,
        profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
        origin_declaration=origin_declaration,
        response_body=body,
    )

    assert caller_declared.response_body is body
    assert caller_declared.response_size_bytes == len(body)
    assert caller_declared.response_body_sha256 == hashlib.sha256(body).hexdigest()
    with pytest.raises(EtradeAccountsListResponseError, match="schema"):
        decode_etrade_accounts_list_caller_declared_response(caller_declared)


def test_exact_raw_and_each_decoded_identity_are_cross_bound() -> None:
    caller_declared = _caller_declared()
    observation = decode_etrade_accounts_list_caller_declared_response(caller_declared)

    assert caller_declared.response_body is MECHANICAL_CONTRACT_BYTES
    assert caller_declared.response_size_bytes == len(MECHANICAL_CONTRACT_BYTES)
    assert (
        caller_declared.response_body_sha256
        == hashlib.sha256(MECHANICAL_CONTRACT_BYTES).hexdigest()
    )
    assert observation.caller_declared_response is caller_declared
    assert observation.provider is ETRADE_PROVIDER
    assert observation.environment is EtradeEnvironment.SANDBOX
    assert observation.account_count == 2
    assert type(observation.accounts) is tuple
    assert tuple(account.numeric_account_id.value for account in observation.accounts) == (
        "00123456",
        "87654321",
    )
    assert tuple(account.account_id_key.value for account in observation.accounts) == (
        "MechanicalKeyA_01",
        "MechanicalKeyB_02",
    )

    for index, account in enumerate(observation.accounts):
        assert type(account) is EtradeAccountsListAccountIdentity
        assert account.caller_declared_response is caller_declared
        assert account.provider is ETRADE_PROVIDER
        assert account.environment is EtradeEnvironment.SANDBOX
        assert account.account_index == index
        assert account.endpoint_profile_sha256 == ETRADE_SANDBOX_ENDPOINT_PROFILE.semantic_sha256
        assert account.request_description_sha256 == caller_declared.description.semantic_sha256
        assert (
            account.origin_declaration_sha256 == caller_declared.origin_declaration.semantic_sha256
        )
        assert account.response_profile_sha256 == ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE_SHA256
        assert account.schema_profile_sha256 == ETRADE_ACCOUNTS_LIST_RESPONSE_SCHEMA_SHA256
        assert account.response_body_sha256 == caller_declared.response_body_sha256
        assert account.caller_declared_response_sha256 == caller_declared.semantic_sha256
        assert not hasattr(account, "local_alias")

    repeated = decode_etrade_accounts_list_caller_declared_response(_caller_declared())
    assert repeated.semantic_sha256 == observation.semantic_sha256
    assert MECHANICAL_CONTRACT_BYTES.decode("utf-8") not in repr(caller_declared)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("operation", "accounts_list"),
        ("media_type", "application/json"),
        ("charset", "utf-8"),
    ),
)
def test_profile_rejects_raw_string_enum_substitution(field_name: str, value: object) -> None:
    with pytest.raises(EtradeAccountsListResponseError, match="exact E\\*TRADE"):
        replace(
            cast(Any, ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE),
            **{field_name: value},
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("declaration_kind", "unauthenticated_caller_declaration"),
        ("declared_media_type", "application/json"),
        ("declared_media_type", "application/json; charset=utf-8"),
        ("declared_charset", "utf-8"),
        ("declared_charset", "UTF-8"),
    ),
)
def test_origin_declaration_rejects_media_charset_and_raw_string_enums(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(EtradeAccountsListResponseError):
        replace(
            cast(
                Any,
                _origin_declaration(_description(), MECHANICAL_CONTRACT_BYTES),
            ),
            **{field_name: value},
        )


@pytest.mark.parametrize(
    "response_body",
    (
        bytearray(b"{}"),
        memoryview(b"{}"),
        b"",
        b" " * (ETRADE_ACCOUNTS_LIST_MAX_RESPONSE_BYTES + 1),
    ),
)
def test_raw_construction_requires_exact_bounded_bytes(response_body: object) -> None:
    description = _description()
    with pytest.raises(EtradeAccountsListResponseError, match=r"bytes|size"):
        create_etrade_accounts_list_unauthenticated_origin_declaration(
            description,
            profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
            declaration_id="mechanical-declaration-0001",
            declared_http_status=200,
            declared_media_type=EtradeAccountsListMediaType.JSON,
            declared_charset=EtradeAccountsListCharset.UTF_8,
            response_body=response_body,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("body", "message"),
    (
        (b"\xff", "UTF-8"),
        (b"{", "invalid JSON"),
        (b"[]", "root"),
        (b'{"AccountListResponse":NaN}', "non-standard"),
        (
            b'{"AccountListResponse":{},"AccountListResponse":{}}',
            "duplicate JSON key",
        ),
    ),
)
def test_decode_rejects_utf8_json_and_duplicate_key_corruption(
    body: bytes,
    message: str,
) -> None:
    caller_declared = _caller_declared(body)
    assert caller_declared.response_body is body
    with pytest.raises(EtradeAccountsListResponseError, match=message):
        decode_etrade_accounts_list_caller_declared_response(caller_declared)


def _schema_corruptions() -> tuple[bytes, ...]:
    missing_root: dict[str, object] = {}
    extra_root = _payload()
    extra_root["unexpected"] = True
    wrong_accounts: object = {"AccountListResponse": {"Accounts": []}}
    wrong_array: object = {"AccountListResponse": {"Accounts": {"Account": {}}}}
    missing_field = _account()
    missing_field.pop("accountName")
    unknown_field = _account(unexpected="drift")
    wrong_text = _account(accountName=[])
    wrong_closed_date = _account(closedDate=True)
    too_many = [
        _account(str(index + 1), f"MechanicalKey{index:03d}")
        for index in range(ETRADE_ACCOUNTS_LIST_MAX_ACCOUNTS + 1)
    ]
    corruptions: tuple[object, ...] = (
        missing_root,
        extra_root,
        wrong_accounts,
        wrong_array,
        {"AccountListResponse": {"Accounts": {"Account": [missing_field]}}},
        {"AccountListResponse": {"Accounts": {"Account": [unknown_field]}}},
        {"AccountListResponse": {"Accounts": {"Account": [wrong_text]}}},
        {"AccountListResponse": {"Accounts": {"Account": [wrong_closed_date]}}},
        {"AccountListResponse": {"Accounts": {"Account": []}}},
        {"AccountListResponse": {"Accounts": {"Account": too_many}}},
    )
    return tuple(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        for value in corruptions
    )


@pytest.mark.parametrize("body", _schema_corruptions())
def test_exact_nested_schema_and_account_bound_fail_closed(body: bytes) -> None:
    caller_declared = _caller_declared(body)
    with pytest.raises(EtradeAccountsListResponseError):
        decode_etrade_accounts_list_caller_declared_response(caller_declared)


def test_duplicate_and_ambiguous_account_pairs_fail_closed() -> None:
    cases = (
        (
            _body(_account(), _account()),
            "repeats an exact account identity",
        ),
        (
            _body(_account(), _account(account_id_key="MechanicalKeyB_02")),
            "multiple accountIdKeys",
        ),
        (
            _body(_account(), _account(numeric_account_id="87654321")),
            "multiple numeric account IDs",
        ),
    )
    for body, message in cases:
        with pytest.raises(EtradeAccountsListResponseError, match=message):
            decode_etrade_accounts_list_caller_declared_response(_caller_declared(body))


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("accountId", None),
        ("accountId", True),
        ("accountId", 1234),
        ("accountId", ""),
        ("accountId", " 1234"),
        ("accountId", "+1234"),
        ("accountId", "1" * 33),
        ("accountIdKey", None),
        ("accountIdKey", True),
        ("accountIdKey", " key"),
        ("accountIdKey", "key/value"),
        ("accountIdKey", "key%2Fvalue"),
        ("accountIdKey", "e\u0301"),
        ("accountIdKey", "k" * 129),
    ),
)
def test_malformed_provider_account_identity_is_rejected(
    field_name: str,
    value: object,
) -> None:
    account = _account()
    account[field_name] = value
    with pytest.raises(EtradeAccountsListResponseError, match="malformed provider identity"):
        decode_etrade_accounts_list_caller_declared_response(_caller_declared(_body(account)))


def test_cross_environment_and_request_replay_are_rejected() -> None:
    body = MECHANICAL_CONTRACT_BYTES
    sandbox_description = _description(EtradeEnvironment.SANDBOX)
    production_description = _description(EtradeEnvironment.PRODUCTION)
    production_declaration = _origin_declaration(production_description, body)

    with pytest.raises(EtradeAccountsListResponseError, match=r"environment.*binding"):
        create_etrade_accounts_list_caller_declared_response(
            sandbox_description,
            profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
            origin_declaration=production_declaration,
            response_body=body,
        )

    wrong_request = replace(
        _origin_declaration(sandbox_description, body),
        declared_request_description_sha256="0" * 64,
    )
    with pytest.raises(EtradeAccountsListResponseError, match=r"request description.*binding"):
        create_etrade_accounts_list_caller_declared_response(
            sandbox_description,
            profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
            origin_declaration=wrong_request,
            response_body=body,
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("declared_response_origin", ETRADE_PRODUCTION_ENDPOINT_PROFILE.data_api_origin),
        ("declared_response_api_root", ETRADE_PRODUCTION_ENDPOINT_PROFILE.data_api_root),
        (
            "declared_response_url",
            f"{ETRADE_PRODUCTION_ENDPOINT_PROFILE.data_api_root}/accounts/list",
        ),
        ("declared_request_method", "POST"),
        ("declared_request_target", "/accounts/balance"),
        ("declared_http_status", 201),
    ),
)
def test_declared_origin_request_and_status_substitution_fail_closed(
    field_name: str,
    value: object,
) -> None:
    origin_declaration = _origin_declaration(_description(), MECHANICAL_CONTRACT_BYTES)
    with pytest.raises(EtradeAccountsListResponseError, match="conflicts with its profile"):
        replace(cast(Any, origin_declaration), **{field_name: value})


@pytest.mark.parametrize(
    "field_name",
    (
        "declared_endpoint_profile_sha256",
        "bound_response_profile_sha256",
        "bound_schema_profile_sha256",
    ),
)
def test_forged_nested_profile_or_endpoint_replay_is_revalidated(field_name: str) -> None:
    description = _description()
    origin_declaration = _origin_declaration(description, MECHANICAL_CONTRACT_BYTES)
    object.__setattr__(origin_declaration, field_name, "0" * 64)

    with pytest.raises(EtradeAccountsListResponseError, match="profile"):
        create_etrade_accounts_list_caller_declared_response(
            description,
            profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
            origin_declaration=origin_declaration,
            response_body=MECHANICAL_CONTRACT_BYTES,
        )


def test_body_and_origin_declaration_cannot_be_replayed_after_decode() -> None:
    first = _caller_declared(declaration_id="mechanical-declaration-0001")
    observation = decode_etrade_accounts_list_caller_declared_response(first)
    other_body = MECHANICAL_CONTRACT_BYTES.replace(b"00123456", b"11112222", 1)
    assert len(other_body) == len(MECHANICAL_CONTRACT_BYTES)
    other_declaration = _origin_declaration(
        _description(),
        other_body,
        declaration_id="mechanical-other-0002",
    )

    with pytest.raises(EtradeAccountsListResponseError, match=r"response body.*binding"):
        create_etrade_accounts_list_caller_declared_response(
            _description(),
            profile=ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
            origin_declaration=other_declaration,
            response_body=MECHANICAL_CONTRACT_BYTES,
        )

    replacement_declaration = _origin_declaration(
        first.description,
        first.response_body,
        declaration_id="mechanical-replay-0003",
    )
    object.__setattr__(first, "origin_declaration", replacement_declaration)
    with pytest.raises(EtradeAccountsListResponseError, match="exact raw response"):
        _ = observation.semantic_sha256


def test_mechanical_fixture_remains_an_unauthenticated_caller_declaration() -> None:
    caller_declared = _caller_declared()
    origin_declaration = caller_declared.origin_declaration
    observation = decode_etrade_accounts_list_caller_declared_response(caller_declared)

    assert tuple(EtradeAccountsListOriginDeclarationKind) == (
        EtradeAccountsListOriginDeclarationKind.UNAUTHENTICATED_CALLER_DECLARATION,
    )
    assert (
        origin_declaration.declaration_kind
        is EtradeAccountsListOriginDeclarationKind.UNAUTHENTICATED_CALLER_DECLARATION
    )
    assert origin_declaration.provider_origin_authenticated is False
    assert origin_declaration.authenticated_provider_evidence is False
    assert origin_declaration.fixture_relabeling_detection_supported is False
    assert caller_declared.provider_origin_authenticated is False
    assert caller_declared.authenticated_provider_evidence is False
    assert caller_declared.fixture_relabeling_detection_supported is False
    assert observation.provider_origin_authenticated is False
    assert observation.authenticated_provider_evidence is False
    assert observation.fixture_relabeling_detection_supported is False
    for identity in observation.accounts:
        assert identity.provider_origin_authenticated is False
        assert identity.authenticated_provider_evidence is False
        assert identity.fixture_relabeling_detection_supported is False


@pytest.mark.parametrize(
    "field_name",
    ("provider_origin_authenticated", "fixture_relabeling_detection_supported"),
)
def test_origin_declaration_rejects_false_to_true_trust_mutation(field_name: str) -> None:
    declaration = _origin_declaration(_description(), MECHANICAL_CONTRACT_BYTES)
    with pytest.raises(EtradeAccountsListResponseError, match="conflicts with its profile"):
        replace(cast(Any, declaration), **{field_name: True})


@pytest.mark.parametrize(
    "field_name",
    ("provider_origin_authentication_supported", "fixture_relabeling_detection_supported"),
)
def test_response_profile_rejects_false_to_true_trust_mutation(field_name: str) -> None:
    with pytest.raises(EtradeAccountsListResponseError, match=field_name):
        replace(
            cast(Any, ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE),
            **{field_name: True},
        )


def test_derived_evidence_is_proof_constructed_frozen_and_exactly_typed() -> None:
    for constructor in (
        EtradeAccountsListCallerDeclaredResponse,
        EtradeAccountsListAccountIdentity,
        EtradeAccountsListObservation,
    ):
        with pytest.raises(TypeError, match="proof-constructed"):
            constructor()

    caller_declared = _caller_declared()
    observation = decode_etrade_accounts_list_caller_declared_response(caller_declared)
    with pytest.raises(FrozenInstanceError):
        caller_declared.response_body = b"{}"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        observation.accounts = ()  # type: ignore[misc]

    object.__setattr__(observation, "accounts", list(observation.accounts))
    with pytest.raises(EtradeAccountsListResponseError, match="exact tuple"):
        _ = observation.account_count

    tuple_substitution = decode_etrade_accounts_list_caller_declared_response(_caller_declared())
    object.__setattr__(tuple_substitution, "accounts", ("raw-string-identity",))
    with pytest.raises(EtradeAccountsListResponseError, match="exact identities"):
        _ = tuple_substitution.account_count

    raw_enum_identity = decode_etrade_accounts_list_caller_declared_response(
        _caller_declared()
    ).accounts[0]
    object.__setattr__(raw_enum_identity, "environment", "sandbox")
    with pytest.raises(EtradeAccountsListResponseError, match="exact E\\*TRADE"):
        _ = raw_enum_identity.semantic_sha256

    equality_spoofed_identity = decode_etrade_accounts_list_caller_declared_response(
        _caller_declared()
    ).accounts[0]
    object.__setattr__(
        equality_spoofed_identity,
        "response_profile_sha256",
        _EqualitySpoof(),
    )
    with pytest.raises(EtradeAccountsListResponseError, match="lowercase SHA-256"):
        _ = equality_spoofed_identity.semantic_sha256

    detached_identity = decode_etrade_accounts_list_caller_declared_response(
        _caller_declared()
    ).accounts[0]
    object.__setattr__(detached_identity, "response_body_sha256", "0" * 64)
    with pytest.raises(EtradeAccountsListResponseError, match="exact raw response"):
        _ = detached_identity.semantic_sha256


def test_unsupported_operations_and_every_authority_remain_closed() -> None:
    caller_declared = _caller_declared()
    origin_declaration = caller_declared.origin_declaration
    observation = decode_etrade_accounts_list_caller_declared_response(caller_declared)
    values: tuple[Any, ...] = (
        ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE,
        origin_declaration,
        caller_declared,
        observation,
        *observation.accounts,
    )

    assert dict(ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE.operation_support) == {
        "accounts_list_response_supported": True,
        "balance_response_supported": False,
        "portfolio_response_supported": False,
        "orders_response_supported": False,
        "transactions_response_supported": False,
        "preview_supported": False,
        "place_supported": False,
        "cancel_supported": False,
        "submission_supported": False,
    }
    assert ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE.provider_origin_authentication_supported is False
    assert ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE.fixture_relabeling_detection_supported is False
    for value in values:
        authority = value.authority
        assert authority
        assert tuple(authority) == tuple(ETRADE_RECORDED_OFFLINE_CAPABILITIES.authority)
        assert set(authority.values()) == {False}
        for field_name in authority:
            assert getattr(value, field_name) is False
        assert value.authenticated_provider_evidence is False
        assert value.runtime_current is False
        assert value.trading_effect_authorized is False

    for field_name in (
        "balance_response_supported",
        "portfolio_response_supported",
        "orders_response_supported",
        "transactions_response_supported",
        "preview_supported",
        "place_supported",
        "cancel_supported",
        "submission_supported",
    ):
        with pytest.raises(EtradeAccountsListResponseError, match=field_name):
            replace(
                cast(Any, ETRADE_ACCOUNTS_LIST_RESPONSE_PROFILE),
                **{field_name: True},
            )

    assert {
        "decode_etrade_balance_response",
        "decode_etrade_portfolio_response",
        "decode_etrade_orders_response",
        "decode_etrade_transactions_response",
        "preview_etrade_order",
        "place_etrade_order",
        "cancel_etrade_order",
    }.isdisjoint(etrade_accounts_module.__all__)


def test_response_contract_is_publicly_exported_without_effecting_api() -> None:
    expected = {
        "EtradeAccountsListCallerDeclaredResponse": EtradeAccountsListCallerDeclaredResponse,
        "EtradeAccountsListObservation": EtradeAccountsListObservation,
        "EtradeAccountsListOriginDeclarationKind": EtradeAccountsListOriginDeclarationKind,
        "EtradeAccountsListUnauthenticatedOriginDeclaration": (
            EtradeAccountsListUnauthenticatedOriginDeclaration
        ),
        "create_etrade_accounts_list_caller_declared_response": (
            create_etrade_accounts_list_caller_declared_response
        ),
        "create_etrade_accounts_list_unauthenticated_origin_declaration": (
            create_etrade_accounts_list_unauthenticated_origin_declaration
        ),
        "decode_etrade_accounts_list_caller_declared_response": (
            decode_etrade_accounts_list_caller_declared_response
        ),
    }
    for name, value in expected.items():
        assert getattr(broker_exports, name) is value
        assert name in broker_exports.__all__
    assert set(etrade_accounts_module.__all__) <= set(broker_exports.__all__)


def test_old_provider_origin_trust_labels_are_not_exposed() -> None:
    old_trust_labels = {
        "EtradeAccountsListCaptureKind",
        "EtradeAccountsListCaptureProvenance",
        "EtradeAccountsListRecordedResponse",
        "create_etrade_accounts_list_capture_provenance",
        "create_etrade_accounts_list_recorded_response",
        "decode_etrade_accounts_list_response",
    }
    for namespace in (etrade_accounts_module, broker_exports):
        assert old_trust_labels.isdisjoint(namespace.__all__)
        for name in old_trust_labels:
            assert not hasattr(namespace, name)


def test_no_authenticated_admission_or_conversion_api_is_exposed() -> None:
    forbidden_apis = {
        "admit_etrade_accounts_list_authenticated_provider_evidence",
        "authenticate_etrade_accounts_list_provider_origin",
        "convert_etrade_accounts_list_to_authenticated_provider_evidence",
        "create_etrade_accounts_list_authenticated_provider_evidence",
        "decode_etrade_accounts_list_authenticated_provider_response",
    }
    for namespace in (etrade_accounts_module, broker_exports):
        assert forbidden_apis.isdisjoint(namespace.__all__)
        for name in namespace.__all__:
            if "etrade_accounts_list" not in name.lower():
                continue
            trust_name = name.lower().replace("unauthenticated", "")
            assert "authenticated" not in trust_name
            assert "authenticate" not in trust_name
        for name in forbidden_apis:
            assert not hasattr(namespace, name)
