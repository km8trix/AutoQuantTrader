# ruff: noqa: E501
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
import json
import lzma
import os
import pickle
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts as workflow
from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
    canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
    decode_post_enrollment_graceful_stop_operator_attestation_statement,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    build_post_enrollment_graceful_stop_operator_authority,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
)
from scripts import trusted_time_post_enrollment_operator_attestation_artifacts as audited_fs
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    canonical_post_enrollment_graceful_stop_decision_bytes,
    decode_post_enrollment_graceful_stop_decision,
)

# Public-only fixture. The canonical semantic decision was produced by the pure
# ADR0104 codec; XZ + Base85 only keeps this test source readable. The public
# key is RFC 8032 test key 2. The detached signature was generated out of tree.
# No private material, signing import, signing call, or key generator is present.
_DECISION_XZ_BASE85 = b"""{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;4ym%<y`<hh=?Y1Y}*tNrzOFii0GP>zZ<WH)*%Mk!NCVoF#})d^X==VHIpeK5|P2uQZ}esM39MJZTL8IskI2dYHya<@Js+N@l8v8Sm~=hI4&mfTgr@b>Y8s2C>omj8iS<!^ivr!4~&}DfKlpU*P35Sknb*V9QMH^qceZep0r#nHb-w|bn37k=8~OqSZX7waejvNx{|%>Q{2cb@563^t>uPLIZJfoGDK~K77%u*1Hg6O<EsqSLsN(hWq0Fg-RH97Nk^BbAH4~<FElhFG$fXMRX*pqeu3ftd}!KVdA}Xs)|g%M)(|R3v_rV(PdEJ)8D&>f$^Abv{_bf6J{u%l<3@Xulv0BT_xV1E*`TaL3+4RX1HGxHyTC{Z-iO7m&A&SUWiEp+hzO*}KM56d6q<zVgszd{E5NcQzzaP<CIgRlEb|e9BtG>?VluCe|M_|5AMlD1%vKy>*n}e9SL*zJqLu43n-(5wlzK%#l_yev##<*ffyV0D2TMaZlZBIR;pp=SvmOT(`z>3yN`=SmPchX74OTOZ`Wbt9V7l5%Pd2*QHp>yoJJNs%Mhwz(taMzhY7^=#^^98IC==9UIKPdK6a&;(ak#%N<h{*ycvsF@IGTWl{{jTL%|z^IDcK&m*es5|{62P|k911F551O<42nU#(_<D}|Aab8s6{Z+Ijov)Pkz)M;$I0%o&dxEOEoxu!{#YD^K*rZ5m)qR(mecchsU@%jFY@syV59ty*Zf+&>^1PWV`k#&?`8Gx>M>sGKwCYJ4*OM<<Q@_AGKk*&VZ{{DTeX3Hv59Y<Dx7lE?;9TQZ(^YjP=j4iBL!ZMw)NLQ~B#}oO9vXXvhfsaskt8TfrBQacuj*A2gr(NN%OPQ;O|mIpM6KlY^yHQw7&IH8%~9)%uLu1G>3J^9>tf5&?_>6uI8*I&g$R9|2Uy6x1w8tgcDR@vG`38_7dh#VRKqo+u6DE)0rtMCVR&wWL0});OQ_h(cs|#<@mZ>BEXl0D){&FqdA^tA{qb;Lm9cs<>@0Sz64zRsCbl_{60OyP0RQ0@P<^qRK&oHAtXo2evN2J^R-YK&aoaJ$}GG3^J9$R-D>OzI_K=_b*SJ4~$88)xxV6wHG==Y<x6nPww;F0i*Lu8_qWJSd>fgQ{1El>0)da)i}Z^4+0DA%^lv<-(YX!ZrU&RnQ&*07uVv?2`US`f$Pi$NiJ_nW(lWSWOK9P-BdC2-WDaxfB4)5u7TGTSX42OBrm^ROO!WZL&Os-U3q}XK|ay{GHCam73bNP8C9r5zKG_wX+Cz~8D|-EMv|TuJnnTu7kN#|X2;|0_?&Lvo8p{()HGc|T{>GI91o0#yP;;@*bpNM2?fa_7q@I17Mj~_XhrYrxEyBy)-omG1e}{WiK*sT6sPWI%;!pH1-L(%!|lnam9M+A1lSPhRpiF6OR``Sw0<ru#?}(P5nBFgteRU52ha|Eo|Epk_UWa!5m_^ZhZ^GCy%Q)}bG48<;rf?reWZAq7Ct*mfS$KI?W}Ff4IEAZ-4VPl!|LG#DPj8SK}n?`P;GA)GVXz3iemy~EPn3D%dE4J&P}*|*287?vszr+z;IjxSRsNul4`Fh15mRk(g~`r{B*#`3(arL49fUZ8KA7zNv;`S&tDpo^I(W&2Hz>PXV#{=8FIx7bun=L5$kj}ACDOJlwP$PDb91r*Vnr9(>z<2Y(6g^FV#+`-$pKer#*IMQbG{5t0$@6X~hg-7wWqpXY6jD1v4s|y+bFRrHf#eVyp(g)%=fwLe;h1cSKKhweW#J&1!zAlAXcM>b~Xq-zda9Ybm5svMROGI<`SbRoZpo&C1$b4utp|bxnSuiD@DOOsqM9#MrFo=#*}6C54bghxQA+TvsKic&Inrz1Wcm7B)T|uk4JxgF`6O+pP~3c_VPK&e{>p!JnWL;d4WmSTitdcTU||%?8D!*F0x}dPx-~=Q87MG}UL&eLl8U1+#KYstr?!7+hwm-&HmSri0Q12Dj3uk73?;W@GAMLsZXGBn|Msk~|du@czh=plcI+k(ZB+|Ma-fp*82A+xd}3TIu*!LkYJv?9|XBi@9ml%rTH-)Dv95mH_#3pI68Q3do3xy$>Y&@{cvPZh;b^qr+u!CODxPAcQ7j8Tf_~yGFh0i+Z&Nffm;F=SsBk<xeOoa3VaPAhZwRj)Ri)l9U{(Az&HBG5#lypv8GQu)D=MnM%j@SV^zRrs%Fo-^Akt%vdl{5s5y=EN8+lX&&&yqkhLqx%P{a(-pDz%?4yk!R8&ti(N2S95{|JPY#f3RM~yj)8JcoG*(WSfxG7}#8swP<?*7h=X*5XDPqdVbH&YdE5u@uRo!bKn^KCiU?JH_B!fUMoj9z%Lqur?Vjn!Ymi<FZKp@&mx*w=0DVQ=xarag^*AYXt9VmL4VN<hlnDerx;plr8ENO`JDD>9?j)9{s-6^d{ecM^)Yyz0k(}d)g^g%G<E7$mz4s$mK!2_Di6>a5iYaF2!#{xSrB^@{eX=buHFI4Lx<^uV62bWj6V$GKx6+xv&i7d{n;%GLZW(kl}Av9;K0r3e+D~~_(1vQ?GA(5wPJ}3GM)aOZu=`rbcjil-TXvD=E=5U5TIpj%CMxQki5MoRVS{ur29|FfvuP^>evcof@LvelYV-?ChT0}0wh^@n@l6&jMY#5k`92`m*aVq{HV&{%@NFn0U2JOZ=9ke&q;seLt$a>{7s}Yqvz`~0nAdTx7`tHIIC+gSiHlZfweFtWXD*8flx!&hBoz-grg4JzfYror~Ya!u{GDoTb_9F7S%1P5FN7ovG5jj<J#wWuzG*8Z}wUP|$B&rz<D8ma7;AsV-8F?yR+k9qZDTj{>g2o|Ps(46~f^&55<!<+94X2+44>~VrA`4gEUoX0SNSQ0A^D2S1{aQIIVY6_z*~tH#gDjl5yYlcZ`O<We1|#4svDZ?;W!aRU9<M#;nICSBXei8VvW&d=)Tooff(y5DN0u6R61hJ+B-v1SjCsHU2r9Z;?JWs%VYtf`b^@V7NUe1JT*{ltA^qi{X2vYOE?`)YRNyju%gQ%Fyyn4u!>Rz|T{oIyAcu%=Kr9@4aT2TntVde>7}>hAZn}658RmaBz~Zh*+_B&W$K2eDxU9B(93RFc)mD)7la+_eK;G1V`CcA49w~@^Fh$KD8zlm*br7?On^0A*=^CRouSno7sqLsVl-e>UQs(~&u|+z$AD(wpq|UiVr7K)qUrljCV+{l8aBz+y2yAQs$Y!Jf00000!>$e(E`@OR00Ds%{9*tAvy?gnvBYQl0ssI200dcD"""
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
DETACHED_SIGNATURE = bytes.fromhex(
    "0f77089e2883e1103f3af2a5806a1cbbe8c84fb32d950c5b42c31702c35a5040"
    "89bea6b18a02bd0b1c48206205a8d7a091aeeea4c7bdfbf6944d02fcaa3c9207"
)
AUTHORITY_SHA256 = "b0b6935d8b9573e55d68f7eb9fb639f71127e34d30110ee06c3613acbdc31db8"
PUBLIC_KEY_SHA256 = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f"
DECISION_SHA256 = "6007b32aa748b78d95e53209d9e81d40ea74d47901dce66f2357b57b272e70da"
TARGET_SHA256 = "9cb7d788dd758ef74807d14c2faba02d2495fd2c62119d4f05c628ffef555a98"
STATEMENT_SHA256 = "61f55c267b9afed3caf7560403c3b37afedcb638bc0e90a138a1d8e262c05105"
SIGNATURE_SHA256 = "3f8d0de2b70f5159b229b6d65355d2ca0cb7d042e2b88a347cf455e973c3eafe"
ENVELOPE_SHA256 = "c91c6a7fe991bfec3349457461b685689d7fa81cc96d14951047222909044ba8"
STOP_OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"
_ED25519_SCALAR_ORDER = 2**252 + 27742317777372353535851937790883648493


@dataclass(frozen=True)
class _Artifacts:
    input_directory: Path
    statement_directory: Path
    envelope_directory: Path
    authority_path: Path
    decision_path: Path
    signature_path: Path
    authority_encoded: bytes
    decision_encoded: bytes
    statement_encoded: bytes


class _AsyncInterruption(BaseException):
    pass


def _write_input(path: Path, encoded: bytes, *, mode: int = 0o600) -> None:
    path.write_bytes(encoded)
    path.chmod(mode)


def _fixed_decision_bytes() -> bytes:
    return lzma.decompress(base64.b85decode(_DECISION_XZ_BASE85))


@pytest.fixture
def artifacts(tmp_path: Path) -> _Artifacts:
    input_directory = tmp_path / "external-inputs"
    statement_directory = tmp_path / "external-statements"
    envelope_directory = tmp_path / "external-envelopes"
    for directory in (input_directory, statement_directory, envelope_directory):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)

    authority = build_post_enrollment_graceful_stop_operator_authority(PUBLIC_KEY)
    authority_encoded = canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
    decision_encoded = _fixed_decision_bytes()
    decision = decode_post_enrollment_graceful_stop_decision(decision_encoded)
    statement = build_post_enrollment_graceful_stop_operator_attestation_statement(
        authority=authority,
        graceful_stop_decision_v1_sha256=DECISION_SHA256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
    )
    statement_encoded = (
        canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
    )

    authority_path = input_directory / (
        f"{workflow.AUTHORITY_CANDIDATE_FILE_PREFIX}{AUTHORITY_SHA256}.json"
    )
    decision_path = input_directory / (
        f"{workflow.GRACEFUL_STOP_DECISION_V1_FILE_PREFIX}{DECISION_SHA256}.json"
    )
    signature_path = input_directory / "detached-signature.ed25519"
    _write_input(authority_path, authority_encoded)
    _write_input(decision_path, decision_encoded, mode=0o400)
    _write_input(signature_path, DETACHED_SIGNATURE)
    return _Artifacts(
        input_directory=input_directory,
        statement_directory=statement_directory,
        envelope_directory=envelope_directory,
        authority_path=authority_path,
        decision_path=decision_path,
        signature_path=signature_path,
        authority_encoded=authority_encoded,
        decision_encoded=decision_encoded,
        statement_encoded=statement_encoded,
    )


def _prepare_kwargs(artifacts: _Artifacts) -> dict[str, object]:
    return {
        "authority_artifact": artifacts.authority_path,
        "graceful_stop_decision_v1_artifact": artifacts.decision_path,
        "statement_candidate_directory": artifacts.statement_directory,
        "expected_authority_sha256": AUTHORITY_SHA256,
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "expected_graceful_stop_decision_v1_sha256": DECISION_SHA256,
    }


def _prepare(
    artifacts: _Artifacts,
) -> workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt:
    return workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate(
        **_prepare_kwargs(artifacts)  # type: ignore[arg-type]
    )


def _verify_kwargs(artifacts: _Artifacts) -> dict[str, object]:
    statement_path = artifacts.statement_directory / (
        f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{STATEMENT_SHA256}.json"
    )
    return {
        "authority_artifact": artifacts.authority_path,
        "graceful_stop_decision_v1_artifact": artifacts.decision_path,
        "statement_artifact": statement_path,
        "detached_signature_file": artifacts.signature_path,
        "envelope_candidate_directory": artifacts.envelope_directory,
        "expected_authority_sha256": AUTHORITY_SHA256,
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "expected_graceful_stop_decision_v1_sha256": DECISION_SHA256,
        "expected_statement_sha256": STATEMENT_SHA256,
        "expected_signature_sha256": SIGNATURE_SHA256,
    }


def _verify(
    artifacts: _Artifacts,
) -> workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt:
    _prepare(artifacts)
    return workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate(
        **_verify_kwargs(artifacts)  # type: ignore[arg-type]
    )


def _assert_error(reason_code: str, operation: Any, /, **kwargs: object) -> None:
    with pytest.raises(
        workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError
    ) as caught:
        operation(**kwargs)
    assert caught.value.reason_code == reason_code


def _replace_named_input(
    *,
    directory: Path,
    prefix: str,
    encoded: bytes,
    mode: int = 0o600,
) -> tuple[Path, str]:
    digest = hashlib.sha256(encoded).hexdigest()
    path = directory / f"{prefix}{digest}.json"
    _write_input(path, encoded, mode=mode)
    return path, digest


def _assert_common_receipt(payload: dict[str, object]) -> None:
    assert payload["contract_version"] == (
        "phase6d-post-enrollment-graceful-stop-operator-attestation-artifact-receipt-v1"
    )
    assert payload["service"] == (
        "trusted-time-post-enrollment-graceful-stop-operator-attestation-artifacts"
    )
    assert payload["authority_artifact_sha256"] == AUTHORITY_SHA256
    assert payload["public_key_sha256"] == PUBLIC_KEY_SHA256
    assert payload["graceful_stop_decision_v1_sha256"] == DECISION_SHA256
    assert payload["graceful_stop_operation_id"] == STOP_OPERATION_ID
    assert payload["graceful_stop_target_sha256"] == TARGET_SHA256
    assert payload["operator_attestation_statement_sha256"] == STATEMENT_SHA256
    assert payload["authority_material_source"] == "explicit_external_candidate"
    assert payload["structural_receipt_only"] is True
    assert payload["verification_only"] is True
    assert payload["later_atomic_stop_admission_revalidation_required"] is True
    for field_name in (
        "graceful_stop_decision_v1_semantically_qualified",
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "installed_authority_used",
    ):
        assert payload[field_name] is False
    assert all(
        payload[field_name] is False
        for field_name in (
            POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        )
    )


def test_fixed_public_vectors_are_exact_semantic_and_canonical(artifacts: _Artifacts) -> None:
    decision = decode_post_enrollment_graceful_stop_decision(artifacts.decision_encoded)

    assert len(artifacts.decision_encoded) == 12_668
    assert len(artifacts.decision_encoded) <= (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES
    )
    assert hashlib.sha256(artifacts.authority_encoded).hexdigest() == AUTHORITY_SHA256
    assert hashlib.sha256(PUBLIC_KEY).hexdigest() == PUBLIC_KEY_SHA256
    assert hashlib.sha256(artifacts.decision_encoded).hexdigest() == DECISION_SHA256
    assert decision.operation_id == STOP_OPERATION_ID
    assert decision.target.target_sha256 == TARGET_SHA256
    assert (
        canonical_post_enrollment_graceful_stop_decision_bytes(decision)
        == artifacts.decision_encoded
    )
    assert hashlib.sha256(artifacts.statement_encoded).hexdigest() == STATEMENT_SHA256
    assert hashlib.sha256(DETACHED_SIGNATURE).hexdigest() == SIGNATURE_SHA256
    assert (
        decode_post_enrollment_graceful_stop_operator_attestation_statement(
            artifacts.statement_encoded
        ).statement_sha256
        == STATEMENT_SHA256
    )


def test_prepare_retains_exact_statement_and_closed_public_receipt(
    artifacts: _Artifacts,
) -> None:
    receipt = _prepare(artifacts)
    payload = receipt.public_payload
    retained = artifacts.statement_directory / receipt.artifact_location

    assert type(receipt) is (
        workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatementReceipt
    )
    assert set(payload) == (
        workflow.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
    )
    assert len(payload) == 77
    _assert_common_receipt(payload)
    assert payload["status"] == (
        "graceful_stop_operator_attestation_statement_candidate_prepared_unqualified"
    )
    assert payload["operator_signature_authentication"] == "not_authenticated"
    assert receipt.artifact_location == retained.name
    assert "/" not in receipt.artifact_location
    assert retained.read_bytes() == artifacts.statement_encoded
    metadata = retained.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    for field_name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
        assert getattr(receipt, field_name) is False


def test_verify_authenticates_and_retains_exact_envelope_with_closed_receipt(
    artifacts: _Artifacts,
) -> None:
    receipt = _verify(artifacts)
    payload = receipt.public_payload
    retained = artifacts.envelope_directory / receipt.artifact_location
    envelope = decode_post_enrollment_graceful_stop_operator_attestation_envelope(
        retained.read_bytes()
    )

    assert type(receipt) is (
        workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelopeReceipt
    )
    assert set(payload) == (
        workflow.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
    )
    assert len(payload) == 79
    _assert_common_receipt(payload)
    assert payload["status"] == ("graceful_stop_operator_attestation_envelope_verified_unqualified")
    assert payload["operator_signature_authentication"] == "authenticated_unqualified"
    assert payload["detached_signature_sha256"] == SIGNATURE_SHA256
    assert payload["operator_attestation_envelope_sha256"] == envelope.envelope_sha256
    assert envelope.envelope_sha256 == ENVELOPE_SHA256
    assert receipt.artifact_location == retained.name
    assert retained.read_bytes() == envelope.encoded
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600
    assert retained.stat().st_nlink == 1
    authority = build_post_enrollment_graceful_stop_operator_authority(PUBLIC_KEY)
    verification = Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority(
        authority
    ).verify(envelope)
    assert verification.operator_attestation_envelope_sha256 == (
        receipt.operator_attestation_envelope_sha256
    )
    assert all(
        getattr(receipt, field_name) is False
        for field_name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    )


def test_exact_idempotent_retries_preserve_inode_and_receipts(
    artifacts: _Artifacts,
) -> None:
    statement_one = _prepare(artifacts)
    statement_path = artifacts.statement_directory / statement_one.artifact_location
    statement_identity = (statement_path.stat().st_dev, statement_path.stat().st_ino)
    statement_two = _prepare(artifacts)

    envelope_one = workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate(
        **_verify_kwargs(artifacts)  # type: ignore[arg-type]
    )
    envelope_path = artifacts.envelope_directory / envelope_one.artifact_location
    envelope_identity = (envelope_path.stat().st_dev, envelope_path.stat().st_ino)
    envelope_two = workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate(
        **_verify_kwargs(artifacts)  # type: ignore[arg-type]
    )

    assert statement_one == statement_two
    assert (statement_path.stat().st_dev, statement_path.stat().st_ino) == statement_identity
    assert envelope_one == envelope_two
    assert (envelope_path.stat().st_dev, envelope_path.stat().st_ino) == envelope_identity


@pytest.mark.parametrize("receipt_kind", ["statement", "envelope"])
def test_receipts_reject_construction_copy_pickle_replace_and_object_mutation(
    artifacts: _Artifacts,
    receipt_kind: str,
) -> None:
    receipt = _prepare(artifacts) if receipt_kind == "statement" else _verify(artifacts)
    receipt_type = type(receipt)
    values = {
        field_name: getattr(receipt, field_name)
        for field_name in receipt_type.__dataclass_fields__
        if field_name != "_sealed_fields"
    }

    _assert_error(
        f"{receipt_kind}_receipt_invalid",
        receipt_type,
        **values,
        _construction_capability=object(),
    )
    forged_type = type(f"Forged{receipt_type.__name__}", (receipt_type,), {})
    _assert_error(
        f"{receipt_kind}_receipt_invalid",
        forged_type,
        **values,
        _construction_capability=object(),
    )
    for operation in (
        copy.copy,
        copy.deepcopy,
        pickle.dumps,
        lambda value: replace(value, artifact_location=value.artifact_location),
    ):
        with pytest.raises(
            (
                TypeError,
                workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError,
            )
        ):
            operation(receipt)
    public_payload = receipt.public_payload
    public_payload["status"] = "tampered"
    assert receipt.public_payload["status"] != "tampered"
    object.__setattr__(receipt, "artifact_location", "tampered.json")
    with pytest.raises(
        workflow.TrustedTimePostEnrollmentGracefulStopOperatorAttestationArtifactError
    ):
        _ = receipt.public_payload


@pytest.mark.parametrize(
    ("field_name", "replacement", "reason_code"),
    [
        ("expected_authority_sha256", "A" * 64, "expected_authority_sha256_invalid"),
        ("expected_public_key_sha256", b"0" * 64, "expected_public_key_sha256_invalid"),
        (
            "expected_graceful_stop_decision_v1_sha256",
            "0" * 63,
            "expected_graceful_stop_decision_v1_sha256_invalid",
        ),
    ],
)
def test_prepare_rejects_invalid_expected_digests_before_io(
    artifacts: _Artifacts,
    field_name: str,
    replacement: object,
    reason_code: str,
) -> None:
    kwargs = _prepare_kwargs(artifacts)
    kwargs[field_name] = replacement
    _assert_error(
        reason_code,
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    [
        ("expected_authority_sha256", "authority_artifact_differs_from_review"),
        ("expected_public_key_sha256", "public_key_differs_from_review"),
        (
            "expected_graceful_stop_decision_v1_sha256",
            "graceful_stop_decision_v1_artifact_differs_from_review",
        ),
    ],
)
def test_prepare_rejects_review_digest_drift(
    artifacts: _Artifacts,
    field_name: str,
    reason_code: str,
) -> None:
    kwargs = _prepare_kwargs(artifacts)
    kwargs[field_name] = "0" * 64
    _assert_error(
        reason_code,
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


@pytest.mark.parametrize("mutation", ["leading-space", "duplicate-key", "target-drift"])
def test_prepare_rejects_noncanonical_duplicate_and_semantically_drifting_decisions(
    artifacts: _Artifacts,
    mutation: str,
) -> None:
    if mutation == "leading-space":
        encoded = b" " + artifacts.decision_encoded
    elif mutation == "duplicate-key":
        encoded = (
            b'{"contract_version":"phase6d-post-enrollment-graceful-stop-decision-v1",'
            + artifacts.decision_encoded[1:]
        )
    else:
        payload = cast(dict[str, object], json.loads(artifacts.decision_encoded))
        payload["graceful_stop_target_sha256"] = "0" * 64
        encoded = canonical_first_enrollment_json_bytes(payload)
    path, digest = _replace_named_input(
        directory=artifacts.input_directory,
        prefix=workflow.GRACEFUL_STOP_DECISION_V1_FILE_PREFIX,
        encoded=encoded,
    )
    kwargs = _prepare_kwargs(artifacts)
    kwargs["graceful_stop_decision_v1_artifact"] = path
    kwargs["expected_graceful_stop_decision_v1_sha256"] = digest

    _assert_error(
        "graceful_stop_decision_v1_artifact_invalid",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


def test_prepare_rejects_oversize_decision_before_decode(artifacts: _Artifacts) -> None:
    encoded = b"x" * (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES + 1
    )
    path, digest = _replace_named_input(
        directory=artifacts.input_directory,
        prefix=workflow.GRACEFUL_STOP_DECISION_V1_FILE_PREFIX,
        encoded=encoded,
    )
    kwargs = _prepare_kwargs(artifacts)
    kwargs["graceful_stop_decision_v1_artifact"] = path
    kwargs["expected_graceful_stop_decision_v1_sha256"] = digest
    _assert_error(
        "graceful_stop_decision_v1_artifact_unavailable",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


def test_prepare_rejects_start_protocol_authority_even_with_matching_review_hash(
    artifacts: _Artifacts,
) -> None:
    start_authority = canonical_post_enrollment_operator_authority_bytes(
        build_post_enrollment_operator_authority(PUBLIC_KEY)
    )
    path, digest = _replace_named_input(
        directory=artifacts.input_directory,
        prefix=workflow.AUTHORITY_CANDIDATE_FILE_PREFIX,
        encoded=start_authority,
    )
    kwargs = _prepare_kwargs(artifacts)
    kwargs["authority_artifact"] = path
    kwargs["expected_authority_sha256"] = digest
    _assert_error(
        "authority_artifact_invalid",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


def test_prepare_rejects_low_order_stop_authority(artifacts: _Artifacts) -> None:
    payload = cast(dict[str, object], json.loads(artifacts.authority_encoded))
    identity = b"\x01" + b"\x00" * 31
    payload["public_key_base64"] = base64.b64encode(identity).decode("ascii")
    payload["public_key_sha256"] = hashlib.sha256(identity).hexdigest()
    encoded = canonical_first_enrollment_json_bytes(payload)
    path, digest = _replace_named_input(
        directory=artifacts.input_directory,
        prefix=workflow.AUTHORITY_CANDIDATE_FILE_PREFIX,
        encoded=encoded,
    )
    kwargs = _prepare_kwargs(artifacts)
    kwargs["authority_artifact"] = path
    kwargs["expected_authority_sha256"] = digest
    kwargs["expected_public_key_sha256"] = hashlib.sha256(identity).hexdigest()
    _assert_error(
        "authority_artifact_invalid",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("path_field", "replacement", "reason_code"),
    [
        ("authority_artifact", Path("relative.json"), "authority_artifact_path_invalid"),
        (
            "graceful_stop_decision_v1_artifact",
            Path("relative.json"),
            "graceful_stop_decision_v1_artifact_path_invalid",
        ),
        (
            "statement_candidate_directory",
            Path("relative-directory"),
            "statement_candidate_directory_path_invalid",
        ),
    ],
)
def test_prepare_requires_explicit_absolute_paths(
    artifacts: _Artifacts,
    path_field: str,
    replacement: Path,
    reason_code: str,
) -> None:
    kwargs = _prepare_kwargs(artifacts)
    kwargs[path_field] = replacement
    _assert_error(
        reason_code,
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


@pytest.mark.parametrize("hazard", ["mode", "symlink", "hardlink", "repository"])
def test_prepare_rejects_unsafe_or_nonexternal_authority_inputs(
    artifacts: _Artifacts,
    hazard: str,
) -> None:
    kwargs = _prepare_kwargs(artifacts)
    if hazard == "mode":
        artifacts.authority_path.chmod(0o644)
    elif hazard == "symlink":
        link = artifacts.input_directory / "authority-link.json"
        link.symlink_to(artifacts.authority_path)
        kwargs["authority_artifact"] = link
    elif hazard == "hardlink":
        link = artifacts.input_directory / "authority-hardlink.json"
        os.link(artifacts.authority_path, link)
    else:
        kwargs["authority_artifact"] = Path(__file__).resolve()
    _assert_error(
        "authority_artifact_unavailable",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **kwargs,
    )


def test_prepare_requires_owner_only_output_directory(artifacts: _Artifacts) -> None:
    artifacts.statement_directory.chmod(0o755)
    _assert_error(
        "statement_candidate_directory_unavailable",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **_prepare_kwargs(artifacts),
    )


@pytest.mark.parametrize("mutation", ["noncanonical", "duplicate", "binding-drift"])
def test_verify_rejects_noncanonical_duplicate_and_rebound_statement(
    artifacts: _Artifacts,
    mutation: str,
) -> None:
    _prepare(artifacts)
    if mutation == "noncanonical":
        encoded = b" " + artifacts.statement_encoded
    elif mutation == "duplicate":
        encoded = b'{"algorithm":"Ed25519",' + artifacts.statement_encoded[1:]
    else:
        payload = cast(dict[str, object], json.loads(artifacts.statement_encoded))
        payload["graceful_stop_target_sha256"] = "0" * 64
        encoded = canonical_first_enrollment_json_bytes(payload)
    path, digest = _replace_named_input(
        directory=artifacts.input_directory,
        prefix=workflow.STATEMENT_CANDIDATE_FILE_PREFIX,
        encoded=encoded,
    )
    kwargs = _verify_kwargs(artifacts)
    kwargs["statement_artifact"] = path
    kwargs["expected_statement_sha256"] = digest
    _assert_error(
        (
            "statement_artifact_differs_from_review"
            if mutation == "binding-drift"
            else "statement_artifact_invalid"
        ),
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **kwargs,
    )


@pytest.mark.parametrize("signature", [b"x" * 63, b"x" * 65])
def test_verify_requires_exact_raw_signature_length(
    artifacts: _Artifacts,
    signature: bytes,
) -> None:
    _prepare(artifacts)
    path = artifacts.input_directory / "wrong-length.ed25519"
    _write_input(path, signature)
    kwargs = _verify_kwargs(artifacts)
    kwargs["detached_signature_file"] = path
    kwargs["expected_signature_sha256"] = hashlib.sha256(signature).hexdigest()
    _assert_error(
        "detached_signature_unavailable",
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **kwargs,
    )


def _signature_with_s_plus_l(signature: bytes) -> bytes:
    scalar = int.from_bytes(signature[32:], "little") + _ED25519_SCALAR_ORDER
    return signature[:32] + scalar.to_bytes(32, "little")


@pytest.mark.parametrize(
    "signature",
    [
        b"\x00" * 64,
        _signature_with_s_plus_l(DETACHED_SIGNATURE),
        (b"\x01" + b"\x00" * 31) + DETACHED_SIGNATURE[32:],
        (b"\x00" * 32) + DETACHED_SIGNATURE[32:],
    ],
)
def test_verify_rejects_tampered_malleable_and_low_order_signature_components(
    artifacts: _Artifacts,
    signature: bytes,
) -> None:
    _prepare(artifacts)
    path = artifacts.input_directory / "invalid-signature.ed25519"
    _write_input(path, signature)
    kwargs = _verify_kwargs(artifacts)
    kwargs["detached_signature_file"] = path
    kwargs["expected_signature_sha256"] = hashlib.sha256(signature).hexdigest()
    _assert_error(
        "operator_attestation_signature_verification_failed",
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **kwargs,
    )


def test_verify_rejects_signature_review_digest_drift(artifacts: _Artifacts) -> None:
    _prepare(artifacts)
    kwargs = _verify_kwargs(artifacts)
    kwargs["expected_signature_sha256"] = "0" * 64
    _assert_error(
        "detached_signature_differs_from_review",
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **kwargs,
    )


def test_verify_rejects_a_nonexact_verifier_result_before_using_it(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(artifacts)

    class _WrongVerifier:
        def verify(self, _: object) -> object:
            return object()

    monkeypatch.setattr(
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier,
        "from_authority",
        classmethod(lambda _cls, _authority: _WrongVerifier()),
    )
    _assert_error(
        "operator_attestation_signature_verification_failed",
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **_verify_kwargs(artifacts),
    )
    assert not any(artifacts.envelope_directory.iterdir())


@pytest.mark.parametrize(
    "phase",
    ["authority_artifact", "graceful_stop_decision_v1_artifact"],
)
def test_prepare_detects_each_input_revalidation_race(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    original = workflow._revalidate_external_binding
    attacked = False

    def race(binding: Any) -> None:
        nonlocal attacked
        if audited_fs._external_file_phase(binding) == phase and not attacked:
            attacked = True
            binding_path = Path(audited_fs._external_file_path(binding))
            metadata = binding_path.stat()
            os.utime(
                binding_path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns - 1_000_000_000),
            )
        original(binding)

    monkeypatch.setattr(workflow, "_revalidate_external_binding", race)
    _assert_error(
        f"{phase}_path_revalidation_failed",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **_prepare_kwargs(artifacts),
    )
    assert attacked is True


@pytest.mark.parametrize(
    "phase",
    [
        "authority_artifact",
        "graceful_stop_decision_v1_artifact",
        "statement_artifact",
        "detached_signature",
    ],
)
def test_verify_detects_each_input_revalidation_race(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    _prepare(artifacts)
    original = workflow._revalidate_external_binding
    attacked = False

    def race(binding: Any) -> None:
        nonlocal attacked
        if audited_fs._external_file_phase(binding) == phase and not attacked:
            attacked = True
            binding_path = Path(audited_fs._external_file_path(binding))
            metadata = binding_path.stat()
            os.utime(
                binding_path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns - 1_000_000_000),
            )
        original(binding)

    monkeypatch.setattr(workflow, "_revalidate_external_binding", race)
    _assert_error(
        f"{phase}_path_revalidation_failed",
        workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
        **_verify_kwargs(artifacts),
    )
    assert attacked is True


def test_publication_interruption_never_unlinks_partial_candidate(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = audited_fs._write_all

    def interrupt(
        owner: audited_fs._OwnedFileDescriptor,
        payload: bytes,
    ) -> None:
        original(owner, payload[:17])
        raise _AsyncInterruption

    monkeypatch.setattr(audited_fs, "_write_all", interrupt)
    with pytest.raises(_AsyncInterruption):
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate(
            **_prepare_kwargs(artifacts)  # type: ignore[arg-type]
        )
    path = artifacts.statement_directory / (
        f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{STATEMENT_SHA256}.json"
    )
    assert path.exists()
    assert path.read_bytes() == artifacts.statement_encoded[:17]

    monkeypatch.setattr(audited_fs, "_write_all", original)
    _assert_error(
        "statement_candidate_retention_unconfirmed",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **_prepare_kwargs(artifacts),
    )
    assert path.read_bytes() == artifacts.statement_encoded[:17]


def test_post_publish_rebind_interruption_retains_exact_idempotent_candidate(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = audited_fs._revalidate_external_published_file

    def interrupt(**_: object) -> tuple[int, ...]:
        raise _AsyncInterruption

    monkeypatch.setattr(audited_fs, "_revalidate_external_published_file", interrupt)
    with pytest.raises(_AsyncInterruption):
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate(
            **_prepare_kwargs(artifacts)  # type: ignore[arg-type]
        )
    path = artifacts.statement_directory / (
        f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{STATEMENT_SHA256}.json"
    )
    assert path.read_bytes() == artifacts.statement_encoded

    monkeypatch.setattr(audited_fs, "_revalidate_external_published_file", original)
    receipt = _prepare(artifacts)
    assert receipt.artifact_location == path.name


def test_publication_syncs_file_and_directory(
    artifacts: _Artifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = audited_fs._fsync
    synced: list[audited_fs._OwnedFileDescriptor] = []

    def observe(owner: audited_fs._OwnedFileDescriptor) -> None:
        synced.append(owner)
        original(owner)

    monkeypatch.setattr(audited_fs, "_fsync", observe)
    _prepare(artifacts)
    assert len(synced) >= 2


def test_conflicting_existing_candidate_is_preserved_and_never_overwritten(
    artifacts: _Artifacts,
) -> None:
    path = artifacts.statement_directory / (
        f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{STATEMENT_SHA256}.json"
    )
    _write_input(path, b"conflict")
    identity = (path.stat().st_dev, path.stat().st_ino)
    _assert_error(
        "statement_candidate_retention_unconfirmed",
        workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
        **_prepare_kwargs(artifacts),
    )
    assert path.read_bytes() == b"conflict"
    assert (path.stat().st_dev, path.stat().st_ino) == identity


def test_cli_prepare_and_verify_require_exact_long_flags_and_emit_canonical_receipts(
    artifacts: _Artifacts,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepare_argv = [
        "prepare-statement",
        "--authority-artifact",
        os.fspath(artifacts.authority_path),
        "--graceful-stop-decision-v1-artifact",
        os.fspath(artifacts.decision_path),
        "--statement-candidate-directory",
        os.fspath(artifacts.statement_directory),
        "--expected-authority-sha256",
        AUTHORITY_SHA256,
        "--expected-public-key-sha256",
        PUBLIC_KEY_SHA256,
        "--expected-graceful-stop-decision-v1-sha256",
        DECISION_SHA256,
    ]
    assert workflow.main(prepare_argv) == 0
    prepared = capsys.readouterr()
    prepared_payload = cast(dict[str, object], json.loads(prepared.out))
    assert set(prepared_payload) == (
        workflow.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
    )
    assert prepared.err == ""
    assert prepared.out.endswith("\n") and prepared.out.count("\n") == 1

    verify_argv = [
        "verify-signature",
        "--authority-artifact",
        os.fspath(artifacts.authority_path),
        "--graceful-stop-decision-v1-artifact",
        os.fspath(artifacts.decision_path),
        "--statement-artifact",
        os.fspath(
            artifacts.statement_directory
            / f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{STATEMENT_SHA256}.json"
        ),
        "--detached-signature-file",
        os.fspath(artifacts.signature_path),
        "--envelope-candidate-directory",
        os.fspath(artifacts.envelope_directory),
        "--expected-authority-sha256",
        AUTHORITY_SHA256,
        "--expected-public-key-sha256",
        PUBLIC_KEY_SHA256,
        "--expected-graceful-stop-decision-v1-sha256",
        DECISION_SHA256,
        "--expected-statement-sha256",
        STATEMENT_SHA256,
        "--expected-signature-sha256",
        SIGNATURE_SHA256,
    ]
    assert workflow.main(verify_argv) == 0
    verified = capsys.readouterr()
    verified_payload = cast(dict[str, object], json.loads(verified.out))
    assert set(verified_payload) == (
        workflow.POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
    )
    assert verified.err == ""
    assert verified.out.endswith("\n") and verified.out.count("\n") == 1

    abbreviated = prepare_argv.copy()
    abbreviated[1] = "--authority-art"
    assert workflow.main(abbreviated) == 2
    rejected = capsys.readouterr()
    assert rejected.out == ""
    assert rejected.err == "command_arguments_invalid\n"


def test_public_apis_are_keyword_only_and_module_has_no_signer_or_effect_surface() -> None:
    expected_prepare = [
        "authority_artifact",
        "graceful_stop_decision_v1_artifact",
        "statement_candidate_directory",
        "expected_authority_sha256",
        "expected_public_key_sha256",
        "expected_graceful_stop_decision_v1_sha256",
    ]
    expected_verify = [
        "authority_artifact",
        "graceful_stop_decision_v1_artifact",
        "statement_artifact",
        "detached_signature_file",
        "envelope_candidate_directory",
        "expected_authority_sha256",
        "expected_public_key_sha256",
        "expected_graceful_stop_decision_v1_sha256",
        "expected_statement_sha256",
        "expected_signature_sha256",
    ]
    for operation, names in (
        (
            workflow.prepare_post_enrollment_graceful_stop_operator_attestation_statement_candidate,
            expected_prepare,
        ),
        (
            workflow.verify_and_retain_post_enrollment_graceful_stop_operator_attestation_envelope_candidate,
            expected_verify,
        ),
    ):
        parameters = list(inspect.signature(operation).parameters.values())
        assert [parameter.name for parameter in parameters] == names
        assert all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in parameters)

    source = Path(workflow.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported_roots.isdisjoint(
        {
            "cryptography",
            "nacl",
            "subprocess",
            "socket",
            "sqlalchemy",
            "docker",
        }
    )
    assert "private_key" not in source
    assert "keygen" not in source
    assert ".sign(" not in source
    assert "os.environ" not in source
    assert "os.getenv" not in source
    assert "sys.stdin" not in source
    assert "Ed25519PostEnrollmentOperatorAttestationVerifier" not in source
    assert all("signer" not in name.lower() for name in workflow.__all__)
    assert "def _open_owned_descriptor" not in source
    assert "def _retain_exact_file" not in source
    assert "os.unlink" not in source
    assert ".unlink(" not in source
    assert "_audited_fs._external_file_encoded" in source
    assert "_audited_fs._external_file_path" in source
    assert "_audited_fs._read_external_binding" in source
    assert "_audited_fs._revalidate_external_binding" in source
    assert "_audited_fs._publish_candidate" in source
    assert (
        len(POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS) == 55
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
    )


def test_cli_runtime_guard_rejects_the_reusable_repository_interpreter() -> None:
    with pytest.raises(RuntimeError, match="CLI runtime attestation failed"):
        cast(Any, workflow)._require_isolated_cli_source_runtime(
            expected_relative_path=Path(
                "scripts/trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts.py"
            )
        )
