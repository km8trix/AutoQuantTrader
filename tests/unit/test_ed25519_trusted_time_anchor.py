from __future__ import annotations

import hashlib

import pytest

from packages.adapters.trusted_time.ed25519_anchor import (
    Ed25519TrustedTimeAnchorSigner,
    Ed25519TrustedTimeAnchorVerifier,
    TrustedTimeAnchorSigningError,
    ed25519_public_key_sha256,
)

KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
PRIVATE_KEY = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
MESSAGE = bytes.fromhex("72")
SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)


def _signer() -> Ed25519TrustedTimeAnchorSigner:
    return Ed25519TrustedTimeAnchorSigner.from_private_key_bytes(
        signing_key_id=KEY_ID,
        expected_signing_public_key_sha256=PUBLIC_KEY_SHA256,
        private_key_bytes=PRIVATE_KEY,
    )


def _verifier() -> Ed25519TrustedTimeAnchorVerifier:
    return Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
        signing_key_id=KEY_ID,
        expected_signing_public_key_sha256=PUBLIC_KEY_SHA256,
        public_key_bytes=PUBLIC_KEY,
    )


def test_rfc8032_vector_binds_exact_payload_and_key_identity() -> None:
    signature = _signer().sign_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=MESSAGE,
    )

    assert signature == SIGNATURE
    assert _verifier().verify_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=MESSAGE,
        signature=signature,
    )
    assert not _verifier().verify_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=b"s",
        signature=signature,
    )


def test_key_material_must_match_the_admitted_public_digest() -> None:
    with pytest.raises(TrustedTimeAnchorSigningError, match="conflicts"):
        Ed25519TrustedTimeAnchorSigner.from_private_key_bytes(
            signing_key_id=KEY_ID,
            expected_signing_public_key_sha256="0" * 64,
            private_key_bytes=PRIVATE_KEY,
        )
    with pytest.raises(TrustedTimeAnchorSigningError, match="conflicts"):
        Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
            signing_key_id=KEY_ID,
            expected_signing_public_key_sha256="0" * 64,
            public_key_bytes=PUBLIC_KEY,
        )


def test_verifier_rejects_cross_key_identity_and_invalid_signature_shape() -> None:
    verifier = _verifier()

    assert not verifier.verify_ed25519(
        signing_key_id="other-trusted-time-anchor-key-v1",
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=MESSAGE,
        signature=SIGNATURE,
    )
    assert not verifier.verify_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=MESSAGE,
        signature=b"short",
    )


def test_signer_repr_and_errors_never_disclose_private_key() -> None:
    signer = _signer()
    rendered = repr(signer)

    assert PRIVATE_KEY.hex() not in rendered
    assert "<redacted>" in rendered
    with pytest.raises(TrustedTimeAnchorSigningError) as captured:
        signer.sign_ed25519(
            signing_key_id=KEY_ID,
            signing_public_key_sha256=PUBLIC_KEY_SHA256,
            payload=b"",
        )
    assert PRIVATE_KEY.hex() not in str(captured.value)


def test_public_key_digest_requires_exact_raw_ed25519_bytes() -> None:
    assert ed25519_public_key_sha256(PUBLIC_KEY) == PUBLIC_KEY_SHA256
    with pytest.raises(TrustedTimeAnchorSigningError, match="public key"):
        ed25519_public_key_sha256(PUBLIC_KEY[:-1])
