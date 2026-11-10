"""Ed25519 signing and verification for external trusted-head checkpoints."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_ED25519_ANCHOR_SIGNED_BYTES = 4_096

_KEY_ID = re.compile(r"[a-z][a-z0-9._:-]{7,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class TrustedTimeAnchorSigningError(RuntimeError):
    """The admitted signing identity or operation failed closed."""


def _require_key_id(value: object) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise TrustedTimeAnchorSigningError("trusted-time anchor signing-key identity is invalid")
    return value


def _require_sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedTimeAnchorSigningError(
            "trusted-time anchor signing public-key digest is invalid"
        )
    return value


def _require_payload(value: object) -> bytes:
    if type(value) is not bytes or not value or len(value) > MAX_ED25519_ANCHOR_SIGNED_BYTES:
        raise TrustedTimeAnchorSigningError("trusted-time anchor signing payload is invalid")
    return value


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_key_sha256(public_key_bytes: bytes) -> str:
    """Return the admitted identity of one exact raw Ed25519 public key."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise TrustedTimeAnchorSigningError("trusted-time anchor public key is invalid")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (TypeError, ValueError):
        raise TrustedTimeAnchorSigningError("trusted-time anchor public key is invalid") from None
    return hashlib.sha256(_public_key_bytes(public_key)).hexdigest()


@dataclass(frozen=True, slots=True)
class Ed25519TrustedTimeAnchorSigner:
    """Process-local signer whose private key is never exposed or represented."""

    signing_key_id: str
    signing_public_key_sha256: str
    _private_key: Ed25519PrivateKey = field(repr=False, compare=False)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        signing_key_id: str,
        expected_signing_public_key_sha256: str,
        private_key_bytes: bytes,
    ) -> Ed25519TrustedTimeAnchorSigner:
        key_id = _require_key_id(signing_key_id)
        expected = _require_sha256(expected_signing_public_key_sha256)
        if type(private_key_bytes) is not bytes or len(private_key_bytes) != 32:
            raise TrustedTimeAnchorSigningError("trusted-time anchor private key is invalid")
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        except (TypeError, ValueError):
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor private key is invalid"
            ) from None
        observed = hashlib.sha256(_public_key_bytes(private_key.public_key())).hexdigest()
        if observed != expected:
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor private key conflicts with admitted public key"
            )
        return cls(
            signing_key_id=key_id,
            signing_public_key_sha256=expected,
            _private_key=private_key,
        )

    def sign_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes:
        if (
            _require_key_id(signing_key_id) != self.signing_key_id
            or _require_sha256(signing_public_key_sha256) != self.signing_public_key_sha256
        ):
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor signing request crossed admitted key identity"
            )
        exact_payload = _require_payload(payload)
        try:
            signature = self._private_key.sign(exact_payload)
        except Exception:
            raise TrustedTimeAnchorSigningError("trusted-time anchor signing failed") from None
        if type(signature) is not bytes or len(signature) != 64:
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor signing returned an invalid signature"
            )
        return signature

    def __repr__(self) -> str:
        return (
            "Ed25519TrustedTimeAnchorSigner("
            f"signing_key_id={self.signing_key_id!r}, "
            f"signing_public_key_sha256={self.signing_public_key_sha256!r}, "
            "private_key=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class Ed25519TrustedTimeAnchorVerifier:
    """Exact admitted public-key verifier for downloaded anchor objects."""

    signing_key_id: str
    signing_public_key_sha256: str
    _public_key: Ed25519PublicKey = field(repr=False, compare=False)

    @classmethod
    def from_public_key_bytes(
        cls,
        *,
        signing_key_id: str,
        expected_signing_public_key_sha256: str,
        public_key_bytes: bytes,
    ) -> Ed25519TrustedTimeAnchorVerifier:
        key_id = _require_key_id(signing_key_id)
        expected = _require_sha256(expected_signing_public_key_sha256)
        if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
            raise TrustedTimeAnchorSigningError("trusted-time anchor public key is invalid")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except (TypeError, ValueError):
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor public key is invalid"
            ) from None
        observed = hashlib.sha256(_public_key_bytes(public_key)).hexdigest()
        if observed != expected:
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor public key conflicts with admitted digest"
            )
        return cls(
            signing_key_id=key_id,
            signing_public_key_sha256=expected,
            _public_key=public_key,
        )

    def verify_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        if (
            _require_key_id(signing_key_id) != self.signing_key_id
            or _require_sha256(signing_public_key_sha256) != self.signing_public_key_sha256
        ):
            return False
        exact_payload = _require_payload(payload)
        if type(signature) is not bytes or len(signature) != 64:
            return False
        try:
            self._public_key.verify(signature, exact_payload)
        except InvalidSignature:
            return False
        except Exception:
            raise TrustedTimeAnchorSigningError(
                "trusted-time anchor signature verification failed"
            ) from None
        return True


__all__ = [
    "MAX_ED25519_ANCHOR_SIGNED_BYTES",
    "Ed25519TrustedTimeAnchorSigner",
    "Ed25519TrustedTimeAnchorVerifier",
    "TrustedTimeAnchorSigningError",
    "ed25519_public_key_sha256",
]
