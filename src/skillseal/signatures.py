"""Ed25519 manifest signing and verification."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .core import SealError, _canonical


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SealError(f"cannot load unencrypted Ed25519 private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SealError("private key must be Ed25519 PEM")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise SealError(f"cannot load Ed25519 public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SealError("public key must be Ed25519 PEM")
    return key


def public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_fingerprint(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_bytes(key)).hexdigest()


def add_signature(manifest: dict, key: Ed25519PrivateKey) -> dict:
    signed = dict(manifest)
    pub = key.public_key()
    signed["signature"] = {
        "algorithm": "ed25519",
        "public_key": base64.b64encode(public_bytes(pub)).decode("ascii"),
        "public_key_sha256": key_fingerprint(pub),
        "value": base64.b64encode(key.sign(_canonical(manifest))).decode("ascii"),
    }
    return signed


def verify_signature(manifest: dict, trusted_key: Ed25519PublicKey | None = None) -> tuple[bool, str | None]:
    signature = manifest.get("signature")
    if signature is None:
        if trusted_key is not None:
            raise SealError("trusted public key provided, but manifest is unsigned")
        return False, None
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "public_key", "public_key_sha256", "value"} or signature.get("algorithm") != "ed25519":
        raise SealError("malformed or unsupported manifest signature")
    try:
        embedded_bytes = base64.b64decode(signature["public_key"], validate=True)
        sig_bytes = base64.b64decode(signature["value"], validate=True)
        embedded = Ed25519PublicKey.from_public_bytes(embedded_bytes)
    except (ValueError, TypeError) as exc:
        raise SealError("malformed Ed25519 signature data") from exc
    fingerprint = key_fingerprint(embedded)
    if signature["public_key_sha256"] != fingerprint:
        raise SealError("manifest public-key fingerprint mismatch")
    if trusted_key is not None and key_fingerprint(trusted_key) != fingerprint:
        raise SealError("manifest was signed by a different key than the trusted public key")
    unsigned = dict(manifest)
    del unsigned["signature"]
    try:
        embedded.verify(sig_bytes, _canonical(unsigned))
    except InvalidSignature as exc:
        raise SealError("manifest signature is invalid") from exc
    return True, fingerprint


def generate_keypair(private_path: Path, public_path: Path) -> None:
    if private_path.expanduser().absolute() == public_path.expanduser().absolute():
        raise SealError("private and public key paths must be different")
    if private_path.exists() or public_path.exists():
        raise SealError("key file already exists; choose new paths")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Exclusive creation prevents accidental replacement. Private key permissions are owner-only on POSIX.
    try:
        import os
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        private_fd = os.open(private_path, flags, 0o600 if os.name == "posix" else 0o666)
    except FileExistsError as exc:
        raise SealError("private-key file already exists") from exc
    try:
        with os.fdopen(private_fd, "wb") as stream:
            stream.write(private_pem)
            stream.flush()
            os.fsync(stream.fileno())
        with public_path.open("xb") as stream:
            stream.write(public_pem)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            private_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise SealError(f"could not write key pair: {exc}") from exc
