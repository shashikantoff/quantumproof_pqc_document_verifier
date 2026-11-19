"""Application-layer PQC primitives and a deliberately opt-in development fallback."""

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

oqs = None


SIGNATURE_ALGORITHM = "ML-DSA-65"
KEM_ALGORITHM = "ML-KEM-768"
FALLBACK_SIGNATURE_ALGORITHM = "DEVELOPMENT-ED25519"
FALLBACK_KEM_ALGORITHM = "DEVELOPMENT-X25519"


class PqcUnavailable(RuntimeError):
    pass


def document_claim(document_hash_hex: str) -> bytes:
    """Domain separation prevents this signature being repurposed elsewhere."""
    return b"PQC-DOCUMENT-VERIFY/v1|sha256:" + document_hash_hex.encode("ascii")


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64 value") from exc


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    kem_ciphertext: bytes
    kem_algorithm: str


class FileKeyStore:
    """Small persistent keystore for the demo. Replace with HSM/KMS in production."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def load(self, name: str) -> KeyPair | None:
        path = self.directory / f"{name}.json"
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return KeyPair(b64decode(payload["public_key"]), b64decode(payload["secret_key"]))

    def save(self, name: str, key_pair: KeyPair) -> None:
        path = self.directory / f"{name}.json"
        temp = self.directory / f".{name}.{os.getpid()}.tmp"
        temp.write_text(json.dumps({"public_key": b64encode(key_pair.public_key), "secret_key": b64encode(key_pair.secret_key)}), encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(path)


class CryptoProvider:
    """liboqs-backed ML-DSA / ML-KEM provider."""

    def __init__(self, allow_insecure_demo: bool = False):
        global oqs
        self.using_real_pqc = False
        if not allow_insecure_demo:
            try:
                import oqs as oqs_module
                oqs = oqs_module
                with oqs.Signature(SIGNATURE_ALGORITHM):
                    pass
                with oqs.KeyEncapsulation(KEM_ALGORITHM):
                    pass
                self.using_real_pqc = True
            except (ImportError, RuntimeError, AttributeError):
                self.using_real_pqc = False
        if not self.using_real_pqc and not allow_insecure_demo:
            raise PqcUnavailable(
                "liboqs-python is unavailable. Install liboqs or set ALLOW_INSECURE_DEMO_PQC=true for non-PQC UI development."
            )

    @property
    def signature_algorithm(self) -> str:
        return SIGNATURE_ALGORITHM if self.using_real_pqc else FALLBACK_SIGNATURE_ALGORITHM

    @property
    def kem_algorithm(self) -> str:
        return KEM_ALGORITHM if self.using_real_pqc else FALLBACK_KEM_ALGORITHM

    def create_signing_keypair(self) -> KeyPair:
        if self.using_real_pqc:
            with oqs.Signature(SIGNATURE_ALGORITHM) as signer:
                public_key = signer.generate_keypair()
                return KeyPair(public_key, signer.export_secret_key())
        private_key = ed25519.Ed25519PrivateKey.generate()
        return KeyPair(
            private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        )

    def sign(self, claim: bytes, secret_key: bytes, algorithm: str) -> bytes:
        if algorithm == SIGNATURE_ALGORITHM and self.using_real_pqc:
            with oqs.Signature(SIGNATURE_ALGORITHM, secret_key) as signer:
                return signer.sign(claim)
        if algorithm == FALLBACK_SIGNATURE_ALGORITHM:
            return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key).sign(claim)
        raise PqcUnavailable(f"cannot sign with {algorithm} in this runtime")

    def verify(self, claim: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
        try:
            if algorithm == SIGNATURE_ALGORITHM and self.using_real_pqc:
                with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:
                    return bool(verifier.verify(claim, signature, public_key))
            if algorithm == FALLBACK_SIGNATURE_ALGORITHM:
                ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, claim)
                return True
        except Exception:
            return False
        return False

    def is_valid_signing_public_key(self, public_key: bytes, algorithm: str) -> bool:
        if algorithm != self.signature_algorithm:
            return False
        if algorithm == SIGNATURE_ALGORITHM and self.using_real_pqc:
            with oqs.Signature(SIGNATURE_ALGORITHM) as signature:
                return len(public_key) == signature.details["length_public_key"]
        if algorithm == FALLBACK_SIGNATURE_ALGORITHM:
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            except ValueError:
                return False
            return True
        return False

    def create_kem_keypair(self) -> KeyPair:
        if self.using_real_pqc:
            with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
                public_key = kem.generate_keypair()
                return KeyPair(public_key, kem.export_secret_key())
        private_key = x25519.X25519PrivateKey.generate()
        return KeyPair(
            private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        )

    def encrypt_for_recipient(self, plaintext: bytes, recipient_public_key: bytes) -> EncryptedPayload:
        if self.using_real_pqc:
            with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
            kem_algorithm = KEM_ALGORITHM
        else:
            ephemeral = x25519.X25519PrivateKey.generate()
            peer = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
            shared_secret = ephemeral.exchange(peer)
            kem_ciphertext = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            kem_algorithm = FALLBACK_KEM_ALGORITHM
        key = hashlib.sha256(b"PQC-DOC-AES-KEY/v1" + shared_secret).digest()
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"PQC-DOCUMENT-VERIFY/v1")
        return EncryptedPayload(ciphertext, nonce, kem_ciphertext, kem_algorithm)

    def decrypt_for_recipient(self, payload: EncryptedPayload, recipient_secret_key: bytes) -> bytes:
        if payload.kem_algorithm == KEM_ALGORITHM and self.using_real_pqc:
            with oqs.KeyEncapsulation(KEM_ALGORITHM, recipient_secret_key) as kem:
                shared_secret = kem.decap_secret(payload.kem_ciphertext)
        elif payload.kem_algorithm == FALLBACK_KEM_ALGORITHM:
            private_key = x25519.X25519PrivateKey.from_private_bytes(recipient_secret_key)
            shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(payload.kem_ciphertext))
        else:
            raise PqcUnavailable(f"cannot decrypt {payload.kem_algorithm} in this runtime")
        key = hashlib.sha256(b"PQC-DOC-AES-KEY/v1" + shared_secret).digest()
        return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, b"PQC-DOCUMENT-VERIFY/v1")


def load_or_create_keys(store: FileKeyStore, provider: CryptoProvider, name: str, kind: str) -> KeyPair:
    key_pair = store.load(name)
    if key_pair is None:
        key_pair = provider.create_signing_keypair() if kind == "signature" else provider.create_kem_keypair()
        store.save(name, key_pair)
    return key_pair
