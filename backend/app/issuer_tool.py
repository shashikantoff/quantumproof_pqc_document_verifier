"""Local issuer key generation and document signing utilities."""

import argparse
import getpass
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    SIGNATURE_ALGORITHM,
    CryptoProvider,
    b64decode,
    b64encode,
    document_claim,
    fingerprint,
)


KEY_FORMAT_VERSION = 1
KDF_ITERATIONS = 600_000
PASSPHRASE_MIN_LENGTH = 12
KEY_ASSOCIATED_DATA = b"QuantumProof issuer key/v1|ML-DSA-65|"


def _require_real_pqc(provider: CryptoProvider | None = None) -> CryptoProvider:
    provider = provider or CryptoProvider(allow_insecure_demo=True)
    if not provider.using_real_pqc or provider.signature_algorithm != SIGNATURE_ALGORITHM:
        raise RuntimeError(
            "real liboqs ML-DSA-65 support is required; development fallback keys are not accepted"
        )
    return provider


def _derive_encryption_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < PASSPHRASE_MIN_LENGTH:
        raise ValueError(
            f"passphrase must contain at least {PASSPHRASE_MIN_LENGTH} characters"
        )
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        KDF_ITERATIONS,
        dklen=32,
    )


def _write_json_once(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except (OSError, TypeError, ValueError):
        path.unlink(missing_ok=True)
        raise


def generate_key_file(
    output_path: Path,
    passphrase: str,
    provider: CryptoProvider | None = None,
) -> dict[str, str]:
    provider = _require_real_pqc(provider)
    key_pair = provider.create_signing_keypair()
    public_key_fingerprint = fingerprint(key_pair.public_key)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    encryption_key = _derive_encryption_key(passphrase, salt)
    encrypted_secret = AESGCM(encryption_key).encrypt(
        nonce,
        key_pair.secret_key,
        KEY_ASSOCIATED_DATA + public_key_fingerprint.encode("ascii"),
    )
    _write_json_once(
        output_path,
        {
            "format_version": KEY_FORMAT_VERSION,
            "algorithm": SIGNATURE_ALGORITHM,
            "key_fingerprint": public_key_fingerprint,
            "public_key_b64": b64encode(key_pair.public_key),
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": KDF_ITERATIONS,
            "salt_b64": b64encode(salt),
            "nonce_b64": b64encode(nonce),
            "encrypted_secret_key_b64": b64encode(encrypted_secret),
        },
    )
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_fingerprint": public_key_fingerprint,
        "public_key_b64": b64encode(key_pair.public_key),
        "key_file": str(output_path.resolve()),
    }


def sign_pdf(
    key_path: Path,
    pdf_path: Path,
    issuer_id: str,
    passphrase: str,
    provider: CryptoProvider | None = None,
) -> dict[str, str]:
    provider = _require_real_pqc(provider)
    issuer_id = issuer_id.strip()
    if not 2 <= len(issuer_id) <= 64:
        raise ValueError("issuer ID must contain between 2 and 64 characters")

    try:
        key_record = json.loads(key_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("issuer key file is not valid JSON") from exc
    if not isinstance(key_record, dict):
        raise ValueError("issuer key file has an invalid structure")
    if (
        key_record.get("format_version") != KEY_FORMAT_VERSION
        or key_record.get("algorithm") != SIGNATURE_ALGORITHM
        or key_record.get("kdf") != "PBKDF2-HMAC-SHA256"
        or key_record.get("kdf_iterations") != KDF_ITERATIONS
    ):
        raise ValueError("issuer key file format or algorithm is unsupported")

    try:
        public_key = b64decode(key_record["public_key_b64"])
        salt = b64decode(key_record["salt_b64"])
        nonce = b64decode(key_record["nonce_b64"])
        encrypted_secret = b64decode(key_record["encrypted_secret_key_b64"])
        stored_fingerprint = key_record["key_fingerprint"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("issuer key file is missing valid key material") from exc

    if not isinstance(stored_fingerprint, str) or len(stored_fingerprint) != 64:
        raise ValueError("issuer key file has an invalid public-key fingerprint")
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("issuer key file has invalid encryption parameters")
    if fingerprint(public_key) != stored_fingerprint:
        raise ValueError("issuer key file public-key fingerprint does not match")
    if not provider.is_valid_signing_public_key(public_key, SIGNATURE_ALGORITHM):
        raise ValueError("issuer key file contains an invalid ML-DSA-65 public key")

    encryption_key = _derive_encryption_key(passphrase, salt)
    try:
        secret_key = AESGCM(encryption_key).decrypt(
            nonce,
            encrypted_secret,
            KEY_ASSOCIATED_DATA + stored_fingerprint.encode("ascii"),
        )
    except InvalidTag as exc:
        raise ValueError("incorrect passphrase or damaged issuer key file") from exc

    test_claim = b"QuantumProof issuer key-pair check/v1"
    test_signature = provider.sign(test_claim, secret_key, SIGNATURE_ALGORITHM)
    if not provider.verify(test_claim, test_signature, public_key, SIGNATURE_ALGORITHM):
        raise ValueError("issuer private key does not match the stored public key")

    content = pdf_path.read_bytes()
    if not content.startswith(b"%PDF-"):
        raise ValueError("input file is not a PDF")
    document_hash = hashlib.sha256(content).hexdigest()
    signature = provider.sign(
        document_claim(document_hash),
        secret_key,
        SIGNATURE_ALGORITHM,
    )
    return {
        "issuer": issuer_id,
        "document_hash": document_hash,
        "signing_algorithm": SIGNATURE_ALGORITHM,
        "key_fingerprint": stored_fingerprint,
        "signing_public_key_b64": b64encode(public_key),
        "signature_b64": b64encode(signature),
    }


def _prompt_for_new_passphrase() -> str:
    passphrase = getpass.getpass("Create a key-file passphrase: ")
    confirmation = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirmation:
        raise ValueError("passphrases do not match")
    if len(passphrase) < PASSPHRASE_MIN_LENGTH:
        raise ValueError(
            f"passphrase must contain at least {PASSPHRASE_MIN_LENGTH} characters"
        )
    return passphrase


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and use issuer-held ML-DSA-65 signing keys locally."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser(
        "keygen",
        help="generate an encrypted local key file and print its public key",
    )
    keygen.add_argument("--output", required=True, type=Path)

    signing = commands.add_parser(
        "sign",
        help="sign a PDF locally and print registration fields as JSON",
    )
    signing.add_argument("--key", required=True, type=Path)
    signing.add_argument("--file", required=True, type=Path)
    signing.add_argument("--issuer", required=True)
    signing.add_argument("--output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "keygen":
            result = generate_key_file(args.output, _prompt_for_new_passphrase())
            print(f"Encrypted private-key file: {result['key_file']}")
            print(f"Algorithm: {result['algorithm']}")
            print(f"Key fingerprint: {result['key_fingerprint']}")
            print("Public key (Base64):")
            print(result["public_key_b64"])
            print("Keep the key file private. Share only the public key and fingerprint.")
        else:
            passphrase = getpass.getpass("Key-file passphrase: ")
            registration = sign_pdf(
                args.key,
                args.file,
                args.issuer,
                passphrase,
            )
            result_json = json.dumps(registration, indent=2)
            if args.output is None:
                print(result_json)
            else:
                _write_json_once(args.output, registration)
                print(f"Registration signature fields saved to {args.output.resolve()}")
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
