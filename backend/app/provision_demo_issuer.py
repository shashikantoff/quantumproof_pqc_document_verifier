"""Provision the local demo issuer against the configured application database."""

import argparse

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .crypto import (
    CryptoProvider,
    FileKeyStore,
    fingerprint,
    load_or_create_keys,
)
from .database import Issuer, make_engine
from .migrations import run_migrations


DEFAULT_ISSUER_ID = "university-issuing-authority-v1"
DEFAULT_ORGANIZATION = "University Issuing Authority"


def ensure_demo_issuer(
    session: Session,
    issuer_id: str,
    organization: str,
    public_key: bytes,
    signing_algorithm: str,
) -> bool:
    key_fingerprint = fingerprint(public_key)
    issuer = session.execute(
        select(Issuer).where(Issuer.issuer_id == issuer_id)
    ).scalar_one_or_none()

    if issuer is not None:
        if (
            issuer.key_fingerprint != key_fingerprint
            or issuer.organization != organization
            or issuer.signing_algorithm != signing_algorithm
        ):
            raise ValueError(
                f"issuer {issuer_id!r} already exists with different registration data"
            )
        if issuer.status != "ACTIVE":
            raise ValueError(f"issuer {issuer_id!r} is not active")
        return False

    key_owner = session.execute(
        select(Issuer.issuer_id).where(
            Issuer.key_fingerprint == key_fingerprint
        )
    ).scalar_one_or_none()
    if key_owner is not None:
        raise ValueError(
            f"this signing key is already registered to issuer {key_owner!r}"
        )

    session.add(
        Issuer(
            issuer_id=issuer_id,
            organization=organization,
            public_key=public_key,
            key_fingerprint=key_fingerprint,
            signing_algorithm=signing_algorithm,
            status="ACTIVE",
        )
    )
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Register the persisted demo signing key as an issuer."
    )
    parser.add_argument("--issuer-id", default=DEFAULT_ISSUER_ID)
    parser.add_argument("--organization", default=DEFAULT_ORGANIZATION)
    args = parser.parse_args()

    settings = get_settings()
    crypto = CryptoProvider(settings.allow_insecure_demo_pqc)
    issuer_keys = load_or_create_keys(
        FileKeyStore(settings.keystore_path),
        crypto,
        "demo_issuer_ml_dsa",
        "signature",
    )
    engine = make_engine(settings)
    try:
        run_migrations(engine)
        sessions: sessionmaker[Session] = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
        with sessions() as session:
            created = ensure_demo_issuer(
                session,
                args.issuer_id,
                args.organization,
                issuer_keys.public_key,
                crypto.signature_algorithm,
            )
            session.commit()
    finally:
        engine.dispose()

    state = "registered" if created else "already registered"
    print(
        f"Demo issuer {args.issuer_id!r} {state}; "
        f"key fingerprint: {fingerprint(issuer_keys.public_key)}"
    )


if __name__ == "__main__":
    main()
