"""Keep the demo issuer in sync with the server's current demo signing key.

For demos on hosts with an ephemeral disk (e.g. Render free), the server's demo
ML-DSA key is regenerated whenever the container restarts. This script runs
before the API starts and makes sure the issuer row in the database matches the
key the server will actually sign with, so "issuer is not registered" and
"configured issuer key does not match issuer registry" cannot occur.

Demo/evaluation use only. Do not use for production issuers.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .crypto import CryptoProvider, FileKeyStore, fingerprint, load_or_create_keys
from .database import Issuer, make_engine
from .migrations import run_migrations
from .provision_demo_issuer import DEFAULT_ISSUER_ID, DEFAULT_ORGANIZATION


def main() -> None:
    settings = get_settings()
    crypto = CryptoProvider(settings.allow_insecure_demo_pqc)
    issuer_keys = load_or_create_keys(
        FileKeyStore(settings.keystore_path),
        crypto,
        "demo_issuer_ml_dsa",
        "signature",
    )
    new_fingerprint = fingerprint(issuer_keys.public_key)

    engine = make_engine(settings)
    try:
        run_migrations(engine)
        sessions: sessionmaker[Session] = sessionmaker(
            bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        with sessions() as session:
            issuer = session.execute(
                select(Issuer).where(Issuer.issuer_id == DEFAULT_ISSUER_ID)
            ).scalar_one_or_none()

            if issuer is None:
                session.add(
                    Issuer(
                        issuer_id=DEFAULT_ISSUER_ID,
                        organization=DEFAULT_ORGANIZATION,
                        public_key=issuer_keys.public_key,
                        key_fingerprint=new_fingerprint,
                        signing_algorithm=crypto.signature_algorithm,
                        status="ACTIVE",
                    )
                )
                state = "created"
            elif issuer.key_fingerprint != new_fingerprint:
                issuer.public_key = issuer_keys.public_key
                issuer.key_fingerprint = new_fingerprint
                issuer.signing_algorithm = crypto.signature_algorithm
                issuer.status = "ACTIVE"
                state = "key updated"
            else:
                state = "already in sync"
            session.commit()
    finally:
        engine.dispose()

    print(f"Demo issuer {DEFAULT_ISSUER_ID!r} {state}; key fingerprint: {new_fingerprint}")


if __name__ == "__main__":
    main()
