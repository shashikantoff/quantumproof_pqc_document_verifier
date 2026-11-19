from pathlib import Path

import pytest

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover
    from starlette.testclient import TestClient

from app.config import Settings
from app.crypto import fingerprint
from app.database import Issuer
from app.main import create_app


@pytest.fixture()
def client(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        keystore_path=tmp_path / "keys",
        allow_insecure_demo_pqc=False,
        public_base_url="http://testserver",
        admin_id="test-admin",
        admin_password="test-password",
    )
    with TestClient(create_app(settings)) as test_client:
        login = test_client.post(
            "/api/v1/auth/login",
            data={"admin_id": "test-admin", "password": "test-password"},
        )
        assert login.status_code == 200, login.text

        runtime = test_client.app.state.runtime
        with runtime.sessions() as session:
            session.add(
                Issuer(
                    issuer_id="Example University",
                    organization="Example University",
                    public_key=runtime.issuer_keys.public_key,
                    key_fingerprint=fingerprint(runtime.issuer_keys.public_key),
                    signing_algorithm=runtime.crypto.signature_algorithm,
                    status="ACTIVE",
                )
            )
            session.commit()

        yield test_client
