from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover
    from starlette.testclient import TestClient

from app.config import Settings
from app.database import AdminUser, Base
from app.ledger import LedgerError
from app.main import create_app
from app.migrations import run_migrations


def test_admin_session_cookie_has_secure_attributes_when_enabled(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'cookie.db'}",
        keystore_path=tmp_path / "keys",
        allow_insecure_demo_pqc=True,
        admin_id="cookie-admin",
        admin_password="cookie-password",
        admin_cookie_secure=True,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/api/v1/auth/login",
            data={"admin_id": "cookie-admin", "password": "cookie-password"},
        )

    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie


def test_admin_login_is_rate_limited_and_reports_retry_after(client):
    headers = {"X-Real-IP": "198.51.100.20"}
    limit = client.app.state.runtime.settings.admin_login_attempt_limit

    for _ in range(limit):
        response = client.post(
            "/api/v1/auth/login",
            data={"admin_id": "test-admin", "password": "incorrect"},
            headers=headers,
        )
        assert response.status_code == 401

    blocked = client.post(
        "/api/v1/auth/login",
        data={"admin_id": "test-admin", "password": "test-password"},
        headers=headers,
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


def test_admin_mutation_rejects_cross_origin_request(client):
    response = client.post(
        "/api/v1/admin/documents/unknown/reconcile",
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_admin_login_rejects_cross_origin_request(client):
    response = client.post(
        "/api/v1/auth/login",
        data={"admin_id": "test-admin", "password": "test-password"},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_health_reports_database_and_ledger_readiness(client):
    health = client.get("/health/ready")
    assert health.status_code == 200
    assert health.json()["components"] == {"database": "up", "ledger": "up"}

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert 'quantumproof_dependency_up{dependency="database"} 1' in metrics.text
    assert 'quantumproof_dependency_up{dependency="ledger"} 1' in metrics.text


def test_ledger_failure_marks_readiness_unhealthy_but_not_liveness(client):
    class UnavailableLedger:
        name = "test-ledger"

        def read(self, document_id: str):
            raise LedgerError("ledger is unavailable")

    runtime = client.app.state.runtime
    original_ledger = runtime.ledger
    runtime.ledger = UnavailableLedger()
    try:
        ready = client.get("/health/ready")
        live = client.get("/health/live")
    finally:
        runtime.ledger = original_ledger

    assert ready.status_code == 503
    assert ready.json()["components"] == {"database": "up", "ledger": "down"}
    assert live.status_code == 200


def test_migrations_upgrade_a_fresh_database(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    try:
        run_migrations(engine)
        inspector = inspect(engine)
        assert "alembic_version" in inspector.get_table_names()
        assert "login_rate_limits" in inspector.get_table_names()
        with engine.connect() as connection:
            version = connection.scalar(text("SELECT version_num FROM alembic_version"))
        assert version == "0002_login_rate_limits"
    finally:
        engine.dispose()


def test_migrations_adopt_legacy_schema_without_losing_admins(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    try:
        for table in Base.metadata.sorted_tables:
            if table.name != "login_rate_limits":
                table.create(engine)

        with Session(engine) as session:
            session.add(
                AdminUser(
                    admin_id="preserved-admin",
                    password_hash="existing-hash",
                )
            )
            session.commit()

        run_migrations(engine)

        with Session(engine) as session:
            admin = session.scalar(
                select(AdminUser).where(AdminUser.admin_id == "preserved-admin")
            )
            assert admin is not None
            assert admin.password_hash == "existing-hash"
        assert "login_rate_limits" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_migrations_refuse_to_adopt_partial_legacy_schema(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'partial.db'}")
    try:
        Base.metadata.tables["admin_users"].create(engine)
        with pytest.raises(RuntimeError, match="partial legacy schema"):
            run_migrations(engine)
    finally:
        engine.dispose()
