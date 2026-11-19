from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./verifier.db"
    ledger_backend: str = "development"
    fabric_gateway_url: str | None = None
    fabric_gateway_token: str | None = None

    # Admin login configuration.
    # ADMIN_PASSWORD is only used to bootstrap the first admin account;
    # the database stores a password hash, never the plaintext password.
    admin_id: str = "admin"
    admin_password: str | None = None
    admin_session_hours: int = Field(default=8, ge=1, le=168)
    admin_login_attempt_limit: int = Field(default=5, ge=1, le=20)
    admin_login_window_seconds: int = Field(default=900, ge=60, le=86400)
    # Set true whenever QuantumProof is served over HTTPS. Keep false only for
    # the local HTTP demo at http://localhost:8080.
    admin_cookie_secure: bool = False

    keystore_path: Path = Path("./secrets")
    allow_insecure_demo_pqc: bool = False
    max_document_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    cors_origins: str = "http://localhost:8080"
    public_base_url: str = "http://localhost:8080"

    @property
    def allowed_origins(self) -> list[str]:
        return [value.strip() for value in self.cors_origins.split(",") if value.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
