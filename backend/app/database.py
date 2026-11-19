from datetime import datetime

from sqlalchemy import DateTime, Engine, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import Settings


class Base(DeclarativeBase):
    pass



class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    admin_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    admin_user_id: Mapped[int] = mapped_column(ForeignKey("admin_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    admin_user: Mapped["AdminUser"] = relationship()


class LoginRateLimit(Base):
    __tablename__ = "login_rate_limits"

    bucket_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Issuer(Base):
    __tablename__ = "issuers"

    issuer_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization: Mapped[str] = mapped_column(String(160), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    signing_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class IssuerAuditEvent(Base):
    __tablename__ = "issuer_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    issuer_id: Mapped[str] = mapped_column(ForeignKey("issuers.issuer_id"), index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_hint: Mapped[str] = mapped_column(String(160), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    previous_key_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_key_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    issuer: Mapped[str] = mapped_column(String(160))
    mime_type: Mapped[str] = mapped_column(String(120), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer)
    document_hash: Mapped[str] = mapped_column(String(64), index=True)
    signature: Mapped[bytes] = mapped_column(LargeBinary)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary)
    signing_algorithm: Mapped[str] = mapped_column(String(64))
    key_fingerprint: Mapped[str] = mapped_column(String(64))
    kem_algorithm: Mapped[str] = mapped_column(String(64))
    kem_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    encryption_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted_document: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    ledger_transaction_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ledger_block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    revocation_transaction_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="document", cascade="all, delete-orphan")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    result: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(Text, default="")
    actor_hint: Mapped[str] = mapped_column(String(160), default="anonymous")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    document: Mapped[Document] = relationship(back_populates="audit_events")


class DevelopmentLedgerRecord(Base):
    """Durable development substitute, never advertised as a blockchain record."""

    __tablename__ = "development_ledger_records"
    __table_args__ = (UniqueConstraint("document_id", name="uq_development_ledger_document"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(String(36), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    transaction_id: Mapped[str] = mapped_column(String(128), unique=True)
    block_number: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


def make_engine(settings: Settings):
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    return create_engine(settings.database_url, future=True, pool_pre_ping=True, connect_args=connect_args)


def make_session_factory(settings: Settings, engine: Engine | None = None):
    return sessionmaker(
        bind=engine or make_engine(settings),
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
