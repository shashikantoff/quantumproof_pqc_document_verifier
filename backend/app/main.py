import hashlib
import hmac
import io
import secrets
import threading
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Generator, Literal
from urllib.parse import urlsplit

import qrcode
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Response,
    HTTPException,
    Request,
    UploadFile,
    Query,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from .benchmarks import run_benchmark
from .config import Settings, get_settings
from .crypto import (
    CryptoProvider,
    EncryptedPayload,
    FileKeyStore,
    PqcUnavailable,
    b64decode,
    document_claim,
    fingerprint,
    load_or_create_keys,
)
from .database import (
    AdminSession,
    AdminUser,
    AuditEvent,
    Document,
    Issuer,
    IssuerAuditEvent,
    LoginRateLimit,
    make_engine,
    make_session_factory,
)
from .ledger import LedgerAdapter, LedgerError, make_ledger
from .migrations import run_migrations


_REQUEST_METRICS: Counter[tuple[str, str, int]] = Counter()
_REQUEST_METRICS_LOCK = threading.Lock()


# ============================================================
# RUNTIME
# ============================================================


@dataclass
class Runtime:
    settings: Settings
    sessions: sessionmaker[Session]
    crypto: CryptoProvider
    issuer_keys: object
    archive_keys: object
    ledger: LedgerAdapter


# ============================================================
# RESPONSE MODELS
# ============================================================


class RegistrationResponse(BaseModel):
    document_id: str
    document_hash: str
    signing_algorithm: str
    kem_algorithm: str
    key_fingerprint: str
    ledger_backend: str
    transaction_id: str
    block_number: int | None
    verification_url: str


class VerificationResponse(BaseModel):
    document_id: str
    overall_status: str
    document_hash_matches: bool
    signature_valid: bool
    ledger_valid: bool
    ledger_backend: str
    transaction_id: str | None
    detail: str


class BenchmarkRequest(BaseModel):
    iterations: int = Field(
        default=100,
        ge=100,
        le=5000,
    )
    warmup: int = Field(
        default=30,
        ge=0,
        le=1000,
    )


class IssuerEnrollmentRequest(BaseModel):
    issuer_id: str = Field(min_length=2, max_length=64)
    organization: str = Field(min_length=2, max_length=160)
    public_key_b64: str = Field(min_length=1, max_length=8192)
    expires_at: datetime | None = None


class IssuerKeyRotationRequest(BaseModel):
    public_key_b64: str = Field(min_length=1, max_length=8192)
    expires_at: datetime | None = None


class IssuerStatusRequest(BaseModel):
    status: Literal["ACTIVE", "SUSPENDED"]


# ============================================================
# HELPERS
# ============================================================


def _runtime(request: Request) -> Runtime:
    return request.app.state.runtime


def _validated_issuer_expiration(expires_at: datetime | None) -> datetime | None:
    if expires_at is None:
        return None
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail="issuer expiration must include a timezone",
        )
    normalized = expires_at.astimezone(timezone.utc)
    if normalized <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=422,
            detail="issuer expiration must be in the future",
        )
    return normalized


def _issuer_public_key(
    encoded_key: str,
    algorithm: str,
    runtime: Runtime,
) -> bytes:
    try:
        public_key = b64decode(encoded_key.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="issuer public key must be valid base64",
        ) from exc

    if not runtime.crypto.is_valid_signing_public_key(public_key, algorithm):
        raise HTTPException(
            status_code=422,
            detail="issuer public key is invalid for the configured signing algorithm",
        )
    return public_key


def _issuer_history_event(
    session: Session,
    issuer_id: str,
    action: str,
    actor: str,
    *,
    previous_status: str | None = None,
    new_status: str | None = None,
    previous_key_fingerprint: str | None = None,
    new_key_fingerprint: str | None = None,
    detail: str = "",
) -> None:
    session.add(
        IssuerAuditEvent(
            issuer_id=issuer_id,
            action=action,
            actor_hint=actor[:160],
            previous_status=previous_status,
            new_status=new_status,
            previous_key_fingerprint=previous_key_fingerprint,
            new_key_fingerprint=new_key_fingerprint,
            detail=detail,
        )
    )


# ============================================================
# ADMIN AUTHENTICATION
# ============================================================


ADMIN_SESSION_COOKIE = "quantumproof_admin_session"
PASSWORD_ITERATIONS = 310_000


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations_text, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _session_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bootstrap_admin(session: Session, settings: Settings) -> None:
    admin = session.execute(
        select(AdminUser).where(AdminUser.admin_id == settings.admin_id)
    ).scalar_one_or_none()

    if admin is not None:
        return

    if not settings.admin_password:
        raise RuntimeError(
            "ADMIN_PASSWORD must be configured before the first QuantumProof admin login."
        )

    admin = AdminUser(
        admin_id=settings.admin_id,
        password_hash=_hash_password(settings.admin_password),
        is_active=True,
    )
    session.add(admin)
    session.commit()


def _get_current_admin(request: Request, session: Session) -> AdminUser | None:
    raw_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not raw_token:
        return None

    admin_session = session.execute(
        select(AdminSession).where(
            AdminSession.session_token_hash == _session_hash(raw_token),
            AdminSession.revoked_at.is_(None),
        )
    ).scalar_one_or_none()

    if admin_session is None:
        return None

    now = datetime.now(timezone.utc)
    expires_at = admin_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        admin_session.revoked_at = now
        session.commit()
        return None

    admin = session.get(AdminUser, admin_session.admin_user_id)
    if admin is None or not admin.is_active:
        return None

    return admin


# ============================================================
# DATABASE SESSION
# ============================================================


def get_session(
    request: Request,
) -> Generator[Session, None, None]:

    session = _runtime(request).sessions()

    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


def require_admin(
    request: Request,
    session: SessionDep,
) -> AdminUser:
    admin = _get_current_admin(request, session)
    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="admin login is required",
    )
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        _require_same_origin(request)
    return admin


def _require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is None:
        referer = request.headers.get("referer")
        if referer:
            parsed = urlsplit(referer)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        else:
            return

    allowed_origins = {
        value.rstrip("/") for value in request.app.state.runtime.settings.allowed_origins
    }
    if origin == "null" or origin.rstrip("/") not in allowed_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="request origin is not allowed",
        )


def _login_bucket_key(request: Request) -> str:
    source_ip = request.headers.get("x-real-ip")
    if not source_ip and request.client is not None:
        source_ip = request.client.host
    return hashlib.sha256((source_ip or "unknown").encode("utf-8")).hexdigest()


def _login_retry_after(
    session: Session,
    bucket_key: str,
    now: datetime,
    window_seconds: int,
    attempt_limit: int,
) -> int | None:
    bucket = session.get(LoginRateLimit, bucket_key)
    if bucket is None or bucket.failure_count < attempt_limit:
        return None

    started_at = bucket.window_started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    remaining = (started_at + timedelta(seconds=window_seconds) - now).total_seconds()
    return max(1, int(remaining + 0.999)) if remaining > 0 else None


def _record_failed_login(
    session: Session,
    bucket_key: str,
    now: datetime,
    window_seconds: int,
) -> None:
    dialect = session.get_bind().dialect.name
    insert = postgresql_insert if dialect == "postgresql" else sqlite_insert
    statement = insert(LoginRateLimit).values(
        bucket_key=bucket_key,
        window_started_at=now,
        failure_count=1,
    )
    expired_window = LoginRateLimit.window_started_at <= now - timedelta(
        seconds=window_seconds
    )
    statement = statement.on_conflict_do_update(
        index_elements=[LoginRateLimit.bucket_key],
        set_={
            "window_started_at": case(
                (expired_window, now),
                else_=LoginRateLimit.window_started_at,
            ),
            "failure_count": case(
                (expired_window, 1),
                else_=LoginRateLimit.failure_count + 1,
            ),
        },
    )
    session.execute(statement)
    session.commit()


# ============================================================
# DOCUMENT HELPERS
# ============================================================


def _get_document(
    session: Session,
    document_id: str,
) -> Document:

    document = session.get(
        Document,
        document_id,
    )

    if document is None or document.status not in {
        "REGISTERED",
        "REVOKED",
    }:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="registered document not found",
        )

    return document


def _audit(
    session: Session,
    document_id: str,
    action: str,
    result: str,
    detail: str,
    actor_hint: str = "anonymous",
) -> None:

    session.add(
        AuditEvent(
            document_id=document_id,
            action=action,
            result=result,
            detail=detail,
            actor_hint=actor_hint[:160],
        )
    )


def _ledger_payload(
    document: Document,
) -> dict:

    return {
        "documentId": document.id,
        "status": "REGISTERED",
        "documentHash": document.document_hash,
        "signatureDigest": hashlib.sha256(
            document.signature
        ).hexdigest(),
        "keyFingerprint": document.key_fingerprint,
        "signingAlgorithm": document.signing_algorithm,
        "kemAlgorithm": document.kem_algorithm,
        "issuer": document.issuer,
        "sizeBytes": document.size_bytes,
        "registeredAt": document.created_at.isoformat(),
    }


def _public_record(
    document: Document,
    runtime: Runtime,
) -> dict:

    return {
        "document_id": document.id,
        "issuer": document.issuer,
        "original_filename": document.original_filename,
        "mime_type": document.mime_type,
        "size_bytes": document.size_bytes,
        "document_hash": document.document_hash,
        "signature_digest": hashlib.sha256(
            document.signature
        ).hexdigest(),
        "signing_algorithm": document.signing_algorithm,
        "kem_algorithm": document.kem_algorithm,
        "key_fingerprint": document.key_fingerprint,
        "registered_at": document.registered_at,
        "status": document.status,
        "revoked_at": document.revoked_at,
        "revocation_reason": document.revocation_reason,
        "revocation_transaction_id": (
            document.revocation_transaction_id
        ),
        "ledger_backend": runtime.ledger.name,
        "transaction_id": document.ledger_transaction_id,
        "block_number": document.ledger_block_number,
        "verification_url": (
            f"{runtime.settings.public_base_url.rstrip('/')}"
            f"/verify/{document.id}"
        ),
    }


def _ledger_matches(
    record: dict | None,
    expected: dict,
) -> bool:

    if not record:
        return False

    fields = (
        "documentId",
        "documentHash",
        "signatureDigest",
        "keyFingerprint",
        "signingAlgorithm",
        "kemAlgorithm",
        "issuer",
        "sizeBytes",
    )

    return all(
        record.get(field) == expected.get(field)
        for field in fields
    )


def _mark_document_registered(
    session: Session,
    document: Document,
    commit_transaction_id: str,
    commit_block_number: int | None,
    actor_hint: str,
    action: str = "REGISTER",
) -> None:
    """Finalize the PostgreSQL state after a confirmed ledger commitment."""

    document.status = "REGISTERED"
    document.ledger_transaction_id = commit_transaction_id
    document.ledger_block_number = commit_block_number
    document.registered_at = datetime.now(timezone.utc)
    _audit(
        session,
        document.id,
        action,
        "SUCCESS",
        f"Ledger commitment confirmed: {commit_transaction_id}",
        actor_hint,
    )


def _ledger_history_transaction_id(
    runtime: Runtime,
    document_id: str,
) -> str | None:
    history = runtime.ledger.history(document_id)
    if not history:
        return None
    latest = history[-1]
    if not isinstance(latest, dict):
        return None
    transaction_id = latest.get("transactionId")
    if transaction_id:
        return transaction_id
    record = latest.get("record")
    if isinstance(record, dict):
        return record.get("transactionId")
    return None


# ============================================================
# APPLICATION
# ============================================================


def create_app(
    settings: Settings | None = None,
) -> FastAPI:

    settings = settings or get_settings()

    # ========================================================
    # LIFESPAN
    # ========================================================

    @asynccontextmanager
    async def lifespan(app: FastAPI):

        engine = make_engine(settings)

        run_migrations(engine)

        sessions = make_session_factory(
            settings,
            engine,
        )

        bootstrap_session = sessions()
        try:
            _bootstrap_admin(bootstrap_session, settings)
        finally:
            bootstrap_session.close()

        crypto = CryptoProvider(
            settings.allow_insecure_demo_pqc
        )

        store = FileKeyStore(
            settings.keystore_path
        )

        issuer_keys = load_or_create_keys(
            store,
            crypto,
            "demo_issuer_ml_dsa",
            "signature",
        )

        archive_keys = load_or_create_keys(
            store,
            crypto,
            "archive_ml_kem",
            "kem",
        )

        app.state.runtime = Runtime(
            settings=settings,
            sessions=sessions,
            crypto=crypto,
            issuer_keys=issuer_keys,
            archive_keys=archive_keys,
            ledger=make_ledger(
                settings.ledger_backend,
                sessions,
                settings.fabric_gateway_url,
                settings.fabric_gateway_token,
            ),
        )

        yield

        engine.dispose()

    # ========================================================
    # FASTAPI APP
    # ========================================================

    api = FastAPI(
        title="Quantum-Resistant Document Verification API",
        version="1.0.0",
        description=(
            "Application-layer ML-DSA + ML-KEM document registration "
            "with a Fabric-ready evidence ledger."
        ),
        lifespan=lifespan,
    )

    api.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=[
            "GET",
            "POST",
            "PATCH",
            "DELETE",
        ],
        allow_headers=["*"],
    )

    @api.middleware("http")
    async def no_store_sensitive_responses(
        request: Request,
        call_next,
    ):
        response = await call_next(request)

        if (
            request.url.path == "/health"
            or request.url.path.startswith("/health/")
            or request.url.path.startswith("/api/v1/")
            or request.url.path == "/metrics"
        ):
            response.headers["Cache-Control"] = "no-store"

        return response

    @api.middleware("http")
    async def record_request_metrics(request: Request, call_next):
        response = await call_next(request)
        route = request.scope.get("route")
        route_name = getattr(route, "path", "unmatched")
        if route_name != "/metrics":
            with _REQUEST_METRICS_LOCK:
                _REQUEST_METRICS[
                    (request.method, route_name, response.status_code)
                ] += 1
        return response

    # ========================================================
    # HEALTH
    # PUBLIC
    # ========================================================

    def dependency_status(runtime: Runtime) -> dict[str, str]:
        components = {"database": "up", "ledger": "up"}
        try:
            with runtime.sessions() as session:
                session.execute(select(1))
        except SQLAlchemyError:
            components["database"] = "down"

        try:
            runtime.ledger.read(str(uuid.uuid4()))
        except (LedgerError, SQLAlchemyError):
            components["ledger"] = "down"
        return components

    def health_payload(runtime: Runtime) -> dict:
        components = dependency_status(runtime)
        return {
            "status": "ok" if all(value == "up" for value in components.values()) else "degraded",
            "components": components,
            "ledger_backend": runtime.ledger.name,
            "pqc_backend": (
                "liboqs"
                if runtime.crypto.using_real_pqc
                else "INSECURE-DEMO-FALLBACK"
            ),
            "signature_algorithm": runtime.crypto.signature_algorithm,
            "kem_algorithm": runtime.crypto.kem_algorithm,
        }

    @api.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/health/ready")
    @api.get("/health")
    def health(
        response: Response,
        runtime: Runtime = Depends(_runtime),
    ) -> dict:
        payload = health_payload(runtime)
        if payload["status"] != "ok":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return payload

    @api.get("/metrics", include_in_schema=False)
    def metrics(runtime: Runtime = Depends(_runtime)) -> PlainTextResponse:
        components = dependency_status(runtime)
        lines = [
            "# HELP quantumproof_dependency_up Whether a required dependency is reachable.",
            "# TYPE quantumproof_dependency_up gauge",
        ]
        lines.extend(
            f'quantumproof_dependency_up{{dependency="{name}"}} '
            f'{1 if state == "up" else 0}'
            for name, state in sorted(components.items())
        )
        lines.extend(
            [
                "# HELP quantumproof_http_requests_total Total HTTP requests by route and status.",
                "# TYPE quantumproof_http_requests_total counter",
            ]
        )
        with _REQUEST_METRICS_LOCK:
            request_metrics = sorted(_REQUEST_METRICS.items())
        for (method, route, status_code), count in request_metrics:
            escaped_route = route.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(
                f'quantumproof_http_requests_total{{method="{method}",'
                f'route="{escaped_route}",status="{status_code}"}} {count}'
            )
        return PlainTextResponse("\n".join(lines) + "\n")

    # ========================================================
    # ADMIN AUTHENTICATION
    # ========================================================

    @api.post("/api/v1/auth/login")
    def admin_login(
        request: Request,
        response: Response,
        session: SessionDep,
        admin_id: str = Form(...),
        password: str = Form(...),
    ) -> dict:
        _require_same_origin(request)
        clean_id = admin_id.strip()
        if not clean_id or not password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="admin ID and password are required",
            )

        runtime = request.app.state.runtime
        now = datetime.now(timezone.utc)
        bucket_key = _login_bucket_key(request)
        retry_after = _login_retry_after(
            session,
            bucket_key,
            now,
            runtime.settings.admin_login_window_seconds,
            runtime.settings.admin_login_attempt_limit,
        )
        if retry_after is not None:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many failed login attempts; try again later",
                headers={"Retry-After": str(retry_after)},
            )

        admin = session.execute(
            select(AdminUser).where(
                AdminUser.admin_id == clean_id,
                AdminUser.is_active.is_(True),
            )
        ).scalar_one_or_none()

        if admin is None or not _verify_password(password, admin.password_hash):
            _record_failed_login(
                session,
                bucket_key,
                now,
                runtime.settings.admin_login_window_seconds,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid admin ID or password",
            )

        # Revoke previous active sessions for this admin.
        active_sessions = session.scalars(
            select(AdminSession).where(
                AdminSession.admin_user_id == admin.id,
                AdminSession.revoked_at.is_(None),
            )
        ).all()
        for old_session in active_sessions:
            old_session.revoked_at = now

        rate_limit = session.get(LoginRateLimit, bucket_key)
        if rate_limit is not None:
            session.delete(rate_limit)

        raw_token = secrets.token_urlsafe(48)
        expires_at = now + timedelta(hours=runtime.settings.admin_session_hours)

        session.add(
            AdminSession(
                session_token_hash=_session_hash(raw_token),
                admin_user_id=admin.id,
                created_at=now,
                expires_at=expires_at,
            )
        )
        admin.last_login_at = now
        session.commit()

        response.set_cookie(
            key=ADMIN_SESSION_COOKIE,
            value=raw_token,
            httponly=True,
            secure=runtime.settings.admin_cookie_secure,
            samesite="strict",
            max_age=int(runtime.settings.admin_session_hours * 3600),
            path="/",
        )

        return {
            "authenticated": True,
            "admin_id": admin.admin_id,
            "expires_at": expires_at,
        }


    @api.get("/api/v1/auth/me")
    def admin_me(
        request: Request,
        session: SessionDep,
    ) -> dict:
        admin = require_admin(request, session)
        raw_token = request.cookies.get(ADMIN_SESSION_COOKIE)
        admin_session = session.execute(
            select(AdminSession).where(
                AdminSession.session_token_hash == _session_hash(raw_token),
                AdminSession.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        return {
            "authenticated": True,
            "admin_id": admin.admin_id,
            "expires_at": admin_session.expires_at if admin_session else None,
        }


    @api.post("/api/v1/auth/logout")
    def admin_logout(
        request: Request,
        response: Response,
        session: SessionDep,
    ) -> dict:
        _require_same_origin(request)
        raw_token = request.cookies.get(ADMIN_SESSION_COOKIE)
        if raw_token:
            admin_session = session.execute(
                select(AdminSession).where(
                    AdminSession.session_token_hash == _session_hash(raw_token),
                    AdminSession.revoked_at.is_(None),
                )
            ).scalar_one_or_none()
            if admin_session is not None:
                admin_session.revoked_at = datetime.now(timezone.utc)
                session.commit()

        response.delete_cookie(
            key=ADMIN_SESSION_COOKIE,
            path="/",
            secure=request.app.state.runtime.settings.admin_cookie_secure,
            httponly=True,
            samesite="strict",
        )
        return {"authenticated": False}

    # ========================================================
    # REGISTER DOCUMENT
    # ADMIN ONLY
    # ========================================================

    @api.post(
        "/api/v1/documents/register",
        response_model=RegistrationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def register_document(
        request: Request,
        file: Annotated[
            UploadFile,
            File(description="Document to register"),
        ],
        issuer: Annotated[
            str,
            Form(
                min_length=2,
                max_length=160,
            ),
        ],
        signature_b64: Annotated[
            str | None,
            Form(),
        ] = None,
        signing_public_key_b64: Annotated[
            str | None,
            Form(),
        ] = None,
        admin: AdminUser = Depends(require_admin),
        session: Session = Depends(get_session),
    ) -> RegistrationResponse:

        runtime = _runtime(request)

        # ----------------------------------------------------
        # 1. Validate issuer
        # ----------------------------------------------------

        issuer_name = issuer.strip()

        issuer_record = session.execute(
            select(Issuer).where(
                Issuer.issuer_id == issuer_name
            )
        ).scalar_one_or_none()

        if issuer_record is None:
            raise HTTPException(
                status_code=422,
                detail="issuer is not registered",
            )

        if issuer_record.status != "ACTIVE":
            raise HTTPException(
                status_code=403,
                detail=(
                    f"issuer is "
                    f"{issuer_record.status.lower()}"
                ),
            )

        issuer_expires_at = issuer_record.expires_at
        if issuer_expires_at is not None and issuer_expires_at.tzinfo is None:
            issuer_expires_at = issuer_expires_at.replace(tzinfo=timezone.utc)
        if (
            issuer_expires_at is not None
            and issuer_expires_at <= datetime.now(timezone.utc)
        ):
            raise HTTPException(
                status_code=403,
                detail="issuer registration has expired",
            )

        # ----------------------------------------------------
        # 2. Read document with size protection
        # ----------------------------------------------------

        content = await file.read(
            runtime.settings.max_document_bytes + 1
        )

        # ----------------------------------------------------
        # 3. Empty document validation
        # ----------------------------------------------------

        if not content:
            raise HTTPException(
                status_code=422,
                detail="document must not be empty",
            )

        # ----------------------------------------------------
        # 4. Maximum document size validation
        # ----------------------------------------------------

        if len(content) > runtime.settings.max_document_bytes:
            raise HTTPException(
                status_code=413,
                detail=(
                    "document exceeds "
                    f"{runtime.settings.max_document_bytes} "
                    "byte limit"
                ),
            )

        # ----------------------------------------------------
        # 5. Real PDF validation
        # ----------------------------------------------------

        if not content.startswith(b"%PDF-"):
            raise HTTPException(
                status_code=415,
                detail=(
                    "uploaded file is not a valid "
                    "PDF document"
                ),
            )

        # ----------------------------------------------------
        # 6. External signature fields
        # ----------------------------------------------------

        if bool(signature_b64) != bool(
            signing_public_key_b64
        ):
            raise HTTPException(
                status_code=422,
                detail=(
                    "signature_b64 and "
                    "signing_public_key_b64 "
                    "must be supplied together"
                ),
            )

        # ----------------------------------------------------
        # 7. SHA-256
        # ----------------------------------------------------

        document_hash = hashlib.sha256(
            content
        ).hexdigest()

        # ----------------------------------------------------
        # 8. Duplicate active registration check
        # ----------------------------------------------------

        existing_document = session.execute(
            select(Document).where(
                Document.document_hash == document_hash,
                Document.status == "REGISTERED",
            )
        ).scalars().first()

        if existing_document is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "document is already registered as "
                    f"{existing_document.id}"
                ),
            )

        claim = document_claim(
            document_hash
        )

        # ----------------------------------------------------
        # 9. External signature supplied
        # ----------------------------------------------------

        if (
            signature_b64
            and signing_public_key_b64
        ):

            try:
                signature_bytes = b64decode(
                    signature_b64
                )

                signing_public_key = b64decode(
                    signing_public_key_b64
                )

            except ValueError as exc:

                raise HTTPException(
                    status_code=422,
                    detail=str(exc),
                ) from exc

            signing_algorithm = (
                runtime.crypto.signature_algorithm
            )

            if (
                fingerprint(signing_public_key)
                != issuer_record.key_fingerprint
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "issuer public key does not "
                        "match registered issuer"
                    ),
                )

            if not runtime.crypto.verify(
                claim,
                signature_bytes,
                signing_public_key,
                signing_algorithm,
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "external signature does not "
                        "validate for this document hash"
                    ),
                )

        # ----------------------------------------------------
        # 10. Internal issuer signature
        # ----------------------------------------------------

        else:

            signing_algorithm = (
                runtime.crypto.signature_algorithm
            )

            signing_public_key = (
                runtime.issuer_keys.public_key
            )

            if (
                fingerprint(signing_public_key)
                != issuer_record.key_fingerprint
            ):
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "configured issuer key does not "
                        "match issuer registry"
                    ),
                )

            signature_bytes = runtime.crypto.sign(
                claim,
                runtime.issuer_keys.secret_key,
                signing_algorithm,
            )

        # ----------------------------------------------------
        # 11. Encrypt document
        # ----------------------------------------------------

        encrypted = (
            runtime.crypto.encrypt_for_recipient(
                content,
                runtime.archive_keys.public_key,
            )
        )

        now = datetime.now(timezone.utc)

        document = Document(
            id=str(uuid.uuid4()),
            original_filename=(
                file.filename
                or "unnamed-document"
            )[:255],
            issuer=issuer_name,
            mime_type=(
                file.content_type
                or "application/octet-stream"
            )[:120],
            size_bytes=len(content),
            document_hash=document_hash,
            signature=signature_bytes,
            signing_public_key=signing_public_key,
            signing_algorithm=signing_algorithm,
            key_fingerprint=fingerprint(
                signing_public_key
            ),
            kem_algorithm=encrypted.kem_algorithm,
            kem_ciphertext=encrypted.kem_ciphertext,
            encryption_nonce=encrypted.nonce,
            encrypted_document=encrypted.ciphertext,
            status="PENDING",
            created_at=now,
        )

        session.add(document)
        session.commit()

        # ----------------------------------------------------
        # 12. Fabric ledger registration
        # ----------------------------------------------------

        try:

            commit = runtime.ledger.register(
                _ledger_payload(document)
            )

        except LedgerError as exc:

            document.status = "LEDGER_FAILED"

            _audit(
                session,
                document.id,
                "REGISTER",
                "FAILED",
                str(exc),
                issuer_name,
            )

            session.commit()

            raise HTTPException(
                status_code=503,
                detail=(
                    "ledger commitment failed; "
                    "document was not registered"
                ),
            ) from exc

        # ----------------------------------------------------
        # 13. Mark document registered
        # ----------------------------------------------------

        _mark_document_registered(
            session,
            document,
            commit.transaction_id,
            commit.block_number,
            admin.admin_id,
        )

        session.commit()

        # ----------------------------------------------------
        # 14. Response
        # ----------------------------------------------------

        return RegistrationResponse(
            document_id=document.id,
            document_hash=document.document_hash,
            signing_algorithm=(
                document.signing_algorithm
            ),
            kem_algorithm=document.kem_algorithm,
            key_fingerprint=document.key_fingerprint,
            ledger_backend=commit.backend,
            transaction_id=commit.transaction_id,
            block_number=commit.block_number,
            verification_url=(
                f"{runtime.settings.public_base_url.rstrip('/')}"
                f"/verify/{document.id}"
            ),
        )

    # ========================================================
    # ADMIN ISSUER MANAGEMENT
    # ========================================================

    @api.get("/api/v1/admin/issuers")
    def list_issuers(
        request: Request,
        session: SessionDep,
        _: AdminUser = Depends(require_admin),
    ) -> dict:
        runtime = _runtime(request)
        issuers = session.scalars(
            select(Issuer).order_by(Issuer.organization.asc(), Issuer.issuer_id.asc())
        ).all()
        issuer_ids = [issuer.issuer_id for issuer in issuers]
        history_by_issuer: dict[str, list[dict]] = {
            issuer_id: [] for issuer_id in issuer_ids
        }

        if issuer_ids:
            history = session.scalars(
                select(IssuerAuditEvent)
                .where(IssuerAuditEvent.issuer_id.in_(issuer_ids))
                .order_by(
                    IssuerAuditEvent.occurred_at.desc(),
                    IssuerAuditEvent.id.desc(),
                )
            ).all()
            for event in history:
                history_by_issuer[event.issuer_id].append({
                    "action": event.action,
                    "actor": event.actor_hint,
                    "previous_status": event.previous_status,
                    "new_status": event.new_status,
                    "previous_key_fingerprint": event.previous_key_fingerprint,
                    "new_key_fingerprint": event.new_key_fingerprint,
                    "detail": event.detail,
                    "occurred_at": event.occurred_at,
                })

        server_key_fingerprint = fingerprint(runtime.issuer_keys.public_key)
        return {
            "items": [{
                "issuer_id": issuer.issuer_id,
                "organization": issuer.organization,
                "signing_algorithm": issuer.signing_algorithm,
                "key_fingerprint": issuer.key_fingerprint,
                "status": issuer.status,
                "created_at": issuer.created_at,
                "expires_at": issuer.expires_at,
                "server_managed": issuer.key_fingerprint == server_key_fingerprint,
                "history": history_by_issuer[issuer.issuer_id],
            } for issuer in issuers],
            "total": len(issuers),
        }

    @api.post("/api/v1/admin/issuers", status_code=status.HTTP_201_CREATED)
    def enroll_issuer(
        payload: IssuerEnrollmentRequest,
        request: Request,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> dict:
        runtime = _runtime(request)
        issuer_id = payload.issuer_id.strip()
        organization = payload.organization.strip()
        if len(issuer_id) < 2 or len(organization) < 2:
            raise HTTPException(
                status_code=422,
                detail="issuer ID and organization must contain at least 2 characters",
            )
        if session.get(Issuer, issuer_id) is not None:
            raise HTTPException(status_code=409, detail="issuer ID is already enrolled")

        algorithm = runtime.crypto.signature_algorithm
        public_key = _issuer_public_key(payload.public_key_b64, algorithm, runtime)
        key_fingerprint = fingerprint(public_key)
        if key_fingerprint == fingerprint(runtime.issuer_keys.public_key):
            raise HTTPException(
                status_code=409,
                detail="the server-managed demo key cannot be enrolled as an external issuer",
            )

        used_key = session.scalar(
            select(Issuer.issuer_id).where(Issuer.key_fingerprint == key_fingerprint)
        )
        historical_key = session.scalar(
            select(IssuerAuditEvent.id)
            .where(or_(
                IssuerAuditEvent.previous_key_fingerprint == key_fingerprint,
                IssuerAuditEvent.new_key_fingerprint == key_fingerprint,
            ))
            .limit(1)
        )
        if used_key is not None or historical_key is not None:
            raise HTTPException(
                status_code=409,
                detail="this signing key is already assigned or was previously used",
            )

        issuer = Issuer(
            issuer_id=issuer_id,
            organization=organization,
            public_key=public_key,
            key_fingerprint=key_fingerprint,
            signing_algorithm=algorithm,
            status="ACTIVE",
            expires_at=_validated_issuer_expiration(payload.expires_at),
        )
        session.add(issuer)
        _issuer_history_event(
            session,
            issuer_id,
            "ENROLLED",
            admin.admin_id,
            new_status="ACTIVE",
            new_key_fingerprint=key_fingerprint,
            detail="Issuer enrolled by an administrator.",
        )
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(
                status_code=409,
                detail="issuer ID or signing key is already enrolled",
            ) from exc

        return {
            "issuer_id": issuer.issuer_id,
            "organization": issuer.organization,
            "signing_algorithm": issuer.signing_algorithm,
            "key_fingerprint": issuer.key_fingerprint,
            "status": issuer.status,
            "expires_at": issuer.expires_at,
        }

    @api.post("/api/v1/admin/issuers/{issuer_id}/rotate-key")
    def rotate_issuer_key(
        issuer_id: str,
        payload: IssuerKeyRotationRequest,
        request: Request,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> dict:
        runtime = _runtime(request)
        issuer = session.scalar(
            select(Issuer)
            .where(Issuer.issuer_id == issuer_id)
            .with_for_update()
        )
        if issuer is None:
            raise HTTPException(status_code=404, detail="issuer not found")
        if issuer.key_fingerprint == fingerprint(runtime.issuer_keys.public_key):
            raise HTTPException(
                status_code=409,
                detail="the server-managed demo signing key cannot be rotated through issuer management",
            )
        if issuer.signing_algorithm != runtime.crypto.signature_algorithm:
            raise HTTPException(
                status_code=409,
                detail="issuer signing algorithm is not supported by this runtime",
            )

        public_key = _issuer_public_key(
            payload.public_key_b64,
            issuer.signing_algorithm,
            runtime,
        )
        new_fingerprint = fingerprint(public_key)
        if new_fingerprint == issuer.key_fingerprint:
            raise HTTPException(
                status_code=409,
                detail="new signing key must differ from the current key",
            )

        used_key = session.scalar(
            select(Issuer.issuer_id).where(Issuer.key_fingerprint == new_fingerprint)
        )
        historical_key = session.scalar(
            select(IssuerAuditEvent.id)
            .where(or_(
                IssuerAuditEvent.previous_key_fingerprint == new_fingerprint,
                IssuerAuditEvent.new_key_fingerprint == new_fingerprint,
            ))
            .limit(1)
        )
        if used_key is not None or historical_key is not None:
            raise HTTPException(
                status_code=409,
                detail="this signing key is already assigned or was previously used",
            )

        previous_fingerprint = issuer.key_fingerprint
        issuer.public_key = public_key
        issuer.key_fingerprint = new_fingerprint
        if payload.expires_at is not None:
            issuer.expires_at = _validated_issuer_expiration(payload.expires_at)
        _issuer_history_event(
            session,
            issuer_id,
            "KEY_ROTATED",
            admin.admin_id,
            previous_status=issuer.status,
            new_status=issuer.status,
            previous_key_fingerprint=previous_fingerprint,
            new_key_fingerprint=new_fingerprint,
            detail="Signing key rotated; existing document evidence remains unchanged.",
        )
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(
                status_code=409,
                detail="this signing key is already assigned or was previously used",
            ) from exc

        return {
            "issuer_id": issuer.issuer_id,
            "key_fingerprint": issuer.key_fingerprint,
            "status": issuer.status,
            "expires_at": issuer.expires_at,
        }

    @api.patch("/api/v1/admin/issuers/{issuer_id}/status")
    def update_issuer_status(
        issuer_id: str,
        payload: IssuerStatusRequest,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> dict:
        issuer = session.scalar(
            select(Issuer)
            .where(Issuer.issuer_id == issuer_id)
            .with_for_update()
        )
        if issuer is None:
            raise HTTPException(status_code=404, detail="issuer not found")
        if issuer.status == payload.status:
            return {
                "issuer_id": issuer.issuer_id,
                "status": issuer.status,
                "action": "unchanged",
            }

        previous_status = issuer.status
        issuer.status = payload.status
        action = "SUSPENDED" if payload.status == "SUSPENDED" else "REACTIVATED"
        _issuer_history_event(
            session,
            issuer_id,
            action,
            admin.admin_id,
            previous_status=previous_status,
            new_status=payload.status,
            detail=f"Issuer status changed from {previous_status} to {payload.status}.",
        )
        session.commit()
        return {
            "issuer_id": issuer.issuer_id,
            "status": issuer.status,
            "action": action.lower(),
        }

    # ========================================================
    # LEDGER RECONCILIATION
    # ADMIN ONLY
    # ========================================================

    @api.post("/api/v1/admin/documents/{document_id}/reconcile")
    def reconcile_document(
        document_id: str,
        request: Request,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> dict:
        """Recover a document after an ambiguous or failed DB/Fabric boundary.

        If Fabric already contains a matching record, PostgreSQL is repaired from
        the ledger without submitting a duplicate transaction. If Fabric has no
        record, registration is retried. A conflicting ledger record is never
        overwritten automatically.
        """

        runtime = _runtime(request)
        document = session.get(Document, document_id)

        if document is None:
            raise HTTPException(status_code=404, detail="document not found")

        if document.status == "REGISTERED":
            return {
                "document_id": document.id,
                "status": document.status,
                "action": "already_registered",
                "transaction_id": document.ledger_transaction_id,
                "block_number": document.ledger_block_number,
            }

        if document.status == "LEDGER_CONFLICT":
            raise HTTPException(
                status_code=409,
                detail="ledger conflict requires manual investigation",
            )

        if document.status not in {"PENDING", "LEDGER_FAILED"}:
            raise HTTPException(
                status_code=409,
                detail=f"document status {document.status} is not reconcilable",
            )

        expected = _ledger_payload(document)

        # First read Fabric. This handles the ambiguous case where the ledger
        # transaction succeeded but the HTTP request or DB finalization failed.
        try:
            ledger_record = runtime.ledger.read(document.id)
        except LedgerError as exc:
            _audit(session, document.id, "RECONCILE", "FAILED", str(exc), admin.admin_id)
            session.commit()
            raise HTTPException(
                status_code=503,
                detail="ledger is unavailable; reconciliation was not completed",
            ) from exc

        if ledger_record is not None:
            matches = _ledger_matches(ledger_record, expected)
            status_matches = ledger_record.get("status", "REGISTERED") == "REGISTERED"
            if not matches or not status_matches:
                document.status = "LEDGER_CONFLICT"
                _audit(
                    session,
                    document.id,
                    "RECONCILE",
                    "CONFLICT",
                    "ledger record exists but does not match the PostgreSQL evidence",
                    admin.admin_id,
                )
                session.commit()
                raise HTTPException(
                    status_code=409,
                    detail="ledger record conflicts with PostgreSQL evidence; no overwrite was attempted",
                )

            try:
                transaction_id = _ledger_history_transaction_id(runtime, document.id)
            except LedgerError as exc:
                _audit(session, document.id, "RECONCILE", "FAILED", str(exc), admin.admin_id)
                session.commit()
                raise HTTPException(
                    status_code=503,
                    detail="ledger history is unavailable; reconciliation was not completed",
                ) from exc

            transaction_id = transaction_id or document.ledger_transaction_id
            if not transaction_id:
                _audit(
                    session, document.id, "RECONCILE", "FAILED",
                    "matching ledger record has no recoverable transaction ID",
                    admin.admin_id,
                )
                session.commit()
                raise HTTPException(
                    status_code=503,
                    detail="ledger record is valid but its transaction ID could not be recovered",
                )

            _mark_document_registered(
                session,
                document,
                transaction_id,
                ledger_record.get("blockNumber") or document.ledger_block_number,
                admin.admin_id,
                action="RECONCILE",
            )
            session.commit()
            return {
                "document_id": document.id,
                "status": document.status,
                "action": "recovered_from_ledger",
                "transaction_id": document.ledger_transaction_id,
                "block_number": document.ledger_block_number,
            }

        # Fabric has no record, so retry registration. If a concurrent request
        # wins the race, the subsequent read will recover it on the next call.
        try:
            commit = runtime.ledger.register(expected)
        except LedgerError as exc:
            document.status = "LEDGER_FAILED"
            _audit(session, document.id, "RECONCILE", "FAILED", str(exc), admin.admin_id)
            session.commit()
            raise HTTPException(
                status_code=503,
                detail="ledger registration retry failed; document remains unreconciled",
            ) from exc

        _mark_document_registered(
            session,
            document,
            commit.transaction_id,
            commit.block_number,
            admin.admin_id,
            action="RECONCILE",
        )
        session.commit()
        return {
            "document_id": document.id,
            "status": document.status,
            "action": "registered_on_retry",
            "transaction_id": commit.transaction_id,
            "block_number": commit.block_number,
        }

    # ========================================================
    # ADMIN DOCUMENT REGISTRY
    # ========================================================

    @api.get("/api/v1/admin/documents")
    def list_documents(
        request: Request,
        session: SessionDep,
        _: AdminUser = Depends(require_admin),
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict:
        runtime = _runtime(request)
        total = session.scalar(select(func.count()).select_from(Document)) or 0
        grouped_counts = session.execute(
            select(Document.status, func.count())
            .group_by(Document.status)
        )
        status_counts = {
            "REGISTERED": 0,
            "REVOKED": 0,
            "PENDING": 0,
            "LEDGER_FAILED": 0,
            "LEDGER_CONFLICT": 0,
        }
        for document_status, count in grouped_counts:
            status_counts[document_status] = count

        documents = session.scalars(
            select(Document)
            .order_by(Document.created_at.desc(), Document.id.asc())
            .offset(offset)
            .limit(limit)
        ).all()
        document_ids = [document.id for document in documents]
        latest_operations: dict[str, AuditEvent] = {}
        if document_ids:
            events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.document_id.in_(document_ids),
                    AuditEvent.action.in_(("REGISTER", "RECONCILE")),
                )
                .order_by(
                    AuditEvent.occurred_at.desc(),
                    AuditEvent.id.desc(),
                )
            ).all()
            for event in events:
                latest_operations.setdefault(event.document_id, event)

        return {
            "items": [{
                **_public_record(document, runtime),
                "created_at": document.created_at,
                "reconciliation_result": (
                    latest_operations[document.id].result
                    if document.id in latest_operations
                    else None
                ),
                "reconciliation_detail": (
                    latest_operations[document.id].detail[:1000]
                    if document.id in latest_operations
                    and document.status in {
                        "PENDING",
                        "LEDGER_FAILED",
                        "LEDGER_CONFLICT",
                    }
                    else None
                ),
            } for document in documents],
            "status_counts": status_counts,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # ========================================================
    # PUBLIC DOCUMENT RECORD
    # ========================================================

    @api.get(
        "/api/v1/documents/{document_id}"
    )
    def get_document(
        document_id: str,
        request: Request,
        session: SessionDep,
    ) -> dict:

        return _public_record(
            _get_document(
                session,
                document_id,
            ),
            _runtime(request),
        )

    @api.get(
        "/api/v1/admin/documents/{document_id}/decrypt",
        response_class=Response,
    )
    def decrypt_document(
        document_id: str,
        request: Request,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> Response:
        del admin
        runtime = _runtime(request)
        document = _get_document(session, document_id)
        plaintext = runtime.crypto.decrypt_for_recipient(
            EncryptedPayload(
                document.encrypted_document,
                document.encryption_nonce,
                document.kem_ciphertext,
                document.kem_algorithm,
            ),
            runtime.archive_keys.secret_key,
        )
        return Response(
            content=plaintext,
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{document_id}.pdf"',
            },
        )

    # ========================================================
    # PUBLIC QR
    # ========================================================

    @api.get(
        "/api/v1/documents/{document_id}/qr"
    )
    def get_qr(
        document_id: str,
        request: Request,
        session: SessionDep,
    ) -> StreamingResponse:

        _get_document(
            session,
            document_id,
        )

        url = (
            f"{_runtime(request).settings.public_base_url.rstrip('/')}"
            f"/verify/{document_id}"
        )

        buffer = io.BytesIO()

        qrcode.make(url).save(
            buffer,
            format="PNG",
        )

        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store"
            },
        )

    # ========================================================
    # REVOKE DOCUMENT
    # ADMIN ONLY
    # ========================================================

    @api.post(
        "/api/v1/documents/{document_id}/revoke"
    )
    def revoke_document(
        document_id: str,
        request: Request,
        session: SessionDep,
        reason: str = Form(
            ...,
            min_length=3,
            max_length=500,
        ),
        admin: AdminUser = Depends(require_admin),
    ) -> dict:

        runtime = _runtime(request)

        document = _get_document(
            session,
            document_id,
        )

        if document.status == "REVOKED":
            raise HTTPException(
                status_code=409,
                detail="document is already revoked",
            )

        clean_reason = reason.strip()

        if len(clean_reason) < 3:
            raise HTTPException(
                status_code=422,
                detail="revocation reason is too short",
            )

        try:

            commit = runtime.ledger.revoke(
                document.id,
                clean_reason,
            )

        except LedgerError as exc:

            _audit(
                session,
                document.id,
                "REVOKE",
                "FAILED",
                str(exc),
                admin.admin_id,
            )

            session.commit()

            raise HTTPException(
                status_code=503,
                detail=(
                    "ledger revocation failed; "
                    "document remains registered"
                ),
            ) from exc

        document.status = "REVOKED"

        document.revoked_at = (
            datetime.now(timezone.utc)
        )

        document.revocation_reason = (
            clean_reason
        )

        document.revocation_transaction_id = (
            commit.transaction_id
        )

        _audit(
            session,
            document.id,
            "REVOKE",
            "SUCCESS",
            (
                f"Revoked via {commit.backend}: "
                f"{commit.transaction_id}; "
                f"reason: {clean_reason}"
            ),
            admin.admin_id,
        )

        session.commit()

        return {
            "document_id": document.id,
            "status": document.status,
            "reason": document.revocation_reason,
            "transaction_id": commit.transaction_id,
            "block_number": commit.block_number,
        }

    # ========================================================
    # DELETE APPLICATION RECORD
    # ADMIN ONLY
    # ========================================================

    @api.delete(
        "/api/v1/documents/{document_id}"
    )
    def delete_document(
        document_id: str,
        session: SessionDep,
        admin: AdminUser = Depends(require_admin),
    ) -> dict:

        document = _get_document(
            session,
            document_id,
        )

        if document.status != "REVOKED":
            raise HTTPException(
                status_code=409,
                detail=(
                    "only revoked documents "
                    "can be deleted"
                ),
            )

        session.delete(document)
        session.commit()

        return {
            "document_id": document_id,
            "deleted": True,
            "message": (
                "Application record deleted. "
                "Hyperledger Fabric history "
                "is preserved."
            ),
        }

    # ========================================================
    # PUBLIC VERIFICATION
    # ========================================================

    @api.post(
        "/api/v1/documents/{document_id}/verify",
        response_model=VerificationResponse,
    )
    async def verify_document(
        document_id: str,
        request: Request,
        file: Annotated[
            UploadFile,
            File(
                description=(
                    "Candidate document to validate"
                )
            ),
        ],
        session: Session = Depends(get_session),
    ) -> VerificationResponse:

        runtime = _runtime(request)

        document = _get_document(
            session,
            document_id,
        )

        # ----------------------------------------------------
        # 1. Read candidate document
        # ----------------------------------------------------

        content = await file.read(
            runtime.settings.max_document_bytes + 1
        )

        if not content:
            raise HTTPException(
                status_code=422,
                detail="document must not be empty",
            )

        if len(content) > runtime.settings.max_document_bytes:
            raise HTTPException(
                status_code=413,
                detail=(
                    "document exceeds "
                    f"{runtime.settings.max_document_bytes} "
                    "byte limit"
                ),
            )

        # ----------------------------------------------------
        # 2. Validate candidate PDF
        # ----------------------------------------------------

        if not content.startswith(b"%PDF-"):
            raise HTTPException(
                status_code=415,
                detail=(
                    "uploaded file is not a valid "
                    "PDF document"
                ),
            )

        # ----------------------------------------------------
        # 3. Calculate candidate hash
        # ----------------------------------------------------

        candidate_hash = hashlib.sha256(
            content
        ).hexdigest()

        hash_matches = (
            candidate_hash
            == document.document_hash
        )

        # ----------------------------------------------------
        # 4. Verify ML-DSA signature
        #
        # IMPORTANT:
        # Verify against the candidate hash, not the
        # registered hash. This prevents a modified document
        # from being reported as having a valid signature.
        # ----------------------------------------------------

        signature_valid = runtime.crypto.verify(
            document_claim(candidate_hash),
            document.signature,
            document.signing_public_key,
            document.signing_algorithm,
        )

        # ----------------------------------------------------
        # 5. Verify Fabric ledger
        # ----------------------------------------------------

        try:

            ledger_record = runtime.ledger.read(
                document.id
            )

            ledger_valid = _ledger_matches(
                ledger_record,
                _ledger_payload(document),
            )

            ledger_problem = (
                ""
                if ledger_valid
                else (
                    "ledger record is missing "
                    "or inconsistent"
                )
            )

        except LedgerError as exc:

            ledger_valid = False

            ledger_problem = (
                f"ledger unavailable: {exc}"
            )

        # ----------------------------------------------------
        # 6. Overall verification result
        # ----------------------------------------------------

        if document.status == "REVOKED":

            overall_status = "REVOKED"

            detail = (
                "This document record has been revoked. "
                f"Reason: "
                f"{document.revocation_reason or 'No reason supplied.'}"
            )

        elif (
            hash_matches
            and signature_valid
            and ledger_valid
        ):

            overall_status = "VALID"

            detail = (
                "Candidate hash, ML-DSA signature, "
                "and ledger evidence all match."
            )

        elif not hash_matches:

            overall_status = "INVALID"

            detail = (
                "The uploaded document hash differs "
                "from the registered hash "
                "(tampering or a different file)."
            )

        elif not signature_valid:

            overall_status = "INVALID"

            detail = (
                "The stored signing evidence is invalid."
            )

        else:

            overall_status = "INDETERMINATE"

            detail = ledger_problem

        # ----------------------------------------------------
        # 7. Audit verification
        # ----------------------------------------------------

        _audit(
            session,
            document.id,
            "VERIFY",
            overall_status,
            detail,
            (
                request.client.host
                if request.client
                else "anonymous"
            ),
        )

        session.commit()

        # ----------------------------------------------------
        # 8. Response
        # ----------------------------------------------------

        return VerificationResponse(
            document_id=document.id,
            overall_status=overall_status,
            document_hash_matches=hash_matches,
            signature_valid=signature_valid,
            ledger_valid=ledger_valid,
            ledger_backend=runtime.ledger.name,
            transaction_id=(
                document.ledger_transaction_id
            ),
            detail=detail,
        )

    # ========================================================
    # AUDIT
    # ADMIN ONLY
    # ========================================================

    @api.get(
        "/api/v1/documents/{document_id}/audit"
    )
    def get_audit(
        document_id: str,
        session: SessionDep,
        _: AdminUser = Depends(require_admin),
    ) -> list[dict]:

        _get_document(
            session,
            document_id,
        )

        events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.document_id
                == document_id
            )
            .order_by(
                AuditEvent.occurred_at.desc()
            )
        ).all()

        return [
            {
                "action": event.action,
                "result": event.result,
                "detail": event.detail,
                "actor_hint": event.actor_hint,
                "occurred_at": event.occurred_at,
            }
            for event in events
        ]

    # ========================================================
    # BENCHMARK
    # ========================================================

    @api.post(
        "/api/v1/benchmarks/run"
    )
    def benchmark(
        payload: BenchmarkRequest,
        request: Request,
        _: AdminUser = Depends(require_admin),
    ) -> dict:

        try:

            return run_benchmark(
                _runtime(request).crypto,
                payload.iterations,
                payload.warmup,
            )

        except (
            ValueError,
            PqcUnavailable,
        ) as exc:

            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

    return api


app = create_app()
