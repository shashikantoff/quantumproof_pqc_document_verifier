import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

try:
    from fastapi.testclient import TestClient  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    from starlette.testclient import TestClient  # type: ignore[import-not-found]

from app.crypto import (
    CryptoProvider,
    EncryptedPayload,
    KeyPair,
    b64decode,
    b64encode,
    document_claim,
    fingerprint,
)
from app.database import (
    AuditEvent,
    DevelopmentLedgerRecord,
    Document,
    Issuer,
    IssuerAuditEvent,
)
from app.issuer_tool import generate_key_file, sign_pdf
from app.provision_demo_issuer import ensure_demo_issuer


PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n"
    b"%%EOF\n"
)


def register(
    client: TestClient,
    content: bytes = PDF_BYTES,
    issuer: str = "Example University",
    filename: str = "certificate.pdf",
) -> dict:
    response = client.post(
        "/api/v1/documents/register",
        data={"issuer": issuer},
        files={"file": (filename, content, "application/pdf")},
    )
    assert response.status_code == 201, response.text
    return response.json()


def verify(client: TestClient, document_id: str, content: bytes):
    return client.post(
        f"/api/v1/documents/{document_id}/verify",
        files={"file": ("candidate.pdf", content, "application/pdf")},
    )


def enroll_external_issuer(
    client: TestClient,
    issuer_id: str = "External Authority",
) -> KeyPair:
    runtime = client.app.state.runtime
    pair = runtime.crypto.create_signing_keypair()
    response = client.post(
        "/api/v1/admin/issuers",
        json={
            "issuer_id": issuer_id,
            "organization": issuer_id,
            "public_key_b64": b64encode(pair.public_key),
        },
    )
    assert response.status_code == 201, response.text
    return pair


def register_with_external_key(
    client: TestClient,
    issuer_id: str,
    pair: KeyPair,
    content: bytes,
):
    runtime = client.app.state.runtime
    document_hash = hashlib.sha256(content).hexdigest()
    signature = runtime.crypto.sign(
        document_claim(document_hash),
        pair.secret_key,
        runtime.crypto.signature_algorithm,
    )
    return client.post(
        "/api/v1/documents/register",
        data={
            "issuer": issuer_id,
            "signature_b64": b64encode(signature),
            "signing_public_key_b64": b64encode(pair.public_key),
        },
        files={"file": ("external.pdf", content, "application/pdf")},
    )


def test_register_encrypts_and_verifies_matching_document(client: TestClient):
    original = PDF_BYTES
    result = register(client, original)
    assert result["document_hash"]
    assert result["verification_url"].endswith(result["document_id"])

    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        assert document.encrypted_document != original
        decrypted = runtime.crypto.decrypt_for_recipient(
            EncryptedPayload(
                document.encrypted_document,
                document.encryption_nonce,
                document.kem_ciphertext,
                document.kem_algorithm,
            ),
            runtime.archive_keys.secret_key,
        )
        assert decrypted == original

    response = verify(client, result["document_id"], original)
    assert response.status_code == 200
    assert response.json()["overall_status"] == "VALID"


def test_admin_pdf_upload_decryption_api_round_trip(client: TestClient):
    original = PDF_BYTES
    result = register(client, original)

    response = client.get(
        f"/api/v1/admin/documents/{result['document_id']}/decrypt"
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content == original


def test_changed_document_is_reported_as_invalid(client: TestClient):
    result = register(client)
    changed = PDF_BYTES.replace(b"%%EOF", b"%%EOX", 1)
    response = verify(client, result["document_id"], changed)
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "INVALID"
    assert body["document_hash_matches"] is False
    assert body["signature_valid"] is False


def test_revoked_document_can_be_registered_again_without_deleting_history(
    client: TestClient,
):
    original = register(client)

    revoke_response = client.post(
        f"/api/v1/documents/{original['document_id']}/revoke",
        data={"reason": "Issuer reissued this document"},
    )
    assert revoke_response.status_code == 200, revoke_response.text
    assert revoke_response.json()["status"] == "REVOKED"

    replacement = register(client, PDF_BYTES)
    assert replacement["document_id"] != original["document_id"]

    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        original_record = session.get(Document, original["document_id"])
        replacement_record = session.get(Document, replacement["document_id"])
        assert original_record is not None
        assert original_record.status == "REVOKED"
        assert replacement_record is not None
        assert replacement_record.status == "REGISTERED"

    original_ledger_record = runtime.ledger.read(original["document_id"])
    replacement_ledger_record = runtime.ledger.read(replacement["document_id"])
    assert original_ledger_record["status"] == "REVOKED"
    assert replacement_ledger_record["status"] == "REGISTERED"

    original_verification = verify(client, original["document_id"], PDF_BYTES)
    replacement_verification = verify(client, replacement["document_id"], PDF_BYTES)
    assert original_verification.json()["overall_status"] == "REVOKED"
    assert replacement_verification.json()["overall_status"] == "VALID"


def test_tampered_stored_signature_is_reported_as_invalid(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        document.signature = b"tampered-signature"
        session.commit()

    response = verify(client, result["document_id"], PDF_BYTES)
    assert response.status_code == 200
    assert response.json()["signature_valid"] is False


def test_wrong_issuer_key_is_reported_as_invalid(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    wrong_pair = runtime.crypto.create_signing_keypair()
    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        document.signing_public_key = wrong_pair.public_key
        session.commit()

    response = verify(client, result["document_id"], PDF_BYTES)
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "INVALID"
    assert body["signature_valid"] is False


def test_wrong_external_signature_is_rejected_at_registration(client: TestClient):
    pair = enroll_external_issuer(client, "Wrong Signature Authority")
    wrong_pair = client.app.state.runtime.crypto.create_signing_keypair()
    content = PDF_BYTES.replace(b"%%EOF", b"wrong external signature%%EOF", 1)
    wrong_signature = client.app.state.runtime.crypto.sign(
        document_claim(hashlib.sha256(b"different document").hexdigest()),
        wrong_pair.secret_key,
        client.app.state.runtime.crypto.signature_algorithm,
    )

    response = client.post(
        "/api/v1/documents/register",
        data={
            "issuer": "Wrong Signature Authority",
            "signature_b64": b64encode(wrong_signature),
            "signing_public_key_b64": b64encode(pair.public_key),
        },
        files={"file": ("wrong-signature.pdf", content, "application/pdf")},
    )
    assert response.status_code == 422
    assert "does not validate" in response.json()["detail"]


def test_missing_ledger_record_is_reported_as_indeterminate(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        ledger_record = session.scalar(
            select(DevelopmentLedgerRecord).where(
                DevelopmentLedgerRecord.document_id == result["document_id"]
            )
        )
        assert ledger_record is not None
        session.delete(ledger_record)
        session.commit()

    response = verify(client, result["document_id"], PDF_BYTES)
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "INDETERMINATE"
    assert body["ledger_valid"] is False


def test_ledger_field_mismatch_is_reported_as_indeterminate(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        ledger_record = session.scalar(
            select(DevelopmentLedgerRecord).where(
                DevelopmentLedgerRecord.document_id == result["document_id"]
            )
        )
        assert ledger_record is not None
        payload = json.loads(ledger_record.payload_json)
        payload["issuer"] = "Tampered Issuer"
        ledger_record.payload_json = json.dumps(payload)
        session.commit()

    response = verify(client, result["document_id"], PDF_BYTES)
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "INDETERMINATE"
    assert body["ledger_valid"] is False


def test_external_issuer_signature_is_verified_before_registration(client: TestClient):
    runtime = client.app.state.runtime
    content = PDF_BYTES.replace(b"%%EOF", b"external%%EOF", 1)
    hash_hex = hashlib.sha256(content).hexdigest()
    pair = runtime.crypto.create_signing_keypair()
    signature = runtime.crypto.sign(
        document_claim(hash_hex),
        pair.secret_key,
        runtime.crypto.signature_algorithm,
    )

    with runtime.sessions() as session:
        session.add(
            Issuer(
                issuer_id="External Issuer",
                organization="External Issuer",
                public_key=pair.public_key,
                key_fingerprint=fingerprint(pair.public_key),
                signing_algorithm=runtime.crypto.signature_algorithm,
                status="ACTIVE",
            )
        )
        session.commit()

    response = client.post(
        "/api/v1/documents/register",
        data={
            "issuer": "External Issuer",
            "signature_b64": b64encode(signature),
            "signing_public_key_b64": b64encode(pair.public_key),
        },
        files={"file": ("external.pdf", content, "application/pdf")},
    )
    assert response.status_code == 201, response.text

    response = verify(client, response.json()["document_id"], content)
    assert response.status_code == 200
    assert response.json()["overall_status"] == "VALID"


def test_local_issuer_tool_encrypts_key_and_signs_pdf(tmp_path: Path):
    crypto = CryptoProvider(allow_insecure_demo=False)
    if not crypto.using_real_pqc:
        pytest.skip("local issuer tool requires real liboqs")

    key_path = tmp_path / "issuer-keys" / "authority.json"
    key_info = generate_key_file(key_path, "a-secure-local-passphrase", crypto)
    stored_key = json.loads(key_path.read_text(encoding="utf-8"))
    assert "secret_key_b64" not in stored_key
    assert stored_key["encrypted_secret_key_b64"]
    assert key_info["key_fingerprint"] == fingerprint(
        b64decode(key_info["public_key_b64"])
    )

    pdf_path = tmp_path / "certificate.pdf"
    content = PDF_BYTES.replace(b"%%EOF", b"issuer signed%%EOF", 1)
    pdf_path.write_bytes(content)
    result = sign_pdf(
        key_path,
        pdf_path,
        "Local Test Issuer",
        "a-secure-local-passphrase",
        crypto,
    )
    signature_valid = crypto.verify(
        document_claim(hashlib.sha256(content).hexdigest()),
        b64decode(result["signature_b64"]),
        b64decode(result["signing_public_key_b64"]),
        result["signing_algorithm"],
    )
    assert signature_valid
    assert result["issuer"] == "Local Test Issuer"
    assert "secret_key" not in result

    with pytest.raises(ValueError, match="incorrect passphrase"):
        sign_pdf(
            key_path,
            pdf_path,
            "Local Test Issuer",
            "different-local-passphrase",
            crypto,
        )
    with pytest.raises(FileExistsError):
        generate_key_file(key_path, "a-secure-local-passphrase", crypto)


def test_admin_can_enroll_external_issuer_and_record_history(client: TestClient):
    pair = enroll_external_issuer(client)
    runtime = client.app.state.runtime

    content = PDF_BYTES.replace(b"%%EOF", b"new issuer%%EOF", 1)
    registration = register_with_external_key(
        client,
        "External Authority",
        pair,
        content,
    )
    assert registration.status_code == 201, registration.text

    response = client.get("/api/v1/admin/issuers")
    assert response.status_code == 200, response.text
    enrolled = next(
        item for item in response.json()["items"]
        if item["issuer_id"] == "External Authority"
    )
    assert enrolled["key_fingerprint"] == fingerprint(pair.public_key)
    assert enrolled["history"][0]["action"] == "ENROLLED"
    assert enrolled["history"][0]["actor"] == "test-admin"

    with runtime.sessions() as session:
        event = session.scalar(
            select(IssuerAuditEvent).where(
                IssuerAuditEvent.issuer_id == "External Authority"
            )
        )
        assert event is not None
        assert event.new_key_fingerprint == fingerprint(pair.public_key)


def test_issuer_enrollment_rejects_invalid_and_reused_public_keys(client: TestClient):
    invalid = client.post(
        "/api/v1/admin/issuers",
        json={
            "issuer_id": "Malformed Authority",
            "organization": "Malformed Authority",
            "public_key_b64": b64encode(b"not-a-signing-key"),
        },
    )
    assert invalid.status_code == 422

    pair = enroll_external_issuer(client, "First Authority")
    reused = client.post(
        "/api/v1/admin/issuers",
        json={
            "issuer_id": "Second Authority",
            "organization": "Second Authority",
            "public_key_b64": b64encode(pair.public_key),
        },
    )
    assert reused.status_code == 409


def test_issuer_expiration_is_timezone_safe_after_database_reload(client: TestClient):
    runtime = client.app.state.runtime
    pair = runtime.crypto.create_signing_keypair()
    response = client.post(
        "/api/v1/admin/issuers",
        json={
            "issuer_id": "Expiring Authority",
            "organization": "Expiring Authority",
            "public_key_b64": b64encode(pair.public_key),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        },
    )
    assert response.status_code == 201, response.text

    content = PDF_BYTES.replace(b"%%EOF", b"unexpired issuer%%EOF", 1)
    registration = register_with_external_key(
        client,
        "Expiring Authority",
        pair,
        content,
    )
    assert registration.status_code == 201, registration.text


def test_issuer_key_rotation_preserves_old_document_evidence(client: TestClient):
    old_pair = enroll_external_issuer(client, "Rotating Authority")
    runtime = client.app.state.runtime
    old_content = PDF_BYTES.replace(b"%%EOF", b"before rotation%%EOF", 1)
    old_registration = register_with_external_key(
        client,
        "Rotating Authority",
        old_pair,
        old_content,
    )
    assert old_registration.status_code == 201, old_registration.text

    new_pair = runtime.crypto.create_signing_keypair()
    rotation = client.post(
        "/api/v1/admin/issuers/Rotating%20Authority/rotate-key",
        json={"public_key_b64": b64encode(new_pair.public_key)},
    )
    assert rotation.status_code == 200, rotation.text
    assert rotation.json()["key_fingerprint"] == fingerprint(new_pair.public_key)

    old_verification = verify(
        client,
        old_registration.json()["document_id"],
        old_content,
    )
    assert old_verification.status_code == 200
    assert old_verification.json()["overall_status"] == "VALID"

    reused_key = client.post(
        "/api/v1/admin/issuers/Rotating%20Authority/rotate-key",
        json={"public_key_b64": b64encode(old_pair.public_key)},
    )
    assert reused_key.status_code == 409

    new_content = PDF_BYTES.replace(b"%%EOF", b"after rotation%%EOF", 1)
    new_registration = register_with_external_key(
        client,
        "Rotating Authority",
        new_pair,
        new_content,
    )
    assert new_registration.status_code == 201, new_registration.text

    response = client.get("/api/v1/admin/issuers")
    issuer = next(
        item for item in response.json()["items"]
        if item["issuer_id"] == "Rotating Authority"
    )
    assert [event["action"] for event in issuer["history"][:2]] == [
        "KEY_ROTATED",
        "ENROLLED",
    ]
    assert issuer["history"][0]["previous_key_fingerprint"] == fingerprint(
        old_pair.public_key
    )


def test_server_managed_demo_key_cannot_be_rotated(client: TestClient):
    runtime = client.app.state.runtime
    pair = runtime.crypto.create_signing_keypair()
    response = client.post(
        "/api/v1/admin/issuers/Example%20University/rotate-key",
        json={"public_key_b64": b64encode(pair.public_key)},
    )
    assert response.status_code == 409


def test_suspended_issuer_cannot_register_until_reactivated(client: TestClient):
    pair = enroll_external_issuer(client, "Suspended Authority")
    status_url = "/api/v1/admin/issuers/Suspended%20Authority/status"

    suspended = client.patch(status_url, json={"status": "SUSPENDED"})
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["status"] == "SUSPENDED"

    content = PDF_BYTES.replace(b"%%EOF", b"suspended issuer%%EOF", 1)
    rejected = register_with_external_key(
        client,
        "Suspended Authority",
        pair,
        content,
    )
    assert rejected.status_code == 403

    reactivated = client.patch(status_url, json={"status": "ACTIVE"})
    assert reactivated.status_code == 200, reactivated.text
    assert reactivated.json()["action"] == "reactivated"
    accepted = register_with_external_key(
        client,
        "Suspended Authority",
        pair,
        content,
    )
    assert accepted.status_code == 201, accepted.text


def test_admin_registry_lists_server_records_with_pagination(client: TestClient):
    first = register(client)
    second_content = PDF_BYTES.replace(b"%%EOF", b"second%%EOF", 1)
    second = register(client, second_content)

    first_page = client.get(
        "/api/v1/admin/documents",
        params={"limit": 1, "offset": 0},
    )
    second_page = client.get(
        "/api/v1/admin/documents",
        params={"limit": 1, "offset": 1},
    )

    assert first_page.status_code == 200, first_page.text
    assert first_page.json()["total"] == 2
    assert first_page.json()["items"][0]["signature_digest"]
    assert second_page.status_code == 200, second_page.text
    assert second_page.json()["total"] == 2
    page_ids = {
        first_page.json()["items"][0]["document_id"],
        second_page.json()["items"][0]["document_id"],
    }
    assert page_ids == {first["document_id"], second["document_id"]}
    assert first_page.json()["status_counts"]["REGISTERED"] == 2
    assert first_page.json()["status_counts"]["LEDGER_FAILED"] == 0


def test_admin_registry_includes_unresolved_statuses_and_latest_operation(client: TestClient):
    failed = register(client)
    conflict = register(
        client,
        PDF_BYTES.replace(b"%%EOF", b"conflict%%EOF", 1),
    )
    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        failed_document = session.get(Document, failed["document_id"])
        failed_document.status = "LEDGER_FAILED"
        session.add(
            AuditEvent(
                document_id=failed_document.id,
                action="REGISTER",
                result="FAILED",
                detail="Ledger gateway unavailable",
                actor_hint="system",
            )
        )

        conflict_document = session.get(Document, conflict["document_id"])
        conflict_document.status = "LEDGER_CONFLICT"
        session.add(
            AuditEvent(
                document_id=conflict_document.id,
                action="RECONCILE",
                result="CONFLICT",
                detail="Ledger evidence does not match",
                actor_hint="test-admin",
            )
        )
        session.commit()

    response = client.get("/api/v1/admin/documents")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 2
    assert body["status_counts"]["LEDGER_FAILED"] == 1
    assert body["status_counts"]["LEDGER_CONFLICT"] == 1
    records = {record["document_id"]: record for record in body["items"]}
    assert records[failed["document_id"]]["reconciliation_detail"] == (
        "Ledger gateway unavailable"
    )
    assert records[failed["document_id"]]["reconciliation_result"] == "FAILED"
    assert records[conflict["document_id"]]["reconciliation_detail"] == (
        "Ledger evidence does not match"
    )


def test_reconcile_recovers_matching_ledger_record(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        document.status = "LEDGER_FAILED"
        document.ledger_transaction_id = None
        document.registered_at = None
        session.commit()

    response = client.post(
        f"/api/v1/admin/documents/{result['document_id']}/reconcile"
    )
    assert response.status_code == 200, response.text
    assert response.json()["action"] == "recovered_from_ledger"
    assert response.json()["status"] == "REGISTERED"

    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        assert document.status == "REGISTERED"
        assert document.ledger_transaction_id


def test_reconcile_does_not_overwrite_ledger_conflict(client: TestClient):
    result = register(client)
    runtime = client.app.state.runtime
    ledger_before = runtime.ledger.read(result["document_id"])
    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        document.status = "LEDGER_CONFLICT"
        session.commit()

    response = client.post(
        f"/api/v1/admin/documents/{result['document_id']}/reconcile"
    )
    assert response.status_code == 409
    assert runtime.ledger.read(result["document_id"]) == ledger_before

    with runtime.sessions() as session:
        document = session.get(Document, result["document_id"])
        assert document.status == "LEDGER_CONFLICT"


def test_admin_registry_requires_admin_session(client: TestClient):
    client.cookies.clear()
    response = client.get("/api/v1/admin/documents")
    assert response.status_code == 401
    issuer_response = client.get("/api/v1/admin/issuers")
    assert issuer_response.status_code == 401


def test_benchmark_endpoint_accepts_supported_iteration_count(client: TestClient):
    rejected = client.post(
        "/api/v1/benchmarks/run",
        json={"iterations": 25, "warmup": 0},
    )
    assert rejected.status_code == 422

    response = client.post(
        "/api/v1/benchmarks/run",
        json={"iterations": 100, "warmup": 0},
    )
    assert response.status_code == 200, response.text
    assert response.json()["protocol"]["measured_iterations"] == 100


def test_demo_issuer_provisioning_is_idempotent_and_rejects_key_changes(
    client: TestClient,
):
    runtime = client.app.state.runtime
    issuer_keys = runtime.crypto.create_signing_keypair()

    with runtime.sessions() as session:
        created = ensure_demo_issuer(
            session,
            "provisioned-demo-issuer",
            "Provisioned Demo Issuer",
            issuer_keys.public_key,
            runtime.crypto.signature_algorithm,
        )
        session.commit()
    assert created is True

    with runtime.sessions() as session:
        created_again = ensure_demo_issuer(
            session,
            "provisioned-demo-issuer",
            "Provisioned Demo Issuer",
            issuer_keys.public_key,
            runtime.crypto.signature_algorithm,
        )
        assert created_again is False

        replacement_key = runtime.crypto.create_signing_keypair()
        with pytest.raises(ValueError, match="different registration data"):
            ensure_demo_issuer(
                session,
                "provisioned-demo-issuer",
                "Provisioned Demo Issuer",
                replacement_key.public_key,
                runtime.crypto.signature_algorithm,
            )
