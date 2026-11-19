import os

import httpx
import pytest

from app.crypto import CryptoProvider, b64encode, document_claim
from app.ledger import FabricGatewayLedger, LedgerError


LIVE_API_URL = os.environ.get("QUANTUMPROOF_LIVE_API_URL")
LIVE_ADMIN_ID = os.environ.get("QUANTUMPROOF_LIVE_ADMIN_ID")
LIVE_ADMIN_PASSWORD = os.environ.get("QUANTUMPROOF_LIVE_ADMIN_PASSWORD")

pytestmark = pytest.mark.skipif(
    not (LIVE_API_URL and LIVE_ADMIN_ID and LIVE_ADMIN_PASSWORD),
    reason="live Fabric integration environment not configured",
)


PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"trailer<</Root 1 0 R>>\n"
    b"%%EOF\n"
)


def _login() -> tuple[httpx.Client, str]:
    client = httpx.Client(base_url=LIVE_API_URL, timeout=30.0)
    response = client.post(
        "/api/v1/auth/login",
        data={
            "admin_id": LIVE_ADMIN_ID,
            "password": LIVE_ADMIN_PASSWORD,
        },
    )
    assert response.status_code == 200, response.text
    return client, response.cookies.get("quantumproof_admin_session", "")


def test_live_fabric_wrong_external_signature_is_rejected():
    crypto = CryptoProvider(allow_insecure_demo=False)
    pair = crypto.create_signing_keypair()
    issuer_id = "Live Fabric Wrong Signature Test"
    with _login()[0] as client:
        enrolled = client.post(
            "/api/v1/admin/issuers",
            json={
                "issuer_id": issuer_id,
                "organization": issuer_id,
                "public_key_b64": b64encode(pair.public_key),
            },
        )
        assert enrolled.status_code == 201, enrolled.text

        content = PDF_BYTES.replace(b"%%EOF", b" live-fabric%%EOF", 1)
        wrong_document_hash = __import__("hashlib").sha256(b"wrong document").hexdigest()
        wrong_signature = crypto.sign(
            document_claim(wrong_document_hash),
            pair.secret_key,
            crypto.signature_algorithm,
        )
        rejected = client.post(
            "/api/v1/documents/register",
            data={
                "issuer": issuer_id,
                "signature_b64": b64encode(wrong_signature),
                "signing_public_key_b64": b64encode(pair.public_key),
            },
            files={"file": ("wrong-signature.pdf", content, "application/pdf")},
        )
        assert rejected.status_code == 422
        assert "does not validate" in rejected.json()["detail"]


def test_live_fabric_encrypted_pdf_upload_and_admin_decryption():
    with _login()[0] as client:
        issuer_id = "Live Fabric Wrong Signature Test"
        issuers = client.get("/api/v1/admin/issuers")
        assert issuers.status_code == 200
        if not any(item["issuer_id"] == issuer_id for item in issuers.json()["items"]):
            pytest.skip("live issuer fixture is not available")

        registered = client.post(
            "/api/v1/documents/register",
            data={"issuer": issuer_id},
            files={"file": ("round-trip.pdf", PDF_BYTES, "application/pdf")},
        )
        assert registered.status_code == 201, registered.text

        document_id = registered.json()["document_id"]
        decrypted = client.get(
            f"/api/v1/admin/documents/{document_id}/decrypt"
        )
        assert decrypted.status_code == 200
        assert decrypted.content == PDF_BYTES


@pytest.mark.skipif(
    not os.environ.get("QUANTUMPROOF_LIVE_FABRIC_GATEWAY_URL"),
    reason="live Fabric gateway URL not configured",
)
def test_live_fabric_unavailable_gateway_is_reported_as_ledger_error():
    ledger = FabricGatewayLedger(
        os.environ["QUANTUMPROOF_LIVE_FABRIC_GATEWAY_URL"],
        os.environ.get("QUANTUMPROOF_LIVE_FABRIC_GATEWAY_TOKEN", "invalid-test-token"),
    )
    with pytest.raises(LedgerError):
        ledger.read("00000000-0000-0000-0000-000000000000")


def test_live_fabric_ledger_field_mismatch_requires_mutation_fixture():
    pytest.skip(
        "live Fabric field mismatch requires an isolated gateway or "
        "chaincode fixture that can alter only a committed field"
    )
