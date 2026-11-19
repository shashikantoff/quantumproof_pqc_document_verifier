# API examples

The commands assume the default Docker deployment at `http://localhost:8000`.

## Register with the demo issuer

```bash
curl -X POST http://localhost:8000/api/v1/documents/register \
  -F "issuer=Example University" \
  -F "file=@./certificate.pdf"
```

The response includes a UUID, SHA-256 digest, key fingerprint, ledger transaction identifier, and a QR-friendly verification URL. It never returns a private key or the original document.

## Register a document signed by an external issuer

On the issuer's computer, generate a local encrypted key file and sign the PDF using the issuer-tools container:

```powershell
New-Item -ItemType Directory -Force issuer-workspace
Copy-Item .\certificate.pdf .\issuer-workspace\
docker compose --profile issuer-tools run --build --rm issuer-tools keygen --output /issuer-workspace/issuer.json
docker compose --profile issuer-tools run --rm issuer-tools sign --key /issuer-workspace/issuer.json --file /issuer-workspace/certificate.pdf --issuer "ISSUER_ID" --output /issuer-workspace/signature.json
```

Enroll the printed public key in the admin issuer workspace. The signature JSON contains the `signing_public_key_b64` and `signature_b64` values used below; the encrypted private key stays in the issuer workspace.

Alternatively, create the ML-DSA signature over the exact domain-separated claim derived from the file hash and base64 encode the signature and issuer public key:

```bash
curl -X POST http://localhost:8000/api/v1/documents/register \
  -F "issuer=Example University" \
  -F "signature_b64=<base64-ml-dsa-signature>" \
  -F "signing_public_key_b64=<base64-ml-dsa-public-key>" \
  -F "file=@./certificate.pdf"
```

The service rejects a supplied signature that does not validate against the uploaded file before it calls the ledger.

## Verify

```bash
curl -X POST http://localhost:8000/api/v1/documents/<document-id>/verify \
  -F "file=@./certificate.pdf"
```

`VALID` means all three controls passed: candidate hash equality, ML-DSA signature validation, and ledger-record consistency. `INDETERMINATE` means a ledger lookup was unavailable or inconsistent and must be investigated.

## Benchmark

```bash
curl -X POST http://localhost:8000/api/v1/benchmarks/run \
  -H "Content-Type: application/json" \
  -d '{"iterations": 50}'
```

Capture the container image digest, CPU model, memory, operating system, algorithm version, iteration count, and all raw results when producing a research table.
