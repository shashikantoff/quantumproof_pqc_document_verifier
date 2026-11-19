# Quantum-Resistant Blockchain Document Verifier

A research/educational prototype for registering, encrypting, signing, and verifying documents using **post-quantum cryptography (PQC)** with **Hyperledger Fabric** as a permissioned, tamper-evident ledger.

The application uses the NIST-standardized names **ML-DSA** and **ML-KEM** (formerly CRYSTALS-Dilithium and CRYSTALS-Kyber). The current implementation uses **ML-DSA-65** for digital signatures and **ML-KEM-768** for key encapsulation.

---

## 1. What the Project Does

The system provides an end-to-end document registration and verification workflow:

1. An authorized issuer uploads a PDF document.
2. The backend validates the PDF and calculates its **SHA-256** digest.
3. The digest is signed using **ML-DSA-65**.
4. A document-encryption key is established using **ML-KEM-768** and used with **AES-256-GCM** to encrypt the stored document.
5. The encrypted document and application metadata are stored in **PostgreSQL**.
6. A compact document commitment is registered through the **Fabric Gateway** on **Hyperledger Fabric**.
7. The system returns a document ID and QR-based verification URL.
8. A verifier can upload a candidate PDF or open the QR URL.
9. The candidate document is hashed again, its signature is checked, and the stored Fabric record is compared.
10. The system reports **VALID**, **INVALID**, **REVOKED**, or **INDETERMINATE** according to the verification checks.
11. Application-level audit events record registration, verification, and administrative actions.

The cryptography is implemented at the application layer. Hyperledger Fabric provides the permissioned ledger, transaction history, ordering, and organization-level trust model.

---

## 2. Core Technology Stack

| Layer | Technology |
| --- | --- |
| Frontend | React + Vite |
| Backend API | FastAPI + Python |
| Database | PostgreSQL |
| Permissioned Ledger | Hyperledger Fabric |
| Smart Contract | Go chaincode |
| Ledger Bridge | Node.js Fabric Gateway |
| Digital Signature | ML-DSA-65 |
| Key Encapsulation | ML-KEM-768 |
| Symmetric Encryption | AES-256-GCM |
| Document Hash | SHA-256 |
| Containerization | Docker + Docker Compose |
| QR Verification | QR code linked to public verification route |

Pinned package versions, lockfiles, container image digests, and the Fabric version-recording procedure are documented in [`docs/reproducibility.md`](docs/reproducibility.md).

---

## 3. System Workflow

### Registration

```text
Issuer
  │
  ▼
React Frontend
  │
  ▼
FastAPI Backend
  │
  ├── Validate PDF
  ├── SHA-256
  ├── ML-DSA-65 signature
  ├── ML-KEM-768 key encapsulation
  └── AES-256-GCM encryption
          │
          ├──────────────► PostgreSQL
          │
          └──────────────► Fabric Gateway
                                  │
                                  ▼
                         Hyperledger Fabric
                                  │
                                  ▼
                            Document Ledger
```

### Verification

```text
Verifier
  │
  ├── Upload candidate PDF
  │
  └── Open QR verification URL
          │
          ▼
     FastAPI Backend
          │
          ├── SHA-256 candidate hash
          ├── ML-DSA signature verification
          ├── PostgreSQL document lookup
          └── Fabric ledger verification
                  │
                  ▼
          Verification Decision
          ├── VALID
          ├── INVALID
          ├── REVOKED
          └── INDETERMINATE
```

---

## 4. Cryptographic Design

### ML-DSA-65 — Digital Signature

The document hash is converted into a domain-separated signing claim and signed using **ML-DSA-65**.

This provides authenticity and allows the verifier to detect a mismatch between the registered document and a candidate document.

### ML-KEM-768 — Key Encapsulation

**ML-KEM-768** is used to establish a shared secret for document encryption.

The shared secret is transformed into a 32-byte AES key using the project's domain-separated key derivation step.

### AES-256-GCM — Document Encryption

The original document is encrypted with **AES-256-GCM** using:

- a fresh 12-byte nonce;
- a 256-bit derived encryption key;
- authenticated associated data defined by the application.

The database stores the encrypted document rather than the plaintext document.

### SHA-256 — Document Commitment

The SHA-256 digest is the primary document commitment used throughout registration and verification.

---

## 5. What Is Stored on the Blockchain?

The complete document is **not** written to Hyperledger Fabric.

The Fabric record contains a compact commitment and verification metadata such as:

- document ID;
- SHA-256 document hash;
- signature digest;
- public-key fingerprint;
- signing algorithm;
- KEM algorithm;
- issuer information;
- document size;
- registration timestamp;
- ledger transaction/block information.

The encrypted document and application records remain in PostgreSQL.

This separation keeps the blockchain record compact while allowing the ledger to provide an independent, tamper-evident registration history.

> **Important:** PostgreSQL audit events and Hyperledger Fabric history are different things. PostgreSQL stores application/audit information; Fabric stores the blockchain evidence and transaction history.

---

## 6. Verification Logic

For a candidate document, the backend performs the following checks:

1. Calculate the candidate's SHA-256 hash.
2. Compare it with the registered document hash.
3. Verify the stored ML-DSA signature against the candidate-document claim.
4. Read the corresponding record from Fabric.
5. Compare the ledger record with the application's registered record.
6. Check the document status, including revocation state.
7. Produce the final verification status.

### Expected behavior

| Situation | Result |
| --- | --- |
| Original document, valid signature, valid ledger record | `VALID` |
| Document bytes changed | `INVALID` |
| Stored signature is altered/invalid | `INVALID` |
| Document has been revoked | `REVOKED` |
| Required evidence cannot be conclusively established | `INDETERMINATE` |

A changed document can therefore show both a **hash mismatch** and an **invalid signature**, because the signature was generated for the original document hash.

---

## 7. External Issuer Signing

The system also supports an issuer-controlled signing flow.

Instead of sending an issuer secret key to the server, an external issuer can provide:

- `signature_b64`
- `signing_public_key_b64`

The backend validates the supplied public key against the registered issuer and verifies the signature before registering the document.

This is preferable to uploading issuer private keys and provides a cleaner separation between the issuing authority and the verifier service.

### Generate a key and sign documents on the issuer's computer

Run these commands from the project root on the issuer's own computer. Docker builds a separate tool image; it does not connect to the running API or receive server credentials. The key workspace is git-ignored.

```powershell
New-Item -ItemType Directory -Force issuer-workspace
Copy-Item .\certificate.pdf .\issuer-workspace\

docker compose --profile issuer-tools run --build --rm issuer-tools keygen --output /issuer-workspace/example-university.json
docker compose --profile issuer-tools run --rm issuer-tools sign --key /issuer-workspace/example-university.json --file /issuer-workspace/certificate.pdf --issuer "ISSUER_ID" --output /issuer-workspace/certificate-signature.json
```

The key-generation command prompts for a passphrase and stores an encrypted private key in `issuer-workspace`. It prints the public key and fingerprint; enroll that public key in the admin issuer workspace and compare the fingerprint with the issuer through a trusted channel. The signing command prompts for the passphrase and writes only public registration fields and the PDF signature to `certificate-signature.json`.

In the admin registration form, select **Issuer-signed external key**, upload the same PDF, and paste `signing_public_key_b64` and `signature_b64` from the generated JSON. The private key never leaves the issuer's computer. Back up the encrypted key file and passphrase separately; losing either means the key cannot sign future documents.

The built-in server-side issuer key path is retained for the educational/demo workflow.

---

## 8. Hyperledger Fabric Integration

The project uses a Node.js **Fabric Gateway** between FastAPI and the Fabric network.

```text
FastAPI
   │
   ▼
Fabric Gateway
   │
   ▼
Hyperledger Fabric Network
   ├── Org1 Peer
   ├── Org2 Peer
   ├── Orderer
   └── Document Chaincode
```

The Go chaincode manages document registration, reading, revocation, and history operations used by the application.

The project uses the Fabric channel:

```text
documentchannel
```

and the document chaincode:

```text
document
```

The application selects the ledger implementation through:

```env
LEDGER_BACKEND=fabric
```

and connects to the gateway using:

```env
FABRIC_GATEWAY_URL=http://fabric-gateway:3000
FABRIC_GATEWAY_TOKEN=<your-token>
```

---

## 9. Project Structure

```text
quantum-document-verifier/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── crypto.py
│   │   ├── database.py
│   │   ├── ledger.py
│   │   ├── config.py
│   │   └── benchmarks.py
│   ├── tests/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── requirements.lock
│   ├── requirements-dev.txt
│   └── requirements-dev.lock
│
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── Dockerfile
│   └── nginx.conf
│
├── fabric/
│   ├── chaincode/
│   │   └── document/
│   │       ├── document.go
│   │       └── go.mod
│   └── gateway/
│       ├── server.js
│       ├── package.json
│       └── .env
│
├── docs/
├── paper/
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## 10. Main API Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/documents/register` | Register a PDF document |
| `POST /api/v1/documents/{id}/verify` | Verify a candidate document |
| `GET /api/v1/documents/{id}` | Read public document registration information |
| `GET /api/v1/admin/documents` | List document records by status with admin-only pagination and reconciliation context |
| `GET /api/v1/admin/issuers` | List enrolled issuers and audited lifecycle/key history (admin only) |
| `POST /api/v1/admin/issuers` | Enroll an issuer public key (admin only) |
| `PATCH /api/v1/admin/issuers/{id}/status` | Activate or suspend an issuer (admin only) |
| `POST /api/v1/admin/issuers/{id}/rotate-key` | Rotate an issuer public key while preserving existing document evidence (admin only) |
| `GET /api/v1/documents/{id}/audit` | Read application audit events |
| `POST /api/v1/documents/{id}/revoke` | Revoke a registered document |
| `POST /api/v1/admin/documents/{id}/reconcile` | Recover a pending/failed registration after a DB/Fabric boundary failure (admin only) |
| `DELETE /api/v1/documents/{id}` | Delete an application record when allowed |
| `POST /api/v1/benchmarks/run` | Run the cryptographic benchmark |
| `GET /health/live` | Check whether the API process is running |
| `GET /health/ready` | Check database and ledger readiness (503 when unavailable) |
| `GET /metrics` | Prometheus metrics for API requests and database/ledger availability |

API documentation is available from FastAPI at:

```text
http://localhost:8000/docs
```

---

## 11. QR Verification

Each registered document can have a QR verification URL.

For local-network demonstration, the project can use the machine's LAN address through:

```env
PUBLIC_BASE_URL=http://<your-lan-ip>:8080
```

For example:

```env
PUBLIC_BASE_URL=http://192.168.1.39:8080
```

The phone and computer must be on the same network for a private LAN URL to work.

For public deployment, use a proper HTTPS domain and reverse proxy rather than exposing the development URL directly.

---

## 12. Admin, Revocation and Audit

The project includes an administrative workflow for actions that should not be publicly available.

### Admin authentication

The backend supports:

- admin login;
- password hashing;
- session tokens;
- session expiry/revocation;
- protected administrative operations.

Login is throttled per client IP (five failed attempts in a 15-minute window by default; configure `ADMIN_LOGIN_ATTEMPT_LIMIT` and `ADMIN_LOGIN_WINDOW_SECONDS`). Browser login and admin mutations reject unexpected `Origin`/`Referer` origins. The session cookie is HTTP-only, `SameSite=Strict`, and can be marked `Secure` with `ADMIN_COOKIE_SECURE=true`; enable that setting whenever the app is served over HTTPS. Keep the API behind the configured reverse proxy so its `X-Real-IP` value cannot be supplied by an untrusted client.

### Revocation

A registered document can be revoked through the administrative flow.

The Fabric record is updated first. If the ledger operation fails, the application does not falsely mark the document as successfully revoked.

A revoked document is returned as:

```text
REVOKED
```

during verification.

### Audit trail

Application-level audit events record important actions such as:

- registration;
- verification;
- revocation;
- administrative operations;
- relevant failures.

Fabric history remains the blockchain-side evidence.

---

## 13. Security Model and Boundaries

### Confidentiality

The original document is encrypted using AES-256-GCM. The AES key is derived from the ML-KEM-768 shared secret.

### Authenticity

ML-DSA-65 signs a domain-separated SHA-256 document claim.

### Integrity

SHA-256 provides the document commitment used for comparison during verification.

### Traceability

Hyperledger Fabric provides an immutable ledger record, transaction identifiers, and history.

### Key handling

The demo deployment persists server-side issuer/archive keys in the Docker `pqc-keys` volume.

For production:

- issuers should keep signing private keys in their own secure environment;
- HSM/KMS integration should replace the demo file keystore;
- issuer secret keys should never be uploaded to the verifier service.

The server-side signing path is therefore a **research/demo convenience**, not a recommended production separation-of-duties model.

---

## 14. Local Setup

### Prerequisites

Install:

- Docker Desktop
- Docker Compose support
- WSL2 when required by Docker Desktop on Windows

No host Python or Node.js installation is required for the Docker-based application.

### Start the Application

On a first-time setup, create `.env` from `.env.example`, then replace the admin password placeholder with a unique password. Do not overwrite an existing `.env` file. Keep the file local and out of source control. When enabling Fabric, also create `fabric/gateway/.env` from its example, set the certificate paths to the mounted files, and use the same fresh gateway token in both `.env` files.

From the project root:

```powershell
docker compose up --build -d
```

On startup, the API applies Alembic migrations before serving requests. A complete legacy schema created by the previous `create_all` startup is checked and stamped at the baseline revision before newer migrations are applied. A partial or mismatched legacy schema stops startup with an explicit error instead of being silently marked current.

For a Fabric-backed `.env`, use the optional network overlay instead (the `fabric_test` network and gateway must already be running):

```powershell
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up --build -d
```

Check the containers:

```powershell
docker compose ps
```

Open:

```text
Frontend: http://localhost:8080
API Docs: http://localhost:8000/docs
```

For the first run, provision the demo issuer used by the registration page:

```powershell
docker compose exec api python -m app.provision_demo_issuer
```

This command is idempotent for the same issuer key. The demo issuer is for local evaluation only; production issuers should be enrolled through an authenticated, organization-controlled process.

### Stop the Application

```powershell
docker compose down
```

To stop without removing the database volume:

```powershell
docker compose stop
```

### PostgreSQL backup and restore

The helper uses the Compose PostgreSQL service and streams a custom-format dump directly to a local file. Backups can contain sensitive document metadata; store them on encrypted, access-controlled storage.

```powershell
python scripts/database_ops.py backup --output backups\quantumproof-2026-09-09.dump
python scripts/database_ops.py verify backups\quantumproof-2026-09-09.dump
```

`verify` restores the archive into a uniquely named disposable database, checks that the `documents` table can be queried, and removes only that temporary database. To perform an actual restore, use a **new database name**; the helper refuses to overwrite the live `verifier` database or any existing target:

```powershell
python scripts/database_ops.py restore backups\quantumproof-2026-09-09.dump --database verifier_restore
```

After validating the restored database, switch `DATABASE_URL` during a planned maintenance window. The original database remains unchanged.

### Monitoring and alerts

Prometheus and Alertmanager are available in the optional monitoring profile. Set `ALERT_WEBHOOK_URL` in the local `.env` to an Alertmanager-compatible webhook endpoint, then run:

```powershell
docker compose --profile monitoring up -d
```

Prometheus is available at `http://localhost:9090`; Alertmanager is available at `http://localhost:9093`. Both bind to loopback. Alerts cover API scrape failure, database/ledger unavailability, and sustained API 5xx responses. The health endpoint performs live dependency probes; the web service remains reachable during a dependency outage so administrators can still inspect the UI while the API reports itself unhealthy.

---

## 15. Fabric Startup / Restart

The Fabric test network is separate from the main application Compose stack.

After a Docker Desktop or PC restart, Fabric containers may need to be started again.

From WSL, start the Fabric test network if needed:

```bash
cd ~/fabric-samples/test-network

docker start ca_orderer ca_org1 ca_org2   orderer.example.com   peer0.org1.example.com   peer0.org2.example.com
```

From the project root, build and recreate the gateway so it loads the current environment and pinned image:

```bash
docker compose -f fabric/docker-compose.fabric-gateway.yml up -d --build --force-recreate fabric-gateway
```

Check:

```bash
docker ps
```

The project application containers and Fabric network have different lifecycles. If the FastAPI, frontend, and PostgreSQL containers are running but Fabric is stopped, blockchain-backed registration/verification will not work until the Fabric network and gateway are available.

---

## 16. Testing

Run the automated backend tests with:

```powershell
docker compose run --build --rm api-tests
```

The test suite covers important positive and negative cases, including:

- registration and verification;
- encrypted document storage/decryption;
- changed document bytes;
- altered stored signatures;
- external issuer signatures.
- migration of fresh and legacy schemas without losing existing admin records;
- login throttling, cross-origin rejection, and readiness/metrics behavior.

Run the isolated browser end-to-end suite with:

```powershell
docker compose -f docker-compose.e2e.yml run --build --rm e2e
docker compose -f docker-compose.e2e.yml down --volumes
```

The E2E stack uses a separate Compose project and a temporary PostgreSQL filesystem; it does not connect to or remove the normal application database. The suite exercises browser login, PDF registration, public verification, and the admin reconciliation interaction (the recovery response is simulated at the browser boundary).

Before reporting benchmark numbers, use the project's experiment protocol and record the actual environment and measured results.

---

## 17. Cryptographic Benchmark

The project contains a benchmark for comparing the implemented PQC operations with classical comparison algorithms.

Run:

```powershell
docker compose run --rm api python -m app.benchmark --iterations 100
```

The benchmark is a measurement tool; its output should be treated as experimental data from the actual execution environment, not as a fixed performance claim.

---

## 18. Algorithm Summary

| Purpose | Project Algorithm | Classical Comparison |
| --- | --- | --- |
| Digital signature | ML-DSA-65 | Ed25519 |
| Key establishment | ML-KEM-768 | X25519 |
| Document encryption | AES-256-GCM | AES-256-GCM |
| Document hash | SHA-256 | SHA-256 |

The project uses the standardized ML-DSA/ML-KEM names while retaining the former Dilithium/Kyber terminology only where it helps explain the technology.

If liboqs is unavailable, the development-only fallback is explicitly labeled by the health/runtime status. The fallback must not be treated as the project's production cryptographic configuration.

---

## 19. Deployment and Production Considerations

This project is intended for educational/research demonstration and should receive a security review before operational deployment.

For a production deployment, consider:

- HTTPS/TLS through a reverse proxy;
- stronger issuer authentication and organization-level authorization;
- HSM/KMS-backed key management;
- encrypted storage for database and key material;
- rate limiting and stricter file-size controls;
- secure secret management instead of committed `.env` secrets;
- independent PostgreSQL and Fabric backups;
- monitoring and alerting;
- deliberate dependency and container-image updates following the reproducibility guide;
- the built-in admin reconciliation endpoint for failures between PostgreSQL and Fabric; it retries missing ledger writes and recovers matching ledger commits without overwriting conflicts.

The admin registry lists pending, failed, conflicting, registered, and revoked records. It provides a reconciliation action for pending or failed records; conflicts remain explicitly marked for manual investigation. The issuer workspace at `/admin/issuers` supports public-key enrollment, key rotation, activation/suspension, and a management history. Administrators must independently confirm issuer key fingerprints through a trusted channel. Private keys are never uploaded, and the server-managed demo key cannot be rotated through issuer management.

### Recommended next implementation priorities

The registry is shared across admin sessions, issuer lifecycle actions are audited, and demo issuer setup is available as a CLI command. Before multi-organization or production use, prioritize:

1. Database migrations, login throttling/CSRF protection, deployment-specific monitoring, and an external KMS/HSM integration.
2. Issuer proof-of-possession onboarding, stronger organization-level roles, and multi-factor administrator authentication.

Keep the product focused on document evidence and verification. OCR, AI classification, face recognition, chatbots, NFTs/tokens, unrelated chains, and a separate mobile app do not address the core reliability gaps and should remain out of scope unless a concrete requirement emerges.

Do not publish benchmark values, security claims, or experimental conclusions without measuring them on the target environment.

---

## 20. Important Architecture Boundary

The system has two complementary persistence layers:

```text
PostgreSQL
│
├── encrypted document
├── document metadata
├── issuer information
├── admin/session information
├── application state
└── application audit events

Hyperledger Fabric
│
├── document commitment
├── ledger metadata
├── transaction information
└── immutable transaction/history evidence
```

PostgreSQL is therefore **not a replacement for the blockchain**, and the blockchain is **not a replacement for the application database**.

---

## 21. Current Project Scope

The core project intentionally focuses on:

- post-quantum document signatures;
- post-quantum key encapsulation;
- authenticated document encryption;
- document integrity verification;
- permissioned blockchain registration;
- tamper detection;
- document revocation;
- auditability;
- QR-based verification;
- Dockerized deployment.

Features such as AI classification, OCR, face recognition, chatbots, NFTs/tokens, additional blockchain networks, and a separate mobile application are outside the current core scope.

Keeping the architecture focused makes the cryptographic and blockchain contribution easier to demonstrate and evaluate.

---

## 22. License / Usage

Educational and research use.

A complete security review is required before using the system for real-world document issuance or high-value records.
