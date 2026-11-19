# Architecture and security design

## Component responsibilities

```text
Issuer / verifier browser
           │ HTTPS + REST
           ▼
React portal ───────────────► FastAPI verification service
                                      │        │
                         PostgreSQL (ciphertext, signature, audit)
                                      │        │ compact evidence
                                      │        ▼
                                      │  Fabric gateway bridge
                                      │        │ mTLS + enrolled identity
                                      ▼        ▼
                              ML-DSA / ML-KEM   Hyperledger Fabric ledger
```

The React portal never implements cryptography in JavaScript. This avoids browser-side algorithm substitution and permits institutional issuers to move signing into an HSM-backed service. The FastAPI service exposes the same API to a separate issuer integration.

## Registration sequence

1. The service limits the incoming file, calculates `SHA-256(file)`, then forms a domain-separated claim: `PQC-DOCUMENT-VERIFY/v1|sha256:<digest>`.
2. In demo mode it signs the claim with the persisted issuer ML-DSA-65 key. In production mode an issuer may send a precomputed signature and public key; the service verifies it before accepting the document.
3. The service creates a fresh ML-KEM-768 shared secret by encapsulating to the archive recipient public key. `SHA-256("PQC-DOC-AES-KEY/v1" || shared_secret)` becomes a one-time AES-256-GCM key. The encrypted document, nonce, and KEM ciphertext are stored in PostgreSQL.
4. The service sends an immutable record to Fabric containing the document ID, document hash, signature digest, public-key fingerprint, algorithms, issuer, size, and timestamp. It stores neither document bytes nor raw public keys/signatures on-chain.
5. The database record is first persisted as `PENDING`. Only after a successful ledger commit does it become `REGISTERED`. If the ledger call fails or times out, the record is retained as `LEDGER_FAILED` rather than discarded. An authenticated admin can reconcile it: a matching existing ledger record is recovered without duplication; an absent ledger record is retried; a conflicting ledger record is marked `LEDGER_CONFLICT` and is not overwritten automatically.

Administrators manage external issuer public keys in the issuer workspace. Enrollment, suspension/reactivation, and key rotation are recorded in an issuer management history. Rotation changes the key used for future registrations; existing document records retain their original public key and remain independently verifiable. Issuer private keys are never uploaded, and administrators must confirm public-key fingerprints with issuers through a trusted channel. The server-managed demo key is excluded from external rotation.

## Verification sequence

1. The candidate file’s hash is recalculated.
2. The stored ML-DSA signature is verified over the registered hash claim using the stored public key.
3. The Fabric record is fetched independently through the gateway and compared field-by-field with the application record.
4. A result is `VALID` only if all three checks pass. A changed file is `INVALID`; unavailable or inconsistent ledger evidence is `INDETERMINATE`, never silently accepted.

## Threat controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Modified document | SHA-256 equality plus ML-DSA verification and Fabric evidence | SHA-256/ML-DSA cryptanalysis or compromised issuer key |
| Database alteration | Fabric comparison detects changes to committed evidence | An attacker can delete records or ciphertext; backups are needed |
| Ledger rewriting | Fabric endorsement/orderer policies and immutable chaincode record | Depends on consortium governance and policy configuration |
| Archive database disclosure | AES-GCM encryption with per-document ML-KEM secret | Archive recipient secret key compromise |
| Server demo-key compromise | Explicitly limited to demo mode | Use external issuer/HSM mode in production |
| Replay of an identical file | Document ID and audit log provide event context | Content-only signatures intentionally do not bind mutable display metadata |

## Database lifecycle, admin sessions, and service monitoring

Alembic revisions are the source of truth for schema changes. The API applies pending revisions before accepting traffic. A legacy `create_all` database is adopted only after all baseline tables and columns are present; partial schemas fail startup rather than being stamped as current. PostgreSQL backups use custom-format `pg_dump`; the verification command restores into a uniquely named disposable database and checks a table query. Actual restores always target a new database, never an existing production database.

Admin sessions use random opaque tokens whose hashes are stored in PostgreSQL. Login attempts are rate-limited per reverse-proxy client IP; Nginx overwrites `X-Real-IP`, so the API must not be exposed directly to untrusted clients. Admin cookies are HTTP-only and `SameSite=Strict`; set `ADMIN_COOKIE_SECURE=true` behind HTTPS. Login and authenticated state-changing requests validate `Origin` (or `Referer` when `Origin` is absent) against `CORS_ORIGINS`.

`/health/live` reports process liveness, `/health/ready` probes PostgreSQL and the configured ledger, and `/metrics` exposes Prometheus request counters and dependency gauges. The optional monitoring profile evaluates alerts for API scrape failure, dependency outages, and sustained server errors, then posts notifications to the configured Alertmanager-compatible webhook.

## Key lifecycle

- **Issuer ML-DSA key:** rotate by registering a new public-key fingerprint and maintaining a trust registry outside this prototype. Existing signatures remain verifiable.
- **Archive ML-KEM key:** preserve historical private keys until all associated ciphertexts are retired or re-encrypted. A key rotation must decrypt/re-encrypt each document under a new recipient key; it does not change the Fabric evidence.
- **Application secrets:** the Compose key volume is demonstrative only. Production should use a KMS/HSM and separate the issuer signing service from the storage service.
- **Hybrid migration:** consider signing with both ML-DSA and a mature classical scheme during policy transition, retaining both signature digests in an evolved chaincode schema.
