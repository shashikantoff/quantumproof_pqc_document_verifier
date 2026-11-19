# Experimental evaluation protocol

## Research questions

- **RQ1:** What latency and size overhead does ML-DSA-65 / ML-KEM-768 add relative to Ed25519 / X25519 at the application layer?
- **RQ2:** How does end-to-end registration and verification latency vary with document size and ledger backend?
- **RQ3:** Does the framework correctly detect modified files, modified signatures, and ledger-evidence inconsistencies?

## Experimental controls

Run all algorithms inside the same pinned container image on the same host. Record CPU model, core count, RAM, operating system, Docker version, liboqs version, Python version, Fabric version, channel endorsement policy, and database configuration. Disable CPU frequency scaling where practical and avoid concurrent benchmark workloads.

Before running a benchmark, replace `BENCHMARK_DOCKER_VERSION`, `BENCHMARK_FABRIC_VERSION`, `BENCHMARK_POSTGRES_VERSION`, `BENCHMARK_ENDORSEMENT_POLICY`, and `BENCHMARK_SOURCE_REVISION` in the local `.env` with measured/configured values. These values are passed to the API by Compose and appear in the benchmark environment record. The end-to-end runner refuses to start while any of these fields is `not_available`.

Use files of 10 KB, 100 KB, 1 MB, and 10 MB. For each size and configuration, perform 30 warm-up operations followed by at least 100 measured operations. Report median, mean, standard deviation, p95, and a 95% confidence interval. Do not compare a cold container initialization to a warm classical implementation.

## Measurements

| Metric | Method | Unit |
| --- | --- | --- |
| ML-DSA sign / verify | `POST /benchmarks/run`; retain raw JSON | ms/op |
| ML-KEM + AES-GCM envelope | `POST /benchmarks/run`; retain raw JSON | ms/op |
| Classical baseline | Same process, Ed25519/X25519 rows | ms/op |
| Key/signature/ciphertext sizes | Record encoded byte lengths | bytes |
| Registration latency | client request until observed Fabric commit status | ms |
| Verification latency | candidate upload through ledger comparison | ms |
| Throughput | closed-loop concurrent client test | docs/s |
| CPU/RSS | container metrics during tests | %, MiB |

The in-app endpoint is a cryptographic micro-benchmark aid. It is not an end-to-end Fabric benchmark because it intentionally excludes network and consensus effects from cryptographic comparisons.

## End-to-end Fabric run

`backend/app/fabric_e2e_benchmark.py` exercises the deployed FastAPI registration and verification endpoints and requires `/health` to report both `hyperledger-fabric` and real `liboqs`. Registration timing ends only after the API has observed a successful Fabric commit status. It records registration and verification latency, bounded-concurrency throughput for both operations, raw per-request samples, summary statistics, an environment ID, and sampled API-container cgroup CPU/RSS. Capture `docker stats` separately for the Gateway, peers, orderers, and PostgreSQL; those service metrics are not represented by the API-container sample.

Run it from the project root after the Fabric-backed API is healthy and the benchmark metadata above is complete:

```powershell
docker compose exec api python -m app.fabric_e2e_benchmark --confirm-ledger-writes --provision-demo-issuer --issuer "QuantumProof Benchmark" --output-dir /tmp/experiment-results
docker compose cp api:/tmp/experiment-results ./experiment-results
```

Omit `--provision-demo-issuer` only when that issuer is already registered with the API's persisted demo ML-DSA key. The option explicitly enrolls that demo public key in the application database. The default run performs 920 permanent Fabric registrations (including warm-ups and throughput samples) and stores encrypted documents in PostgreSQL; ledger records cannot be cleaned up. Confirm storage capacity and use an isolated research network. If a run fails, its JSON/CSV is marked `failed` and must not be cited as completed evidence.

The command creates timestamped `fabric-e2e-*.json` and `fabric-e2e-*.csv` raw artifacts. Add those generated files to the research ZIP only after a completed run. No result table is populated from estimates; the `TBD` values below remain until corresponding measured evidence exists.

## Correctness and adversarial test matrix

| Test | Input mutation | Expected result |
| --- | --- | --- |
| Baseline | Exact original file | `VALID` |
| One-bit file change | Flip a byte | `INVALID`, hash mismatch |
| Replaced signature | Modify database evidence in an isolated test instance | `INVALID`, signature failure |
| Absent ledger evidence | Query unknown UUID or remove test-ledger row | `INDETERMINATE` / not found |
| Inconsistent ledger field | Alter only development test record | `INDETERMINATE` |
| Bad external signature | Submit signature from a different file | registration rejected |
| Oversized upload | Send file larger than policy limit | HTTP 413 |

## Independent Fabric run accounting

Three independent successful Fabric runs were retained:

- `20261118T121724Z-4aab4c57`
- `20261118T133437Z-8acee635`
- `20261118T140938Z-7f6a2be6`

Run `20261118T130814Z-995f9963` is preserved in
`experiment-results-fabric-e2e-run-2-failed/`. It is not a successful
benchmark run: the runner ended with `RuntimeError: 1 concurrent registration
request(s) failed`. The artifact contains completed sequential results for
several sizes, but no verification-throughput samples and incomplete 1 MB
concurrent registration coverage. It is excluded from all aggregate results.

An earlier provisioning attempt under `experiment-results-fabric-e2e-run-1/`
also remains preserved but is excluded because it failed before benchmark
measurement while the demo signing key was already enrolled under another
issuer ID.

All normal and throughput samples from successful runs remain in their original
JSON and CSV artifacts. The aggregate reports only successful run IDs.

## Statistical reporting limitation

Per-operation and per-document observations are summarized within each run.
The cross-run aggregate pools 300 observations per size/metric
(100 observations × 3 independent runs). Means, medians, sample standard
deviations, interpolated p95 values, and normal 95% confidence intervals are
calculated over the pooled samples. The confidence interval is a
normal approximation using `mean ± 1.96 × (SD / sqrt(n))`. It does not model
run identity as a random effect and should not be interpreted as a hierarchical
between-run confidence interval. Variability is reported both within individual
run summaries and in the pooled cross-run aggregate.

## Security-test scope

The 30-test JUnit suite verifies real liboqs-backed application behavior using
SQLite and the development ledger fixture. It establishes ML-DSA/ML-KEM
application behavior and tamper handling, but it does not establish live
Hyperledger Fabric consensus or gateway behavior. Live Fabric integration
tests are explicitly gated behind `QUANTUMPROOF_LIVE_API_URL`,
`QUANTUMPROOF_LIVE_ADMIN_ID`, and `QUANTUMPROOF_LIVE_ADMIN_PASSWORD`.
They must not be reported as passed until JUnit/external execution evidence
exists.

## Recorded local security-test result

The focused backend suite recorded 29 passing tests and 1 platform-dependent
skip. The document/security cases covering original PDF, modified PDF,
tampered signature, revoked document, wrong issuer key, missing ledger record,
encrypted-PDF round trip, and suspended issuer are represented by
`test_document_flow.py`. These local results use the development-ledger adapter
and in-scope SQLite test database; they do not establish Fabric consensus
behavior. Run the full suite in the pinned Docker environment for the final
paper's Fabric-backed evidence.

## Reporting template

Do not insert illustrative numbers as experimental findings. Fill the following table only from captured raw output:

| Algorithm | Operation | Mean ms | Median ms | P95 ms | n | Environment ID |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| ML-DSA-65 | Sign | TBD | TBD | TBD | 100 | TBD |
| ML-DSA-65 | Verify | TBD | TBD | TBD | 100 | TBD |
| ML-KEM-768 | Envelope round trip | TBD | TBD | TBD | 100 | TBD |
| Ed25519 | Sign | TBD | TBD | TBD | 100 | TBD |
| X25519 | Agreement | TBD | TBD | TBD | 100 | TBD |
