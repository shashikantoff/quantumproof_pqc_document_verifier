# Reproducibility baseline

This baseline records the resolved build inputs as of 2026-10-03. The Python API and its test image target `linux/amd64`.

## Runtime and build inputs

| Component | Pinned input |
| --- | --- |
| Python base | `python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3` (Python 3.12.15) |
| Debian build packages | Debian Bookworm and Bookworm Security snapshot `20260901T000000Z` |
| liboqs | Commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` (release 0.16.0) |
| Python runtime packages | Exact top-level pins in `backend/requirements.txt`; transitive versions and artifact hashes in `backend/requirements.lock` |
| Python test packages | `backend/requirements-dev.txt` and the hashed `backend/requirements-dev.lock` |
| Frontend | React and React DOM 19.3.0; Vite 8.3.2; `@vitejs/plugin-react` 6.1.1 |
| Fabric gateway | `@grpc/grpc-js` 1.14.5; `@hyperledger/fabric-gateway` 1.12.1; Express 4.21.2 |
| JavaScript package manager | pnpm 11.19.0; both applications use `pnpm-lock.yaml` and frozen installs |
| Python lock generator | uv 0.10.2 |
| Node base | `node:22.22.2-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f` |
| Nginx base | `nginx:stable-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94` (Nginx 1.30.5) |
| PostgreSQL | `postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea` (PostgreSQL 16.15) |
| Fabric peer | `hyperledger/fabric-peer:2.5.16@sha256:09ee75042de9983bfde31ca88a5bf033386351f10a990e4c48264ee50172dee0` |
| Fabric orderer | `hyperledger/fabric-orderer:2.5.16@sha256:e322c57331d37e0a35ffae3cb3d3265a0e852211c0f801f2514cc15b964ffc93` |
| Fabric CA | `hyperledger/fabric-ca:1.5.17@sha256:fac0c4a70afc2fe6ae291ffb3c6d27db87ac638ecf5b5418841c7363588e568a` |
| Fabric chaincode builder | `hyperledger/fabric-ccenv:2.5.16@sha256:19ea2b3c144055807cac5ad1a0cd19f89753e930e06a4b6b261f12d7087ae3b4` |
| Fabric chaincode runtime | `hyperledger/fabric-baseos:2.5.16@sha256:0087a600908f792a46c6850a1383b54b11e0bd451e9dcdbd1505dcf9e30a1511` |
| Optional CouchDB state database | `couchdb:3.4.2@sha256:2817ad50b5c5cf7461f5963670466197426605a790a19a6208068c509a2d8a59` |
| Go chaincode | Go language level 1.22; module versions and checksums in `fabric/chaincode/document/go.mod` and `go.sum` |

The container digests are multi-platform index digests. The Python API and tests are explicitly built for `linux/amd64`, matching the Python lock target. The Fabric chaincode is built by the Fabric peer environment; record that peer's Go toolchain as part of each deployment.

## Fabric network version

The default bundled Fabric test network now uses the 2.5.16 and 1.5.17 image digests above; the installer defaults to those same releases. `docs/fabric-deployment.md` still supports an external Fabric 2.4+ network. The project copy has no Git metadata, and the network may be a separate WSL checkout, so these pins do not prove which version is currently running. Record the actual `peer version` output and Fabric CA version in the experiment notes and set `BENCHMARK_FABRIC_VERSION` in the local `.env` before a benchmark.

## Rebuilding locks

Keep the direct dependency files as the reviewed inputs. After intentionally changing a JavaScript version, regenerate its lock with pnpm 11.19.0 and commit both files together:

```powershell
Push-Location frontend
pnpm install --lockfile-only
Pop-Location

Push-Location fabric/gateway
pnpm install --lockfile-only
Pop-Location
```

After intentionally changing a Python dependency, use uv 0.10.2 to regenerate both hashed locks for Python 3.12.15 on Linux x86_64:

```powershell
uv pip compile backend/requirements.txt -o backend/requirements.lock --python-version 3.12.15 --python-platform x86_64-unknown-linux-gnu --generate-hashes
uv pip compile backend/requirements-dev.txt -o backend/requirements-dev.lock --python-version 3.12.15 --python-platform x86_64-unknown-linux-gnu --generate-hashes
```

Build application images with `docker compose up --build`. Run the isolated backend test image with `docker compose run --build --rm api-tests`.

## Benchmark metadata

The root `.env.example` contains `BENCHMARK_DOCKER_VERSION`, `BENCHMARK_FABRIC_VERSION`, and `BENCHMARK_POSTGRES_VERSION`. Replace the `not_available` values in the private `.env` with the measured Docker Engine, Fabric peer, and PostgreSQL versions. Preserve the raw benchmark JSON with the source revision, host CPU/OS, channel endorsement policy, lockfiles, and image digests. A source archive without Git metadata must also record its originating commit separately.
