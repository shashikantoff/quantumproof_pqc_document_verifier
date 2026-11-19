"""Capture end-to-end registration and verification timings against Fabric."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from .config import get_settings
from .crypto import CryptoProvider, FileKeyStore, fingerprint
from .database import Issuer, make_engine

DEFAULT_SIZES_BYTES = (10_000, 100_000, 1_000_000, 10_000_000)
CSV_FIELDS = (
    "environment_id",
    "size_bytes",
    "metric",
    "phase",
    "sample_index",
    "latency_ms",
    "document_id",
    "transaction_id",
    "block_number",
    "overall_status",
)


def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    rank = (len(ordered) - 1) * percentile / 100
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def _summarize(samples: list[float]) -> dict[str, float | int | str]:
    mean = statistics.fmean(samples)
    standard_deviation = statistics.stdev(samples) if len(samples) > 1 else 0.0
    margin = 1.96 * standard_deviation / (len(samples) ** 0.5)
    return {
        "n": len(samples),
        "mean_ms": round(mean, 4),
        "median_ms": round(statistics.median(samples), 4),
        "stddev_ms": round(standard_deviation, 4),
        "p95_ms": round(_percentile(samples, 95), 4),
        "ci95_low_ms": round(mean - margin, 4),
        "ci95_high_ms": round(mean + margin, 4),
        "ci95_method": "normal approximation (1.96 * SE)",
    }


def _pdf_bytes(size_bytes: int) -> bytes:
    header = b"%PDF-1.4\n% benchmark " + uuid.uuid4().hex.encode("ascii") + b"\n"
    catalog = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pages = b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    object_one_offset = len(header)
    object_two_offset = object_one_offset + len(catalog)
    cross_reference_offset = object_two_offset + len(pages)
    cross_reference = (
        "xref\n0 3\n"
        "0000000000 65535 f \n"
        f"{object_one_offset:010d} 00000 n \n"
        f"{object_two_offset:010d} 00000 n \n"
    ).encode("ascii")
    trailer = (
        "trailer\n<< /Size 3 /Root 1 0 R >>\n"
        f"startxref\n{cross_reference_offset}\n%%EOF\n"
    ).encode("ascii")
    content = header + catalog + pages + cross_reference + trailer
    if len(content) > size_bytes:
        raise ValueError("document size is too small for a valid PDF payload")
    return content + b" " * (size_bytes - len(content))


def _required_versions() -> dict[str, str]:
    keys = (
        "BENCHMARK_DOCKER_VERSION",
        "BENCHMARK_FABRIC_VERSION",
        "BENCHMARK_POSTGRES_VERSION",
        "BENCHMARK_ENDORSEMENT_POLICY",
        "BENCHMARK_SOURCE_REVISION",
    )
    values = {key: os.environ.get(key, "not_available").strip() for key in keys}
    missing = [key for key, value in values.items() if not value or value.lower() == "not_available"]
    if missing:
        raise RuntimeError(
            "Set measured values before the run: " + ", ".join(missing)
        )
    return values


def _provision_demo_issuer(issuer_id: str) -> None:
    settings = get_settings()
    if settings.ledger_backend != "fabric":
        raise RuntimeError("demo issuer provisioning requires LEDGER_BACKEND=fabric")
    provider = CryptoProvider(settings.allow_insecure_demo_pqc)
    if not provider.using_real_pqc:
        raise RuntimeError("benchmark issuer provisioning requires real liboqs PQC")
    keys = FileKeyStore(settings.keystore_path).load("demo_issuer_ml_dsa")
    if keys is None:
        raise RuntimeError("the configured demo issuer signing key was not found")

    key_fingerprint = fingerprint(keys.public_key)
    engine = make_engine(settings)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    try:
        with factory() as session:
            issuer = session.get(Issuer, issuer_id)
            if issuer is not None:
                if issuer.key_fingerprint != key_fingerprint:
                    raise RuntimeError(
                        "the requested issuer ID already has a different signing key"
                    )
                return
            matching_key = session.scalars(
                select(Issuer).where(Issuer.key_fingerprint == key_fingerprint)
            ).first()
            if matching_key is not None:
                raise RuntimeError(
                    "the demo signing key is already enrolled under another issuer ID"
                )
            session.add(
                Issuer(
                    issuer_id=issuer_id,
                    organization=issuer_id,
                    public_key=keys.public_key,
                    key_fingerprint=key_fingerprint,
                    signing_algorithm=provider.signature_algorithm,
                    status="ACTIVE",
                )
            )
            session.commit()
    finally:
        engine.dispose()


class CgroupSampler:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._cpu_start: int | None = None
        self._cpu_end: int | None = None
        self._memory_start: int | None = None
        self._memory_end: int | None = None
        self._memory_peak: int | None = None
        self._started_at: float | None = None

    @staticmethod
    def _read_metric(path: Path, key: str | None = None) -> int | None:
        try:
            content = path.read_text(encoding="ascii").strip()
            if key is None:
                return int(content)
            for line in content.splitlines():
                name, value = line.split()
                if name == key:
                    return int(value)
        except (OSError, ValueError):
            return None
        return None

    def _sample(self) -> tuple[int | None, int | None]:
        cpu_path = Path("/sys/fs/cgroup/cpu.stat")
        memory_path = Path("/sys/fs/cgroup/memory.current")
        cpu_usage = self._read_metric(cpu_path, "usage_usec")
        memory_usage = self._read_metric(memory_path)
        return cpu_usage, memory_usage

    async def start(self) -> None:
        self._cpu_start, self._memory_start = self._sample()
        self._memory_peak = self._memory_start
        self._started_at = time.perf_counter()
        self._task = asyncio.create_task(self._monitor())

    async def _monitor(self) -> None:
        while not self._stop.is_set():
            cpu_usage, memory_usage = self._sample()
            if cpu_usage is not None:
                self._cpu_end = cpu_usage
            if memory_usage is not None:
                self._memory_end = memory_usage
                self._memory_peak = max(self._memory_peak or 0, memory_usage)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=0.5)
            except TimeoutError:
                pass

    async def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._task is not None:
            await self._task
        elapsed = time.perf_counter() - self._started_at if self._started_at else 0
        cpu_percent = None
        if self._cpu_start is not None and self._cpu_end is not None and elapsed > 0:
            cpu_percent = round((self._cpu_end - self._cpu_start) / (elapsed * 10_000), 2)
        to_mib = lambda value: round(value / (1024 * 1024), 2) if value is not None else None
        if self._memory_start is None and self._memory_peak is None:
            return {"available": False, "scope": "not available"}
        return {
            "available": True,
            "scope": "API container cgroup, including the benchmark client process",
            "cpu_percent_of_one_core": cpu_percent,
            "memory_start_mib": to_mib(self._memory_start),
            "memory_end_mib": to_mib(self._memory_end),
            "memory_peak_sampled_mib": to_mib(self._memory_peak),
            "sampling_interval_ms": 500,
        }


def _environment(api_url: str, health: dict[str, Any], versions: dict[str, str]) -> dict[str, Any]:
    cpu_model = platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "")
    if not cpu_model:
        try:
            cpu_info = Path("/proc/cpuinfo").read_text(encoding="utf-8")
            cpu_model = next(
                line.split(":", 1)[1].strip()
                for line in cpu_info.splitlines()
                if line.lower().startswith(("model name", "hardware"))
            )
        except (OSError, StopIteration):
            cpu_model = "not_available"
    package_versions = {}
    for package in ("liboqs-python", "cryptography", "fastapi", "httpx", "sqlalchemy"):
        try:
            package_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            package_versions[package] = "not_available"
    identity = {
        "api_url": api_url,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "cpu": cpu_model,
        "logical_cpus": os.cpu_count(),
        "python_version": platform.python_version(),
        "package_versions": package_versions,
        "health": health,
        "versions": versions,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return {"environment_id": hashlib.sha256(encoded).hexdigest()[:16], **identity}


async def _request_sample(
    client: httpx.AsyncClient,
    api_path: str,
    files: dict[str, tuple[str, bytes, str]],
    data: dict[str, str] | None = None,
) -> tuple[float, httpx.Response]:
    started = time.perf_counter_ns()
    response = await client.post(api_path, data=data, files=files)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if response.status_code not in (200, 201):
        raise RuntimeError(f"request failed with HTTP {response.status_code}: {api_path}")
    return elapsed_ms, response


def _registration_record(
    elapsed_ms: float,
    payload: dict[str, Any],
    phase: str,
    sample_index: int,
    size_bytes: int,
) -> dict[str, Any]:
    if payload.get("ledger_backend") != "hyperledger-fabric" or not payload.get("transaction_id"):
        raise RuntimeError("registration did not return a committed Fabric transaction")
    return {
        "metric": "registration",
        "phase": phase,
        "sample_index": sample_index,
        "latency_ms": round(elapsed_ms, 4),
        "document_id": payload["document_id"],
        "transaction_id": payload["transaction_id"],
        "block_number": payload.get("block_number"),
        "size_bytes": size_bytes,
    }


async def _register(
    client: httpx.AsyncClient,
    issuer_id: str,
    size_bytes: int,
    phase: str,
    sample_index: int,
) -> tuple[dict[str, Any], bytes]:
    content = _pdf_bytes(size_bytes)
    elapsed_ms, response = await _request_sample(
        client,
        "/api/v1/documents/register",
        data={"issuer": issuer_id},
        files={
            "file": (
                f"benchmark-{uuid.uuid4().hex}.pdf",
                content,
                "application/pdf",
            )
        },
    )
    return _registration_record(elapsed_ms, response.json(), phase, sample_index, size_bytes), content


async def _verify(
    client: httpx.AsyncClient,
    document_id: str,
    content: bytes,
    phase: str,
    sample_index: int,
    size_bytes: int,
) -> dict[str, Any]:
    elapsed_ms, response = await _request_sample(
        client,
        f"/api/v1/documents/{document_id}/verify",
        files={"file": ("benchmark-candidate.pdf", content, "application/pdf")},
    )
    payload = response.json()
    if payload.get("overall_status") != "VALID":
        raise RuntimeError("verification did not return VALID for the registered document")
    return {
        "metric": "verification",
        "phase": phase,
        "sample_index": sample_index,
        "latency_ms": round(elapsed_ms, 4),
        "document_id": document_id,
        "transaction_id": payload.get("transaction_id"),
        "block_number": None,
        "overall_status": payload["overall_status"],
        "size_bytes": size_bytes,
    }


async def _run_experiment(args: argparse.Namespace, result: dict[str, Any]) -> None:
    admin_id = os.environ.get("ADMIN_ID", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD must be available in the API container environment")
    versions = _required_versions()
    timeout = httpx.Timeout(300.0, connect=10.0)
    async with httpx.AsyncClient(base_url=args.api_url.rstrip("/"), timeout=timeout) as client:
        login = await client.post(
            "/api/v1/auth/login",
            data={"admin_id": admin_id, "password": admin_password},
        )
        if login.status_code != 200:
            raise RuntimeError(f"admin login failed with HTTP {login.status_code}")
        try:
            health_response = await client.get("/health")
            if health_response.status_code != 200:
                raise RuntimeError(f"API health check failed with HTTP {health_response.status_code}")
            health = health_response.json()
            if health.get("ledger_backend") != "hyperledger-fabric":
                raise RuntimeError("the API is not configured to use Hyperledger Fabric")
            if health.get("pqc_backend") != "liboqs":
                raise RuntimeError("real liboqs-backed PQC is required; demo fallback is not measurable")
            if args.provision_demo_issuer:
                _provision_demo_issuer(args.issuer)

            result["environment"] = _environment(args.api_url, health, versions)
            result["protocol"] = {
                "warmup_operations_per_metric": args.warmup,
                "measured_operations_per_metric": args.iterations,
                "registration_throughput_concurrency": args.concurrency,
                "document_sizes_bytes": list(args.sizes),
                "document_sizes_decimal_kb": [size / 1000 for size in args.sizes],
                "document_format": "minimal valid PDF with a unique comment marker and exact-size whitespace padding",
                "p95_method": "linear interpolation",
                "confidence_interval": "95% normal approximation (1.96 * SE)",
                "registration_commit_boundary": "HTTP response after Fabric commit status is observed",
            }
            sampler = CgroupSampler()
            await sampler.start()
            try:
                for size_bytes in args.sizes:
                    print(f"Measuring {size_bytes} byte PDF payloads...", flush=True)
                    run_data = {
                        "size_bytes": size_bytes,
                        "registration": {
                            "warmup_samples": [],
                            "samples": [],
                        },
                        "verification": {
                            "warmup_samples": [],
                            "samples": [],
                        },
                        "registration_throughput": {
                            "samples": [],
                            "concurrency": args.concurrency,
                        },
                        "verification_throughput": {
                            "samples": [],
                            "concurrency": args.concurrency,
                        },
                    }
                    result["runs"].append(run_data)
                    for index in range(args.warmup):
                        record, _ = await _register(client, args.issuer, size_bytes, "warmup", index + 1)
                        run_data["registration"]["warmup_samples"].append(record)

                    verification_document_id = ""
                    verification_content = b""
                    for index in range(args.iterations):
                        record, content = await _register(
                            client, args.issuer, size_bytes, "measured", index + 1
                        )
                        run_data["registration"]["samples"].append(record)
                        verification_document_id = record["document_id"]
                        verification_content = content
                    run_data["registration"]["summary"] = _summarize(
                        [sample["latency_ms"] for sample in run_data["registration"]["samples"]]
                    )

                    for index in range(args.warmup):
                        run_data["verification"]["warmup_samples"].append(
                            await _verify(
                                client,
                                verification_document_id,
                                verification_content,
                                "warmup",
                                index + 1,
                                size_bytes,
                            )
                        )

                    for index in range(args.iterations):
                        run_data["verification"]["samples"].append(
                            await _verify(
                                client,
                                verification_document_id,
                                verification_content,
                                "measured",
                                index + 1,
                                size_bytes,
                            )
                        )
                    run_data["verification"]["summary"] = _summarize(
                        [sample["latency_ms"] for sample in run_data["verification"]["samples"]]
                    )

                    throughput_started = time.perf_counter()
                    semaphore = asyncio.Semaphore(args.concurrency)

                    async def bounded_registration(index: int) -> dict[str, Any]:
                        async with semaphore:
                            record, _ = await _register(
                                client, args.issuer, size_bytes, "throughput", index + 1
                            )
                            return record

                    registration_tasks = [
                        asyncio.create_task(bounded_registration(index))
                        for index in range(args.iterations)
                    ]
                    registration_outcomes = await asyncio.gather(
                        *registration_tasks, return_exceptions=True
                    )
                    registration_errors = []
                    for outcome in registration_outcomes:
                        if isinstance(outcome, BaseException):
                            registration_errors.append(outcome)
                        else:
                            run_data["registration_throughput"]["samples"].append(outcome)
                    if registration_errors:
                        raise RuntimeError(
                            f"{len(registration_errors)} concurrent registration request(s) failed"
                        ) from registration_errors[0]
                    throughput_elapsed = time.perf_counter() - throughput_started
                    run_data["registration_throughput"].update(
                        {
                            "elapsed_seconds": round(throughput_elapsed, 4),
                            "documents_per_second": round(
                                len(run_data["registration_throughput"]["samples"])
                                / throughput_elapsed,
                                4,
                            ),
                            "latency_summary": _summarize(
                                [sample["latency_ms"] for sample in run_data["registration_throughput"]["samples"]]
                            ),
                        }
                    )

                    verification_started = time.perf_counter()
                    verification_semaphore = asyncio.Semaphore(args.concurrency)

                    async def bounded_verification(index: int) -> dict[str, Any]:
                        async with verification_semaphore:
                            return await _verify(
                                client,
                                verification_document_id,
                                verification_content,
                                "throughput",
                                index + 1,
                                size_bytes,
                            )

                    verification_tasks = [
                        asyncio.create_task(bounded_verification(index))
                        for index in range(args.iterations)
                    ]
                    verification_outcomes = await asyncio.gather(
                        *verification_tasks, return_exceptions=True
                    )
                    verification_errors = []
                    for outcome in verification_outcomes:
                        if isinstance(outcome, BaseException):
                            verification_errors.append(outcome)
                        else:
                            run_data["verification_throughput"]["samples"].append(outcome)
                    if verification_errors:
                        raise RuntimeError(
                            f"{len(verification_errors)} concurrent verification request(s) failed"
                        ) from verification_errors[0]
                    verification_elapsed = time.perf_counter() - verification_started
                    run_data["verification_throughput"].update(
                        {
                            "elapsed_seconds": round(verification_elapsed, 4),
                            "documents_per_second": round(
                                len(run_data["verification_throughput"]["samples"])
                                / verification_elapsed,
                                4,
                            ),
                            "latency_summary": _summarize(
                                [sample["latency_ms"] for sample in run_data["verification_throughput"]["samples"]]
                            ),
                        }
                    )
            finally:
                result["container_resource_sample"] = await sampler.stop()
                result["external_container_metrics_required"] = [
                    "fabric-gateway",
                    "fabric peer(s)",
                    "orderer(s)",
                    "postgres",
                ]
        finally:
            await client.post("/api/v1/auth/logout")


def _csv_rows(result: dict[str, Any]):
    environment_id = result.get("environment", {}).get("environment_id", "")
    for run in result.get("runs", []):
        size_bytes = run["size_bytes"]
        for metric in ("registration", "verification"):
            section = run[metric]
            for phase in ("warmup_samples", "samples"):
                for sample in section[phase]:
                    yield {
                        "environment_id": environment_id,
                        "size_bytes": size_bytes,
                        "metric": metric,
                        "phase": "warmup" if phase == "warmup_samples" else "measured",
                        "sample_index": sample["sample_index"],
                        "latency_ms": sample["latency_ms"],
                        "document_id": sample.get("document_id"),
                        "transaction_id": sample.get("transaction_id"),
                        "block_number": sample.get("block_number"),
                        "overall_status": sample.get("overall_status"),
                    }
        for sample in run.get("registration_throughput", {}).get("samples", []):
            yield {
                "environment_id": environment_id,
                "size_bytes": size_bytes,
                "metric": "registration_throughput",
                "phase": "throughput",
                "sample_index": sample["sample_index"],
                "latency_ms": sample["latency_ms"],
                "document_id": sample.get("document_id"),
                "transaction_id": sample.get("transaction_id"),
                "block_number": sample.get("block_number"),
                "overall_status": sample.get("overall_status"),
            }
        for sample in run.get("verification_throughput", {}).get("samples", []):
            yield {
                "environment_id": environment_id,
                "size_bytes": size_bytes,
                "metric": "verification_throughput",
                "phase": "throughput",
                "sample_index": sample["sample_index"],
                "latency_ms": sample["latency_ms"],
                "document_id": sample.get("document_id"),
                "transaction_id": sample.get("transaction_id"),
                "block_number": sample.get("block_number"),
                "overall_status": sample.get("overall_status"),
            }


def _write_artifacts(output_dir: Path, result: dict[str, Any]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = result["run_id"]
    json_path = output_dir / f"fabric-e2e-{run_id}.json"
    csv_path = output_dir / f"fabric-e2e-{run_id}.csv"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(_csv_rows(result))
    return json_path, csv_path


def _parse_sizes(value: str) -> tuple[int, ...]:
    try:
        sizes = tuple(int(item.strip()) for item in value.split(","))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("sizes must be comma-separated positive byte counts") from exc
    if not sizes or any(size < 512 or size > 10_000_000 for size in sizes):
        raise argparse.ArgumentTypeError("document sizes must be between 512 and 10,000,000 bytes")
    return sizes


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real Fabric registration and verification measurements")
    parser.add_argument("--api-url", default=os.environ.get("BENCHMARK_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--issuer", default=os.environ.get("BENCHMARK_ISSUER_ID", "QuantumProof Benchmark"))
    parser.add_argument("--sizes", type=_parse_sizes, default=DEFAULT_SIZES_BYTES)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output-dir", type=Path, default=Path("experiment-results"))
    parser.add_argument("--provision-demo-issuer", action="store_true")
    parser.add_argument("--confirm-ledger-writes", action="store_true")
    args = parser.parse_args()

    if not args.confirm_ledger_writes:
        parser.error("this run writes permanent Fabric transactions; pass --confirm-ledger-writes to continue")
    if not 100 <= args.iterations <= 1000:
        parser.error("--iterations must be between 100 and 1000")
    if not 30 <= args.warmup <= 1000:
        parser.error("--warmup must be between 30 and 1000")
    if not 1 <= args.concurrency <= 64:
        parser.error("--concurrency must be between 1 and 64")
    if not args.issuer.strip() or len(args.issuer) > 64:
        parser.error("--issuer must contain 1 to 64 characters")
    api_url = httpx.URL(args.api_url)
    if api_url.username or api_url.password:
        parser.error("credentials are not allowed in --api-url")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    result: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "issuer_id": args.issuer,
        "runs": [],
    }
    try:
        asyncio.run(_run_experiment(args, result))
        result["status"] = "completed"
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        print(result["error"], file=sys.stderr)
    finally:
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        try:
            json_path, csv_path = _write_artifacts(args.output_dir, result)
            print(f"JSON: {json_path}")
            print(f"CSV: {csv_path}")
        except OSError as exc:
            print(f"Could not save benchmark artifacts: {exc}", file=sys.stderr)
            return 1
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
