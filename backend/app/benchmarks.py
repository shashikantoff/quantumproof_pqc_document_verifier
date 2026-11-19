"""Reproducible cryptographic micro-benchmarks.

The benchmark separates warm-up executions from measured executions and reports
summary statistics suitable for experimental evaluation. It does not invent or
persist results; every value is measured in the runtime where the command runs.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import statistics
import time
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from .crypto import CryptoProvider, document_claim

DEFAULT_WARMUP = 30
DEFAULT_ITERATIONS = 100
MIN_ITERATIONS = 100
MAX_ITERATIONS = 5000


def _percentile(samples: list[float], percentile: float) -> float:
    """Return an interpolated percentile for a non-empty sample set."""
    if not samples:
        raise ValueError("samples cannot be empty")
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (percentile / 100.0)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _confidence_interval_95(samples: list[float]) -> tuple[float, float]:
    """Return a two-sided 95% CI using a normal approximation.

    With the default n=100 this is a practical approximation. The benchmark
    reports the method explicitly so results are not presented as an exact
    small-sample t interval.
    """
    mean = statistics.fmean(samples)
    if len(samples) < 2:
        return mean, mean
    standard_error = statistics.stdev(samples) / (len(samples) ** 0.5)
    margin = 1.96 * standard_error
    return mean - margin, mean + margin


def _measure(
    operation: Callable[[], None],
    iterations: int,
    warmup: int,
) -> dict[str, float | int | str]:
    for _ in range(warmup):
        operation()

    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)

    mean = statistics.fmean(samples)
    median = statistics.median(samples)
    stddev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    p95 = _percentile(samples, 95)
    ci_low, ci_high = _confidence_interval_95(samples)

    return {
        "measured_iterations": iterations,
        "warmup_iterations": warmup,
        "raw_ms": samples,
        "mean_ms": round(mean, 4),
        "median_ms": round(median, 4),
        "stddev_ms": round(stddev, 4),
        "p95_ms": round(p95, 4),
        "ci95_low_ms": round(ci_low, 4),
        "ci95_high_ms": round(ci_high, 4),
        "ci95_method": "normal approximation (1.96 * SE)",
    }


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not_available"


def _total_memory_mb() -> float | None:
    # Linux containers expose this without requiring an extra dependency.
    try:
        for line in open("/proc/meminfo", encoding="utf-8"):
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024, 2)
    except (OSError, ValueError):
        return None
    return None


def _environment(provider: CryptoProvider) -> dict:
    return {
        "pqc_backend": "liboqs" if provider.using_real_pqc else "INSECURE-DEMO-FALLBACK",
        "signature_algorithm": provider.signature_algorithm,
        "kem_algorithm": provider.kem_algorithm,
        "python_version": platform.python_version(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "cpu": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "not_available"),
        "logical_cpus": os.cpu_count(),
        "memory_mb": _total_memory_mb(),
        "liboqs_python_version": _package_version("liboqs-python"),
        "cryptography_version": _package_version("cryptography"),
        "docker_version": os.environ.get("BENCHMARK_DOCKER_VERSION", "not_available"),
        "fabric_version": os.environ.get("BENCHMARK_FABRIC_VERSION", "not_available"),
        "postgresql_version": os.environ.get("BENCHMARK_POSTGRES_VERSION", "not_available"),
    }


def run_benchmark(
    provider: CryptoProvider,
    iterations: int = DEFAULT_ITERATIONS,
    warmup: int = DEFAULT_WARMUP,
) -> dict:
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError(
            f"iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}"
        )
    if not 0 <= warmup <= 1000:
        raise ValueError("warmup must be between 0 and 1000")

    claim = document_claim(hashlib.sha256(b"benchmark document" * 1024).hexdigest())

    pqc_signing = provider.create_signing_keypair()
    pqc_signature = provider.sign(claim, pqc_signing.secret_key, provider.signature_algorithm)
    pqc_kem = provider.create_kem_keypair()
    pqc_payload = provider.encrypt_for_recipient(b"benchmark", pqc_kem.public_key)

    ed_private = ed25519.Ed25519PrivateKey.generate()
    ed_public = ed_private.public_key()
    ed_signature = ed_private.sign(claim)
    x_private = x25519.X25519PrivateKey.generate()
    x_public = x_private.public_key()
    ed_public_bytes = ed_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def pqc_kem_roundtrip() -> None:
        payload = provider.encrypt_for_recipient(b"benchmark", pqc_kem.public_key)
        provider.decrypt_for_recipient(payload, pqc_kem.secret_key)

    def pqc_kem_encapsulate() -> None:
        provider.encrypt_for_recipient(b"benchmark", pqc_kem.public_key)

    def pqc_kem_decapsulate() -> None:
        provider.decrypt_for_recipient(pqc_payload, pqc_kem.secret_key)

    def x25519_roundtrip() -> None:
        ephemeral = x25519.X25519PrivateKey.generate()
        secret_one = ephemeral.exchange(x_public)
        secret_two = x_private.exchange(ephemeral.public_key())
        assert secret_one == secret_two

    results = [
        {
            "family": "post-quantum",
            "algorithm": provider.signature_algorithm,
            "operation": "key generation",
            "public_key_bytes": len(pqc_signing.public_key),
            "secret_key_bytes": len(pqc_signing.secret_key),
            "signature_bytes": len(pqc_signature),
            **_measure(lambda: provider.create_signing_keypair(), iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.signature_algorithm,
            "operation": "sign",
            "signature_bytes": len(pqc_signature),
            **_measure(lambda: provider.sign(claim, pqc_signing.secret_key, provider.signature_algorithm), iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.signature_algorithm,
            "operation": "verify",
            **_measure(lambda: provider.verify(claim, pqc_signature, pqc_signing.public_key, provider.signature_algorithm), iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.kem_algorithm,
            "operation": "key generation",
            "public_key_bytes": len(pqc_kem.public_key),
            "secret_key_bytes": len(pqc_kem.secret_key),
            "ciphertext_bytes": len(pqc_payload.kem_ciphertext),
            **_measure(lambda: provider.create_kem_keypair(), iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.kem_algorithm,
            "operation": "encapsulation",
            "ciphertext_bytes": len(pqc_payload.kem_ciphertext),
            **_measure(pqc_kem_encapsulate, iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.kem_algorithm,
            "operation": "decapsulation",
            "ciphertext_bytes": len(pqc_payload.kem_ciphertext),
            **_measure(pqc_kem_decapsulate, iterations, warmup),
        },
        {
            "family": "post-quantum",
            "algorithm": provider.kem_algorithm,
            "operation": "encapsulate+decapsulate+AES-GCM",
            **_measure(pqc_kem_roundtrip, iterations, warmup),
        },
        {
            "family": "classical",
            "algorithm": "Ed25519",
            "operation": "key generation",
            "public_key_bytes": len(ed_public_bytes),
            "secret_key_bytes": 32,
            "signature_bytes": len(ed_signature),
            **_measure(lambda: ed25519.Ed25519PrivateKey.generate(), iterations, warmup),
        },
        {
            "family": "classical",
            "algorithm": "Ed25519",
            "operation": "sign",
            "signature_bytes": len(ed_signature),
            **_measure(lambda: ed_private.sign(claim), iterations, warmup),
        },
        {
            "family": "classical",
            "algorithm": "Ed25519",
            "operation": "verify",
            **_measure(lambda: ed_public.verify(ed_signature, claim), iterations, warmup),
        },
        {
            "family": "classical",
            "algorithm": "X25519",
            "operation": "key generation",
            "public_key_bytes": 32,
            "secret_key_bytes": 32,
            **_measure(lambda: x25519.X25519PrivateKey.generate(), iterations, warmup),
        },
        {
            "family": "classical",
            "algorithm": "X25519",
            "operation": "key agreement",
            **_measure(x25519_roundtrip, iterations, warmup),
        },
    ]

    return {
        "protocol": {
            "warmup_iterations": warmup,
            "measured_iterations": iterations,
            "confidence_interval": "95%",
            "p95_method": "linear interpolation",
        },
        "environment": _environment(provider),
        "results": results,
    }
