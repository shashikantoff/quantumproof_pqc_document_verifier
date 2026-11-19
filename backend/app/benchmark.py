"""CLI entry point for the reproducible cryptographic benchmark."""

import argparse
import csv
import json
import uuid
import statistics
from datetime import datetime, timezone
from pathlib import Path

from .benchmarks import DEFAULT_ITERATIONS, DEFAULT_WARMUP, run_benchmark
from .config import get_settings
from .crypto import CryptoProvider


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the QuantumProof crypto benchmark")
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"measured iterations (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
        help=f"warm-up iterations before measurement (default: {DEFAULT_WARMUP})",
    )
    parser.add_argument("--runs", type=int, default=1, help="number of independent benchmark runs")
    parser.add_argument("--output-dir", type=Path, default=None, help="directory for raw JSON and CSV artifacts")
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be between 1 and 10")

    settings = get_settings()
    provider = CryptoProvider(settings.allow_insecure_demo_pqc)
    independent_runs = []
    for run_index in range(1, args.runs + 1):
        payload = run_benchmark(provider, args.iterations, args.warmup)
        payload["run_index"] = run_index
        payload["run_id"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        independent_runs.append(payload)
        print(json.dumps(payload, indent=2))

    aggregate = []
    operation_results: dict[tuple[str, str, str], list[float]] = {}
    for payload in independent_runs:
        for row in payload["results"]:
            key = (row["family"], row["algorithm"], row["operation"])
            operation_results.setdefault(key, []).extend(row["raw_ms"])
    for (family, algorithm, operation), samples in operation_results.items():
        mean = statistics.fmean(samples)
        median = statistics.median(samples)
        stddev = statistics.stdev(samples) if len(samples) > 1 else 0.0
        ordered = sorted(samples)
        rank = (len(ordered) - 1) * 0.95
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        p95 = ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)
        ci_margin = 1.96 * (stddev / (len(samples) ** 0.5))
        aggregate.append({
            "family": family,
            "algorithm": algorithm,
            "operation": operation,
            "n": len(samples),
            "runs": args.runs,
            "mean_ms": round(mean, 4),
            "median_ms": round(median, 4),
            "stddev_ms": round(stddev, 4),
            "p95_ms": round(p95, 4),
            "ci95_low_ms": round(mean - ci_margin, 4),
            "ci95_high_ms": round(mean + ci_margin, 4),
            "ci95_method": "normal approximation (1.96 * SE)",
        })

    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        aggregate_path = args.output_dir / "crypto-benchmark-cross-run.json"
        aggregate_payload = {
            "environment": independent_runs[0]["environment"],
            "protocol": independent_runs[0]["protocol"],
            "runs": [payload["run_id"] for payload in independent_runs],
            "results": aggregate,
        }
        aggregate_path.write_text(json.dumps(aggregate_payload, indent=2) + "\n", encoding="utf-8")
        for payload in independent_runs:
            run_id = payload["run_id"]
            json_path = args.output_dir / f"crypto-benchmark-{run_id}.json"
            csv_path = args.output_dir / f"crypto-benchmark-{run_id}.csv"
            json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            fields = (
                "run_id",
                "family",
                "algorithm",
                "operation",
                "measured_iterations",
                "warmup_iterations",
                "mean_ms",
                "median_ms",
                "stddev_ms",
                "p95_ms",
                "ci95_low_ms",
                "ci95_high_ms",
                "ci95_method",
                "public_key_bytes",
                "secret_key_bytes",
                "signature_bytes",
                "ciphertext_bytes",
            )
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                for row in payload["results"]:
                    csv_row = {"run_id": run_id, **row}
                    writer.writerow({field: csv_row.get(field, "") for field in fields})
