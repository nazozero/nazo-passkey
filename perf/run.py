#!/usr/bin/env python3
"""Compare already-built ceremony benchmarks; never compile during measurement.

Use --checkpoint for a three-way comparison. Six rounds give each revision
all three positions twice. Quantiles in median_by_case are medians of round
quantiles, not pooled percentiles. Run this Linux driver without a profiler.
"""
import argparse
import hashlib
import json
import math
import os
import platform
import resource
import statistics
import subprocess
import time
from pathlib import Path

CASES = frozenset(
    f"{algorithm}.{operation}"
    for algorithm in ("es256", "ed25519")
    for operation in (
        "registration_begin", "registration_finish",
        "authentication_begin", "authentication_finish",
    )
) | {"primitive.es256.rustcrypto", "primitive.ed25519_strict.rustcrypto"}
METRICS = (
    "p50_ns", "p95_ns", "p99_ns", "throughput_per_sec",
    "allocations_per_op", "allocated_bytes_per_op",
)
FIELDS = {"case", "iterations", "concurrency", *METRICS}


def parse_rows(stdout: str, iterations: int) -> list[dict]:
    """Validate the benchmark boundary before comparing or aggregating rows."""
    rows = [json.loads(line) for line in stdout.splitlines() if line.lstrip().startswith("{")]
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError("benchmark row has missing or unexpected fields")
        case = row["case"]
        if not isinstance(case, str) or case not in CASES or case in seen:
            raise ValueError(f"unknown or duplicate benchmark case: {case!r}")
        seen.add(case)
        if type(row["iterations"]) is not int or row["iterations"] != iterations:
            raise ValueError(f"{case}: iterations differ from requested {iterations}")
        if type(row["concurrency"]) is not int or row["concurrency"] != 1:
            raise ValueError(f"{case}: expected concurrency one")
        for metric in METRICS:
            value = row[metric]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{case}: invalid {metric}: {value!r}")
        if row["throughput_per_sec"] <= 0:
            raise ValueError(f"{case}: throughput must be positive")
        if not row["p50_ns"] <= row["p95_ns"] <= row["p99_ns"]:
            raise ValueError(f"{case}: quantiles are out of order")
    if seen != CASES:
        raise ValueError(f"missing benchmark cases: {sorted(CASES - seen)}")
    return rows


def round_order(labels: list[str], round_index: int) -> list[str]:
    offset = round_index % len(labels)
    order = labels[offset:] + labels[:offset]
    if len(labels) == 3 and round_index % 2:
        order.reverse()
    return order


def benchmark_environment(environment: dict[str, str], iterations: int) -> dict[str, str]:
    # A single-case selector or allocation tracer changes the measurement, not
    # just its presentation. Reject accidental inheritance rather than hide it.
    for name in ("PERF_CASE", "PERF_MTRACE", "MALLOC_TRACE", "LD_PRELOAD", "LD_AUDIT"):
        if name in environment and (environment[name] or name.startswith("PERF_")):
            raise ValueError(f"unset {name} before a latency run")
    return {**environment, "PERF_ITERATIONS": str(iterations)}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--checkpoint", help="optional previous candidate artifact")
    parser.add_argument("--output", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--wasi", action="store_true")
    parser.add_argument("--cpu", type=int, help="pin this driver and its children to one logical CPU")
    args = parser.parse_args(argv)
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    # ceremony.rs clamps smaller requests to ten; do not mislabel its samples.
    if args.iterations < 10:
        parser.error("--iterations must be at least 10")
    try:
        child_environment = benchmark_environment(dict(os.environ), args.iterations)
    except ValueError as error:
        parser.error(str(error))
    if args.cpu is not None:
        if args.cpu not in os.sched_getaffinity(0):
            parser.error("selected CPU is outside this process affinity")
        os.sched_setaffinity(0, {args.cpu})

    labels = ["baseline", "checkpoint", "candidate"] if args.checkpoint else ["baseline", "candidate"]
    artifacts = {}
    for label in labels:
        path = Path(getattr(args, label)).resolve(strict=True)
        artifacts[label] = {
            "path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    cpu = {}
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip() in ("model name", "cpu MHz", "cpu cores"):
                cpu.setdefault(key.strip(), value.strip())
    metadata = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "cpu": cpu,
        "logical_cpus": os.cpu_count(), "affinity": sorted(os.sched_getaffinity(0)),
        "memory": Path("/proc/meminfo").read_text().splitlines()[:3],
        "node": subprocess.check_output(["node", "--version"], text=True).strip() if args.wasi else None,
        "mode": "WASI preview1 / Node" if args.wasi else "native",
        "artifacts": artifacts, "iterations": args.iterations, "rounds": args.rounds,
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "summary_statistic": "median of per-round values; not pooled percentiles",
        "process_order": [],
    }
    runs = []
    for round_index in range(args.rounds):
        order = round_order(labels, round_index)
        metadata["process_order"].append({"round": round_index + 1, "labels": order})
        for label in order:
            command = [artifacts[label]["path"]]
            if args.wasi:
                command = ["node", str(Path(__file__).with_name("wasi.mjs")), artifacts[label]["path"]]
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            start = time.perf_counter()
            process = subprocess.run(command, capture_output=True, text=True, env=child_environment)
            wall = time.perf_counter() - start
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            if process.returncode:
                raise RuntimeError(f"{label} round {round_index + 1} exited {process.returncode}:\n{process.stderr}")
            rows = parse_rows(process.stdout, args.iterations)
            cpu_seconds = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
            runs.append({
                "round": round_index + 1, "label": label,
                "wall_seconds": wall, "cpu_seconds": cpu_seconds,
                "cpu_percent_of_one_core": 100 * cpu_seconds / wall,
                "stderr": process.stderr, "rows": rows,
            })
            print(f"{label} round {round_index + 1}: {wall:.3f}s", flush=True)
    summary = {}
    for label in labels:
        summary[label] = {}
        for case in sorted(CASES):
            rows = [row for run in runs if run["label"] == label for row in run["rows"] if row["case"] == case]
            summary[label][case] = {
                key: statistics.median(row[key] for row in rows)
                for key in ("iterations", "concurrency", *METRICS)
            }
    Path(args.output).write_text(json.dumps({
        "environment": metadata, "runs": runs, "median_by_case": summary,
    }, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
