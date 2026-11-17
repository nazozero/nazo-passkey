#!/usr/bin/env python3
"""Run already-built baseline/candidate binaries in alternating order.

Example: python3 perf/run.py --baseline ../passkey-auth-baseline/perf/target/release/ceremony-bench --candidate perf/target/release/ceremony-bench --output results.json
An optional --checkpoint adds a third revision in rotated/reversed order.
No compilation or dependency installation runs during measurement.
"""
import argparse
import hashlib
import json
import os
import platform
import resource
import statistics
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--baseline", required=True)
parser.add_argument("--candidate", required=True)
parser.add_argument("--checkpoint", help="optional previously shipped candidate artifact")
parser.add_argument("--output", required=True)
parser.add_argument("--rounds", type=int, default=5)
parser.add_argument("--iterations", type=int, default=5000)
parser.add_argument("--wasi", action="store_true")
parser.add_argument("--cpu", type=int, help="pin the driver and child process to one available logical CPU")
args = parser.parse_args()
if args.cpu is not None:
    if args.cpu not in os.sched_getaffinity(0):
        parser.error("selected CPU is outside this process affinity")
    os.sched_setaffinity(0, {args.cpu})

labels = ["baseline", "checkpoint", "candidate"] if args.checkpoint else ["baseline", "candidate"]
artifacts = {}
for label in labels:
    path = Path(getattr(args, label)).resolve()
    artifacts[label] = {"path": str(path), "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
cpu = {}
for line in Path("/proc/cpuinfo").read_text().splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        if key.strip() in ("model name", "cpu MHz", "cpu cores"):
            cpu.setdefault(key.strip(), value.strip())
metadata = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "platform": platform.platform(), "cpu": cpu, "logical_cpus": os.cpu_count(), "affinity": sorted(os.sched_getaffinity(0)), "memory": Path("/proc/meminfo").read_text().splitlines()[:3], "node": subprocess.check_output(["node", "--version"], text=True).strip() if args.wasi else None, "mode": "WASI preview1 / Node" if args.wasi else "native", "artifacts": artifacts, "iterations": args.iterations, "rounds": args.rounds}
if args.checkpoint:
    metadata["process_order"] = []
runs = []
for round_index in range(args.rounds):
    if args.checkpoint:
        offset = round_index % len(labels)
        order = labels[offset:] + labels[:offset]
        if round_index % 2:
            order.reverse()
        metadata["process_order"].append({"round": round_index + 1, "labels": order})
    else:
        order = ["baseline", "candidate"] if round_index % 2 == 0 else ["candidate", "baseline"]
    for label in order:
        command = [artifacts[label]["path"]]
        if args.wasi:
            command = ["node", str(Path(__file__).with_name("wasi.mjs")), artifacts[label]["path"]]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        process = subprocess.run(command, capture_output=True, text=True, check=True, env={**os.environ, "PERF_ITERATIONS": str(args.iterations)})
        wall = time.perf_counter() - start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_seconds = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
        rows = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
        if len(rows) != 10:
            raise RuntimeError(f"expected 10 benchmark cases, got {len(rows)}")
        runs.append({"round": round_index + 1, "label": label, "wall_seconds": wall, "cpu_seconds": cpu_seconds, "cpu_percent_of_one_core": 100 * cpu_seconds / wall, "rows": rows})
        print(f"{label} round {round_index+1}: {wall:.3f}s", flush=True)
summary = {}
for label in labels:
    cases = {row["case"] for run in runs if run["label"] == label for row in run["rows"]}
    summary[label] = {}
    for case in sorted(cases):
        rows = [row for run in runs if run["label"] == label for row in run["rows"] if row["case"] == case]
        summary[label][case] = {key: statistics.median(row[key] for row in rows) for key in rows[0] if key != "case"}
Path(args.output).write_text(json.dumps({"environment": metadata, "runs": runs, "median_by_case": summary}, indent=2) + "\n")
