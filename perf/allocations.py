#!/usr/bin/env python3
"""Count native allocation requests in already-built benchmark executables.

The benchmark enables glibc mtrace only around its 100-operation allocation
loop. This driver parses '+' allocation and '>' realloc-result records. It
does not use or report the benchmark's timings while malloc tracing is active.

Example:
  python3 perf/allocations.py --baseline /path/baseline-native \
    --rustcrypto /path/candidate-native-rustcrypto \
    --aws-lc /path/candidate-native-aws-lc --aws-lc-version 1.19.0 \
    --aws-lc-sys-version 0.47.0 --trace-dir /tmp/passkey-allocation-traces \
    --output docs/evidence/allocations-native.json

The AWS version arguments describe the lock used to build that executable;
they are not inferred from a potentially newer source checkout. Executable,
profiler, harness and raw-trace hashes identify the exact measured artifacts.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import subprocess
import uuid
from pathlib import Path


OPERATIONS = 100
CASES = [
    f"{algorithm}.{stage}"
    for algorithm in ("es256", "ed25519")
    for stage in (
        "registration_begin",
        "registration_finish",
        "authentication_begin",
        "authentication_finish",
    )
] + ["primitive.es256.rustcrypto", "primitive.ed25519_strict.rustcrypto"]

# Call-site prefixes are platform-dependent. The event, pointer and optional
# hex size are the final fields; do not confuse a call-site address with size.
EVENT = re.compile(r"(?:^|\s)([+<>!\-])\s+(0x[0-9a-fA-F]+|\(nil\))(?:\s+(0x[0-9a-fA-F]+))?$")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path):
    path = path.resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def parse_trace(path):
    """Count successful allocation requests; fail closed on unknown records."""
    counts = {"+": 0, ">": 0, "<": 0, "-": 0, "!": 0}
    byte_counts = {"+": 0, ">": 0}
    started = False
    ended = False
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if line == "= Start":
            if started or ended:
                raise ValueError(f"{path}:{number}: duplicate Start marker")
            started = True
            continue
        if line == "= End":
            if not started or ended:
                raise ValueError(f"{path}:{number}: unmatched End marker")
            ended = True
            continue
        if not started or ended:
            raise ValueError(f"{path}:{number}: event outside tracing window")
        match = EVENT.search(line)
        if match is None:
            raise ValueError(f"{path}:{number}: unknown mtrace record: {line!r}")
        event, pointer, size = match.groups()
        counts[event] += 1
        if event in ("+", ">"):
            if size is None or pointer in ("(nil)", "0x0"):
                raise ValueError(f"{path}:{number}: failed or sizeless allocation")
            byte_counts[event] += int(size, 16)
        elif event != "!" and size is not None:
            raise ValueError(f"{path}:{number}: unexpected size on {event} record")
    if not started or not ended:
        raise ValueError(f"{path}: incomplete trace; check LD_PRELOAD and glibc support")
    if counts["!"]:
        raise ValueError(f"{path}: failed realloc requests must be investigated")
    if counts["<"] != counts[">"]:
        raise ValueError(f"{path}: unmatched realloc old/new records")
    requests = counts["+"] + counts[">"]
    requested_bytes = byte_counts["+"] + byte_counts[">"]
    return {
        "allocation_plus_events": counts["+"],
        "reallocation_new_events": counts[">"],
        "reallocation_old_events": counts["<"],
        "deallocation_events": counts["-"],
        "failed_reallocation_events": counts["!"],
        "allocation_plus_requested_bytes": byte_counts["+"],
        "reallocation_new_requested_bytes": byte_counts[">"],
        "requests_total": requests,
        "requested_bytes_total": requested_bytes,
        "requests_per_operation": requests / OPERATIONS,
        "requested_bytes_per_operation": requested_bytes / OPERATIONS,
    }


def measured_integer(value):
    total = value * OPERATIONS
    if not total.is_integer():
        raise ValueError(f"Rust counter {value} does not represent a whole request total")
    return int(total)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--rustcrypto", type=Path, required=True)
    parser.add_argument("--aws-lc", dest="aws_lc", type=Path)
    parser.add_argument("--checkpoint-rustcrypto", type=Path)
    parser.add_argument("--checkpoint-aws-lc", type=Path)
    parser.add_argument("--aws-lc-version")
    parser.add_argument("--aws-lc-sys-version")
    parser.add_argument("--trace-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preload", type=Path, default=Path("/lib/x86_64-linux-gnu/libc_malloc_debug.so"))
    args = parser.parse_args()
    if (args.aws_lc is not None or args.checkpoint_aws_lc is not None) and (not args.aws_lc_version or not args.aws_lc_sys_version):
        parser.error("the AWS executable requires explicit --aws-lc-version and --aws-lc-sys-version")
    if platform.system() != "Linux" or os.confstr("CS_GNU_LIBC_VERSION") is None:
        parser.error("this experiment requires Linux/glibc and libc_malloc_debug")
    if os.environ.get("LD_PRELOAD"):
        parser.error("unset inherited LD_PRELOAD so this experiment has one known profiler")

    profiler = artifact(args.preload)
    paths = {"baseline": args.baseline, "rustcrypto": args.rustcrypto}
    if args.aws_lc is not None:
        paths["aws_lc"] = args.aws_lc
    if args.checkpoint_rustcrypto is not None:
        paths["checkpoint_rustcrypto"] = args.checkpoint_rustcrypto
    if args.checkpoint_aws_lc is not None:
        paths["checkpoint_aws_lc"] = args.checkpoint_aws_lc
    binaries = {label: artifact(path) for label, path in paths.items()}
    session_dir = args.trace_dir.resolve() / uuid.uuid4().hex
    session_dir.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    results = {
        "schema_version": 1,
        "environment": {
            "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "platform": platform.platform(),
            "glibc": os.confstr("CS_GNU_LIBC_VERSION"),
            "profiler": profiler,
            "artifacts": binaries,
            "harness_source": artifact(root / "benches/ceremony.rs"),
            "driver_source": artifact(Path(__file__)),
            "aws_lc_rs": args.aws_lc_version if args.aws_lc or args.checkpoint_aws_lc else None,
            "aws_lc_sys": args.aws_lc_sys_version if args.aws_lc or args.checkpoint_aws_lc else None,
        },
        "method": {
            "trace_window_operations": OPERATIONS,
            "warmup_operations_before_trace": 200,
            "unreported_timing_iterations_before_trace": 10,
            "concurrency": 1,
            "counted_trace_events": ["+", ">"],
            "definition": "Successful malloc/calloc/aligned-allocation and realloc requests intercepted by glibc mtrace. Realloc contributes its full requested new size, not the size delta.",
            "scope": "Steady-state API calls and returned-value destruction. Fixture construction, warm-up, tracing startup/shutdown and JSON reporting are outside the traced window.",
            "limits": "Requested bytes are cumulative and exclude allocator metadata; they are not peak memory, RSS or retained bytes. Direct mmap and allocations bypassing glibc malloc hooks are not counted. No traced latency is reported.",
        },
        "cases": {},
    }
    for label, executable in binaries.items():
        results["cases"][label] = {}
        for case in CASES:
            prefix = session_dir / f"{label}-{case}"
            trace = prefix.with_suffix(prefix.suffix + ".trace")
            stdout_path = prefix.with_suffix(prefix.suffix + ".stdout")
            stderr_path = prefix.with_suffix(prefix.suffix + ".stderr")
            env = {
                **os.environ,
                "LD_PRELOAD": profiler["path"],
                "MALLOC_TRACE": str(trace),
                "PERF_CASE": case,
                "PERF_ITERATIONS": "10",
                "PERF_MTRACE": "1",
            }
            process = subprocess.run([executable["path"]], env=env, text=True, capture_output=True, check=True, timeout=120)
            stdout_path.write_text(process.stdout)
            stderr_path.write_text(process.stderr)
            rows = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
            if len(rows) != 1 or rows[0]["case"] != case or rows[0]["iterations"] != 10 or rows[0]["concurrency"] != 1:
                raise ValueError(f"{label}/{case}: wrong benchmark selection or instrumentation")
            row = rows[0]
            native = parse_trace(trace)
            rust_requests = measured_integer(float(row["allocations_per_op"]))
            rust_bytes = measured_integer(float(row["allocated_bytes_per_op"]))
            excess_requests = native["requests_total"] - rust_requests
            excess_bytes = native["requested_bytes_total"] - rust_bytes
            if excess_requests < 0 or excess_bytes < 0:
                raise ValueError(f"{label}/{case}: native tracer missed Rust allocator requests")
            matches = excess_requests == 0 and excess_bytes == 0
            if label in ("baseline", "rustcrypto", "checkpoint_rustcrypto") and not matches:
                raise ValueError(f"{label}/{case}: portable native/Rust counters differ; investigate profiling overhead")
            results["cases"][label][case] = {
                "native_glibc": native,
                "rust_global": {
                    "requests_total": rust_requests,
                    "requested_bytes_total": rust_bytes,
                    "requests_per_operation": rust_requests / OPERATIONS,
                    "requested_bytes_per_operation": rust_bytes / OPERATIONS,
                },
                "native_minus_rust": {
                    "requests_total": excess_requests,
                    "requested_bytes_total": excess_bytes,
                    "requests_per_operation": excess_requests / OPERATIONS,
                    "requested_bytes_per_operation": excess_bytes / OPERATIONS,
                },
                "native_matches_rust_global": matches,
                "trace": artifact(trace),
                "benchmark_stdout": artifact(stdout_path),
                "benchmark_stderr": artifact(stderr_path),
            }
            print(f"{label} {case}: native {native['requests_per_operation']:g} requests / {native['requested_bytes_per_operation']:g} bytes; Rust {rust_requests / OPERATIONS:g} / {rust_bytes / OPERATIONS:g}", flush=True)
        if sha256(Path(executable["path"])) != executable["sha256"]:
            raise RuntimeError(f"{label}: executable changed during measurement")
    if sha256(Path(profiler["path"])) != profiler["sha256"]:
        raise RuntimeError("malloc tracer changed during measurement")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"Saved {args.output}; raw traces: {session_dir}", flush=True)


if __name__ == "__main__":
    main()
