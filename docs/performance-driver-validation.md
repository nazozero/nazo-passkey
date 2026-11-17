# Performance report driver validation

## Scope

This follow-up changes `perf/run.py`, its regression tests and the existing CI quality job. It does not change the WebAuthn verifier, cryptographic acceptance policy, public Rust API or consumer dependency pin. It is not a new latency measurement or a production-readiness declaration.

## Evidence-integrity defect

The previous driver checked only that each child emitted ten JSON rows. A duplicate case replacing a missing case still satisfied that check. Aggregation could then compare different case sets or sample counts across revisions without failing. Invalid numeric metrics and inherited measurement modifiers were also unchecked.

The comparison boundary now requires the exact eight production-API cases and two primitive controls, each once per child execution, with the requested iteration count, concurrency one, the expected metric fields, finite nonnegative values, positive throughput and ordered quantiles. This validation happens outside the timed benchmark process and adds no verifier-path overhead.

`PERF_CASE`, `PERF_MTRACE`, nonempty `MALLOC_TRACE`, `LD_PRELOAD` and `LD_AUDIT` are rejected for comparison runs. Profiling remains a separate invocation of the benchmark binary. This check does not detect every external profiler or competing process: the operator must still isolate the host and finish compilation before measurement.

The report retains binary hashes, adds the driver hash and records execution order for both two-way and three-way comparisons. Child stderr is retained. Failed child execution or invalid rows abort instead of producing a fresh aggregate report. Use a new output path per run; a previously existing report is not deleted when a later invocation fails.

## Statistical interpretation

`median_by_case` contains medians of the per-round metrics. In particular, its P95/P99 values are **medians of per-round quantiles**, not pooled percentiles over all requests. Raw per-round metrics remain in `runs`.

Two-way runs alternate order. Three-way runs rotate and reverse order; use six rounds (or a multiple of six) to exercise all six permutations with each revision appearing in each position equally often. The default remains five for compatibility and is not fully position-balanced for three revisions.

## Tests

Run on Linux with Python 3.10 or later:

```sh
python3 -m unittest discover -s perf -p 'test_*.py' -v
```

The suite covers exact case-set validation, duplicate/missing cases, schema and sample-count mismatches, invalid numbers, quantile ordering, malformed JSON, environment contamination, scheduling and real subprocess execution of synthetic two-way and three-way fixtures. These fixtures test the report contract only; their invented timings must never be used as performance evidence.

The existing CI quality job runs this suite without adding a Python package dependency or another CI job. Before accepting a final Ed25519 performance conclusion, run the actual original-baseline/checkpoint/candidate binaries on the same isolated host and retain their build revisions, lockfiles and compiler details alongside the new report. Historical reports keep their original revision attribution; this driver fix does not validate or replace them.
