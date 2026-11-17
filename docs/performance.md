# Performance methodology and measured results

All figures below were measured, including regressions. The production baseline is NazoAuth's exact pinned revision **d59b317998e56f4a16a69133d7a854c5c34f795b**. The candidate implementation is **b3ecfa40c8f626903f36d6065640236ac87fe472**. Native AWS results use **aws-lc-rs 1.19.0 / aws-lc-sys 0.47.0**, matching the NazoAuth lock. All three full-API comparisons were repeated after the final registration-error compatibility fix; the previous fa0f0c results remain clearly labeled checkpoints.

## Findings

- In its own five-round native comparison, AWS-LC reduced ES256 **complete authentication finish** P50 from **419.884 to 86.491 microseconds**, a **79.4%** reduction (about **4.85x** the inverse latency). All five per-round P50 comparisons improve, by **78.95%–80.08%**. This includes decoding, policy checks, COSE parsing and real signature verification, not only a primitive call.
- This is a tradeoff: ES256 native allocation requests are **23 / 1,327 bytes** with AWS-LC, versus **16 / 1,363 bytes** at baseline. The Rust-only allocator sees just **6 / 324 bytes** and misses 17 C-side allocation requests. The benchmark executable is larger with AWS-LC.
- Portable RustCrypto removes substantial allocation and parser overhead. Its complete ES256 authentication P50 changes by **-2.1%**, with paired-round changes from **-8.4% to +37.0%**. Scheduling variation and long tails mean this small median change does **not** establish a stable attributable verification speedup.
- Ed25519 becomes stricter and has a latency cost. In the AWS comparison window (Ed still uses dalek), authentication P50 is **56.315 to 62.384 microseconds (+10.8%)**; registration finish is **4.517 to 9.184 microseconds (+103.3%)**. The separate portable window reports **+17.4% / +140.2%** respectively. None-attestation registration now validates the public point, while authentication now uses dalek strict verification and canonical/weak-key checks. These are security costs; they were not removed to improve a chart. The experiment does not isolate an exact time for each individual new check.
- WASI has no AWS backend and shows no general latency improvement. Its ES256 authentication P50 changes by **-0.6%** and Ed25519 authentication by **+7.1%**; Ed25519 registration changes by **+135.1%**. Native numbers must not be extrapolated to browser or WASI performance.

## Controlled inputs and boundaries

Both revisions use byte-identical benches/ceremony.rs (SHA-256 **7d5fa01b880c39b22f7f7d0bf7b439f47f09ffd9236aefd2a18d1cee5b8984a2**) through an independent perf workspace. Baseline production source was not changed. Archived baseline manifests and locks, final candidate locks, compiler details and binary SHA-256 values identify the experiment. The [final build record](evidence/artifact-builds-final.json) identifies the exact three freshly built candidate artifacts used here. The earlier [byte-identical rebuild experiment](evidence/artifact-reproduction.json) belongs to fa0f0c and is retained only as historical evidence; it is not presented as a rebuild of this final commit.

The fixed finish fixtures use real deterministic ES256/Ed25519 signatures, fixed challenges and client data, one 32-byte credential ID, one allow-listed credential, strict Base64, UV=true under Preferred policy, BE=BS=false, no authenticator extensions, and none attestation at registration. Begin operations issue a real fresh random challenge each time. Registration-begin labels for ES256 and Ed25519 call the same algorithm-independent API; their differences are timing variation, not algorithm effects. Constructor work is excluded: NazoAuth also constructs and reuses its Webauthn verifier. Configuration binding is computed on construction/configuration, not rehashed by each begin call.

All runs use the same Linux x86_64 AMD EPYC 9V74 host, Rust 1.100.0, release mode, thin LTO, one codegen unit, stripped symbols, panic=abort, concurrency **one**, and CPU affinity **logical CPU 0**. There are 200 warm-up operations and **5,000 timed operations per case per round**, followed by a separate 100-operation Rust allocation count. Five rounds alternate baseline/candidate order. Builds, fuzz and NazoAuth tests were paused; PostgreSQL and Valkey were stopped. Allocation tracing was also excluded from the timing windows. The shared host's other tenants and hardware frequency were not controllable.

Public registration/authentication begin/finish methods are measured through successful returned values and their destruction. Finish includes its input parsing, state/account/policy checks and signature work. HTTP, external response-JSON deserialization, database queries, Valkey GETDEL, SQL CAS, queues and sessions are outside the timing boundary. Reusing a valid assertion measures the pure verifier; it does not bypass or simulate application replay protection. Neither certificate-path performance nor maximum-size/many-credential/malicious-input workloads are inferred from these fixtures.

### Statistics and noise

Each displayed P50/P95/P99 is the **median of the five per-round quantiles**, not a pooled percentile of 25,000 samples. Throughput is likewise the median of per-round throughput; it includes the timing loop/sample bookkeeping and need not equal 1/P50. All rounds and tails remain in the raw records, including unusually slow runs. The portable and AWS native experiments have separate baseline windows: each percentage uses its own paired experiment, never a baseline selected from the other window.

Host variability is material. The portable experiment's unchanged ES256 primitive P50 differs by **-0.87%** between revisions, but its paired-round changes range from **-3.60% to +24.63%**. The AWS experiment's unchanged ES256 control differs by **+0.49%** overall. Large P95/P99 spikes and process-duration variation prevent strong low-tail-latency or small-speedup claims. The unchanged Ed control uses strict verification with a cached key on both sides, whereas baseline production Ed verification used ordinary verify; equal control times do not mean equal production security work.

## Complete API latency and throughput

Each cell is **baseline → candidate**. Latencies are microseconds; throughput is operations/second. Primitive rows are controls and do not replace API measurements.

### Native, portable RustCrypto

[Raw five-round record](evidence/performance-final-native-rustcrypto.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.421 → 0.411 | 0.531 → 0.651 | 0.591 → 0.681 | 1,999,900 → 1,825,220 |
| ed25519.authentication_finish | 54.983 → 64.528 | 141.864 → 117.598 | 599.966 → 273.373 | 12,167 → 11,878 |
| ed25519.registration_begin | 0.360 → 0.401 | 0.471 → 0.651 | 0.511 → 0.701 | 2,259,058 → 1,856,654 |
| ed25519.registration_finish | 4.216 → 10.125 | 4.787 → 11.307 | 19.048 → 47.191 | 205,351 → 87,607 |
| es256.authentication_begin | 0.411 → 0.401 | 0.531 → 0.661 | 0.580 → 0.691 | 1,980,534 → 1,634,121 |
| es256.authentication_finish | 424.581 → 415.778 | 606.326 → 778.295 | 1939.188 → 1975.685 | 2,128 → 2,039 |
| es256.registration_begin | 0.351 → 0.391 | 0.480 → 0.641 | 0.530 → 0.701 | 2,178,500 → 1,895,640 |
| es256.registration_finish | 5.379 → 2.393 | 5.939 → 2.784 | 6.500 → 5.037 | 170,803 → 376,075 |
| control: ed25519_strict | 54.312 → 53.160 | 96.266 → 91.569 | 344.650 → 191.189 | 14,602 → 12,886 |
| control: es256 | 412.603 → 409.018 | 682.300 → 520.416 | 2681.879 → 2381.846 | 1,988 → 2,092 |

### Native, AWS-LC feature

[Raw five-round record](evidence/performance-final-native-aws-lc.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.431 → 0.380 | 0.550 → 0.641 | 0.581 → 0.711 | 1,972,124 → 1,816,904 |
| ed25519.authentication_finish | 56.315 → 62.384 | 93.110 → 101.383 | 145.600 → 121.363 | 15,437 → 14,104 |
| ed25519.registration_begin | 0.371 → 0.371 | 0.481 → 0.611 | 0.511 → 0.661 | 2,272,870 → 1,882,579 |
| ed25519.registration_finish | 4.517 → 9.184 | 4.887 → 11.448 | 6.701 → 41.513 | 188,727 → 87,160 |
| es256.authentication_begin | 0.431 → 0.401 | 0.541 → 0.641 | 0.580 → 0.681 | 1,973,970 → 1,865,772 |
| es256.authentication_finish | 419.884 → 86.491 | 531.312 → 127.623 | 3207.093 → 324.280 | 1,999 → 9,465 |
| es256.registration_begin | 0.361 → 0.390 | 0.481 → 0.641 | 0.520 → 0.671 | 2,038,351 → 1,808,695 |
| es256.registration_finish | 5.318 → 2.434 | 5.829 → 2.874 | 16.755 → 3.025 | 160,058 → 361,710 |
| control: ed25519_strict | 55.094 → 55.985 | 94.503 → 91.548 | 116.666 → 181.875 | 15,736 → 15,256 |
| control: es256 | 403.580 → 405.542 | 476.910 → 713.258 | 953.380 → 2907.529 | 2,289 → 2,067 |

### WASI preview1, Node v24.22.1, RustCrypto

[Raw five-round record](evidence/performance-final-wasi.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.902 → 1.212 | 1.883 → 1.522 | 2.594 → 3.125 | 491,065 → 483,593 |
| ed25519.authentication_finish | 179.511 → 192.230 | 227.553 → 257.819 | 293.022 → 1662.510 | 5,034 → 4,311 |
| ed25519.registration_begin | 0.781 → 1.353 | 1.802 → 1.582 | 2.754 → 3.636 | 663,697 → 498,219 |
| ed25519.registration_finish | 7.502 → 17.637 | 8.663 → 21.622 | 38.458 → 56.204 | 116,331 → 43,834 |
| es256.authentication_begin | 1.112 → 1.432 | 2.083 → 1.773 | 2.404 → 2.113 | 295,428 → 219,885 |
| es256.authentication_finish | 1153.071 → 1146.691 | 1387.305 → 2305.291 | 2876.714 → 7842.041 | 804 → 647 |
| es256.registration_begin | 1.252 → 1.663 | 3.225 → 2.204 | 6.100 → 4.406 | 167,993 → 171,473 |
| es256.registration_finish | 9.124 → 7.041 | 24.998 → 16.706 | 50.556 → 38.298 | 30,006 → 32,227 |
| control: ed25519_strict | 171.549 → 169.986 | 225.070 → 211.399 | 333.884 → 276.508 | 5,089 → 5,543 |
| control: es256 | 1159.030 → 1075.324 | 1889.383 → 1234.704 | 4184.268 → 2027.752 | 766 → 862 |

## Allocation requests and bytes

Counts below include allocation and reallocation requests; a realloc contributes its entire requested new size. Bytes are cumulative allocator requests, **not peak memory, live bytes or RSS**. The allocation experiment is separate from all timed comparisons: no timing run loads a malloc tracer.

### Native totals, including AWS-LC C allocations

The benchmark enables glibc mtrace only around its separate 100-operation allocation loop, with libc_malloc_debug loaded. The [driver](../perf/allocations.py) checks complete trace windows, event formats, realloc pairs, binary/profiler identities and successful requests. All **30** cases completed. For baseline and portable RustCrypto, all **20** cases exactly match the Rust global counters; both zero-allocation controls contain only Start/End markers. No fixed in-window profiler allocation was observed. Direct mmap or allocation mechanisms bypassing glibc hooks are outside this measurement.

Each cell is **requests / bytes per operation**. See [full allocation evidence](evidence/allocations-native.json), including trace digests and measured artifact hashes, and the [30 original allocation traces](evidence/native-allocation-traces.tar.gz). Every archived trace was checked against its recorded SHA-256.

| Scenario | Baseline | Portable RustCrypto | Native AWS-LC |
|---|---:|---:|---:|
| es256.registration_begin | 9 / 184 | 9 / 184 | 9 / 184 |
| es256.registration_finish | 28 / 2,860 | 8 / 519 | 8 / 519 |
| es256.authentication_begin | 12 / 351 | 10 / 295 | 10 / 295 |
| es256.authentication_finish | 16 / 1,363 | 6 / 324 | 23 / 1,327 |
| ed25519.registration_begin | 9 / 184 | 9 / 184 | 9 / 184 |
| ed25519.registration_finish | 23 / 1,599 | 8 / 448 | 8 / 448 |
| ed25519.authentication_begin | 12 / 351 | 10 / 295 | 10 / 295 |
| ed25519.authentication_finish | 13 / 781 | 7 / 396 | 7 / 396 |

AWS ES256 authentication therefore increases total request count **43.75%** and decreases cumulative requested bytes only **2.64%** against baseline. Portable ES256 authentication reduces them **62.5% / 76.2%**, and Ed25519 authentication reduces them **46.2% / 49.3%**. These figures are Linux/glibc measurements; they do not describe another platform's native allocator.

### WASI Rust-module allocations

WASI pointer widths/layout differ from native. The module's Rust allocator counters exclude Node/V8/JIT allocations and do not measure whole-process peak memory.

| Scenario | Baseline requests / bytes | Candidate requests / bytes |
|---|---:|---:|
| ed25519.authentication_begin | 12 / 283 | 10 / 239 |
| ed25519.authentication_finish | 13 / 781 | 7 / 396 |
| ed25519.registration_begin | 9 / 168 | 9 / 168 |
| ed25519.registration_finish | 23 / 1,587 | 8 / 436 |
| es256.authentication_begin | 12 / 283 | 10 / 239 |
| es256.authentication_finish | 16 / 1,363 | 6 / 324 |
| es256.registration_begin | 9 / 168 | 9 / 168 |
| es256.registration_finish | 28 / 2,848 | 8 / 507 |

## Process CPU and artifact size

These are whole benchmark child processes (all ten cases, warm-up, fixture creation, reporting and allocation loops), not isolated API CPU counters. CPU seconds are user+system time; utilization is relative to **one** core. Each value is the median of the five recorded process measurements. WASI additionally includes Node startup, compilation and JIT activity. CPU% medians and wall/CPU medians are summarized separately and should not be recomputed as if they came from one run.

| Comparison | Revision | Wall seconds | CPU seconds | One-core CPU % | Artifact bytes |
|---|---|---:|---:|---:|---:|
| native-rustcrypto | baseline | 5.861 | 5.734 | 97.8% | 1,012,496 |
| native-rustcrypto | candidate | 6.419 | 6.214 | 96.8% | 1,237,976 |
| native-aws-lc | baseline | 6.184 | 6.144 | 98.9% | 1,012,496 |
| native-aws-lc | candidate | 4.500 | 4.357 | 97.0% | 3,833,808 |
| wasi | baseline | 16.631 | 16.377 | 98.5% | 735,591 |
| wasi | candidate | 16.840 | 16.672 | 98.0% | 952,662 |

Artifacts are the same benchmark app linked with each revision, not the crate's standalone text section or an entire NazoAuth deployment. The harness directly depends on P-256 signing, CBOR and fixture-generation tools; Cargo feature unification enables some features that a production consumer may omit. These sizes therefore cannot establish NazoAuth's incremental binary growth or the size benefit of removing production PEM support. AWS native build time and a larger linked artifact remain costs. No multi-core throughput/capacity or application CPU-utilization claim is made.

## Backend experiment and security boundary

The [final five-round parsed-key experiment](evidence/performance-final-backends.json) uses the same host and AWS-LC 1.19.0, with 5,000 samples/case and one pinned CPU. It is explanatory evidence, separate from the full API comparisons above. This standalone program does not link passkey-auth, and neither its source nor its lock changed in the final registration-error fix; the recorded five-round 1.19.0 backend experiment is retained without relabeling it as a new full-library run.

| Parsed-key verification | P50 µs | P95 µs | P99 µs |
|---|---:|---:|---:|
| es256.rustcrypto.parse_and_verify | 409.098 | 1135.024 | 2408.539 |
| es256.aws_lc.parse_and_verify | 64.237 | 228.606 | 487.116 |
| ed25519.rustcrypto.parse_and_verify_strict | 48.914 | 189.086 | 578.113 |
| ed25519.aws_lc.parse_and_verify | 46.510 | 192.080 | 484.863 |

The AWS Ed25519 probe accepted a deliberately weak/small-order public-key fixture in all five runs; dalek strict rejects that policy case. This is an acceptance-policy difference, not a newly established AWS-LC vulnerability. The implementation never selects AWS for Ed25519. The native ES256 feature retains the same DER/scalar boundary and locally computed SHA-256 transcript, with positive, negative and high-S/backend-differential tests. Certificate attestation verification remains RustCrypto.

Initial pre-optimization measurements are retained in performance-native-initial.json, performance-wasi-initial.json and performance-backends.json. The latter uses **AWS-LC 1.18.2**, and those exploratory values are not substituted for final results. An early Ed25519 decompress/recompress implementation was removed after measurement identified redundant inversion work; its equivalent canonical-byte check is covered by differential properties and explicit edge cases. The remaining strict verification and registration-point checks stay in place.

The three `performance-checkpoint-fa0f0c-*.json` API records and the separately named allocation JSON/archive preserve the preceding implementation measurements. They are historical observations, not additional rounds in the final comparison. The final raw RustCrypto record also discloses a corrected metadata-wrapper path error after its benchmark process had completed successfully; all original samples were preserved.

## Reproducing the experiment

Use Rust 1.100.0 and a quiet machine. Choose an available CPU in your process affinity; CPU 0 was used here. Build artifacts before measuring, copy each native binary before changing feature settings, and preserve all locks.

    git worktree add --detach ../passkey-auth-baseline d59b317998e56f4a16a69133d7a854c5c34f795b
    mkdir -p ../passkey-auth-baseline/benches ../passkey-auth-baseline/perf artifacts
    cp benches/ceremony.rs ../passkey-auth-baseline/benches/
    cp docs/evidence/baseline-perf-Cargo.toml ../passkey-auth-baseline/perf/Cargo.toml
    cp docs/evidence/baseline-perf-Cargo.lock ../passkey-auth-baseline/perf/Cargo.lock
    cargo build --locked --release --manifest-path ../passkey-auth-baseline/perf/Cargo.toml
    cp ../passkey-auth-baseline/perf/target/release/ceremony-bench artifacts/baseline-native
    cargo build --locked --release --manifest-path perf/Cargo.toml --no-default-features
    cp perf/target/release/ceremony-bench artifacts/candidate-native-rustcrypto
    cargo build --locked --release --manifest-path perf/Cargo.toml --features aws-lc
    cp perf/target/release/ceremony-bench artifacts/candidate-native-aws-lc
    python3 perf/run.py --baseline artifacts/baseline-native --candidate artifacts/candidate-native-rustcrypto --cpu 0 --rounds 5 --iterations 5000 --output native-rustcrypto.json
    python3 perf/run.py --baseline artifacts/baseline-native --candidate artifacts/candidate-native-aws-lc --cpu 0 --rounds 5 --iterations 5000 --output native-aws-lc.json

Add the wasm32-wasip1 target, build each workspace with that target (candidate --all-features), and pass the two .wasm paths to the same driver with --wasi. Use the recorded Node version. Do not infer browser timings from Node's WASI runtime.

For native allocation counts on Linux/glibc, install the matching libc_malloc_debug library and run the separate driver; no latency from this command is reported:

    python3 perf/allocations.py --baseline artifacts/baseline-native --rustcrypto artifacts/candidate-native-rustcrypto --aws-lc artifacts/candidate-native-aws-lc --aws-lc-version 1.19.0 --aws-lc-sys-version 0.47.0 --trace-dir allocation-traces --output allocations.json

For the supporting backend experiment, build perf/backend-comparison with --locked --release, run its executable five times on the same chosen CPU, and retain the JSON lines and negative-probe results. The production API measurements remain the primary performance evidence.
