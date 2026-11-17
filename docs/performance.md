# Performance methodology and measured results

All figures below were measured, including regressions. The production baseline is NazoAuth's exact pinned revision **d59b317998e56f4a16a69133d7a854c5c34f795b**. The candidate implementation is **fa0f0c869b88c8609fbd6097a8ecfefacff2a6b3**. Native AWS results use **aws-lc-rs 1.19.0 / aws-lc-sys 0.47.0**, matching the NazoAuth lock.

## Findings

- In its own five-round native comparison, AWS-LC reduced ES256 **complete authentication finish** P50 from **431.722 to 87.482 microseconds**, a **79.7%** reduction (about **4.93x** the inverse latency). All five per-round P50 comparisons improve, by **78.96%–81.46%**. This includes decoding, policy checks, COSE parsing and real signature verification, not only a primitive call.
- This is a tradeoff: ES256 native allocation requests are **23 / 1,327 bytes** with AWS-LC, versus **16 / 1,363 bytes** at baseline. The Rust-only allocator sees just **6 / 324 bytes** and misses 17 C-side allocation requests. The benchmark executable is larger with AWS-LC.
- Portable RustCrypto removes substantial allocation and parser overhead. Its ES256 authentication P50 change is smaller than the change in the unchanged ES256 control; these data do **not** establish an attributable ES256 verification latency improvement for the portable backend.
- Ed25519 becomes stricter and slower. In the AWS comparison window (Ed still uses dalek), authentication P50 is **54.993 to 67.842 microseconds (+23.4%)**; registration finish is **4.366 to 10.005 microseconds (+129.2%)**. The separate portable window reports **+41.5% / +81.1%** respectively. None-attestation registration now validates the public point, while authentication now uses dalek strict verification and canonical/weak-key checks. These are security costs; they were not removed to improve a chart. The experiment does not isolate an exact time for each individual new check.
- WASI has no AWS backend and shows no general latency improvement. ES256 authentication P50 is nearly unchanged; Ed registration and begin operations become slower. Native numbers must not be extrapolated to browser or WASI performance.

## Controlled inputs and boundaries

Both revisions use byte-identical benches/ceremony.rs (SHA-256 **7d5fa01b880c39b22f7f7d0bf7b439f47f09ffd9236aefd2a18d1cee5b8984a2**) through an independent perf workspace. Baseline production source was not changed. Archived baseline manifests and locks, final candidate locks, compiler details and binary SHA-256 values identify the experiment. After measurement, rebuilding the portable and WASI artifacts with the final lock produced [byte-identical binaries](evidence/artifact-reproduction.json); the unused optional AWS lock update did not change them.

The fixed finish fixtures use real deterministic ES256/Ed25519 signatures, fixed challenges and client data, one 32-byte credential ID, one allow-listed credential, strict Base64, UV=true under Preferred policy, BE=BS=false, no authenticator extensions, and none attestation at registration. Begin operations issue a real fresh random challenge each time. Registration-begin labels for ES256 and Ed25519 call the same algorithm-independent API; their differences are timing variation, not algorithm effects. Constructor work is excluded: NazoAuth also constructs and reuses its Webauthn verifier. Configuration binding is computed on construction/configuration, not rehashed by each begin call.

All runs use the same Linux x86_64 AMD EPYC 9V74 host, Rust 1.100.0, release mode, thin LTO, one codegen unit, stripped symbols, panic=abort, concurrency **one**, and CPU affinity **logical CPU 0**. There are 200 warm-up operations and **5,000 timed operations per case per round**, followed by a separate 100-operation Rust allocation count. Five rounds alternate baseline/candidate order. Builds, fuzz and NazoAuth tests were paused; PostgreSQL and Valkey were idle. The shared host's other tenants and hardware frequency were not controllable.

Public registration/authentication begin/finish methods are measured through successful returned values and their destruction. Finish includes its input parsing, state/account/policy checks and signature work. HTTP, external response-JSON deserialization, database queries, Valkey GETDEL, SQL CAS, queues and sessions are outside the timing boundary. Reusing a valid assertion measures the pure verifier; it does not bypass or simulate application replay protection. Neither certificate-path performance nor maximum-size/many-credential/malicious-input workloads are inferred from these fixtures.

### Statistics and noise

Each displayed P50/P95/P99 is the **median of the five per-round quantiles**, not a pooled percentile of 25,000 samples. Throughput is likewise the median of per-round throughput; it includes the timing loop/sample bookkeeping and need not equal 1/P50. All rounds and tails remain in the raw records, including unusually slow runs. The portable and AWS native experiments have separate baseline windows: each percentage uses its own paired experiment, never a baseline selected from the other window.

Host variability is material. The portable experiment's unchanged ES256 primitive P50 varies between revisions by about **16.7%**; the AWS experiment's unchanged ES256 control by about **5.0%**. Large P95/P99 spikes and process-duration variation prevent strong low-tail-latency or small-speedup claims. The unchanged Ed control uses strict verification with a cached key on both sides, whereas baseline production Ed verification used ordinary verify; equal control times do not mean equal production security work.

## Complete API latency and throughput

Each cell is **baseline → candidate**. Latencies are microseconds; throughput is operations/second. Primitive rows are controls and do not replace API measurements.

### Native, portable RustCrypto

[Raw five-round record](evidence/performance-final-native-rustcrypto.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.371 → 0.251 | 0.481 → 0.501 | 0.601 → 0.651 | 861,617 → 1,876,311 |
| ed25519.authentication_finish | 45.058 → 63.746 | 430.450 → 280.714 | 1298.801 → 916.614 | 7,366 → 8,844 |
| ed25519.registration_begin | 0.231 → 0.241 | 0.411 → 0.601 | 0.550 → 0.691 | 535,517 → 1,709,744 |
| ed25519.registration_finish | 4.036 → 7.311 | 4.947 → 12.309 | 59.950 → 115.794 | 99,569 → 84,618 |
| es256.authentication_begin | 0.280 → 0.251 | 0.421 → 0.581 | 0.631 → 0.761 | 1,909,196 → 975,187 |
| es256.authentication_finish | 504.822 → 475.868 | 2295.987 → 3117.397 | 3746.767 → 7449.327 | 1,188 → 907 |
| es256.registration_begin | 0.240 → 0.241 | 0.390 → 0.481 | 0.531 → 0.721 | 1,522,204 → 1,548,157 |
| es256.registration_finish | 4.277 → 1.563 | 6.180 → 2.654 | 106.681 → 32.069 | 117,474 → 218,003 |
| control: ed25519_strict | 43.987 → 43.996 | 369.157 → 227.053 | 1060.761 → 673.217 | 9,831 → 11,740 |
| control: es256 | 546.215 → 454.726 | 2500.806 → 1503.100 | 4980.239 → 3651.623 | 1,087 → 1,558 |

### Native, AWS-LC feature

[Raw five-round record](evidence/performance-final-native-aws-lc.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.390 → 0.420 | 0.511 → 0.671 | 0.591 → 0.731 | 1,892,779 → 1,694,499 |
| ed25519.authentication_finish | 54.993 → 67.842 | 94.623 → 104.267 | 292.582 → 157.868 | 15,244 → 13,546 |
| ed25519.registration_begin | 0.341 → 0.371 | 0.461 → 0.641 | 0.521 → 0.751 | 1,984,675 → 1,136,759 |
| ed25519.registration_finish | 4.366 → 10.005 | 4.947 → 11.457 | 15.273 → 47.381 | 187,489 → 89,942 |
| es256.authentication_begin | 0.421 → 0.421 | 0.541 → 0.651 | 0.601 → 0.741 | 1,941,493 → 1,759,758 |
| es256.authentication_finish | 431.722 → 87.482 | 1068.674 → 127.803 | 2369.538 → 285.732 | 1,782 → 10,380 |
| es256.registration_begin | 0.350 → 0.401 | 0.471 → 0.651 | 0.531 → 0.711 | 1,953,060 → 1,458,506 |
| es256.registration_finish | 5.398 → 2.434 | 5.908 → 2.685 | 41.763 → 2.985 | 129,136 → 362,794 |
| control: ed25519_strict | 54.262 → 54.472 | 218.360 → 95.003 | 933.469 → 243.418 | 10,878 → 15,146 |
| control: es256 | 427.876 → 406.624 | 1603.849 → 524.462 | 3244.334 → 1042.163 | 1,426 → 2,222 |

### WASI preview1, Node v24.22.1, RustCrypto

[Raw five-round record](evidence/performance-final-wasi.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.961 → 1.251 | 1.933 → 1.412 | 3.275 → 3.756 | 312,328 → 301,128 |
| ed25519.authentication_finish | 176.236 → 192.882 | 425.853 → 349.558 | 1307.405 → 1589.000 | 4,119 → 4,074 |
| ed25519.registration_begin | 0.801 → 1.172 | 1.823 → 1.352 | 3.575 → 3.856 | 234,090 → 397,381 |
| ed25519.registration_finish | 5.528 → 17.096 | 10.176 → 31.217 | 147.683 → 124.157 | 88,064 → 38,784 |
| es256.authentication_begin | 0.691 → 1.543 | 1.271 → 1.812 | 2.644 → 2.404 | 298,695 → 173,201 |
| es256.authentication_finish | 1169.446 → 1176.907 | 3907.936 → 1623.674 | 9325.117 → 3905.117 | 603 → 763 |
| es256.registration_begin | 0.852 → 1.713 | 5.098 → 2.173 | 7.030 → 4.657 | 123,577 → 141,056 |
| es256.registration_finish | 6.770 → 6.971 | 23.916 → 17.447 | 106.420 → 53.751 | 28,419 → 27,228 |
| control: ed25519_strict | 170.348 → 171.229 | 417.069 → 459.995 | 1670.873 → 1342.940 | 4,077 → 4,489 |
| control: es256 | 1109.400 → 1148.183 | 2933.200 → 1976.176 | 5908.819 → 4135.629 | 692 → 767 |

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
| native-rustcrypto | baseline | 10.590 | 10.200 | 96.3% | 1,012,496 |
| native-rustcrypto | candidate | 11.651 | 11.054 | 94.6% | 1,237,912 |
| native-aws-lc | baseline | 8.269 | 8.146 | 98.5% | 1,012,496 |
| native-aws-lc | candidate | 3.746 | 3.659 | 98.2% | 3,833,808 |
| wasi | baseline | 20.396 | 19.827 | 97.9% | 735,591 |
| wasi | candidate | 18.058 | 17.686 | 98.5% | 952,559 |

Artifacts are the same benchmark app linked with each revision, not the crate's standalone text section or an entire NazoAuth deployment. The harness directly depends on P-256 signing, CBOR and fixture-generation tools; Cargo feature unification enables some features that a production consumer may omit. These sizes therefore cannot establish NazoAuth's incremental binary growth or the size benefit of removing production PEM support. AWS native build time and a larger linked artifact remain costs. No multi-core throughput/capacity or application CPU-utilization claim is made.

## Backend experiment and security boundary

The [final five-round parsed-key experiment](evidence/performance-final-backends.json) uses the same host and AWS-LC 1.19.0, with 5,000 samples/case and one pinned CPU. It is explanatory evidence, separate from the full API comparisons above.

| Parsed-key verification | P50 µs | P95 µs | P99 µs |
|---|---:|---:|---:|
| es256.rustcrypto.parse_and_verify | 409.098 | 1135.024 | 2408.539 |
| es256.aws_lc.parse_and_verify | 64.237 | 228.606 | 487.116 |
| ed25519.rustcrypto.parse_and_verify_strict | 48.914 | 189.086 | 578.113 |
| ed25519.aws_lc.parse_and_verify | 46.510 | 192.080 | 484.863 |

The AWS Ed25519 probe accepted a deliberately weak/small-order public-key fixture in all five runs; dalek strict rejects that policy case. This is an acceptance-policy difference, not a newly established AWS-LC vulnerability. The implementation never selects AWS for Ed25519. The native ES256 feature retains the same DER/scalar boundary and locally computed SHA-256 transcript, with positive, negative and high-S/backend-differential tests. Certificate attestation verification remains RustCrypto.

Initial pre-optimization measurements are retained in performance-native-initial.json, performance-wasi-initial.json and performance-backends.json. The latter uses **AWS-LC 1.18.2**, and those exploratory values are not substituted for final results. An early Ed25519 decompress/recompress implementation was removed after measurement identified redundant inversion work; its equivalent canonical-byte check is covered by differential properties and explicit edge cases. The remaining strict verification and registration-point checks stay in place.

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
