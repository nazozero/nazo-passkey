> Historical checkpoint only: 8260480. References to current/final below mean that checkpoint, not runtime 8493867. See [performance.md](performance.md) for the newer evidence.

# Performance methodology and measured results

All figures below were measured, including regressions. The production baseline is NazoAuth's exact pinned revision **d59b317998e56f4a16a69133d7a854c5c34f795b**. The candidate implementation is **8260480634fac09e1151ca2b1a9eaa1c02af6f67**. Native AWS results use **aws-lc-rs 1.19.0 / aws-lc-sys 0.47.0**, matching the NazoAuth lock. All three full-API comparisons were repeated after the final packed certificate extension checks and rejection-order fix; the previous fa0f0c and b3ecfa4 results remain clearly labeled checkpoints.

## Findings

- In its own five-round native comparison, AWS-LC reduced ES256 **complete authentication finish** P50 from **415.448 to 79.050 microseconds**, a **81.0%** reduction (about **5.26x** the inverse latency). All five per-round P50 comparisons improve, by **79.47%–84.93%**. This includes decoding, policy checks, COSE parsing and real signature verification, not only a primitive call.
- This is a tradeoff: ES256 native allocation requests are **23 / 1,327 bytes** with AWS-LC, versus **16 / 1,363 bytes** at baseline. The Rust-only allocator sees just **6 / 324 bytes** and misses 17 C-side allocation requests. The benchmark executable is larger with AWS-LC.
- Portable RustCrypto removes substantial allocation and parser overhead. Its complete ES256 authentication P50 changes by **+2.1%**, with paired-round changes from **-1.2% to +2.2%**. Scheduling variation and long tails mean this small median change does **not** establish a stable attributable verification speedup.
- Ed25519 becomes stricter and has a latency cost. In the AWS comparison window (Ed still uses dalek), authentication P50 is **53.310 to 67.101 microseconds (+25.9%)**; registration finish is **4.107 to 9.084 microseconds (+121.2%)**. The separate portable window reports **+12.4% / +104.7%** respectively. None-attestation registration now validates the public point, while authentication now uses dalek strict verification and canonical/weak-key checks. These are security costs; they were not removed to improve a chart. The experiment does not isolate an exact time for each individual new check.
- WASI has no AWS backend and shows no general latency improvement. Its ES256 authentication P50 changes by **+0.2%** and Ed25519 authentication by **+11.3%**; Ed25519 registration changes by **+143.3%**. Native numbers must not be extrapolated to browser or WASI performance.

## Controlled inputs and boundaries

Both revisions use byte-identical benches/ceremony.rs (SHA-256 **7d5fa01b880c39b22f7f7d0bf7b439f47f09ffd9236aefd2a18d1cee5b8984a2**) through an independent perf workspace. Baseline production source was not changed. Archived baseline manifests and locks, final candidate locks, compiler details and binary SHA-256 values identify the experiment. The [final build record](evidence/artifact-builds-final.json) identifies the exact three freshly built candidate artifacts used here. The earlier [byte-identical rebuild experiment](evidence/artifact-reproduction.json) belongs to fa0f0c and is retained only as historical evidence; it is not presented as a rebuild of this final commit.

The fixed finish fixtures use real deterministic ES256/Ed25519 signatures, fixed challenges and client data, one 32-byte credential ID, one allow-listed credential, strict Base64, UV=true under Preferred policy, BE=BS=false, no authenticator extensions, and none attestation at registration. Begin operations issue a real fresh random challenge each time. Registration-begin labels for ES256 and Ed25519 call the same algorithm-independent API; their differences are timing variation, not algorithm effects. Constructor work is excluded: NazoAuth also constructs and reuses its Webauthn verifier. Configuration binding is computed on construction/configuration, not rehashed by each begin call.

All runs use the same Linux x86_64 AMD EPYC 9V74 host, Rust 1.100.0, release mode, thin LTO, one codegen unit, stripped symbols, panic=abort, concurrency **one**, and CPU affinity **logical CPU 0**. There are 200 warm-up operations and **5,000 timed operations per case per round**, followed by a separate 100-operation Rust allocation count. Five rounds alternate baseline/candidate order. Builds, fuzz and NazoAuth tests were paused; PostgreSQL and Valkey were stopped. Allocation tracing was also excluded from the timing windows. The shared host's other tenants and hardware frequency were not controllable.

Public registration/authentication begin/finish methods are measured through successful returned values and their destruction. Finish includes its input parsing, state/account/policy checks and signature work. HTTP, external response-JSON deserialization, database queries, Valkey GETDEL, SQL CAS, queues and sessions are outside the timing boundary. Reusing a valid assertion measures the pure verifier; it does not bypass or simulate application replay protection. Neither certificate-path performance nor maximum-size/many-credential/malicious-input workloads are inferred from these fixtures.

### Statistics and noise

Each displayed P50/P95/P99 is the **median of the five per-round quantiles**, not a pooled percentile of 25,000 samples. Throughput is likewise the median of per-round throughput; it includes the timing loop/sample bookkeeping and need not equal 1/P50. All rounds and tails remain in the raw records, including unusually slow runs. The portable and AWS native experiments have separate baseline windows: each percentage uses its own paired experiment, never a baseline selected from the other window.

An [independent numerical review](evidence/performance-final-826-independent-qa.json)
recomputed the tables, percentages, allocation totals and artifact identities
from the retained records. It checks reporting consistency; it does not remove
the experimental limitations or constitute another timing run.

Host variability is material. The portable experiment's unchanged ES256 primitive P50 differs by **-1.28%** between revisions, but its paired-round changes range from **-3.29% to +3.84%**. The AWS experiment's unchanged ES256 control differs by **+1.26%** overall. Large P95/P99 spikes and process-duration variation prevent strong low-tail-latency or small-speedup claims. The unchanged Ed control uses strict verification with a cached key on both sides, whereas baseline production Ed verification used ordinary verify; equal control times do not mean equal production security work.

## Complete API latency and throughput

Each cell is **baseline → candidate**. Latencies are microseconds; throughput is operations/second. Primitive rows are controls and do not replace API measurements.

### Native, portable RustCrypto

[Raw five-round record](evidence/performance-final-native-rustcrypto.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.421 → 0.390 | 0.531 → 0.641 | 0.571 → 0.681 | 2,018,073 → 1,958,631 |
| ed25519.authentication_finish | 59.060 → 66.360 | 100.001 → 104.278 | 169.245 → 173.662 | 11,525 → 12,969 |
| ed25519.registration_begin | 0.350 → 0.381 | 0.471 → 0.651 | 0.511 → 0.701 | 2,186,382 → 1,869,747 |
| ed25519.registration_finish | 4.487 → 9.184 | 4.917 → 11.136 | 5.739 → 42.654 | 192,643 → 89,933 |
| es256.authentication_begin | 0.421 → 0.390 | 0.541 → 0.641 | 0.601 → 0.732 | 2,014,587 → 1,716,645 |
| es256.authentication_finish | 417.170 → 425.743 | 550.361 → 1222.486 | 1462.759 → 3557.742 | 2,127 → 1,616 |
| es256.registration_begin | 0.370 → 0.360 | 0.481 → 0.621 | 0.531 → 0.702 | 2,227,739 → 1,469,072 |
| es256.registration_finish | 5.328 → 2.313 | 5.769 → 2.664 | 25.168 → 3.696 | 151,389 → 293,210 |
| control: ed25519_strict | 52.530 → 53.020 | 92.339 → 87.722 | 276.557 → 635.449 | 15,309 → 13,550 |
| control: es256 | 409.218 → 403.960 | 1251.049 → 611.333 | 3541.627 → 3172.421 | 1,654 → 2,004 |

### Native, AWS-LC feature

[Raw five-round record](evidence/performance-final-native-aws-lc.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.380 → 0.390 | 0.501 → 0.641 | 0.621 → 0.681 | 1,952,648 → 1,908,707 |
| ed25519.authentication_finish | 53.310 → 67.101 | 85.579 → 103.907 | 148.034 → 121.804 | 14,573 → 14,241 |
| ed25519.registration_begin | 0.330 → 0.361 | 0.431 → 0.631 | 0.520 → 0.671 | 2,400,977 → 1,912,999 |
| ed25519.registration_finish | 4.107 → 9.084 | 4.937 → 11.418 | 5.429 → 39.170 | 211,708 → 96,515 |
| es256.authentication_begin | 0.380 → 0.381 | 0.490 → 0.651 | 0.581 → 0.691 | 2,144,523 → 1,809,291 |
| es256.authentication_finish | 415.448 → 79.050 | 507.456 → 122.625 | 1042.474 → 180.813 | 2,299 → 11,012 |
| es256.registration_begin | 0.331 → 0.371 | 0.461 → 0.631 | 0.611 → 0.661 | 2,081,940 → 1,873,129 |
| es256.registration_finish | 4.807 → 2.124 | 6.099 → 2.574 | 6.750 → 3.015 | 162,692 → 366,778 |
| control: ed25519_strict | 51.528 → 53.961 | 82.594 → 86.020 | 182.766 → 239.762 | 13,411 → 16,272 |
| control: es256 | 395.348 → 400.314 | 487.086 → 479.234 | 767.299 → 697.563 | 2,379 → 2,375 |

### WASI preview1, Node v24.22.1, RustCrypto

[Raw five-round record](evidence/performance-final-wasi.json).

| Scenario | P50 µs | P95 µs | P99 µs | Throughput /s |
|---|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.931 → 1.422 | 1.933 → 1.652 | 2.504 → 2.263 | 484,197 → 465,693 |
| ed25519.authentication_finish | 177.568 → 197.618 | 244.028 → 244.649 | 457.510 → 333.553 | 4,979 → 4,635 |
| ed25519.registration_begin | 0.811 → 1.402 | 1.833 → 1.633 | 2.854 → 3.585 | 577,472 → 504,642 |
| ed25519.registration_finish | 7.662 → 18.638 | 8.903 → 21.432 | 39.880 → 60.472 | 116,545 → 46,158 |
| es256.authentication_begin | 1.181 → 1.622 | 2.234 → 1.883 | 2.674 → 2.163 | 236,131 → 225,518 |
| es256.authentication_finish | 1157.808 → 1159.658 | 1418.582 → 1333.133 | 3041.843 → 3195.095 | 803 → 808 |
| es256.registration_begin | 1.362 → 1.683 | 5.828 → 2.163 | 6.349 → 4.487 | 165,602 → 167,180 |
| es256.registration_finish | 9.154 → 7.091 | 25.949 → 11.787 | 55.564 → 50.797 | 27,194 → 33,802 |
| control: ed25519_strict | 169.637 → 171.028 | 246.922 → 228.675 | 463.410 → 361.847 | 4,795 → 5,330 |
| control: es256 | 1128.915 → 1135.264 | 1439.093 → 1682.441 | 2305.741 → 7226.751 | 829 → 719 |

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
| native-rustcrypto | baseline | 6.706 | 6.558 | 97.8% | 1,012,496 |
| native-rustcrypto | candidate | 6.867 | 6.767 | 97.8% | 1,239,496 |
| native-aws-lc | baseline | 5.516 | 5.305 | 96.2% | 1,012,496 |
| native-aws-lc | candidate | 3.572 | 3.477 | 97.5% | 3,835,088 |
| wasi | baseline | 16.296 | 15.885 | 97.6% | 735,591 |
| wasi | candidate | 17.102 | 16.705 | 97.7% | 954,507 |

Artifacts are the same benchmark app linked with each revision, not the crate's standalone text section or an entire NazoAuth deployment. The harness directly depends on P-256 signing, CBOR and fixture-generation tools; Cargo feature unification enables some features that a production consumer may omit. These sizes therefore cannot establish NazoAuth's incremental binary growth or the size benefit of removing production PEM support. AWS native build time and a larger linked artifact remain costs. No multi-core throughput/capacity or application CPU-utilization claim is made.

## Backend experiment and security boundary

The [final five-round parsed-key experiment](evidence/performance-final-backends.json) uses the same host and AWS-LC 1.19.0, with 5,000 samples/case and one pinned CPU. It is explanatory evidence, separate from the full API comparisons above. This standalone program does not link passkey-auth, and neither its source nor its lock changed in the final certificate and rejection-order fixes; the recorded five-round 1.19.0 backend experiment is retained without relabeling it as a new full-library run.

| Parsed-key verification | P50 µs | P95 µs | P99 µs |
|---|---:|---:|---:|
| es256.rustcrypto.parse_and_verify | 409.098 | 1135.024 | 2408.539 |
| es256.aws_lc.parse_and_verify | 64.237 | 228.606 | 487.116 |
| ed25519.rustcrypto.parse_and_verify_strict | 48.914 | 189.086 | 578.113 |
| ed25519.aws_lc.parse_and_verify | 46.510 | 192.080 | 484.863 |

The AWS Ed25519 probe accepted a deliberately weak/small-order public-key fixture in all five runs; dalek strict rejects that policy case. This is an acceptance-policy difference, not a newly established AWS-LC vulnerability. The implementation never selects AWS for Ed25519. The native ES256 feature retains the same DER/scalar boundary and locally computed SHA-256 transcript, with positive, negative and high-S/backend-differential tests. Certificate attestation verification remains RustCrypto.

Initial pre-optimization measurements are retained in performance-native-initial.json, performance-wasi-initial.json and performance-backends.json. The latter uses **AWS-LC 1.18.2**, and those exploratory values are not substituted for final results. An early Ed25519 decompress/recompress implementation was removed after measurement identified redundant inversion work; its equivalent canonical-byte check is covered by differential properties and explicit edge cases. The remaining strict verification and registration-point checks stay in place.

The `performance-checkpoint-fa0f0c-*.json` and `performance-checkpoint-b3ecfa4-*.json` API records and their separately named allocation JSON/archives preserve the preceding implementation measurements. They are historical observations, not additional rounds in the final comparison. The historical b3ecfa4 raw RustCrypto record also discloses a corrected metadata-wrapper path error after that benchmark process had completed successfully; all original samples were preserved.

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
