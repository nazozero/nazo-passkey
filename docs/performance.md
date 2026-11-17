# Performance methodology and measurements

This draft checkpoint contains the complete executable measurement harness; the final controlled measurements are still in progress. No speedup claim is made from smoke tests or from concurrent compilation.

## Comparison design

The baseline is exactly NazoAuth's pinned source revision `d59b317998e56f4a16a69133d7a854c5c34f795b`. Both revisions use the same `benches/ceremony.rs` through a small independent `perf/Cargo.toml` workspace. The baseline's production source is untouched. The experiment uses fixed real ES256/Ed25519 signing seeds, challenges, IDs, client JSON and authenticator data, strict Base64, one credential, and concurrency one. Registration uses none attestation; certificate-path performance is not generalized from it.

The release profile uses thin LTO, one codegen unit, symbol stripping and panic=abort. Each scenario has 200 warm-up operations, 5,000 measured operations, and a separate 100-operation allocation count. Five rounds alternate which revision runs first. Each process is pinned to one permitted logical CPU. Builds, dependency installation, fuzzing and database tests finish or pause before timed runs.

The public ceremony APIs are measured end to end within the library: registration begin/finish and authentication begin/finish for both algorithms. Finish includes input decoding, JSON/CBOR/COSE processing, state and policy checks and signature verification where applicable. These are pure verifier calls; HTTP, PostgreSQL, Valkey GETDEL/CAS, queueing and session creation are outside this timing boundary. The fixed valid assertion is deliberately reusable for measuring the pure verifier; application replay protection remains mandatory.

Two cached-key RustCrypto primitive controls and a separate parsed-key RustCrypto/AWS-LC experiment help interpret crypto cost. They do not substitute for the production API comparisons or prove backend security equivalence.

## Metrics and limits

The driver records every round, median P50/P95/P99, throughput, allocation/reallocation calls and allocated bytes per operation, process user+system CPU time, elapsed time, and CPU usage relative to one core. Allocation bytes are cumulative allocator requests, not peak retained memory; the Rust allocator does not count Node/V8 runtime allocations. Artifacts are the same benchmark application linked to each revision, not an entire NazoAuth deployment.

Native and WASI preview1/Node results are separate. Node WASI results are not browser, Cloudflare Workers, or all-WASM-platform performance claims. A shared virtualized host can still have scheduling/frequency noise despite CPU affinity and quiet local workloads. Small differences near the unchanged crypto controls must not be called reliable optimizations.

## Reproduction

```sh
git worktree add --detach ../passkey-auth-baseline d59b317998e56f4a16a69133d7a854c5c34f795b
mkdir -p ../passkey-auth-baseline/benches ../passkey-auth-baseline/perf
cp benches/ceremony.rs ../passkey-auth-baseline/benches/
cp perf/Cargo.toml ../passkey-auth-baseline/perf/
# Use the archived baseline perf lock and candidate perf/Cargo.lock once the
# final evidence commit lands, then build both with --locked.
cargo build --release --manifest-path ../passkey-auth-baseline/perf/Cargo.toml
cargo build --locked --release --manifest-path perf/Cargo.toml
python3 perf/run.py --baseline ../passkey-auth-baseline/perf/target/release/ceremony-bench --candidate perf/target/release/ceremony-bench --cpu 0 --rounds 5 --iterations 5000 --output native-results.json
```

Choose an available CPU listed by the environment, not necessarily CPU 0. Build both workspaces with `--target wasm32-wasip1`, pass the resulting `.wasm` files to the same driver with `--wasi`, and preserve the Node version in the output. `perf/backend-comparison` pins AWS-LC to the NazoAuth version used by this task and contains real-signature negative probes as well as timings.
