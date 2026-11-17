# Validation record

The baseline is NazoAuth's actual pinned revision d59b317998e56f4a16a69133d7a854c5c34f795b. The final production implementation is **b3ecfa40c8f626903f36d6065640236ac87fe472** (crate 0.2.0). Its final correction separates `CredentialExcluded` from `CredentialIdMismatch`, restoring NazoAuth's duplicate-registration HTTP 409 contract while preserving the accepted input set and verification order. Earlier complete CI runs for fa0f0c/787a717 remain historical evidence, not substitutes for running this revision. The [protocol matrix](protocol-compliance.md) gives source-level assessments, which are distinct from actual command outcomes.

## Environment and evidence

Local commands use Rust **1.100.0** (0ef1bc386, 2026-11-09), Linux x86_64, and dated nightly **2026-11-17** for libFuzzer/AddressSanitizer. The host exposes nine logical CPUs and about 9.7 GiB RAM. Browser compilation targets wasm32-unknown-unknown; executable WASI checks use wasm32-wasip1 and Node **v24.22.1**. Final AWS-enabled locks use **aws-lc-rs 1.19.0 / aws-lc-sys 0.47.0**. Ed25519 remains dalek strict in every configuration.

- [Local command evidence](evidence/local-validation.json) includes exit codes, test summaries and log digests. It distinguishes the initial dual-backend gate with AWS-LC 1.18.2 from the complete 1.19.0 all-target test rerun.
- [Implementation CI evidence](evidence/ci-implementation-snapshot.json) records jobs, steps and final-implementation fuzz log excerpts for [run 44065263386](https://github.com/nazozero/passkey-auth-rs/actions/runs/44065263386).
- [Windows failure and remediation evidence](evidence/ci-windows-aws-lc-setup.json) preserves the original failure; it is not relabeled as a successful test.
- [Historical complete library CI evidence](evidence/ci-validation-787a717.json) records all 12 successful jobs in run 44070479207, before the error-contract correction, including both backends on macOS Intel and the exact tested PR merge commit.
- [Final error-contract local gates](evidence/credential-excluded-local-validation.json) record formatting, Clippy, both complete test suites and the documentation test after the correction in b3ecfa4.
- [Final library CI evidence](evidence/ci-final-validation.json) records all 12 successful jobs in run 44074112339 for b3ecfa4, including the exact synthetic merge, core job steps, macOS test counts and both completed fuzz campaigns.
- [Final four-lock audit summaries](evidence/audit-final-summary.json) preserve the database revision and findings.
- [Performance report](performance.md) links separate raw timing and allocation records. Debug test runs and fuzz throughput are not performance benchmarks.

## Executed library gates

The final b3ecfa4 hosted run reran the applicable workflow gates below on its
own synthetic merge. Earlier local commands and four-lock audit records retain
their original provenance. The separate b3ecfa4 local record also confirms
formatting, Clippy, 104 default tests, 105 AWS-LC tests and one all-feature
doctest passed after the final correction.

| Command or scope | Observed outcome |
|---|---|
| Baseline cargo test --all-targets | PASS: 27 unit + 6 attestation + 13 ceremony tests; **46** total. |
| cargo fmt --all -- --check | PASS locally and in final-implementation CI. |
| cargo check --locked --all-targets --no-default-features | PASS locally and in final-implementation CI. |
| cargo check --locked --all-targets --all-features | PASS locally; final-version all-target compilation also occurs in CI Clippy/tests. |
| cargo clippy --locked --all-targets --all-features -- -D warnings | PASS locally and in final-implementation CI. |
| cargo test --locked --all-targets --no-default-features | PASS: **104** tests: 56 unit, 15 attestation, 8 binary regression, 20 ceremony, 1 official-vector suite, 4 example tests. Zero failures or ignored tests. |
| cargo test --locked --all-targets --features aws-lc | PASS after rebuilding with **1.19.0 / 0.47.0**: **105** tests, including the additional ES256 backend-differential regression. Zero failures or ignored tests. |
| cargo test --locked --doc with the applicable feature setting | PASS: **1** doctest per tested backend. |
| RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps | PASS; the local all-features documentation gate also passed. |
| Browser WASM library check with --no-default-features | PASS locally and in final-implementation CI. |
| Browser WASM library check with --all-features | PASS; AWS-LC is excluded from WASM by target dependencies and implementation cfg. |
| WASI release build with --all-features, then Node execution | PASS: all **10** benchmark scenarios execute. Browser or hardware interoperability is not implied. |
| cargo audit for main, perf, fuzz and backend-comparison locks | PASS: **0 vulnerabilities, 0 warnings, 0 ignored advisories** in each final lock. |

### Hosted platform matrix

The workflow retains both backends on Linux x86_64, Linux ARM64, macOS and Windows, including all-target and documentation tests.

The implementation run passed both Linux architectures and both backends, plus Windows RustCrypto, quality, WASM, audit and fuzz. Windows AWS-LC initially failed before any protocol test because aws-lc-sys could not find NASM. Commit **0f2bf0061796a123f7b64adbe5ccc8ab649ae0a3** adds a pinned Windows-only NASM installation, checks installation status and verifies the executable. No assembly, platform or backend test was disabled.

In the [post-fix run 44067111623](https://github.com/nazozero/passkey-auth-rs/actions/runs/44067111623), Windows AWS-LC job **133983529674 passed**, as did Windows RustCrypto, both Linux architectures/backends, quality, audit, WASM and fuzz. The two macOS ARM64 jobs subsequently cancelled before acquiring a runner. GitHub's visible annotations explicitly reported ARM64 capacity constraints and repeated acquisition failure; this was not a compiler/test failure. [The original annotations and remediation](evidence/ci-macos-runner-capacity.json) are preserved. The workflow executes the identical backend/test commands on macos-15-intel, while keeping Linux ARM64 coverage. **macOS ARM64 itself remains unverified.**

The [earlier complete library run 44070479207](https://github.com/nazozero/passkey-auth-rs/actions/runs/44070479207) passed **12 of 12 jobs**. It covered both backends on Linux x86_64, Linux ARM64, Windows x86_64 and macOS Intel, plus quality, audit, WASM and fuzz. macOS RustCrypto job **133995125663** ran **104 tests + 1 doctest**; macOS AWS-LC job **133995126042** ran **105 tests + 1 doctest**, with no failures or ignored tests. Its PR head was **787a717ce7e3daeeb578a69a4b5c3dd8f9236024**; Actions checked out synthetic merge **51cd42793469ca7dc17ca1112bc637bd706060b3** against the pinned base. [The historical snapshot](evidence/ci-validation-787a717.json) preserves those identities, every job outcome, core steps and macOS log digests. This result predates b3ecfa4.

The final production revision's [run 44074112339](https://github.com/nazozero/passkey-auth-rs/actions/runs/44074112339) also completed successfully: **all 12 jobs passed**. The exact PR head is **b3ecfa40c8f626903f36d6065640236ac87fe472**, source tree **720707ed776e82db5ba6acc3f82c1437834cdddb**, and the Actions-tested synthetic merge is **961270ed1c4eecd555575e6ad422935fe580aad7**. Both backends passed all-target and documentation tests on Linux x86_64, Linux ARM64, Windows x86_64 and macOS Intel; quality, audit, WASM and fuzz passed too. macOS jobs **134007580167 / 134007580178** confirm **104 / 105 tests respectively, plus one doctest each**, with no failures or ignored tests. [The final snapshot](evidence/ci-final-validation.json) preserves outcomes, steps and log digests. The earlier ARM64 runner acquisition failure remains unverified macOS ARM64 coverage. Library CI results do not cover NazoAuth's separate dependency gate or integration CI.

## Independent vectors and negative tests

The committed W3C fixture preserves original bytes from the Level 3 Recommendation dated 2026-08-25, section 16, with source URL and document digest. The official-vector suite evaluates **all 15 source cases**. The **six** within the declared format/algorithm/origin scope must register and authenticate; unsupported formats/algorithms and cross-origin cases must reject. Each supported assertion also rejects a corrupted signature.

Supported cases include none ES256, packed self ES256, a 1,023-byte credential ID, packed x5c ES256, packed x5c with an Ed25519 credential, and FIDO U2F. These signatures were not regenerated by this implementation. An independent literal RFC 8032 section 7.1 TEST 1 verifies an Ed25519 signature and rejects changed message bytes.

Locally generated real ES256 and Ed25519 signatures separately exercise positive and negative registration/authentication paths. Tests cover invalid DER/scalars, changed messages/signatures, algorithm/curve confusion, weak/noncanonical Ed25519 keys, and ordinary Ed25519 rather than an accidental prehashed variant. Native AWS-LC additionally checks agreement with the RustCrypto ES256 acceptance boundary.

The regression inventory includes:

- Exact challenge/type/origin checks; crossOrigin/topOrigin policy; BOM parsing with hashing of original bytes; duplicate security JSON fields.
- Strict and compatibility Base64; length limits before/after decoding; exact response/attested credential IDs and registration exclusions, including distinct `CredentialExcluded` and higher-priority `CredentialIdMismatch` errors.
- UP/UV required/preferred behavior; unknown historical UV; immutable known BE; BS implies BE; AT/ED framing and complete extension parsing.
- Zero/future/expired state, exact RP/policy context binding, account handles, username-first and discoverable credentials, wrong-account rejection.
- CBOR duplicate keys, truncation, overflow, trailing data, nesting/item limits, canonical new keys and the bounded legacy-COSE compatibility path.
- Packed/self/U2F signatures, certificate profile and curve rules, x5c bounds, duplicate X.509 extensions, AAGUID consistency and explicit untrusted evidence.
- Counter anomalies, old credential JSON, SQLite lazy migration/CAS, and concurrent registration insertion checks in examples.

### Property testing and fuzzing

**Nine property tests** run in the ordinary suite. They exercise arbitrary binary inputs, valid-key round trips, prefix consumption, malformed metadata, strict Ed25519 real signatures, and equivalence of the optimized canonical-key predicate to the previous decompress/recompress predicate. The last property uses **2,048 cases**, supplemented by explicit noncanonical and small-order cases. This is bounded testing, not an exhaustive proof.

The public-API fuzz harness has eight mutation modes and five independently signed fixture families. It preserves valid surrounding state and refreshes timestamps each iteration, so mutations reach intended binary, JSON, signature and account-binding paths instead of always failing on unrelated TTL or credential identity checks. The corpus includes original W3C bytes and malformed boundary cases.

The earlier fa0f0c implementation hosted CI completed:

| Backend | Requested duration | Observed executions | Outcome |
|---|---:|---:|---|
| RustCrypto | 60 seconds | **815,795** in 61 seconds | PASS, process exit 0. |
| Native AWS-LC 1.19.0 | 60 seconds | **995,046** in 61 seconds | PASS, process exit 0. |

The final b3ecfa4 run repeated both campaigns successfully, without the local
leak-detection override. [Its log evidence](evidence/ci-final-validation.json)
preserves these distinct results:

| Backend | Requested duration | Observed executions | Outcome |
|---|---:|---:|---|
| RustCrypto | 60 seconds | **1,321,531** in 61 seconds | PASS, successful CI step. |
| Native AWS-LC 1.19.0 | 60 seconds | **1,634,909** in 61 seconds | PASS, successful CI step. |

An earlier local 120-second campaign executed **341,464** inputs but exited 1 during LeakSanitizer teardown because the managed environment does not support its required ptrace behavior. That run is **not PASS**. Replaying its empty artifact and rerunning with only local ASAN_OPTIONS=detect_leaks=0 succeeded; the latter completed **579,392** inputs in 121 seconds. AddressSanitizer remained enabled. Hosted CI ran both final backends without that local leak-detection override. These campaigns establish neither leak freedom nor absence of every memory or protocol defect.

## Dependency advisory checks

The final four-lock scan uses RustSec database **233155b4025b854c68a4b199c0e32d7fd53291a2**, **1,527 advisories**, updated 2026-11-17T11:14:35+01:00. Raw results: [main](evidence/audit-final-main.json), [perf](evidence/audit-final-perf.json), [fuzz](evidence/audit-final-fuzz.json), [backend comparison](evidence/audit-final-backends.json).

The freshly resolved **baseline development lock**, not a reconstructed historical NazoAuth production lock, reported RUSTSEC-2026-0258 (h2 0.3.27) and RUSTSEC-2026-0459 (libsqlite3-sys 0.30.1). The candidate disables unneeded Rocket example HTTP/2 and updates the SQLite example dependency to rusqlite 0.41.1 / libsqlite3-sys 0.39.1. Both the failed baseline audit and the earlier 1,509-advisory checkpoint remain in docs/evidence.

NazoAuth has a separate full application lock and audit record. Its later scan found three newly added actix-http advisories, corrected by the targeted **3.21.3** patch using the repository's documented urgent-patch exception. Its remaining **chrono 0.4.45 unmaintained advisory** is a cargo-audit warning but an **error in the existing cargo-deny supply-chain gate**. This blocks that integration check and its dependent CI job; it is not a green CI result. The advisory affects every Chrono version and has no upgrade fix. Baseline and candidate have the identical Chrono package and all 17 direct reverse dependencies, including 15 workspace crates, Diesel and the pinned mdoc-rs dependency. Removing it requires a separately validated migration of public DateTime types, timestamp persistence/serialization and dependencies. No advisory is ignored and the gate is not weakened. The integration PR preserves the exact baseline evidence and the blocked outcome.

## Integration and practical limits

The companion NazoAuth PR records exact Git-pinned commands and real PostgreSQL/Valkey service results for legacy JSONB, tenant/account/credential ownership, GETDEL/TTL/replay, metadata/counter CAS, required auditing, UV/MFA eligibility, session creation, remembered MFA, CSRF and HTTP handlers. Application-level claims depend on those integration results; pure library tests cannot establish transactional session or database behavior.

Early local installation and NazoAuth Diesel builds were killed by the memory limit. Unused duplicate toolchains on a memory-backed filesystem were preserved on disk and build parallelism was bounded. Subsequent Diesel compilation succeeded without removing database features. Development compiler/lint errors were corrected before the passing gates; failures are not counted as passes.

No browser interaction or hardware authenticator certification, vendor trust chain validation, FIDO MDS integration, public-suffix validation, formal proof, unbounded fuzz campaign, whole-NazoAuth performance claim or multi-user capacity claim is made. Protocol and integration limitations remain in the matrix and security review even when executable gates pass.

## Reproduction

Install Rust 1.100.0 with rustfmt and clippy, and add wasm32-unknown-unknown and wasm32-wasip1 targets. Run:

    cargo fmt --all -- --check
    cargo check --locked --all-targets --no-default-features
    cargo check --locked --all-targets --all-features
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-targets --no-default-features
    cargo test --locked --all-targets --features aws-lc
    cargo test --locked --doc --no-default-features
    cargo test --locked --doc --features aws-lc
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
    cargo install cargo-audit --version 0.23.0 --locked
    cargo audit --file Cargo.lock
    cargo audit --file perf/Cargo.lock
    cargo audit --file fuzz/Cargo.lock
    cargo audit --file perf/backend-comparison/Cargo.lock
    cargo check --locked --lib --target wasm32-unknown-unknown --no-default-features
    cargo check --locked --lib --target wasm32-unknown-unknown --all-features
    cargo build --locked --release --manifest-path perf/Cargo.toml --target wasm32-wasip1 --all-features
    PERF_ITERATIONS=100 node perf/wasi.mjs perf/target/wasm32-wasip1/release/ceremony-bench.wasm
    rustup toolchain install nightly-2026-11-17 --profile minimal
    cargo +nightly-2026-11-17 install cargo-fuzz --version 0.13.2 --locked
    cargo +nightly-2026-11-17 fuzz run ceremonies -- -max_total_time=60 -rss_limit_mb=1024 -max_len=65540
    cargo +nightly-2026-11-17 fuzz run ceremonies --features aws-lc -- -max_total_time=60 -rss_limit_mb=1024 -max_len=65540

Windows AWS builds additionally need NASM as installed by the workflow. See [fuzz/README.md](../fuzz/README.md) for fixture/mutation details and [performance.md](performance.md) for release measurement commands.
