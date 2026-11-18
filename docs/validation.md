# Validation — 2026-11-18

Package: **nazo-passkey 0.2.0**. Review input: PR #1 at
`4652c67b1bdea01163296cfd5735d4b0bebeac18`. This review adds three ceremony
corrections, current dependencies, an independent package identity, and revised
public documentation. The protocol and binary paths received separate reviews.

## Executed local gates

Toolchain: Rust 1.100.0, Linux x86-64. Native tests use the updated lockfile.

| Command / gate | Outcome |
| --- | --- |
| `cargo test --locked --offline --all-targets` | 128 tests passed, zero failures; benchmark smoke program also completed |
| `cargo test --locked --offline --all-targets --features aws-lc` | 129 tests passed, zero failures; benchmark smoke program also completed |
| `cargo test --locked --offline --doc --all-features` | One documentation test passed |
| `cargo clippy --locked --offline --all-targets --all-features -- -D warnings` | Passed |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline --no-deps --all-features` | Passed |
| Browser WASM library check, no default features | Passed |
| Browser WASM library check, all features | Passed |
| `cargo check --locked --offline --manifest-path perf/backend-comparison/Cargo.toml` | Passed |
| `python -m unittest discover -s perf -p 'test_*.py' -v` | 22 tests passed |
| `cargo package --locked --allow-dirty --offline` | Archive creation and compilation from extracted package passed |

The native totals comprise 68 / 69 library tests, 24 attestation tests, eight
binary regression tests, 23 ceremony tests, one official-vector corpus test,
and four example persistence / account-race tests. All five examples compiled.
The Ed25519 unit suite includes 914 independent C2SP/CCTV vectors, every message
split, strict-oracle comparisons, and point/scalar boundary properties.

The review's new regressions cover canonical signed challenges, WebAuthn UTF-8
replacement decoding, signatures over exact original client-data bytes, and
preidentified accounts with an empty allow list. Existing malformed-certificate
tests were preserved through the x509-cert 0.3 migration.

## Dependency checks

All direct dependencies were checked against their latest stable published
versions. Four active lockfiles were refreshed. The root runtime and tests now
share x509-cert 0.3; older Base64, Rand, Axum, tower-http, and rusqlite direct
dependencies were upgraded. The backend comparison uses dalek 3.

| Lockfile | Packages audited | Vulnerabilities | Warnings |
| --- | ---: | ---: | ---: |
| Root | 302 | 0 | 0 |
| Performance | 131 | 0 | 0 |
| Backend comparison | 72 | 0 | 0 |
| Fuzz | 126 | 0 | 0 |

RustSec database commit: `233155b4025b854c68a4b199c0e32d7fd53291a2`.
The [dependency inventory](https://github.com/nazozero/nazo-passkey/blob/main/docs/evidence/merge-review-20261118/dependencies.json)
records versions and source links. Transitive versions follow their upstream
compatibility constraints.

## Hosted merge gates

[PR #1](https://github.com/nazozero/nazo-passkey/pull/1) targets `main`.
The [CI workflow](https://github.com/nazozero/nazo-passkey/actions/workflows/ci.yml)
checks both backends on Linux x86-64 / ARM64, Windows x86-64, and macOS Intel,
plus formatting, Clippy, rustdoc, package verification, browser WASM compilation,
WASI execution, all four dependency audits, and both bounded fuzz campaigns.
The final PR head must pass these jobs before merge. Run results identify the
tested commit; workflow configuration describes the required coverage.

macOS ARM64 and physical-authenticator / browser interoperability require
separate validation. The [protocol matrix](protocol-compliance.md) defines the
supported algorithms, formats, and application responsibilities.

## Performance evidence

The benchmark run during `--all-targets` is a smoke check with ten operations
per case. The [historical performance report](performance.md) retains the
full six-round comparison and its original source / lockfile identities.
This review does not assign those historical latency measurements to the new
dependency graph.

Earlier validation remains in
[the 8493867 record](https://github.com/nazozero/nazo-passkey/blob/main/docs/validation-checkpoint-8493867.md)
and [the 8260480 record](https://github.com/nazozero/nazo-passkey/blob/main/docs/validation-checkpoint-8260480.md).
