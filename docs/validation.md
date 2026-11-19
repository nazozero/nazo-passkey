# Validation

## 0.3 protocol boundary update — 2026-11-19

Baseline: `092f672175e5facdd24062536df34a75c6145f98`. The 0.3 change separates
authenticated counter evidence from RP risk policy and supplies the expected
and new counter / backup values for atomic application updates. Modified
certificate-profile fixtures now carry independently verified issuer signatures.

Executed locally with Rust 1.100.0 on Linux x86-64:

| Gate | Outcome |
| --- | --- |
| `cargo test --locked --lib --tests --no-default-features` | 128 tests passed |
| `cargo test --locked --all-targets --all-features` | 129 library/integration and four example tests passed; benchmark smoke completed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --locked --doc --all-features` | One doctest passed |
| `cargo fmt --all -- --check` | Passed |
| `wasm32-unknown-unknown` library, all features | Compiled |
| `wasm32-wasip1` portable benchmark, all features | Release build and ten cases at 100 iterations completed |

The existing W3C vectors and independent strict Ed25519 oracle remain in the
native suites. The new counter regression checks authenticated outcomes and
rejects invalid signatures for every tested counter pair. Hosted CI must run
the new head for the other platforms, browser and fuzz gates; the earlier
results below do not substitute for those runs.

A short native comparison used the existing performance driver, identical
release dependencies, six alternating rounds of 1,500 iterations and one CPU.
Registration retained seven allocations (485 bytes for ES256, 414 for Ed25519);
assertion verification retained three allocations / 203 bytes. The independent
glibc trace matched these counts and bytes. Concurrent workspace builds make
the timing sample unsuitable for a speedup claim.

## Historical 0.2 validation — 2026-11-18

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

Native macOS ARM64 and physical-authenticator interoperability require separate
validation. The [protocol matrix](protocol-compliance.md) defines the supported
algorithms, formats, and application responsibilities.

## Browser and authenticator interoperability

The `browser-interop` CI job builds the two Axum demos on Ubuntu 24.04 and runs
`interop/browser.test.mjs` against Playwright's pinned Chromium build. Each
fixture starts a fresh demo and browser context with a CDP virtual CTAP2.1
authenticator. The tests give server options to
`PublicKeyCredential.parseCreationOptionsFromJSON()` and
`parseRequestOptionsFromJSON()`, call the browser's credential APIs, and POST
`credential.toJSON()` directly to the finish routes.
The test output records the browser product, version and revision, OS, Node and
Playwright versions, authenticator options, and observed ceremony fields.
[WebAuthn JSON APIs](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-parsecreationoptionsfromjson),
[Chromium virtual authenticator protocol](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/WebAuthn.pdl)

| Fixture | Verified by the suite |
| --- | --- |
| `axum_server`, virtual USB without resident key or UV | Username-first allow-list login, UV preferred, `none` attestation, BE/BS clear and signature counter increases. Reject same counter, wrong account, modified RP ID hash, wrong signature and a genuine assertion made at a different origin. |
| `axum_passwordless`, virtual internal with resident key and UV | Empty allow-list login with the registered handle, `none` attestation, BE set and BS changes from clear to set. Reject a stale challenge, repeat finish and UV-clear assertion under required UV. Confirm sign-in with `/whoami`. |

Run from the repository root with Node.js 24, the pinned Rust toolchain, and
port 3000 free. On Linux, add `--with-deps` to the browser install command if
the Chromium system dependencies are missing.

```sh
cargo build --locked --example axum_server --example axum_passwordless
npm --prefix interop ci
npm --prefix interop exec --no -- playwright install --no-shell chromium
npm --prefix interop test
```

Routine CI checks expiry with the Rust test `expired_ceremony_rejected`, which
backdates the ceremony state. To also exercise the real five-minute TTL through
the browser, set `WEBAUTHN_TEST_EXPIRY=1` for the test run and allow about six
minutes. The browser fixture submits the unchanged assertion after 302 seconds
and expects HTTP 401 for expired state.

```sh
WEBAUTHN_TEST_EXPIRY=1 npm --prefix interop test
```

```powershell
$env:WEBAUTHN_TEST_EXPIRY = '1'
npm --prefix interop test
Remove-Item Env:WEBAUTHN_TEST_EXPIRY
```

Challenges and credentials are generated anew by each run. The lockfiles and
fixtures reproduce the test inputs and expected behavior. This validation has
no FIDO-issued certification status.

### Executed browser run

On 2026-11-18, all three browser fixtures passed locally on Windows 11 Pro x64
(build 10.0.26200) with Chrome for Testing 159.0.8154.6
(revision `98a2592026af8d673b9fa83b626ac68bdf4ae78a`, CDP 1.3),
Playwright 1.65.1, Node.js 24.16.0, and Rust 1.100.0.

| Virtual CTAP2.1 authenticator | Observed result |
| --- | --- |
| USB without resident-key or UV support | `none` attestation, UV/BE/BS clear, counter 1 at registration and 2 then 3 at sign-in. Same counter, wrong account, modified RP ID hash, wrong signature and alternate origin each returned HTTP 401. |
| Internal with resident-key support and UV | `none` attestation, UV/BE set, BS clear at registration and set at sign-in. The stale challenge and missing UV returned HTTP 401. Resubmission returned HTTP 400. The fresh assertion signed in as the registered account, confirmed by `/whoami`. |
| USB with expired state | The unchanged browser assertion returned HTTP 401 after the state had aged for 302 seconds. |

### Manual browser and device matrix

Start one example at a time from the repo root with
`cargo run --locked --example axum_server` or
`cargo run --locked --example axum_passwordless`. Open
`http://localhost:3000` in a browser window with the WebAuthn JSON APIs. Use a
disposable browser profile or test account where supported, choose the
authenticator named in the row, and remove the test credentials afterward.
The demos store registrations in memory. Keep the same demo running from
registration through sign-in.

| Target | Procedure and expected result | Physical result |
| --- | --- | --- |
| Safari on macOS | In the passwordless demo, register with Safari's platform passkey provider, then sign in by selecting the registered account. Expect the correct account and `UV=true`. Dismiss a subsequent browser prompt and confirm the demo reports a credential error. | Pending |
| Firefox desktop | In the username-first demo, register and authenticate twice with a supported authenticator. In the passwordless demo, register a discoverable credential and select it at sign-in. Record the OS authenticator or external key used and any unavailable operation. | Pending |
| Platform passkey | In the passwordless demo, use an enrolled platform authenticator, such as Windows Hello or Touch ID. Complete local verification at registration and at sign-in. Expect the correct account and `UV=true`. Record the provider and verification method. | Pending |
| Synced passkey | Use two desktops signed in to the same sync provider. Run the passwordless demo on the first desktop. On the second, use `ssh -NT -L 127.0.0.1:3000:127.0.0.1:3000 user@first-desktop` to reach that same process at `http://localhost:3000`. Register on the first desktop, wait for the provider to sync, then choose the synced credential on the second. Expect the registered account and `UV=true`. Record the provider and both environments. | Pending |
| Roaming security key | In the username-first demo, select the physical key and register and authenticate twice. Record observed counters, including zero if the key does not implement a counter. For a CTAP2 key supporting resident credentials and a PIN or biometric UV, repeat in the passwordless demo and expect account selection and `UV=true`. Record model, firmware and transport. | Pending |

For each execution, record date, source revision, browser full version, OS
version/build, device and authenticator model/provider, available firmware or
provider version, transport, ceremony, and pass/fail with any browser or HTTP
error. Record UV and counters from the demo output where available. To inspect
assertion BE/BS in browser developer tools, base64url-decode
`authenticatorData` from the `/authenticate/finish` request and apply masks
`0x08` and `0x10` to its flags byte at offset 32. Mark unavailable observations
as such and retain only the observations, without credential payloads.
[Authenticator data flags](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)

## Performance evidence

The benchmark run during `--all-targets` is a smoke check with ten operations
per case. The [historical performance report](performance.md) retains the
full six-round comparison and its original source / lockfile identities.
This review does not assign those historical latency measurements to the new
dependency graph.

Earlier validation remains in
[the 8493867 record](https://github.com/nazozero/nazo-passkey/blob/main/docs/validation-checkpoint-8493867.md)
and [the 8260480 record](https://github.com/nazozero/nazo-passkey/blob/main/docs/validation-checkpoint-8260480.md).
