# passkey-auth

[![CI](https://github.com/nazozero/passkey-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/nazozero/passkey-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#maintainers-and-license)

A synchronous Rust WebAuthn relying party library for **ES256 / P-256** and
**Ed25519** passkeys. It creates ceremony options, verifies browser responses,
and returns the credential facts an application must persist. Applications own
accounts, one-time ceremony storage, transactions, sessions, and MFA policy.

This is the NazoZero-maintained fork used by
[NazoAuth](https://github.com/nazozero/NazoAuth). It targets **Rust 1.100.0,
edition 2024**. The default cryptographic implementation is RustCrypto;
optional native AWS-LC verification is available for ES256. The library has no
network or database dependencies and forbids unsafe Rust in its own code.

The protocol baseline is
[WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/), with
compatibility for the supported Level 1/2 credential and browser behavior.
The [requirements matrix](docs/protocol-compliance.md) states each checked
requirement, its scope, and its evidence. This is not a claim of FIDO
certification or support for every optional WebAuthn feature.

## Supported behavior

| Area | Contract |
| --- | --- |
| Credential keys | ES256: `alg=-7`, EC2, P-256. Ed25519: `alg=-8`, OKP, Ed25519. Key type, algorithm, curve, coordinate encoding, and point validity must agree. |
| Registration | Validate ceremony state, client type/challenge/origin, RP ID hash, UP/UV, credential ID and exclusions, COSE key, and attestation. |
| Authentication | Validate account/credential binding, ceremony state, client data, signed flags, backup eligibility, signature, and counter policy. |
| User verification | `required` rejects missing signed UV. `preferred` permits a valid UP-only assertion. Signed UV and eligibility to count UV as another factor are distinct results. |
| Login modes | Username-first login, including optional legacy `userHandle`; discoverable login with mandatory account-handle binding. |
| Attestation | `none`, `packed` self-attestation, and ES256 certificate signatures for `packed` / `fido-u2f`. |
| Trust result | Explicit `Unknown`, `None`, `SelfAttestation`, or `UntrustedCertificate`. No result claims a trusted manufacturer. |
| Origins | Exact configured origin. Same-origin ceremonies only; `crossOrigin=true` and any present `topOrigin` reject. |
| Extensions | Bounded structural validation. No PRF, credProtect, credProps, AppID, or unknown output supplies authentication or MFA evidence. |
| Stored credentials | Existing 0.1.3 credential JSON remains readable; absent security history stays unknown. No passkey re-registration is required. |

RSA, other curves, Ed448, ECDAA, TPM, Android Key/SafetyNet, Apple, compound or
enterprise attestation, related-origin discovery, and conditional registration
without UP are outside this implementation's scope. Supporting the `fido-u2f`
attestation format does not enable the AppID extension.

**A verified attestation signature is not verified manufacturer trust.** The
library checks the applicable certificate profile and statement signature. It
does not verify the certificate chain to trusted roots, certificate lifetime,
revocation, or device provenance. AAGUID and attachment hints do not prove
hardware protection. An application needing approved authenticator models must
add an explicit trust policy before admitting the credential.

## Installation

The 0.2.0 migration is currently reviewed on this Git branch:

```toml
[dependencies]
passkey-auth = { git = "https://github.com/nazozero/passkey-auth-rs", branch = "nazoauth/webauthn-protocol-calibration-20261117" }
```

For production, replace `branch` with the reviewed immutable `rev` and commit
`Cargo.lock`. The older crates.io `0.1.3` package does not contain these changes.
Add `features = ["aws-lc"]` when selecting the native ES256 backend below.

## Ceremony integration

Configure the exact serialized origin, without a path or trailing slash:

```rust
use passkey_auth::Webauthn;

let webauthn = Webauthn::try_new("example.com", "Example", "https://example.com")?
    .strict_base64(true)
    .require_user_verification(true);
```

Use an opaque, stable account handle of 1–64 bytes. Generate and persist it when
creating the account; a username or email address is not an appropriate handle.

| Stage | Library operation | Application operation |
| --- | --- | --- |
| Register begin | `try_start_registration` | Authorize enrollment; obtain existing credential IDs; retain the returned state with tenant, account, session, and TTL. |
| Register finish | `finish_registration` | Atomically consume the retained state; persist the whole returned credential under an atomic uniqueness constraint. |
| Username-first begin | `start_authentication_with_creds_for_user` | Resolve the account in the tenant and fetch its credentials. |
| Username-first finish | `finish_authentication` | Consume state once; load the selected credential through the expected account; commit the verified update with CAS before session success. |
| Discoverable finish | `finish_discoverable_authentication` | Resolve the returned handle within the tenant; load that account's credential; provide its expected handle explicitly. |

An empty authentication allow list enables discoverable login. A returned
`userHandle` must match the expected account. Username-first authentication
allows an omitted handle by default for older non-discoverable authenticators;
`.require_user_handle(true)` makes its presence a local requirement.

Wire structs are the library's **flat JSON adapter**, not the browser's nested
`PublicKeyCredential.toJSON()` object. Extract `credential.response` fields and
encode their bytes as unpadded base64url. The examples include browser adapters.
Strict Base64 is opt-in for compatibility; controlled production clients should
enable it. Strict mode accepts only the URL-safe alphabet without padding.

### State and transaction boundaries

Each challenge contains 32 bytes from the platform CSPRNG through `getrandom`.
There is no weak randomness fallback. Pending states bind the RP, exact origin,
and validation policy, reject missing/zero/future issue times, and expire after
at most 300 seconds. The application's shorter TTL still applies.

State must remain server-owned and be consumed atomically once, for example
with Valkey `GETDEL`. A context hash or a signed cookie does not provide
one-time consumption. Do not accept client-supplied serialized ceremony state.

Authentication success is a verification result. Persist `new_counter`, signed
`backup_eligible` / `backup_state`, and any separately authorized UV-history
change in the same account-scoped transaction. Compare the previous counter and
metadata; a CAS conflict must not issue a successful session. Zero-only counters
are permitted; otherwise the library rejects non-increasing counters. This
conservative policy can reject a reordered concurrent assertion and is not
proof that a credential was cloned.

### UV and MFA

`AuthSuccess::user_verified` is the UV flag authenticated by the signature.
`user_verification_eligible` is true only when that flag is set **and** the
stored credential has `uv_initialized == Some(true)`.

At registration, the verifier records the observed UV value. An older record
without UV history remains `None`; a later UV assertion cannot silently promote
it. An application may establish that history through an explicit flow using
another suitable factor. The assertion performing the promotion must still be
evaluated against the old history. Use `user_verification_eligible` for MFA
decisions, together with the application's AMR and session policy.

Enrollment/deletion authorization, CSRF, account recovery, rate limits, and
remembered-MFA evidence belong to the application. See the
[NazoAuth integration contract and evidence](docs/nazo-integration.md).

## Credential migration from 0.1.3

Persist `PasskeyCredential` as a complete serde record. Existing byte-array
representations of credential IDs, COSE public keys, AAGUIDs, transports, and
counters are retained. The following metadata is added:

| Field | Missing from an existing record | New registration |
| --- | --- | --- |
| `user_handle` | `None`; use the application's account binding | Ceremony's account handle |
| `uv_initialized` | `None`, meaning unknown | Registration's verified UV flag |
| `backup_eligible`, `backup_state` | `None`, meaning unknown | Registration's verified BE/BS flags |
| `attestation` | `Unknown` | `None`, `SelfAttestation`, or `UntrustedCertificate` |

The stored-key reader tolerates historical COSE map ordering, integer widths,
and harmless optional metadata. A stored `key_ops` array, when present, must
permit signature verification; `kid` and `Base IV` must have their COSE byte-string
types. Conflicting usage restrictions, duplicate labels, private key material,
malformed framing, and algorithm/curve confusion reject. New wire keys use the
WebAuthn/CTAP2 canonical profile. Conforming original key bytes need no migration;
malformed historical keys are not grandfathered into successful verification.

Existing **pending ceremonies** lack the context binding and must restart after
upgrade. Existing credentials remain usable. New public Rust struct fields and
error variants require source updates, which is why the crate version is 0.2.0.
The convenience `new` and `start_registration` methods panic on invalid
configuration/input; prefer their `try_` equivalents at fallible boundaries.

## Backends, borrowing, and resource limits

| Target / feature | Credential ES256 | Ed25519 | Certificate attestation |
| --- | --- | --- | --- |
| Native default | RustCrypto | dalek, strict acceptance policy | RustCrypto |
| Native `aws-lc` | AWS-LC | dalek, same acceptance policy | RustCrypto |
| WASM, either feature setting | RustCrypto | dalek, same acceptance policy | RustCrypto |

Backend selection is compile-time. It does not alter credential serialization,
signature encoding, attestation trust, or MFA semantics. Native AWS-LC builds
need its [C/C++ toolchain requirements](https://aws.github.io/aws-lc-rs/requirements/);
Windows x86-64 MSVC also needs NASM. JavaScript-hosted `wasm32-unknown-unknown`
uses Web Crypto and `web-time`; WASI uses its system interfaces.

Ed25519 verifies the ordinary message through dalek's multipart API, avoiding
transcript concatenation. Canonical encoding and small-order-point checks retain
the previous strict acceptance policy; independent vectors and differential
tests compare that policy with dalek's strict verifier. Do not enable dalek's
`legacy_compatibility` feature in the application's dependency graph: it relaxes
the scalar bound in both its ordinary and strict verification APIs.

CBOR and client-data parsing borrow the decoded input. Fixed-size key material,
hashes, and short binary fields use bounded stack storage where useful. Base64
decoding and owned results still require storage: this is not a claim that a
whole ceremony allocates nothing. The [performance report](docs/performance.md)
provides actual full-ceremony latency, allocations, CPU, artifact size, native /
WASI results, and any remaining regressions. No speed claim follows from a
backend or dependency name alone.

| Input | Library resource policy |
| --- | ---: |
| Decoded `clientDataJSON` | 8 KiB |
| Attestation object / CBOR input | 64 KiB |
| `authenticatorData` | 16 KiB |
| Credential ID / account handle | 1–1,023 / 1–64 bytes |
| Signature | 80 bytes |
| Transport hints | 16 strings of at most 32 bytes |
| CBOR container / depth / total items | 64 entries / 12 / 2,048 |
| Attestation chain | 8 certificates, at most 16 KiB each, within the outer bound |

These are RP resource policies, not universal WebAuthn limits. Unsupported
extension value structures and certificate algorithms are documented in the
matrix. HTTP body size must be bounded before deserializing the outer response.
Credential allow/exclude lists grow with the account's stored credentials;
applications need appropriate account quotas and request controls.

## Examples and development

The following local examples run at <http://localhost:3000>:

| Example | Demonstrates |
| --- | --- |
| [`axum_server`](examples/axum_server.rs), [`rocket_server`](examples/rocket_server.rs) | Registration and username-first authentication |
| [`axum_passwordless`](examples/axum_passwordless.rs) | Discoverable login and multiple accounts |
| [`rocket_credential_manager`](examples/rocket_credential_manager.rs) | Session-authorized listing, addition, and deletion |
| [`axum_sqlite`](examples/axum_sqlite.rs) | Full credential persistence, legacy-row migration, and CAS |

```sh
cargo run --example axum_server
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
cargo audit
```

Run the verification commands with `--features aws-lc` as well when deploying
that feature. The examples use demonstration account/session stores and do not
provide a complete production CSRF, rate-limit, or recovery layer.

The [validation record](docs/validation.md) identifies the exact executed
revisions, commands, feature/target combinations, independent vectors, property
tests, fuzz runs, and failures. The [security review](docs/security-review.md)
explains findings and their fixes. A test's presence or a CI configuration entry
does not mean that it ran successfully.

## Maintainers and license

Maintained by [bymoye](https://github.com/bymoye) in
[NazoZero](https://github.com/nazozero). Derived from
[Sriram's `marirs/passkey-auth-rs`](https://github.com/marirs/passkey-auth-rs);
the original author's attribution and upstream license texts are retained.
The [fork record](NAZOAUTH_PATCH.md) identifies the inherited production baseline.

Licensed under either the [Apache License 2.0](APACHE-LICENSE) or the
[MIT License](LICENSE), at your option.
