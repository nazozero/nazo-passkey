# nazo-passkey

[![CI](https://github.com/nazozero/nazo-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/nazozero/nazo-passkey/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license-and-origin)

A synchronous Rust library for WebAuthn registration and authentication. It
creates ceremony options, verifies responses, and returns credential records
and authenticated state updates. Applications supply account storage, sessions,
and transaction policy.

The protocol baseline is [WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
The implementation supports ES256 and Ed25519, preserves compatible Level 1/2
credentials, and runs on native and WebAssembly targets. RustCrypto is the
default; the `aws-lc` feature accelerates native ES256 verification. The library
uses Rust 1.100 and edition 2024, has no database or HTTP dependencies, and
forbids unsafe Rust in its own source.

## Install

The independent package is named `nazo-passkey`, with Rust imports under
`nazo_passkey`. Until its first registry release, use the repository:

```toml
[dependencies]
nazo-passkey = { git = "https://github.com/nazozero/nazo-passkey", branch = "main" }
```

Use an immutable `rev` and commit `Cargo.lock` for a reproducible deployment.
Add `features = ["aws-lc"]` to select native AWS-LC ES256 verification.

## Supported operations

| Area | Behavior |
| --- | --- |
| Keys | ES256 / P-256 (`alg=-7`) and Ed25519 (`alg=-8`), with matching COSE key type, curve, and coordinates |
| Registration | Challenge, origin, RP ID, UP/UV, backup flags, credential key, exclusion list, and attestation verification |
| Authentication | Account and credential binding, signed flags, signature, backup eligibility, and signature counter policy |
| Login | Username-first and discoverable credentials |
| Attestation | `none`, ES256/Ed25519 `packed` self-attestation, and ES256 certificate attestation for `packed` and `fido-u2f` |
| Origins | Exact configured web origin; same-origin ceremonies |
| Extensions | Bounded structural parsing; extension values do not influence authentication decisions |
| Persistence | Serde credential records, including UV history, backup state, and attestation evidence |

Certificate attestation returns `UntrustedCertificate`: the signature and
applicable leaf profile have been checked. Applications can inspect the borrowed
certificate evidence and apply their trust policy before receiving a credential
to persist. The complete feature and responsibility matrix is in
[protocol compliance](docs/protocol-compliance.md).

## Integrate a ceremony

```rust
use nazo_passkey::{RegistrationOptions, Webauthn};

let webauthn = Webauthn::try_new("example.com", "Example", "https://example.com")?
    .require_user_verification(true);

let (options, state) = webauthn.try_start_registration(
    b"opaque-account-handle",
    "alice",
    "Alice",
    &[],
    RegistrationOptions::default(),
)?;
```

Use a stable, opaque account handle of 1–64 bytes. Send `options` to the browser
and retain `state` on the server with the account and session. The examples use
the browser's `PublicKeyCredential.parseCreationOptionsFromJSON()` or
`parseRequestOptionsFromJSON()` and POST the result of `credential.toJSON()`
directly. Deserialize the finish request as `RegistrationResponse` or
`AuthenticationResponse`.

| Operation | Application responsibility |
| --- | --- |
| `try_start_registration` | Authorize enrollment and supply existing credential IDs |
| `finish_registration` | Consume ceremony state once; insert the complete record under a credential-ID uniqueness constraint within the RP |
| `finish_registration_with_attestation` | Apply the application's attestation trust policy before inserting the returned record |
| `start_authentication_with_creds_for_user` | Load the intended account's credentials and bind its handle |
| `finish_authentication` | Select the stored credential within that account; commit the verified update before creating a session |
| `finish_discoverable_authentication` | Resolve the returned handle within the RP and supply its expected account binding |

Each challenge contains 32 random bytes. Pending states bind the RP, origin,
and validation policy and expire after at most 300 seconds. A shorter server
TTL can further restrict their lifetime. Consume state atomically, for example
with a transactional delete or `GETDEL`.

Authentication returns the new signature counter and signed backup flags. Save
these with an account-scoped compare-and-swap before issuing a session. The
counter policy accepts zero-only counters and rejects other non-increasing
values; concurrent assertions can therefore require a retry.

### Discoverable credentials

The final registration argument is `RegistrationOptions`. Its `resident_key`
field accepts `ResidentKeyRequirement::Required`, `Preferred`, or `Discouraged`.
The library defaults to `Required` so newly enrolled passkeys support
username-less login. Select `Preferred` when enrollment may fall back to a
non-discoverable credential, or `Discouraged` to prefer that storage mode.
`requireResidentKey` is derived from `resident_key` when serializing options.

Resident-key selection controls credential creation in the browser. The
registration response carries no signed discoverability flag. Server-side
verification separately enforces UP, configured UV, and account binding;
discoverable assertions require the credential's owning account handle.

### User verification

`AuthSuccess::user_verified` reports the signed UV flag.
`user_verification_eligible` also requires established UV history in the stored
credential. Use the latter when counting user verification as an additional
factor. Registration records its observed UV value; older records retain
unknown history until the application establishes it through an independently
authorized flow.

Username-first authentication accepts an absent `userHandle` for older
non-discoverable credentials. A supplied handle must match the expected account.
Discoverable authentication requires a handle and account binding.

### Attestation policy

`RegistrationOptions::default()` requests `AttestationConveyancePreference::None`.
Ordinary registration uses `finish_registration` and requires no PKI setup.
Select `Direct` only when applying a real attestation trust policy. A browser
may still return `none` or self-attestation; the application decides whether
to accept that evidence.

Use `finish_registration_with_attestation(&state, &response, check_attestation)`
to supply a callback accepting `VerifiedAttestation<'_>` and returning
`nazo_passkey::Result<()>`. It runs after all protocol and statement checks,
before the credential is constructed. Return `Error::AttestationRejected` to
reject enrollment.

The view contains the evidence kind, format, AAGUID, and original leaf-first
DER certificate slices, borrowed for the callback's duration. None and
self-attestation have an empty chain. The application verifies trust anchors,
chain signatures, certificate validity, revocation, and metadata as required
by its policy. The persisted `UntrustedCertificate` value records the library's
checks; store any application trust decision separately.

The `packed` statement signs the AAGUID in `authData`; `none` and `fido-u2f`
leave that field unauthenticated, even when the application trusts the U2F
certificate.

### Parsing and borrowing

CBOR fields and valid UTF-8 client data borrow the decoded response buffers.
Fixed-size signatures, keys, and hashes use bounded storage. Ed25519 hashes the
two transcript parts directly through dalek's multipart verification API.
Base64 decoding, owned credential records, and ceremony state allocate storage.
The [performance record](docs/performance.md) retains measurements for its
recorded revisions.

The credential envelope and signed client-data challenge require canonical,
unpadded base64url. The finish request parser verifies `type`, `id`, and
`rawId`, then shares the decoded ID and optional user handle with account
lookup and verification.
Client-data decoding follows WebAuthn's UTF-8 rules; signature verification
hashes the original bytes, including a leading BOM when present.

| Decoded input | Bound |
| --- | ---: |
| Client data | 8 KiB |
| Attestation object | 64 KiB |
| Authenticator data | 16 KiB |
| Credential ID / account handle | 1–1,023 / 1–64 bytes |
| Signature | 80 bytes |
| CBOR container / depth / item budget | 64 / 12 / 2,048 |
| Certificate chain | 8 certificates, 16 KiB per certificate, within the attestation-object bound |

The application limits HTTP bodies before deserialization and sets account
quotas, enrollment authorization, CSRF protection, and request throttling.

## Examples and development

| Example | Purpose |
| --- | --- |
| `axum_server`, `rocket_server` | Registration and username-first login |
| `axum_passwordless` | Discoverable login |
| `rocket_credential_manager` | Session-authorized credential management |
| `axum_sqlite` | Credential persistence, migration, and atomic updates |

```sh
cargo run --example axum_server
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --all-targets --features aws-lc
cargo test --locked --doc
cargo package --locked
```

Native AWS-LC builds require its [C/C++ build toolchain](https://aws.github.io/aws-lc-rs/requirements/).
WebAssembly uses RustCrypto under both feature settings; browser targets obtain
randomness through Web Crypto. The examples run locally at `http://localhost:3000`.

See [migration](docs/migration.md), [protocol compliance](docs/protocol-compliance.md),
[security review](docs/security-review.md), and [validation](docs/validation.md).

## License and origin

Maintained by [bymoye](https://github.com/bymoye), `s3moye@gmail.com`, in NazoZero.
This independently maintained rewrite is based on Sriram's
[`marirs/passkey-auth-rs`](https://github.com/marirs/passkey-auth-rs).
[Upstream provenance](UPSTREAM_PROVENANCE.md) records the retained history.

Licensed under [MIT](LICENSE) or [Apache-2.0](APACHE-LICENSE), at your option.
