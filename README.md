# passkey-auth

[![CI](https://github.com/nazozero/passkey-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/nazozero/passkey-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/passkey-auth.svg)](#license)

A synchronous WebAuthn relying party verifier for **ES256 / P-256** and
**Ed25519** credentials, with a pure Rust default and optional native ES256
acceleration. It verifies browser registration and authentication
responses and returns the credential state an application must persist. It does
not own accounts, sessions, a database, or a challenge store.

This fork is used by [NazoAuth](https://github.com/nazozero/NazoAuth). This work
starts from its pinned revision
`d59b317998e56f4a16a69133d7a854c5c34f795b` on `nazoauth/patched-rustcrypto`,
not the upstream repository's older `main` branch. The revised crate is **0.2.0** because public Rust struct fields changed.
The migration from the pinned 0.1.3 revision keeps existing credential JSON and
signing keys usable; users do not need to register their passkeys again.
The implementation and consumer changes are reviewed in
[passkey-auth-rs PR #1](https://github.com/nazozero/passkey-auth-rs/pull/1) and
[NazoAuth PR #287](https://github.com/nazozero/NazoAuth/pull/287).

**Rust 1.100.0 / edition 2024** is the target toolchain. The default uses
RustCrypto `p256`, `ed25519-dalek`, and `sha2`. The optional `aws-lc` feature
selects `aws-lc-rs` for native credential ES256 verification; the manifest permits
compatible versions from 1.18.2 and the final lockfiles select **1.19.0**. Ed25519
always uses dalek's strict verifier. There is no locally implemented
cryptographic primitive. See
[validation](docs/validation.md) for the exact builds actually run and
[performance](docs/performance.md) for measured results and their limits.
The [NazoAuth integration record](docs/nazo-integration.md) traces legacy JSONB,
tenant/account binding, live PostgreSQL/Valkey tests, UV/MFA decisions and the
remaining application dependency gate to their original execution evidence.

Challenges take 32 bytes directly from the platform CSPRNG through
`getrandom 0.4`: operating-system randomness on native targets, WASI randomness on WASI,
and Web Crypto on browser/worker WASM. Failure to obtain secure randomness
panics; there is no deterministic or weaker fallback. The production library
does not retain the former `rand 0.8` / ChaCha generator dependency. P-256 enables
`ecdsa`, `std`, and `precomputed-tables` explicitly; PEM support is confined to
development builds that construct test certificates.

For `wasm32-unknown-unknown`, the crate explicitly enables `getrandom`'s
`wasm_js` feature. This target already uses `wasm-bindgen` through `web-time`,
matching the exception in the [getrandom library guidance](https://docs.rs/getrandom/0.4.3/getrandom/#webassembly-support).
It is a JavaScript-hosted target contract, not support for arbitrary non-web
WASM hosts. WASI uses its separate system interface.

## Scope and security boundary

The primary protocol reference is the
[WebAuthn Level 3 Recommendation of 25 August 2026](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
The [compliance matrix](docs/protocol-compliance.md) records Level 1/2 compatibility,
applicable RP requirements, implementation locations, and regression evidence.
The [security review](docs/security-review.md) describes the baseline defects,
changes, and remaining application responsibilities. This is an implementation
review, not FIDO certification or a claim that every optional WebAuthn feature is
implemented.

| Capability | Behavior |
|---|---|
| Credential signatures | ES256 (`alg=-7`, EC2, P-256) and Ed25519 (`alg=-8`, OKP, Ed25519); algorithm, key type, curve, coordinates, and point validity are checked |
| Registration | Challenge, type, exact origin, RP ID hash, UP, requested UV, returned credential ID, excluded IDs, credential key, and attestation statement are validated |
| Authentication | Account / credential binding, challenge, type, exact origin, RP ID hash, UP, requested UV, backup flags, signature, and counter policy are validated |
| Embedded origins | `crossOrigin=true` and any present `topOrigin` are rejected; this implementation is for same-origin ceremonies |
| Attestation | `none`, `packed` self-attestation with either supported credential algorithm, and ES256 certificate signatures for `packed` / `fido-u2f` |
| Attestation trust | Certificate signatures and the applicable certificate structure are checked; trusted roots, chain signatures, time validity, revocation, and manufacturer identity are **not verified** |
| State | Server-created random challenges, expiry checks, and RP / origin / policy binding; the caller provides atomic one-time state consumption |
| Persistence | Existing credential JSON remains readable; new optional fields preserve known account, UV, and backup metadata without inventing missing history |
| Extensions | Authenticator extensions receive bounded structural validation; no PRF, credProtect, credProps, AppID, or other extension output is used as authentication evidence |

RSA, other EC curves, Ed448, ECDAA, TPM, Android Key, Android SafetyNet, Apple,
and compound attestation are not enabled. Related-origin discovery, conditional
registration without UP, authenticator management, and CTAP transports are not
implemented by this RP library. Browser conditional UI may still be used for
an ordinary assertion that meets the verifier's checks.

A valid attestation signature does **not** identify a trusted manufacturer or
prove that a credential is hardware bound. `Attachment::Platform` and
`Attachment::CrossPlatform` are browser selection hints, not evidence of key
protection. An application requiring approved authenticator models needs a
separate trust policy with pinned roots or another authenticated metadata
source. FIDO Metadata Service is one possible source, not the only one.

## Installation

For the review branch:

```toml
[dependencies]
passkey-auth = { git = "https://github.com/nazozero/passkey-auth-rs", branch = "nazoauth/webauthn-protocol-calibration-20261117" }
```

Pin the reviewed commit with Cargo's `rev` setting in a production application
and commit `Cargo.lock`, as NazoAuth does. The previously published crates.io
`0.1.3` package does not contain this 0.2.0 migration.

### Signature backend selection

The `aws-lc` feature is **disabled by default**. Add `features = ["aws-lc"]` to
the dependency declaration to select it for native builds.

| Build | Credential ES256 authentication / packed self-attestation | Ed25519 |
|---|---|---|
| Native, default features | RustCrypto P-256 | dalek `verify_strict` |
| Native, `aws-lc` enabled | AWS-LC (`aws-lc-rs 1.19.0` in the final lockfiles) | dalek `verify_strict` |
| Any WASM target, either feature setting | RustCrypto P-256 | dalek `verify_strict` |

Certificate-attestation verification for packed x5c and FIDO U2F remains on
RustCrypto in every configuration. The feature changes no COSE schema, signed
transcript, DER boundary, attestation policy, credential storage shape, or MFA
decision. Selection happens at compile time, with no application-level runtime
backend selector or shared-state wrapper. Native builds with the feature acquire an AWS-LC native
build dependency; WASM does not build it.
Follow the [AWS-LC build requirements](https://aws.github.io/aws-lc-rs/requirements/)
for the target. In particular, an x86-64 Windows MSVC build needs the C/C++
toolchain and NASM on PATH; the CI installs and checks NASM before compiling
that feature. The default RustCrypto build has no AWS-LC build dependency.

NazoAuth's baseline already locks `aws-lc-rs 1.19.0` / `aws-lc-sys 0.47.0`.
The library's compatible version requirement preserves that resolution. An
initial exact 1.18.2 constraint would have forced a consumer downgrade; integration
review blocked it before merging or deployment and the constraint was corrected.

The [final performance comparison](docs/performance.md) uses AWS-LC **1.19.0**
and measures production commit `8260480634fac09e1151ca2b1a9eaa1c02af6f67` against the exact pinned baseline.
In its five-round native comparison, complete ES256 authentication finish P50
fell from **415.448 to 79.050 µs (81.0%)** with the feature enabled.
Ed25519 still uses dalek: its authentication P50 changed from
**53.310 to 67.101 µs (+25.9%)**, and registration finish from
**4.107 to 9.084 µs (+121.2%)**.
The additional key-validity and strict-verification work remains enabled.
These figures are medians of per-round P50s on the recorded Linux host with
one concurrent operation, not application or multi-user capacity measurements.

The native allocation measurement includes AWS-LC's C allocator requests:
ES256 authentication uses **23 requests / 1,327 bytes** per operation, compared
with baseline **16 / 1,363**. Reporting only the Rust allocator's **6 / 324**
would omit C-side work. Portable RustCrypto reduces parser allocations, but
host scheduling noise prevents attributing its small ES256 latency change to
the code. WASI uses RustCrypto and shows no general latency improvement.
The performance report retains every round, P95/P99, throughput, CPU and
artifact-size results, along with measurement boundaries and regressions.

The [initial AWS-LC 1.18.2 experiment](docs/evidence/performance-backends.json)
is retained as exploratory evidence. The final 1.19.0 probe also accepted a
small-order Ed25519 fixture that dalek's strict policy rejects; this acceptance
policy difference is why AWS-LC is never selected for Ed25519. Actual tested
feature/target combinations are recorded in [validation](docs/validation.md).

## Registration and username-first authentication

```rust,ignore
use passkey_auth::{AuthenticationResponse, RegistrationResponse, Webauthn};

// Validate configuration at startup. This is the origin's exact serialized
// scheme / host / optional port, with no path or trailing slash.
let wa = Webauthn::try_new("example.com", "Example", "https://example.com")?
    .strict_base64(true)
    .require_user_verification(true);

// Generate once when creating the account, then persist this opaque handle.
// Do not derive it from an email address, username, or other personal data.
let user_handle = rand::random::<[u8; 32]>();
let existing_ids = vec![];
let (options, pending) = wa.try_start_registration(
    &user_handle, "alice@example.com", "Alice", &existing_ids,
)?;
// Store pending under a server-generated ceremony ID with TTL, bound to the
// current tenant, account, and session. Send options to the browser.
// At finish, atomically consume the stored pending state before verification.
let response: RegistrationResponse = todo!();
let mut credential = wa.finish_registration(&pending, &response)?;
// Atomically enforce the credential ID's uniqueness in the RP's account store,
// check registration authorization, and persist the WHOLE credential record.

let (options, pending) = wa.start_authentication_with_creds_for_user(
    &user_handle, std::slice::from_ref(&credential),
);
// Send options; retain and later atomically consume the pending state.
let response: AuthenticationResponse = todo!();
// Fetch this credential using the expected tenant and account as well as ID.
let result = wa.finish_authentication(&pending, &response, &credential)?;

// Keep a snapshot of the previous counter and metadata for CAS.
credential.counter = result.new_counter;
credential.backup_eligible = Some(result.backup_eligible);
credential.backup_state = Some(result.backup_state);
// Compare-and-swap using the old counter/metadata and account / credential ID.
// Persist the complete record before issuing or upgrading a session.
// Do not set credential.uv_initialized=true just because result.user_verified.
let may_count_uv_as_factor = result.user_verification_eligible;
```

The snippet leaves storage and session operations to the application. A valid
library result is not by itself a committed authentication transaction.

`require_user_verification(true)` requests `userVerification="required"` and
rejects a response without the signed UV bit. The default requests
`"preferred"`; a correctly signed UP-only response can authenticate possession
of the credential under that policy. The application must keep that event
separate from an authentication event eligible to count UV as another factor.

`start_authentication_for_user` and
`start_authentication_with_creds_for_user` bind the expected account handle.
In these username-first flows, an omitted response `userHandle` remains valid
by default for older, non-discoverable authenticators. A supplied handle must
match. `.require_user_handle(true)` adds a local policy requiring it even in
username-first flows; enable that only when your supported authenticators
provide it. Handles contain 1 through 64 bytes.

## Discoverable credentials

Start with an empty allow list when the user is not known:

```rust,ignore
let (options, pending) = wa.start_authentication(&[]);
// The browser must return userHandle. Decode it using your configured wire
// policy, resolve the account within the current tenant, then find response.id
// within that account. Consume pending once before the finish operation.
let expected_handle: &[u8] = todo!();
let credential = todo!();
let result = wa.finish_discoverable_authentication(
    &pending, &response, &credential, expected_handle,
)?;
```

The explicit handle also permits existing credentials whose serialized record
predates `user_handle`. Newly registered credentials carry their account handle,
so ordinary `finish_authentication` can check that stored binding. A discoverable
assertion with no resolvable expected handle or with an absent / mismatched
response handle is rejected. The library cannot identify a tenant or validate
a database query on the application's behalf.

The passwordless example asks the browser for a discoverable credential and
uses the explicit finish method. A `residentKey` preference alone does not
prove that a credential is discoverable; browser hints and extensions should
not replace account binding.

## UV history and MFA

`AuthSuccess::user_verified` reports the UV bit only after the credential
signature has been verified. `user_verification_eligible` is true only when
that assertion has UV **and** the stored credential has
`uv_initialized == Some(true)`.

This distinction implements the Level 3
[credential record](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#credential-record)
rule. A credential that was enrolled without UV, or one with unknown historical
UV initialization, must not automatically make a later UV assertion an
additional factor. Unknown history is represented by `None`, not a fabricated
`true`. Applications can establish UV initialization through an explicit flow
with another suitable factor; the library never performs that promotion
implicitly. That flow must not count the assertion that performs the promotion
as already eligible based on the new value.

For MFA decisions, consume `user_verification_eligible` under the application's
AMR / session policy. Required UV and MFA eligibility answer different questions:
a response may meet the requested UV requirement while its old credential
record still lacks the history needed to count UV as another factor. Such
credentials remain usable and do not need to be registered again.

The NazoAuth integration applies this rule to new authentication decisions and
provides a controlled initialization flow using recent independent OTP or
recovery-code MFA. The upgrade preserves existing session and remembered-MFA
lifetimes; it does not retrospectively establish UV history for their old AMR
claims or revoke every existing session. A still-fresh historical session can
retain credential-management authority under the existing policy. Historical
`passkey_uv` alone cannot directly initialize an old credential's UV history.

## Upgrading from 0.1.3 to 0.2.0

Persist `PasskeyCredential` as a complete serde record, including fields added
after the original release:

| Field | Existing JSON without the field | New registration |
|---|---|---|
| `id`, `public_key_cose`, `counter`, `transports`, `aaguid` | Existing representation retained | Populated from the validated response |
| `user_handle` | `None`; caller's account binding can supply it | `Some` with the ceremony's account handle |
| `uv_initialized` | `None` (unknown) | `Some` with registration UV |
| `backup_eligible`, `backup_state` | `None` (unknown) | `Some` with registration BE / BS |
| `attestation` | `Unknown` | `None`, `SelfAttestation`, or `UntrustedCertificate` |

There is deliberately no `TrustedManufacturer` result. `Unknown` means the old
record did not preserve this information; `None` is a verified empty `none`
attestation statement. `UntrustedCertificate` records a successfully verified
attestation signature without a verified chain of trust.

The stored COSE bytes remain unchanged. The historical reader tolerates old map
ordering, integer widths, and harmless optional metadata, while rejecting
ambiguous / duplicate labels, private key material, malformed framing, and
invalid algorithm / curve combinations. New registrations use the stricter
WebAuthn / CTAP2 canonical profile. This compatibility path is for persisted
records; it is not a way to opt new incoming keys out of validation.

Old **in-flight ceremony states** lack the new context binding and must restart
a ceremony after deployment. This short-lived state invalidation does not
invalidate a stored credential. States with missing / zero / future timestamps
are rejected; the verifier imposes a 300-second maximum age in addition to the
caller's shorter TTL. Changing RP ID, origin, UV policy, strict Base64 policy,
or required-handle policy also invalidates previously issued states.

The existing convenience `new` and `start_registration` methods remain. They
panic on invalid configuration or invalid handle length. Use `try_new` and
`try_start_registration` for fallible startup / input validation. Adding fields
to a public Rust struct requires updating external struct literals even though
old serialized JSON remains compatible.

`AuthSuccess` is a transient verification result, not a persisted credential.
Its new backup fields are required when deserializing an outcome, so replaying an
old result cannot silently overwrite known credential metadata with `false`.

## Application obligations

The verifier deliberately has no database or network side effects. A production
integration must provide these operations:

1. Generate an opaque account handle once, authorize passkey enrollment and
   deletion, and keep tenant / account / credential lookups scoped correctly.
2. Keep pending ceremony state on the server, bind it to the intended account
   and session, apply a short TTL, and consume it atomically once. A signed
   cookie alone does not make state single-use. Never accept a client-supplied
   serialized `RegistrationState` or `AuthenticationState` as trusted state.
3. Compare-and-swap the counter and prior metadata, then persist verified metadata before session
   success. Treat a conflict as an uncommitted authentication result. The
   library permits `0 → 0` counters and rejects non-increasing nonzero counters
   as its conservative policy; that anomaly is not proof of cloning and the
   counter is not a replacement for one-time challenges.
4. Keep session rotation, MFA / AMR upgrades, remembered MFA, audit events, and
   transaction failure handling consistent with the committed outcome.
5. Bound HTTP bodies before JSON deserialization, rate-limit ceremonies, and
   enforce TLS, CSRF / origin controls for application endpoints, and normal
   account authorization. The field limits below apply after the response
   struct exists; they cannot undo an allocation by the HTTP framework.

`try_new` checks exact origin serialization, HTTPS (HTTP only for localhost /
loopback), and the RP ID's relationship to that host. A domain host can use
itself or a parent domain; an IP-address host requires an exact RP ID match,
never an address suffix. The constructor does not maintain a
Public Suffix List or authorize all subdomains of an RP ID. Configure the exact
trusted origin you serve and an RP ID acceptable under the browser's effective
domain and public-suffix rules. Local loopback configuration support is not a
claim of portable browser support for IP-address RP IDs. Unrelated, opaque, native-app, and embedded origins
are outside this implementation's configured scope.

## Wire encoding and resource limits

The public response structs retain the existing flat JSON adapter shape. The
examples convert browser `ArrayBuffer` fields to base64url without padding.
The browser's nested `PublicKeyCredential.toJSON()` object needs a corresponding
adapter; this library does not claim the flat shape is that browser dictionary.

Strict mode applies to credential ID, attestation object, client data,
authenticator data, signature, challenge, and user handle. The default remains
lenient for existing applications; NazoAuth and the examples select strict mode.
Client data retains its original bytes for hashing, including any initial UTF-8
BOM. Unknown JSON members are allowed; duplicate or mistyped security fields
are rejected.

| Input | Limit |
|---|---:|
| Decoded `clientDataJSON` | 8 KiB |
| Decoded attestation object / CBOR input | 64 KiB |
| Decoded registration / assertion `authenticatorData` | 16 KiB |
| Credential ID | 1–1,023 bytes |
| User handle | 1–64 bytes |
| Signature field | 80 bytes |
| Transports | 16 strings, each at most 32 bytes |
| CBOR container / nesting / total items | 64 entries / depth 12 / 2,048 items |
| Attestation chain | 8 certificates, each at most 16 KiB, within the outer limit |

These are deliberate RP resource policies, not CTAP transport limits. Unsupported
future extension structures may require an explicit limit / schema update.
Decoded binary data is borrowed internally where practical, and fixed-size
coordinates / hashes use stack buffers. See the performance artifact for actual
before / after measurements; no backend speed claim follows from dependency
choice alone.

These limits cover individual response fields and parsing. They do not bound
the number of stored credentials an account can supply to begin operations.
Registration exclusion lists, authentication allow lists, serialized options
and pending state grow with that number. NazoAuth currently has no per-account
credential quota, so its repository reads and begin work retain this linear
cost. Deployment-level quotas and request controls remain application policy;
this update does not silently discard existing credentials to impose a cap.

## Working examples

Run one server at a time at <http://localhost:3000>.

| Example | Purpose |
|---|---|
| [`axum_server`](examples/axum_server.rs) | Minimal single-account registration and username-first authentication |
| [`rocket_server`](examples/rocket_server.rs) | The same flow with Rocket |
| [`axum_passwordless`](examples/axum_passwordless.rs) | Multiple accounts, random handles, discoverable login, and atomic registration uniqueness |
| [`rocket_credential_manager`](examples/rocket_credential_manager.rs) | Authenticated passkey listing / addition / deletion for a demo account |
| [`axum_sqlite`](examples/axum_sqlite.rs) | Complete credential JSON, legacy-row migration, account-scoped lookup, and counter / metadata CAS |

```bash
cargo run --example axum_server
cargo run --example axum_passwordless
cargo run --example rocket_credential_manager
cargo run --example axum_sqlite
```

These are local demonstrations, not deployment templates: in-memory session
stores are unbounded, several examples use one hard-coded account, and they do
not provide a complete production CSRF, rate-limit, or account recovery layer.
The manager renders untrusted transport labels as text, and its credential
listing requires a session; its public setup-status endpoint reveals only
whether the demo account has a credential.

## Development and evidence

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
cargo audit
```

`--all-targets` includes the regression tests inside the examples. Official W3C
vectors, generated real-signature tests, malformed-input cases, property tests,
and fuzz targets supplement each other; none alone establishes complete
protocol correctness. Exact command results, targets, feature combinations,
constraints, and any failed / unrun checks are recorded in
[validation](docs/validation.md). Do not infer a platform passed from a CI
configuration entry alone.

## License

Licensed under either:

- Apache License, Version 2.0 ([license text](APACHE-LICENSE)).
- MIT License ([license text](LICENSE)).
