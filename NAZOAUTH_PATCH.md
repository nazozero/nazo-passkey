# NazoAuth fork and compatibility

This is the maintained NazoZero fork of
[`marirs/passkey-auth-rs`](https://github.com/marirs/passkey-auth-rs), authored
upstream by Sriram. Its current maintainer is
[`bymoye`](https://github.com/bymoye); both are credited in Cargo metadata.

The production baseline for the 0.2.0 work is
[`d59b317998e56f4a16a69133d7a854c5c34f795b`](https://github.com/nazozero/passkey-auth-rs/commit/d59b317998e56f4a16a69133d7a854c5c34f795b)
on `nazoauth/patched-rustcrypto`, which NazoAuth used as `passkey-auth 0.1.3`.
That baseline already upgraded P-256 to remove the vulnerable `crypto-bigint
0.5.5` dependency and declared Rust 1.88. The protocol calibration preserves
those fixes and targets NazoAuth's Rust 1.100.0 toolchain.

The fork provides a bounded WebAuthn RP verifier for ES256 and Ed25519,
explicit attestation evidence, verified UV/backup metadata, and an optional
native ES256 backend. It preserves existing credential key bytes and JSON
readability. Public Rust API changes are versioned as 0.2.0; short-lived pending
ceremonies issued by 0.1.3 must restart.

NazoAuth pins immutable Git revisions. Dependency updates must preserve its
tenant/account bindings, atomic challenge consumption, credential CAS,
UV-history/MFA policy, audit outcomes, and session ordering. Refer to the
[integration record](docs/nazo-integration.md) for the concrete persistence
contract and regression evidence, and to the
[requirements matrix](docs/protocol-compliance.md) for supported protocol scope.

Use the [README](README.md) for installation and API guidance. Historical
benchmark or validation results apply only to their recorded source and
lockfile revisions; the evidence directory retains those checkpoints.
