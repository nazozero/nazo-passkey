# Origin

`nazo-passkey` is an independently maintained rewrite derived from
[Sriram's `marirs/passkey-auth-rs`](https://github.com/marirs/passkey-auth-rs).
The upstream Git history, author attribution, and MIT / Apache-2.0 license
texts are retained.

The inherited `passkey-auth 0.1.3` baseline is commit
`d59b317998e56f4a16a69133d7a854c5c34f795b`, including the RustCrypto maintenance
changes. The WebAuthn verifier, credential security metadata, bounded parsers,
backend selection, examples, and validation were subsequently reworked here.

The independent crate is `nazo-passkey`; its Rust library name is
`nazo_passkey`. Maintainer: [bymoye](https://github.com/bymoye),
`s3moye@gmail.com`. Credential compatibility is documented in
[migration](docs/migration.md).
