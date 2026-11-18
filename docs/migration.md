# Migrate from passkey-auth

## Package and imports

Use package `nazo-passkey` and Rust imports under `nazo_passkey`. The independently
maintained repository is `https://github.com/nazozero/nazo-passkey`.

```toml
[dependencies]
nazo-passkey = { git = "https://github.com/nazozero/nazo-passkey", branch = "main" }
```

An application can keep its existing import name while changing the dependency:

```toml
[dependencies]
passkey-auth = { package = "nazo-passkey", git = "https://github.com/nazozero/nazo-passkey", branch = "main" }
```

Pin a reviewed commit through `rev` for production deployments. Earlier Git
revisions retain their original package metadata and remain reproducible.

## Stored credentials

Complete `PasskeyCredential` serde records preserve the existing byte-array
representation of credential IDs, COSE keys, AAGUIDs, transports, and counters.
The following fields extend the original 0.1.3 record:

| Field | Existing record without the field | Newly registered credential |
| --- | --- | --- |
| `user_handle` | `None`; application supplies account binding | Registration account handle |
| `uv_initialized` | `None`; history is unknown | Observed UV flag |
| `backup_eligible`, `backup_state` | `None`; history is unknown | Observed BE / BS flags |
| `attestation` | `Unknown` | `None`, `SelfAttestation`, or `UntrustedCertificate` |

Persist the complete returned credential. Conforming existing ES256 / Ed25519
keys remain usable. The stored-key reader accepts historical ordering and
integer widths while enforcing key type, curve, point validity, usage
restrictions, and public-only key material. Invalid historical key records
require repair or re-enrollment.

## Pending ceremonies and application code

Restart pending 0.1.3 ceremonies: current state binds the RP, origin, and
verification policy. Store state on the server and consume it atomically once.

New fields and error variants require updates to struct literals and exhaustive
matches. Prefer `try_new` and `try_start_registration` for fallible inputs.
Bind username-first requests to the account's stable handle. For discoverable
login, resolve the returned handle and pass the expected binding to
`finish_discoverable_authentication`.

Commit verified counter and backup metadata with compare-and-swap before
creating a session. Use `user_verification_eligible` for additional-factor
policy. Establish unknown UV history through an independently authorized flow;
evaluate the assertion performing that update against the previous history.

## Wire encoding

Responses use the existing flat adapter structs. Browser integrations extract
the nested `credential.response` fields and encode binary values as unpadded
base64url. `strict_base64(true)` enforces this on the outer adapter.

The signed `clientDataJSON.challenge` now always requires canonical base64url,
including when the outer adapter allows legacy encodings. Client data uses
WebAuthn's UTF-8 replacement decoding for parsing, while hashing the original
response bytes for signature verification.
