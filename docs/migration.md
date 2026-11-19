# Migrate from passkey-auth

## 0.2 to 0.3

Authentication now returns protocol evidence before the relying party's counter
risk decision. `Error::CounterReplay` is removed. Check
`outcome.counter_status == CounterStatus::NonIncreasing` to preserve a strict
reject policy. Zero/zero returns `Unsupported`; an increase returns `Advanced`.
All mandatory account, challenge, flag, key and signature checks still execute
before any outcome is returned.

`AuthSuccess::new_counter`, `backup_eligible`, and `backup_state` move into
`AuthSuccess::update`, a `CredentialUpdate`. The update also carries the
expected counter, backup eligibility and backup state from the authenticated
credential snapshot. Use these expected fields in an atomic storage update;
do not repeat WebAuthn's counter classification in the storage implementation.
UV initialization and its authorization remain application decisions.

Stored `PasskeyCredential` and ceremony-state serialization remain unchanged.
The transient `AuthSuccess` JSON shape changes with the Rust API.

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

## Registration options

`start_registration` and `try_start_registration` take `RegistrationOptions`
as their final argument. `RegistrationOptions::default()` now requests
`residentKey: "required"` and `attestation: "none"`, making discoverable passkey
enrollment the default. To allow non-discoverable enrollment, pass:

```rust
use nazo_passkey::{RegistrationOptions, ResidentKeyRequirement};

let options = RegistrationOptions {
    resident_key: ResidentKeyRequirement::Preferred,
    ..Default::default()
};
```

`AuthenticatorSelection::resident_key` and `RegistrationChallenge::attestation`
are typed enums. The wire `requireResidentKey` boolean is derived from the
resident-key choice.

Applications with an attestation trust policy can request
`AttestationConveyancePreference::Direct` and use
`finish_registration_with_attestation` to inspect `VerifiedAttestation`
before receiving a credential to persist. Reject with
`Error::AttestationRejected`; handle `None` and `SelfAttestation` according
to policy even after requesting `Direct`. The ordinary finish method requires
no trust-policy callback.

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

The attestation callback borrows certificate DER without changing the stored
record. `UntrustedCertificate` continues to record the library's verification
result even when the application accepts the chain. Persist application trust
decisions in application-owned fields.

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

Post the result of `PublicKeyCredential.toJSON()` directly to the finish route.
Deserialize it as `RegistrationResponse` or `AuthenticationResponse`. Read
the decoded credential ID from `id` and the decoded optional assertion handle
from `response.user_handle`. Remove any client-side response repacking and
`strict_base64` configuration. Wire values and the signed
`clientDataJSON.challenge` require canonical unpadded base64url.

Restart pending ceremonies when switching wire formats. Existing stored
credentials can still be used. Client data follows WebAuthn's UTF-8 replacement
rules for parsing and uses the original bytes for signature verification.
