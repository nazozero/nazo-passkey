//! Errors surfaced from registration / authentication ceremonies.
//!
//! All variants are deliberately specific (not "verification failed")
//! so callers can log/audit them - they don't leak data to the client
//! since the route layer must translate them into its safe public error
//! contract rather than exposing internal diagnostic strings.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// An input exceeds the documented bound, checked before decoding.
    #[error("{field} exceeds the {limit}-byte limit")]
    InputTooLarge { field: &'static str, limit: usize },

    /// This RP supports same-origin ceremonies only.
    #[error("cross-origin ceremonies and topOrigin are not enabled")]
    CrossOriginUnsupported,

    /// State is unbound, from a different RP policy, or has an invalid timestamp.
    #[error("invalid ceremony state: {0}")]
    InvalidState(&'static str),

    #[error("invalid WebAuthn configuration: {0}")]
    Configuration(&'static str),

    #[error("credential ID does not match the attested credential")]
    CredentialIdMismatch,

    /// The matching ID is excluded by the server-issued state after all
    /// supported attestation-statement checks have passed. This does not
    /// establish certificate-chain or manufacturer trust.
    /// Distinct from an inconsistent response ID so callers can preserve
    /// their duplicate-enrollment conflict response without misclassifying
    /// malformed registrations.
    #[error("credential is excluded by the registration state")]
    CredentialExcluded,

    /// The application's attestation policy rejected a protocol-valid response.
    #[error("attestation rejected by the relying party's trust policy")]
    AttestationRejected,

    #[error("credential backup eligibility changed")]
    BackupEligibilityChanged,

    /// Invalid base64url encoding on a wire field (challenge, credential
    /// id, signature, etc.).
    #[error("invalid base64url: {0}")]
    Base64(String),

    /// `clientDataJSON` failed to parse as UTF-8 JSON, or was JSON but
    /// missing required fields.
    #[error("clientDataJSON parse failed: {0}")]
    ClientData(String),

    /// `clientDataJSON.type` was wrong for the ceremony in flight
    /// (expected `webauthn.create` / `webauthn.get`).
    #[error("clientDataJSON.type mismatch: expected {expected}, got {actual}")]
    ClientDataType {
        expected: &'static str,
        actual: String,
    },

    /// `clientDataJSON.challenge` did not match the challenge issued
    /// at the start of the ceremony.
    #[error("challenge mismatch")]
    ChallengeMismatch,

    /// `clientDataJSON.origin` was not exactly the configured RP origin.
    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    /// `authenticatorData.rpIdHash` did not match SHA-256(RP_ID).
    #[error("rpIdHash mismatch")]
    RpIdHashMismatch,

    /// The user-present (UP) bit was 0 - caller required UP.
    #[error("user-present flag not set")]
    UserNotPresent,

    /// The user-verified (UV) bit was 0 - caller required UV.
    #[error("user-verified flag not set")]
    UserNotVerified,

    /// Binary parse of `authenticatorData` failed at the byte level.
    #[error("authenticatorData parse failed: {0}")]
    AuthData(&'static str),

    /// CBOR parse of attestationObject or COSE key failed.
    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    /// COSE key used an algorithm we don't support (only ES256 / EdDSA).
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlg(i64),

    /// Signature verification with the stored public key failed.
    #[error("signature verification failed")]
    BadSignature,

    /// The ceremony state handed to `finish_*` is older than the
    /// allowed ceiling (default 5 minutes). Indicates the caller did
    /// not TTL their session store, or the response came back after
    /// the user walked away. Reject and restart the ceremony.
    #[error("ceremony state expired ({age_secs} seconds old, max {max_secs})")]
    CeremonyExpired { age_secs: u64, max_secs: u64 },

    /// The `userHandle` carried in the assertion response did not
    /// match the user handle recorded at `start_authentication_for_user`
    /// time (WebAuthn-3 §7.2 step 6). Indicates an attack — the
    /// assertion is for a different user than the ceremony was
    /// started for — or, when `require_user_handle(true)` is set, an
    /// authenticator that did not emit a user_handle at all.
    #[error(
        "user handle mismatch: assertion is for a different user than the ceremony was started for"
    )]
    UserHandleMismatch,

    /// Internal invariant violation (bug). Should never reach a user.
    #[error("internal: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
