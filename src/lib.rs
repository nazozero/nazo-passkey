//! WebAuthn relying party verifier with a pure-Rust default and optional native
//! AWS-LC credential ES256 verification. Ed25519 uses borrowed transcript parts
//! with a strict acceptance policy; WASM uses RustCrypto.
//!
//! Quickstart:
//! ```no_run
//! use nazo_passkey::Webauthn;
//!
//! let wa = Webauthn::try_new("example.com", "Example", "https://example.com")?;
//!
//! // Registration ------------------------------------------------------
//! let (challenge, state) = wa.try_start_registration(
//!     b"user-handle-bytes",
//!     "alice@example.com",
//!     "Alice",
//!     &[], // no existing credentials yet
//!     Default::default(), // discoverable credential, no attestation requested
//! )?;
//! // → send `challenge` to the browser as JSON
//! // ← browser POSTs a `RegistrationResponse` back
//! # let response: nazo_passkey::RegistrationResponse = unimplemented!();
//! let credential = wa.finish_registration(&state, &response).expect("ok");
//! // → persist the complete credential, including account, UV and backup metadata
//!
//! // Authentication ----------------------------------------------------
//! let (challenge, state) = wa.start_authentication_with_creds_for_user(
//!     b"user-handle-bytes", std::slice::from_ref(&credential),
//! );
//! // → send `challenge` to the browser
//! # let response: nazo_passkey::AuthenticationResponse = unimplemented!();
//! let outcome = wa.finish_authentication(&state, &response, &credential).expect("ok");
//! // → commit counter and backup metadata with account-scoped compare-and-swap
//! // → use outcome.user_verification_eligible when applying the MFA/session policy
//! # Ok::<(), nazo_passkey::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

mod attestation;
mod auth_data;
mod cbor;
mod ceremony;
mod client_data;
mod cose;
mod crypto;
pub mod error;
mod types;
mod x509;

pub use ceremony::{Attachment, Webauthn};
pub use error::{Error, Result};
pub use types::{
    AssertionResponse, AttestationConveyancePreference, AttestationEvidence, AttestationResponse,
    AuthSuccess, AuthenticationChallenge, AuthenticationResponse, AuthenticationState, Challenge,
    CosePublicKey, CredentialId, PasskeyCredential, PublicKeyCredential, RegistrationChallenge,
    RegistrationOptions, RegistrationResponse, RegistrationState, ResidentKeyRequirement, RpId,
    VerifiedAttestation,
};
