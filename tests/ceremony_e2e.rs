//! End-to-end integration test for the full WebAuthn ceremony.
//!
//! Builds a synthetic Ed25519 authenticator, drives registration and
//! authentication through the public `Webauthn` API, and checks the
//! invariants that matter:
//!
//! - registration extracts the public key the authenticator provided
//! - authentication verifies the signature against that stored key
//! - the counter check rejects replays
//! - user-verification enforcement (`require_user_verification(true)`)
//!   rejects assertions where the UV bit is clear
//! - clientDataJSON tampering (wrong challenge / wrong origin) is
//!   rejected
//!
//! Ed25519 is used because it has a smaller setup than ES256 (no
//! curve point assembly, no DER signature wrapping) and the rest of
//! the crate treats both algorithms identically, so coverage carries.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use nazo_passkey::{
    AssertionResponse, AttestationResponse, AuthenticationResponse, CredentialId, Error,
    RegistrationResponse, Webauthn,
};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

// ---------- authenticator simulation ---------------------------------------

/// Synthetic authenticator. Holds an Ed25519 keypair and the
/// monotonic sign counter; can produce registration attestation
/// objects and assertion signatures the way a real authenticator
/// would (modulo: we emit attestation `fmt=none` so there is no
/// statement to sign).
struct FakeAuthenticator {
    sk: SigningKey,
    credential_id: Vec<u8>,
    counter: u32,
    /// What flag bits to set on every authData. Test cases tweak this
    /// to simulate UV-less or absent-user authenticators.
    flags: u8,
}

const FLAG_UP: u8 = 1 << 0;
const FLAG_UV: u8 = 1 << 2;
const FLAG_AT: u8 = 1 << 6;

impl FakeAuthenticator {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        Self {
            sk: SigningKey::from_bytes(&seed),
            credential_id: b"test-credential-0001".to_vec(),
            counter: 0,
            flags: FLAG_UP | FLAG_UV,
        }
    }

    /// COSE_Key for an Ed25519 public key: {1: 1, 3: -8, -1: 6, -2: <pub>}.
    fn cose_pubkey(&self) -> Vec<u8> {
        let pk = self.sk.verifying_key().to_bytes().to_vec();
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(1.into())), // kty=OKP
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-8).into()),
            ), // alg=EdDSA
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(6.into()),
            ), // crv=Ed25519
            (CborValue::Integer((-2).into()), CborValue::Bytes(pk)),      // x=pub
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    /// authenticatorData with attestedCredentialData (AT flag set).
    /// Used at registration time.
    fn auth_data_register(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        buf.push(self.flags | FLAG_AT);
        buf.extend_from_slice(&self.counter.to_be_bytes());
        // attestedCredentialData
        buf.extend_from_slice(&[0u8; 16]); // aaguid (zeros for fmt=none)
        let cid_len = self.credential_id.len() as u16;
        buf.extend_from_slice(&cid_len.to_be_bytes());
        buf.extend_from_slice(&self.credential_id);
        buf.extend_from_slice(&self.cose_pubkey());
        buf
    }

    /// authenticatorData without attestedCredentialData. Used at
    /// authentication time. Increments the counter automatically -
    /// passing `tamper_counter=Some(n)` overrides it for replay tests.
    fn auth_data_authenticate(&mut self, tamper_counter: Option<u32>) -> Vec<u8> {
        let count = match tamper_counter {
            Some(n) => n,
            None => {
                self.counter += 1;
                self.counter
            }
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        buf.push(self.flags); // no AT bit
        buf.extend_from_slice(&count.to_be_bytes());
        buf
    }

    /// attestationObject for fmt=none, wrapping the registration authData.
    fn attestation_object(&self) -> Vec<u8> {
        let map = CborValue::Map(vec![
            (
                CborValue::Text("fmt".into()),
                CborValue::Text("none".into()),
            ),
            (
                CborValue::Text("attStmt".into()),
                CborValue::Map(Vec::new()),
            ),
            (
                CborValue::Text("authData".into()),
                CborValue::Bytes(self.auth_data_register()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    /// Sign authData || SHA-256(clientDataJSON), as a real authenticator
    /// does for assertion.
    fn sign_assertion(&self, auth_data: &[u8], client_data_json_raw: &[u8]) -> Vec<u8> {
        let cdj_hash = Sha256::digest(client_data_json_raw);
        let mut msg = Vec::with_capacity(auth_data.len() + 32);
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&cdj_hash);
        self.sk.sign(&msg).to_bytes().to_vec()
    }
}

/// Build the clientDataJSON the browser would send. Returns (raw_bytes,
/// base64url_encoded). The raw bytes are what gets hashed; the base64
/// version is what goes on the wire.
fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> (Vec<u8>, String) {
    let json = format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    );
    let raw = json.into_bytes();
    let enc = B64URL.encode(&raw);
    (raw, enc)
}

// ---------- actual tests ---------------------------------------------------

#[test]
fn register_then_authenticate_happy_path() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();

    // ---- Registration ----------------------------------------------------
    let (chal, state) = wa.start_registration(USER_HANDLE, "alice@example.com", "Alice", &[]);

    let (_cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);
    let attestation = B64URL.encode(auth.attestation_object());

    let response = RegistrationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AttestationResponse {
            transports: vec!["internal".into()],
            attestation_object: attestation,
            client_data_json: cdj_b64,
        },
    };

    let credential = wa
        .finish_registration(&state, &response)
        .expect("registration must succeed");
    assert_eq!(credential.id.as_bytes(), auth.credential_id.as_slice());
    assert_eq!(credential.counter, 0);
    assert_eq!(credential.transports, vec!["internal".to_string()]);

    // ---- Authentication --------------------------------------------------
    let (chal, state) = wa.start_authentication(std::slice::from_ref(&credential.id));

    let auth_data = auth.auth_data_authenticate(None); // counter -> 1
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &chal.challenge, ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);

    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let outcome = wa
        .finish_authentication(&state, &response, &credential)
        .expect("auth must succeed");
    assert_eq!(outcome.new_counter, 1);
    assert!(outcome.user_verified);
}

#[test]
fn counter_replay_rejected() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    // Pretend the user already authenticated up to counter=5.
    let mut stored = credential.clone();
    stored.counter = 5;

    // Authenticator (somehow) emits counter=5 - equal, not strictly greater.
    let (chal, state) = wa.start_authentication(&[stored.id.clone()]);
    let auth_data = auth.auth_data_authenticate(Some(5));
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &chal.challenge, ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);

    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let err = wa
        .finish_authentication(&state, &response, &stored)
        .unwrap_err();
    assert!(matches!(err, Error::CounterReplay { stored: 5, new: 5 }));
}

#[test]
fn require_uv_rejects_uv_less_assertion() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN).require_user_verification(true);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    // Authenticator drops the UV bit for the assertion (simulates a
    // user who tapped without biometric / PIN).
    auth.flags = FLAG_UP; // UP only, no UV
    let (chal, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let auth_data = auth.auth_data_authenticate(None);
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &chal.challenge, ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);

    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::UserNotVerified), "got {err:?}");
}

#[test]
fn wrong_origin_rejected() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let auth_data = auth.auth_data_authenticate(None);
    // ClientDataJSON pretends to come from a different origin.
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &chal.challenge, "https://evil.com");
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);

    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::OriginMismatch { .. }), "got {err:?}");
}

#[test]
fn wrong_challenge_rejected() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (_chal, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let auth_data = auth.auth_data_authenticate(None);
    // ClientDataJSON contains a challenge we never issued.
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &B64URL.encode([0u8; 32]), ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);

    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::ChallengeMismatch), "got {err:?}");
}

#[test]
fn signed_challenges_reject_padding_in_both_ceremonies() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (_, registration) = wa.start_registration(USER_HANDLE, "alice", "Alice", &[]);
    let padded =
        base64::engine::general_purpose::URL_SAFE.encode(registration.challenge.as_bytes());
    assert!(padded.ends_with('='));
    let (_, client_data_json) = client_data("webauthn.create", &padded, ORIGIN);
    let response = RegistrationResponse {
        id: credential.id.clone(),
        response: AttestationResponse {
            transports: vec![],
            attestation_object: B64URL.encode(auth.attestation_object()),
            client_data_json,
        },
    };
    assert!(matches!(
        wa.finish_registration(&registration, &response),
        Err(Error::Base64(_))
    ));

    let (_, authentication) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let padded =
        base64::engine::general_purpose::URL_SAFE.encode(authentication.challenge.as_bytes());
    let response = make_assertion(&mut auth, &padded, None);
    assert!(matches!(
        wa.finish_authentication(&authentication, &response, &credential),
        Err(Error::Base64(_))
    ));
}

#[test]
fn client_data_utf8_decoding_preserves_the_signed_transcript() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);
    let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let (mut json, _) = client_data("webauthn.get", &challenge.challenge, ORIGIN);
    assert_eq!(json.pop(), Some(b'}'));
    json.extend_from_slice(b",\"future\xff\":true}");
    let mut raw = vec![0xef, 0xbb, 0xbf];
    raw.extend_from_slice(&json);
    let auth_data = auth.auth_data_authenticate(None);
    let mut response = AuthenticationResponse {
        id: credential.id.clone(),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(auth.sign_assertion(&auth_data, &raw)),
            client_data_json: B64URL.encode(&raw),
            user_handle: None,
        },
    };
    wa.finish_authentication(&state, &response, &credential)
        .unwrap();

    let decoded = String::from_utf8_lossy(&json);
    response.response.signature =
        B64URL.encode(auth.sign_assertion(&auth_data, decoded.as_bytes()));
    assert!(matches!(
        wa.finish_authentication(&state, &response, &credential),
        Err(Error::BadSignature)
    ));
}

#[test]
fn expired_ceremony_rejected() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    // Build a valid assertion, then back-date the state's
    // `created_at` to 10 minutes ago to simulate a caller that
    // forgot to TTL their session store.
    let (chal, mut state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    state.created_at = state.created_at.saturating_sub(600); // 10 minutes ago

    let auth_data = auth.auth_data_authenticate(None);
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", &chal.challenge, ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);
    let response = AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: None,
        },
    };

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::CeremonyExpired { .. }), "got {err:?}");
}

// ---------- user_handle (I2) ----------------------------------------------

/// Helper: build an AuthenticationResponse for a credential, optionally
/// stamping a user handle. Used by the four
/// user_handle tests below.
fn make_assertion(
    auth: &mut FakeAuthenticator,
    chal_b64: &str,
    user_handle: Option<&[u8]>,
) -> AuthenticationResponse {
    let auth_data = auth.auth_data_authenticate(None);
    let (cdj_raw, cdj_b64) = client_data("webauthn.get", chal_b64, ORIGIN);
    let sig = auth.sign_assertion(&auth_data, &cdj_raw);
    AuthenticationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AssertionResponse {
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(&sig),
            client_data_json: cdj_b64,
            user_handle: user_handle.map(<[u8]>::to_vec),
        },
    }
}

const USER_HANDLE: &[u8] = b"user-handle-0001";
const OTHER_USER_HANDLE: &[u8] = b"user-handle-0002";

#[test]
fn user_handle_match_succeeds() {
    // start_authentication_for_user + response.user_handle = expected → ok.
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));

    wa.finish_authentication(&state, &response, &credential)
        .expect("matching user_handle must succeed");
}

#[test]
fn user_handle_mismatch_rejected() {
    // start_authentication_for_user + response.user_handle = different
    // → UserHandleMismatch (the credential-id-collision protection).
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, Some(OTHER_USER_HANDLE));

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::UserHandleMismatch), "got {err:?}");
}

#[test]
fn user_handle_absent_in_response_is_accepted_by_default() {
    // start_authentication_for_user + response.user_handle = None →
    // accept (WebAuthn-3 §7.2 step 6: "if present, verify"). This is
    // the spec-default behaviour so non-resident hardware keys keep
    // working.
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, None);

    wa.finish_authentication(&state, &response, &credential)
        .expect("absent user_handle must be accepted by default");
}

#[test]
fn preidentified_account_allows_an_empty_allow_list_without_a_response_handle() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);
    let (challenge, state) = wa.start_authentication_for_user(USER_HANDLE, &[]);
    let response = make_assertion(&mut auth, &challenge.challenge, None);
    wa.finish_authentication(&state, &response, &credential)
        .unwrap();

    let mut other_account = credential.clone();
    other_account.user_handle = Some(OTHER_USER_HANDLE.to_vec());
    assert!(matches!(
        wa.finish_authentication(&state, &response, &other_account),
        Err(Error::UserHandleMismatch)
    ));

    let required = wa.require_user_handle(true);
    let (challenge, state) = required.start_authentication_for_user(USER_HANDLE, &[]);
    let response = make_assertion(&mut auth, &challenge.challenge, None);
    assert!(matches!(
        required.finish_authentication(&state, &response, &credential),
        Err(Error::UserHandleMismatch)
    ));
}

#[test]
fn require_user_handle_rejects_absent_response_handle() {
    // start_authentication_for_user + response.user_handle = None +
    // require_user_handle(true) → reject. This is the tighter mode for
    // platform-authenticator-only deployments where the user_handle
    // is always emitted.
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN).require_user_handle(true);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, None);

    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::UserHandleMismatch), "got {err:?}");
}

#[test]
fn stored_user_handle_is_checked_without_username_first_state() {
    // The credential's stored account handle binds the generic entry point.
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN).require_user_handle(true);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);

    let (chal, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, Some(b"anything"));

    assert!(matches!(
        wa.finish_authentication(&state, &response, &credential),
        Err(Error::UserHandleMismatch)
    ));
}

// ---------- helper ---------------------------------------------------------

fn do_register(wa: &Webauthn, auth: &mut FakeAuthenticator) -> nazo_passkey::PasskeyCredential {
    let (chal, state) = wa.start_registration(USER_HANDLE, "alice@example.com", "Alice", &[]);
    let (_cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);
    let attestation = B64URL.encode(auth.attestation_object());
    let response = RegistrationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AttestationResponse {
            transports: vec!["internal".into()],
            attestation_object: attestation,
            client_data_json: cdj_b64,
        },
    };
    wa.finish_registration(&state, &response)
        .expect("registration must succeed")
}

#[test]
fn registration_outer_id_and_exclusion_are_enforced() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let existing = do_register(&wa, &mut auth);
    let (chal, state) = wa.start_registration(USER_HANDLE, "alice", "Alice", &[]);
    let (_, client_data_json) = client_data("webauthn.create", &chal.challenge, ORIGIN);
    let mut response = RegistrationResponse {
        id: CredentialId(b"other-id".to_vec()),
        response: AttestationResponse {
            transports: vec![],
            attestation_object: B64URL.encode(auth.attestation_object()),
            client_data_json,
        },
    };
    assert!(matches!(
        wa.finish_registration(&state, &response),
        Err(Error::CredentialIdMismatch)
    ));
    response.id = existing.id.clone();
    let mut excluded = state;
    excluded.exclude_credentials.push(existing.id);
    assert!(matches!(
        wa.finish_registration(&excluded, &response),
        Err(Error::CredentialExcluded)
    ));
    // An excluded outer ID must still match the ID actually attested. Do not
    // let callers mistake a malformed response for a duplicate enrollment.
    response.id = CredentialId(b"other-id".to_vec());
    excluded
        .exclude_credentials
        .push(nazo_passkey::CredentialId(b"other-id".to_vec()));
    assert!(matches!(
        wa.finish_registration(&excluded, &response),
        Err(Error::CredentialIdMismatch)
    ));
}

#[test]
fn state_has_exact_rp_policy_binding_and_no_timestamp_bypass() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);
    let (challenge, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &challenge.challenge, Some(USER_HANDLE));
    for created_at in [0, u64::MAX] {
        let mut bad = state.clone();
        bad.created_at = created_at;
        assert!(matches!(
            wa.finish_authentication(&bad, &response, &credential),
            Err(Error::InvalidState(_))
        ));
    }
    let mut legacy = state.clone();
    legacy.context_binding = None;
    assert!(matches!(
        wa.finish_authentication(&legacy, &response, &credential),
        Err(Error::InvalidState(_))
    ));
    let relaxed = wa.clone().require_user_verification(true);
    assert!(matches!(
        relaxed.finish_authentication(&state, &response, &credential),
        Err(Error::InvalidState(_))
    ));
    let other = Webauthn::new("other.example.com", "Other", "https://other.example.com");
    assert!(matches!(
        other.finish_authentication(&state, &response, &credential),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn uv_fact_and_factor_eligibility_are_distinct_and_legacy_json_is_readable() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let credential = do_register(&wa, &mut auth);
    assert_eq!(credential.uv_initialized, Some(true));
    let (challenge, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &challenge.challenge, Some(USER_HANDLE));
    for initialized in [None, Some(false), Some(true)] {
        let mut stored = credential.clone();
        stored.uv_initialized = initialized;
        let result = wa
            .finish_authentication(&state, &response, &stored)
            .unwrap();
        assert!(result.user_verified);
        assert_eq!(result.user_verification_eligible, initialized == Some(true));
    }
    let mut old = serde_json::to_value(&credential).unwrap();
    for field in [
        "uv_initialized",
        "backup_eligible",
        "backup_state",
        "attestation",
        "user_handle",
    ] {
        old.as_object_mut().unwrap().remove(field);
    }
    let legacy: nazo_passkey::PasskeyCredential = serde_json::from_value(old).unwrap();
    assert!(legacy.uv_initialized.is_none());
    assert_eq!(
        legacy.attestation,
        nazo_passkey::AttestationEvidence::Unknown
    );
    let result = wa
        .finish_authentication(&state, &response, &legacy)
        .unwrap();
    assert!(result.user_verified);
    assert!(!result.user_verification_eligible);
}

#[test]
fn uv_preferred_false_and_required_registration_behavior() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    auth.flags = FLAG_UP;
    let credential = do_register(&wa, &mut auth);
    assert_eq!(credential.uv_initialized, Some(false));
    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));
    let result = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap();
    assert!(!result.user_verified && !result.user_verification_eligible);
    let required = wa.require_user_verification(true);
    let (chal, state) = required.start_registration(USER_HANDLE, "alice", "Alice", &[]);
    let (_, client_data_json) = client_data("webauthn.create", &chal.challenge, ORIGIN);
    let response = RegistrationResponse {
        id: CredentialId(auth.credential_id.clone()),
        response: AttestationResponse {
            transports: vec![],
            attestation_object: B64URL.encode(auth.attestation_object()),
            client_data_json,
        },
    };
    assert!(matches!(
        required.finish_registration(&state, &response),
        Err(Error::UserNotVerified)
    ));
}

#[test]
fn backup_flags_and_immutable_eligibility_are_enforced() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    auth.flags |= 8;
    let credential = do_register(&wa, &mut auth);
    assert_eq!(credential.backup_eligible, Some(true));
    let (chal, state) =
        wa.start_authentication_for_user(USER_HANDLE, std::slice::from_ref(&credential.id));
    auth.flags |= 16;
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));
    let result = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap();
    assert!(result.backup_eligible && result.backup_state);
    auth.flags = FLAG_UP | FLAG_UV;
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));
    assert!(matches!(
        wa.finish_authentication(&state, &response, &credential),
        Err(Error::BackupEligibilityChanged)
    ));
    auth.flags |= 16;
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));
    assert!(
        wa.finish_authentication(&state, &response, &credential)
            .is_err()
    );
}

#[test]
fn discoverable_assertions_bind_an_account_even_for_legacy_credentials() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut auth = FakeAuthenticator::new();
    let mut credential = do_register(&wa, &mut auth);
    let (chal, state) = wa.start_authentication(&[]);
    let missing = make_assertion(&mut auth, &chal.challenge, None);
    assert!(matches!(
        wa.finish_authentication(&state, &missing, &credential),
        Err(Error::UserHandleMismatch)
    ));
    let response = make_assertion(&mut auth, &chal.challenge, Some(USER_HANDLE));
    wa.finish_authentication(&state, &response, &credential)
        .unwrap();
    credential.user_handle = None;
    assert!(matches!(
        wa.finish_authentication(&state, &response, &credential),
        Err(Error::UserHandleMismatch)
    ));
    wa.finish_discoverable_authentication(&state, &response, &credential, USER_HANDLE)
        .unwrap();
    assert!(
        wa.finish_discoverable_authentication(&state, &response, &credential, OTHER_USER_HANDLE)
            .is_err()
    );
}

#[test]
fn registration_attestation_evidence_is_explicit() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let credential = do_register(&wa, &mut FakeAuthenticator::new());
    assert_eq!(
        credential.attestation,
        nazo_passkey::AttestationEvidence::None
    );
}
