//! Unmodified byte vectors from W3C WebAuthn Level 3, REC 2026-08-25 §16.
//! Fixture provenance and document license are in fixtures/README.md.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_passkey::{
    AssertionResponse, AttestationResponse, AuthenticationResponse, Challenge, CredentialId, Error,
    RegistrationResponse, Webauthn,
};
use serde_json::Value;

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}

#[test]
fn official_registration_assertion_vectors_and_wrong_signatures() {
    let vectors: Value = serde_json::from_str(include_str!("fixtures/w3c-level3.json")).unwrap();
    let wa = Webauthn::new("example.org", "W3C vectors", "https://example.org");
    let supported = [
        "none-es256",
        "packed-self-es256",
        "none-es256-long-credential-id",
        "packed-es256",
        "packed-eddsa",
        "fido-u2f-es256",
    ];
    for vector in vectors["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let registration = &vector["registration"];
        let (_, mut state) = wa.start_registration(b"w3c-test-user", "user", "User", &[]);
        state.challenge = Challenge(bytes(registration, "challenge"));
        let response = RegistrationResponse {
            id: CredentialId(bytes(registration, "credential_id")),
            response: AttestationResponse {
                transports: vec![],
                attestation_object: URL_SAFE_NO_PAD
                    .encode(bytes(registration, "attestationObject")),
                client_data_json: URL_SAFE_NO_PAD.encode(bytes(registration, "clientDataJSON")),
            },
        };
        let result = wa.finish_registration(&state, &response);
        if name.contains("crossOrigin") || name.contains("topOrigin") {
            assert!(
                matches!(result, Err(Error::CrossOriginUnsupported)),
                "{name}: {result:?}"
            );
            continue;
        }
        if !supported.contains(&name) {
            assert!(
                result.is_err(),
                "unsupported algorithm/format accepted: {name}"
            );
            continue;
        }
        let credential = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            credential.id.as_bytes(),
            bytes(registration, "credential_id")
        );
        let authentication = &vector["authentication"];
        let (_, mut state) = wa
            .start_authentication_for_user(b"w3c-test-user", std::slice::from_ref(&credential.id));
        state.challenge = Challenge(bytes(authentication, "challenge"));
        let mut response = AuthenticationResponse {
            id: credential.id.clone(),
            response: AssertionResponse {
                authenticator_data: URL_SAFE_NO_PAD
                    .encode(bytes(authentication, "authenticatorData")),
                client_data_json: URL_SAFE_NO_PAD.encode(bytes(authentication, "clientDataJSON")),
                signature: URL_SAFE_NO_PAD.encode(bytes(authentication, "signature")),
                user_handle: None,
            },
        };
        wa.finish_authentication(&state, &response, &credential)
            .unwrap_or_else(|error| panic!("{name} assertion: {error:?}"));
        // Persisted 0.1.3 records have no new metadata, but the same key still verifies.
        let mut legacy = serde_json::to_value(&credential).unwrap();
        for key in [
            "user_handle",
            "uv_initialized",
            "backup_eligible",
            "backup_state",
            "attestation",
        ] {
            legacy.as_object_mut().unwrap().remove(key);
        }
        let legacy = serde_json::from_value(legacy).unwrap();
        let result = wa
            .finish_authentication(&state, &response, &legacy)
            .unwrap();
        assert!(!result.user_verification_eligible);
        let mut wrong = bytes(authentication, "signature");
        *wrong.last_mut().unwrap() ^= 1;
        response.response.signature = URL_SAFE_NO_PAD.encode(wrong);
        assert!(
            matches!(
                wa.finish_authentication(&state, &response, &credential),
                Err(Error::BadSignature)
            ),
            "{name}"
        );
    }
}
