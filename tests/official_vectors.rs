//! Unmodified byte vectors from W3C WebAuthn Level 3, REC 2026-08-25 §16.
//! Fixture provenance and document license are in fixtures/README.md.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value as CborValue;
use nazo_passkey::{
    AssertionResponse, AttestationConveyancePreference, AttestationEvidence, AttestationResponse,
    AuthenticationResponse, Challenge, CredentialId, Error, RegistrationOptions,
    RegistrationResponse, Webauthn,
};
use serde_json::Value;

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}

#[test]
fn official_attestation_evidence_is_independent_of_requested_conveyance() {
    let vectors: Value = serde_json::from_str(include_str!("fixtures/w3c-level3.json")).unwrap();
    let wa = Webauthn::new("example.org", "W3C vectors", "https://example.org");
    for (name, expected) in [
        ("none-es256", AttestationEvidence::None),
        ("packed-self-es256", AttestationEvidence::SelfAttestation),
        ("packed-es256", AttestationEvidence::UntrustedCertificate),
        ("packed-eddsa", AttestationEvidence::UntrustedCertificate),
        ("fido-u2f-es256", AttestationEvidence::UntrustedCertificate),
    ] {
        let vector = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap();
        let registration = &vector["registration"];
        let encoded = bytes(registration, "attestationObject");
        let attestation: CborValue = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        let field = |name| {
            &attestation
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_text() == Some(name))
                .unwrap()
                .1
        };
        let format = field("fmt").as_text().unwrap();
        let auth_data = field("authData").as_bytes().unwrap();
        let chain: Vec<&[u8]> = field("attStmt")
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| key.as_text() == Some("x5c"))
            .map(|(_, chain)| {
                chain
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|cert| cert.as_bytes().unwrap().as_slice())
                    .collect()
            })
            .unwrap_or_default();
        let response = RegistrationResponse {
            id: CredentialId(bytes(registration, "credential_id")),
            response: AttestationResponse {
                transports: vec![],
                attestation_object: URL_SAFE_NO_PAD.encode(&encoded),
                client_data_json: URL_SAFE_NO_PAD.encode(bytes(registration, "clientDataJSON")),
            },
        };
        for conveyance in [
            AttestationConveyancePreference::None,
            AttestationConveyancePreference::Direct,
        ] {
            let (options, mut state) = wa.start_registration(
                b"w3c-test-user",
                "user",
                "User",
                &[],
                RegistrationOptions {
                    attestation: conveyance,
                    ..Default::default()
                },
            );
            assert_eq!(options.attestation, conveyance);
            state.challenge = Challenge(bytes(registration, "challenge"));
            let mut inspected = false;
            let credential = wa
                .finish_registration_with_attestation(&state, &response, |verified| {
                    inspected = true;
                    assert_eq!(verified.evidence, expected, "{name}");
                    assert_eq!(verified.format, format, "{name}");
                    assert_eq!(verified.aaguid.as_slice(), &auth_data[37..53], "{name}");
                    assert_eq!(verified.certificate_chain, chain.as_slice(), "{name}");
                    Ok(())
                })
                .unwrap_or_else(|error| panic!("{name}/{conveyance:?}: {error:?}"));
            assert!(inspected, "{name}");
            assert_eq!(credential.attestation, expected, "{name}");

            if conveyance == AttestationConveyancePreference::Direct {
                // A provenance policy can reject any otherwise valid evidence,
                // including a browser's none response to a direct request.
                assert!(matches!(
                    wa.finish_registration_with_attestation(&state, &response, |_| {
                        Err(Error::AttestationRejected)
                    }),
                    Err(Error::AttestationRejected)
                ));
            }
        }
    }
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
        let (_, mut state) = wa.start_registration(
            b"w3c-test-user",
            "user",
            "User",
            &[],
            Default::default(),
        );
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
