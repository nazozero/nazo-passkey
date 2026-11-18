#![no_main]

use std::sync::OnceLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use libfuzzer_sys::fuzz_target;
use nazo_passkey::{
    AssertionResponse, AttestationResponse, AuthenticationResponse, AuthenticationState, Challenge,
    CredentialId, PasskeyCredential, RegistrationResponse, RegistrationState, Webauthn,
};
use serde_json::Value;

const MODES: u8 = 8;
const USER_HANDLE: &[u8] = b"fuzz-user";
const FIXTURE_NAMES: [&str; 5] = [
    "none-es256",
    "packed-self-es256",
    "packed-es256",
    "packed-eddsa",
    "fido-u2f-es256",
];

struct Fixture {
    wa: Webauthn,
    registration: RegistrationState,
    authentication: AuthenticationState,
    discoverable: AuthenticationState,
    credential: PasskeyCredential,
    create_json: String,
    get_json: String,
    signature: String,
    authenticator_data: String,
    attestation: String,
}

fn fixtures() -> &'static [Fixture] {
    static FIXTURES: OnceLock<Vec<Fixture>> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let all: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/w3c-level3.json")).unwrap();
        FIXTURE_NAMES
            .into_iter()
            .map(|name| {
                let vector = all["vectors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["name"] == name)
                    .unwrap();
                let bytes = |part: &str, field: &str| {
                    hex::decode(vector[part][field].as_str().unwrap()).unwrap()
                };
                let wa = Webauthn::new("example.org", "Fuzz", "https://example.org");
                let (_, mut registration) = wa.start_registration(
                    USER_HANDLE,
                    "user",
                    "User",
                    &[],
                    Default::default(),
                );
                registration.challenge = Challenge(bytes("registration", "challenge"));
                let create_json = B64.encode(bytes("registration", "clientDataJSON"));
                let attestation = B64.encode(bytes("registration", "attestationObject"));
                let credential = wa
                    .finish_registration(
                        &registration,
                        &RegistrationResponse {
                            id: CredentialId(bytes("registration", "credential_id")),
                            response: AttestationResponse {
                                transports: vec![],
                                attestation_object: attestation.clone(),
                                client_data_json: create_json.clone(),
                            },
                        },
                    )
                    .unwrap_or_else(|error| panic!("{name} registration fixture: {error}"));
                let (_, mut authentication) = wa.start_authentication_for_user(
                    USER_HANDLE,
                    std::slice::from_ref(&credential.id),
                );
                authentication.challenge = Challenge(bytes("authentication", "challenge"));
                let (_, mut discoverable) = wa.start_authentication(&[]);
                discoverable.challenge = authentication.challenge.clone();
                let get_json = B64.encode(bytes("authentication", "clientDataJSON"));
                let signature = B64.encode(bytes("authentication", "signature"));
                let authenticator_data = B64.encode(bytes("authentication", "authenticatorData"));
                let mut assertion = AuthenticationResponse {
                    id: credential.id.clone(),
                    response: AssertionResponse {
                        authenticator_data: authenticator_data.clone(),
                        signature: signature.clone(),
                        client_data_json: get_json.clone(),
                        user_handle: None,
                    },
                };
                // Fail loudly if a fixture stops reaching real signature verification;
                // never weaken validation merely to increase fuzz coverage.
                wa.finish_authentication(&authentication, &assertion, &credential)
                    .unwrap_or_else(|error| panic!("{name} assertion fixture: {error}"));
                assertion.response.user_handle = Some(USER_HANDLE.to_vec());
                wa.finish_discoverable_authentication(
                    &discoverable,
                    &assertion,
                    &credential,
                    USER_HANDLE,
                )
                .unwrap_or_else(|error| panic!("{name} discoverable fixture: {error}"));
                Fixture {
                    wa,
                    registration,
                    authentication,
                    discoverable,
                    credential,
                    create_json,
                    get_json,
                    signature,
                    authenticator_data,
                    attestation,
                }
            })
            .collect()
    })
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, data)) = input.split_first() else {
        return;
    };
    if data.len() > 65536 {
        return;
    }
    let fixtures = fixtures();
    let f = &fixtures[usize::from(selector / MODES) % fixtures.len()];
    let mode = selector % MODES;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut registration = f.registration.clone();
    registration.created_at = now;
    let mut authentication = f.authentication.clone();
    authentication.created_at = now;
    let mut discoverable = f.discoverable.clone();
    discoverable.created_at = now;
    match mode {
        0 | 1 => {
            let response = RegistrationResponse {
                id: f.credential.id.clone(),
                response: AttestationResponse {
                    transports: vec![],
                    attestation_object: if mode == 0 {
                        B64.encode(data)
                    } else {
                        f.attestation.clone()
                    },
                    client_data_json: if mode == 1 {
                        B64.encode(data)
                    } else {
                        f.create_json.clone()
                    },
                },
            };
            let _ = f.wa.finish_registration(&registration, &response);
        }
        2..=4 | 6 | 7 => {
            let mut credential = f.credential.clone();
            if mode == 3 {
                credential.public_key_cose.0 = data.to_vec();
            }
            let response = AuthenticationResponse {
                id: credential.id.clone(),
                response: AssertionResponse {
                    authenticator_data: if mode == 2 {
                        B64.encode(data)
                    } else {
                        f.authenticator_data.clone()
                    },
                    signature: if mode == 4 {
                        B64.encode(data)
                    } else {
                        f.signature.clone()
                    },
                    client_data_json: if mode == 6 {
                        B64.encode(data)
                    } else {
                        f.get_json.clone()
                    },
                    user_handle: (mode == 7).then(|| data.to_vec()),
                },
            };
            if mode == 7 {
                let _ = f.wa.finish_discoverable_authentication(
                    &discoverable,
                    &response,
                    &credential,
                    USER_HANDLE,
                );
            } else {
                let _ =
                    f.wa.finish_authentication(&authentication, &response, &credential);
            }
        }
        _ => {
            if let Ok(response) = serde_json::from_slice::<AuthenticationResponse>(data) {
                let _ =
                    f.wa.finish_authentication(&authentication, &response, &f.credential);
            }
            if let Ok(response) = serde_json::from_slice::<RegistrationResponse>(data) {
                let _ = f.wa.finish_registration(&registration, &response);
            }
        }
    }
});
