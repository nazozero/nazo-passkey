//! Public-API regressions for attacker-controlled CBOR and authenticator data.
//! The positive baseline is a real P-256 public point; no random byte strings
//! masquerade as credential keys in registration tests.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::value::Value;
use passkey_auth::{RegistrationResponse, RegistrationState, Webauthn};
use sha2::{Digest, Sha256};

const CREDENTIAL_ID: &[u8] = b"binary-regression-credential";

fn key() -> Value {
    let signing = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    Value::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        ((-2).into(), Value::Bytes(point.x().unwrap().to_vec())),
        ((-3).into(), Value::Bytes(point.y().unwrap().to_vec())),
    ])
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}

fn auth_data(cose: &[u8], flags: u8, extension: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(b"example.com").to_vec();
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&(CREDENTIAL_ID.len() as u16).to_be_bytes());
    out.extend_from_slice(CREDENTIAL_ID);
    out.extend_from_slice(cose);
    out.extend_from_slice(extension);
    out
}

fn envelope(ad: &[u8], statement: Value) -> Value {
    Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), statement),
        (Value::Text("authData".into()), Value::Bytes(ad.to_vec())),
    ])
}

fn fixture() -> (Webauthn, RegistrationState, RegistrationResponse, Vec<u8>) {
    let wa = Webauthn::new("example.com", "Test", "https://example.com").strict_base64(true);
    let (challenge, state) = wa.start_registration(b"user", "alice", "Alice", &[]);
    let client_data = serde_json::json!({
        "type": "webauthn.create", "challenge": challenge.challenge,
        "origin": "https://example.com", "crossOrigin": false,
    });
    let ad = auth_data(&encode(&key()), 0x45, &[]);
    let response = RegistrationResponse {
        id: B64.encode(CREDENTIAL_ID),
        transports: vec![],
        client_data_json: B64.encode(serde_json::to_vec(&client_data).unwrap()),
        attestation_object: B64.encode(encode(&envelope(&ad, Value::Map(vec![])))),
    };
    (wa, state, response, ad)
}

#[test]
fn canonical_none_registration_is_valid() {
    let (wa, state, response, _) = fixture();
    let stored = wa.finish_registration(&state, &response).unwrap();
    assert_eq!(stored.id.as_bytes(), CREDENTIAL_ID);
    assert_eq!(stored.public_key_cose.as_bytes(), encode(&key()));
}

#[test]
fn none_requires_present_empty_map() {
    let (wa, state, mut response, ad) = fixture();
    for statement in [
        Value::Map(vec![("sig".into(), Value::Bytes(vec![1]))]),
        Value::Array(vec![]),
        Value::Null,
    ] {
        response.attestation_object = B64.encode(encode(&envelope(&ad, statement)));
        assert!(wa.finish_registration(&state, &response).is_err());
    }
    let Value::Map(mut fields) = envelope(&ad, Value::Map(vec![])) else {
        unreachable!()
    };
    fields.remove(1);
    response.attestation_object = B64.encode(encode(&Value::Map(fields)));
    assert!(wa.finish_registration(&state, &response).is_err());
}

#[test]
fn duplicate_envelope_keys_and_trailing_items_are_rejected() {
    let (wa, state, mut response, ad) = fixture();
    let Value::Map(fields) = envelope(&ad, Value::Map(vec![])) else {
        unreachable!()
    };
    for position in 0..3 {
        let mut duplicate = fields.clone();
        duplicate.insert(position, fields[position].clone());
        response.attestation_object = B64.encode(encode(&Value::Map(duplicate)));
        assert!(wa.finish_registration(&state, &response).is_err());
    }
    let mut trailing = encode(&Value::Map(fields));
    trailing.push(0);
    response.attestation_object = B64.encode(trailing);
    assert!(wa.finish_registration(&state, &response).is_err());
}

#[test]
fn algorithm_and_label_integer_overflow_cannot_alias_negative_values() {
    let (wa, state, mut response, _) = fixture();
    for index in [1, 2] {
        let Value::Map(mut fields) = key() else {
            unreachable!()
        };
        if index == 1 {
            fields[index].1 = Value::Integer((u64::MAX - 6).into());
        } else {
            fields[index].0 = Value::Integer(u64::MAX.into());
        }
        let ad = auth_data(&encode(&Value::Map(fields)), 0x45, &[]);
        response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
        assert!(wa.finish_registration(&state, &response).is_err());
    }
}

#[test]
fn invalid_points_and_private_or_optional_parameters_do_not_register() {
    let (wa, state, mut response, _) = fixture();
    let Value::Map(fields) = key() else {
        unreachable!()
    };
    let mut candidates = Vec::new();
    let mut zero_point = fields.clone();
    zero_point[3].1 = Value::Bytes(vec![0; 32]);
    zero_point[4].1 = Value::Bytes(vec![0; 32]);
    candidates.push(Value::Map(zero_point));
    let mut private = fields.clone();
    private.push(((-4).into(), Value::Bytes(vec![1; 32])));
    candidates.push(Value::Map(private));
    let mut optional = fields;
    optional.insert(1, (2.into(), Value::Bytes(vec![1])));
    candidates.push(Value::Map(optional));
    // Ed25519 identity and low-order points must not create inert or forgeable credentials.
    for encoded in [vec![0; 32], {
        let mut point = vec![0; 32];
        point[0] = 1;
        point
    }] {
        candidates.push(Value::Map(vec![
            (1.into(), 1.into()),
            (3.into(), (-8).into()),
            ((-1).into(), 6.into()),
            ((-2).into(), Value::Bytes(encoded)),
        ]));
    }
    for candidate in candidates {
        let ad = auth_data(&encode(&candidate), 0x45, &[]);
        response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
        assert!(wa.finish_registration(&state, &response).is_err());
    }
}

#[test]
fn extension_and_backup_flags_have_complete_framing() {
    let (wa, state, mut response, _) = fixture();
    for (flags, extension) in [
        (0xc5, &[][..]),
        (0xc5, &[0x80][..]),
        (0xc5, &[0xa0, 0][..]),
        (0x45, &[0xa0][..]),
        (0x55, &[][..]),
    ] {
        let ad = auth_data(&encode(&key()), flags, extension);
        response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
        assert!(wa.finish_registration(&state, &response).is_err());
    }
    let ad = auth_data(&encode(&key()), 0xdd, &[0xa0]);
    response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
    assert!(wa.finish_registration(&state, &response).is_ok());
}

#[test]
fn every_truncated_envelope_is_rejected_without_panic() {
    let (wa, state, mut response, _) = fixture();
    let complete = B64.decode(&response.attestation_object).unwrap();
    for length in 0..complete.len() {
        response.attestation_object = B64.encode(&complete[..length]);
        assert!(
            wa.finish_registration(&state, &response).is_err(),
            "prefix length {length}"
        );
    }
}

#[test]
fn excessive_nesting_and_noncanonical_encodings_are_rejected() {
    let (wa, state, mut response, _) = fixture();
    let mut deeply_nested = vec![0xa1, 0x61, b'x'];
    deeply_nested.extend_from_slice(&[0x81; 20]);
    deeply_nested.push(0);
    let ad = auth_data(&encode(&key()), 0xc5, &deeply_nested);
    response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
    assert!(wa.finish_registration(&state, &response).is_err());
    let mut cose = encode(&key());
    cose.splice(1..2, [0x18, 0x01]);
    let ad = auth_data(&cose, 0x45, &[]);
    response.attestation_object = B64.encode(encode(&envelope(&ad, Value::Map(vec![]))));
    assert!(wa.finish_registration(&state, &response).is_err());
}
