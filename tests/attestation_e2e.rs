//! End-to-end tests for `packed (x5c)` and `fido-u2f` attestation.
//!
//! Both formats verify the attestation `sig` against the public key
//! of a real X.509 certificate. The tests here synthesise a P-256
//! self-signed cert at runtime using `x509-cert`'s builder, then
//! drive a full registration through the public Webauthn API.
//!
//! These tests complement (do NOT duplicate) the ones in
//! `tests/ceremony_e2e.rs`, which exercises `fmt: "none"` only.

use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as CborValue;
use p256::ecdsa::{Signature as EsSig, SigningKey, signature::Signer};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert::builder::{Builder, CertificateBuilder, profile::BuilderProfile};
use x509_cert::der::asn1::OctetString;
use x509_cert::der::{Encode, oid::AssociatedOid};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::{Criticality, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

// ---------- AAGUID extension (custom) ----------------------------------------

/// Thin wrapper that implements x509-cert's ToExtension trait so we can
/// add the FIDO AAGUID extension to a synthetic cert. The on-wire shape
/// is OCTET STRING (16 bytes); the outer OCTET STRING wrapping is done
/// automatically by ToExtension::to_extension.
#[derive(Clone, Debug)]
struct FidoAaguid([u8; 16]);

impl AssociatedOid for FidoAaguid {
    const OID: x509_cert::der::oid::ObjectIdentifier =
        x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
}

impl x509_cert::der::Encode for FidoAaguid {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        OctetString::new(self.0.to_vec()).unwrap().encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        OctetString::new(self.0.to_vec()).unwrap().encode(encoder)
    }
}

impl Criticality for FidoAaguid {
    fn criticality(&self, _subject: &Name, _exts: &[Extension]) -> bool {
        false
    }
}

/// Deliberately malformed AAGUID extension. Encodes the wrong shape -
/// we use this in a regression test for the "malformed extension is
/// rejected" path. The bytes here are NOT a valid DER OCTET STRING of
/// 16 bytes; the inner tag/length is junk.
#[derive(Clone, Debug)]
struct MalformedAaguid;

impl AssociatedOid for MalformedAaguid {
    const OID: x509_cert::der::oid::ObjectIdentifier =
        x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
}

impl x509_cert::der::Encode for MalformedAaguid {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        // 7 bytes of attacker-chosen junk inside the outer OCTET STRING.
        OctetString::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22])
            .unwrap()
            .encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        OctetString::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22])
            .unwrap()
            .encode(encoder)
    }
}

impl Criticality for MalformedAaguid {
    fn criticality(&self, _subject: &Name, _exts: &[Extension]) -> bool {
        false
    }
}

use nazo_passkey::{RegistrationResponse, Webauthn};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

struct TestProfile(Name);
impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _: &Name) -> Name {
        self.0.clone()
    }
    fn get_subject(&self) -> Name {
        self.0.clone()
    }
    fn build_extensions(
        &self,
        _: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _: &x509_cert::certificate::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

// ---------- cert + key bundle ----------------------------------------------

/// A fresh P-256 keypair plus a self-signed DER cert for that key.
/// Used as the attestation cert in tests.
struct CertBundle {
    signing_key: SigningKey,
    cert_der: Vec<u8>,
}

/// Which AAGUID extension (if any) to embed in the test cert.
#[derive(Clone, Copy)]
enum AaguidExt {
    /// No FIDO AAGUID extension on the cert.
    None,
    /// Well-formed extension carrying the given 16 bytes.
    Valid([u8; 16]),
    /// Extension OID is present but the inner OCTET STRING is junk.
    /// Used to test the "must not silently swallow malformed extensions"
    /// path.
    Malformed,
}

impl CertBundle {
    /// Mint a fresh self-signed leaf cert with the requested AAGUID
    /// extension shape.
    fn new(aaguid: AaguidExt) -> Self {
        let signing_key = SigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // SubjectPublicKeyInfo for the verifying key, in PKCS8/SEC1 form.
        let pk_der = p256::PublicKey::from(verifying_key)
            .to_public_key_der()
            .expect("p256 pubkey to DER")
            .as_bytes()
            .to_vec();
        let spki =
            SubjectPublicKeyInfoOwned::try_from(pk_der.as_slice()).expect("SPKI from p256 DER");

        let subject = Name::from_str("C=US,O=Passkey Auth Tests,OU=Authenticator Attestation,CN=passkey-auth test attestation")
            .expect("name parse")
            .to_der()
            .expect("name to DER");
        let subject = Name::from_der_slice(&subject);

        // Keep the profile minimal; packed-required subject fields and
        // BasicConstraints are added explicitly for these test certificates.
        let profile = TestProfile(subject);
        let mut builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(60 * 60)).expect("validity"),
            spki,
        )
        .expect("CertificateBuilder::new");

        builder
            .add_extension(&BasicConstraints {
                ca: false,
                path_len_constraint: None,
            })
            .expect("add basic constraints");

        // Add the FIDO AAGUID extension if requested. ToExtension on
        // FidoAaguid handles the double OCTET STRING wrapping the spec
        // requires (outer wrap done by ToExtension::to_extension, inner
        // wrap done by our Encode impl).
        match aaguid {
            AaguidExt::None => {}
            AaguidExt::Valid(value) => {
                builder
                    .add_extension(&FidoAaguid(value))
                    .expect("add aaguid ext");
            }
            AaguidExt::Malformed => {
                builder
                    .add_extension(&MalformedAaguid)
                    .expect("add malformed aaguid ext");
            }
        }

        let cert: x509_cert::Certificate = builder
            .build::<_, p256::ecdsa::DerSignature>(&signing_key)
            .expect("cert build");
        let cert_der = cert.to_der().expect("cert to DER");

        Self {
            signing_key,
            cert_der,
        }
    }
}

// Tiny shim because x509-cert's `from_der` returns a Result we
// always unwrap in this test file.
trait FromDerSlice: Sized {
    fn from_der_slice(der: &[u8]) -> Self;
}
impl FromDerSlice for Name {
    fn from_der_slice(der: &[u8]) -> Self {
        use x509_cert::der::Decode;
        Self::from_der(der).expect("Name from DER")
    }
}

// ---------- credential keypair (the one embedded in authData) --------------

/// The credential's own keypair, separate from the attestation cert's.
/// In `packed-x5c` they are different; in `fido-u2f` they are different too.
///
/// The signing key is used for real packed self-attestation signatures.
struct CredKey {
    signing_key: SigningKey,
    x: [u8; 32],
    y: [u8; 32],
}

impl CredKey {
    fn new() -> Self {
        let signing_key = SigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let vk = signing_key.verifying_key();
        let pt = vk.to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pt.x().unwrap()[..]);
        y.copy_from_slice(&pt.y().unwrap()[..]);
        Self { signing_key, x, y }
    }

    fn cose_pubkey(&self) -> Vec<u8> {
        // COSE_Key for ES256: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(self.x.to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(self.y.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }
}

// ---------- authenticator helpers ------------------------------------------

fn auth_data_register(rp_id: &str, aaguid: [u8; 16], cred_id: &[u8], cose_pk: &[u8]) -> Vec<u8> {
    const FLAG_UP: u8 = 1 << 0;
    const FLAG_UV: u8 = 1 << 2;
    const FLAG_AT: u8 = 1 << 6;
    let mut buf = Vec::new();
    buf.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    buf.push(FLAG_UP | FLAG_UV | FLAG_AT);
    buf.extend_from_slice(&0u32.to_be_bytes()); // counter
    buf.extend_from_slice(&aaguid);
    buf.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(cred_id);
    buf.extend_from_slice(cose_pk);
    buf
}

fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> (Vec<u8>, String) {
    let json = format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    );
    let raw = json.into_bytes();
    let enc = B64URL.encode(&raw);
    (raw, enc)
}

// ---------- packed-x5c tests -----------------------------------------------

#[test]
fn packed_x5c_happy_path() {
    let aaguid: [u8; 16] = *b"yubico-test-0001";
    let cert = CertBundle::new(AaguidExt::Valid(aaguid));
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0001";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // Build the packed attestation statement signed by the CERT key
    // (not the credential key) over authData || SHA256(clientDataJSON).
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec!["usb".into()],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let credential = wa
        .finish_registration(&state, &response)
        .expect("packed-x5c registration must succeed");
    assert_eq!(credential.aaguid, aaguid);
}

#[test]
fn packed_x5c_aaguid_mismatch_rejected() {
    let cert_aaguid: [u8; 16] = *b"yubico-test-0001";
    let auth_aaguid: [u8; 16] = *b"different-aaguid";
    let cert = CertBundle::new(AaguidExt::Valid(cert_aaguid));
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0002";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, auth_aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("AAGUID mismatch must reject");
    let msg = err.to_string();
    assert!(msg.contains("AAGUID"), "expected AAGUID error, got: {msg}",);
}

#[test]
fn packed_x5c_bad_signature_rejected() {
    let aaguid: [u8; 16] = *b"yubico-test-0001";
    let cert = CertBundle::new(AaguidExt::Valid(aaguid));
    let _wrong_cert = CertBundle::new(AaguidExt::Valid(aaguid)); // different key
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0003";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    // Sign with the WRONG key (the other cert's key), so the x5c
    // public key will not verify.
    let sig: EsSig = _wrong_cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("bad x5c sig must reject");
    assert!(matches!(err, nazo_passkey::Error::BadSignature,));
}

// ---------- fido-u2f tests -------------------------------------------------

#[test]
fn fido_u2f_happy_path() {
    let cert = CertBundle::new(AaguidExt::None); // U2F format does NOT include AAGUID ext
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-u2f-0001";
    let cose_pk = cred.cose_pubkey();
    let aaguid = [0u8; 16]; // U2F authenticators always emit zero AAGUID
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // U2F pre-image: 0x00 || rpIdHash || cdjHash || credId || pubKey-SEC1
    let mut pre_image = Vec::new();
    pre_image.push(0x00);
    pre_image.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    pre_image.extend_from_slice(&Sha256::digest(&cdj_raw));
    pre_image.extend_from_slice(cred_id);
    pre_image.push(0x04);
    pre_image.extend_from_slice(&cred.x);
    pre_image.extend_from_slice(&cred.y);

    let sig: EsSig = cert.signing_key.sign(&pre_image);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("fido-u2f".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec!["usb".into()],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let credential = wa
        .finish_registration(&state, &response)
        .expect("fido-u2f registration must succeed");
    assert_eq!(credential.id.as_bytes(), cred_id);
}

#[test]
fn fido_u2f_wrong_credential_pubkey_rejected() {
    let cert = CertBundle::new(AaguidExt::None);
    let real_cred = CredKey::new();
    let bogus_cred = CredKey::new(); // we'll sign the U2F pre-image with the bogus pubkey
    let cred_id: &[u8] = b"cred-u2f-0002";
    // authData carries the REAL credential public key...
    let cose_pk = real_cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, [0u8; 16], cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // ...but we sign over the WRONG pubkey, simulating tampering.
    let mut pre_image = Vec::new();
    pre_image.push(0x00);
    pre_image.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    pre_image.extend_from_slice(&Sha256::digest(&cdj_raw));
    pre_image.extend_from_slice(cred_id);
    pre_image.push(0x04);
    pre_image.extend_from_slice(&bogus_cred.x);
    pre_image.extend_from_slice(&bogus_cred.y);
    let sig: EsSig = cert.signing_key.sign(&pre_image);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("fido-u2f".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    assert!(wa.finish_registration(&state, &response).is_err());
}

// ---------- regression test for malformed AAGUID extension ------------------

/// Without the fix this catches, a cert containing an AAGUID extension
/// whose inner OCTET STRING is junk would parse as "no AAGUID extension"
/// and skip the cert-vs-authData AAGUID match check in verify_packed -
/// letting a malicious cert claim ANY authData AAGUID despite carrying
/// a contradictory one of its own.
///
/// The fix in src/x509.rs propagates the parse error instead of using
/// `.ok()`. This test signs a packed attestation with a cert that
/// carries the AAGUID extension OID but a deliberately-broken inner
/// value, and asserts the registration is rejected outright rather
/// than silently treated as if the extension were absent.
#[test]
fn packed_x5c_malformed_aaguid_rejected() {
    let cert = CertBundle::new(AaguidExt::Malformed);
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-malformed-aaguid";
    let cose_pk = cred.cose_pubkey();
    // authData carries SOME AAGUID. The malformed extension means we
    // cannot tell if it matches; the parser must refuse rather than
    // silently accept.
    let auth_data = auth_data_register(RP_ID, *b"any-authd-aaguid", cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("malformed AAGUID extension must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("AAGUID") || msg.contains("malformed"),
        "expected malformed/AAGUID error, got: {msg}",
    );
}

// ---------- certificate profile and format-confusion regressions -----------

// Mutable DER fixtures let negative tests construct invalid certificates while
// x509-cert keeps the production certificate model immutable. Parsing and
// encoding still use RustCrypto DER; these types never enter the library.
#[derive(x509_cert::der::Sequence)]
struct CertificateFixture {
    tbs_certificate: TbsCertificateFixture,
    signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    signature: x509_cert::der::asn1::BitString,
}

#[derive(x509_cert::der::Sequence)]
struct TbsCertificateFixture {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: x509_cert::certificate::Version,
    serial_number: SerialNumber,
    signature: x509_cert::spki::AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<x509_cert::der::asn1::BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<x509_cert::der::asn1::BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

impl CertBundle {
    /// Attestation verification does not authenticate the certificate issuer.
    /// Mutating a certificate's profile does not change the key that signs the
    /// attestation, which isolates these checks from the signature check.
    fn modify(&mut self, change: impl FnOnce(&mut CertificateFixture)) {
        use x509_cert::der::{Decode, Encode};
        let mut certificate = CertificateFixture::from_der(&self.cert_der).unwrap();
        change(&mut certificate);
        self.cert_der = certificate.to_der().unwrap();
    }

    fn add_raw_extension(&mut self, oid: &str, critical: bool, value: &[u8]) {
        self.modify(|certificate| {
            certificate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(x509_cert::ext::Extension {
                    extn_id: const_oid::ObjectIdentifier::new(oid).unwrap(),
                    critical,
                    extn_value: x509_cert::der::asn1::OctetString::new(value.to_vec()).unwrap(),
                });
        });
    }
}

fn registration_with_chain(
    format: &str,
    cert: &CertBundle,
    chain: Vec<Vec<u8>>,
    aaguid: [u8; 16],
) -> (
    Webauthn,
    nazo_passkey::RegistrationState,
    RegistrationResponse,
) {
    let credential = CredKey::new();
    let auth_data = auth_data_register(
        RP_ID,
        aaguid,
        b"profile-regression",
        &credential.cose_pubkey(),
    );
    let wa = Webauthn::new(RP_ID, "Test", ORIGIN).strict_base64(true);
    let (challenge, state) = wa.start_registration(b"user", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &challenge.challenge, ORIGIN);
    let mut message = Vec::new();
    if format == "fido-u2f" {
        message.push(0);
        message.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        message.extend_from_slice(&Sha256::digest(&cdj_raw));
        message.extend_from_slice(b"profile-regression");
        message.push(4);
        message.extend_from_slice(&credential.x);
        message.extend_from_slice(&credential.y);
    } else {
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(&Sha256::digest(&cdj_raw));
    }
    let signature: EsSig = cert.signing_key.sign(&message);
    let mut statement = Vec::new();
    if format == "packed" {
        statement.push((CborValue::Text("alg".into()), (-7).into()));
    }
    statement.push((
        CborValue::Text("sig".into()),
        CborValue::Bytes(signature.to_der().as_bytes().to_vec()),
    ));
    statement.push((
        CborValue::Text("x5c".into()),
        CborValue::Array(chain.into_iter().map(CborValue::Bytes).collect()),
    ));
    let envelope = CborValue::Map(vec![
        ("fmt".into(), format.into()),
        ("attStmt".into(), CborValue::Map(statement)),
        ("authData".into(), CborValue::Bytes(auth_data)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut bytes).unwrap();
    let response = RegistrationResponse {
        id: B64URL.encode(b"profile-regression"),
        transports: vec![],
        attestation_object: B64URL.encode(bytes),
        client_data_json: cdj_b64,
    };
    (wa, state, response)
}

#[test]
fn packed_certificate_subject_version_and_constraints_are_checked() {
    use x509_cert::certificate::Version;
    use x509_cert::der::asn1::OctetString;
    use x509_cert::name::Name;
    let cases: [fn(&mut CertificateFixture); 7] = [
        |cert| cert.tbs_certificate.version = Version::V2,
        |cert| cert.tbs_certificate.subject = Name::from_str("CN=Only Common Name").unwrap(),
        |cert| {
            cert.tbs_certificate.subject =
                Name::from_str("C=US,O=Tests,OU=Wrong Unit,CN=Test").unwrap()
        },
        |cert| {
            cert.tbs_certificate.subject =
                Name::from_str("C=USA,O=Tests,OU=Authenticator Attestation,CN=Test").unwrap()
        },
        |cert| cert.tbs_certificate.extensions.as_mut().unwrap().clear(),
        |cert| {
            let extension = cert
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .first_mut()
                .unwrap();
            extension.extn_value = OctetString::new(
                BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                }
                .to_der()
                .unwrap(),
            )
            .unwrap();
        },
        |cert| {
            let extension = cert
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .first_mut()
                .unwrap();
            extension.extn_value = OctetString::new(
                BasicConstraints {
                    ca: false,
                    path_len_constraint: Some(0),
                }
                .to_der()
                .unwrap(),
            )
            .unwrap();
        },
    ];
    for (index, change) in cases.into_iter().enumerate() {
        let mut cert = CertBundle::new(AaguidExt::None);
        cert.modify(change);
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        assert!(
            wa.finish_registration(&state, &response).is_err(),
            "certificate case {index}"
        );
    }
}

#[test]
fn packed_country_is_structural_and_does_not_claim_vendor_jurisdiction() {
    let mut cert = CertBundle::new(AaguidExt::None);
    // ISO 3166 permits private-use codes such as AA (also used by the W3C
    // vectors). Reserved/historical country names do not prove current
    // legal incorporation, and this verifier does not authenticate issuers.
    for code in ["US", "GB", "AA", "ZZ", "UK", "BU"] {
        cert.modify(|certificate| {
            certificate.tbs_certificate.subject = x509_cert::name::Name::from_str(&format!(
                "C={code},O=Tests,OU=Authenticator Attestation,CN=Test"
            ))
            .unwrap();
        });
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        let credential = wa.finish_registration(&state, &response).unwrap();
        assert_eq!(
            credential.attestation,
            nazo_passkey::AttestationEvidence::UntrustedCertificate
        );
    }
    for code in ["USX", "us", "U1"] {
        cert.modify(|certificate| {
            certificate.tbs_certificate.subject = x509_cert::name::Name::from_str(&format!(
                "C={code},O=Tests,OU=Authenticator Attestation,CN=Test"
            ))
            .unwrap();
        });
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        let error = wa.finish_registration(&state, &response).unwrap_err();
        assert!(error.to_string().contains("country"), "{code}: {error}");
    }
}

#[test]
fn packed_aaguid_extension_cannot_be_critical_or_duplicated() {
    for duplicate in [false, true] {
        let mut cert = CertBundle::new(AaguidExt::Valid([0; 16]));
        cert.modify(|certificate| {
            let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
            let index = extensions
                .iter()
                .position(|e| {
                    e.extn_id == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4")
                })
                .unwrap();
            if duplicate {
                extensions.push(extensions[index].clone());
            } else {
                extensions[index].critical = true;
            }
        });
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        assert!(wa.finish_registration(&state, &response).is_err());
    }
}

#[test]
fn packed_firmware_version_accepts_nonnegative_der_integers() {
    let versions: [&[u8]; 6] = [
        &[0x02, 0x01, 0x00], // Zero is a valid non-negative version.
        &[0x02, 0x01, 0x2a], // The WebAuthn Level 3 certificate example uses 42.
        &[0x02, 0x01, 0x7f],
        &[0x02, 0x02, 0x00, 0x80], // Positive 128 needs a sign-padding byte.
        &[
            0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        &[
            0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ], // 2^64
    ];
    for (index, version) in versions.into_iter().enumerate() {
        let mut cert = CertBundle::new(AaguidExt::None);
        cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.5", false, version);
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        let credential = wa
            .finish_registration(&state, &response)
            .unwrap_or_else(|error| panic!("firmware case {index}: {error}"));
        assert_eq!(
            credential.attestation,
            nazo_passkey::AttestationEvidence::UntrustedCertificate
        );
    }
}

#[test]
fn packed_firmware_version_rejects_invalid_der() {
    let versions: [(&str, &[u8]); 10] = [
        ("negative one", &[0x02, 0x01, 0xff]),
        ("negative 128", &[0x02, 0x01, 0x80]),
        ("wrong tag", &[0x04, 0x01, 0x00]),
        ("missing INTEGER", &[]),
        ("empty INTEGER", &[0x02, 0x00]),
        ("redundant sign padding", &[0x02, 0x02, 0x00, 0x01]),
        ("nonminimal length", &[0x02, 0x81, 0x01, 0x00]),
        ("indefinite length", &[0x02, 0x80, 0x00, 0x00]),
        ("truncated value", &[0x02, 0x02, 0x01]),
        ("trailing value", &[0x02, 0x01, 0x00, 0x05, 0x00]),
    ];
    for (name, version) in versions {
        let mut cert = CertBundle::new(AaguidExt::None);
        cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.5", false, version);
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        assert!(
            matches!(
                wa.finish_registration(&state, &response),
                Err(nazo_passkey::Error::Cbor(message))
                    if message == "firmware version must be a non-negative DER INTEGER"
            ),
            "invalid firmware encoding: {name}"
        );
    }
}

#[test]
fn packed_firmware_version_cannot_be_critical_or_duplicated() {
    for duplicate in [false, true] {
        let mut cert = CertBundle::new(AaguidExt::None);
        cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.5", !duplicate, &[0x02, 0x01, 0x2a]);
        if duplicate {
            cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.5", false, &[0x02, 0x01, 0x2b]);
        }
        let (wa, state, response) =
            registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
        let expected = if duplicate {
            "duplicate X.509 extension"
        } else {
            "firmware version extension must not be critical"
        };
        assert!(matches!(
            wa.finish_registration(&state, &response),
            Err(nazo_passkey::Error::Cbor(message)) if message == expected
        ));
    }
}

#[test]
fn ordinary_packed_attestation_rejects_enterprise_serial_numbers() {
    for critical in [false, true] {
        for value in [&[0x04, 0x03, 0x01, 0x02, 0x03][..], &[][..]] {
            let mut cert = CertBundle::new(AaguidExt::None);
            // Even a well-formed, noncritical device serial is forbidden:
            // this RP has not requested or authorized enterprise attestation.
            cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.2", critical, value);
            let (wa, state, response) =
                registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
            assert!(matches!(
                wa.finish_registration(&state, &response),
                Err(nazo_passkey::Error::Cbor(message))
                    if message == "enterprise serial number attestation is not enabled"
            ));
        }
    }
}

#[test]
fn excluded_registration_still_verifies_packed_signature_and_certificate() {
    let mut cert = CertBundle::new(AaguidExt::None);
    let (wa, mut state, mut response) =
        registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
    state.exclude_credentials.push(nazo_passkey::CredentialId(
        B64URL.decode(&response.id).unwrap(),
    ));
    assert!(matches!(
        wa.finish_registration(&state, &response),
        Err(nazo_passkey::Error::CredentialExcluded)
    ));

    let bytes = B64URL.decode(&response.attestation_object).unwrap();
    let original: CborValue = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    // A real, correctly encoded ECDSA signature over the wrong transcript
    // must remain a verification failure, not become a duplicate conflict.
    let wrong_signature: EsSig = cert.signing_key.sign(b"not the registration transcript");
    let mut envelope = original.clone();
    let CborValue::Map(fields) = &mut envelope else {
        unreachable!()
    };
    let (_, CborValue::Map(statement)) = &mut fields[1] else {
        unreachable!()
    };
    statement[1].1 = CborValue::Bytes(wrong_signature.to_der().as_bytes().to_vec());
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut bytes).unwrap();
    response.attestation_object = B64URL.encode(bytes);
    assert!(matches!(
        wa.finish_registration(&state, &response),
        Err(nazo_passkey::Error::BadSignature)
    ));

    // Restore the valid statement signature and keep the same credential,
    // challenge, outer ID and certificate key. Only the leaf profile changes.
    cert.add_raw_extension("1.3.6.1.4.1.45724.1.1.5", true, &[0x02, 0x01, 0x2a]);
    let mut envelope = original;
    let CborValue::Map(fields) = &mut envelope else {
        unreachable!()
    };
    let (_, CborValue::Map(statement)) = &mut fields[1] else {
        unreachable!()
    };
    statement[2].1 = CborValue::Array(vec![CborValue::Bytes(cert.cert_der)]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut bytes).unwrap();
    response.attestation_object = B64URL.encode(bytes);
    assert!(matches!(
        wa.finish_registration(&state, &response),
        Err(nazo_passkey::Error::Cbor(message))
            if message == "firmware version extension must not be critical"
    ));
}

#[test]
fn certificate_named_curve_is_checked_independently_of_point_length() {
    use x509_cert::der::asn1::Any;
    let mut cert = CertBundle::new(AaguidExt::None);
    cert.modify(|certificate| {
        let p384 = const_oid::ObjectIdentifier::new_unwrap("1.3.132.0.34");
        certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(Any::encode_from(&p384).unwrap());
    });
    for format in ["packed", "fido-u2f"] {
        let (wa, state, response) =
            registration_with_chain(format, &cert, vec![cert.cert_der.clone()], [0; 16]);
        assert!(wa.finish_registration(&state, &response).is_err());
    }
}

#[test]
fn compressed_attestation_certificate_points_are_supported_without_trust_promotion() {
    let mut cert = CertBundle::new(AaguidExt::None);
    let compressed = cert.signing_key.verifying_key().to_sec1_point(true);
    cert.modify(|certificate| {
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key =
            x509_cert::der::asn1::BitString::from_bytes(compressed.as_bytes()).unwrap();
    });
    for format in ["packed", "fido-u2f"] {
        let (wa, state, response) =
            registration_with_chain(format, &cert, vec![cert.cert_der.clone()], [0; 16]);
        let credential = wa.finish_registration(&state, &response).unwrap();
        assert_eq!(
            credential.attestation,
            nazo_passkey::AttestationEvidence::UntrustedCertificate
        );
    }
}

#[test]
fn malformed_or_hybrid_attestation_certificate_points_are_rejected() {
    let cert = CertBundle::new(AaguidExt::None);
    let mut hybrid = cert
        .signing_key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    hybrid[0] = 6;
    let mut invalid_compressed = vec![0xff; 33];
    invalid_compressed[0] = 2;
    for point in [vec![0], vec![2; 32], invalid_compressed, hybrid] {
        let mut changed = CertBundle {
            signing_key: cert.signing_key.clone(),
            cert_der: cert.cert_der.clone(),
        };
        changed.modify(|certificate| {
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key = x509_cert::der::asn1::BitString::from_bytes(&point).unwrap();
        });
        for format in ["packed", "fido-u2f"] {
            let (wa, state, response) =
                registration_with_chain(format, &changed, vec![changed.cert_der.clone()], [0; 16]);
            assert!(wa.finish_registration(&state, &response).is_err());
        }
    }
}

#[test]
fn u2f_does_not_apply_the_packed_certificate_profile() {
    let mut cert = CertBundle::new(AaguidExt::Malformed);
    cert.modify(|certificate| {
        certificate.tbs_certificate.subject =
            x509_cert::name::Name::from_str("CN=Legacy U2F Attestation").unwrap();
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|extension| extension.extn_id.to_string() != "2.5.29.19");
    });
    let (wa, state, response) =
        registration_with_chain("fido-u2f", &cert, vec![cert.cert_der.clone()], [0; 16]);
    let credential = wa.finish_registration(&state, &response).unwrap();
    assert_eq!(
        credential.attestation,
        nazo_passkey::AttestationEvidence::UntrustedCertificate
    );
    // The same noncritical extension and subject still fail the packed
    // profile. U2F did not vouch for their semantics or the certificate issuer.
    let (wa, state, response) =
        registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
    assert!(wa.finish_registration(&state, &response).is_err());
}

#[test]
fn chain_length_and_intermediate_der_are_checked() {
    let cert = CertBundle::new(AaguidExt::None);
    for format in ["packed", "fido-u2f"] {
        for chain in [
            Vec::new(),
            vec![cert.cert_der.clone(), vec![1, 2, 3]],
            vec![cert.cert_der.clone(); 9],
        ] {
            let (wa, state, response) = registration_with_chain(format, &cert, chain, [0; 16]);
            assert!(wa.finish_registration(&state, &response).is_err());
        }
    }
    let (wa, state, response) =
        registration_with_chain("fido-u2f", &cert, vec![cert.cert_der.clone(); 2], [0; 16]);
    assert!(wa.finish_registration(&state, &response).is_err());
}

#[test]
fn u2f_nonzero_aaguid_is_not_an_unsupported_extra_requirement() {
    let cert = CertBundle::new(AaguidExt::None);
    let (wa, state, response) =
        registration_with_chain("fido-u2f", &cert, vec![cert.cert_der.clone()], [0x55; 16]);
    let credential = wa.finish_registration(&state, &response).unwrap();
    assert_eq!(
        credential.attestation,
        nazo_passkey::AttestationEvidence::UntrustedCertificate
    );
}

#[test]
fn checked_attestation_signature_does_not_claim_certificate_trust() {
    let cert = CertBundle::new(AaguidExt::None);
    let (wa, state, response) =
        registration_with_chain("packed", &cert, vec![cert.cert_der.clone()], [0; 16]);
    let credential = wa.finish_registration(&state, &response).unwrap();
    assert_eq!(
        credential.attestation,
        nazo_passkey::AttestationEvidence::UntrustedCertificate
    );
}

fn self_attestation_response(
    ed25519: bool,
    mutation: u8,
) -> (
    Webauthn,
    nazo_passkey::RegistrationState,
    RegistrationResponse,
) {
    use ed25519_dalek::Signer as _;
    let ec = CredKey::new();
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let cose = if ed25519 {
        let map = CborValue::Map(vec![
            (1.into(), 1.into()),
            (3.into(), (-8).into()),
            ((-1).into(), 6.into()),
            (
                (-2).into(),
                CborValue::Bytes(ed.verifying_key().to_bytes().to_vec()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut bytes).unwrap();
        bytes
    } else {
        ec.cose_pubkey()
    };
    let auth_data = auth_data_register(RP_ID, [0; 16], b"self-attestation", &cose);
    let wa = Webauthn::new(RP_ID, "Test", ORIGIN).strict_base64(true);
    let (challenge, state) = wa.start_registration(b"user", "alice", "Alice", &[]);
    let (cdj, cdj_encoded) = client_data("webauthn.create", &challenge.challenge, ORIGIN);
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&cdj));
    let mut signature = if ed25519 {
        ed.sign(&message).to_bytes().to_vec()
    } else {
        let signature: EsSig = ec.signing_key.sign(&message);
        signature.to_der().as_bytes().to_vec()
    };
    if mutation == 2 {
        let last = signature.len() - 1;
        signature[last] ^= 1;
    }
    let algorithm = if mutation == 1 {
        if ed25519 { -7 } else { -8 }
    } else if ed25519 {
        -8
    } else {
        -7
    };
    let algorithm_value = if mutation == 5 {
        CborValue::Integer((u64::MAX - 6).into())
    } else {
        algorithm.into()
    };
    let mut statement = vec![
        ("alg".into(), algorithm_value),
        ("sig".into(), CborValue::Bytes(signature)),
    ];
    if mutation == 3 {
        statement.push(("ecdaaKeyId".into(), CborValue::Bytes(vec![1])));
    }
    if mutation == 4 {
        statement.push(("x5c".into(), CborValue::Array(vec![])));
    }
    let envelope = CborValue::Map(vec![
        ("fmt".into(), "packed".into()),
        ("attStmt".into(), CborValue::Map(statement)),
        ("authData".into(), CborValue::Bytes(auth_data)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut bytes).unwrap();
    (
        wa,
        state,
        RegistrationResponse {
            id: B64URL.encode(b"self-attestation"),
            transports: vec![],
            attestation_object: B64URL.encode(bytes),
            client_data_json: cdj_encoded,
        },
    )
}

#[test]
fn es256_self_attestation_uses_the_registered_algorithm_and_real_signature() {
    for mutation in 0..=5 {
        let (wa, state, response) = self_attestation_response(false, mutation);
        let result = wa.finish_registration(&state, &response);
        if mutation == 0 {
            assert_eq!(
                result.unwrap().attestation,
                nazo_passkey::AttestationEvidence::SelfAttestation
            );
        } else {
            assert!(result.is_err(), "mutation {mutation}");
        }
    }
}

#[test]
fn ed25519_self_attestation_uses_the_registered_algorithm_and_real_signature() {
    for mutation in 0..=5 {
        let (wa, state, response) = self_attestation_response(true, mutation);
        let result = wa.finish_registration(&state, &response);
        if mutation == 0 {
            assert_eq!(
                result.unwrap().attestation,
                nazo_passkey::AttestationEvidence::SelfAttestation
            );
        } else {
            assert!(result.is_err(), "mutation {mutation}");
        }
    }
}

#[test]
fn duplicate_attestation_statement_members_are_rejected() {
    let (wa, state, mut response) = self_attestation_response(false, 0);
    let bytes = B64URL.decode(&response.attestation_object).unwrap();
    let envelope: CborValue = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    for position in 0..2 {
        let mut duplicated = envelope.clone();
        let CborValue::Map(fields) = &mut duplicated else {
            unreachable!()
        };
        let (_, CborValue::Map(statement)) = &mut fields[1] else {
            unreachable!()
        };
        statement.insert(position, statement[position].clone());
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&duplicated, &mut bytes).unwrap();
        response.attestation_object = B64URL.encode(bytes);
        assert!(wa.finish_registration(&state, &response).is_err());
    }
}
