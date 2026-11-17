//! Signature verification - the only crypto operation the server
//! performs during the WebAuthn auth ceremony.
//!
//! Algorithms supported (matching `cose::CoseKey`):
//!   * ES256 (P-256 ECDSA over SHA-256), the universal default
//!   * EdDSA (Ed25519), used by some authenticators (e.g. Yubikey 5+)
//!
//! WebAuthn signs `authenticatorData || SHA-256(clientDataJSON)`. The
//! ES256 signature on the wire is **DER-encoded**, not raw r||s - be
//! careful here.

use ed25519_dalek::{Signature as EdSig, ed25519::signature::MultipartVerifier as _};
#[cfg(test)]
use p256::PublicKey;
use p256::ecdsa::Signature as EsSig;
#[cfg(any(test, not(all(feature = "aws-lc", not(target_family = "wasm")))))]
use p256::ecdsa::VerifyingKey as EsKey;
#[cfg(test)]
use p256::ecdsa::signature::Verifier as _;
#[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

use crate::cose::{CoseKey, check_ed25519_encoding, ed25519_verifying_key};
use crate::error::{Error, Result};

/// Verify `sig` over `msg` using the COSE public key. Returns `Ok(())`
/// on a valid signature; any failure path (wrong key, malformed sig,
/// algorithm mismatch) collapses to [`Error::BadSignature`] so we
/// don't leak which check failed to the wire.
#[cfg(test)]
pub(crate) fn verify(key: &CoseKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    match key {
        CoseKey::Es256 { x, y } => verify_es256(x, y, msg, sig),
        CoseKey::Ed25519 { key } => verify_ed25519(key, &[msg], sig),
    }
}

/// Verify the exact WebAuthn transcript from its two borrowed parts. ES256
/// hashes the parts directly; ordinary Ed25519 signs the complete message,
/// not an Ed25519ph digest.
pub(crate) fn verify_auth_data(
    key: &CoseKey,
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
    sig: &[u8],
) -> Result<()> {
    match key {
        CoseKey::Es256 { x, y } => {
            let mut sec1 = [0; 65];
            sec1[0] = 4;
            sec1[1..33].copy_from_slice(x);
            sec1[33..].copy_from_slice(y);
            let mut digest = Sha256::new();
            digest.update(auth_data);
            digest.update(client_data_hash);
            let digest = digest.finalize();
            #[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
            {
                // Keep identical DER/scalar bounds across backends.
                let _signature = EsSig::from_der(sig).map_err(|_| Error::BadSignature)?;
                // This digest is computed above from the exact local transcript;
                // no caller-supplied hash enters import_less_safe. The public
                // API checks its SHA-256 algorithm and fixed 32-byte length.
                let digest = aws_lc_rs::digest::Digest::import_less_safe(
                    &digest,
                    &aws_lc_rs::digest::SHA256,
                )
                .map_err(|_| Error::BadSignature)?;
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
                    &sec1,
                )
                .verify_digest(&digest, sig)
                .map_err(|_| Error::BadSignature)
            }
            #[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
            {
                let vk = EsKey::from_sec1_bytes(&sec1).map_err(|_| Error::BadSignature)?;
                let signature = EsSig::from_der(sig).map_err(|_| Error::BadSignature)?;
                vk.verify_prehash(&digest, &signature)
                    .map_err(|_| Error::BadSignature)
            }
        }
        CoseKey::Ed25519 { key } => verify_ed25519(key, &[auth_data, client_data_hash], sig),
    }
}

#[cfg(test)]
fn verify_es256(x: &[u8; 32], y: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    #[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
    {
        let mut sec1 = [0; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let _signature = EsSig::from_der(sig).map_err(|_| Error::BadSignature)?;
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
            &sec1,
        )
        .verify(msg, sig)
        .map_err(|_| Error::BadSignature)
    }
    #[cfg(not(all(feature = "aws-lc", not(target_family = "wasm"))))]
    {
        verify_es256_rustcrypto(x, y, msg, sig)
    }
}

#[cfg(test)]
fn verify_es256_rustcrypto(x: &[u8; 32], y: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    // SEC1 uncompressed point: 0x04 || X || Y.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    let pk = PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::BadSignature)?;
    let vk = EsKey::from(&pk);

    // WebAuthn ES256 signatures are DER-encoded ECDSA. p256 has a
    // direct `from_der` parser.
    //
    // Note on signature malleability (high-S):
    // ECDSA admits two valid signatures (r, s) and (r, n-s) for any
    // message. WebAuthn does NOT require the verifier to reject the
    // high-S form. Accept either valid form; the application must atomically
    // consume its challenge state so a malleable signature cannot be used
    // to repeat an already completed ceremony.
    let parsed = EsSig::from_der(sig).map_err(|_| Error::BadSignature)?;
    vk.verify(msg, &parsed).map_err(|_| Error::BadSignature)
}

fn verify_ed25519(key: &[u8; 32], message: &[&[u8]], sig: &[u8]) -> Result<()> {
    let vk = ed25519_verifying_key(key).map_err(|_| Error::BadSignature)?;
    let parsed = EdSig::from_slice(sig).map_err(|_| Error::BadSignature)?;
    check_ed25519_encoding(parsed.r_bytes()).map_err(|_| Error::BadSignature)?;
    // Reviewed against ed25519-dalek 3.0.0. MultipartVerifier and verify_strict
    // share the S<L parser and exact RCompute(SHA512(R||A||message)) equation.
    // Success compares the canonical encoded expected R to wire R, so it also
    // proves R is a decodable canonical point. The complete finite encoding
    // filter above preserves strict's separate small-order A/R rejection;
    // A's actual point decoding remains in dalek. This avoids an otherwise
    // redundant R decompression and message concatenation, without computing
    // our own signature equation, hash or curve arithmetic. Dependency changes
    // must retain the independent CCTV and strict-oracle differential tests.
    // This is ordinary Ed25519, never Ed25519ph. Do not enable dalek's
    // legacy_compatibility feature, which relaxes even verify_strict's S check.
    vk.multipart_verify(message, &parsed)
        .map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as EsSigningKey;
    use rand::RngCore;

    #[test]
    fn rfc8032_ed25519_vector_and_small_order_forgery() {
        // RFC 8032 §7.1, TEST 1. Signature bytes are copied, not generated here.
        let public: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        let signature = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let key = CoseKey::Ed25519 { key: public };
        verify(&key, b"", &signature).unwrap();
        assert!(verify(&key, b"changed", &signature).is_err());
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut forged = [0; 64];
        forged[0] = 1;
        assert!(verify(&CoseKey::Ed25519 { key: identity }, b"any message", &forged).is_err());
    }

    #[test]
    fn ed25519_round_trip() {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk_bytes = sk.verifying_key().to_bytes();
        let msg = b"hello passkey world";
        let sig: EdSig = sk.sign(msg);
        let key = CoseKey::Ed25519 { key: vk_bytes };
        verify(&key, msg, &sig.to_bytes()).expect("good sig must verify");

        // Tamper → rejected.
        let mut bad = sig.to_bytes();
        bad[0] ^= 0x01;
        assert!(verify(&key, msg, &bad).is_err());
    }

    fn ed25519_strict_reference(key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
            return false;
        };
        // Independent, deliberately slower oracle for the pre-optimization
        // acceptance policy, including RFC 8032's canonical public encoding.
        if key.to_edwards().compress().as_bytes() != key.as_bytes() {
            return false;
        }
        let Ok(signature) = EdSig::from_slice(signature) else {
            return false;
        };
        key.verify_strict(message, &signature).is_ok()
    }

    #[test]
    fn cctv_ed25519_independent_acceptance_contract() {
        // Pinned independent vectors and their BSD license are retained in
        // tests/fixtures/cctv. These distinguish wholly small-order points
        // from valid points with a nonzero torsion component.
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/cctv/ed25519vectors.json"))
                .unwrap();
        assert_eq!(vectors.len(), 914);
        let mut accepted = 0;
        for vector in &vectors {
            let public: [u8; 32] = hex::decode(vector["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let signature = hex::decode(vector["sig"].as_str().unwrap()).unwrap();
            let message = vector["msg"].as_str().unwrap().as_bytes();
            let expected = vector["flags"].as_array().is_none_or(|flags| {
                flags.iter().all(|flag| {
                    matches!(
                        flag.as_str(),
                        Some("low_order_component_A" | "low_order_component_R")
                    )
                })
            });
            let key = CoseKey::Ed25519 { key: public };
            let actual = verify(&key, message, &signature).is_ok();
            assert_eq!(actual, expected, "CCTV vector {}", vector["number"]);
            assert_eq!(
                actual,
                ed25519_strict_reference(&public, message, &signature),
                "strict reference for CCTV vector {}",
                vector["number"]
            );
            for split in 0..=message.len() {
                assert_eq!(
                    verify_ed25519(
                        &public,
                        &[&message[..split], &[], &message[split..]],
                        &signature,
                    )
                    .is_ok(),
                    expected,
                    "CCTV vector {} at split {split}",
                    vector["number"]
                );
            }
            accepted += usize::from(actual);
        }
        assert_eq!(accepted, 43);
        assert_eq!(vectors.len() - accepted, 871);
    }

    #[test]
    fn ed25519_borrowed_transcript_and_scalar_bounds() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let key = CoseKey::Ed25519 {
            key: signing.verifying_key().to_bytes(),
        };
        let client_hash = [29; 32];
        for length in [0, 37, 38, 512, 16_384] {
            let auth_data = vec![23; length];
            let unchanged = auth_data.clone();
            let mut message = auth_data.clone();
            message.extend_from_slice(&client_hash);
            let signature = signing.sign(&message).to_bytes();
            verify_auth_data(&key, &auth_data, &client_hash, &signature).unwrap();
            assert_eq!(auth_data, unchanged);
            let mut wrong_hash = client_hash;
            wrong_hash[0] ^= 1;
            assert!(verify_auth_data(&key, &auth_data, &wrong_hash, &signature).is_err());

            // S+L must remain rejected even though it represents the same
            // scalar modulo the group order. Arithmetic here mutates a test
            // fixture; the production scalar parser remains in dalek.
            let order =
                hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                    .unwrap();
            let mut noncanonical = signature;
            let mut carry = 0u16;
            for (destination, byte) in noncanonical[32..].iter_mut().zip(order) {
                let sum = u16::from(*destination) + u16::from(byte) + carry;
                *destination = sum as u8;
                carry = sum >> 8;
            }
            assert_eq!(carry, 0);
            assert!(verify_auth_data(&key, &auth_data, &client_hash, &noncanonical).is_err());
            for signature_length in [0, 1, 31, 32, 63, 65, 128] {
                assert!(
                    verify_auth_data(&key, &auth_data, &client_hash, &vec![0; signature_length],)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn ed25519_verifier_rejects_every_out_of_range_y_and_negative_zero() {
        let mut forged = [0; 64];
        forged[0] = 1;
        for sign in [0, 0x80] {
            for offset in 0..19u8 {
                let mut key = [0xff; 32];
                key[0] = 0xed + offset;
                key[31] = 0x7f | sign;
                assert!(verify(&CoseKey::Ed25519 { key }, b"message", &forged).is_err());
            }
            let mut key = [0; 32];
            key[0] = 1;
            key[31] = sign;
            assert!(verify(&CoseKey::Ed25519 { key }, b"message", &forged).is_err());
            let mut key = [0xff; 32];
            key[0] = 0xec;
            key[31] = 0x7f | sign;
            assert!(verify(&CoseKey::Ed25519 { key }, b"message", &forged).is_err());
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1024))]

        #[test]
        fn ed25519_random_transcripts_preserve_strict_acceptance(
            public in proptest::prelude::any::<[u8; 32]>(),
            signature in proptest::prelude::any::<[u8; 64]>(),
            message in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let key = CoseKey::Ed25519 { key: public };
            proptest::prop_assert_eq!(
                verify(&key, &message, &signature).is_ok(),
                ed25519_strict_reference(&public, &message, &signature)
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn ed25519_encoding_optimization_preserves_real_signatures(
            seed in proptest::prelude::any::<[u8; 32]>(),
            message in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let signing = SigningKey::from_bytes(&seed);
            let key = CoseKey::Ed25519 { key: signing.verifying_key().to_bytes() };
            let signature = signing.sign(&message).to_bytes();
            proptest::prop_assert!(verify(&key, &message, &signature).is_ok());
            let mut wrong_message = message;
            wrong_message.push(0);
            proptest::prop_assert!(verify(&key, &wrong_message, &signature).is_err());
            let mut wrong_signature = signature;
            wrong_signature[0] ^= 1;
            proptest::prop_assert!(verify(&key, &wrong_message[..wrong_message.len() - 1], &wrong_signature).is_err());
        }
    }

    #[test]
    fn es256_round_trip() {
        let sk = EsSigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let pt = vk.to_sec1_point(false);
        let xs = pt.x().expect("x coord");
        let ys = pt.y().expect("y coord");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        // GenericArray derefs to &[u8] - avoid the deprecated as_slice().
        x.copy_from_slice(&xs[..]);
        y.copy_from_slice(&ys[..]);

        let msg = b"hello passkey world";
        let sig: EsSig = sk.sign(msg);
        let der = sig.to_der().to_bytes().to_vec();

        let key = CoseKey::Es256 { x, y };
        verify(&key, msg, &der).expect("good sig must verify");

        // Tamper → rejected.
        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(verify(&key, msg, &bad).is_err());
    }

    fn es256_key(signing: &EsSigningKey) -> CoseKey {
        let point = signing.verifying_key().to_sec1_point(false);
        CoseKey::Es256 {
            x: <[u8; 32]>::try_from(&point.x().unwrap()[..]).unwrap(),
            y: <[u8; 32]>::try_from(&point.y().unwrap()[..]).unwrap(),
        }
    }

    #[test]
    fn es256_backends_preserve_transcript_high_s_and_der_contract() {
        let signing = EsSigningKey::from_slice(&[7; 32]).unwrap();
        let key = es256_key(&signing);
        let auth_data = vec![23; 37];
        let client_hash = [29; 32];
        let mut message = auth_data.clone();
        message.extend(client_hash);
        let signature: EsSig = signing.sign(&message);
        let low = signature.normalize_s();
        let high = EsSig::from_scalars(low.r(), -low.s()).unwrap();
        assert_ne!(low, high);
        for signature in [low, high] {
            let der = signature.to_der();
            verify(&key, &message, der.as_bytes()).unwrap();
            let borrowed_transcript = auth_data.clone();
            verify_auth_data(&key, &borrowed_transcript, &client_hash, der.as_bytes()).unwrap();
            // ES256 hashes borrowed parts under both backends.
            assert_eq!(borrowed_transcript, auth_data);
            assert!(verify(&key, b"wrong message", der.as_bytes()).is_err());
            let mut wrong_hash = client_hash;
            wrong_hash[0] ^= 1;
            assert!(verify_auth_data(&key, &auth_data, &wrong_hash, der.as_bytes()).is_err());
        }
        let mut trailing = low.to_der().as_bytes().to_vec();
        trailing.push(0);
        let mut out_of_range_r = vec![0x30, 0x26, 0x02, 0x21, 0];
        out_of_range_r.extend([0xff; 32]);
        out_of_range_r.extend([0x02, 0x01, 0x01]);
        let invalid = [
            vec![],
            low.to_bytes().to_vec(), // raw r||s is not the WebAuthn ES256 wire format
            trailing,
            vec![0x30, 6, 2, 1, 0, 2, 1, 1],          // zero r
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],       // negative r
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],       // non-minimal integer
            vec![0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0], // indefinite length
            out_of_range_r,
        ];
        for signature in invalid {
            assert!(verify(&key, &message, &signature).is_err());
            assert!(verify_auth_data(&key, &auth_data, &client_hash, &signature).is_err());
        }
        for invalid_key in [
            CoseKey::Es256 {
                x: [0; 32],
                y: [0; 32],
            },
            CoseKey::Es256 {
                x: [0xff; 32],
                y: [0xff; 32],
            },
            es256_key(&EsSigningKey::from_slice(&[8; 32]).unwrap()),
        ] {
            assert!(verify(&invalid_key, &message, low.to_der().as_bytes()).is_err());
            assert!(
                verify_auth_data(
                    &invalid_key,
                    &auth_data,
                    &client_hash,
                    low.to_der().as_bytes(),
                )
                .is_err()
            );
        }
    }

    #[cfg(all(feature = "aws-lc", not(target_family = "wasm")))]
    #[test]
    fn es256_native_backend_matches_rustcrypto_for_fixed_key_corpus() {
        let signing = EsSigningKey::from_slice(&[7; 32]).unwrap();
        let message = b"fixed native backend equivalence corpus";
        let signature: EsSig = signing.sign(message);
        let low = signature.normalize_s();
        let high = EsSig::from_scalars(low.r(), -low.s()).unwrap();
        for key in [
            es256_key(&signing),
            es256_key(&EsSigningKey::from_slice(&[8; 32]).unwrap()),
            CoseKey::Es256 {
                x: [0; 32],
                y: [0; 32],
            },
            CoseKey::Es256 {
                x: [0xff; 32],
                y: [0xff; 32],
            },
        ] {
            let CoseKey::Es256 { x, y } = key else {
                unreachable!()
            };
            for message in [message.as_slice(), b"wrong".as_slice(), b"".as_slice()] {
                for signature in [
                    low.to_der().as_bytes().to_vec(),
                    high.to_der().as_bytes().to_vec(),
                    low.to_bytes().to_vec(),
                ] {
                    assert_eq!(
                        verify_es256(&x, &y, message, &signature).is_ok(),
                        verify_es256_rustcrypto(&x, &y, message, &signature).is_ok()
                    );
                }
            }
        }
    }
}
