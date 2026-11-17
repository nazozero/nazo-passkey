//! Borrowing COSE_Key decoding (RFC 9052/9053, WebAuthn §6.5.1).
//!
//! Newly registered keys use the CTAP2 canonical profile and contain only
//! required public parameters. Persisted keys retain the previous reader's
//! compatibility with map ordering and optional metadata. Both paths reject
//! ambiguous labels, integer narrowing, private parameters and trailing data.

use crate::cbor::{Decoder, invalid};
use crate::error::{Error, Result};

pub(crate) const ALG_ES256: i64 = -7;
pub(crate) const ALG_EDDSA: i64 = -8;

/// Decode a canonical, nonweak Ed25519 public key using RustCrypto.
///
/// RFC 8032 §5.1.3 requires y < p = 2^255 - 19 after removing the sign bit.
/// The only 19 out-of-range y encodings have the high 31 bytes shown below.
/// This byte check replaces decompress-then-recompress, which adds a field
/// inversion. The only remaining non-unique sign encoding would have x=0:
/// on the Edwards curve that implies y=±1, both small-order points rejected
/// by dalek's is_weak(). Point decoding and weak-point detection stay in dalek.
pub(crate) fn ed25519_verifying_key(bytes: &[u8; 32]) -> Result<ed25519_dalek::VerifyingKey> {
    if bytes[31] & 0x7f == 0x7f && bytes[1..31] == [0xff; 30] && bytes[0] >= 0xed {
        return Err(invalid("non-canonical Ed25519 public point"));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|_| invalid("invalid Ed25519 public point"))?;
    if key.is_weak() {
        return Err(invalid("weak Ed25519 public point"));
    }
    Ok(key)
}

#[derive(Debug, Clone)]
pub(crate) enum CoseKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    Ed25519 { key: [u8; 32] },
}

impl CoseKey {
    /// Parse an existing stored public key. The verifier checks curve-point
    /// validity when constructing its verification key; do not do that twice.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Decoder::new(bytes, false)?;
        let key = Self::read(&mut reader, false)?;
        reader.finish()?;
        Ok(key)
    }

    /// Registration has no subsequent signature for fmt=none, so it must
    /// validate the point here. The parsed key is retained by authData.
    pub(crate) fn parse_prefix(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut reader = Decoder::new(bytes, true)?;
        let key = Self::read(&mut reader, true)?;
        key.validate_point()?;
        Ok((key, reader.position()))
    }

    fn read(reader: &mut Decoder<'_>, registration: bool) -> Result<Self> {
        let count = reader.map()?;
        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut seen = [None; 64];
        let mut seen_text = [None; 64];
        let mut previous = None;
        for i in 0..count {
            let start = reader.position();
            if reader.major() == Some(3) && !registration {
                let label = reader.text()?;
                if seen_text[..i].contains(&Some(label)) {
                    return Err(invalid("duplicate COSE label"));
                }
                seen_text[i] = Some(label);
                reader.skip()?;
                continue;
            }
            let label = reader.integer()?;
            reader.check_key_order(start, &mut previous)?;
            // Canonical registration ordering already proves uniqueness.
            // Legacy stored maps need an order-independent duplicate check.
            if !registration {
                if seen[..i].contains(&Some(label)) {
                    return Err(invalid("duplicate COSE label"));
                }
                seen[i] = Some(label);
            }
            match label {
                1 => kty = Some(reader.integer()?),
                3 => alg = Some(reader.integer()?),
                -1 => crv = Some(reader.integer()?),
                -2 => x = Some(reader.bytes()?),
                -3 => y = Some(reader.bytes()?),
                -4 => return Err(invalid("COSE public key contains private parameter")),
                _ if registration => {
                    return Err(invalid("credentialPublicKey contains optional parameters"));
                }
                _ => reader.skip()?,
            }
        }
        let kty = kty.ok_or_else(|| invalid("COSE key missing kty"))?;
        let alg = alg.ok_or_else(|| invalid("COSE key missing alg"))?;
        let x = x.ok_or_else(|| invalid("COSE key missing x"))?;
        match (kty, alg, crv) {
            (2, ALG_ES256, Some(1)) => {
                let y = y.ok_or_else(|| invalid("ES256 key missing y"))?;
                Ok(Self::Es256 {
                    x: x.try_into()
                        .map_err(|_| invalid("ES256 x must be 32 bytes"))?,
                    y: y.try_into()
                        .map_err(|_| invalid("ES256 y must be 32 bytes"))?,
                })
            }
            (1, ALG_EDDSA, Some(6)) if y.is_none() => Ok(Self::Ed25519 {
                key: x
                    .try_into()
                    .map_err(|_| invalid("Ed25519 key must be 32 bytes"))?,
            }),
            (_, ALG_ES256 | ALG_EDDSA, _) => {
                Err(invalid("COSE algorithm, key type and curve mismatch"))
            }
            _ => Err(Error::UnsupportedAlg(alg)),
        }
    }

    fn validate_point(&self) -> Result<()> {
        match self {
            Self::Es256 { x, y } => {
                let mut sec1 = [0; 65];
                sec1[0] = 4;
                sec1[1..33].copy_from_slice(x);
                sec1[33..].copy_from_slice(y);
                p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| invalid("invalid P-256 public point"))?;
            }
            Self::Ed25519 { key } => {
                ed25519_verifying_key(key)?;
            }
        }
        Ok(())
    }

    pub(crate) fn alg(&self) -> i64 {
        match self {
            Self::Es256 { .. } => ALG_ES256,
            Self::Ed25519 { .. } => ALG_EDDSA,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn good_map() -> Vec<(Value, Value)> {
        let sk = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        vec![
            (1.into(), 2.into()),
            (3.into(), (-7).into()),
            ((-1).into(), 1.into()),
            ((-2).into(), Value::Bytes(point.x().unwrap().to_vec())),
            ((-3).into(), Value::Bytes(point.y().unwrap().to_vec())),
        ]
    }
    fn encode(map: Vec<(Value, Value)>) -> Vec<u8> {
        let mut output = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut output).unwrap();
        output
    }

    #[test]
    fn registration_and_existing_keys_validate() {
        let bytes = encode(good_map());
        assert!(CoseKey::parse(&bytes).is_ok());
        assert!(CoseKey::parse_prefix(&bytes).is_ok());
        let mut map = good_map();
        map.reverse();
        let legacy = encode(map);
        assert!(CoseKey::parse(&legacy).is_ok());
        assert!(CoseKey::parse_prefix(&legacy).is_err());
    }

    #[test]
    fn malformed_key_parameters_are_rejected() {
        for position in 0..5 {
            let mut map = good_map();
            map.push(map[position].clone());
            assert!(CoseKey::parse(&encode(map)).is_err());
        }
        let mut bad = good_map();
        bad[2].1 = 6.into();
        assert!(CoseKey::parse(&encode(bad)).is_err());
        let mut bad = good_map();
        bad[3].1 = Value::Bytes(vec![0; 31]);
        assert!(CoseKey::parse(&encode(bad)).is_err());
        let mut bad = good_map();
        bad[3].1 = Value::Bytes(vec![0; 32]);
        bad[4].1 = Value::Bytes(vec![0; 32]);
        assert!(CoseKey::parse_prefix(&encode(bad)).is_err());
        let mut bad = good_map();
        bad.push(((-4).into(), Value::Bytes(vec![0; 32])));
        assert!(CoseKey::parse(&encode(bad)).is_err());
        let mut bytes = encode(good_map());
        bytes.push(0);
        assert!(CoseKey::parse(&bytes).is_err());
    }

    #[test]
    fn legacy_optional_metadata_does_not_change_key_but_new_keys_reject_it() {
        let mut map = good_map();
        map.push((2.into(), Value::Bytes(vec![1])));
        let bytes = encode(map);
        assert!(CoseKey::parse(&bytes).is_ok());
        assert!(CoseKey::parse_prefix(&bytes).is_err());
    }

    #[test]
    fn oversized_negative_labels_do_not_wrap_into_curve_labels() {
        let mut bad = vec![0xa1, 0x3b];
        bad.extend_from_slice(&u64::MAX.to_be_bytes());
        bad.push(1);
        assert!(CoseKey::parse(&bad).is_err());
    }

    #[test]
    fn rfc8032_ed25519_test_vector_1_validates_without_generated_signatures() {
        // RFC 8032 §7.1, TEST 1: public key and signature for the empty message.
        let public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let signature = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let bytes = encode(vec![
            (1.into(), 1.into()),
            (3.into(), (-8).into()),
            ((-1).into(), 6.into()),
            ((-2).into(), Value::Bytes(public)),
        ]);
        let (key, consumed) = CoseKey::parse_prefix(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        crate::crypto::verify(&key, b"", &signature).unwrap();
        assert!(crate::crypto::verify(&key, b"x", &signature).is_err());
    }

    #[test]
    fn noncanonical_ed25519_public_points_are_rejected() {
        // ZIP-215 accepts y >= 2^255-19; WebAuthn Ed25519 uses RFC 8032.
        // Exercise decompressible non-small-order encodings, not just identity.
        let mut tested = 0;
        for offset in 0..19u8 {
            let mut public = [0xff; 32];
            public[0] = 0xed + offset;
            public[31] = 0x7f;
            if ed25519_dalek::VerifyingKey::from_bytes(&public).is_ok_and(|key| !key.is_weak()) {
                let bytes = encode(vec![
                    (1.into(), 1.into()),
                    (3.into(), (-8).into()),
                    ((-1).into(), 6.into()),
                    ((-2).into(), Value::Bytes(public.to_vec())),
                ]);
                assert!(CoseKey::parse_prefix(&bytes).is_err());
                tested += 1;
            }
        }
        assert!(tested > 0);
    }

    fn recompressed_ed25519_accepts(bytes: &[u8; 32]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .is_ok_and(|key| !key.is_weak() && key.to_edwards().compress().as_bytes() == bytes)
    }

    #[test]
    fn every_noncanonical_ed25519_y_and_both_signs_are_rejected() {
        for sign in [0, 0x80] {
            for offset in 0..19u8 {
                let mut bytes = [0xff; 32];
                bytes[0] = 0xed + offset;
                bytes[31] = 0x7f | sign;
                assert!(!recompressed_ed25519_accepts(&bytes));
                assert!(ed25519_verifying_key(&bytes).is_err());
                let cose = encode(vec![
                    (1.into(), 1.into()),
                    (3.into(), (-8).into()),
                    ((-1).into(), 6.into()),
                    ((-2).into(), Value::Bytes(bytes.to_vec())),
                ]);
                assert!(CoseKey::parse_prefix(&cose).is_err());
            }
        }
    }

    #[test]
    fn ed25519_zero_x_is_weak_for_both_y_values_and_signs() {
        let mut positive_one = [0; 32];
        positive_one[0] = 1;
        let mut negative_one = [0xff; 32];
        negative_one[0] = 0xec;
        negative_one[31] = 0x7f;
        for y in [positive_one, negative_one] {
            for sign in [0, 0x80] {
                let mut bytes = y;
                bytes[31] |= sign;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
                assert!(key.is_weak());
                assert!(!recompressed_ed25519_accepts(&bytes));
                assert!(ed25519_verifying_key(&bytes).is_err());
            }
        }
    }

    #[test]
    fn ed25519_encoding_boundary_does_not_reject_lower_y_values() {
        // Check both the low byte threshold and every more significant byte.
        // A byte below 0xff in positions 1..31 makes y<p regardless of byte 0.
        for position in 0..32 {
            for sign in [0, 0x80] {
                let mut bytes = [0xff; 32];
                bytes[31] = 0x7f | sign;
                bytes[position] = match position {
                    0 => 0xec,
                    31 => 0x7e | sign,
                    _ => 0xfe,
                };
                assert_eq!(
                    ed25519_verifying_key(&bytes).is_ok(),
                    recompressed_ed25519_accepts(&bytes),
                    "position {position}, sign {sign}"
                );
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(2048))]

        #[test]
        fn ed25519_byte_bound_is_equivalent_to_recompression(bytes in proptest::prelude::any::<[u8; 32]>()) {
            proptest::prop_assert_eq!(
                ed25519_verifying_key(&bytes).is_ok(),
                recompressed_ed25519_accepts(&bytes)
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn malformed_cose_input_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let _ = CoseKey::parse(&bytes);
            if let Ok((_, consumed)) = CoseKey::parse_prefix(&bytes) {
                proptest::prop_assert!(consumed <= bytes.len());
            }
        }

        #[test]
        fn registration_key_prefix_consumes_only_the_key(tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..128)) {
            let mut bytes = encode(good_map());
            let expected = bytes.len();
            bytes.extend_from_slice(&tail);
            let (_, consumed) = CoseKey::parse_prefix(&bytes).unwrap();
            proptest::prop_assert_eq!(consumed, expected);
        }

        #[test]
        fn duplicate_key_parameters_never_choose_first_or_last(index in 0usize..5, insert_at in 0usize..6) {
            let mut map = good_map();
            map.insert(insert_at, map[index].clone());
            let bytes = encode(map);
            proptest::prop_assert!(CoseKey::parse(&bytes).is_err());
            proptest::prop_assert!(CoseKey::parse_prefix(&bytes).is_err());
        }
    }
}
