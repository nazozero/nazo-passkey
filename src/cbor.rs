//! Bounded, borrowing decoder for the CBOR subset used by WebAuthn.
//!
//! This is a wire parser, not a cryptographic primitive. Bytes and text are
//! borrowed; no attacker-controlled length is ever used to allocate. New
//! authenticator output uses CTAP2 canonical encodings. The stored-key reader
//! also accepts the old library's non-canonical ordering/widths, but never
//! duplicate labels, indefinite lengths, tags, or truncated values.

use crate::error::{Error, Result};

pub(crate) const MAX_CBOR_BYTES: usize = 64 * 1024;
const MAX_CONTAINER_ITEMS: usize = 64;
const MAX_DEPTH: usize = 12;
const MAX_ITEMS: usize = 2048;

#[derive(Clone)]
pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    canonical: bool,
    remaining_items: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum MapKey<'a> {
    Integer(i128),
    Bytes(&'a [u8]),
    Text(&'a str),
    Simple(u8),
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(input: &'a [u8], canonical: bool) -> Result<Self> {
        if input.len() > MAX_CBOR_BYTES {
            return Err(invalid("CBOR resource limit exceeded"));
        }
        Ok(Self {
            input,
            pos: 0,
            canonical,
            remaining_items: MAX_ITEMS,
        })
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn major(&self) -> Option<u8> {
        self.input.get(self.pos).map(|b| b >> 5)
    }

    pub(crate) fn check_key_order(
        &self,
        start: usize,
        previous: &mut Option<&'a [u8]>,
    ) -> Result<()> {
        let encoded = &self.input[start..self.pos];
        if self.canonical && previous.is_some_and(|p| p >= encoded) {
            return Err(invalid("duplicate or non-canonical CBOR map key"));
        }
        *previous = Some(encoded);
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(invalid("trailing CBOR data"))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| invalid("CBOR length overflow"))?;
        let out = self
            .input
            .get(self.pos..end)
            .ok_or_else(|| invalid("truncated CBOR"))?;
        self.pos = end;
        Ok(out)
    }

    fn head(&mut self) -> Result<(u8, u64)> {
        self.remaining_items = self
            .remaining_items
            .checked_sub(1)
            .ok_or_else(|| invalid("CBOR item limit exceeded"))?;
        let first = self.take(1)?[0];
        let major = first >> 5;
        let additional = first & 31;
        let (argument, minimum) = match additional {
            n @ 0..=23 => (u64::from(n), 0),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                256,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                65536,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                1 << 32,
            ),
            _ => return Err(invalid("indefinite or reserved CBOR encoding")),
        };
        if self.canonical && major != 7 && argument < minimum {
            return Err(invalid("non-minimal CBOR integer or length"));
        }
        // Simple values < 32 must not use the two-byte representation.
        if major == 7 && additional == 24 && argument < 32 {
            return Err(invalid("invalid CBOR simple value"));
        }
        Ok((major, argument))
    }

    fn length(&mut self, wanted: u8) -> Result<usize> {
        let (major, n) = self.head()?;
        if major != wanted {
            return Err(invalid("wrong CBOR type"));
        }
        usize::try_from(n).map_err(|_| invalid("CBOR length overflow"))
    }

    pub(crate) fn integer(&mut self) -> Result<i64> {
        let (major, n) = self.head()?;
        let value = match major {
            0 => i128::from(n),
            1 => -1 - i128::from(n),
            _ => return Err(invalid("CBOR integer expected")),
        };
        i64::try_from(value).map_err(|_| invalid("CBOR integer outside i64 range"))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.length(2)?;
        self.take(len)
    }

    pub(crate) fn text(&mut self) -> Result<&'a str> {
        let len = self.length(3)?;
        std::str::from_utf8(self.take(len)?).map_err(|_| invalid("invalid CBOR UTF-8"))
    }

    pub(crate) fn map(&mut self) -> Result<usize> {
        self.container(5)
    }
    pub(crate) fn array(&mut self) -> Result<usize> {
        self.container(4)
    }

    fn container(&mut self, major: u8) -> Result<usize> {
        let count = self.length(major)?;
        if count > MAX_CONTAINER_ITEMS {
            return Err(invalid("CBOR container limit exceeded"));
        }
        Ok(count)
    }

    pub(crate) fn skip(&mut self) -> Result<()> {
        self.skip_at_depth(0)
    }

    /// Authenticator extension identifiers are text keys (WebAuthn §5.7.4).
    /// Values may themselves contain maps with other CBOR key types. Unknown
    /// extensions are checked structurally, never used as security policy.
    pub(crate) fn validate_map(&mut self) -> Result<()> {
        let count = self.map()?;
        let mut previous = None;
        for _ in 0..count {
            let start = self.pos;
            self.text()?;
            self.check_key_order(start, &mut previous)?;
            self.skip_at_depth(1)?;
        }
        Ok(())
    }

    fn key(&mut self) -> Result<MapKey<'a>> {
        let additional = self.input.get(self.pos).copied().unwrap_or(0) & 31;
        let (major, n) = self.head()?;
        match major {
            0 => Ok(MapKey::Integer(i128::from(n))),
            1 => Ok(MapKey::Integer(-1 - i128::from(n))),
            2 | 3 => {
                let len = usize::try_from(n).map_err(|_| invalid("CBOR key length overflow"))?;
                let bytes = self.take(len)?;
                if major == 2 {
                    Ok(MapKey::Bytes(bytes))
                } else {
                    Ok(MapKey::Text(
                        std::str::from_utf8(bytes).map_err(|_| invalid("invalid CBOR UTF-8"))?,
                    ))
                }
            }
            7 if additional <= 23 && (20..=23).contains(&n) => Ok(MapKey::Simple(n as u8)),
            _ => Err(invalid("unsupported CBOR map-key type")),
        }
    }

    fn skip_at_depth(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(invalid("CBOR nesting limit exceeded"));
        }
        let (major, n) = self.head()?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let len = usize::try_from(n).map_err(|_| invalid("CBOR length overflow"))?;
                let bytes = self.take(len)?;
                if major == 3 {
                    std::str::from_utf8(bytes).map_err(|_| invalid("invalid CBOR UTF-8"))?;
                }
                Ok(())
            }
            4 | 5 => {
                let count = usize::try_from(n).map_err(|_| invalid("CBOR length overflow"))?;
                if count > MAX_CONTAINER_ITEMS {
                    return Err(invalid("CBOR container limit exceeded"));
                }
                let mut keys = [None; MAX_CONTAINER_ITEMS];
                let mut previous: Option<&[u8]> = None;
                for i in 0..count {
                    if major == 5 {
                        let start = self.pos;
                        let key = self.key()?;
                        let encoded = &self.input[start..self.pos];
                        if keys[..i].contains(&Some(key)) {
                            return Err(invalid("duplicate CBOR map key"));
                        }
                        // CTAP2 ordering is major-type first, then encoded key
                        // length/value. Canonical encodings compare lexically.
                        if self.canonical && previous.is_some_and(|p| p >= encoded) {
                            return Err(invalid("non-canonical CBOR map ordering"));
                        }
                        keys[i] = Some(key);
                        previous = Some(encoded);
                    }
                    self.skip_at_depth(depth + 1)?;
                }
                Ok(())
            }
            7 => Ok(()), // Simple values and IEEE floats keep their CTAP width.
            _ => Err(invalid("CBOR tags are not supported by WebAuthn")),
        }
    }
}

pub(crate) fn invalid(message: &'static str) -> Error {
    Error::Cbor(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(bytes: &[u8], canonical: bool) -> bool {
        Decoder::new(bytes, canonical)
            .and_then(|mut d| {
                d.skip()?;
                d.finish()
            })
            .is_ok()
    }

    #[test]
    fn malformed_lengths_duplicates_and_trailing_are_rejected() {
        for input in [
            &b"\xbf\xff"[..],
            &b"\xd8\x01\x00"[..],
            &b"\x5b\xff\xff\xff\xff\xff\xff\xff\xff"[..],
            &b"\xa2\x01\x02\x01\x03"[..],
            &b"\xa2\x01\x02\x18\x01\x03"[..],
            &b"\x00\x00"[..],
            &b"\x61\xff"[..],
            &b"\x1c"[..],
            &b"\xf8\x00"[..],
        ] {
            assert!(!valid(input, false), "{input:?}");
        }
    }

    #[test]
    fn stored_ordering_is_compatible_but_new_encoding_is_canonical() {
        assert!(valid(b"\xa2\x03\x26\x01\x02", false));
        assert!(!valid(b"\xa2\x03\x26\x01\x02", true));
        assert!(valid(b"\xa2\x01\x02\x03\x26", true));
        assert!(valid(b"\x18\x01", false));
        assert!(!valid(b"\x18\x01", true));
    }

    #[test]
    fn nesting_and_integer_overflow_are_bounded() {
        let mut input = vec![0x81; MAX_DEPTH + 2];
        input.push(0);
        assert!(!valid(&input, true));
        assert!(
            Decoder::new(
                &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                true
            )
            .unwrap()
            .integer()
            .is_err()
        );
    }
    proptest::proptest! {
        #[test]
        fn arbitrary_input_is_bounded_and_never_panics(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096), canonical in proptest::prelude::any::<bool>()) {
            if let Ok(mut decoder) = Decoder::new(&input, canonical) {
                let _ = decoder.skip();
                proptest::prop_assert!(decoder.position() <= input.len());
            }
        }

        #[test]
        fn independent_cbor_serializer_preserves_borrowed_byte_strings(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)) {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&ciborium::value::Value::Bytes(bytes.clone()), &mut encoded).unwrap();
            let mut decoder = Decoder::new(&encoded, true).unwrap();
            proptest::prop_assert_eq!(decoder.bytes().unwrap(), bytes.as_slice());
            proptest::prop_assert!(decoder.finish().is_ok());
        }
    }
}
