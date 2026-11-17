//! Borrowed, fully consumed authenticatorData (WebAuthn §6.1).
//!
//! Credential bytes remain in the decoded response until registration has
//! passed every check. Only the final stored credential owns copies.

use crate::cbor::Decoder;
use crate::cose::CoseKey;
use crate::error::{Error, Result};

pub(crate) const FLAG_UP: u8 = 1;
pub(crate) const FLAG_UV: u8 = 1 << 2;
pub(crate) const FLAG_BE: u8 = 1 << 3;
pub(crate) const FLAG_BS: u8 = 1 << 4;
pub(crate) const FLAG_AT: u8 = 1 << 6;
pub(crate) const FLAG_ED: u8 = 1 << 7;
pub(crate) const MAX_AUTH_DATA_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct AuthenticatorData<'a> {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<AttestedCredentialData<'a>>,
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData<'a> {
    pub aaguid: [u8; 16],
    pub credential_id: &'a [u8],
    pub public_key_cose: &'a [u8],
    pub key: CoseKey,
}

impl<'a> AuthenticatorData<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        if !(37..=MAX_AUTH_DATA_BYTES).contains(&bytes.len()) {
            return Err(Error::AuthData(
                "authenticatorData length outside 37..=16384",
            ));
        }
        let rp_id_hash = bytes[..32].try_into().unwrap();
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
        if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
            return Err(Error::AuthData("backup state requires backup eligibility"));
        }
        let mut pos = 37;
        let attested = if flags & FLAG_AT != 0 {
            let header = bytes
                .get(pos..pos + 18)
                .ok_or(Error::AuthData("attestedCredentialData truncated header"))?;
            let aaguid = header[..16].try_into().unwrap();
            let credential_len = usize::from(u16::from_be_bytes(header[16..].try_into().unwrap()));
            if !(1..=1023).contains(&credential_len) {
                return Err(Error::AuthData("credentialIdLength outside 1..=1023"));
            }
            pos += 18;
            let credential_id = bytes
                .get(pos..pos + credential_len)
                .ok_or(Error::AuthData("credentialId truncated"))?;
            pos += credential_len;
            let (key, consumed) = CoseKey::parse_prefix(&bytes[pos..])?;
            let public_key_cose = &bytes[pos..pos + consumed];
            pos += consumed;
            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                public_key_cose,
                key,
            })
        } else {
            None
        };

        if flags & FLAG_ED != 0 {
            let mut decoder = Decoder::new(&bytes[pos..], true)?;
            decoder.validate_map()?;
            decoder.finish()?;
        } else if pos != bytes.len() {
            return Err(Error::AuthData("trailing bytes without ED flag"));
        }
        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested,
        })
    }

    pub(crate) fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub(crate) fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }
    pub(crate) fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BE != 0
    }
    pub(crate) fn backup_state(&self) -> bool {
        self.flags & FLAG_BS != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(flags: u8) -> Vec<u8> {
        let mut bytes = vec![0xab; 32];
        bytes.push(flags);
        bytes.extend_from_slice(&42u32.to_be_bytes());
        bytes
    }

    #[test]
    fn parse_minimal_auth_data() {
        let bytes = minimal(FLAG_UP | FLAG_UV);
        let parsed = AuthenticatorData::parse(&bytes).unwrap();
        assert_eq!(parsed.rp_id_hash, [0xab; 32]);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.user_present());
        assert!(parsed.user_verified());
        assert!(parsed.attested.is_none());
    }

    #[test]
    fn all_backup_flag_combinations_are_checked() {
        for flags in [0, FLAG_BE, FLAG_BE | FLAG_BS] {
            let bytes = minimal(flags);
            let parsed = AuthenticatorData::parse(&bytes).unwrap();
            assert_eq!(parsed.backup_eligible(), flags & FLAG_BE != 0);
            assert_eq!(parsed.backup_state(), flags & FLAG_BS != 0);
        }
        assert!(AuthenticatorData::parse(&minimal(FLAG_BS)).is_err());
    }

    #[test]
    fn extension_presence_type_and_consumption_are_checked() {
        assert!(AuthenticatorData::parse(&minimal(FLAG_ED)).is_err());
        for suffix in [
            &[0x80][..],
            &[0xa0, 0][..],
            &[0xa2, 0x61, b'x', 0, 0x61, b'x', 1][..],
            &[0xa1, 0x01, 0x00][..],
            &[0xa1, 0x41, 0x01, 0x00][..],
            &[0xa1, 0xf5, 0x00][..],
        ] {
            let mut bytes = minimal(FLAG_ED);
            bytes.extend_from_slice(suffix);
            assert!(AuthenticatorData::parse(&bytes).is_err());
        }
        let mut good = minimal(FLAG_ED);
        good.push(0xa0);
        assert!(AuthenticatorData::parse(&good).is_ok());
        let mut trailing = minimal(0);
        trailing.push(0);
        assert!(AuthenticatorData::parse(&trailing).is_err());
    }

    #[test]
    fn attested_credential_id_lengths_are_bounded() {
        for n in [0, 1024, u16::MAX] {
            let mut bytes = minimal(FLAG_AT);
            bytes.extend_from_slice(&[0; 16]);
            bytes.extend_from_slice(&n.to_be_bytes());
            assert!(AuthenticatorData::parse(&bytes).is_err());
        }
        assert!(AuthenticatorData::parse(&[0; 36]).is_err());
    }
    proptest::proptest! {
        #[test]
        fn arbitrary_authenticator_data_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
            let _ = AuthenticatorData::parse(&bytes);
        }

        #[test]
        fn counter_endianness_and_all_flags_are_preserved(counter in proptest::prelude::any::<u32>(), supplied_flags in proptest::prelude::any::<u8>()) {
            let flags = supplied_flags & !(FLAG_AT | FLAG_ED);
            let mut bytes = minimal(flags);
            bytes[33..37].copy_from_slice(&counter.to_be_bytes());
            let result = AuthenticatorData::parse(&bytes);
            if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
                proptest::prop_assert!(result.is_err());
            } else {
                let data = result.unwrap();
                proptest::prop_assert_eq!(data.sign_count, counter);
                proptest::prop_assert_eq!(data.flags, flags);
            }
        }
    }
}
