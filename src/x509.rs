//! X.509 structure and packed-attestation profile checks.
//!
//! No trust anchors or time-validation policy are configured here. Parsed
//! chains are evidence with an explicitly unverified trust status.

use const_oid::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;
use x509_cert::ext::pkix::BasicConstraints;

use crate::cbor::invalid;
use crate::error::{Error, Result};

const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_C: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_O: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_OU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

#[derive(Debug)]
pub(crate) struct AttestationCert {
    pub p256_pubkey_sec1: [u8; 65],
    pub aaguid: Option<[u8; 16]>,
}

impl AttestationCert {
    pub(crate) fn validate_der(der: &[u8]) -> Result<()> {
        Certificate::from_der(der).map_err(|e| Error::Cbor(format!("x509 parse: {e}")))?;
        Ok(())
    }

    pub(crate) fn from_der(der: &[u8], packed: bool) -> Result<Self> {
        let certificate =
            Certificate::from_der(der).map_err(|e| Error::Cbor(format!("x509 parse: {e}")))?;
        let tbs = &certificate.tbs_certificate;
        let spki = &tbs.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(invalid("attestation certificate key must be EC"));
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| invalid("attestation certificate missing named curve"))?
            .decode_as::<ObjectIdentifier>()
            .map_err(|_| invalid("attestation certificate invalid named curve"))?;
        if curve != OID_P256 {
            return Err(invalid("attestation certificate named curve must be P-256"));
        }
        let key = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| invalid("attestation certificate key has unused bits"))?;
        let p256_pubkey_sec1: [u8; 65] = key
            .try_into()
            .map_err(|_| invalid("attestation certificate key must be uncompressed P-256"))?;
        if p256_pubkey_sec1[0] != 4 {
            return Err(invalid(
                "attestation certificate key must be uncompressed P-256",
            ));
        }

        let mut aaguid = None;
        let mut basic_constraints = None;
        if let Some(extensions) = &tbs.extensions {
            if extensions.len() > 64 {
                return Err(invalid("attestation certificate extension limit exceeded"));
            }
            for (i, extension) in extensions.iter().enumerate() {
                if extensions[..i]
                    .iter()
                    .any(|old| old.extn_id == extension.extn_id)
                {
                    return Err(invalid("duplicate X.509 extension"));
                }
                if extension.extn_id == OID_AAGUID {
                    if extension.critical {
                        return Err(invalid("AAGUID extension must not be critical"));
                    }
                    aaguid = Some(parse_aaguid(extension.extn_value.as_bytes())?);
                }
                if extension.extn_id == OID_BASIC_CONSTRAINTS {
                    basic_constraints = Some(
                        BasicConstraints::from_der(extension.extn_value.as_bytes())
                            .map_err(|_| invalid("invalid basicConstraints extension"))?,
                    );
                }
            }
        }
        if packed {
            if tbs.version != Version::V3 {
                return Err(invalid("packed attestation certificate must be X.509 v3"));
            }
            let constraints = basic_constraints
                .ok_or_else(|| invalid("packed certificate missing basicConstraints"))?;
            if constraints.ca || constraints.path_len_constraint.is_some() {
                return Err(invalid(
                    "packed certificate basicConstraints must have CA=false",
                ));
            }
            validate_packed_subject(&tbs.subject)?;
        }
        Ok(Self {
            p256_pubkey_sec1,
            aaguid,
        })
    }
}

fn validate_packed_subject(subject: &x509_cert::name::Name) -> Result<()> {
    let mut present = [false; 4];
    for rdn in &subject.0 {
        for attribute in rdn.0.iter() {
            let index = match attribute.oid {
                OID_C => 0,
                OID_O => 1,
                OID_OU => 2,
                OID_CN => 3,
                _ => continue,
            };
            if present[index] {
                return Err(invalid(
                    "packed certificate duplicate required subject field",
                ));
            }
            present[index] = true;
            let text = if index == 0 {
                PrintableStringRef::try_from(&attribute.value)
                    .map_err(|_| invalid("packed certificate C must be PrintableString"))?
                    .as_str()
            } else {
                Utf8StringRef::try_from(&attribute.value)
                    .map_err(|_| invalid("packed certificate O, OU and CN must be UTF8String"))?
                    .as_str()
            };
            if text.is_empty() {
                return Err(invalid("packed certificate empty subject field"));
            }
            if index == 0 && (text.len() != 2 || !text.bytes().all(|v| v.is_ascii_uppercase())) {
                return Err(invalid(
                    "packed certificate country must be an ISO 3166 alpha-2 code",
                ));
            }
            if index == 2 && text != "Authenticator Attestation" {
                return Err(invalid(
                    "packed certificate OU must be Authenticator Attestation",
                ));
            }
        }
    }
    if present.iter().any(|v| !v) {
        return Err(invalid(
            "packed certificate subject requires C, O, OU and CN",
        ));
    }
    Ok(())
}

fn parse_aaguid(value: &[u8]) -> Result<[u8; 16]> {
    if value.len() != 18 || value[..2] != [4, 16] {
        return Err(invalid("malformed AAGUID extension"));
    }
    Ok(value[2..].try_into().unwrap())
}
