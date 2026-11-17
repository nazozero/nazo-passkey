//! Borrowed attestation parsing and statement verification.
//!
//! A valid certificate signature proves possession of the leaf private key.
//! It does not establish manufacturer identity, a trusted chain, certificate
//! validity at a particular time, metadata status, or hardware key protection.
//! The public result explicitly records that limitation.

use crate::auth_data::AuthenticatorData;
use crate::cbor::{Decoder, invalid};
use crate::cose::{ALG_ES256, CoseKey};
use crate::crypto;
use crate::error::{Error, Result};
use crate::types::AttestationEvidence;
use crate::x509::AttestationCert;

#[derive(Debug)]
pub(crate) struct ParsedAttestation<'a> {
    pub auth_data_raw: &'a [u8],
    pub auth_data: AuthenticatorData<'a>,
    att_stmt: AttestationStatement<'a>,
}

#[derive(Debug)]
enum AttestationStatement<'a> {
    None,
    Packed(Statement<'a>),
    FidoU2f(Statement<'a>),
}

impl<'a> ParsedAttestation<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Decoder::new(bytes, true)?;
        let count = reader.map()?;
        let mut previous = None;
        let mut fmt = None;
        let mut auth_data = None;
        let mut att_stmt = None;
        for _ in 0..count {
            let start = reader.position();
            let field = reader.text()?;
            reader.check_key_order(start, &mut previous)?;
            match field {
                "fmt" => fmt = Some(reader.text()?),
                "authData" => auth_data = Some(reader.bytes()?),
                "attStmt" => {
                    // CTAP2 canonical ordering puts "fmt" before "attStmt".
                    // Parse the selected schema once, borrowing its fields.
                    att_stmt = Some(match fmt {
                        Some("none") => {
                            if reader.map()? != 0 {
                                return Err(invalid("none attestation requires an empty attStmt"));
                            }
                            AttestationStatement::None
                        }
                        Some("packed") => {
                            AttestationStatement::Packed(Statement::parse(&mut reader, true)?)
                        }
                        Some("fido-u2f") => {
                            AttestationStatement::FidoU2f(Statement::parse(&mut reader, false)?)
                        }
                        Some(_) => return Err(invalid("unsupported attestation format")),
                        None => return Err(invalid("attestationObject missing fmt")),
                    });
                }
                _ => reader.skip()?,
            }
        }
        reader.finish()?;
        let auth_data_raw =
            auth_data.ok_or_else(|| invalid("attestationObject missing authData"))?;
        let att_stmt = att_stmt.ok_or_else(|| invalid("attestationObject missing attStmt"))?;
        let auth_data = AuthenticatorData::parse(auth_data_raw)?;
        Ok(Self {
            auth_data_raw,
            auth_data,
            att_stmt,
        })
    }

    pub(crate) fn verify_statement(
        &self,
        credential_key: &CoseKey,
        client_data_hash: &[u8; 32],
    ) -> Result<AttestationEvidence> {
        match &self.att_stmt {
            AttestationStatement::None => Ok(AttestationEvidence::None),
            AttestationStatement::Packed(statement) => {
                self.verify_packed(statement, credential_key, client_data_hash)
            }
            AttestationStatement::FidoU2f(statement) => {
                self.verify_fido_u2f(statement, credential_key, client_data_hash)
            }
        }
    }

    fn verify_packed(
        &self,
        statement: &Statement<'_>,
        key: &CoseKey,
        client_data_hash: &[u8; 32],
    ) -> Result<AttestationEvidence> {
        let alg = statement.alg.ok_or_else(|| invalid("packed missing alg"))?;
        let mut message = Vec::with_capacity(self.auth_data_raw.len() + 32);
        message.extend_from_slice(self.auth_data_raw);
        message.extend_from_slice(client_data_hash);
        if statement.chain_len == 0 {
            if alg != key.alg() {
                return Err(invalid("packed self attestation algorithm mismatch"));
            }
            crypto::verify(key, &message, statement.sig)?;
            return Ok(AttestationEvidence::SelfAttestation);
        }
        if alg != ALG_ES256 {
            return Err(Error::UnsupportedAlg(alg));
        }
        let leaf = AttestationCert::from_der(statement.chain[0], true)?;
        if let Some(cert_aaguid) = leaf.aaguid {
            let attested = self
                .auth_data
                .attested
                .as_ref()
                .ok_or_else(|| invalid("packed missing attested credential data"))?;
            if cert_aaguid != attested.aaguid {
                return Err(invalid("packed cert AAGUID does not match authData"));
            }
        }
        for certificate in &statement.chain[1..statement.chain_len] {
            AttestationCert::validate_der(certificate)?;
        }
        verify_es256_sec1(&leaf.p256_pubkey_sec1, &message, statement.sig)?;
        Ok(AttestationEvidence::UntrustedCertificate)
    }

    fn verify_fido_u2f(
        &self,
        statement: &Statement<'_>,
        key: &CoseKey,
        client_data_hash: &[u8; 32],
    ) -> Result<AttestationEvidence> {
        let CoseKey::Es256 { x, y } = key else {
            return Err(invalid("fido-u2f credential must use ES256"));
        };
        if statement.chain_len != 1 {
            return Err(invalid("fido-u2f requires exactly one certificate"));
        }
        let leaf = AttestationCert::from_der(statement.chain[0], false)?;
        let attested = self
            .auth_data
            .attested
            .as_ref()
            .ok_or_else(|| invalid("fido-u2f missing attested credential data"))?;
        let mut message = Vec::with_capacity(130 + attested.credential_id.len());
        message.push(0);
        message.extend_from_slice(&self.auth_data.rp_id_hash);
        message.extend_from_slice(client_data_hash);
        message.extend_from_slice(attested.credential_id);
        message.push(4);
        message.extend_from_slice(x);
        message.extend_from_slice(y);
        verify_es256_sec1(&leaf.p256_pubkey_sec1, &message, statement.sig)?;
        Ok(AttestationEvidence::UntrustedCertificate)
    }
}

/// Only stack-owned references to the bounded certificate chain and signature.
#[derive(Debug)]
struct Statement<'a> {
    alg: Option<i64>,
    sig: &'a [u8],
    chain: [&'a [u8]; 8],
    chain_len: usize,
}

impl<'a> Statement<'a> {
    fn parse(reader: &mut Decoder<'a>, packed: bool) -> Result<Self> {
        let count = reader.map()?;
        let mut previous = None;
        let mut alg = None;
        let mut sig = None;
        let mut chain = [&[][..]; 8];
        let mut chain_len = 0;
        for _ in 0..count {
            let start = reader.position();
            let name = reader.text()?;
            reader.check_key_order(start, &mut previous)?;
            match name {
                "alg" if packed => alg = Some(reader.integer()?),
                "sig" => {
                    let bytes = reader.bytes()?;
                    if bytes.is_empty() || bytes.len() > 80 {
                        return Err(invalid("attestation signature length invalid"));
                    }
                    sig = Some(bytes);
                }
                "x5c" => {
                    chain_len = reader.array()?;
                    if !(1..=chain.len()).contains(&chain_len) {
                        return Err(invalid("attestation certificate chain length invalid"));
                    }
                    for item in &mut chain[..chain_len] {
                        *item = reader.bytes()?;
                        if item.is_empty() || item.len() > 16384 {
                            return Err(invalid("attestation certificate size invalid"));
                        }
                    }
                }
                // In particular, do not silently interpret deprecated ECDAA
                // or an unrecognised attestation scheme as self-attestation.
                _ => return Err(invalid("unsupported attestation statement member")),
            }
        }
        Ok(Self {
            alg,
            sig: sig.ok_or_else(|| invalid("attestation statement missing signature"))?,
            chain,
            chain_len,
        })
    }
}

fn verify_es256_sec1(sec1: &[u8; 65], message: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(|_| Error::BadSignature)?;
    let signature = p256::ecdsa::Signature::from_der(sig).map_err(|_| Error::BadSignature)?;
    key.verify(message, &signature)
        .map_err(|_| Error::BadSignature)
}
