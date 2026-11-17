//! Parse + validate `clientDataJSON`.
//!
//! Format (UTF-8 JSON, NOT to be transformed before SHA-256ing):
//! ```text
//! {
//!   "type":      "webauthn.create" | "webauthn.get",
//!   "challenge": "<base64url>",
//!   "origin":    "https://example.com",
//!   "crossOrigin": false,
//!   ...
//! }
//! ```
//! We deserialize the typed shape *for validation* but keep the raw
//! bytes around because the spec hashes those exact bytes into the
//! signed message (any pretty-printing or field reordering would
//! break verification).

use std::borrow::Cow;

use serde::{Deserialize, Deserializer};

use crate::error::{Error, Result};
use crate::types::{Challenge, decode_b64_bounded};

/// Type tags the spec puts in `clientDataJSON.type`.
pub(crate) const TYPE_REGISTER: &str = "webauthn.create";
pub(crate) const TYPE_AUTHENTICATE: &str = "webauthn.get";

#[derive(Debug, Deserialize)]
struct Parsed<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    #[serde(borrow)]
    challenge: Cow<'a, str>,
    #[serde(borrow)]
    origin: Cow<'a, str>,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    // A present null is not a DOMString and must not look like an absent field.
    #[serde(rename = "topOrigin", default, deserialize_with = "present_string")]
    top_origin: Option<String>,
}

fn present_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// Validate the exact signed bytes. A single UTF-8 BOM is removed only for
/// JSON decoding (WebAuthn §7); it remains in the returned bytes for hashing.
/// Unknown JSON fields remain allowed for forward compatibility. This RP
/// supports same-origin ceremonies: crossOrigin=true or topOrigin is rejected.
pub(crate) fn validate(
    encoded: &str,
    expected_type: &'static str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    strict: bool,
) -> Result<Vec<u8>> {
    let raw = decode_b64_bounded(encoded, strict, 8192, "clientDataJSON")?;
    let json = raw.as_slice().trim_prefix(&[0xef, 0xbb, 0xbf]);
    let p: Parsed<'_> =
        serde_json::from_slice(json).map_err(|e| Error::ClientData(e.to_string()))?;
    if p.kind != expected_type {
        return Err(Error::ClientDataType {
            expected: expected_type,
            actual: p.kind.into_owned(),
        });
    }
    let got_challenge = decode_b64_bounded(&p.challenge, strict, 64, "challenge")?;
    if got_challenge != expected_challenge.as_bytes() {
        return Err(Error::ChallengeMismatch);
    }
    if p.origin != expected_origin {
        return Err(Error::OriginMismatch {
            expected: expected_origin.to_owned(),
            actual: p.origin.into_owned(),
        });
    }
    if p.cross_origin || p.top_origin.is_some() {
        return Err(Error::CrossOriginUnsupported);
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn make_cdj(kind: &str, challenge_b64: &str, origin: &str) -> String {
        let json = format!(
            r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        );
        B64URL.encode(json.as_bytes())
    }

    #[test]
    fn happy_path_register() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://example.com");
        let raw = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap();
        // Returned raw is the decoded JSON, suitable for hashing.
        assert!(raw.starts_with(b"{\"type\":\"webauthn.create\""));
    }

    #[test]
    fn wrong_type_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.get", &chal.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ClientDataType { .. }));
    }

    #[test]
    fn wrong_challenge_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let bad = Challenge(vec![9, 9, 9]);
        let cdj = make_cdj("webauthn.create", &bad.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn wrong_origin_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://evil.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::OriginMismatch { .. }));
    }
    #[test]
    fn same_origin_policy_rejects_cross_origin_and_top_origin() {
        let challenge = Challenge(vec![9; 32]);
        for extra in [
            r#","crossOrigin":true"#,
            r#","topOrigin":"https://evil.example""#,
        ] {
            let json = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com"{extra}}}"#,
                challenge.to_b64url()
            );
            assert!(matches!(
                validate(
                    &B64URL.encode(json),
                    TYPE_AUTHENTICATE,
                    &challenge,
                    "https://example.com",
                    true
                ),
                Err(Error::CrossOriginUnsupported)
            ));
        }
    }

    #[test]
    fn bom_is_ignored_for_json_but_preserved_for_signature_hash() {
        let challenge = Challenge(vec![9; 32]);
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","futureField":42}}"#,
            challenge.to_b64url()
        );
        let mut raw = vec![0xef, 0xbb, 0xbf];
        raw.extend(json.as_bytes());
        assert_eq!(
            validate(
                &B64URL.encode(&raw),
                TYPE_AUTHENTICATE,
                &challenge,
                "https://example.com",
                true
            )
            .unwrap(),
            raw
        );
    }

    #[test]
    fn duplicate_security_fields_null_top_origin_and_oversize_are_rejected() {
        let challenge = Challenge(vec![9; 32]);
        for extra in [
            r#","origin":"https://example.com""#,
            r#","topOrigin":null"#,
            r#","crossOrigin":null"#,
        ] {
            let json = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com"{extra}}}"#,
                challenge.to_b64url()
            );
            assert!(
                validate(
                    &B64URL.encode(json),
                    TYPE_AUTHENTICATE,
                    &challenge,
                    "https://example.com",
                    true
                )
                .is_err()
            );
        }
        assert!(matches!(
            validate(
                &"A".repeat(20000),
                TYPE_AUTHENTICATE,
                &challenge,
                "https://example.com",
                true
            ),
            Err(Error::InputTooLarge { .. })
        ));
    }
}
