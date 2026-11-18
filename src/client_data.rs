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
use crate::types::{Challenge, decode_b64_bounded, decode_b64_into};

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

/// Validate the exact signed bytes. JSON decoding removes one leading BOM and
/// replaces malformed UTF-8 (WebAuthn §7); hashing uses the unchanged bytes.
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
    let json = String::from_utf8_lossy(json);
    let p: Parsed<'_> =
        serde_json::from_str(&json).map_err(|e| Error::ClientData(e.to_string()))?;
    if p.kind != expected_type {
        return Err(Error::ClientDataType {
            expected: expected_type,
            actual: p.kind.into_owned(),
        });
    }
    let mut challenge = [0; 64];
    // The signed challenge is always canonical base64url (WebAuthn §7.1/§7.2).
    // The compatibility setting only applies to the outer JSON adapter.
    let length = decode_b64_into(&p.challenge, true, &mut challenge, "challenge")?;
    if &challenge[..length] != expected_challenge.as_bytes() {
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
    fn signed_challenge_is_canonical_even_with_a_lenient_outer_adapter() {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE};

        let challenge = Challenge(vec![0xfb; 32]);
        for encoded_challenge in [
            URL_SAFE.encode(challenge.as_bytes()),
            STANDARD_NO_PAD.encode(challenge.as_bytes()),
        ] {
            let cdj = make_cdj(TYPE_AUTHENTICATE, &encoded_challenge, "https://example.com");
            assert!(matches!(
                validate(
                    &cdj,
                    TYPE_AUTHENTICATE,
                    &challenge,
                    "https://example.com",
                    false
                ),
                Err(Error::Base64(_))
            ));
        }

        let raw = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com"}}"#,
            challenge.to_b64url()
        );
        assert_eq!(
            validate(
                &URL_SAFE.encode(raw.as_bytes()),
                TYPE_AUTHENTICATE,
                &challenge,
                "https://example.com",
                false,
            )
            .unwrap(),
            raw.as_bytes()
        );
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
    fn utf8_replacement_only_affects_json_decoding() {
        let challenge = Challenge(vec![9; 32]);
        let mut raw = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","future"#,
            challenge.to_b64url()
        )
        .into_bytes();
        raw.extend_from_slice(b"\xff\":\"\xed\xa0\x80\"}");
        assert_eq!(
            validate(
                &B64URL.encode(&raw),
                TYPE_AUTHENTICATE,
                &challenge,
                "https://example.com",
                true,
            )
            .unwrap(),
            raw
        );

        let mut twice_bom = vec![0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf];
        twice_bom.extend_from_slice(&raw);
        assert!(matches!(
            validate(
                &B64URL.encode(twice_bom),
                TYPE_AUTHENTICATE,
                &challenge,
                "https://example.com",
                true,
            ),
            Err(Error::ClientData(_))
        ));
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
