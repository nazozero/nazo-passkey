//! Wire types shared by registration + authentication ceremonies.
//!
//! Finish requests use the browser's `PublicKeyCredential.toJSON()` format.
//! Stored credential byte arrays retain their Serde array representation.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::error::{Error, Result};

// ---------- Challenge ----------------------------------------------------

/// 32 random bytes the browser signs (indirectly) to prove freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Challenge(pub Vec<u8>);

impl Challenge {
    /// Obtain 32 bytes directly from the operating system's CSPRNG, or Web
    /// Crypto on browser/worker WASM targets. No application PRNG state is kept.
    ///
    /// # Panics
    /// Panics if the platform cannot supply secure randomness. Never falls
    /// back to timestamps, counters, deterministic output, or weaker entropy.
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).expect("secure challenge randomness unavailable");
        Self(buf.to_vec())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Browser-friendly base64url encoding (no padding).
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
}

// ---------- CredentialId -------------------------------------------------

/// Authenticator-assigned credential ID. Opaque, treat as raw bytes;
/// not a UUID. Up to 1023 bytes long per the spec, in practice ~64–256.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(pub Vec<u8>);

impl CredentialId {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
    pub fn from_b64url(s: &str) -> Result<Self> {
        decode_b64_bounded(s, 1023, "credential ID").map(Self)
    }
}

// ---------- COSE / public-key blob --------------------------------------

/// COSE_Key-encoded public key (CBOR), exactly as carried in
/// `attestedCredentialData.credentialPublicKey`. Stored as-is so we can
/// verify signatures from the original public key encoding. Authentication
/// validates the stored COSE parameters without constructing an intermediate AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CosePublicKey(pub Vec<u8>);

impl CosePublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------- Configuration -----------------------------------------------

/// Relying-party identifier. By spec this is a domain (no scheme, no
/// port). `example.com`, not `https://example.com`. The browser's
/// SHA-256 of this string is what the authenticator signs into
/// `authenticatorData.rpIdHash`.
#[derive(Debug, Clone)]
pub struct RpId(pub(crate) String);

impl RpId {
    /// Construct from a string that already IS a bare RP ID
    /// (`example.com`, `subdomain.example.com`). Use this in
    /// production code where the value comes from a config file or
    /// known constant.
    ///
    /// If you might receive a full URL, use [`Self::try_from_url`]
    /// instead - this constructor stores the input verbatim and does
    /// NOT strip scheme/port/path, so passing `"https://example.com"`
    /// here gives you a broken RP ID.
    pub fn new(rp_id: impl Into<String>) -> Self {
        Self(rp_id.into())
    }

    /// Try to extract an RP ID from a URL or URL-like input.
    /// Accepts:
    ///   - bare domains:        `"example.com"`
    ///   - full origins:        `"https://example.com:8443"`
    ///   - origins with a path: `"https://example.com/auth/start"`
    ///
    /// Returns `Err` if the input is neither parseable as a URL nor a
    /// plausible bare hostname (no whitespace, no userinfo, etc.).
    /// Use this when the input might be a URL the operator pasted.
    pub fn try_from_url(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::Internal("RP ID is empty"));
        }

        // First try a strict URL parse - works for "https://..." inputs.
        if let Ok(u) = url::Url::parse(trimmed) {
            if let Some(host) = u.host_str() {
                return Ok(Self(host.to_owned()));
            }
            return Err(Error::Internal("URL has no host component"));
        }

        // Fall back: treat as a bare hostname. Reject anything that
        // contains characters a hostname cannot legitimately have
        // (whitespace, `@` for userinfo, `:` for ports, `/` for paths)
        // rather than silently mangling them as the v1 implementation
        // did.
        if trimmed
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '@' | ':' | '/' | '?' | '#'))
        {
            return Err(Error::Internal(
                "RP ID is not a bare hostname (contains scheme/port/path/userinfo)",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------- Helpers ------------------------------------------------------

/// Bound canonical base64url input before allocating the decoded buffer.
pub(crate) fn decode_b64_bounded(
    input: &str,
    limit: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if input.len() > limit.div_ceil(3) * 4 {
        return Err(Error::InputTooLarge { field, limit });
    }
    let bytes = B64URL
        .decode(input)
        .map_err(|error| Error::Base64(error.to_string()))?;
    if bytes.len() > limit {
        return Err(Error::InputTooLarge { field, limit });
    }
    Ok(bytes)
}

/// Decode a short wire field directly into caller-owned storage. The same
/// encodings and size policy as `decode_b64_bounded` apply; successful decoding
/// performs no allocation and never exposes bytes beyond the returned length.
pub(crate) fn decode_b64_into(
    input: &str,
    output: &mut [u8],
    field: &'static str,
) -> Result<usize> {
    let limit = output.len();
    if input.len() > limit.div_ceil(3) * 4 {
        return Err(Error::InputTooLarge { field, limit });
    }
    B64URL
        .decode_slice(input, output)
        .map_err(|error| match error {
            base64::DecodeSliceError::OutputSliceTooSmall => Error::InputTooLarge { field, limit },
            base64::DecodeSliceError::DecodeError(error) => Error::Base64(error.to_string()),
        })
}

// ---------- Wire structs (request bodies) -------------------------------

/// A browser `PublicKeyCredential.toJSON()` response.
///
/// Deserialization checks `type`, `id` and `rawId` and decodes the credential
/// ID once for account lookup and verification. Client extension results and
/// other unused browser hints are ignored.
#[derive(Debug)]
pub struct PublicKeyCredential<R> {
    pub id: CredentialId,
    pub response: R,
}

impl<'de, R: Deserialize<'de>> Deserialize<'de> for PublicKeyCredential<R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        use std::borrow::Cow;

        #[derive(Deserialize)]
        struct Wire<'a, R> {
            #[serde(borrow)]
            id: Cow<'a, str>,
            #[serde(rename = "rawId", borrow)]
            raw_id: Cow<'a, str>,
            #[serde(rename = "type", borrow)]
            kind: Cow<'a, str>,
            #[serde(
                deserialize_with = "deserialize_object",
                bound(deserialize = "R: Deserialize<'de>")
            )]
            response: R,
        }

        let wire: Wire<'_, R> = deserialize_object(deserializer)?;
        if wire.kind != "public-key" {
            return Err(de::Error::custom("credential type must be public-key"));
        }
        // In canonical base64url equal byte strings have equal encodings.
        if wire.id.is_empty() || wire.id != wire.raw_id {
            return Err(de::Error::custom(
                "credential id and rawId must match and be nonempty",
            ));
        }
        let id = CredentialId::from_b64url(&wire.id).map_err(de::Error::custom)?;
        Ok(Self {
            id,
            response: wire.response,
        })
    }
}

// WebAuthn JSON dictionaries are objects. Serde's derived structs also accept
// positional sequences unless the deserializer is asked for a map.
fn deserialize_object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a WebAuthn JSON object")
        }

        fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> std::result::Result<T, M::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

/// Standard JSON body for finishing registration.
pub type RegistrationResponse = PublicKeyCredential<AttestationResponse>;

/// Standard JSON body for finishing authentication.
pub type AuthenticationResponse = PublicKeyCredential<AssertionResponse>;

/// Registration response fields used by the verifier.
#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    /// Authenticator-attached transports (USB / NFC / BLE / internal).
    /// Optional; some browsers omit it.
    #[serde(default)]
    pub transports: Vec<String>,
    /// The attestation object (CBOR), base64url-encoded.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// The clientDataJSON (UTF-8 JSON), base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Authentication response fields used by the verifier.
#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    /// Raw authenticator data, base64url-encoded.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature over `authenticatorData || SHA-256(clientDataJSON)`,
    /// base64url-encoded.
    pub signature: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// User handle (the opaque user id we registered with). Optional;
    /// Required for discoverable credentials; checked against the account binding.
    #[serde(
        rename = "userHandle",
        default,
        deserialize_with = "deserialize_user_handle"
    )]
    pub user_handle: Option<Vec<u8>>,
}

fn deserialize_user_handle<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|handle| decode_b64_bounded(&handle, 64, "userHandle"))
        .transpose()
        .map_err(de::Error::custom)
}

// ---------- Challenge JSON for the START side ---------------------------

/// Discoverable-credential storage requested for registration.
///
/// The default requires discoverability so enrolled passkeys can support
/// username-less sign-in. UP, UV and account binding are verified separately.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    /// Require a discoverable credential; fail creation if unavailable.
    #[default]
    Required,
    /// Prefer a discoverable credential, allowing a non-discoverable fallback.
    Preferred,
    /// Prefer a non-discoverable credential.
    Discouraged,
}

/// Attestation conveyance requested from the browser.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// Preserve privacy by requesting no attestation statement.
    #[default]
    None,
    /// Request the authenticator's statement for an application trust policy.
    /// The browser may still return `none`.
    Direct,
}

/// Per-registration choices, independent of UV and authenticator attachment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegistrationOptions {
    pub resident_key: ResidentKeyRequirement,
    pub attestation: AttestationConveyancePreference,
}

/// What we send to the browser for `navigator.credentials.create()`.
/// All byte fields are base64url-encoded; the client JS is expected
/// to decode them before passing to the WebAuthn API.
#[derive(Debug, Serialize)]
pub struct RegistrationChallenge {
    pub challenge: String, // base64url
    pub rp: RpInfo,
    pub user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Credentials we already have for this user - browser SHOULD
    /// refuse to register a duplicate.
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub timeout: u32, // milliseconds
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: AttestationConveyancePreference,
}

#[derive(Debug, Serialize)]
pub struct RpInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String, // base64url
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub id: String, // base64url
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorSelection {
    /// Browser selection hint. It does not prove that a key is hardware
    /// protected, or authorize an authenticator-vendor policy.
    pub authenticator_attachment: Option<&'static str>,
    pub resident_key: ResidentKeyRequirement,
    pub user_verification: &'static str, // "preferred"
}

impl Serialize for AuthenticatorSelection {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let fields = 3 + usize::from(self.authenticator_attachment.is_some());
        let mut wire = serializer.serialize_struct("AuthenticatorSelection", fields)?;
        if let Some(attachment) = self.authenticator_attachment {
            wire.serialize_field("authenticatorAttachment", attachment)?;
        }
        wire.serialize_field("residentKey", &self.resident_key)?;
        // WebAuthn §5.4.4 derives this wire field from residentKey.
        wire.serialize_field(
            "requireResidentKey",
            &(self.resident_key == ResidentKeyRequirement::Required),
        )?;
        wire.serialize_field("userVerification", self.user_verification)?;
        wire.end()
    }
}

/// What we send to the browser for `navigator.credentials.get()`.
#[derive(Debug, Serialize)]
pub struct AuthenticationChallenge {
    pub challenge: String, // base64url
    #[serde(rename = "rpId")]
    pub rp_id: String,
    pub timeout: u32,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

// ---------- Ceremony state (server-side, opaque to client) --------------

/// Per-ceremony state retained between start_* and finish_*. Caller
/// stores this server-side keyed by however they like (session cookie,
/// user id, in-memory map). Treat as secret-ish: contains the
/// challenge we issued.
///
/// The state carries a `created_at` (Unix seconds, UTC) so callers can
/// reject stale ceremonies without needing their own out-of-band TTL.
/// `finish_*` ALSO enforces a hard ceiling (see
/// `Webauthn::CEREMONY_MAX_AGE_SECS`) so a forgetful caller cannot
/// accept a registration response from yesterday.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub challenge: Challenge,
    pub user_id: Vec<u8>,
    /// Unix timestamp (seconds, UTC) when `start_registration` was
    /// called. Stable serialization-friendly form.
    #[serde(default)]
    pub created_at: u64,
    /// Binds this state to the RP, origin and validation policy that issued it.
    /// Old in-flight states without a binding must restart their ceremony.
    #[serde(default)]
    pub context_binding: Option<[u8; 32]>,
    #[serde(default)]
    pub exclude_credentials: Vec<CredentialId>,
}

impl RegistrationState {
    /// `true` if more than `max_age_secs` seconds have elapsed since
    /// the ceremony was started. Cheap helper for callers that want
    /// to evict stale state from their session store proactively;
    /// `finish_registration` ALSO enforces its own ceiling.
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = now_secs();
        self.created_at == 0 || self.created_at > now || now - self.created_at > max_age_secs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub challenge: Challenge,
    /// Credentials the browser was allowed to use, so finish_* can
    /// verify the asserted credential id is one of them.
    pub allow_credentials: Vec<CredentialId>,
    /// Unix timestamp (seconds, UTC) when `start_authentication` was
    /// called.
    #[serde(default)]
    pub created_at: u64,
    /// User handle the caller expects to authenticate. Populated by
    /// [`crate::Webauthn::start_authentication_for_user`] for
    /// username-first flows; left `None` for discoverable-credential
    /// (passwordless) flows where the user is not known until the
    /// response arrives.
    ///
    /// When `Some` AND the assertion response carries a `userHandle`,
    /// `finish_authentication` enforces equality (WebAuthn-3 §7.2 step
    /// 6). `#[serde(default)]` means states persisted by older
    /// versions of the crate deserialize cleanly with `None`.
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,
    #[serde(default)]
    pub context_binding: Option<[u8; 32]>,
}

impl AuthenticationState {
    /// See [`RegistrationState::is_expired`].
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = now_secs();
        self.created_at == 0 || self.created_at > now || now - self.created_at > max_age_secs
    }
}

/// Current Unix time in seconds. Used to stamp ceremony states.
/// Saturates to 0 if the system clock is before the Unix epoch (which
/// will never happen on a sane host) so the helpers never panic.
pub(crate) fn now_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- Outcomes ----------------------------------------------------

/// What registration actually established. No variant asserts a trusted vendor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEvidence {
    /// Older records did not retain attestation evidence.
    #[default]
    Unknown,
    /// No attestation signature or authenticator provenance was verified.
    None,
    /// The credential key verified its own attestation signature.
    SelfAttestation,
    /// Certificate profile and statement signature verified; chain trust,
    /// certificate validity and manufacturer identity remain unverified.
    UntrustedCertificate,
}

/// Protocol-checked attestation supplied to the application's registration policy.
///
/// The certificate slices borrow the decoded response and are valid only during
/// the callback. Their order is the original `x5c` order, with the leaf first.
/// The applicable leaf profile and statement signature have been checked; other
/// certificates have been checked for valid DER. The application decides chain
/// trust, validity, revocation and metadata policy.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedAttestation<'a> {
    /// What the verifier established, independently of the requested conveyance.
    pub evidence: AttestationEvidence,
    /// The verified statement format: `none`, `packed`, or `fido-u2f`.
    pub format: &'static str,
    /// The credential's AAGUID. Packed statements sign this field; `none` and
    /// `fido-u2f` leave it unauthenticated. Manufacturer provenance requires
    /// the application's certificate and metadata trust decision.
    pub aaguid: [u8; 16],
    /// DER certificates in leaf-first order; empty for none or self-attestation.
    /// This is the supplied `x5c` sequence, not a validated certificate path.
    pub certificate_chain: &'a [&'a [u8]],
}

/// Stored after a successful registration. The caller persists this
/// (one row per credential per user) and looks it up at auth time.
///
/// `Serialize + Deserialize` are derived so callers can stash the
/// whole credential in a single column (e.g. a JSONB blob or a
/// `SecretString`-wrapped JSON string) without writing a wrapper struct.
/// The legacy wire shape is preserved: `CredentialId` and `CosePublicKey`
/// serialize as JSON arrays of byte integers. New security metadata is optional
/// on old records; absence is represented explicitly as unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub public_key_cose: CosePublicKey,
    pub counter: u32,
    pub transports: Vec<String>,
    /// Authenticator AAGUID, as carried in attestedCredentialData.
    ///
    /// Informational only - this crate does NOT validate it against
    /// the FIDO Metadata Service or any allow/deny list. Callers who
    /// want authenticator-attestation policy (e.g. "reject Yubikeys
    /// older than firmware 5.2") must implement that check themselves
    /// using a separately validated trust path. With attestation "none", a
    /// nonzero AAGUID is still possible and provides no manufacturer proof.
    pub aaguid: [u8; 16],
    /// Account handle captured during registration. Missing on legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
    /// Whether UV was established at registration or subsequently authorized
    /// using an independent factor. `None` means unknown, never implicitly true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv_initialized: Option<bool>,
    /// Immutable backup eligibility; absent on records from older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_eligible: Option<bool>,
    /// Last authenticated backup state, persisted together with the counter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_state: Option<bool>,
    #[serde(default)]
    pub attestation: AttestationEvidence,
}

/// Result of comparing the authenticated signature counter with the stored one.
///
/// WebAuthn §7.2 leaves the response to a non-increasing counter to the relying
/// party's risk policy. Such a result may indicate cloning, a malfunction, or
/// reordered concurrent assertions; it does not invalidate the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterStatus {
    /// Both counters are zero; this credential does not supply a counter signal.
    Unsupported,
    /// The authenticated counter is greater than the stored counter.
    Advanced,
    /// At least one counter is nonzero and the authenticated counter did not rise.
    NonIncreasing,
}

/// Authenticated credential facts and the snapshot they were verified against.
///
/// After accepting the counter outcome, persist the new values atomically only
/// if the expected values still match. Compare backup state even for zero-only
/// counters so an update based on a different backup state fails the comparison.
/// User-verification initialization requires application authorization and is
/// deliberately absent from this protocol update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialUpdate {
    pub expected_counter: u32,
    pub new_counter: u32,
    pub expected_backup_eligible: Option<bool>,
    pub backup_eligible: bool,
    pub expected_backup_state: Option<bool>,
    pub backup_state: bool,
}

/// Cryptographically verified authentication outcome.
///
/// Apply the relying party's counter policy and atomically persist `update`
/// before creating a session. The relying party decides how to handle
/// [`CounterStatus::NonIncreasing`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSuccess {
    pub credential_id: CredentialId,
    pub update: CredentialUpdate,
    pub counter_status: CounterStatus,
    pub user_verified: bool,
    /// The signed UV flag may count as a factor only when this is true.
    /// A false/unknown `uv_initialized` cannot be upgraded by this assertion alone.
    #[serde(default)]
    pub user_verification_eligible: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_base64_decoding_enforces_canonical_encoding_and_bounds() {
        for limit in [0, 1, 2, 3, 32, 64, 80] {
            for length in 0..=limit + 3 {
                let bytes: Vec<_> = (0..length).map(|i| (i as u8).wrapping_mul(127)).collect();
                let encoded = B64URL.encode(&bytes);
                let bounded = decode_b64_bounded(&encoded, limit, "test");
                let mut output = vec![0xa5; limit];
                let actual = decode_b64_into(&encoded, &mut output, "test");
                assert_eq!(actual.is_ok(), length <= limit);
                assert_eq!(bounded.is_ok(), actual.is_ok());
                if let (Ok(written), Ok(expected)) = (actual, bounded) {
                    assert_eq!(&output[..written], expected);
                }
            }
        }
        for invalid in ["!", "A", "Zh", "Zg=", "Zg==", "Zg==\\n", "+/8"] {
            assert!(decode_b64_into(invalid, &mut [0; 80], "test").is_err());
            assert!(decode_b64_bounded(invalid, 80, "test").is_err());
        }
    }

    #[test]
    fn standard_registration_response_uses_only_verifier_fields() {
        let wire = r#"{
            "type":"public-key","id":"-_8","rawId":"-_8",
            "response":{
                "attestationObject":"AA","clientDataJSON":"AQ","transports":["usb"],
                "authenticatorData":"Ag","publicKeyAlgorithm":-7
            },
            "clientExtensionResults":{"credProps":{"rk":true}},
            "authenticatorAttachment":"cross-platform"
        }"#;
        let parsed: RegistrationResponse = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.id.as_bytes(), [0xfb, 0xff]);
        assert_eq!(parsed.response.attestation_object, "AA");
        assert_eq!(parsed.response.client_data_json, "AQ");
        assert_eq!(parsed.response.transports, ["usb"]);
    }

    #[test]
    fn standard_assertion_response_checks_required_fields_and_id_consistency() {
        let wire = serde_json::json!({
            "type":"public-key", "id":"-_8", "rawId":"-_8",
            "response": {
                "authenticatorData":"AA", "clientDataJSON":"AQ", "signature":"Ag", "userHandle":"Aw"
            },
            "clientExtensionResults": {}
        });
        let parsed: AuthenticationResponse = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(parsed.id.as_bytes(), [0xfb, 0xff]);
        assert_eq!(parsed.response.signature, "Ag");
        assert_eq!(parsed.response.user_handle.as_deref(), Some(&[3][..]));

        for key in ["type", "id", "rawId", "response"] {
            let mut missing = wire.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<AuthenticationResponse>(missing).is_err(),
                "{key}"
            );
        }
        for key in ["authenticatorData", "clientDataJSON", "signature"] {
            let mut missing = wire.clone();
            missing["response"].as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<AuthenticationResponse>(missing).is_err(),
                "{key}"
            );
        }

        for (key, invalid) in [("rawId", "AA"), ("type", "password")] {
            let mut mismatched = wire.clone();
            mismatched[key] = invalid.into();
            assert!(serde_json::from_value::<AuthenticationResponse>(mismatched).is_err());
        }
        for id in ["", "+/8", "-_8=", "-_9", &B64URL.encode(vec![5; 1024])] {
            let mut invalid = wire.clone();
            invalid["id"] = id.into();
            invalid["rawId"] = id.into();
            assert!(
                serde_json::from_value::<AuthenticationResponse>(invalid).is_err(),
                "{id}"
            );
        }

        let mut invalid_handle = wire.clone();
        invalid_handle["response"]["userHandle"] = B64URL.encode(vec![5; 65]).into();
        assert!(serde_json::from_value::<AuthenticationResponse>(invalid_handle).is_err());

        let mut omitted_handle = wire;
        omitted_handle["response"]
            .as_object_mut()
            .unwrap()
            .remove("userHandle");
        let parsed = serde_json::from_value::<AuthenticationResponse>(omitted_handle).unwrap();
        assert_eq!(parsed.response.user_handle, None);
    }

    #[test]
    fn rejects_flat_bodies_and_duplicate_security_fields() {
        let flat = r#"{"id":"AA","attestationObject":"AA","clientDataJSON":"AA"}"#;
        assert!(serde_json::from_str::<RegistrationResponse>(flat).is_err());
        let response = r#"{"attestationObject":"AA","clientDataJSON":"AA"}"#;
        for duplicate in [
            r#""type":"public-key""#,
            r#""id":"AA""#,
            r#""rawId":"AA""#,
            r#""response":{}"#,
        ] {
            let wire = format!(
                r#"{{"type":"public-key","id":"AA","rawId":"AA","response":{response},{duplicate}}}"#
            );
            assert!(serde_json::from_str::<RegistrationResponse>(&wire).is_err());
        }
        let duplicate = r#"{"type":"public-key","id":"AA","rawId":"AA",
            "response":{"attestationObject":"AA","clientDataJSON":"AA","clientDataJSON":"AA"}}"#;
        assert!(serde_json::from_str::<RegistrationResponse>(duplicate).is_err());
    }

    #[test]
    fn credential_envelope_and_nested_response_must_be_objects() {
        let positional =
            r#"["AA","AA","public-key",{"attestationObject":"AA","clientDataJSON":"AA"}]"#;
        assert!(serde_json::from_str::<RegistrationResponse>(positional).is_err());
        let positional =
            r#"{"type":"public-key","id":"AA","rawId":"AA","response":[[],"AA","AA"]}"#;
        assert!(serde_json::from_str::<RegistrationResponse>(positional).is_err());
    }

    // ---- RpId ----------------------------------------------------------

    #[test]
    fn rpid_new_stores_verbatim() {
        assert_eq!(RpId::new("example.com").as_str(), "example.com");
        // No magic stripping any more.
        assert_eq!(RpId::new("sub.example.com").as_str(), "sub.example.com");
    }

    #[test]
    fn rpid_try_from_url_bare_domain() {
        assert_eq!(
            RpId::try_from_url("example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_https_origin() {
        assert_eq!(
            RpId::try_from_url("https://example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_with_port_and_path() {
        assert_eq!(
            RpId::try_from_url("https://example.com:8443/auth/start")
                .unwrap()
                .as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_rejects_userinfo_in_bare() {
        // "user:pass@host" looks like a hostname but isn't one. The v1
        // implementation silently truncated to "user" - we reject.
        assert!(RpId::try_from_url("user:pass@example.com").is_err());
    }

    #[test]
    fn rpid_try_from_url_rejects_empty() {
        assert!(RpId::try_from_url("").is_err());
        assert!(RpId::try_from_url("   ").is_err());
    }

    // ── PasskeyCredential serde round-trip ────────────────────────────────
    // Callers persist a `PasskeyCredential` as a single JSON blob (e.g. a
    // SecretString-wrapped column on a `passkeys` row). The two tests
    // below pin the wire shape so a future field addition can't silently
    // break that storage contract.

    fn fixture_credential() -> PasskeyCredential {
        PasskeyCredential {
            id: CredentialId(vec![0x01, 0x02, 0x03, 0x04]),
            public_key_cose: CosePublicKey(vec![0xAA, 0xBB, 0xCC]),
            counter: 7,
            transports: vec!["usb".into(), "nfc".into()],
            aaguid: [0xFE; 16],
            user_handle: None,
            uv_initialized: None,
            backup_eligible: None,
            backup_state: None,
            attestation: AttestationEvidence::Unknown,
        }
    }

    #[test]
    fn passkey_credential_json_round_trips() {
        let original = fixture_credential();
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: PasskeyCredential = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.id.0, original.id.0);
        assert_eq!(back.public_key_cose.0, original.public_key_cose.0);
        assert_eq!(back.counter, original.counter);
        assert_eq!(back.transports, original.transports);
        assert_eq!(back.aaguid, original.aaguid);
    }

    #[test]
    fn auth_success_json_round_trips() {
        let original = AuthSuccess {
            credential_id: CredentialId(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            update: CredentialUpdate {
                expected_counter: 41,
                new_counter: 42,
                expected_backup_eligible: Some(false),
                backup_eligible: false,
                expected_backup_state: Some(false),
                backup_state: false,
            },
            counter_status: CounterStatus::Advanced,
            user_verified: true,
            user_verification_eligible: true,
        };
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: AuthSuccess = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.credential_id.0, original.credential_id.0);
        assert_eq!(back.update, original.update);
        assert_eq!(back.counter_status, original.counter_status);
        assert_eq!(back.user_verified, original.user_verified);
    }
}
