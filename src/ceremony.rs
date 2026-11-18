//! High-level register / authenticate flow. Wires the parsers + the
//! crypto layer together into the WebAuthn ceremony state machine.

use sha2::{Digest, Sha256};

use crate::attestation::ParsedAttestation;
use crate::auth_data::AuthenticatorData;
use crate::client_data::{self, TYPE_AUTHENTICATE, TYPE_REGISTER};
use crate::cose::{ALG_EDDSA, ALG_ES256, CoseKey};
use crate::crypto;
use crate::error::{Error, Result};
use crate::types::{
    AuthSuccess, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    AuthenticatorSelection, Challenge, CosePublicKey, CredentialDescriptor, CredentialId,
    PasskeyCredential, PubKeyCredParam, RegistrationChallenge, RegistrationOptions,
    RegistrationResponse, RegistrationState, RpId, RpInfo, UserInfo, VerifiedAttestation,
    decode_b64_bounded, decode_b64_into, now_secs,
};

const CEREMONY_TIMEOUT_MS: u32 = 60_000;

/// Algorithms this crate is willing to accept on a registered credential,
/// in MOST-preferred order (per WebAuthn §5.4.3 the RP advertises a
/// preference; the authenticator picks one of the listed values).
///
/// Used in two places that must agree:
///   1. `start_registration` advertises this list to the browser in
///      `pubKeyCredParams`.
///   2. `finish_registration` enforces (WebAuthn-3 §7.1 step 19) that
///      the algorithm of the credential the authenticator actually
///      returned is one of the advertised values. Without this check a
///      hostile or buggy authenticator could register a key for any
///      algorithm our COSE parser happens to support — bypassing the
///      relying party's algorithm policy.
const ALLOWED_REGISTRATION_ALGS: &[i64] = &[ALG_ES256, ALG_EDDSA];

/// Hard ceiling on how old a ceremony state may be when `finish_*` is
/// called. Slightly larger than `CEREMONY_TIMEOUT_MS` (which is what
/// we ask the browser to honour) so a slow round-trip does not trigger
/// false rejections. The point is defence-in-depth: even a caller who
/// forgets to TTL their session store cannot accept a registration
/// response from yesterday.
pub(crate) const CEREMONY_MAX_AGE_SECS: u64 = 300;

/// Which class of authenticator the relying party wants to use.
///
/// This becomes the `authenticatorSelection.authenticatorAttachment`
/// field in the registration challenge - a hint to the browser about
/// which authenticators to surface to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    /// Built-in authenticators only: Touch ID, Windows Hello,
    /// Android biometrics, ChromeOS, iCloud Keychain. The Gmail /
    /// iCloud "synced passkey" flow lives here. **Default.**
    Platform,
    /// Roaming / removable authenticators: USB Yubikeys, NFC, BLE
    /// security keys. This is a browser selection preference, not proof
    /// of hardware protection or manufacturer identity.
    CrossPlatform,
    /// No preference - the browser offers both platform and roaming
    /// authenticators and lets the user pick. Use this when you want
    /// to support hardware keys AND platform authenticators
    /// simultaneously (e.g. "any passkey works").
    Any,
}

impl Attachment {
    /// String that goes on the wire, or `None` to omit the field
    /// entirely (which is how WebAuthn signals "no preference").
    fn as_token(self) -> Option<&'static str> {
        match self {
            Self::Platform => Some("platform"),
            Self::CrossPlatform => Some("cross-platform"),
            Self::Any => None,
        }
    }
}

/// The relying-party-side WebAuthn façade. Construct once at boot and
/// re-use for every ceremony. Cheap to clone; carries only `String`s
/// internally.
#[derive(Debug, Clone)]
pub struct Webauthn {
    rp_id: RpId,
    rp_name: String,
    origin: String,
    /// When `true`, finish_registration and finish_authentication
    /// fail with Error::UserNotVerified if the authenticator did not
    /// set the UV flag. This is what a production passkey deployment
    /// almost always wants - the user has to prove identity (Touch
    /// ID, biometric, PIN), not just presence (any button press).
    require_uv: bool,
    /// Which authenticator class to ask the browser for at
    /// registration time. Does NOT affect authentication - by then
    /// the user already has a specific credential.
    attachment: Attachment,
    /// When `true`, `finish_authentication` REQUIRES the assertion
    /// response to include a `userHandle` whenever the ceremony was
    /// started via `start_authentication_for_user`. WebAuthn-3 §7.2
    /// step 6 says "if present, verify"; this flag tightens that to
    /// "must be present and verify." Recommended for platform-
    /// authenticator-only deployments (Touch ID, Windows Hello,
    /// iCloud Keychain) where the user_handle is always emitted.
    /// Leave `false` (default) if you also accept hardware keys in
    /// non-resident mode, where the user_handle may legitimately be
    /// absent.
    require_user_handle: bool,
    rp_id_hash: [u8; 32],
    context_binding: [u8; 32],
}

impl Webauthn {
    /// `rp_id` is the bare domain (e.g. `"example.com"`). `origin` is
    /// the full scheme+host (e.g. `"https://example.com"`); it must
    /// match exactly what the browser puts into `clientDataJSON.origin`.
    ///
    /// # Panics
    ///
    /// Panics if the configuration fails [`Self::try_new`]. Applications
    /// loading external configuration should use the fallible constructor.
    ///
    /// Use [`RpId::try_from_url`] if you have a URL/origin string and
    /// want a graceful conversion.
    ///
    /// Defaults to NOT requiring user verification on the server side;
    /// the JSON challenges still ask for `userVerification: "preferred"`.
    /// Call [`Self::require_user_verification`] to flip the server
    /// check to strict before using it in production.
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> Self {
        Self::try_new(rp_id, rp_name, origin).expect("invalid WebAuthn RP configuration")
    }

    /// Validate RP configuration once, before issuing any ceremonies.
    /// This implementation supports HTTPS web origins (HTTP only for local
    /// development), and the RP host itself or a parent domain. Related-origin
    /// and embedded cross-origin ceremonies are not enabled.
    pub fn try_new(rp_id: &str, rp_name: &str, origin: &str) -> Result<Self> {
        let url =
            url::Url::parse(origin).map_err(|_| Error::Configuration("origin is not a URL"))?;
        if url.origin().ascii_serialization() != origin
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Configuration(
                "origin must be its exact scheme/host/port serialization",
            ));
        }
        let host = url
            .host_str()
            .ok_or(Error::Configuration("origin has no host"))?;
        let local = host == "localhost"
            || host.ends_with(".localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if url.scheme() != "https" && !(url.scheme() == "http" && local) {
            return Err(Error::Configuration(
                "origin must use HTTPS, except localhost/loopback",
            ));
        }
        if rp_id.is_empty()
            || rp_id.len() > 253
            || origin.len() > 2048
            || rp_id
                .bytes()
                .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@' | b'?' | b'#'))
            || !(host == rp_id
                || (matches!(url.host(), Some(url::Host::Domain(_)))
                    && host
                        .strip_suffix(rp_id)
                        .is_some_and(|prefix| prefix.ends_with('.'))))
        {
            return Err(Error::Configuration(
                "RP ID must be the origin host or its domain suffix",
            ));
        }
        let rp_id_hash = sha256_32(rp_id.as_bytes());
        let mut this = Self {
            rp_id: RpId::new(rp_id),
            rp_name: rp_name.to_owned(),
            origin: origin.to_owned(),
            require_uv: false,
            attachment: Attachment::Platform,
            require_user_handle: false,
            rp_id_hash,
            context_binding: [0; 32],
        };
        this.bind_context();
        Ok(this)
    }

    fn bind_context(&mut self) {
        let mut digest = Sha256::new();
        digest.update([
            2,
            u8::from(self.require_uv),
            u8::from(self.require_user_handle),
        ]);
        digest.update(self.rp_id_hash);
        digest.update(self.origin.as_bytes());
        self.context_binding = digest.finalize().into();
    }

    fn check_state(
        &self,
        created_at: u64,
        binding: Option<[u8; 32]>,
        challenge: &Challenge,
    ) -> Result<()> {
        check_not_expired(created_at)?;
        if binding != Some(self.context_binding) {
            return Err(Error::InvalidState(
                "RP/origin/policy binding missing or changed; restart ceremony",
            ));
        }
        if !(16..=64).contains(&challenge.as_bytes().len()) {
            return Err(Error::InvalidState(
                "challenge length must be 16..=64 bytes",
            ));
        }
        Ok(())
    }

    /// Builder: when `true`, an authentication ceremony started via
    /// [`Self::start_authentication_for_user`] REQUIRES the assertion
    /// response to carry a matching `userHandle`. A missing
    /// `userHandle` becomes `Error::UserHandleMismatch`.
    ///
    /// WebAuthn-3 §7.2 step 6 only mandates checking the user_handle
    /// "if present"; this flag tightens that to "must be present and
    /// match." Use it when your deployment only accepts platform
    /// authenticators (Touch ID, Windows Hello, iCloud Keychain) or
    /// hardware keys in resident-credential mode — those always emit
    /// a user_handle. Leave it `false` (default) if you also accept
    /// hardware keys in non-resident mode, where the user_handle is
    /// legitimately absent.
    ///
    /// Also applies to the generic entry points. A stored handle or the
    /// explicit discoverable-account binding supplies the expected value.
    #[must_use]
    pub fn require_user_handle(mut self, require: bool) -> Self {
        self.require_user_handle = require;
        self.bind_context();
        self
    }

    /// Builder method: when set to `true`, the server REJECTS any
    /// ceremony where the authenticator did not set the UV flag.
    /// Recommended for any deployment where presence-only credentials
    /// (e.g. a button press on a roaming key) should not count as
    /// authentication.
    ///
    /// Also tightens the challenge sent to the browser to ask for
    /// `userVerification: "required"`, so a compliant browser will
    /// not even attempt a UV-less assertion.
    #[must_use]
    pub fn require_user_verification(mut self, require: bool) -> Self {
        self.require_uv = require;
        self.bind_context();
        self
    }

    /// Builder method: which class of authenticator to request at
    /// registration time. Defaults to [`Attachment::Platform`] (the
    /// built-in biometric / cloud-keychain flow, like Gmail).
    ///
    /// Set to [`Attachment::CrossPlatform`] for hardware-key-only
    /// deployments, or [`Attachment::Any`] to let the user pick
    /// between a built-in passkey and a hardware key.
    ///
    /// Does not affect authentication - by the time the user is
    /// asserting, they have already chosen which credential to use.
    #[must_use]
    pub fn authenticator_attachment(mut self, attachment: Attachment) -> Self {
        self.attachment = attachment;
        self
    }

    pub fn rp_id(&self) -> &str {
        self.rp_id.as_str()
    }

    /// The `userVerification` string we put into the challenge JSON.
    /// Mirrors `require_uv`: "required" if strict, "preferred" otherwise.
    fn uv_token(&self) -> &'static str {
        if self.require_uv {
            "required"
        } else {
            "preferred"
        }
    }

    // ─── Registration ─────────────────────────────────────────────────

    /// Build the challenge to feed to `navigator.credentials.create()`.
    /// Returned `RegistrationState` is what the caller must hand back
    /// to `finish_registration` (typically stashed in a session-keyed
    /// map with a short TTL).
    /// `RegistrationOptions::default()` requests a discoverable credential
    /// with no attestation statement. UV follows this RP's verification policy.
    pub fn start_registration(
        &self,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        existing: &[CredentialId],
        options: RegistrationOptions,
    ) -> (RegistrationChallenge, RegistrationState) {
        self.try_start_registration(user_id, user_name, user_display_name, existing, options)
            .expect("user handle must contain 1..=64 bytes")
    }

    /// Fallible registration entry point for applications accepting user handles
    /// from an external source. The infallible variant requires a valid handle.
    pub fn try_start_registration(
        &self,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        existing: &[CredentialId],
        options: RegistrationOptions,
    ) -> Result<(RegistrationChallenge, RegistrationState)> {
        if !(1..=64).contains(&user_id.len()) {
            return Err(Error::InvalidState("user handle must contain 1..=64 bytes"));
        }
        let challenge = Challenge::random();
        let exclude = existing
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.to_b64url(),
                transports: Vec::new(),
            })
            .collect();
        let chal = RegistrationChallenge {
            challenge: challenge.to_b64url(),
            rp: RpInfo {
                id: self.rp_id.as_str().to_owned(),
                name: self.rp_name.clone(),
            },
            user: UserInfo {
                id: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    user_id,
                ),
                name: user_name.to_owned(),
                display_name: user_display_name.to_owned(),
            },
            // Algorithm preference, MOST-preferred first per the
            // WebAuthn spec. ES256 leads because every passkey-class
            // authenticator (Touch ID, Windows Hello, Android, Yubikey)
            // implements it; EdDSA is a fallback for the small set of
            // authenticators that prefer Ed25519 (some Yubikey 5+).
            // Sourced from `ALLOWED_REGISTRATION_ALGS` so the advertise-
            // and-enforce sides cannot drift.
            pub_key_cred_params: ALLOWED_REGISTRATION_ALGS
                .iter()
                .map(|&alg| PubKeyCredParam {
                    kind: "public-key",
                    alg,
                })
                .collect(),
            exclude_credentials: exclude,
            timeout: CEREMONY_TIMEOUT_MS,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: self.attachment.as_token(),
                resident_key: options.resident_key,
                user_verification: self.uv_token(),
            },
            attestation: options.attestation,
        };
        let state = RegistrationState {
            challenge,
            user_id: user_id.to_vec(),
            created_at: now_secs(),
            context_binding: Some(self.context_binding),
            exclude_credentials: existing.to_vec(),
        };
        Ok((chal, state))
    }

    /// Verify registration without requiring trusted authenticator provenance.
    ///
    /// Use [`Self::finish_registration_with_attestation`] to apply an attestation
    /// trust policy before receiving the credential to persist.
    /// The caller must consume the ceremony state once, authorize enrollment,
    /// and enforce RP-wide credential-ID uniqueness when inserting the record.
    pub fn finish_registration(
        &self,
        state: &RegistrationState,
        response: &RegistrationResponse,
    ) -> Result<PasskeyCredential> {
        self.finish_registration_with_attestation(state, response, |_| Ok(()))
    }

    /// Verify registration and apply the caller's attestation trust policy.
    ///
    /// The callback runs once after all protocol and statement checks, before
    /// constructing the credential. It borrows the original certificate DER
    /// without copying or reparsing the attestation object. Return an error,
    /// such as [`Error::AttestationRejected`], to reject enrollment.
    ///
    /// The callback receives the evidence actually returned by the browser,
    /// including `none` or self-attestation after a `direct` request. Certificate
    /// chain trust, validity, revocation and metadata policy belong to the caller.
    /// An accepted certificate remains recorded as `UntrustedCertificate`: the
    /// library's evidence summary records its checks, not the caller's decision.
    pub fn finish_registration_with_attestation(
        &self,
        state: &RegistrationState,
        response: &RegistrationResponse,
        check_attestation: impl FnOnce(VerifiedAttestation<'_>) -> Result<()>,
    ) -> Result<PasskeyCredential> {
        // 0. Reject ceremonies older than the hard ceiling. Defence
        // in depth. The caller must atomically consume state as well:
        // a TTL does not prevent reuse within that time window.
        self.check_state(state.created_at, state.context_binding, &state.challenge)?;
        let body = &response.response;

        // 1. Validate clientDataJSON.
        let cdj_raw = client_data::validate(
            &body.client_data_json,
            TYPE_REGISTER,
            &state.challenge,
            &self.origin,
        )?;
        let cdj_hash = sha256_32(&cdj_raw);

        // 2. Parse the attestation object.
        if !(1..=64).contains(&state.user_id.len()) {
            return Err(Error::InvalidState("user handle must contain 1..=64 bytes"));
        }
        if body.transports.len() > 16 || body.transports.iter().any(|s| s.len() > 32) {
            return Err(Error::InputTooLarge {
                field: "transports",
                limit: 512,
            });
        }
        let att_bytes = decode_b64_bounded(&body.attestation_object, 65536, "attestationObject")?;
        let att = ParsedAttestation::parse(&att_bytes)?;

        // 3. rpIdHash check. Note: non-constant-time `!=` is fine here
        // because both sides are public (SHA-256 of the RP ID) and an
        // attacker who could probe timing learns only the RP ID, which
        // they already know from the same TLS handshake.
        if att.auth_data.rp_id_hash != self.rp_id_hash {
            return Err(Error::RpIdHashMismatch);
        }

        // 4. User-present is mandatory for registration. UV is gated
        // by `require_uv` - opt-in strict mode for production passkey
        // deployments where presence-only must not count.
        if !att.auth_data.user_present() {
            return Err(Error::UserNotPresent);
        }
        if self.require_uv && !att.auth_data.user_verified() {
            return Err(Error::UserNotVerified);
        }

        // 5. AT flag MUST be set on registration; we need the attested
        // credential data to extract the public key.
        let attested = att
            .auth_data
            .attested
            .as_ref()
            .ok_or(Error::AuthData("registration authData missing AT flag"))?;

        // 6. Parse the COSE public key and verify any attestation
        // statement signed by it.
        let asserted_id = response.id.as_bytes();
        if asserted_id != attested.credential_id {
            return Err(Error::CredentialIdMismatch);
        }
        let cose = &attested.key;

        // 6a. WebAuthn §7.1 step 19: the credential's alg MUST be one of
        // the algorithms the RP advertised in pubKeyCredParams. Without
        // this check a hostile or buggy authenticator could register a
        // key for any algorithm our COSE parser supports, bypassing the
        // RP's algorithm policy. We source the allowed list from the
        // same const start_registration used to build the challenge, so
        // the advertise side and the enforce side cannot drift.
        if !ALLOWED_REGISTRATION_ALGS.contains(&cose.alg()) {
            return Err(Error::UnsupportedAlg(cose.alg()));
        }

        let attestation = att.verify_statement(attested, &cdj_hash)?;

        // A duplicate is a distinct application conflict only after the
        // statement is valid. Preserve invalid-attestation rejection/audit
        // behavior even when the asserted credential is already excluded.
        if state
            .exclude_credentials
            .iter()
            .any(|id| id.as_bytes() == asserted_id)
        {
            return Err(Error::CredentialExcluded);
        }

        let evidence = attestation.evidence;
        check_attestation(attestation)?;

        // 7. Build the persisted credential after the application's policy accepts it.
        Ok(PasskeyCredential {
            id: response.id.clone(),
            public_key_cose: CosePublicKey(attested.public_key_cose.to_vec()),
            counter: att.auth_data.sign_count,
            transports: body.transports.clone(),
            aaguid: attested.aaguid,
            user_handle: Some(state.user_id.clone()),
            uv_initialized: Some(att.auth_data.user_verified()),
            backup_eligible: Some(att.auth_data.backup_eligible()),
            backup_state: Some(att.auth_data.backup_state()),
            attestation: evidence,
        })
    }

    // ─── Authentication ───────────────────────────────────────────────

    /// Build the challenge to feed to `navigator.credentials.get()`.
    /// `allow_credentials` SHOULD be the user's registered credential
    /// IDs; can be empty for discoverable-credential ("usernameless")
    /// flows.
    ///
    /// Convenience form that omits the `transports` hint in the
    /// challenge JSON. Browsers will fall back to "try every transport"
    /// which usually works but adds a small UX delay (e.g. the browser
    /// may briefly poll for BLE devices that the credential cannot
    /// actually use). For best UX, prefer
    /// [`Self::start_authentication_with_creds`] which threads the
    /// per-credential transports captured at registration.
    pub fn start_authentication(
        &self,
        allow_credentials: &[CredentialId],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.to_b64url(),
                transports: Vec::new(),
            })
            .collect();
        self.build_auth_challenge(allow_credentials.to_vec(), descriptors)
    }

    /// Like [`Self::start_authentication`] but pulls the `transports`
    /// hint from each stored credential. This is the version a real
    /// deployment usually wants: the browser narrows authenticator
    /// discovery to the channels we know work for the credential
    /// (e.g. "internal" for Touch ID, "usb" + "nfc" for a Yubikey).
    pub fn start_authentication_with_creds(
        &self,
        allow_credentials: &[PasskeyCredential],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.id.to_b64url(),
                transports: c.transports.clone(),
            })
            .collect();
        let ids: Vec<CredentialId> = allow_credentials.iter().map(|c| c.id.clone()).collect();
        self.build_auth_challenge(ids, descriptors)
    }

    /// Internal: assemble the challenge JSON + state from already-built
    /// descriptors. Shared by both `start_authentication*` entry points.
    fn build_auth_challenge(
        &self,
        ids: Vec<CredentialId>,
        descriptors: Vec<CredentialDescriptor>,
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let challenge = Challenge::random();
        let chal = AuthenticationChallenge {
            challenge: challenge.to_b64url(),
            rp_id: self.rp_id.as_str().to_owned(),
            timeout: CEREMONY_TIMEOUT_MS,
            allow_credentials: descriptors,
            user_verification: self.uv_token(),
        };
        let state = AuthenticationState {
            challenge,
            allow_credentials: ids,
            created_at: now_secs(),
            // Account-aware start methods set this. Otherwise verification
            // requires the stored handle or an explicit discoverable binding
            // whenever the assertion supplies a handle.
            user_handle: None,
            context_binding: Some(self.context_binding),
        };
        (chal, state)
    }

    /// Like [`Self::start_authentication`] but records the user
    /// handle of the user being authenticated. When the assertion
    /// response comes back, `finish_authentication` will verify that
    /// `response.userHandle` equals this value (WebAuthn-3 §7.2
    /// step 6) — protection against credential-id-collision attacks
    /// in multi-user stores.
    ///
    /// Use this in username-first flows where the server already
    /// knows which user is trying to sign in. For discoverable /
    /// passwordless flows (the user is unknown until the response
    /// arrives), use [`Self::start_authentication`] and look the
    /// user up by the assertion's decoded user handle yourself.
    ///
    /// By default the check is skipped when the assertion's user handle
    /// is absent (per spec). Tighten that with
    /// [`Self::require_user_handle`] for platform-authenticator-only
    /// deployments where the user_handle is always emitted.
    pub fn start_authentication_for_user(
        &self,
        user_handle: &[u8],
        allow_credentials: &[CredentialId],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.to_b64url(),
                transports: Vec::new(),
            })
            .collect();
        let (chal, mut state) = self.build_auth_challenge(allow_credentials.to_vec(), descriptors);
        state.user_handle = Some(user_handle.to_vec());
        (chal, state)
    }

    /// Like [`Self::start_authentication_with_creds`] but ALSO records
    /// the user_handle for the §7.2 step 6 check. Use this in
    /// production username-first flows: you get both the transports
    /// hint (better UX) and the user_handle equality protection.
    pub fn start_authentication_with_creds_for_user(
        &self,
        user_handle: &[u8],
        allow_credentials: &[PasskeyCredential],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.id.to_b64url(),
                transports: c.transports.clone(),
            })
            .collect();
        let ids: Vec<CredentialId> = allow_credentials.iter().map(|c| c.id.clone()).collect();
        let (chal, mut state) = self.build_auth_challenge(ids, descriptors);
        state.user_handle = Some(user_handle.to_vec());
        (chal, state)
    }

    /// Verify an assertion against the credential selected by `response.id`.
    ///
    /// The caller must resolve the owning account within the current RP/tenant.
    /// Username-first flows bind its handle with an account-aware start method.
    /// Discoverable flows resolve the assertion's user handle to the owning account;
    /// [`Self::finish_discoverable_authentication`] supplies that binding for
    /// records whose stored user handle is absent.
    ///
    /// Consume the ceremony state once and atomically persist the returned
    /// counter and backup metadata before granting authentication success.
    pub fn finish_authentication(
        &self,
        state: &AuthenticationState,
        response: &AuthenticationResponse,
        stored: &PasskeyCredential,
    ) -> Result<AuthSuccess> {
        self.verify_authentication(state, response, stored, None)
    }

    /// Bind a discoverable assertion to the account selected by the caller's
    /// tenant-scoped credential lookup. Also supports legacy credentials whose
    /// JSONB predates the stored user handle; no credential re-enrollment is needed.
    pub fn finish_discoverable_authentication(
        &self,
        state: &AuthenticationState,
        response: &AuthenticationResponse,
        stored: &PasskeyCredential,
        expected_user_handle: &[u8],
    ) -> Result<AuthSuccess> {
        self.verify_authentication(state, response, stored, Some(expected_user_handle))
    }

    fn verify_authentication(
        &self,
        state: &AuthenticationState,
        response: &AuthenticationResponse,
        stored: &PasskeyCredential,
        account_handle: Option<&[u8]>,
    ) -> Result<AuthSuccess> {
        self.check_state(state.created_at, state.context_binding, &state.challenge)?;
        let asserted_id = &response.id;
        let body = &response.response;
        if !(1..=1023).contains(&asserted_id.as_bytes().len())
            || asserted_id != &stored.id
            || (!state.allow_credentials.is_empty()
                && !state.allow_credentials.contains(asserted_id))
        {
            return Err(Error::BadSignature);
        }
        let expected = account_handle
            .or(state.user_handle.as_deref())
            .or(stored.user_handle.as_deref());
        if let Some(expected) = expected
            && (!(1..=64).contains(&expected.len())
                || state.user_handle.as_deref().is_some_and(|h| h != expected)
                || stored.user_handle.as_deref().is_some_and(|h| h != expected))
        {
            return Err(Error::UserHandleMismatch);
        }
        let discoverable = state.user_handle.is_none() && state.allow_credentials.is_empty();
        match body.user_handle.as_deref() {
            Some(handle) if handle.is_empty() || expected != Some(handle) => {
                return Err(Error::UserHandleMismatch);
            }
            None if discoverable || self.require_user_handle => {
                return Err(Error::UserHandleMismatch);
            }
            _ => {}
        }
        let cdj_raw = client_data::validate(
            &body.client_data_json,
            TYPE_AUTHENTICATE,
            &state.challenge,
            &self.origin,
        )?;
        let cdj_hash = sha256_32(&cdj_raw);
        let ad_bytes = decode_b64_bounded(&body.authenticator_data, 16384, "authenticatorData")?;
        let ad = AuthenticatorData::parse(&ad_bytes)?;
        if ad.rp_id_hash != self.rp_id_hash {
            return Err(Error::RpIdHashMismatch);
        }
        if ad.attested.is_some() {
            return Err(Error::AuthData(
                "assertion must not contain attested credential data",
            ));
        }
        if !ad.user_present() {
            return Err(Error::UserNotPresent);
        }
        if self.require_uv && !ad.user_verified() {
            return Err(Error::UserNotVerified);
        }
        let backup_eligible = ad.backup_eligible();
        let backup_state = ad.backup_state();
        if stored
            .backup_eligible
            .is_some_and(|known| known != backup_eligible)
        {
            return Err(Error::BackupEligibilityChanged);
        }
        let user_verified = ad.user_verified();
        let new_counter = ad.sign_count;
        let key = CoseKey::parse(stored.public_key_cose.as_bytes())?;
        let mut sig = [0; 80];
        let sig_len = decode_b64_into(&body.signature, &mut sig, "signature")?;
        crypto::verify_auth_data(&key, &ad_bytes, &cdj_hash, &sig[..sig_len])?;
        // Reject non-increasing counters, including backups; 0/0 is supported.
        if (new_counter != 0 || stored.counter != 0) && new_counter <= stored.counter {
            return Err(Error::CounterReplay {
                stored: stored.counter,
                new: new_counter,
            });
        }
        Ok(AuthSuccess {
            credential_id: asserted_id.clone(),
            new_counter,
            user_verified,
            user_verification_eligible: user_verified && stored.uv_initialized == Some(true),
            backup_eligible,
            backup_state,
        })
    }
}

/// SHA-256 helper that returns the 32-byte array (not a `Vec`) so
/// rpIdHash comparison is a stack-allocated `==`.
fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Old in-flight states restart, while persisted credentials remain compatible.
fn check_not_expired(created_at: u64) -> Result<()> {
    let now = now_secs();
    if created_at == 0 || created_at > now {
        return Err(Error::InvalidState("missing or future creation timestamp"));
    }
    let age = now - created_at;
    if age > CEREMONY_MAX_AGE_SECS {
        return Err(Error::CeremonyExpired {
            age_secs: age,
            max_secs: CEREMONY_MAX_AGE_SECS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttestationConveyancePreference, ResidentKeyRequirement};

    #[test]
    fn registration_defaults_request_discoverability_without_attestation() {
        let wa = Webauthn::new("example.com", "Example", "https://example.com");
        let (challenge, _) = wa.start_registration(b"u", "u", "U", &[], Default::default());
        let wire = serde_json::to_value(challenge).unwrap();
        assert_eq!(wire["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(wire["authenticatorSelection"]["requireResidentKey"], true);
        assert_eq!(
            wire["authenticatorSelection"]["userVerification"],
            "preferred"
        );
        assert_eq!(wire["attestation"], "none");
    }

    #[test]
    fn registration_choices_serialize_independently() {
        for (resident_key, token, require_resident_key) in [
            (ResidentKeyRequirement::Required, "required", true),
            (ResidentKeyRequirement::Preferred, "preferred", false),
            (ResidentKeyRequirement::Discouraged, "discouraged", false),
        ] {
            for (attestation, attestation_token) in [
                (AttestationConveyancePreference::None, "none"),
                (AttestationConveyancePreference::Direct, "direct"),
            ] {
                for require_uv in [false, true] {
                    for (attachment, attachment_token) in [
                        (Attachment::Platform, Some("platform")),
                        (Attachment::CrossPlatform, Some("cross-platform")),
                        (Attachment::Any, None),
                    ] {
                        let wa = Webauthn::new("example.com", "Example", "https://example.com")
                            .require_user_verification(require_uv)
                            .authenticator_attachment(attachment);
                        let (challenge, _) = wa.start_registration(
                            b"u",
                            "u",
                            "U",
                            &[],
                            RegistrationOptions {
                                resident_key,
                                attestation,
                            },
                        );
                        let wire = serde_json::to_value(challenge).unwrap();
                        let selection = &wire["authenticatorSelection"];
                        assert_eq!(selection["residentKey"], token);
                        assert_eq!(selection["requireResidentKey"], require_resident_key);
                        assert_eq!(
                            selection["userVerification"],
                            if require_uv { "required" } else { "preferred" }
                        );
                        assert_eq!(
                            selection
                                .get("authenticatorAttachment")
                                .and_then(serde_json::Value::as_str),
                            attachment_token
                        );
                        assert_eq!(wire["attestation"], attestation_token);
                    }
                }
            }
        }
    }

    #[test]
    fn require_resident_key_is_derived_when_options_are_serialized() {
        let wa = Webauthn::new("example.com", "Example", "https://example.com");
        let (mut challenge, _) = wa.start_registration(b"u", "u", "U", &[], Default::default());
        challenge.authenticator_selection.resident_key = ResidentKeyRequirement::Discouraged;
        let wire = serde_json::to_value(challenge).unwrap();
        assert_eq!(wire["authenticatorSelection"]["residentKey"], "discouraged");
        assert_eq!(wire["authenticatorSelection"]["requireResidentKey"], false);
    }

    #[test]
    fn configuration_requires_an_exact_secure_related_origin() {
        for (rp_id, origin) in [
            ("example.com", "https://example.com"),
            ("example.com", "https://login.example.com"),
            ("localhost", "http://localhost:8080"),
            ("127.0.0.1", "http://127.0.0.1"),
        ] {
            assert!(Webauthn::try_new(rp_id, "Example", origin).is_ok());
        }
        for (rp_id, origin) in [
            ("example.com", "http://example.com"),
            ("example.com", "https://example.com/"),
            ("example.com", "https://example.com/path"),
            ("example.com", "https://user@example.com"),
            ("example.com", "https://evil-example.com"),
            ("0.0.1", "http://127.0.0.1"),
            ("", "https://example.com"),
        ] {
            assert!(matches!(
                Webauthn::try_new(rp_id, "Example", origin),
                Err(Error::Configuration(_))
            ));
        }
    }

    #[test]
    fn registration_handle_length_boundaries_are_fallible() {
        let wa = Webauthn::new("example.com", "Example", "https://example.com");
        for length in [0, 65] {
            assert!(
                wa.try_start_registration(
                    &vec![7; length],
                    "user",
                    "User",
                    &[],
                    Default::default()
                )
                .is_err()
            );
        }
        for length in [1, 64] {
            assert!(
                wa.try_start_registration(
                    &vec![7; length],
                    "user",
                    "User",
                    &[],
                    Default::default()
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn attachment_tokens() {
        assert_eq!(Attachment::Platform.as_token(), Some("platform"));
        assert_eq!(Attachment::CrossPlatform.as_token(), Some("cross-platform"),);
        assert_eq!(Attachment::Any.as_token(), None);
    }

    #[test]
    fn advertised_algs_match_enforced_algs() {
        // I1: the algorithm list the browser is offered (in
        // pubKeyCredParams) MUST be the same one finish_registration
        // checks. If they drift, an authenticator could legitimately
        // pick an alg the RP advertised but finish_registration
        // would reject — or worse, register an alg the RP did not
        // advertise. This test pins them together.
        let wa = Webauthn::new("example.com", "Example", "https://example.com");
        let (chal, _) = wa.start_registration(b"u", "u", "U", &[], Default::default());
        let advertised: Vec<i64> = chal.pub_key_cred_params.iter().map(|p| p.alg).collect();
        assert_eq!(advertised, ALLOWED_REGISTRATION_ALGS);
    }

    #[test]
    fn challenge_reflects_attachment_builder() {
        let wa_platform = Webauthn::new("example.com", "Example", "https://example.com");
        let (chal, _) = wa_platform.start_registration(b"u", "u", "U", &[], Default::default());
        assert_eq!(
            chal.authenticator_selection.authenticator_attachment,
            Some("platform"),
        );

        let wa_any = Webauthn::new("example.com", "Example", "https://example.com")
            .authenticator_attachment(Attachment::Any);
        let (chal, _) = wa_any.start_registration(b"u", "u", "U", &[], Default::default());
        assert_eq!(chal.authenticator_selection.authenticator_attachment, None,);

        let wa_cross = Webauthn::new("example.com", "Example", "https://example.com")
            .authenticator_attachment(Attachment::CrossPlatform);
        let (chal, _) = wa_cross.start_registration(b"u", "u", "U", &[], Default::default());
        assert_eq!(
            chal.authenticator_selection.authenticator_attachment,
            Some("cross-platform"),
        );
    }
}
