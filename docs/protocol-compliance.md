# Protocol scope and verification

Reviewed on **2026-11-19** for `nazo-passkey 0.3.0`. The primary reference is
[WebAuthn Level 3, W3C Recommendation 2026-08-25][W3]. The library implements
the relying-party verification operations listed below. Browser APIs,
authenticator operations, and CTAP transports belong to their respective peers.

## Implemented verification

| Requirement | Implementation and evidence |
| --- | --- |
| [W3] §5.4.3: stable account handle, 1–64 bytes | Registration checks the length. Applications choose opaque handles and own their account binding. `ceremony` unit and end-to-end tests cover boundaries. |
| [W3] §5.4.4 / §5.4.6: discoverable-credential selection | Per-registration `Required`, `Preferred`, or `Discouraged`; derive `requireResidentKey` from the selected value. The library defaults to `Required` for username-less passkey enrollment. |
| [W3] §5.4.7: attestation conveyance | Per-registration `None` (default) or `Direct`; verify the returned statement format and let application policy assess its evidence. |
| [W3] §13.1: unpredictable challenge | 32 bytes from `getrandom`; native OS, WASI, or browser Web Crypto backend. |
| [W3] §7.1 / §7.2: server challenge state | State binds the RP, origin, and verification policy; zero, future, expired, or mismatched state rejects. Applications consume it once. |
| [W3] §7.1 steps 5–6, §7.2 steps 8–9: UTF-8 and JSON | Strip one leading BOM for parsing; use UTF-8 replacement decoding; reject malformed JSON and duplicate typed fields. Preserve all original bytes for hashing. |
| [W3] §7.1 steps 7–8, §7.2 steps 10–11: type and challenge | Exact ceremony type and canonical unpadded base64url challenge. |
| [W3] §7.1 steps 9–11, §7.2 steps 12–14: origin | Exact configured origin; same-origin policy rejects `crossOrigin=true` and any `topOrigin`. |
| [W3] §7.1 step 12, §7.2 step 20: client-data hash | SHA-256 over the original decoded bytes. Signature tests distinguish original bytes from BOM-stripped or replacement-decoded text. |
| [W3] §7.1 step 14, §7.2 step 15: RP ID | Compare the signed `rpIdHash` with the configured RP hash. |
| [W3] §7.1 steps 15–16, §7.2 steps 16–17: UP / UV | Require UP for ordinary registration and all authentication; require UV when configured. |
| [W3] §6.1, §7.1 step 17, §7.2 steps 18–20: backup flags | Reject BS without BE. Preserve BE/BS; known credential BE remains immutable. |
| [W3] §7.1 step 20: offered algorithm | Advertise and accept only ES256 and Ed25519 through one shared algorithm list. |
| [W3] §6.5.1, §5.8.5: credential key | Require public-only COSE key parameters and matching type / algorithm / curve. Check coordinate lengths and point validity. |
| [W3] §2.4: wire CBOR | Enforce CTAP canonical encoding, complete framing, ordered unique keys, bounded nesting, and definite lengths. |
| [W3] §6.1: authenticator-data framing | Validate base fields, registration AT data, and exact ED extension tail. Authentication rejects AT. |
| [W3] §7.1: credential identity and exclusions | Match the response ID to attested credential data; verify attestation before reporting exclusion. The application enforces RP-wide credential uniqueness at insertion. |
| [W3] §7.2 step 5: allow list | A nonempty original allow list must contain the asserted credential. |
| [W3] §7.2 step 6: account binding | Match state, credential, explicit expected account, and supplied user handle. When the account was identified at start, an absent handle is permitted even with an empty allow list. |
| [W3] §7.2 step 6: discoverable login | Require the response handle when no account was identified; require a matching stored or explicit expected handle. |
| [W3] §7.2 step 21: assertion signature | Verify `authenticatorData || SHA256(clientDataJSON)` using the stored credential key. |
| [W3] §6.5.5: signature representation | ES256 uses ASN.1 DER with valid scalars; Ed25519 uses its 64-byte representation. |
| [W3] §7.2 step 22: signature counter | Return `Unsupported`, `Advanced`, or `NonIncreasing` after signature verification; the application applies its risk policy. |
| [W3] §4 credential record: UV initialization | Distinguish signed UV from established additional-factor eligibility. Unknown legacy history remains unknown. |
| [W3] §7.2 step 24: verified state updates | Return `CredentialUpdate` with expected and new counter / BE / BS; the application accepts policy and atomically persists the update before session success. |

The named source modules are in `src/`. Executable coverage comprises unit
tests, `ceremony_e2e`, `binary_regressions`, `attestation_e2e`, the official W3C
fixture corpus, and independent C2SP/CCTV Ed25519 vectors. Executed commands
and outcomes are recorded in [validation](validation.md).

## Attestation

| Format | Verified behavior |
| --- | --- |
| `none` | Present, empty attestation-statement map; returns `None` |
| `packed` self | Matching statement / credential algorithm and valid ES256 or Ed25519 signature; returns `SelfAttestation` |
| `packed` certificate | ES256 statement signature; P-256 leaf key; v3 certificate; required C/O/OU/CN fields and ASN.1 types; exact attestation OU; CA=false basic constraints; applicable AAGUID, firmware, and enterprise-extension rules |
| `fido-u2f` | Single P-256 certificate; ES256 credential; required U2F transcript and signature |

Certificate-backed formats return `UntrustedCertificate`. Certificate-chain
trust, issuer signatures, lifetime, revocation, metadata status, and vendor
legal identity are application trust decisions. The country field is checked
as two uppercase ASCII letters; the verifier does not establish the vendor's
incorporation jurisdiction. AAGUID and transport hints are descriptive data.

`finish_registration_with_attestation` implements the handoff between
[W3] §7.1 statement verification and RP trust assessment. Its callback receives
`VerifiedAttestation` after protocol verification and exclusions, before
credential construction. The view includes the evidence kind, format, AAGUID,
and original leaf-first DER slices; `None` and self-attestation have empty
chains. An application rejection prevents a credential from being returned.
An accepted certificate remains `UntrustedCertificate` in the stored library
summary; applications retain their own trust outcomes.

Requesting `Direct` permits the browser to return `none` or self-attestation;
the callback handles both according to application policy. Ordinary
`finish_registration` accepts protocol-valid evidence without a PKI trust
requirement, matching the default privacy-friendly `None` request.

Resident-key selection affects browser creation rather than server-side proof
of storage mode. The library's `Required` default supports discoverable login;
WebAuthn's omitted-field default is `Discouraged`. UP, UV, and account-binding
verification remain independent of the resident-key request.

## Compatibility and implementation policy

| Area | Policy |
| --- | --- |
| Level 1 / Level 2 | Supported credential algorithms and same-origin client behavior remain usable. Existing records can omit the newly added security metadata. `requireResidentKey` preserves Level 1 option handling; omitted `crossOrigin` is accepted. |
| Historical Token Binding | L3 §5.8.1 reserves `tokenBinding`. This verifier neither negotiates nor relies on it; applications needing the former L1/L2 Token Binding mode require a separate protocol choice. |
| Historical COSE keys | Accept historical map ordering and integer widths; enforce required fields, known metadata types, `key_ops` verification permission, and public-only material. |
| Outer response encoding | [W3] §5.1 `PublicKeyCredential.toJSON()` envelope. Check `type` and matching `id` / `rawId` and require canonical unpadded base64url for verifier inputs. Client extension hints do not participate in verification. |
| Reserved flags | Ignore unknown reserved bits while enforcing known AT/ED/UP/UV/BE/BS rules. |
| Extensions | Parse bounded signed output structures; ignore their values for authentication and factor policy. |
| Resource bounds | Client data 8 KiB, attestation 64 KiB, authenticator data 16 KiB, CBOR depth 12 / container 64 / total items 2,048; see README for all bounds. |
| RP configuration | Validate exact secure origin serialization and host relationship. The operator selects an appropriate registrable RP ID; public-suffix data is not embedded. |
| Ed25519 | Ordinary multipart verification with canonical / weak-point / scalar checks; differential tests preserve dalek strict acceptance. The dependency's `legacy_compatibility` feature is unsupported. |

## Features outside this release

RSA and other curves, Ed448, ECDAA, TPM, Android Key / SafetyNet, Apple,
enterprise attestation, cross-origin and related-origin policy, conditional
registration without UP, and extension-specific behavior such as AppID, PRF,
credProtect, and largeBlob are outside this release. The supported `fido-u2f`
attestation format is separate from AppID authentication.

The library is a protocol component. A complete relying party also implements
enrollment authorization, account and tenant isolation, single-use state,
atomic credential uniqueness and updates, session issuance, and any selected
attestation-trust policy. Physical authenticator and browser interoperability
and FIDO certification require separate evidence.

## FIDO2 server boundary

[FIDO2 Server Requirements v2.3][FIDO] is linked as active by the FIDO
certification site; the linked specification identifies itself as the
2025-10-23 Review Draft. Sections 2.1, 2.3 and 6 require broader attestation,
metadata and algorithm coverage than this library's selected WebAuthn scope.
TPM, SafetyNet and RSA support remain absent. Chain trust and Metadata Service
validation require the assembled server's application policy and integrations.
The [official conformance tool][FIDO-TEST] requires registered access; local
vectors, browser interoperability and fuzz tests are distinct evidence.

[FIDO]: https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20251023.html
[FIDO-TEST]: https://fidoalliance.org/certification/functional-certification/conformance/

## References

- [WebAuthn Level 1 Recommendation](https://www.w3.org/TR/2019/REC-webauthn-1-20190304/)
- [WebAuthn Level 2 Recommendation](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/)
- [WebAuthn Level 3 Recommendation][W3]
- [WHATWG UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 9052 — COSE structures](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 9053 — COSE algorithms](https://www.rfc-editor.org/rfc/rfc9053)
- [RFC 8032 — EdDSA](https://www.rfc-editor.org/rfc/rfc8032)

The earlier 111-row baseline comparison remains in
[the historical matrix](https://github.com/nazozero/nazo-passkey/blob/main/docs/protocol-compliance-checkpoint-8260480.md).

[W3]: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
