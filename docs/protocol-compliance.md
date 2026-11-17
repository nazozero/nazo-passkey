# WebAuthn protocol compliance and compatibility matrix

Review date: **2026-11-17**. Baseline: NazoAuth's actual
`nazoauth/patched-rustcrypto` revision
`d59b317998e56f4a16a69133d7a854c5c34f795b` (`passkey-auth 0.1.3`).
The revised column describes this working branch (crate **0.2.0**). It does not describe the
older upstream `main` or the crates.io package merely sharing that version.

## References and interpretation

| Reference | Version used | Role in this review |
|---|---|---|
| [W1] | W3C Recommendation, 2019-03-04 | Existing credential / client compatibility |
| [W2] | W3C Recommendation, 2021-04-08 | Existing credential / client compatibility |
| [W3] | W3C Recommendation, 2026-08-25 | Primary RP algorithm and new credential-record rules |
| [CTAP] | CTAP 2.3 Proposed Standard, 2026-02-26 | CBOR profile and authenticator extension semantics |
| [COSE-S] | RFC 9052, August 2022 | Key structure and processing |
| [COSE-A] | RFC 9053, August 2022 | Algorithm / key-parameter consistency |
| [CBOR] | RFC 8949, December 2020 | Encoding validity, ambiguity, and bounded processing |
| [EDDSA] | RFC 8032, January 2017 | Ed25519 point encoding, signature verification, independent vectors |

The stable, dated documents above were read directly. Level 3 is a
Recommendation at the review date, not an assumed draft. CTAP is not a protocol
this RP library speaks to an authenticator; only its referenced data-format
rules apply here. In particular, a CTAP transport message limit is not a
WebAuthn HTTP request limit.

Level 1 section/step numbers differ from Level 2/3; they are cited separately.
Where later levels intentionally change a rule (for example unsolicited
extensions), this implementation follows Level 3 while retaining usable Level
1/2 credentials; it does not claim to simulate every historical rule at once.

Rows identify the applicable rule by section and, where useful, algorithm step.
`MUST` includes an obligatory verification step under the RP conformance rule.
`POLICY` identifies an implementation choice or integration obligation and does
not promote a recommendation into a normative requirement.

- **PASS**: source review finds the stated rule implemented in the named scope.
- **FAIL**: the baseline or revision violates / omits the rule in that scope.
- **PARTIAL**: additional application behavior, unavailable historical state,
  a documented compatibility exception, or missing implementation remains.
- **NOT APPLICABLE**: the feature / conformance role is not implemented or claimed.

A PASS in this matrix is **not** an assertion that a command ran. The evidence
column names executable regression cases or an inspected integration location.
Actual command exit status, test counts, target support, and unrun work are
recorded separately in [validation.md](validation.md). Performance conclusions
belong in [performance.md](performance.md). No certification claim follows from
this matrix.

## Implementation and evidence keys

| Key | Source / evidence |
|---|---|
| `ceremony` | `src/ceremony.rs`: `try_new`, `check_state`, start / finish methods, `verify_authentication` |
| `client` | `src/client_data.rs`: `validate` and typed client data |
| `types` | `src/types.rs`: wire types, persisted credential, states, bounded Base64 |
| `binary` | `src/cbor.rs`, `src/auth_data.rs`, `src/cose.rs` |
| `attest` | `src/attestation.rs`, `src/x509.rs` |
| `crypto` | `src/crypto.rs`: RustCrypto default; optional native AWS-LC for credential ES256; Ed25519 always dalek strict; all WASM uses RustCrypto |
| `CE` | `tests/ceremony_e2e.rs` |
| `BR` | `tests/binary_regressions.rs` |
| `AE` | `tests/attestation_e2e.rs` |
| `UNIT` | Tests in the named source module |
| `W3 vectors` | Official [W3] §16 fixture cases in `tests/fixtures/w3c-level3.json`, exercised by `tests/official_vectors.rs`; see validation inventory |
| `Nazo identity` | NazoAuth `crates/identity/src/passkey.rs` and passkey ceremony repository |
| `Nazo DB` | NazoAuth PostgreSQL passkey repository and identity conversion code |
| `Nazo HTTP` | NazoAuth register / login / delete handlers, session, MFA and remembered-MFA policy |

## 1. Configuration, challenge issuance, and caller state

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| RP-01 | [W1] §2.3; [W2] §2.3; [W3] §2.3 · MUST · claimed RP operations | Required ceremony checks | PARTIAL | PASS within declared feature scope | See all ceremony rows below; unsupported optional features are explicit. |
| RP-02 | [W1] §5.4.3; [W3] §5.4.3 · MUST / POLICY · user entity | Handle length | FAIL | PASS | `try_start_registration` and finish enforce 1–64 bytes; fallible API avoids panicking on caller input. `UNIT::registration_handle_length_boundaries_are_fallible` covers 0/65 rejection and 1/64 acceptance. |
| RP-03 | [W1] §5.4.3 · MUST NOT / SHOULD NOT · user entity | PII / shared handle | PARTIAL | PARTIAL, caller-owned | Library accepts caller bytes; examples now generate independent random handles. NazoAuth retains opaque persisted user IDs. A library cannot detect whether arbitrary bytes encode PII. |
| RP-04 | [W1] §5.4.3 · MUST NOT · account identity | Names are display-only | PASS | PASS | Credential/account binding uses opaque handles and IDs, not `name` or `displayName`; `ceremony`. |
| RP-05 | [W2] §5.4.1, §5.4.3 · SHOULD · display strings | PRECIS display enforcement | PARTIAL | PARTIAL, application UI | No PRECIS dependency or normalization of supplied names is added. Display strings are never authentication identifiers in the verifier; embedding UI owns this recommendation. |
| RP-06 | [W1] §5.3; [W2] §7.1 s16; [W3] §7.1 s20 · MUST · offered algorithms | Offer / accept agreement | PASS | PASS | One `ALLOWED_REGISTRATION_ALGS` constant advertises and enforces -7/-8. `UNIT::advertised_algs_match_enforced_algs`; retain baseline fix. |
| RP-07 | [W1] §13.1 · MUST / SHOULD · every ceremony | Random challenge entropy | PASS | PASS | `Challenge::random` takes 32 bytes directly from the platform CSPRNG through `getrandom 0.4`: native OS, WASI or Web Crypto. No timestamp/user-ID derivation or weak fallback; entropy failure panics. Source inspection plus native/WASM build and WASI execution evidence. |
| RP-08 | [W1] §13.1; [W3] §7 · MUST / POLICY | Issued-state ownership | PARTIAL, caller | PARTIAL, caller | State must be server-controlled, tenant/account/session-bound, and atomically consumed. NazoAuth retains Valkey GETDEL; borrowed `&state` alone cannot provide single-use semantics. |
| RP-09 | [W1] §13.1 · SHOULD / POLICY | Freshness | PARTIAL | PASS in verifier; caller TTL retained | Baseline accepted zero timestamps and used saturating subtraction for future timestamps. Revised `check_not_expired` rejects both and checks 300-second ceiling. `CE::state_has_exact_rp_policy_binding_and_no_timestamp_bypass`, `expired_ceremony_rejected`. |
| RP-10 | [W3] §7 · POLICY · mutable deployment configuration | State policy binding | FAIL | PASS | Hash binds RP, exact origin, UV, Base64 and handle policies. Missing / changed binding rejects; old pending states restart. `CE::state_has_exact_rp_policy_binding_and_no_timestamp_bypass`. |
| RP-11 | [W2] §5.1.3, §5.4 · MUST / POLICY · web origin configuration | Origin / RP relationship | PARTIAL | PARTIAL | `try_new` validates serialization/scheme; parent suffixes apply only to domain hosts, while IP hosts require exact RP ID equality. `UNIT::configuration_requires_an_exact_secure_related_origin`. No Public Suffix List: registrable-domain suitability remains operator/browser enforced. |
| RP-12 | [W2] §5.4; [W3] §15.1 · SHOULD / POLICY · options | Timeout / exclusion hints | PASS | PASS | 60-second browser timeout; library 300-second hard ceiling is not the server TTL. Exclusion list now also retained in registration state. |
| RP-13 | [W2] §5.4.7 · MAY · attestation preference | Privacy-preserving preference | PASS | PASS | Options request `attestation="none"`; returned supported attestation is still checked and its evidence level recorded. |
| RP-14 | [W3] §5.4.4, §5.8.8 · POLICY · browser hints | Hints are not assurance | PARTIAL | PASS in documented contract | Attachment / transports are not vendor trust or MFA evidence. README removes hardware-policy implications. |

## 2. Client data and registration

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| CD-01 | [W1] §7.1 s1–2; [W3] §7.1 s5–6 · MUST · client data | UTF-8 JSON / BOM | PARTIAL | PASS | `client` strips one leading BOM for parsing only. Raw bytes remain unchanged for hashing. `UNIT::bom_is_ignored_for_json_but_preserved_for_signature_hash`. |
| CD-02 | [W1] §7.1 s3; §7.2 s7 · MUST | Ceremony type | PASS | PASS | Exact create/get tag. `UNIT::wrong_type_rejected`; no type inference from body shape. |
| CD-03 | [W1] §7.1 s4; §7.2 s8 · MUST | Challenge equality | PASS | PASS | Decoded challenge equals issued bytes; strict mode also enforces canonical wire encoding. `CE::wrong_challenge_rejected`. |
| CD-04 | [W1] §7.1 s5; §7.2 s9 · MUST | Origin equality | PASS | PASS | Exact configured origin; no wildcard or RP-suffix acceptance. `CE::wrong_origin_rejected`. |
| CD-05 | [W3] §7.1 s10; §7.2 s13 · MUST · embedded assertion | `crossOrigin` policy | FAIL | PASS | Baseline parsed but ignored the flag. Revised same-origin policy rejects true; missing remains compatible. `UNIT::same_origin_policy_rejects_cross_origin_and_top_origin`, W3 vectors. |
| CD-06 | [W3] §7.1 s11; §7.2 s14 · MUST · present member | `topOrigin` policy | FAIL | PASS | Any present top origin is outside enabled scope and rejects, even without crossOrigin=true. Null / wrong type rejects. Same tests as CD-05. |
| CD-07 | [W2] §5.8.1; [CBOR] §10 analogue · POLICY | Ambiguous JSON fields | PASS for existing known fields; PARTIAL overall | PASS | Serde rejects duplicate typed security fields; new topOrigin has presence-aware typing. Unknown members allowed. `UNIT::duplicate_security_fields_null_top_origin_and_oversize_are_rejected`. |
| CD-08 | [W1] §7.1 s7; §7.2 s15 · MUST | Hash original bytes | PASS | PASS | SHA-256 input is decoded original client bytes, not reserialized JSON. BOM included. Real-signature tests and W3 vectors exercise hash binding. |
| CD-09 | [W2] §5.8.1; [W3] §5.8.1 · conditional | Token Binding | NOT APPLICABLE | NOT APPLICABLE | No Token Binding transport is used / claimed. Reserved legacy member may be ignored; this does not claim a validated binding. |
| REG-01 | [W1] §7.1 s8 · MUST | Attestation decoding | PARTIAL | PASS | Borrowed, bounded, fully consumed map parser; required members cannot be omitted. `BR::none_requires_present_empty_map`, `duplicate_envelope_keys_and_trailing_items_are_rejected`. |
| REG-02 | [W1] §7.1 s9 · MUST | RP ID hash | PASS | PASS | Constant expected RP hash computed at configuration; compared before attestation success. `ceremony`; wrong-RP cases / official vectors. |
| REG-03 | [W1] §7.1 s10; [W3] §7.1 s15 · MUST · ordinary registration | UP | PASS | PASS | UP required; conditional registration exception is not offered. `ceremony`; UV/flag regression tests. |
| REG-04 | [W1] §7.1 s11; [W3] §7.1 s16 · MUST · UV requested required | UV requirement | PASS | PASS | Required rejects UV=false; preferred permits it but stores false history. `CE::uv_preferred_false_and_required_registration_behavior`. |
| REG-05 | [W2] §6.1, §6.5.1 · MUST | AT / credential data | PARTIAL | PASS | Registration requires AT; bounded credential ID and key framing; curve point checked even for none. `BR::invalid_points_and_private_or_optional_parameters_do_not_register`. |
| REG-06 | [W3] §7.1 s17 · MUST | BS ⇒ BE | FAIL | PASS | Invalid flag combination rejected by `auth_data`; all four combinations tested. `UNIT::all_backup_flag_combinations_are_checked`. |
| REG-07 | [W3] §7.1 s18–19 · MAY · policy uses backup | Backup admission policy | NOT APPLICABLE | NOT APPLICABLE | No “synced only” or “hardware only” policy is advertised. BE/BS are retained and exposed, not converted into manufacturer assurance. |
| REG-08 | [W3] §7.1 s20 · MUST | Credential algorithm | PASS | PASS | Enforced against advertised algorithms; binary parser additionally proves kty/alg/crv consistency. `BR::algorithm_and_label_integer_overflow_cannot_alias_negative_values`. |
| REG-09 | [W1] §7.1 s13–14; [W3] §7.1 s21–22 · MUST | Exact format / statement | PARTIAL | PASS within scope | Case-sensitive dispatch; unknown format / ECDAA is an explicit error. See attestation rows. |
| REG-10 | [W3] §7.1 s25 · SHOULD; type consistency · POLICY | Credential ID bound | FAIL | PASS | Response `id` must equal attested ID; new ID limited to 1–1,023 bytes. `CE::registration_outer_id_and_exclusion_are_enforced`; long-ID W3 vector. |
| REG-11 | [W3] §7.1 s26 · SHOULD · RP account store | Duplicate ID rejection | PARTIAL, caller | PARTIAL, caller | Library enforces state exclusion list; global / RP account uniqueness remains a transactional store operation. Examples enforce insertion under lock / SQL unique key; Nazo DB has uniqueness. |
| REG-12 | [W3] §7.1 s27 · MUST | Record metadata | FAIL for new L3 fields | PASS | Whole record includes user handle, uv_initialized, BE/BS and explicit attestation evidence. `CE::registration_attestation_evidence_is_explicit`, `uv_fact_and_factor_eligibility_are_distinct_and_legacy_json_is_readable`. |
| REG-13 | [W3] §7.1 s28–29 · MUST / POLICY | Store only on success | PARTIAL, caller | PARTIAL, caller | Verifier has no side effects and returns only after checks. Authorization, transaction and session state remain caller-owned. Example double-pending signup regression proves insertion-time check. |

## 3. Authentication and security-state transitions

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| AUTH-01 | [W1] §7.2 s1; [W3] §7.2 s5 · MUST · nonempty allow list | Allowed ID membership | PASS | PASS | Asserted ID equals stored ID and belongs to original list; strict decode and 1–1,023-byte bound precede signature. `ceremony` and CE. |
| AUTH-02 | [W1] §7.2 s2; [W3] §7.2 s6 · MUST · identified user | Account / credential binding | PARTIAL | PASS in bound API; caller lookup required | State handle, record handle, optional explicit account handle, and response handle must agree. Tenant cannot be inferred by the library. `CE::user_handle_match_succeeds`, `user_handle_mismatch_rejected`. |
| AUTH-03 | [W1] §7.2 s2; [W3] §7.2 s6 · MUST · supplied handle | Optional handle equality | PASS in for_user flow | PASS | Absent handle allowed for username-first by default; supplied handle always validated. `CE::user_handle_absent_in_response_is_accepted_by_default`, `stored_user_handle_is_checked_without_username_first_state`. |
| AUTH-04 | [W3] §7.2 s6 · MUST · discoverable | Required account handle | PARTIAL, caller | PASS in verifier; caller resolves tenant | Empty allow list requires returned handle and expected binding. Explicit discoverable finish supports old stored records. `CE::discoverable_assertions_bind_an_account_even_for_legacy_credentials`. |
| AUTH-05 | Local tightening of AUTH-03 · POLICY | Require returned handle | PASS | PASS | `require_user_handle` retained; may exclude older nonresident credentials when enabled. `CE::require_user_handle_rejects_absent_response_handle`. |
| AUTH-06 | [W1] §7.2 s5–10; [W3] §7.2 s8–14 · MUST | Client-data checks | PARTIAL | PASS | Same client validator as registration; includes newly enforced embedding policy. See CD rows. |
| AUTH-07 | [W1] §7.2 s11; [W3] §7.2 s15 · MUST | RP ID hash | PASS | PASS | Expected RP hash only. No AppID fallback or suffix-based substitute. `ceremony`, real-signature vectors. |
| AUTH-08 | [W1] §7.2 s12; [W3] §7.2 s16 · MUST | UP | PASS | PASS | UP always required on assertions. Attachment hints cannot bypass it. `ceremony`, negative flag tests. |
| AUTH-09 | [W1] §7.2 s13; [W3] §7.2 s17 · MUST (W1) / SHOULD (W3) · requested required | UV policy | PASS | PASS | Required fails UV=false; preferred accepts properly signed UV=false. `CE::require_uv_rejects_uv_less_assertion`, `uv_preferred_false_and_required_registration_behavior`. |
| AUTH-10 | [W3] §6.1 / §7.2 s18 · MUST | AT / BS framing | FAIL | PASS | Assertions with AT reject; BS without BE rejects; ED tail framing is complete. `CE::backup_flags_and_immutable_eligibility_are_enforced`, BR extension tests. |
| AUTH-11 | [W3] §7.2 s19–20 · conditional / POLICY | Stable backup eligibility | FAIL | PASS for known metadata | Known stored BE must agree; unknown legacy BE is initialized from a verified assertion. BS may change. Same CE test; database update tests in NazoAuth. |
| AUTH-12 | [W1] §7.2 s15–16; [W3] §7.2 s21 · MUST | Credential signature | PASS | PASS in reviewed source; feature runs tracked separately | ES256 DER / Ed25519 over authData plus SHA-256 of raw client data. Optional native AWS-LC imports only the internally computed SHA-256 transcript digest; no caller-supplied digest. Invalid signatures never produce AuthSuccess. Real signatures, W3 vectors, backend transcript / malformed-DER tests. |
| AUTH-13 | [W1] §7.2 s17; [W3] §7.2 s22 · POLICY | Counter anomaly handling | PASS, docs overstated | PASS, policy explicit | 0→0 remains accepted; otherwise non-increasing count rejects. A race / fault can cause this; not proof of cloning. `CE::counter_replay_rejected`; SQLite/Nazo CAS tests. |
| AUTH-14 | [W3] §7.2 s24 · MUST / POLICY | Atomic persistence | PARTIAL, caller | PARTIAL, caller | Counter / BS changes commit with CAS before session success. SQLite example now does account-scoped counter/metadata CAS; NazoAuth preserves its transactional conflict semantics. |
| AUTH-15 | [W3] §4 credential record · MUST NOT | UV-factor eligibility | FAIL | PASS with integration | `user_verified` and `user_verification_eligible` separate signed fact from established UV history. Legacy None is not eligible. `CE::uv_fact_and_factor_eligibility_are_distinct_and_legacy_json_is_readable`; Nazo MFA tests. |
| AUTH-16 | [W3] §7.2 s24.3 · SHOULD · false/unknown UV history | Authorized UV initialization | NOT IMPLEMENTED | PARTIAL in library; Nazo flow implemented | Library never promotes automatically. NazoAuth permits explicit initialization under a recent independent factor and CSRF-protected session; current assertion stays ineligible. See integration evidence inventory. |
| AUTH-17 | [W3] §7.2 s23 · MUST / POLICY · extension output | Extension policy | PARTIAL | PASS within ignore policy | Signed extension maps must be well formed; ignored outputs cannot create AMR/MFA or substitute for UV. Client extension results are not consumed by the flat response API. |

## 4. Binary, COSE, signature, and resource rules

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| BIN-01 | [W1], [W2], [W3] §2.4; [CTAP] §8 · MUST encode / SHOULD reject | Canonical new CBOR | FAIL | PASS | New input enforces definite lengths, minimal integer/length widths, canonical key order and no tags. Stored-key compatibility is separate. `UNIT::stored_ordering_is_compatible_but_new_encoding_is_canonical`, BR malformed tests. |
| BIN-02 | [W2] §2.4; [COSE-S] §7; [CBOR] §5.6 · SHOULD / MUST | Duplicate labels | FAIL | PASS | Duplicate top-level, statement, nested map and COSE labels reject, including alternate integer encodings. No last-key-wins semantics. `BR::duplicate_envelope_keys_and_trailing_items_are_rejected`, CBOR unit tests. |
| BIN-03 | [CBOR] §3, §5.3 · MUST | Well-formed / consumed input | PARTIAL | PASS | Checked offsets and lengths; correct UTF-8; no incomplete items or trailing CBOR after a complete value. `BR::every_truncated_envelope_is_rejected_without_panic`. |
| BIN-04 | [CBOR] §3.1, §10 · MUST / POLICY | No integer narrowing | FAIL | PASS | u64/i128 conversion checked before i64 use; huge values cannot alias -7/-8 or negative labels. `BR::algorithm_and_label_integer_overflow_cannot_alias_negative_values`. |
| BIN-05 | [CBOR] §10 · POLICY | Resource bounds | FAIL | PASS at binary boundary | Byte/item/depth/container caps with borrowed strings/bytes; no allocation from attacker-declared lengths. `BR::excessive_nesting_and_noncanonical_encodings_are_rejected`; fuzz/property corpus. HTTP caps and credential-count quotas remain external; NazoAuth has no per-account quota and begin work remains linear in that count. |
| BIN-06 | [CTAP] §8; [CBOR] §4.2 · profile-specific | CTAP canonical variant | PARTIAL | PASS for supported key types | CTAP order is used, not RFC 8949 length-first ordering. Float values retain their encoded width; tags and indefinite forms reject. Complex / floating map keys are unsupported by this parser's bounded subset. |
| BIN-07 | [W2] §6.1 · MUST | Authenticator-data frame | PARTIAL | PASS | 37-byte base, big-endian count, checked AT and exact ED tail; no unexplained remaining bytes. `UNIT::extension_presence_type_and_consumption_are_checked`. |
| BIN-08 | [W2] §6.1 · MUST · ED | Extension map / text IDs | FAIL | PASS | ED requires a fully consumed map of text extension identifiers. ED=false forbids a tail. Unrecognized values are structurally bounded and ignored. BR extension tests. |
| BIN-09 | [W2] §6.5.1; [COSE-S] §7.1 · MUST / MUST NOT | Required public key fields | PARTIAL | PASS for new keys | Required kty, alg, crv, coordinates only at registration. Unknown optional metadata only tolerated in historical stored keys. `UNIT::legacy_optional_metadata_does_not_change_key_but_new_keys_reject_it`. |
| BIN-10 | [COSE-A] §2.1 / §7.1; [W3] §5.8.5 · MUST | ES256 consistency | PARTIAL | PASS | EC2=2, alg=-7, crv=1; x/y exactly32 bytes, uncompressed valid P-256 point. `BR::invalid_points_and_private_or_optional_parameters_do_not_register`. |
| BIN-11 | [COSE-A] §2.2 / §7.2; [EDDSA] §5.1.3; [W3] §5.8.5 · MUST | Ed25519 consistency | PARTIAL | PASS | OKP=1, alg=-8, crv=6; x32; no y/private field; canonical y and valid nonweak point. Ed448 cannot be reinterpreted as Ed25519. Exact 19-value boundary/sign cases and `ed25519_byte_bound_is_equivalent_to_recompression` property compare the optimized check with the previous acceptance set. |
| BIN-12 | [COSE-S] §7; [COSE-A] §7 · MUST / POLICY | Public / private separation | FAIL | PASS | Private parameter -4 always rejected; conflicting / inappropriate alg, curve and coordinate fields reject. BR and COSE malformed-key tests. |
| BIN-13 | [W2] §6.5.5 · MUST | ES256 signature encoding | PASS | PASS in reviewed source; feature runs tracked separately | RustCrypto DER/scalar parsing precedes either backend; COSE R\|\|S is not substituted for WebAuthn DER. `es256_backends_preserve_transcript_high_s_and_der_contract` covers high/low S, malformed DER, wrong digest and invalid keys. No additional low-S condition is imposed. |
| BIN-14 | [COSE-A] §2.2; [W2] §6.5.5 · MUST | Ed25519 signature validation | PASS | PASS | dalek `verify_strict` under every feature/target combination; AWS-LC never substitutes its Ed25519 acceptance policy. Wrong key/message/signature rejects. Real-signature property, CE tests, RFC 8032 and W3 vectors. |
| BIN-15 | [W2] §5.8.1; [W3] §5.1 · MUST in canonical JSON / POLICY in adapter | Base64 policy | PARTIAL | PASS when strict configured | Bounded strict decoding covers every wire field including registration id. Lenient mode retained explicitly for legacy adapters. `CE::strict_base64_rejects_standard_alphabet`, lenient compatibility test. |
| BIN-16 | [W2] §6.1 · authenticator MUST emit; RP policy | Reserved flag bits | NOT APPLICABLE to emitter | PASS in compatibility scope | RP does not infer security meaning from RFU bits. Required known bits / AT / ED / BE / BS are independently checked; no blanket rejection of future reserved flags. |

## 5. Attestation: validity versus trust

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| ATT-01 | [W2] §8.7 · MUST · none | Empty statement | FAIL | PASS | Present empty map required; missing / scalar / nonempty statement rejects. `BR::none_requires_present_empty_map`, W3 none vector. |
| ATT-02 | [W2] §8.2 · MUST · packed self | Algorithm / signature | PASS | PASS | Statement alg equals credential alg; signed input exact; ES256 and Ed25519 supported. Real self-signature tests / W3 self vector. |
| ATT-03 | [W2] §8.2 · MUST · packed x5c | Leaf signature | PASS within ES256 scope | PASS within ES256 scope | Nonempty bounded chain; leaf key used for attestation signature. Unsupported certificate algorithms reject explicitly. `AE::packed_x5c_happy_path`, `packed_x5c_bad_signature_rejected`. |
| ATT-04 | [W2] §8.2.1 · MUST · packed leaf | Version / constraints | FAIL | PASS | v3 and present basicConstraints CA=false; no pathLen constraint for a non-CA leaf. `AE::packed_certificate_subject_version_and_constraints_are_checked`. |
| ATT-05 | [W2] §8.2.1 · MUST · packed leaf | Required subject fields | FAIL | PASS for structural profile | C/O/OU/CN presence, required ASN.1 tags and exact OU checked. Country syntax is checked, not vendor nationality or trust. `AE::packed_certificate_subject_version_and_constraints_are_checked`; see security review. |
| ATT-06 | [W2] §8.2.1 · MUST / MUST NOT · AAGUID present | AAGUID DER / criticality | PARTIAL | PASS | Double OCTET structure, 16-byte content, noncritical, equal authData AAGUID; duplicate extensions reject. `AE::packed_x5c_aaguid_mismatch_rejected`, `packed_x5c_malformed_aaguid_rejected`, `packed_aaguid_extension_cannot_be_critical_or_duplicated`. |
| ATT-07 | [W2] §8.2 / §8.6; [COSE-A] §2.1 · MUST · ES256 leaf | Certificate key / curve | PARTIAL | PASS | EC algorithm OID, named P-256 OID, uncompressed key and real point verification. No guessing curve from byte length. `AE::certificate_named_curve_is_checked_independently_of_point_length`. |
| ATT-08 | [W2] §8.6 · MUST · U2F | Exactly one certificate | FAIL | PASS | x5c cardinality must be exactly one. `AE::chain_length_and_intermediate_der_are_checked`. |
| ATT-09 | [W2] §8.6 · MUST · U2F | P-256 / verification bytes | PASS | PASS | Legacy 0x00 prefix and uncompressed credential point included in prescribed signed input. `AE::fido_u2f_happy_path`, `fido_u2f_wrong_credential_pubkey_rejected`, W3 U2F vector. |
| ATT-10 | [W3] §8.6, §16.16 · scope clarification | U2F AAGUID assumption | PASS | PASS | No invented zero-AAGUID verification rule; official U2F vector has a nonzero AAGUID. AAGUID is not vendor authentication. |
| ATT-11 | [W1] §7.1 s15–16, s19; [W3] §7.1 s23–24 · policy-dependent | Trust assessment | PARTIAL (docs only) | PASS for explicit untrusted policy | Successful certificate signature returns `UntrustedCertificate`; no chain-root, lifetime, revocation or device-model claim. `AE::checked_attestation_signature_does_not_claim_certificate_trust`; `CE::registration_attestation_evidence_is_explicit`. |
| ATT-12 | [W3] §13.4.5 · SHOULD · trusted attestation policy | Root / status validation | NOT APPLICABLE to declared untrusted acceptance | NOT APPLICABLE | No trust store / MDS / pinned-root validation configured. Enterprise trusted-manufacturer use case remains unsupported, not silently passed. |
| ATT-13 | [W2] §8.2; [W3] §8 · unsupported option | ECDAA / other formats | NOT APPLICABLE | NOT APPLICABLE | Unsupported statement members / formats fail explicitly. Never downgrade an unrecognized packed scheme to self-attestation. |

## 6. Optional features, integration, and compatibility

| ID | Normative source / applicability | Check | Baseline | Revised | Location, security impact, and evidence |
|---|---|---|---|---|---|
| EXT-01 | [W3] §9, §10.1.4 · extension conditional | PRF | NOT APPLICABLE | NOT APPLICABLE | Not requested or evaluated by RP library. Client PRF results are not an MFA factor; no decryption / PRF protection claim is made. |
| EXT-02 | [CTAP] §12.1 · extension conditional | credProtect | NOT APPLICABLE | NOT APPLICABLE | No requested policy or enforcement claim. An ignored authenticator output does not substitute for actual signed UV or initialized history. |
| EXT-03 | [W3] §10.1.3 · extension conditional | credProps | NOT APPLICABLE | NOT APPLICABLE | Client discoverability hint is not accepted as signed security evidence. Discoverable login still verifies returned handle and credential ownership. |
| EXT-04 | [W2] §10.1–2 · extension conditional | AppID / AppIDExclude | NOT APPLICABLE | NOT APPLICABLE | No legacy appId hash fallback; support for the fido-u2f attestation format does not imply AppID extension support. |
| EXT-05 | [W3] §5.10–11 · optional browser flows | Embedded / related origins | NOT APPLICABLE | NOT APPLICABLE | Embedded cross-origin operations reject. No `.well-known/webauthn` fetcher or implicit suffix allow list. |
| EXT-06 | [W3] §5.1, §11; [CTAP] §6–7 / transport chapters | Browser / authenticator role | NOT APPLICABLE | NOT APPLICABLE | Browser JSON helpers, WebDriver, PIN protocol, transports, biometrics, largeBlob and credential management are outside RP implementation scope. |
| COMP-01 | Existing NazoAuth persistence contract · POLICY | Old credential JSONB | PASS | PASS with integration | Existing byte arrays/key material remain readable; missing metadata defaults to unknown. CE legacy serde test and Nazo legacy ES256/Ed25519 real-signature tests. No re-enrollment required. |
| COMP-02 | [W1]; [W2] optional client fields · POLICY | Older browser behavior | PASS | PASS | Missing crossOrigin remains same-origin; unknown JSON members allowed; username-first missing userHandle accepted by default; zero counters remain allowed. |
| COMP-03 | [W1], [W2], [W3] §2.4 · SHOULD / storage policy | Stored noncanonical key | PASS leniently | PASS with bounded compatibility | Original COSE bytes retained; stored parser tolerates ordering/width/optional metadata only. Duplicate/private/malformed key ambiguity is deliberately not grandfathered. COSE unit tests. |
| COMP-04 | Deployment upgrade · POLICY | Old pending state | PASS without binding | PASS by safe restart | Old states reject; stored credentials unaffected. All callers must restart the short ceremony rather than bypass context binding. CE state test. |
| COMP-05 | NazoAuth security contract · POLICY | Tenant / user / credential | PARTIAL application-specific | PASS in revised integration source | GETDEL envelope tenant rechecked; repository lookup scoped; credential ID and account handle checks retained. Nazo identity / HTTP tests. |
| COMP-06 | NazoAuth security contract · POLICY | MFA / remembered MFA | PARTIAL for uvInitialized | PASS for new decisions; PARTIAL historical evidence | UV=false and unknown-history UV=true do not automatically gain new MFA. Authorized later initialization is explicit. Existing session / remembered lifetimes remain; historical AMR is not retrospectively re-proven or globally revoked. Nazo policy and HTTP tests. |
| COMP-07 | NazoAuth security contract · POLICY | Counter / metadata CAS | PASS counter CAS | PASS with complete metadata CAS | Prior counter and prior known BE constrain write; JSONB updates preserve UV history and BS. SQL conflict cannot issue success. Live DB regression tests; execution status separate. |
| COMP-08 | Public API / wire adapter · POLICY | API compatibility | PASS | PARTIAL source compatibility; credential serialization retained | The crate moves to 0.2.0. Methods retained; new fallible / discoverable methods added. Rust struct literals need new fields. Old credential JSON does not. Flat response adapter preserved; not identical to browser nested toJSON. |
| COMP-09 | [W1] §7.1 s12 / §7.2 s14; [W2] §7.1 s17 / §7.2 s18; [W3] §7 · version change | Unsolicited extensions | PARTIAL | PASS to L2/3 policy; intentional L1 rule difference | L1 demanded requested extension IDs only. Later levels permit ignoring unsolicited outputs. This verifier structurally validates then ignores unimplemented outputs without assigning security meaning. |


## 7. RP recommendations and application-owned controls

These recommendations are included so that a narrow verifier PASS cannot hide
remaining product or deployment obligations. They do not justify adding browser,
authenticator, account-recovery or hosting infrastructure to this crate.

| ID | Normative source / applicability | Check | Baseline | Revised | Location, decision, and evidence |
|---|---|---|---|---|---|
| APP-01 | [W3] §4 RP definition · MUST · client/server transport | HTTPS / equivalent | PARTIAL, deployment | PARTIAL, deployment | Production origin configuration requires HTTPS; actual TLS termination remains outside the verifier. Localhost HTTP examples are local development only. |
| APP-02 | [W3] §5.4.1, §5.4.3 · SHOULD / SHOULD NOT | User-facing names | PARTIAL, application | PARTIAL, application | Callers supply displayName and user name; no unnecessary script/name restriction is added. PRECIS recommendation remains RP-05; UI choices are not credential identity. |
| APP-03 | [W1] §7, §14.10; [W3] §7, §14.6.2 · SHOULD | Enumeration resistance | PARTIAL, application | PARTIAL, application | Library errors are not a public account-existence oracle contract. NazoAuth's existing uniform-response behavior is retained (`passkey_login_begin_does_not_enumerate_account_or_credential_state`). Response/rate-limit policy remains application-owned; demos deliberately expose setup state. |
| APP-04 | [W3] §13.4.8–9 · SHOULD NOT / MUST NOT (conditional) | Untrusted origin code | PARTIAL, deployment | PASS exact-origin verifier; PARTIAL hosting | No automatic subdomain acceptance. Production CSP, script supply chain and code hosting still matter. Manager example removes a concrete stored HTML injection sink. |
| APP-05 | [W3] §13.4.6 · SHOULD | Multiple credentials / recovery | PASS API; PARTIAL product | PASS API; PARTIAL product | Multiple credential lists and exclude IDs supported; NazoAuth's enrollment/deletion authorization retained. Account recovery UX is outside the library. |
| APP-06 | [W3] §6.1.3 · RECOMMENDED / SHOULD · backup loss | Backup-state recovery UX | FAIL metadata; PARTIAL product | PASS metadata; PARTIAL product | BE/BS now stored after verification. No automatic recovery-factor prompt or password deletion is introduced on BS transitions; NazoAuth does not make those decisions from these flags. |
| APP-07 | [W2] §7.1 s23; [W3] §5.2.1, §7.2 s1 · SHOULD / SHOULD NOT | Preserve transport hints | PASS core; PARTIAL SQLite | PASS | Accepted strings retained without filtering unknown enum values. Full-record persistence avoids lossy CSV reconstruction of new rows. with_creds APIs replay hints; labels render as text. |
| APP-08 | [W3] §5.4 · SHOULD · broad authenticator coverage | Recommended algorithm breadth | PARTIAL, explicit subset | PARTIAL, explicit subset | RSA remains unoffered to preserve the two required algorithms and a smaller verifier surface. This is a justified interoperability limit, not a claim that all registered COSE algorithms work. |
| APP-09 | [W3] §5.4 · NOT RECOMMENDED | Fully specified algorithm aliases | PASS | PASS | Offers -7/-8 as before; no automatic migration to new alias identifiers based only on IANA registry evolution. Keys remain bound to the explicit supported curves. |
| APP-10 | [W2] §5.4.4; [W3] §5.4.4 · SHOULD · residentKey=required | Legacy resident-key option | PASS in example | PASS in example | Core default is preferred. Passwordless browser adapter already sets both residentKey=required and requireResidentKey=true; this baseline behavior is retained. |
| APP-11 | [W3] §5.1.3–4, §5.1.7 · SHOULD / MUST NOT · capabilities | Feature detection / extension assumptions | NOT APPLICABLE | NOT APPLICABLE | No conditional-create or capability-dependent extension assurance is claimed. Supporting a client capability would not prove the selected authenticator supports it. |
| APP-12 | [W3] §5.1.10.3 · SHOULD · credential signals | Authenticator signal API | NOT APPLICABLE | NOT APPLICABLE | No signalAllAcceptedCredentials / signalUnknownCredential integration is shipped; server-side deletion remains account-authorized. |

## Verification order and atomicity

The revised verifier can reject malformed / oversized data before an expensive
cryptographic operation. It never treats an early parse result as authenticated
state. Registration returns a record only after client binding, RP hash, flags,
credential schema, ID agreement and applicable attestation checks. Authentication
resolves the allowed credential and expected account before parsing signed
fields; success is emitted only after signature validation and counter policy.

Application commits are a second boundary. NazoAuth must consume ceremony state,
verify account/tenant binding, obtain a valid result, atomically persist the
credential update, and only then issue the corresponding session/audit outcome.
The verifier cannot roll back an application-issued session or make a database
write atomic. A retry after a consumed state must start a fresh ceremony.

## Compatibility decisions that need continued attention

1. Strictness for new wire CBOR is not a Level 3-only change: all three WebAuthn
   levels reference the CTAP2 encoding profile. The historical stored-key path
   is separate so harmless old ordering does not force new enrollment.
2. Old `uv_initialized=None` records keep their signing keys and login capability.
   They lose no cryptographic ability; the application cannot infer historical
   initialization from an assertion. NazoAuth provides a controlled path to
   establish that missing fact without creating a new credential. Existing
   session / remembered-MFA lifetimes are preserved rather than globally
   revoked. Their historical AMR is not retrospectively proved; a still-fresh
   historical session can retain enrollment authority under the old management
   policy. Direct initialization of an old credential requires independent
   OTP/recovery-code evidence, not historical `passkey_uv` alone.
3. `none` attestation proves no device origin. AAGUID can be nonzero. Certificate
   signature validity alone is still untrusted evidence, even if its subject
   spells a familiar vendor name.
4. The counter rejection is preserved local policy. It can reject a legitimate
   reordered concurrent assertion or synced-credential behavior; users retry
   with a fresh ceremony, and operators can inspect the audit outcome. Relaxing
   that policy would be a separate NazoAuth business decision.
5. Limits and unsupported map-key structures are explicit. An extension needing
   broader structures must receive its own schema / policy review rather than
   silently weakening the existing decoder.

## Evidence completion

The matrix identifies both retained baseline coverage and new tests. The
release/PR reviewer must consult [validation.md](validation.md) for actual
execution. A test filename, a CI job definition, source-level PASS, or the
presence of a fuzz target is not proof of a successful run. Remaining PARTIAL
rows describe intentional application boundaries or explicit limitations; they
must not be rewritten as universal Level 3 conformance.

[W1]: https://www.w3.org/TR/2019/REC-webauthn-1-20190304/
[W2]: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/
[W3]: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
[CTAP]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html
[COSE-S]: https://www.rfc-editor.org/rfc/rfc9052.html
[COSE-A]: https://www.rfc-editor.org/rfc/rfc9053.html
[CBOR]: https://www.rfc-editor.org/rfc/rfc8949.html
[EDDSA]: https://www.rfc-editor.org/rfc/rfc8032.html
