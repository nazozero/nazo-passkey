# Security review and engineering decisions

Review date: **2026-11-17**.

Library baseline:
`d59b317998e56f4a16a69133d7a854c5c34f795b`, branch
`nazoauth/patched-rustcrypto`, package `passkey-auth 0.1.3`.
NazoAuth integration baseline:
`9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9`.

This review examines the complete library verification path, its tests and
examples, and the NazoAuth integration contract. It introduces code changes,
regressions, and explicit boundaries. It is not a third-party certification,
a formal proof, or a statement that all possible authenticators have been
interoperability-tested. The [protocol matrix](protocol-compliance.md) is the
normative cross-reference. Actual commands and failures belong in
[validation.md](validation.md); benchmarks belong in
[performance.md](performance.md).

## Outcome and security model

The revised implementation gives untrusted response bytes a bounded path to a
verified credential or assertion result. It distinguishes a valid signature
from device trust, and a signed UV bit from eligibility to count UV as another
factor. The persisted key bytes survive the upgrade. Newly added metadata uses
an explicit unknown state when historical information was never stored.

The application still controls account enrollment, pending ceremony state,
credential lookups, transactions, sessions and MFA. This boundary is deliberate:
a synchronous verifier with no network/database handles cannot implement atomic
GETDEL, SQL CAS, or session issuance. NazoAuth's integration is audited and
updated alongside the library so those responsibilities remain connected.

The attacker model includes arbitrary registration/authentication payloads,
malformed JSON/Base64/CBOR/DER, malicious credential keys and attestation
certificates, credential/tenant/account confusion, replay, concurrent requests,
and client-provided transport/extension hints. It does not assume a compromised
server can safely submit forged trusted ceremony states or mutate persisted
public keys: state and credential-store integrity remain part of the trusted
computing base. Public nonce/hash comparisons do not need constant-time equality
because their values are not authentication secrets.

## Baseline provenance and retained fixes

The work starts from the dependency actually locked by NazoAuth. The repository
history includes `63a54b2` (serde support), `1958b77` (patched RustCrypto P-256),
and `d59b317` (Rust minimum), on top of earlier security fixes. Inspection of
`NAZOAUTH_PATCH.md` and the baseline manifest established that the dependency
patch was already present. This task does not reintroduce the older P-256 tree
or pretend the existing patch is a new finding. The security-advisory result for
the resolved dependency tree is recorded with the audit execution, not inferred
from package names.

The following baseline properties were correct and are retained:

- Real RustCrypto ES256 and Ed25519 verification; no handwritten elliptic-curve
  implementation and `#![forbid(unsafe_code)]` in the library.
- An advertised algorithm list shared with registration enforcement.
- Exact configured origin and RP hash comparison; original client JSON bytes
  hashed into the signature input.
- Required UV and UP checks; username-first optional-handle equality and the
  configurable stricter required-handle policy.
- Configurable strict Base64, with the legacy lenient default retained as an
  explicit compatibility choice.
- A conservative counter policy and a prospective update returned to the caller.
- Actual packed / U2F attestation signature verification, and explicit existing
  documentation that a trusted root was not validated.
- Existing malformed-AAGUID rejection rather than silently discarding that
  extension error.

These retained properties have regression coverage; they were not redesigned
merely to increase the amount of changed code.

## Coverage inventory

| Area read | Files / paths | Review focus |
|---|---|---|
| Public API and data | `src/lib.rs`, `types.rs`, `error.rs` | Serde stability, wire shapes, error semantics, trust-state representation, configuration |
| Ceremonies | `src/ceremony.rs`, `client_data.rs` | Verification order, state, account binding, UV / MFA distinction, origin and challenge |
| Binary boundary | `src/auth_data.rs`, `cose.rs`, new `cbor.rs` | Full consumption, duplicate / overflow defense, flags, key schema, bounded borrowing |
| Cryptography / attestation | `src/crypto.rs`, `attestation.rs`, `x509.rs` | Signature inputs, algorithm dispatch, certificate profile, proof versus trust |
| Existing and new tests | Every integration test and source-module test | Real signatures, error paths, compatibility, official vectors, properties |
| HTTP examples | All five Rust examples and all three HTML pages | Enrollment races, user handles, lookup scope, metadata persistence, CAS, DOM rendering |
| Build / dependencies | `Cargo.toml`, lockfiles, `.github/workflows/ci.yml`, patch notes | Existing RustCrypto patch, feature/target compatibility, reported gates |
| NazoAuth identity / ports | `crates/identity/src/passkey.rs`, passkey repository ports | GETDEL / TTL, config, tenant binding, complete verified outcome |
| NazoAuth storage | PostgreSQL passkey repository and identity converters | Two historical JSONB shapes, indexed identity, conditional writes, unknown metadata |
| NazoAuth HTTP / sessions | Registration, login, deletion, session / AMR / MFA / remembered MFA | Enrollment authorization, CSRF, downgrade prevention, atomic state update before success |

## Findings and revisions

Severity descriptions below reflect the affected boundary and preconditions.
They are not CVSS scores and do not assert that each defect gives an unauthenticated
attacker a complete account takeover. A malformed attestation accepted under an
already-untrusted policy, for example, is different from a bypass of credential
signature verification.

### S-01 — Embedded-origin policy was ignored

**Baseline:** `client_data` parsed `crossOrigin` into an unused field and did not
interpret `topOrigin`. A response with the right child origin could therefore
satisfy a verifier configured only for a same-origin application, despite
unexpected embedding. This weakens the RP's intended browser-context policy;
it does not remove the need for a valid challenge and credential signature.

**Revision:** same-origin scope is explicit. A true crossOrigin or any present
topOrigin rejects. Missing crossOrigin remains compatible with older clients;
wrong types and null topOrigin do not masquerade as absence. Exact origin matching
is retained. Tests include local negatives and W3C embedded-origin vectors.
See matrix CD-05/06 and [W3] §7.1/7.2.

### S-02 — Integer narrowing could confuse COSE labels and algorithms

**Baseline:** CBOR integers passed through unchecked narrowing from a wider
integer type. Oversized unsigned / negative values could alias signed labels
or algorithm numbers, defeating the intended schema even though the downstream
cryptographic primitive was still fixed.

**Revision:** checked integer conversions reject values outside the accepted
range before dispatch. Tuple validation binds kty, alg and curve; byte length is
never an algorithm selector. The regression constructs oversized encoded
integers, including values that could wrap to a recognized negative label.
See `BR::algorithm_and_label_integer_overflow_cannot_alias_negative_values`
and matrix BIN-04/10/11.

### S-03 — CBOR ambiguity and incomplete consumption

**Baseline:** generic value maps permitted duplicate keys; some paths selected
a later value. Top-level CBOR could have a trailing second item. Nested extension
and attestation structures were not uniformly checked. Different consumers could
interpret the same input differently.

**Revision:** new borrowing decoder enforces unique map keys, definite framing,
valid UTF-8, checked lengths and exact input consumption. New wire input uses
CTAP canonical ordering and integer/length widths. Duplicate equality is checked
by decoded value as well as canonical order, so alternate-width encodings do
not evade the historical stored-key reader. Nested ignored values are still
structurally checked. See matrix BIN-01/02/03/06 and BR duplicate/truncation tests.

### S-04 — Unbounded parsing and avoidable allocation amplified denial of service

**Baseline:** decoded fields had no library-level resource limits. CBOR value
trees recursively allocated attacker-specified structures; authenticator data,
public keys and attestation components were repeatedly materialized. HTTP
framework defaults in a particular caller are not a stable library contract.

**Revision:** Base64 encoded length is checked before decode allocation, with a
second decoded-length check. CBOR byte, container, depth and total-item caps bound
work independently of declared length. Strings / byte strings are borrowed,
credential keys are parsed once in registration, and fixed-size coordinates /
hashes use stack arrays. P-256 key validity is not redundantly checked twice on
the authentication path. The decoder remains a new security-sensitive parser,
so truncation, property, fuzz and independent vector coverage are required;
passing bounded runs is not an exhaustive proof. Outer HTTP body limits and
rate limits remain application responsibilities. These per-response limits do
not bound an account's stored credential inventory. NazoAuth currently imposes
no per-account credential quota: repository reads, exclusion/allow-list
construction, option serialization and pending-state size grow with the
credential count. Authentication's allow-list membership check also scans that
list. This update preserves all existing credentials rather than silently
truncating them; an inventory quota is a separate application policy. See the
README limit table and validation results.

### S-05 — Public-key validity and schema were incomplete at enrollment

**Baseline:** the parser selected useful fields but ignored extra/private
parameters and did not consistently validate the actual curve point before
accepting a none-attestation enrollment. An unusable or ambiguous key could
therefore be stored and fail only on later login.

**Revision:** new keys must have the exact supported public schema and a valid
P-256 or nonweak Ed25519 point. Private parameter -4 rejects on every path.
Historical stored keys retain harmless optional metadata and encoding-order
compatibility without weakening algorithm / curve / framing checks. Deliberately
malformed old keys are not treated as a compatibility requirement. Tests cover
invalid points, mismatched alg/kty/crv, coordinate sizes, optional/private fields,
and an independent RFC 8032 Ed25519 vector. See matrix BIN-09 through BIN-14.

### S-06 — Authenticator-data flags and extensions lacked complete semantics

**Baseline:** BE/BS were not validated or retained. AT data could be accepted in
an assertion; ED could be set with no valid extension map; extension data could
be a different CBOR type or leave unexplained bytes.

**Revision:** the parser checks BS⇒BE, bounds the attested ID, and requires an
exact map of text extension identifiers when ED is set. Registration requires
AT; authentication rejects it. With ED clear, no tail is permitted. Known BE is
immutable across assertions; BS may change and is returned only after signature
success. Unrecognized extension outputs never authorize MFA. Reserved flag bits
are not assigned invented semantics. See matrix REG-05/06, AUTH-10/11 and BIN-07/08.

### S-07 — Registration response ID was not validated

**Baseline:** `finish_registration` used the attested credential ID but ignored
the outer response `id`, including in strict Base64 mode. The request's declared
credential and the credential stored by the verifier could disagree. Original
exclusion information was also not retained in pending state for an RP check.

**Revision:** strict/bounded decode applies to the outer ID, which must match the
attested ID. Retained exclusion IDs are checked. The 1–1,023-byte local policy
matches the ordinary supported credential range. RP-wide uniqueness is still
an atomic database check; state exclusion alone cannot prevent two ceremonies
that started concurrently. See `CE::registration_outer_id_and_exclusion_are_enforced`
and example race test.

### S-08 — Certificate parsing did not establish the required supported profile

**Baseline:** x5c attestation checked a leaf signature but did not sufficiently
validate v3, basicConstraints, required subject structure or the explicit P-256
named-curve OID. AAGUID criticality and duplicate extensions were not fully
checked; U2F accepted more than one certificate.

**Revision:** ES256 certificate verification checks EC/P-256 SPKI rather than
inferring a curve from length. Packed checks v3, a non-CA basicConstraints value,
required C/O/OU/CN and specified ASN.1 string tags, exact OU, and correctly encoded
noncritical AAGUID when present. Duplicate extensions reject. U2F has exactly one
certificate and the prescribed signature input. The certificate subject's country
field is checked syntactically, not against a current geopolitical registry;
subject/vendor statements are untrusted in this library. Profile, curve, critical
AAGUID, duplicate-extension and chain-length negatives supplement real-signature
positive cases. See matrix ATT-03 through ATT-09.

### S-09 — None attestation accepted an absent or nonempty statement

**Baseline:** dispatch on fmt=none did not prove that attStmt was present and an
empty CBOR map. This accepted inputs outside the supported attestation syntax.
It did not itself forge a credential signature because none provides no
attestation signature in the first place.

**Revision:** exactly an empty map is required. Missing, wrong-type and nonempty
statements reject, with separate regressions. Unknown statement members in
supported packed/U2F schemes are not silently downgraded. See matrix ATT-01/13.

### S-10 — Attestation evidence was not represented in the persisted result

**Baseline:** documentation said roots were not validated, but callers only
received a public key and AAGUID. A downstream consumer could mistake successful
registration or a recognizable AAGUID for verified authenticator provenance.

**Revision:** an explicit enum records Unknown / None / SelfAttestation /
UntrustedCertificate. No trusted-manufacturer variant is produced. Certificate
chain signatures, anchors, expiry, revocation and metadata status are outside
the implementation; accepting an untrusted attestation is a stated RP policy.
AAGUID alone cannot authorize enterprise device policy. Trusted-root handling
would require a separate design and authenticated trust source, not merely
parsing one more certificate. See matrix ATT-11/12 and [W3] §7.1, §13.4.4–5.

### S-11 — Signed UV was conflated with initialized UV-factor history

**Baseline:** `AuthSuccess.user_verified` faithfully reported signed UV, but the
credential record retained no uvInitialized information. That was insufficient
for the newer Level 3 factor-eligibility rule when a credential was enrolled
without UV or its history was not known.

**Revision:** registration stores UV initialization; legacy JSON defaults to
unknown. Authentication returns both `user_verified` and
`user_verification_eligible = signed_uv && initialized == Some(true)`.
It never promotes history implicitly. NazoAuth bases MFA on eligibility and
can initialize old history through a recent independent OTP/recovery-code MFA
session with matching tenant/user and CSRF proof. Remembered MFA and historical
passkey_uv cannot authorize this bootstrap. The current ceremony still receives
its pre-promotion eligibility; only a later assertion can use the new history.
This avoids unnecessary key replacement while preserving the factor boundary.
It changes new authentication decisions, not the historical evidence behind
already-issued sessions. The deployment preserves their existing lifetimes and
management privileges rather than globally revoking them; see the migration
boundary below.
See matrix AUTH-15/16, [W3] credential-record definition and §7.2 s24.3.

### S-12 — Ceremony state admitted zero/future timestamps and policy drift

**Baseline:** a zero timestamp bypassed expiry, and future timestamps saturated
age to zero. The state did not bind the effective RP/origin/UV/Base64/handle
configuration that issued it. Server-controlled state is trusted input, but
storage migrations or a deployment configuration change could expose these
loopholes.

**Revision:** zero/future timestamps and missing/changed context bindings reject.
Old in-flight states restart. The hash is a consistency binding, not an HMAC
that makes client-controlled state trustworthy. Challenge length is bounded.
Atomic consume and tenant/session binding remain external, preserved in NazoAuth.
See matrix RP-08/09/10 and CE state regressions.

### S-13 — Generic authentication left discoverable-account binding too implicit

**Baseline:** username-first APIs could compare a supplied handle, but generic
empty-allow-list flows depended entirely on the caller to validate the returned
handle and its relationship to the selected key. Public-key verification alone
does not establish which application's account owns that key.

**Revision:** the record carries its registration handle, known state/record/
caller handles must agree, and a discoverable assertion requires a returned
handle plus a resolvable expected account. The explicit discoverable finish API
accepts the verified database account handle for legacy records. NazoAuth's
username-first scoped lookup remains intact, including the explicit tenant
recheck after consuming ceremony state. See matrix AUTH-02 through AUTH-05.

### S-14 — Example enrollment races could add a key after an account was claimed

**Baseline:** the multi-user passwordless example checked username availability
at registration start, then appended a credential at finish. Two pending signups
could both pass the early check and the second could attach its key to the
first-created account. Other examples separately assigned account handles or
allowed an initial-enrollment finish after a first enrollment had already won.
These are example integration defects, not evidence that NazoAuth used the
same in-memory store.

**Revision:** account/credential uniqueness is checked atomically at insertion;
random pending handle is bound to that insertion. Single-account handle creation
is done under one lock and finish checks it. Initial credential-manager finish
refuses after setup has completed. A real Ed25519 registration fixture drives
`two_pending_signups_cannot_add_a_key_to_the_same_account`. Authenticated adding
of another passkey remains a separate operation.

### S-15 — SQLite example lost metadata and updated counters unconditionally

**Baseline:** the example stored only the original fields and updated by
credential ID without expected counter/account. The same-process mutex hid some
races but was not a database-level compare-and-swap contract. Simply adding
library fields without changing this example would also discard them.

**Revision:** an additive nullable JSON column retains the full record alongside
indexed fields. Old rows convert their exact key bytes and mark unknown history
explicitly; lazy update writes the full form. Reads reject disagreement between
indexed identity/key/counter and JSON. Lookups scope by user and credential ID;
updates condition on account, ID, prior counter and prior BE/BS/UV metadata
and must affect exactly one row. The metadata condition protects valid 0→0
counters across processes. Tests cover stale-counter and zero-counter metadata
conflicts, metadata retention, other-account lookup and an actual old-schema
SQLite database upgraded with its original credential still present. The example is not a distributed session service;
NazoAuth's PostgreSQL CAS preserves its zero-counter backup-eligibility
initialization and monotonic UV-history rules.

### S-16 — Credential-manager example rendered untrusted labels as HTML

**Baseline:** `transports` came from the client and was later interpolated into
`innerHTML`. A malicious enrolled value could become stored DOM injection in
the manager UI. Credential listing also lacked the session check used for
credential mutation.

**Revision:** table cells use `textContent` and DOM construction, and listing
requires sign-in. Public initial-setup status returns a boolean instead of the
credential list. Existing start-endpoint CSRF / production session hardening
limitations remain explicitly documented; this fix does not make the examples
production servers.

### S-17 — Example user handles were derived from usernames

**Baseline:** a deterministic username hash was presented as a user handle.
Although opaque-looking, it permitted dictionary recovery and cross-service
correlation of predictable usernames.

**Revision:** each new account gets an independent random 32-byte handle that is
persisted with the account; it is not recomputed from personal information.
NazoAuth's existing stable user identifier contract is retained. The verifier
validates length but cannot detect the semantics of arbitrary caller bytes.
See matrix RP-03.

### S-18 — Counter and attachment documentation overstated security meaning

**Baseline:** documentation described counters as replay protection / proof of
cloning and suggested cross-platform attachment for hardware-only policy.
Those statements could encourage incorrect business decisions even when the
signature implementation was correct.

**Revision:** counters remain a conservative anomaly policy; one-time challenge
consumption supplies ceremony replay prevention. Concurrent response reordering
and authenticator behavior can cause counter conflicts. Attachment/transports
are discovery hints, and AAGUID / certificate subjects without trust anchors
are not hardware provenance. Existing rejection semantics stay unchanged; only
unsupported claims are removed. See [W3] §7.2 and the README caller contract.

### S-19 — Example development dependencies contain published vulnerabilities

**Observed audit results:** the audit of a separately resolved baseline lockfile
for `d59b317` reported two vulnerabilities. The intermediate candidate audit,
after disabling Rocket's default HTTP/2 feature but before the SQLite upgrade,
reported one. These are actual failed advisory checks, not inferred findings:

| Advisory | Baseline package | Intermediate candidate | Relevant path and impact |
|---|---|---|---|
| [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | `h2 0.3.27` | Removed from this dependency graph | Rocket's default HTTP/2 development dependency. Undrained streams can queue unlimited empty DATA frames, consuming memory or causing a panic. |
| [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html) | `libsqlite3-sys 0.30.1` | Still reported at `0.30.1` | `rusqlite 0.32` with `bundled`, used by the SQLite example. Opening a malicious database and sibling WAL file can expose uninitialized process memory; this is a local file-input precondition, not a demonstrated remote WebAuthn attack. |

The machine-readable evidence is `audit-baseline.json` and
`audit-candidate.json`; their authoritative locations and command results are
listed in [validation.md](validation.md). Both used RustSec database revision
`02e2517f457a359fc6d3440ea4560c8ea188fee8`, with 1,509 advisories and no ignored
advisories. The baseline lockfile is a fresh resolution of the pinned library
source at the review date, not evidence of NazoAuth's historical production
dependency resolution.

**Scope:** Rocket and rusqlite are in this crate's `[dev-dependencies]` for
examples/tests. A downstream application depending on `passkey-auth` does not
inherit these development dependencies. These results do not establish that
NazoAuth's production process contains either affected package or that a
production exploit is reachable; its own dependency graph requires its own
audit. They still matter for users running the affected examples.

**Revision and verification:** Rocket now disables default features
and enables only its JSON support, removing the unused HTTP/2 path. The SQLite
example now resolves `rusqlite 0.41.1` and `libsqlite3-sys 0.39.1`, above the
advisory's patched minimum of `libsqlite3-sys 0.39.0`. These advisory-specific
fixes do not change the credential-signature backend. The post-SQLite-upgrade
audit checkpoint exited 0:
`audit-candidate-final.json` records **zero vulnerabilities, zero warnings and
zero ignored advisories**, using the same database revision. The full regression
rerun after the SQLite upgrade also passed, including all three SQLite
migration/CAS tests. Exact commands and logs are recorded in the validation
artifact. An advisory-clean lockfile does not itself prove runtime correctness
or permanent freedom from future advisories.

## Persistence and integration contract

The 0.2.0 credential adds optional metadata through serde defaults; the
original ID and COSE byte representation is unchanged. Missing metadata does
not become false evidence of security, and the existing signing keys remain
usable. The Rust source API does require updating external struct literals.
Old pending states are intentionally invalidated rather than accepting an
unbound compatibility fallback.

The NazoAuth integration touches these boundaries:

| Boundary | Preserved / revised behavior | Regression evidence |
|---|---|---|
| Valkey ceremony | Existing one-time GETDEL and configured TTL remain; consumed envelope's tenant also matches configured tenant | `passkey_login_finish_creates_session_updates_counter_and_consumes_ceremony_once`; `passkey_login_finish_rejects_origin_mismatch_and_consumes_ceremony` |
| Expiry | Existing short-lived ceremony behavior remains independent of verifier's 300-second ceiling | `passkey_login_reuses_verified_uv_and_preserves_mfa_without_it` includes a one-second TTL expiry case |
| JSONB legacy shapes | Existing converters continue reading both historical forms; ES256 / Ed25519 assertions use the same stored bytes | `crates/persistence-postgres/tests/unit/convert/passkey_material.rs::legacy_jsonb_es256_and_ed25519_credentials_authenticate_without_registration`; exact executed inventory in validation |
| UV policy | Required / Preferred and signed UV are separate from factor eligibility | `passkey_login_reuses_verified_uv_and_preserves_mfa_without_it`; `legacy_or_uninitialized_uv_needs_independent_mfa_before_future_eligibility` |
| UV initialization | Same tenant/user, recent independent MFA, current CSRF proof; current assertion stays ineligible | `uv_initialization_requires_fresh_independent_mfa_bound_to_the_account`; `login_only_allows_uv_initialization_with_the_existing_session_csrf_proof` |
| SQL update | Prior count / backup eligibility compare-and-swap, full JSONB backup state, monotonic UV initialization | `passkey_counter_update_is_monotonic_compare_and_set` |
| Session / AMR | MFA decisions consume eligibility; non-UV / unknown-history assertion does not grant new MFA; independent remembered policy is retained | NazoAuth passkey/MFA session regressions in validation |

These are test definitions and inspected call paths. Their existence is not a
claim that PostgreSQL, Valkey, or the entire NazoAuth test suite has run; the
validation artifact is authoritative about execution.


NazoAuth's existing registration/deletion authorizer is also part of this
boundary: it requires an active complete session, CSRF proof and fresh credential
management authorization. For an MFA-enabled account, that authorization uses
recent interactive MFA; a pending session from a non-UV legacy passkey cannot
use a new enrollment to bypass the UV-initialization rule. Accounts without MFA
keep their existing fresh-primary-factor enrollment policy.

The migration deliberately preserves existing sessions and remembered-MFA
lifetimes. It does not retrospectively prove that a historical `passkey_uv` AMR
claim came from an initialized credential. A historical complete session still
inside the existing fresh-management window can therefore authorize enrollment
of a new key under the prior policy. This transitional authority is not the
same operation as directly initializing an old credential: that operation
requires independent recent OTP/recovery-code evidence and current CSRF proof.
Deployments requiring immediate invalidation of all historical claims need an
explicit session-revocation policy; this change does not perform that migration.

## Protocol and architecture decisions

### Supported subset instead of speculative feature expansion

Only the two credential algorithms already needed by NazoAuth remain enabled.
There is no new PRF secret handling, credProtect policy, AppID fallback,
manufacturer allow list, related-origin fetcher, or asynchronous dependency in
the core verifier. Unsupported features fail or remain explicitly unclaimed.
This keeps their security policy out of an API that does not have the state or
trust material to implement it correctly.

### Borrowing parser with an explicit compatibility path

Generic CBOR value trees were replaced where their allocation and ambiguous
schema handling interfered with the verifier's invariants. This is a protocol
parser, not a cryptographic primitive. New input has one strict path; existing
COSE keys have a bounded compatibility path for representation differences.
That distinction avoids re-registering valid keys without grandfathering
ambiguous or private parameters. Known fields become fixed-size validated types
before cryptographic dispatch. No Arc, Mutex, Box, or async wrapper is introduced
into the verification core.

### Crypto backend selection

The default remains RustCrypto. A feature disabled by default, `aws-lc`, selects
`aws-lc-rs =1.18.2` for native credential ES256 verification, matching the version
already used by NazoAuth. All WASM targets retain RustCrypto even when the
feature is enabled. Ed25519 always retains dalek's strict verifier. Certificate
signatures in packed x5c and FIDO U2F also remain on RustCrypto; ES256 assertions
and packed self-attestation use the selected credential backend. No runtime
backend-selection trait, Arc, Mutex, or asynchronous wrapper is introduced.

The choice follows a measured comparison, rather than an assumption about
native code. The [recorded five-round backend experiment](evidence/performance-backends.json)
used 5,000 samples per case. Its median of per-round ES256 parse-and-verify P50s
was 401.7 µs for RustCrypto and 81.1 µs for AWS-LC, a ratio of about 4.95:1.
Ed25519 timings were similar, around 60 µs. The AWS-LC Ed25519 primitive also
accepted the experiment's identity-key/small-order forgery fixture. This
demonstrates that it cannot replace the existing strict RP acceptance policy
without additional validation; the crate does not select it. These measurements
are backend evidence only. They do not establish whole-ceremony gains, total
native allocation counts, or performance on another host; those require the
separate production-path measurements.

Both ES256 paths retain RustCrypto's DER/scalar parser before verification.
AWS-LC uses the fixed P-256/SHA-256/ASN.1 algorithm with the 65-byte uncompressed
SEC1 key. Authentication computes SHA-256 of the exact transcript locally in
two borrowed pieces. Only that local digest enters `Digest::import_less_safe`,
with the fixed SHA-256 identifier; the public `verify_digest` path checks the
algorithm. No client-supplied prehash is imported and the transcript is not
hashed twice. Self-attestation uses the ordinary complete-message API.
The reviewed implementation is accompanied by real signatures, high/low-S,
wrong-transcript, malformed-DER, invalid-point and backend comparison cases;
executed feature-matrix results remain separate from this source review.

P-256 disables default features and explicitly enables `ecdsa`, `std` and
`precomputed-tables`. The verifier does not need PEM parsing; tests that mint
certificates enable it only as a development dependency. `std` is retained for
the synchronization used by cached precomputed tables, preserving that
verification path instead of accidentally trading it away during feature
reduction. This is dependency selection, not a new elliptic-curve implementation
or an unmeasured claim about another backend.

### Ed25519 encoding validity without recompression

The optimized helper preserves the former decode/recompress/nonweak acceptance
set. [RFC 8032 §5.1.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3)
requires the encoded y coordinate, after removing the sign bit, to be below
`2^255 - 19`. Exactly 19 values of the 255-bit encoding violate that strict bound. A
fixed byte-range check rejects them without re-encoding a curve point. Dalek
still performs point decompression and weak-point detection.

For canonical y, the only remaining sign ambiguity has x=0; the Edwards
equation then gives y=±1. Both points are small-order and already rejected by
dalek's weak-key check, for either sign bit. The optimized check therefore
removes a redundant recompression rather than removing a key-validity rule.
Tests enumerate all 19 boundary values with both signs, both x=0 points with
both signs, and each byte boundary; a 2,048-case property compares acceptance
with the previous recompression implementation. Another property exercises
real signatures and corrupted messages/signatures. `verify_strict` remains
unchanged. Field arithmetic and signature verification stay in dalek.

### Challenge entropy selection

Challenge generation now calls `getrandom 0.4` directly for its 32 bytes,
removing production `rand 0.8` / ChaCha state. An entropy-source error panics
rather than issuing a predictable challenge. Native and WASI targets use their
platform random interfaces; unknown WASM explicitly selects `wasm_js` and Web
Crypto. `web-time` already requires `wasm-bindgen` on that target, so this falls
within the documented [getrandom exception for such libraries](https://docs.rs/getrandom/0.4.3/getrandom/#webassembly-support).
It does not claim a generic non-JavaScript unknown-WASM runtime.

### Configuration checked once

RP hash and effective policy binding are computed at construction / policy
change. Invalid origin configuration is a startup error through `try_new`.
Existing convenience methods remain for trusted, already validated inputs.
This removes recurring work while making the accepted policy explicit.
Suffix matching applies only to domain hosts. IP-address hosts require exact
RP ID equality; an address suffix is never treated as a parent domain.
No Public Suffix List is embedded: an operator still must select an appropriate
RP registrable domain. Browser rejection is not presented as server validation.

### No security-cost trade for benchmark improvement

Full signature checks, key validation at the required boundary, context checks,
account binding, duplicate rejection and counter handling remain enabled in
benchmarked finish operations. Performance conclusions must identify inputs,
build mode, same host, concurrency, sample count, percentiles, allocation
instrumentation and artifacts. Native results do not imply WASM results. A
backend or build configuration not run is listed as unmeasured.

## Validation snapshot

Before the optional AWS-LC backend and final Ed25519 encoding optimization, the
local formatting, check, Clippy, 97-test suite, one documentation test and
rustdoc gates passed. Minimal native and browser-target WASM builds
passed, and the WASI executable ran successfully. These distinguish compilation
and WASI execution from real browser/authenticator interoperability; the latter
is not established by a target build. The complete commands and environment
appear in [validation.md](validation.md). That checkpoint is not a claim that
the new backend or encoding changes have already passed the complete suite;
their final feature-matrix and regression results are recorded separately.

The first fuzz run completed 341,464 executions before LeakSanitizer failed under
the environment's ptrace restriction, leaving the overall command at exit 1.
It is retained as a failed run. The emitted empty input replayed under ASan
with exit 0. A second run disabled leak detection only, retained ASan, and
completed 579,392 executions in 121 seconds with exit 0. Leak checking remains
unavailable in this environment; the successful bounded fuzz run does not
replace it or prove the absence of every parser defect.

## Remaining limitations and operational risks

- Trusted authenticator provenance is unavailable. Certificate roots, chain
  signatures, date validity, revocation, metadata status, firmware identity and
  hardware isolation are not verified. Deployments needing those claims need
  another trusted-attestation layer.
- Legacy UV history is unknown until the application establishes it with
  sufficient independent authorization. The controlled NazoAuth migration flow
  avoids re-enrollment but is not implicit evidence that every old key was
  originally enrolled with UV.
- Existing sessions and remembered-MFA claims retain their prior lifetimes;
  the migration neither re-proves their historical AMR nor globally revokes
  them. A still-fresh historical management session can enroll a new credential
  under the existing authorization policy. Only an independent authorized
  factor can directly initialize unknown history on the old credential.
- Same-origin web ceremonies only. Cross-origin embedding, native-app origins
  and related-origin discovery require new explicit policy/API work.
- Strict new-wire canonical CBOR and bounded supported schemas can reject
  nonconforming or unusually large devices / extensions. The historical stored
  key path does not relax new enrollment validation.
- No library-level one-time challenge consume, distributed transaction or HTTP
  request cap. Those responsibilities remain mandatory in integrations. A caller
  that issues a session before CAS success defeats the intended boundary.
- Per-response parser limits do not cap a relying party's total work or storage.
  NazoAuth has no per-account credential quota, so begin work and options/state
  size grow linearly with the account's stored credential list. Account-level
  limits and request throttling require explicit product policy.
- Counter anomalies remain a rejecting local policy, including for synced
  credentials. This can cause recoverable false rejections; it does not justify
  labeling a user or authenticator as malicious.
- The handwritten bounded parser and compatibility path require continued fuzz
  coverage. A finite fuzz duration, property sample set or successful official
  vector suite cannot establish absence of all parser defects.
- The examples still lack production session limits, comprehensive start-route
  CSRF handling, rate limiting and account recovery. Fixed example defects
  should not be misread as a complete web-application security review.
- Real hardware/browser interoperability, additional operating systems,
  long-running fuzzing, leak detection, independent review and unmeasured
  performance dimensions remain outside the successful local gates. WASI
  execution and browser-target compilation do not establish browser runtime
  interoperability; CI declarations alone do not establish a platform result.

[W3]: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
