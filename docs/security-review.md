# Security review

Review date: **2026-11-18**. Component: `nazo-passkey 0.2.0`.

## Verification boundary

The verifier consumes server-owned ceremony state, an untrusted response,
and, for authentication, the stored credential selected within the intended
account. It returns a credential or authenticated update after checking the
challenge, exact origin, RP ID, account binding, flags, key, and signature.
The application consumes state once and commits the result before session
issuance.

The implementation has no HTTP server, database, account-recovery flow, or
background task. Configuration validates the external RP/origin boundary;
parsers validate untrusted wire data; stored-key decoding preserves explicitly
supported historical forms. Internal helpers reuse parsed fields and verified
keys.

## Findings fixed during the final review

| Finding | Change | Regression evidence |
| --- | --- | --- |
| Outer response compatibility could permit a noncanonical signed challenge | Always require canonical unpadded base64url for `clientDataJSON.challenge` | Unit and real-signature ceremony tests reject padded challenges even with the lenient adapter |
| Direct JSON byte parsing differed from WebAuthn's UTF-8 decoding algorithm | Decode with UTF-8 replacement semantics after stripping the parsing BOM; hash the original bytes | Invalid-UTF-8 / BOM tests and signatures over original versus normalized bytes |
| An empty allow list was treated as discoverable even when the account was already bound at start | Derive handle-presence policy from both the account binding and allow list | Username-first empty-list test; missing-handle rejection remains for discoverable and explicit strict-handle policy |
| Runtime and certificate-test dependencies used different x509-cert generations | Consolidate on x509-cert 0.3 and use its immutable accessors | Existing positive and malformed-certificate cases remain executable using test-only DER fixtures |
| Package metadata and examples still described the upstream package | Independent package/import names, corrected maintainer email, preserved origin and license attribution | Package verification, examples, rustdoc, and migration instructions |

## Cryptographic and parser checks

ES256 requires a valid P-256 key and valid DER/scalar representation and
verifies the exact signed transcript. The optional AWS-LC path receives the
internally computed transcript digest; both paths preserve high-S acceptance.

Ed25519 uses ordinary dalek multipart verification. Canonical point encoding,
weak-point rejection, and scalar bounds preserve the established strict policy.
Independent CCTV vectors, every message split, torsion boundaries, and a strict
oracle exercise that policy. Applications must keep dalek's
`legacy_compatibility` feature disabled.

Canonical wire-map ordering establishes key uniqueness in one pass. Decoding
uses bounded lengths, recursion, and item counts and consumes complete frames.
The stored-key compatibility reader checks usage restrictions and known
metadata types without relaxing public-key or algorithm requirements.

Certificate signatures establish the stated evidence level. Trust in a
manufacturer requires a separate root, chain, validity, revocation, and
metadata policy. See the [protocol matrix](protocol-compliance.md) for the
supported leaf profiles and formats.

## Ownership and allocations

Decoded response buffers own Base64 output. CBOR fields and valid UTF-8 client
data borrow those buffers. Invalid UTF-8 uses an allocated replacement string
only on that path; signature hashing still borrows the original bytes. Fixed-size
cryptographic values use bounded stack storage. Ed25519 hashes transcript
parts without concatenating them. Owned returned credentials and x509-cert's
certificate model allocate as required by their APIs.

## Application obligations

- Authorize enrollment and deletion against the intended account.
- Select opaque account handles and enforce tenant/RP isolation.
- Consume server-owned ceremony state atomically once and enforce its TTL.
- Enforce RP-wide credential-ID uniqueness at insertion.
- Commit verified counter and backup metadata with compare-and-swap before issuing a session.
- Count UV as another factor only when `user_verification_eligible` is true.
- Apply HTTP limits, account quotas, CSRF protection, and request throttling.
- Establish a trust policy when approved authenticator provenance is required.

The counter policy can reject a reordered concurrent assertion. A zero-only
counter is accepted; other non-increasing values reject. Retry and recovery
behavior belongs to the application.

## Evidence

[Validation](validation.md) records the current executed gates. The
[historical security review](https://github.com/nazozero/nazo-passkey/blob/main/docs/security-review-checkpoint-8260480.md) retains
earlier findings, fixes, and consumer-specific investigations. Performance
measurements retain their original source and lockfile identities in
[performance](performance.md).
