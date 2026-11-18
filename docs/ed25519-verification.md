# Ed25519 verification policy and implementation

The verifier uses ordinary Ed25519 for COSE `alg=-8`, `kty=OKP`, `crv=Ed25519`.
Its message is `authenticatorData || SHA-256(clientDataJSON)`. Feeding these two
borrowed slices to dalek's multipart API preserves the ordinary Ed25519 message;
it does not turn WebAuthn into Ed25519ph.

The implementation retains the previous acceptance policy: a canonical,
onweak public point and a signature accepted by dalek's strict verifier. The
small-order rejection is an existing local policy, not an assertion that
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) mandates
all of dalek's additional strict checks.

## Why the two paths have the same acceptance boundary

This review is against **ed25519-dalek 3.0.0**, including its
[`VerifyingKey` implementation](https://docs.rs/ed25519-dalek/3.0.0/src/ed25519_dalek/verifying.rs.html).

| Check | Implementation and reason |
| --- | --- |
| COSE algorithm and curve | `src/cose.rs` validates the complete supported tuple; an Ed448 or EC2 key cannot select this verifier. |
| Canonical public encoding | Removing the sign bit must leave `y < 2^255 - 19`. The existing byte-bound check rejects all 19 excluded values without recompression. |
| Nonweak public point | The eight wholly small-order points have five distinct encoded y coordinates. The finite encoding filter rejects both sign bits for each, including the two x=0/sign=1 aliases. |
| Actual public-point validity | `VerifyingKey::from_bytes` still decodes the point. Passing the finite filter alone never establishes that arbitrary bytes represent a curve point. |
| Signature shape and scalar | Dalek parses the 64-byte signature and enforces `S < L`. The strict and multipart paths share this scalar parser. |
| Canonical, nonweak signature R | The same finite encoding filter rejects the forbidden encodings and wholly small-order R. The multipart verifier compares the canonical compressed point it computes with the supplied R bytes. Success therefore also establishes that those R bytes encode that valid point. |
| Signature equation and hash | Dalek performs SHA-512 and the signature equation. The library does not implement group arithmetic, scalar arithmetic, or a replacement signature primitive. |
| Mixed-torsion points | These are not wholly small-order points. They remain accepted when the previous strict verifier accepts the signature; no new prime-order-subgroup restriction is introduced. |

The strict path additionally decompresses R before computing and comparing the
expected R. For a successful signature, the later canonical encoded-point
comparison already establishes R's validity. Retaining the separate finite
small-order filter permits that redundant decompression to be removed. The
multipart API also removes transcript concatenation and its allocation.

**Do not enable dalek's `legacy_compatibility` feature in a consumer dependency
graph.** It relaxes the scalar parser used by both `verify_strict` and the
multipart API. Cargo feature unification can enable a dependency feature from
another crate. This unsupported configuration is not repaired with a second
scalar implementation. The S+L regression must continue to fail verification.

## Evidence required when changing dependencies

`src/crypto.rs` and `src/cose.rs` retain an independent, deliberately slower
oracle using decompression/recompression plus dalek `verify_strict`. The test
suite compares the production policy against that oracle and external vectors:

- The pinned [C2SP/CCTV Ed25519 corpus](../tests/fixtures/cctv/PROVENANCE.txt):
  **914** vectors, **43 accepted and 871 rejected** by this policy. Every split
  of each message, including empty parts, exercises multipart verification.
- The complete `curve25519-dalek::constants::EIGHT_TORSION` set independently
  derives the five y coordinates; both sign bits reject. The production table
  is not used to construct its own expected set.
- **248** mixed-torsion public points retain the former acceptance behavior.
- All noncanonical y-boundary encodings and x=0 sign aliases are tested, with
  a property comparing random public encodings against recompression.
- RFC 8032's literal vector and real signatures cover altered messages, hashes,
  signatures, keys, truncation, and noncanonical S+L signatures.
- Complete registration, authentication, and self-attestation tests exercise
  both credential algorithms. A key accepted at enrollment must still verify
  the intended transcript later.

The curve crate is a **development-only** dependency for these independent
checks; it is not a new production cryptographic implementation. Tests, source
review and bounded fuzzing provide evidence, not a formal proof of all possible
inputs. Dependency upgrades must rerun the acceptance comparisons and review
any change to dalek's scalar parser or multipart verification semantics.

## Measured benefit and scope

The decision was based on full registration and authentication operations,
including parsing and protocol checks, using two builds that differ only in
this Ed25519 path. The fixed transcript removes one allocation of 69 bytes from
authentication; larger authenticator data avoids the corresponding larger copy.
Latency, distributions, shared-host noise, the comparison with the previous
calibration, and the original production baseline are recorded in
[performance.md](performance.md). The fixture's allocation saving is not a
claim that an entire ceremony or application allocates nothing.
