# External test vectors

`w3c-level3.json` contains the original hexadecimal registration and assertion
bytes from [W3C WebAuthn Level 3, Recommendation 25 August 2026, §16](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors).
The source HTML SHA-256 is recorded in the file. Inputs were extracted from the
two example blocks in each subsection; no signatures or signed bytes were
regenerated. Expected policy decisions live in `../official_vectors.rs`.

Copyright © 2026 World Wide Web Consortium. Used under the
[W3C Software and Document License](https://www.w3.org/copyright/software-license-2023/).
These are published test credentials, not production credentials.

Supported cases cover ES256 none, packed self, packed certificate, Ed25519
credential keys, FIDO U2F and the 1023-byte credential ID boundary. Other
algorithms, unsupported attestation formats and cross-origin cases are retained
as negative tests. This is vector coverage, not FIDO certification or a claim
that every WebAuthn feature is implemented.
