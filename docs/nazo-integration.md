# NazoAuth WebAuthn integration evidence

This execution and review record is kept in the verifier repository, outside
the NazoAuth source repository as its AGENTS.md requires. It records failures
as well as successful retries. The [original local evidence archive](evidence/nazo-integration-local-logs.tar.gz)
and [member-by-member digest manifest](evidence/nazo-integration-local-manifest.json)
preserve the source logs, reports, harness and failures.
The command and elapsed time for each row are preserved in
[nazo-integration-results.json](evidence/nazo-integration-results.json); the associated log contains individual test names.
Ledger generated at 2026-11-17T12:17:39.112244+00:00. Only completed
attempts enter the table; an absent group has not been reported as passing.

## Source provenance

- Original NazoAuth source: `9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9`.
- Original verifier: `passkey-auth` 0.1.3, Git revision
  `d59b317998e56f4a16a69133d7a854c5c34f795b` on `nazoauth/patched-rustcrypto`.
- Current NazoAuth checkout HEAD: `2d5c335fc6563e874d8626a5067b4fa8df89bacc`.
- Current uncommitted source diff SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Current verifier pin: `8260480634fac09e1151ca2b1a9eaa1c02af6f67` (`passkey-auth` 0.2.0).
- NazoAuth draft PR: https://github.com/nazozero/NazoAuth/pull/287 .
- Verifier PR (ready for review): https://github.com/nazozero/passkey-auth-rs/pull/1 .
- CLI local commits and GitHub Git Data API commits can have different commit
  metadata; publication verifies exact tree identity.
- [nazo-final-source-provenance.json](evidence/nazo-final-source-provenance.json) verifies that local commit
  `2712efa463afcb949c78ce6a799ec7265ded247f` and published commit
  `c002858a138a134544c1cc64875f7e11a5af2629` have the identical tree
  `57efaec4d1d485679dd5b6608c5223cb27e7ca82`. The SHA-256 of the binary Git diff
  from `500c550200a22cb15b12b593227bbb19f06ecceb` to that published source is
  `3a28a07598d93e1a47e54bbc0761958d3370c67917b13a38cb8f77513e9b3a8a`, exactly the
  worktree diff recorded for successful attempts 15–20. Those attempts tested
  that published checkpoint before its commit metadata was aligned.
- Final 826 integration: local commit
  `c8214e5a32a3f19fb7a7b5cac82a5bb5f4268070` and published commit
  `2d5c335fc6563e874d8626a5067b4fa8df89bacc` have the identical tree
  `f01983bb64f094ec7c88ccda0de7551297be6127`. The binary Git diff from c002 to
  the final published source has SHA-256
  `ef7c92cdc02da82e77b0324179daaa25c5ba2782e8f011c9fa6ca0683dc62e30`, exactly
  matching the working source of the 38-test passkey run in attempt 37.
  [nazo-826-source-provenance.json](evidence/nazo-826-source-provenance.json) records the verified equality. This
  final local result is separate from the earlier c002 checkpoint's 298 test
  executions; hosted final-source workflow status is tracked independently.

## Contract review and implemented changes

Source paths below refer to
[NazoAuth at the reviewed integration checkpoint](https://github.com/nazozero/NazoAuth/tree/2d5c335fc6563e874d8626a5067b4fa8df89bacc).

| Boundary | Preserved or revised behavior | Primary source and regression |
| --- | --- | --- |
| Registration and deletion | Existing full session, CSRF, recent authentication and MFA-sensitive credential-management gates; tenant/user-scoped exclusions; required audit and DB mutation commit together | `crates/authorization-server/src/domain/passkey.rs`; `crates/persistence-postgres/src/repositories/passkeys.rs`; server `profile.rs`; `identity_mutations_and_required_audit_share_the_commit_boundary` |
| Duplicate registration | The verifier's specific `CredentialExcluded` maps to existing `AlreadyRegistered` / HTTP 409. ID mismatch remains HTTP 400 with required rejection evidence. No second credential row is written | `crates/identity/src/passkey.rs::registration_finish`; `registration_finish_returns_conflict_without_second_row_on_duplicate_credential` covers both cases |
| Username-first binding | Account lookup, credential lookup, ceremony tenant, user handle and credential ID remain bound. A ceremony from another tenant service is rejected and consumed | `PasskeyService::login_finish`; `passkey_ceremony_cannot_finish_through_a_different_tenant_service` |
| Replay and expiry | Valkey GETDEL consumes ceremony state before verification; five-minute production TTL, exact existing state keys, corrupt-state consumption and concurrent one-time behavior remain | `crates/state-store-valkey/tests/remaining_contract.rs`; live server login/profile replay tests |
| JSONB compatibility | Full legacy records and material-only JSONB remain readable. Relational ID/counter are authoritative and conflicting embedded copies fail. Missing UV/BE/BS/handle/attestation facts stay unknown | `crates/persistence-postgres/tests/unit/convert/passkey_material.rs::legacy_jsonb_es256_and_ed25519_credentials_authenticate_without_registration` exercises real signatures for both algorithms, old shapes and corrupted signatures |
| UV and MFA | Raw signed UV and prior-enrollment eligibility remain distinct. Only eligible UV adds `passkey_uv` and `mfa`; non-UV and unknown/false UV history retain pending-MFA or independently verified remembered-device behavior | `PasskeyService::create_session`; `passkey_login_reuses_verified_uv_and_preserves_mfa_without_it` covers Required/Preferred and UV true/false |
| Authorizing UV initialization | A signed UV assertion may initialize unknown/false history only with a CSRF-authorized, full, active, same-tenant/user/epoch session, age 0..300 seconds, and interactive OTP or recovery-code MFA evidence. Old passkey UV and remembered-only evidence do not qualify. The initializing assertion itself cannot claim the new UV factor | `authorizes_uv_initialization`; identity unit policy matrix; live `legacy_or_uninitialized_uv_needs_independent_mfa_before_future_eligibility` tests missing/false history, real independent TOTP proof, atomic promotion and subsequent eligibility |
| Counter and metadata CAS | Tenant/user/credential ID, expected counter and prior backup eligibility guard one PostgreSQL update. Counter, signed BE/BS and optional monotonic UV initialization are committed together before session issuance. Zero-only counters remain supported; stale concurrent metadata initialization loses the CAS | `PasskeyRepository::update_authentication`; `passkey_counter_update_is_monotonic_compare_and_set` |
| Origin/configuration | Canonical serialized origins and RP binding are validated at host configuration and mutable facade admission. Default origins exclude issuer paths. HTTP is local-only. Existing controlled switches remain explicit | `crates/server/src/settings/passkey.rs`; `crates/nazoauth/src/config/validation.rs`; settings and facade configuration regressions |
| Boundary allocation | Credential ID validation uses a bounded stack buffer and borrows the validated canonical DB key. Login begin keeps full stored-JSON validation but builds allowCredentials from IDs only; dummy IDs retain the existing distribution | `credential_id_from_response`; `credential_id_is_bounded_before_decode_and_keeps_strict_base64`; login begin privacy/consistency regressions |
| Crypto dependency integration | Native ES256 opts into AWS-LC while Ed25519 keeps strict Dalek validation. Existing AWS-LC 1.19.0 / sys 0.47.0 locks remain; WASM uses RustCrypto fallback. No mdoc or rustls dependency changes | Cargo manifest/lock diff; verifier backend parity evidence and Nazo WASM CI |

### Upgrade boundary

Existing keys need no re-registration or SQL schema migration. This does **not**
reconstruct lost enrollment facts. An MFA-enabled user who has only an old
passkey, no usable OTP or recovery code, and no valid remembered-device evidence
receives a pending-MFA session after a valid signature. That session cannot
automatically finish step-up, enroll another TOTP factor or disable MFA. Normal
MFA enrollment originally confirmed TOTP and generated recovery codes, but it
does not prove their continued possession. Such users need an independent factor
or a separately authorized recovery procedure. This limitation is explicit in
`docs/features/passkeys.md`; historical UV is never invented for compatibility.

Previously issued sessions retain their existing TTL and recent-management
window. Their existing `passkey_uv` AMR alone cannot initialize an old credential.
There is no blanket session revocation or retrospective proof of old enrollment.

Attestation evidence remains explicitly none, self, untrusted certificate or
unknown. Validating an attestation signature is not a trusted-manufacturer claim.
The profile does not add PRF/credProtect-based authorization or discoverable
username-free login.

## Execution environment and reproducibility

Rust 1.100.0, isolated `RUSTUP_HOME=/workspace/scratch/f7903e352d2d/rustup`, Cargo jobs 1, development
debug info disabled, incremental compilation disabled, `CI=true`, test threads 1.
The task built PostgreSQL 18.6 and Valkey 9.1.2 from official source for loopback
test use, with no external database. `nazo_integration_services.py` starts both
services and Cargo inside the same execution namespace, gives each test explicit
backend URLs, checks that required test filters execute positive test counts,
retains immutable logs, and stops the services in its cleanup path. The added TOTP
tests use separately owned/migrated databases and the real writer activation
guard; the guard was not weakened to make fixtures pass.

Run selected groups with:

```sh
# On an initially empty disposable database, apply the main schema first.
python3 nazo_integration_services.py postgres-migrations
python3 nazo_integration_services.py server-passkey server-mfa server-settings \
  server-all-targets-build native-http-adapter native-direct-tls
python3 nazo_integration_services.py identity-unit identity-authentication-contracts \
  postgres-passkey-jsonb postgres-passkey-cas postgres-mfa postgres-totp \
  valkey-authentication-state valkey-login-session valkey-mfa
```

The JSON command list is the authority for exact package/test filters. A group
count is a count of executed test functions; groups may overlap, so sums across
groups are not advertised as unique tests. The first seven execution records use
an earlier provisional 0.2 RustCrypto integration; later records state the exact
Git pin when available. Compile-only rows execute no test bodies.

## Preserved execution ledger

| Attempt | Group | Result (exit) | Passed/failed/ignored | Verifier revision | Raw log |
| --- | --- | --- | --- | --- | --- |
| 1 | `identity-unit` | PASS (0) | 63/0/0 | `provisional` | `nazo-identity-unit-01.log` |
| 2 | `postgres-passkey-jsonb` | PASS (0) | 5/0/0 | `provisional` | `nazo-postgres-passkey-jsonb-02.log` |
| 3 | `postgres-migrations` | PASS (0) | 1/0/0 | `provisional` | `nazo-postgres-migrations-03.log` |
| 4 | `identity-authentication-contracts` | PASS (0) | 23/0/0 | `provisional` | `nazo-identity-authentication-contracts-04.log` |
| 5 | `postgres-passkey-cas` | PASS (0) | 2/0/0 | `provisional` | `nazo-postgres-passkey-cas-05.log` |
| 6 | `postgres-mfa` | PASS (0) | 14/0/0 | `provisional` | `nazo-postgres-mfa-06.log` |
| 7 | `postgres-totp` | PASS (0) | 5/0/0 | `provisional` | `nazo-postgres-totp-07.log` |
| 8 | `postgres-passkey-audit` | PASS (0) | 1/0/0 | `fa0f0c869b88` | `nazo-postgres-passkey-audit-08.log` |
| 9 | `valkey-passkey` | PASS (0) | 4/0/0 | `fa0f0c869b88` | `nazo-valkey-passkey-09.log` |
| 10 | `valkey-session` | PASS (0) | 6/0/0 | `fa0f0c869b88` | `nazo-valkey-session-10.log` |
| 11 | `http-passkey` | PASS (0) | 10/0/0 | `fa0f0c869b88` | `nazo-http-passkey-11.log` |
| 12 | `http-mfa` | PASS (0) | 9/0/0 | `fa0f0c869b88` | `nazo-http-mfa-12.log` |
| 13 | `http-configuration` | PASS (0) | 23/0/0 | `fa0f0c869b88` | `nazo-http-configuration-13.log` |
| 14 | `server-passkey` | FAIL (101) | 35/2/0 | `fa0f0c869b88` | `nazo-server-passkey-14.log` |
| 15 | `server-passkey` | PASS (0) | 37/0/0 | `b3ecfa40c8f6` | `nazo-server-passkey-15.log` |
| 16 | `server-mfa` | PASS (0) | 11/0/0 | `b3ecfa40c8f6` | `nazo-server-mfa-16.log` |
| 17 | `server-settings` | PASS (0) | 70/0/0 | `b3ecfa40c8f6` | `nazo-server-settings-17.log` |
| 18 | `server-all-targets-build` | PASS (0) | compile only | `b3ecfa40c8f6` | `nazo-server-all-targets-build-18.log` |
| 19 | `native-http-adapter` | PASS (0) | 9/0/0 | `b3ecfa40c8f6` | `nazo-native-http-adapter-19.log` |
| 20 | `native-direct-tls` | PASS (0) | 1/0/0 | `b3ecfa40c8f6` | `nazo-native-direct-tls-20.log` |
| 21 | `identity-unit` | PASS (0) | 63/0/0 | `b3ecfa40c8f6` | `nazo-identity-unit-21.log` |
| 22 | `identity-authentication-contracts` | PASS (0) | 23/0/0 | `b3ecfa40c8f6` | `nazo-identity-authentication-contracts-22.log` |
| 23 | `postgres-passkey-jsonb` | PASS (0) | 5/0/0 | `b3ecfa40c8f6` | `nazo-postgres-passkey-jsonb-23.log` |
| 24 | `postgres-migrations` | PASS (0) | 1/0/0 | `b3ecfa40c8f6` | `nazo-postgres-migrations-24.log` |
| 25 | `postgres-passkey-cas` | PASS (0) | 2/0/0 | `b3ecfa40c8f6` | `nazo-postgres-passkey-cas-25.log` |
| 26 | `postgres-mfa` | PASS (0) | 14/0/0 | `b3ecfa40c8f6` | `nazo-postgres-mfa-26.log` |
| 27 | `postgres-totp` | PASS (0) | 5/0/0 | `b3ecfa40c8f6` | `nazo-postgres-totp-27.log` |
| 28 | `postgres-passkey-audit` | PASS (0) | 1/0/0 | `b3ecfa40c8f6` | `nazo-postgres-passkey-audit-28.log` |
| 29 | `valkey-passkey` | PASS (0) | 4/0/0 | `b3ecfa40c8f6` | `nazo-valkey-passkey-29.log` |
| 30 | `valkey-session` | PASS (0) | 6/0/0 | `b3ecfa40c8f6` | `nazo-valkey-session-30.log` |
| 31 | `valkey-authentication-state` | PASS (0) | 1/0/0 | `b3ecfa40c8f6` | `nazo-valkey-authentication-state-31.log` |
| 32 | `valkey-login-session` | PASS (0) | 2/0/0 | `b3ecfa40c8f6` | `nazo-valkey-login-session-32.log` |
| 33 | `valkey-mfa` | PASS (0) | 1/0/0 | `b3ecfa40c8f6` | `nazo-valkey-mfa-33.log` |
| 34 | `http-passkey` | PASS (0) | 10/0/0 | `b3ecfa40c8f6` | `nazo-http-passkey-34.log` |
| 35 | `http-mfa` | PASS (0) | 9/0/0 | `b3ecfa40c8f6` | `nazo-http-mfa-35.log` |
| 36 | `http-configuration` | PASS (0) | 23/0/0 | `b3ecfa40c8f6` | `nazo-http-configuration-36.log` |
| 37 | `server-passkey` | PASS (0) | 38/0/0 | `8260480634fa` | `nazo-server-passkey-37.log` |

## Failures, fixes and remaining limits

- Early local Diesel compilation was killed while duplicate toolchain artifacts
  occupied the shared tmpfs. Moving the inactive toolchain off tmpfs resolved the
  resource limit; the failed logs were retained and subsequent compilation ran.
- Initial remote code-quality checks found incorrect assumptions that the public
  `AuthenticationResponse` DTO implemented Clone, then Serialize. The test now
  explicitly copies its public owned fields, preserving the same signed bytes.
  It does not expand the library API merely to support a replay fixture.
- The first live server run executed 37 test functions: 35 passed and 2 failed.
  One fixture used an inactive TOTP writer in a reused DB; the repair activates
  the real writer and isolates the fixture DB. The second failure exposed a real
  compatibility regression: excluded credential IDs and mismatched IDs had been
  conflated into one library error, changing duplicate registration from 409 to
  400. The library now distinguishes them and Nazo maps only exclusion to 409.
  The b3-pinned rerun passed all 37, including both repairs, with zero ignored.
  The same source also passed all 11 server MFA tests, all 70 settings tests,
  all-target/all-feature compilation, all 9 native HTTP adapter tests, and the
  real HTTPS/mTLS transport regression. The ledger retains the failed attempt.
- Subsequent review found an additional intersection that the c002/b3 passing
  checkpoint did not cover: the library returned exclusion before validating the
  attestation statement, so a matching excluded ID with a bad packed signature
  could return HTTP 409 and omit the baseline required `InvalidAttestation`
  rejection fact. The corrected library order must validate the statement before
  reporting exclusion, while preserving early outer/attested ID mismatch.
  `excluded_credential_with_invalid_packed_signature_is_rejected_and_audited`
  is the new Nazo regression: real packed Ed25519 registration, valid duplicate,
  corrupted real signature, consumed ceremony replay, one persisted credential,
  and one actual tenant-bound required rejection audit row. The complete local
  server passkey suite passed **38/0/0** against verifier revision
  `8260480634fac09e1151ca2b1a9eaa1c02af6f67`, including this new test (attempt 37).
  Earlier c002/b3 counts remain attributed to that checkpoint; final hosted
  workspace CI is not inferred from the earlier run.
- The b3-pinned `cargo audit --json` exited 0 with **zero vulnerabilities and one
  warning**, existing chrono 0.4.45 / RUSTSEC-2026-0543 (unmaintained). RustSec
  database: 1,527 advisories at
  `233155b4025b854c68a4b199c0e32d7fd53291a2`. This does not mean cargo-deny passes:
  the repository's supply-chain gate treats that warning as an error and remains
  **FAIL**. No ignore or weakened policy was added.
- Three actual actix-http 3.21.0 advisories (RUSTSEC-2026-0552/0553/0554) were fixed
  with a precise update to 3.21.3 plus the existing native dependency guard. The
  repository's already-documented reviewed urgent-fix exception was applied to
  this update alone; its global three-day publication-age policy remains.
- [Chrono comparison](evidence/chrono-baseline-review.md) and [raw comparison](evidence/chrono-baseline-review.json) independently confirm that the
  full chrono package entry, 17 direct reverse dependencies, 22 transitive reverse
  dependency names and supply-chain policy/workflow are identical to baseline.
  Baseline cargo-deny was not run; this is static baseline evidence. A time-library
  migration spans public DateTime APIs, Diesel, the pinned mdoc dependency, precise
  Valkey timestamp serialization and audit hash timestamps; it is not hidden
  inside this passkey patch.
- Existing username-first credential-ID hints are not a general account
  enumeration guarantee. Per-account credential-count quotas are still absent.
  These existing boundaries are not described as newly solved.
- Remote native/portable CI outcomes must be cited with their actual head SHA;
  an earlier passing run is not relabeled as evidence for a later source tree.
  The final GitHub job/status summary is recorded separately below.
- At the c002 checkpoint, the conformance workflow's `real-http-security-matrix`
  was **SKIPPED** because it depends on the failed supply-chain gate. The final
  2d5 workflow status must be checked separately. Its actual commands are
  the RFC 9967 SCIM black-box script, the HTTP health/discovery/client-credentials/
  introspection load script (with admin TOTP enrollment as setup), and an injected
  Valkey outage check on health/token responses. It contains no passkey-specific
  black-box script. The local integration suites cover relevant MFA/session
  contracts separately; they do not substitute for that Docker black-box result.
  No Docker CLI is available locally, and the load seed's exact Docker-target
  guard and the CI dependency policy were left intact. The container image scan,
  full black-box load/SCIM/outage job, and unrelated full OAuth/OID4VP scenarios
  are not reported as locally executed.

## Additional retained checks

`nazo-b3-pin-fetch-locked.log`, `nazo-b3-fmt-check.log`,
`nazo-b3-static-contracts.log`, `nazo-b3-cargo-audit.json` and `.log` record actual
b3-pinned commands. `nazo-826-pin-fetch-locked.log`, `nazo-826-fmt-check.log` and
`nazo-826-static-contracts.log` also completed successfully before the final
38-test live passkey run. [nazo-826-source-provenance.json](evidence/nazo-826-source-provenance.json) records the
final test diff, local commit and identical published tree. The pre-update
vulnerable audit, post-Actix audit, original test failures and all subsequent
attempts remain separately available.


## Final hosted outcomes for 2d5c335

The final published integration source is
`2d5c335fc6563e874d8626a5067b4fa8df89bacc`, with verifier revision
`8260480634fac09e1151ca2b1a9eaa1c02af6f67`. Actions tested synthetic merge
`ea551e890c6cc74f029a776c1b05cf33082eb6ac`. All eight workflows reached a
terminal outcome: seven succeeded and the unchanged dependency-security gate
failed. This is **not** an all-green application CI result.

| Workflow | Observed result |
|---|---|
| [Code quality](https://github.com/nazozero/NazoAuth/actions/runs/44081397484) | PASS: six shards each execute 660 tests, **3,960 native tests total**, plus six doctests; formatting, Clippy, build/archive and aggregate gate pass. The final required-audit regression actually executes and passes. |
| [WASM portability](https://github.com/nazozero/NazoAuth/actions/runs/44081397488) | PASS: **71 Rust WASM tests** and 47 Python boundary tests; the log identifies the exact 8260480 verifier pin. |
| [Operator fuzz](https://github.com/nazozero/NazoAuth/actions/runs/44081397683) | PASS: **439,576 executions in 61 seconds** of the operator JWS parser. This is separate from the verifier's WebAuthn fuzz harness. |
| [CodeQL](https://github.com/nazozero/NazoAuth/actions/runs/44081397736) | Analysis/SARIF upload succeeds. One file has a macro-expansion extraction error while 1,193 have no extraction error; an init/analyze action-version warning remains. Success is not a zero-alert or complete-coverage claim. |
| [Conformance/security](https://github.com/nazozero/NazoAuth/actions/runs/44081397523) | FAIL: unchanged Chrono RUSTSEC-2026-0543 is an error in cargo-deny. Bans/licenses/sources and the separate source-policy gate pass. The dependent real HTTP container matrix is SKIPPED. |
| Dependency review / specification freshness / performance images | Workflow success does not mean every optional step ran: conditional Rust advisory, online specification freshness and container-image build steps are skipped as recorded in the final CI JSON. |

The complete [final CI record](evidence/nazo-final-ci.json) preserves job IDs,
commands, coverage limitations and skips. [All eighteen retained raw job logs](evidence/nazo-2d5-ci-logs.tar.gz)
are accompanied by a [verified digest manifest](evidence/nazo-2d5-ci-logs-manifest.json).
Shard filtering and the five existing ignored catalogue entries are not
reported as passing test executions. The six repeated migration setup runs
are also kept separate from the 3,960 distinct shard results.

## Reading and reproducing the retained evidence

The [test log summary](evidence/nazo-integration-log-summary.json) contains exact
commands, test names and original log SHA-256 values. Extract the local archive
to recover the original relative paths. The [harness](evidence/nazo_integration_services.py)
is the original execution harness, not a dependency installer: it expects a
sibling `NazoAuth` checkout, Rust 1.100.0 in `rustup`, PostgreSQL 18.6 binaries in
`postgresql-runtime/bin`, and Valkey 9.1.2 binaries in `valkey-build/src`, relative
to its own directory. Its PATH also names the original Cargo installation.
Prepare those prerequisites in a disposable local test workspace, place the
harness at that workspace root, and use the recorded group commands. The
first migration group is required for a new empty test database: the harness
creates databases but does not itself create the main application tables.
Run PostgreSQL `initdb` as a non-root user and ensure local ports 55432 and
56379 are unused. Native compilation also needs the libpq development files,
pkg-config and C build tools. The recorded PostgreSQL build used
`--prefix=<workspace>/postgresql-runtime --without-readline --without-icu`;
the Valkey source build places its executables under `valkey-build/src`.
The loopback-only fixtures and all-zero test signing key must never be reused as
production configuration. Neither database contents nor production credentials
are part of the archive.

For the current hosted source and workflow outcomes, see
[the validation report](validation.md) and
[the final NazoAuth CI record](evidence/nazo-final-ci.json). The local c002858a
checkpoint, the final 38-test local group, and the final hosted workspace run
have different scopes and must not be summed into a count of unique tests.
