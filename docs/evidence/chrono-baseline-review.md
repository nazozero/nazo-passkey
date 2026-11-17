# Chrono advisory: baseline dependency and migration scope

## Decision

Keep the existing NazoAuth supply-chain failure visible. RUSTSEC-2026-0543 has no patched Chrono version, and removing this dependency safely requires a separate workspace-wide time/API compatibility change. No deny-policy override, advisory ignore, build, or migration was performed for this review. This is a pre-existing dependency exposed by a newly assigned advisory, not a dependency introduced by the passkey PR. It remains a real maintenance-policy blocker; the integration cannot be described as having all CI gates pass.

## Primary advisory evidence

The official RustSec advisory database record is `crates/chrono/RUSTSEC-2026-0543.md`. Its metadata says `date = "2026-09-14"`, `informational = "unmaintained"`, and `patched = []`; its text covers every Chrono version and names Jiff and time as alternatives. The record describes maintenance status, without identifying a specific exploit or CVSS score. The database assigned this ID in commit `233155b4025b854c68a4b199c0e32d7fd53291a2`, dated **2026-11-17 10:08:07 UTC**. Distinguish the advisory's own date from its appearance under this ID.

The upstream maintainer's [issue #1768](https://github.com/chronotope/chrono/issues/1768), opened on 2026-01-22, explains the planned maintenance wind-down of Chrono and chrono-tz and recommends Jiff. A later maintainer comment confirms that chrono-tz time-zone database updates would stop. This review does not infer a newly discovered Passkey exploit from that statement.

## Baseline comparison

Baseline NazoAuth commit: `9560ea04bbc01a2da7b002eeeeb0ebe2e7dffbe9`.

Reviewed current commit: `5031e9b99e2de5f57b12cf04e1cf0919a8ff8312`.

`git show <baseline>:Cargo.lock` and the current lockfile contain the identical Chrono package entry: version **0.4.45**, registry source, checksum `1aa79e62e7697b8e29b513a68abacf485adcd1fe8284a4316c5ae868e6633327`, and identical dependency list. All **17 direct reverse dependencies** retain their names, versions, sources, and checksums. The **22 package names in the transitive reverse closure** are also unchanged. The companion JSON includes both complete lists and the comparison booleans. Both `deny.toml` and `.github/workflows/conformance-security.yml` are byte-for-byte unchanged from the baseline.

Fifteen workspace packages directly depend on Chrono: `nazo-auth`, `nazo-digital-credentials`, `nazo-identity`, `nazo-key-management`, `nazo-oauth-server`, `nazo-oauth-server-object-store`, `nazo-openid4vci`, `nazo-openid4vp`, `nazo-persistence`, `nazo-postgres`, `nazo-resource-server`, `nazo-scim-events`, `nazo-server`, `nazo-valkey`, and `nazoauth`. The other direct reverse dependencies are **diesel 2.3.14** and **mdoc-rs 0.2.0**, with mdoc locked to `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc` in both revisions.

The current workspace's lexical scan finds Chrono/time-type references in **183 files under src (961 matching lines)** and **224 other Rust files, principally tests (1,648 matching lines)**. These are search counts, not an estimate that every line must change; src can also contain embedded tests. The scan expression and categories are recorded in the review process, and the counts appear in the JSON.

## Concrete compatibility boundaries

| Boundary | Source evidence | Required invariant in a future migration |
|---|---|---|
| Public Passkey metadata | `crates/identity/src/ports/passkey.rs`: `last_used_at`, `created_at`, and `updated_at` expose `DateTime<Utc>` | Deliberate public API compatibility or coordinated caller change. |
| PostgreSQL mapping | `crates/persistence-postgres/src/rows/identity.rs` uses those types; `schema.rs` maps them to `Timestamptz`; Cargo enables Diesel's `chrono` feature | Preserve SQL timestamp precision, range, NULL handling, and existing reads. A physical database migration is not inherently required, but equivalence must be tested. |
| Valkey state | `crates/state-store-valkey/src/authorization.rs` sends `to_rfc3339_opts(SecondsFormat::Millis, true)` | Preserve existing RFC3339 bytes/precision, parsing compatibility, and expiration boundaries. |
| Session/MFA | `crates/identity/src/session.rs::step_up` takes a Chrono time and compares its Unix timestamp against authentication metadata | Preserve clock, expiry, authentication-time, and step-up behavior. |
| Audit compatibility | `crates/persistence/src/audit_wire.rs` serializes Chrono timestamps; `audit_chain.rs` hashes `timestamp_micros().to_be_bytes()` | Existing audit hash verification and timestamp wire representation must remain compatible. |
| mdoc API | Locked mdoc `src/model/types.rs::ValidityInfo` exposes Chrono values for signed/valid-from/valid-until/expected-update | Coordinate the dependency and consumer API; preserve date parsing and validity behavior. |

The workspace already uses `time 0.3.55`, so reusing it is a plausible future option. A separate cached mdoc revision `d52cfca16a8d1feccad7c5ddca243ba836d6f045` replaces Chrono with a `Timestamp` type, but NazoAuth does not lock that revision. This review did not validate that upgrade. Removing that single external edge would still leave the fifteen direct workspace dependencies and Diesel's Chrono mapping.

## Why there is no narrow fix here

A Chrono version bump or downgrade cannot remove an all-version advisory. Disabling a local feature or changing only Passkey code cannot remove the other direct users. Adopting Jiff/time entails public type, serialization, PostgreSQL adapter, clock/expiry, and external mdoc compatibility work; a wrapper that still depends on Chrono would not clear the dependency. Merely renaming or relabelling the affected code would not resolve the maintenance problem.

A future migration can preserve stored Passkey credentials and avoid re-registration, but that outcome needs implementation and regression evidence. It should not be assumed from a dependency edit during this protocol/security PR. Leave the existing `cargo deny check advisories bans licenses sources` result failed and document the blocker. The reported PR CI failure comes from the existing workflow; **this review did not rerun the gate against the baseline**. That the same advisory applies to the baseline follows from its identical affected package and policy, not from an invented baseline PASS/FAIL execution.

Evidence: `chrono-baseline-review.json` alongside this document. No repository code, lockfile, policy, or database was changed by this review.
