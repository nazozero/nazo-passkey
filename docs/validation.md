# Current validation record — 2026-11-18

Runtime revision: **84938674306a2ca0b84319e8ee499b61b8f32e84**. Measured/documented library revision: **6b05844a0cc5f7443e0bec378f904b2c3d39f387**. This record supersedes descriptions of 8260480 as the current production source. The [historical record](validation-checkpoint-8260480.md) remains intact.

## Fresh hosted CI

[Run 44130880569](https://github.com/nazozero/passkey-auth-rs/actions/runs/44130880569) completed successfully: **12 of 12 jobs**. The exact run and job/step payloads are retained in [ci-run.json](evidence/continuation-20261118/ci-run.json) and [ci-jobs.json](evidence/continuation-20261118/ci-jobs.json).

| Job | Result |
|---|---|
| quality | success |
| wasm | success |
| test (ubuntu-24.04-arm, rustcrypto) | success |
| test (macos-15-intel, aws-lc) | success |
| test (windows-2022, rustcrypto) | success |
| test (windows-2022, aws-lc) | success |
| test (ubuntu-24.04-arm, aws-lc) | success |
| test (ubuntu-24.04, aws-lc) | success |
| audit | success |
| test (ubuntu-24.04, rustcrypto) | success |
| fuzz | success |
| test (macos-15-intel, rustcrypto) | success |

This covers the workflow's two backends on Linux x86_64, Linux ARM64, Windows x86_64 and macOS Intel, warnings-denied Clippy/rustdoc and formatting, measurement-driver contracts, browser-target WASM compilation, executable WASI checks, dependency audit and both backend fuzz smoke campaigns. macOS ARM64 and physical-device/browser interoperability are not established by these jobs. A bounded fuzz campaign is not proof that no defect exists.

## Performance and memory

The [new three-way report](performance.md) compares original baseline d59b317, calibrated checkpoint 8260480 and current runtime on one host. All three modes, six balanced rounds, and the separate Rust/native allocation collection completed successfully. The report explicitly retains the original-baseline registration cost and several other tail regressions; successful measurement is not an all-cases performance PASS.

## Protocol and deployment boundary

The [protocol matrix](protocol-compliance.md) describes the supported RP profile, not full implementation of every optional WebAuthn feature. Passing signature verification is not attestation trust. Certificate issuer/root/revocation/MDS policy, unsupported algorithms/formats and unsupported extension enforcement remain outside the stated profile. The caller must still provide correct origin/RP-ID policy, trusted state storage, user binding and atomic credential updates.

The current implementation retains strict Ed25519 acceptance checks while verifying borrowed transcript parts. It does not replace ordinary Ed25519 with Ed25519ph. `legacy_compatibility` remains unsupported. Correct `authors` attribution is retained in Cargo.toml.

## Consumer integration is separate

NazoAuth PR #287 pins runtime 8493867, but its earlier dependency-policy failure is not erased by this library CI. The native Jiff migration is being verified on `nazozero/NazoAuth:validation/jiff-continuation-20261118`, based on the independent mdoc/passkey joint branch. Until that branch passes its own full compile, semantic, database, WASM and security gates, it is not integration-ready. No PR was merged and no deployment was performed by this continuation.
