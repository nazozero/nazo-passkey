> Historical evidence index for the 8260480 checkpoint. See [README.md](README.md) for the current index.

# Verification evidence index

The reviewed library production revision is
`8260480634fac09e1151ca2b1a9eaa1c02af6f67`, tree
`5a36536e1b0a67db1f90e6e870fcff7664a44095`. The consumer revision is
`2d5c335fc6563e874d8626a5067b4fa8df89bacc`. Reports and evidence added after
those revisions do not change the production implementation. Local commit
metadata can differ from GitHub Git Data API commits; the records preserve the
original identities and verify the complete tree or tested working diff.

Read the [validation report](../validation.md) for actual outcomes and limits,
the [protocol matrix](../protocol-compliance.md) for scoped source assessments,
and the [security review](../security-review.md) for decisions and remaining
responsibilities. A successful workflow, a parsed fixture, and a protocol-matrix
PASS describe different evidence and are not interchangeable.

## Library verification

| Record | Contents |
|---|---|
| [Final local gates](packed-final-local-gates.json) | Seven exact commands, exit codes, test counts, source identity and log digests |
| [Local raw logs](library-826-local-logs.tar.gz) / [manifest](library-826-local-logs-manifest.json) | Fourteen original local gate, targeted regression and release-build logs, each verified after archiving |
| [Final implementation CI](ci-final-validation.json) | Tested PR merge, source-tree identity, 12 final job outcomes, actual executed steps, fuzz counts and original log digests |
| [First hosted attempt](ci-validation-8260480-attempt1.json) | Eleven successes and the Windows AWS-LC installation failure caused by HTTP 504 |
| [Hosted raw logs](library-826-ci-logs.tar.gz) / [manifest](library-826-ci-logs-manifest.json) | Thirteen saved logs: eleven successful first-attempt jobs, the failed Windows attempt and its successful retry |
| [Four-lock audit summary](audit-final-summary.json) | Exact RustSec database and main, benchmark, fuzz and backend lock results |

The latest CI API view gives replacement IDs to retained successful jobs. The
final snapshot records that only Windows AWS-LC actually reran. Log digests
refer to the exact archived bytes; the CI JSON states which collections
normalized line endings. Original failed results are not relabeled as passes.

## Consumer integration

The [NazoAuth integration report](../nazo-integration.md) connects JSONB
compatibility, account binding, GETDEL/TTL, counter/metadata CAS, UV/MFA and
required audit behavior to real PostgreSQL/Valkey tests.

| Record | Contents |
|---|---|
| [Final local source proof](nazo-826-source-provenance.json) | Final 38-test Passkey run and exact equality of the tested/published tree |
| [Local command ledger](nazo-integration-results.json) / [test-level summary](nazo-integration-log-summary.json) | Original source revisions, exact commands, completed attempts, individual names, failures and retries |
| [Local archive](nazo-integration-local-logs.tar.gz) / [manifest](nazo-integration-local-manifest.json) | Sixty-seven original logs, reports, source proofs, advisory scans and reproduction scripts; every archived member checked against its digest |
| [Final hosted CI](nazo-final-ci.json) | Current consumer source and complete hosted workflow outcomes, including failures and conditional skips |
| [Hosted raw logs](nazo-2d5-ci-logs.tar.gz) / [manifest](nazo-2d5-ci-logs-manifest.json) | Eighteen saved final-source job logs, including all six test shards, the failed dependency gate, WASM and CodeQL coverage limits |
| [Earlier hosted checkpoint](nazo-ci-c002858-checkpoint.json) | Original c002858a results, retained separately from the final source |
| [Chrono comparison](chrono-baseline-review.md) / [raw data](chrono-baseline-review.json) | Baseline/candidate dependency and policy comparison, with the remaining supply-chain failure and migration implications |

The original local report inside the archive is preserved unchanged. The
presentation copy adds repository-relative links and fresh-workspace
reproduction prerequisites. Its harness expects installed local toolchains
and disposable loopback services; it is not a production setup script.

## Performance

The [performance report](../performance.md) documents the complete measurement
boundary and all regressions. `performance-final-{native-rustcrypto,native-aws-lc,wasi}.json`
contains the final five alternating round pairs, artifact hashes, environment,
commands and per-round statistics. Percentiles in the report are medians of
the per-round quantiles, not pooled quantiles.

- [Final build identities](artifact-builds-final.json) bind release artifacts
  to the final source and build logs.
- [Native allocation records](allocations-native.json) include C allocations;
  [the original traces](native-allocation-traces.tar.gz) were independently
  re-summed and checked against their hashes.
- [Independent numerical QA](performance-final-826-independent-qa.json)
  recomputes tables and cross-checks build, timing and allocation identities.
- Files named `performance-checkpoint-fa0f0c-*` and
  `performance-checkpoint-b3ecfa4-*`, along with their build records, are
  historical observations. They are not extra rounds in the final comparison.
- The standalone backend experiment does not link the library. Its original
  source/lock did not change in the final certificate/order fixes; it is retained
  as explanatory evidence, not a new full-library measurement.

Archive digests establish consistency of these retained files, not an external
certification or proof that untested browsers, hardware, workloads or future
inputs will behave correctly.
