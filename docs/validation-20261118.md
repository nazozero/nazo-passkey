# Continuation validation — 2026-11-18

This record resumes the unfinished protocol/performance review. It does **not**
relabel the earlier checkpoint's tests or timings as validation of newer code.

## Recovered, immutable inputs

| Input | Revision |
| --- | --- |
| Original patched library | `d59b317998e56f4a16a69133d7a854c5c34f795b` |
| Earlier measured checkpoint | `8260480634fac09e1151ca2b1a9eaa1c02af6f67` |
| Latest runtime changes | `84938674306a2ca0b84319e8ee499b61b8f32e84` |
| Performance-driver follow-up | `46bbafa6dbd2b0aa01e184b0928cec9210b04e6e` |
| Independent NazoAuth integration | `652507a91af36284a52b024db5bb0a573ed90967` |
| Separate mdoc/WebAuthn integration | `294baefd71b60b96d91fd0ae4574b51221f2a06e` |

The independent consumer pins runtime revision `8493867`. The combined consumer
still pins an older library revision and still contains Chrono. No pushed Jiff
migration was found during the recovery. A historical statement that an
unpublished workspace passed a check is not a reproducible result for either PR.

## Results actually reproduced during this continuation

On the unmodified `46bbafa6` source snapshot:

```text
python3 -m unittest discover -s perf -p 'test_*.py' -v
Ran 22 tests
OK
```

These are **measurement-contract tests with synthetic output**, not performance
measurements. They exercise schema/iteration/concurrency validation, quantile
ordering, error propagation, scheduling balance, report provenance and rejection
of inherited profiling/selection settings.

## Outstanding gates

- Fresh native, documentation, Clippy, browser-WASM build, WASI execution,
  dependency-audit and fuzz results for the current source.
- Balanced same-host comparisons of original baseline, checkpoint and latest
  runtime; native portable, native AWS-LC and WASI are separate result sets.
- Allocation measurements separate from timed runs, with native-library
  allocations included where applicable.
- Complete native Jiff migration and semantic regressions in the separate
  NazoAuth joint-validation branch, without weakening dependency policy.
- Final reconciliation of the protocol, performance, validation and integration
  documents against the exact tested commits.

Until those gates are recorded, this continuation is **in progress**, not a
production-readiness or merge approval. The old reports remain historical
evidence for their explicitly named revisions.
