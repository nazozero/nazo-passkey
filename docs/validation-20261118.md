# Continuation record — 2026-11-18

The recovery has produced fresh [current-source CI evidence](validation.md) and a complete [same-host three-way timing/allocation report](performance.md). Historical 8260480 evidence is explicitly separate. Library CI passed all 12 jobs; all measurement modes completed, but the retained tail regressions prevent an all-cases performance-PASS claim.

The measured runtime is `84938674306a2ca0b84319e8ee499b61b8f32e84`; the measured harness and tested library revision is `6b05844a0cc5f7443e0bec378f904b2c3d39f387`. Subsequent documentation publication did not modify source, tests, manifests, locks or harnesses.

Against the calibrated checkpoint, Ed25519 authentication P50 improved 15.76% with the portable build, 14.83% with the AWS-LC feature build, and 9.65% in WASI. Registration improved 11.85%, 11.41%, and 12.25%, respectively. Corresponding P95/P99 also improved. These are same-host median-of-round observations, not a guarantee of deployment-wide improvements.

The native allocation trace records Ed25519 authentication at **3 requests / 204 requested bytes per call**, versus **7 / 396** at the checkpoint and **13 / 781** at the original baseline. Registration is **7 / 415**, versus **8 / 448** and **23 / 1599**. This is not an allocation-free or universally zero-copy API; returned owned values and their required decoding remain represented in the measurements. AWS-LC's C allocations are counted separately from Rust and included in the native totals.

The separate NazoAuth Jiff candidate passed the unchanged dependency-policy command in [run 44136775412](https://github.com/nazozero/NazoAuth/actions/runs/44136775412). That is a dependency-policy result, not a successful workspace build, database test, container security scan or integration approval. Its source migration and semantic verification remain unfinished. No merge or deployment was performed.
