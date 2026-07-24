# FaFROST benchmark results

Median runtimes per signer, measured with `cargo bench` (Criterion).

| | |
|---|---|
| Machine | Apple M3 Pro (11 cores, 36 GB) |
| OS | macOS 26.5.2 (25F84) |
| Rust | rustc 1.94.0-nightly |
| Date | 2026-07-24 |

`(t, n)` = (threshold, total signers). Commit is independent of the signer set. The IA phases (IA1, IA2, Decide) run only on protocol abort and are off the critical signing path.

## ed25519

| (t, n) | Commit | Sign | Blind | Agg | IA1 | IA2 | Decide |
|:---|---:|---:|---:|---:|---:|---:|---:|
| (4, 256) | 17 µs | 79 µs | 810 ns | 374 ns | 595 µs | 354 ns | 2.81 ms |
| (8, 256) | 17 µs | 105 µs | 2.33 µs | 887 ns | 1.25 ms | 794 ns | 9.32 ms |
| (16, 256) | 17 µs | 145 µs | 4.92 µs | 1.75 µs | 2.33 ms | 1.93 µs | 35.5 ms |
| (32, 256) | 17 µs | 229 µs | 7.81 µs | 3.66 µs | 4.96 ms | 4.33 µs | 131.0 ms |
| (48, 256) | 17 µs | 313 µs | 15 µs | 5.53 µs | 7.07 ms | 6.82 µs | 296.9 ms |
| (64, 256) | 17 µs | 391 µs | 16 µs | 7.20 µs | 9.43 ms | 8.77 µs | 521.8 ms |

## secp256k1 (BIP-340)


| (t, n) | Commit | Sign | Blind | Agg | IA1 | IA2 | Decide |
|:---|---:|---:|---:|---:|---:|---:|---:|
| (4, 256) | 58 µs | 112 µs | 305 ns | 165 ns | 687 µs | 197 ns | 2.90 ms |
| (8, 256) | 58 µs | 132 µs | 728 ns | 381 ns | 1.35 ms | 433 ns | 10.1 ms |
| (16, 256) | 58 µs | 163 µs | 1.50 µs | 807 ns | 2.81 ms | 988 ns | 37.0 ms |
| (32, 256) | 58 µs | 234 µs | 2.91 µs | 1.65 µs | 5.57 ms | 2.48 µs | 144.6 ms |
| (48, 256) | 58 µs | 307 µs | 4.50 µs | 2.52 µs | 8.44 ms | 3.54 µs | 320.1 ms |
| (64, 256) | 58 µs | 378 µs | 5.75 µs | 3.38 µs | 11.0 ms | 5.16 µs | 554.6 ms |



> The `ed25519` backend uses fixed-base (precomputed-table) scalar multiplication
> via `curve25519-dalek`, so its `Commit` and `Sign` rows are faster than
> secp256k1's, which uses the generic group multiplication (`k256` offers no
> precomputed-table path here). The base-multiplication-bound rows are therefore
> not directly comparable across the two curves.