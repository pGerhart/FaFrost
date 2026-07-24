# FaFROST — Fully Adaptive FROST with Identifiable Aborts from AOMDL

[![CI](https://github.com/pGerhart/FaFrost/actions/workflows/ci.yml/badge.svg)](https://github.com/pGerhart/FaFrost/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

A reference implementation of **FaFROST**, a two-round threshold Schnorr signature scheme with **fully adaptive security under AOMDL** and an **identifiable-abort** extension, from the paper:

> **[Fully Adaptive FROST with Identifiable Aborts from AOMDL](https://eprint.iacr.org/2025/1950)**  
> Ruben Baecker, Paul Gerhart, Davide Li Calsi, Luigi Russo, Dominique Schröder, Arkady Yerukhimovich.  
> Cryptology ePrint Archive, Paper 2025/1950.

The crate implements the full signing stack (dealer key generation, two-round signing with pairwise blinding, aggregation, verification, and identifiable aborts), generic over a `Ciphersuite`. Three ciphersuites ship:

| Ciphersuite | Curve | Challenge | Output |
|---|---|---|---|
| `Secp256k1Plain` | secp256k1 | domain-separated `SHA-256` | generic Schnorr |
| `Secp256k1Bip340` | secp256k1 | `BIP0340/challenge` tagged hash | **valid Bitcoin Taproot key-spend signatures** |
| `Ed25519` | edwards25519 | `SHA512(R‖A‖M) mod L` | **valid RFC 8032 EdDSA signatures** |

The same signing stack therefore produces signatures usable **on Bitcoin** (BIP-340) *and* verifiable by **any standard Ed25519 verifier**, including `ed25519-dalek`'s strict `verify_strict` (see [EdDSA interop](#eddsa--ed25519-interop)).

> ⚠️ **Prototype.** This is a research proof-of-concept. It has **not** been security-audited, key generation is an **idealized dealer**, and it **must not** be used in production.

## Repository structure

The protocol logic is generic over the ciphersuite and split across a small set of modules:

| Module | Description |
|---|---|
| `ciphersuite/` | The `Ciphersuite`/`ScalarHasher` traits and the three backends (`secp256k1`, `bip340`, `ed25519`) |
| `keygen.rs` | Idealized dealer-based key generation |
| `sign.rs` | Nonce commitment, signing, and share aggregation |
| `verify.rs` | Signature verification |
| `ia.rs` | Identifiable-abort protocol (IA1, IA2, decide) |
| `wire.rs` | Canonical byte encodings for the wire messages |
| `error.rs` | `Error`/`Result` for untrusted-input paths |
| `utils.rs` | Internal protocol helpers (Lagrange, blinding factors, encodings) |

Ciphersuites live under `src/ciphersuite/` and are re-exported at the crate root (`fafrost::ed25519`, `fafrost::bip340`, ...). Tests are integration tests under `tests/` (`protocol`, `errors`, `vectors`); runnable examples are under `src/bin/`. The abstraction follows the ZF `frost-core` split: every function is generic over `C: Ciphersuite`, using ordinary `+`/`*` via the RustCrypto `group`/`ff` traits that both `k256` and `curve25519-dalek` implement.

## Build and test

```bash
cargo test           # protocol, negative-path, and known-answer tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The crate is `#![forbid(unsafe_code)]`, has an **MSRV of 1.85**, and is checked in CI (fmt, clippy, tests, docs, MSRV build, `cargo audit`) via [`.github/workflows/ci.yml`](.github/workflows/ci.yml). A minimal end-to-end example is in the crate-level documentation (`cargo doc --open`) and is run by `cargo test --doc`.

**Bitcoin demos.** The `generateaddress` and `spenddemo` binaries (see [Demo transaction](#demo-transaction)) depend on the `bitcoin` / `bitcoin_hashes` crates (CC0-1.0), kept out of the default build so the core crate ships under OSI-approved licenses only. Build them behind the `bitcoin-demo` feature (the library, `keygen`, tests, and benches build without it):

```bash
cargo run --features bitcoin-demo --bin spenddemo -- ...
```

## Reproducibility

This repository is meant to reproduce the paper's claims.

- **Interoperability / known-answer vectors.** `cargo test --test vectors` runs a full dealer keygen and `(3,2)` signing session from a **fixed ChaCha20 seed** for each ciphersuite and pins the aggregate signature bytes. A conforming reimplementation that consumes randomness in the same order reproduces these values, and they also guard the wire format. The Ed25519 vector is additionally checked against the independent `ed25519-dalek` verifier.
- **Benchmark numbers.** `cargo bench` reproduces the timing table from the paper. Our measurements, with the machine and toolchain recorded in the header, are in [`benches/bench_results.md`](benches/bench_results.md).

## EdDSA / Ed25519 interop

FaFROST operates entirely in the prime-order subgroup of edwards25519, so an aggregate `(R, s)` under the `Ed25519` ciphersuite is a valid RFC 8032 signature: `[s]B = R + [k]A` with `k = SHA512(R‖A‖M) mod L` and the standard 32-byte encodings. The test `ed25519_interop_with_dalek` verifies a FaFROST threshold signature with the **independent** `ed25519-dalek` implementation on both the standard and strict (`verify_strict`) paths:

```rust
let vk  = VerifyingKey::from_bytes(&fafrost::ed25519::verifying_key_bytes(&pubkeys))?;
let sig = Signature::from_bytes(&fafrost::ed25519::signature_to_bytes(&agg));
assert!(vk.verify_strict(&message, &sig).is_ok());
```

The threshold key and nonces are **not** the deterministic, clamped values of a seed-derived RFC 8032 keypair (they cannot be, being Shamir-shared / jointly random); verification does not depend on that. This is verification-level compatibility, not vector equality with RFC 8032 or RFC 9591.

## Benchmarks

[Criterion](https://github.com/bheisler/criterion.rs) benchmarks cover the main protocol operations, parameterised by ciphersuite and signer set:

| Benchmark | What is measured |
|---|---|
| `commit/<curve>` | Nonce generation (two fixed-base multiplications) |
| `sign/<curve>/<t>/<n>` | Full single-signer signing round |
| `aggregate/<curve>/<t>/<n>` | Share aggregation |
| `blinding_scalar/<curve>/<t>/<n>` | Pairwise blinding computation in isolation |
| `ia1/<curve>/<t>/<n>` | IA round 1: Pedersen commitments + well-formedness Sigma proof |
| `ia2/<curve>/<t>/<n>` | IA round 2: local commitment comparison and key opening |
| `decide/<curve>/<t>/<n>` | Global identification across all signers |

Each run covers both `secp256k1` (BIP-340) and `ed25519` over the configurations `(t, n)` = `(4,256)`, `(8,256)`, `(16,256)`, `(32,256)`, `(48,256)`, `(64,256)`.

```bash
cargo bench
cargo bench -- blinding_scalar   # a single group
```

HTML reports go to `target/criterion/`; pinned results are in [`benches/bench_results.md`](benches/bench_results.md).

## Demo transaction

To exercise FaFROST's Bitcoin compatibility, we used it to construct and broadcast a real Bitcoin testnet Taproot key-spend transaction: the live Bitcoin network accepts a FaFROST threshold signature as an ordinary single-key spend, even though no party ever holds the whole signing key. The full walkthrough (commands, the broadcast transaction, and on-chain screenshots) is in [`bitcoin-demo/README.md`](bitcoin-demo/README.md).
