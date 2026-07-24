# FaFROST – Fully Adaptive FROST (Bitcoin & EdDSA)

This is a reference implementation of a **fully adaptive secure threshold Schnorr signature scheme**, based on the work:

**Fully Adaptive FROST in the Algebraic Group Model From Falsifiable Assumptions**

In this repository, we provide a full prototype of the construction using an *idealized key generation*.
We implement the full FaFROST signing stack, including signing, verification, and identifiable aborts. All components are accompanied by tests that exercise the protocol and check correctness of the implementation.

The scheme is curve-agnostic and ships with **three ciphersuites**, selected by a type parameter `C: Ciphersuite`:

| Ciphersuite | Curve | Challenge | Output |
|---|---|---|---|
| `Secp256k1Plain` | secp256k1 | domain-separated `SHA-256` | generic Schnorr |
| `Secp256k1Bip340` | secp256k1 | `BIP0340/challenge` tagged hash | **valid Bitcoin Taproot key-spend signatures** |
| `Ed25519` | edwards25519 | `SHA512(R‖A‖M) mod L` | **valid RFC 8032 EdDSA signatures** |

The same threshold signing stack therefore produces signatures usable **on Bitcoin** (BIP-340) *and* verifiable by **any standard Ed25519 verifier** — including `ed25519-dalek`'s strict `verify_strict` (see [EdDSA interop](#eddsa--ed25519-interop)).

⚠️ **Prototype Warning**
This implementation is **only a proof-of-concept**. It has **not** undergone any security audits, is **not** hardened against side-channel attacks, and **must not** be used in production environments.
Run it only in controlled, research, or testing settings.

# Repository Structure

The protocol logic is generic over the ciphersuite and split across a small set of modules:

| Module | Description |
|---|---|
| `ciphersuite/mod.rs` | The `Ciphersuite`/`ScalarHasher` traits: group, scalar, hash, challenge, and normalisation hooks |
| `ciphersuite/secp256k1.rs` | secp256k1 backends: `Secp256k1Plain` and `Secp256k1Bip340` |
| `ciphersuite/ed25519.rs` | edwards25519 backend `Ed25519`, plus a standalone RFC 8032 verifier and wire serialisers |
| `ciphersuite/bip340.rs` | BIP-340 low-level primitives (even-y normalisation, x-only encoding, tagged-hash challenge) |
| `keygen.rs` | Idealized dealer-based key generation |
| `sign.rs` | Signing, nonce commitment, and share aggregation |
| `verify.rs` | Signature verification |
| `ia.rs` | Identifiable aborts protocol |
| `utils.rs` | Shared cryptographic primitives (Pedersen commitments, Lagrange coefficients, encodings) |

The ciphersuites live under `src/ciphersuite/` and are re-exported at the crate root, so their public paths (`fafrost::ed25519`, `fafrost::bip340`, ...) are unchanged.

Runnable examples live under `src/bin/`: key generation, Taproot address derivation, and a full Bitcoin testnet spend. The Bitcoin binaries instantiate the `Secp256k1Bip340` ciphersuite and require the `bitcoin-demo` feature (see below); key generation builds by default.

The abstraction follows the standard FROST design (cf. the ZF `frost-core` split): every function is generic over `C: Ciphersuite`, using ordinary `+`/`*` operators via the RustCrypto `group`/`ff` traits, which both `k256` and `curve25519-dalek` implement. Only the scheme-specific points — challenge hash, wire encoding, even-y normalisation, and the Pedersen generator — are ciphersuite methods.

# Usage

**Run the tests** (all three ciphersuites in one run):

```
cargo test
```

The tests cover key generation, signing, verification, and identifiable aborts for `Secp256k1Plain`, `Secp256k1Bip340`, and `Ed25519`, plus the Ed25519 interop test.

> Note: the mode is now chosen by the ciphersuite **type**, not a Cargo feature. The old `--features bip340` flag has been removed.

**Bitcoin demos.** The `generateaddress` and `spenddemo` binaries depend on the `bitcoin` and `bitcoin_hashes` crates (both CC0-1.0), which are kept out of the default build so the core crate ships under OSI-approved licenses only. Build them behind the `bitcoin-demo` feature:

```
cargo run --features bitcoin-demo --bin generateaddress
cargo run --features bitcoin-demo --bin spenddemo
```

The library, the `keygen` binary, the tests, and the benchmarks build without the feature.

# EdDSA / Ed25519 interop

FaFROST operates entirely in the prime-order subgroup of edwards25519, so an aggregate signature `(R, s)` under the `Ed25519` ciphersuite is a valid RFC 8032 Ed25519 signature: `[s]B = R + [k]A` with `k = SHA512(R‖A‖M) mod L` and the standard 32-byte little-endian encodings.

The test `ed25519_interop_with_dalek` proves this by verifying a FaFROST threshold signature with the **independent** `ed25519-dalek` implementation, on both the standard and the strict (`verify_strict`) paths:

```rust
let vk  = VerifyingKey::from_bytes(&fafrost::ed25519::verifying_key_bytes(&pubkeys))?;
let sig = Signature::from_bytes(&fafrost::ed25519::signature_to_bytes(&agg));
assert!(vk.verify_strict(&message, &sig).is_ok());
```

Caveat (as with any FROST-Ed25519): the threshold key and nonces are **not** the deterministic, clamped values of a seed-derived RFC 8032 keypair — they cannot be, being Shamir-shared / jointly random. Verification does not depend on that; it only checks the equation above, which holds. A dependency-free `fafrost::ed25519::ed25519_verify_bytes` mirrors `bip340_verify_bytes`.

# Benchmarks

The repository includes [Criterion](https://github.com/bheisler/criterion.rs) benchmarks covering the main protocol operations:

| Benchmark | What is measured |
|---|---|
| `commit` | Nonce generation (two scalar multiplications) |
| `sign/full` | Full single-signer signing round |
| `aggregate/full` | Share aggregation |
| `blinding_scalar/blinding` | Pairwise blinding computation in isolation |
| `ia1` | IA round 1: Pedersen commitments + well-formedness Sigma proof (per signer) |
| `ia2` | IA round 2: local commitment comparison and pairwise-key opening decision (per signer) |
| `decide` | Global identification: proof verification and key-opening checks across all signers |

All parameterised benchmarks run over six signer-set configurations (min-signers/max-signers): **4/32**, **8/32**, **16/32**, **32/64**, **48/64**, **64/128**.

The benchmark ciphersuite is set by the `type C` alias at the top of `benches/fafrost.rs` (default `Secp256k1Plain`); switch it to `Secp256k1Bip340` or `Ed25519` to measure the other modes.

```
cargo bench
# or a single group:
cargo bench -- blinding_scalar
```

HTML reports are written to `target/criterion/`.

Our own benchmark results, measured on an Apple M3 Pro MacBook Pro with 36 GB RAM, are available in [`bench_results.txt`](bench_results.txt).

# Demo Transaction

FaFROST was used to construct and broadcast a real Bitcoin testnet Taproot key-spend transaction, end to end. The full walkthrough — commands, the broadcast transaction, and on-chain screenshots — is in [`bitcoin-demo/README.md`](bitcoin-demo/README.md). The Bitcoin binaries build behind the `bitcoin-demo` feature.
