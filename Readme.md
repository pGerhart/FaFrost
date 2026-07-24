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

To demonstrate end-to-end compatibility with Bitcoin, we constructed and broadcast a Taproot key-spend transaction using FaFROST. The binaries under `src/bin/` reproduce each step and instantiate the `Secp256k1Bip340` ciphersuite.

**Generate a threshold key** (2-of-3):

```
cargo run --bin keygen -- fafrost-key.yaml 3 2
```

**Derive a Taproot address** from the key file:

```
cargo run --bin generateaddress -- fafrost-key.yaml testnet
```

**Construct and sign a testnet transaction:**

```
cargo run --bin spenddemo -- \
  fafrost-key.yaml \
  19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326 \
  0 \
  143208 \
  800
```

The arguments are: key file, input TXID, vout, input amount (sat), fee (sat). This produces a raw transaction that can be broadcast via any public Bitcoin testnet explorer or a local node. `spenddemo` re-verifies its own output with `bip340_verify_bytes` before printing the transaction.

The originally broadcast transaction spent UTXO `19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326:0` and produced a valid BIP-340 Schnorr signature accepted by the Bitcoin network. The raw transaction was:

```
020000000001012633f8cb440344d14922a699606debc07f785679526d24966635806d149d64190000000000fdffffff02482c020000000000225120aa9768f9873efc61a2d080c70eac65d54a0883124d346fa4e6798063a38b184900000000000000000e6a0c466146524f53542064656d6f0140b817e4a4d9b673e5255ea2b98fe2e711d00c8df5d42951d2ee43eda8803ace234fe2ee793055b08e8de66f28670021c0d339128fd300ce9f1309b216c95d75e100000000
```

The transaction includes an `OP_RETURN` output with the string `"FaFROST demo"` for easy identification:

https://mempool.space/testnet/tx/3b2646d16ee0bd32d765844cac9de7bb5c75c26e4928fc9cd32ab768c2f84a58

> Regenerating `fafrost-key.yaml` produces a fresh random key (and hence a different address), so the historical transaction above corresponds to the key that was in the repository at broadcast time.
