# FaFROST – Fully Adaptive FROST with Bitcoin Integration

This is a reference implementation of a **fully adaptive secure threshold Schnorr signature scheme**, based on the work:

**Fully Adaptive FROST in the Algebraic Group Model From Falsifiable Assumptions**

In this repository, we provide a full prototype of the construction using an *idealized key generation*.
We implement the full FaFROST signing stack, including signing, verification, and identifiable aborts. All components are accompanied by tests that exercise the protocol and check correctness of the implementation.

In addition, the repository contains code that demonstrates compatibility with **BIP-340 Schnorr signatures**. In particular, we show that FaFROST signatures can be used to produce valid Taproot key-spend signatures without modifying the Bitcoin protocol.

⚠️ **Prototype Warning**
This implementation is **only a proof-of-concept**. It has **not** undergone any security audits, is **not** hardened against side-channel attacks, and **must not** be used in production environments.
Run it only in controlled, research, or testing settings.

# Repository Structure

The protocol logic is split across a small set of modules:

| Module | Description |
|---|---|
| `keygen.rs` | Idealized dealer-based key generation |
| `sign.rs` | Signing, nonce commitment, and share aggregation |
| `verify.rs` | Signature verification |
| `ia.rs` | Identifiable aborts protocol |
| `bip340.rs` | BIP-340 compatibility layer (even-y normalisation, tagged-hash challenge) |
| `utils.rs` | Shared cryptographic primitives (hash-to-scalar, point encoding, Pedersen commitments, Lagrange coefficients) |

Runnable examples live under `src/bin/`: key generation, Taproot address derivation, and a full Bitcoin testnet spend.

# Usage

**Run the tests** (standard and BIP-340 mode):

```
cargo test
cargo test --features bip340
```

The tests cover key generation, signing, verification, and identifiable aborts.

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

```
cargo bench
# or a single group:
cargo bench -- blinding_scalar
```

HTML reports are written to `target/criterion/`.

Our own benchmark results, measured on an Apple M3 Pro MacBook Pro with 36 GB RAM, are available in [`bench_results.txt`](bench_results.txt).

# Demo Transaction

To demonstrate end-to-end compatibility with Bitcoin, we constructed and broadcast a Taproot key-spend transaction using FaFROST. The binaries under `src/bin/` reproduce each step.

**Generate a threshold key** (2-of-3, BIP-340 mode):

```
cargo run --bin keygen --features bip340 -- fafrost-key.yaml 3 2
```

**Derive a Taproot address** from the key file:

```
cargo run --bin generateaddress --features bip340 -- fafrost-key.yaml testnet
```

**Construct and sign a testnet transaction:**

```
cargo run --bin spenddemo --features bip340 -- \
  fafrost-key.yaml \
  19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326 \
  0 \
  143208 \
  800
```

The arguments are: key file, input TXID, vout, input amount (sat), fee (sat). This produces a raw transaction that can be broadcast via any public Bitcoin testnet explorer or a local node.

The transaction spends UTXO `19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326:0` and produces a valid BIP-340 Schnorr signature accepted by the Bitcoin network. The raw transaction is:

```
020000000001012633f8cb440344d14922a699606debc07f785679526d24966635806d149d64190000000000fdffffff02482c020000000000225120aa9768f9873efc61a2d080c70eac65d54a0883124d346fa4e6798063a38b184900000000000000000e6a0c466146524f53542064656d6f0140b817e4a4d9b673e5255ea2b98fe2e711d00c8df5d42951d2ee43eda8803ace234fe2ee793055b08e8de66f28670021c0d339128fd300ce9f1309b216c95d75e100000000
```

The transaction includes an `OP_RETURN` output with the string `"FaFROST demo"` for easy identification:

https://mempool.space/testnet/tx/3b2646d16ee0bd32d765844cac9de7bb5c75c26e4928fc9cd32ab768c2f84a58
