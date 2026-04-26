# FaFROST – Fully Adaptive FROST with Bitcoin Integration

This is a reference implementation of a **fully adaptive secure threshold Schnorr signature scheme**, based on the work:

**Fully Adaptive FROST in the Algebraic One-More Discrete Logarithm Model**

In this repository, we provide a full prototype of the construction using an *idealized key generation*. 
We implement the full FaFROST signing stack, including signing, verification, and identifiable aborts. All components are accompanied by tests that exercise the protocol and check correctness of the implementation.

In addition, the repository contains code that demonstrates compatibility with **BIP-340 Schnorr signatures**. In particular, we show that FaFROST signatures can be used to produce valid Taproot key-spend signatures without modifying the Bitcoin protocol.

⚠️ **Prototype Warning**  
This implementation is **only a proof-of-concept**. It has **not** undergone any security audits, is **not** hardened against side-channel attacks, and **must not** be used in production environments.  
Run it only in controlled, research, or testing settings.

# Usage and Structure

The repository is organized into a small set of core modules. The main protocol logic lives in `keygen.rs`, `sign.rs`, and `verify.rs`. The file `ia.rs` implements identifiable aborts. The module `bip340.rs` contains the compatibility layer that adapts FaFROST signatures to Bitcoin’s BIP-340 format.

We also provide several small binaries under `src/bin/` that demonstrate how to use the library in practice. In particular, these binaries allow generating keys, deriving Taproot addresses, and constructing and signing Bitcoin transactions.

To get started, it is recommended to first run the tests to understand the behavior of the protocol and ensure that everything is working correctly:

```
cargo test
```

The tests cover key generation, signing, verification, and identifiable aborts. They serve as both correctness checks and executable documentation for the protocol.

Once the tests pass, the binaries can be used to reproduce the Bitcoin integration. First, a threshold key is generated and written to a YAML file:

```
cargo run --bin keygen --features bip340 -- fafrost-key.yaml 3 2
```

From this key file, a Taproot address can be deterministically derived:

```
cargo run --bin generateaddress --features bip340 -- fafrost-key.yaml testnet
```

After funding the address on Bitcoin testnet, a transaction can be constructed and signed using FaFROST:

```
cargo run --bin spenddemo --features bip340 -- \
  fafrost-key.yaml \
  19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326 \
  0 \
  143208 \
  800
```


This produces a raw transaction, which can then be broadcast to the network using a public explorer or a local Bitcoin node.

# Demo Transaction

To demonstrate end-to-end compatibility with Bitcoin, we constructed and broadcast a Taproot key-spend transaction using FaFROST.

The transaction spends the testnet UTXO:

```
19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326
```

and produces a valid BIP-340 Schnorr signature that is accepted by the Bitcoin network.

The raw transaction is:

```
020000000001012633f8cb440344d14922a699606debc07f785679526d24966635806d149d64190000000000fdffffff02482c020000000000225120aa9768f9873efc61a2d080c70eac65d54a0883124d346fa4e6798063a38b184900000000000000000e6a0c466146524f53542064656d6f0140b817e4a4d9b673e5255ea2b98fe2e711d00c8df5d42951d2ee43eda8803ace234fe2ee793055b08e8de66f28670021c0d339128fd300ce9f1309b216c95d75e100000000
```

The transaction can be inspected via the public testnet explorer:

https://mempool.space/testnet

The transaction includes an `OP_RETURN` output containing the string `"FaFROST demo"`, allowing reviewers to easily identify it.

