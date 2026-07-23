//! Abstraction over the elliptic-curve group and hash of a FaFROST ciphersuite.
//!
//! FaFROST is curve-agnostic: the protocol logic only needs a prime-order group,
//! a hash-to-scalar, a nothing-up-my-sleeve second generator, and a signature
//! challenge. This trait captures exactly those scheme-specific points; the rest
//! of the crate is generic over `C: Ciphersuite` and uses ordinary `+`/`*`
//! operators via the [`group`]/[`ff`] traits.
//!
//! Three ciphersuites are provided:
//!   - [`crate::secp256k1::Secp256k1Plain`]  – generic Schnorr over secp256k1.
//!   - [`crate::secp256k1::Secp256k1Bip340`] – Bitcoin/BIP-340 Taproot key spends.
//!   - [`crate::ed25519::Ed25519`]           – RFC 8032 Ed25519; aggregate
//!     signatures verify under a standard EdDSA verifier (incl. ed25519-dalek
//!     `verify_strict`), because FaFROST operates entirely in the prime-order
//!     subgroup.
#![allow(non_snake_case)]

use std::vec::Vec;

use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Incremental hash accumulator that finalises to a group scalar.
///
/// Cloning captures the current state, so a shared prefix can be hashed once and
/// then branched per peer (used by the pairwise blinding computation).
pub trait ScalarHasher: Clone {
    type Scalar;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Self::Scalar;

    fn finish_with(mut self, data: &[u8]) -> Self::Scalar {
        self.update(data);
        self.finish()
    }
}

/// A FaFROST ciphersuite: the group, scalar field, hash, and the scheme-specific
/// challenge / encoding / normalisation rules.
pub trait Ciphersuite: Copy + Clone + 'static {
    /// Scalar field element (mod the prime group order).
    type Scalar: PrimeField + From<u64>;
    /// Prime-order group element.
    type Point: Group<Scalar = Self::Scalar> + GroupEncoding;
    /// Hash accumulator producing a [`Self::Scalar`].
    type Hasher: ScalarHasher<Scalar = Self::Scalar>;

    /// Domain-separation context string for scheme-internal hashes.
    const CONTEXT: &'static str;
    /// Identifier written into serialized key files.
    const SCHEME_ID: &'static str;

    /// Hash byte strings to a scalar (binding factor, blinding, Fiat–Shamir).
    fn hash_to_scalar(parts: &[&[u8]]) -> Self::Scalar {
        let mut h = Self::Hasher::new();
        for p in parts {
            h.update(p);
        }
        h.finish()
    }

    /// Canonical fixed-length encoding of a group element for scheme-internal
    /// hashing (compressed SEC1 for secp256k1, compressed Edwards for ed25519).
    fn point_bytes(p: &Self::Point) -> Vec<u8> {
        p.to_bytes().as_ref().to_vec()
    }

    /// Nothing-up-my-sleeve second generator with unknown discrete log with
    /// respect to the group generator; used for the Pedersen commitments in IA.
    fn pedersen_generator() -> Self::Point;

    /// External signature challenge `c` binding `(vk, R, msg)`.
    ///
    /// This is the only place where the scheme-specific challenge hash and point
    /// encoding live: BIP-340 tagged hash, RFC 8032 `SHA512(R‖A‖M)`, or the
    /// generic domain-separated `SHA256` challenge.
    fn challenge(vk: &Self::Point, r: &Self::Point, msg: &[u8; 32]) -> Self::Scalar;

    /// Key normalisation at key generation. BIP-340 forces the verifying key to
    /// even y (negating the secret if needed); other suites are the identity.
    fn normalize_keygen(sk: Self::Scalar, vk: Self::Point) -> (Self::Scalar, Self::Point) {
        (sk, vk)
    }

    /// Per-signer `(R, nonce)` normalisation. BIP-340 negates both when `R` has
    /// odd y so the aggregate `R` is even; other suites are the identity.
    fn normalize_share_r(r: Self::Point, nonce: Self::Scalar) -> (Self::Point, Self::Scalar) {
        (r, nonce)
    }

    /// Verification-time predicate on the aggregate `R`. BIP-340 rejects odd y.
    fn accept_r(_r: &Self::Point) -> bool {
        true
    }
}
