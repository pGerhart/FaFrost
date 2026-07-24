//! Curve and hash abstraction. The protocol needs only a prime-order group, a
//! hash-to-scalar, a second generator with unknown discrete log, and a challenge;
//! the rest of the crate is generic over `C: Ciphersuite`.
#![allow(non_snake_case)]

use std::vec::Vec;

use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Hash accumulator finalising to a scalar. `Clone` captures the current state,
/// so a shared prefix can be hashed once and then branched per peer.
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

pub trait Ciphersuite: Copy + Clone + 'static {
    type Scalar: PrimeField + From<u64>;
    type Point: Group<Scalar = Self::Scalar> + GroupEncoding;
    type Hasher: ScalarHasher<Scalar = Self::Scalar>;

    /// Domain separator for scheme-internal hashes.
    const CONTEXT: &'static str;
    const SCHEME_ID: &'static str;

    fn hash_to_scalar(parts: &[&[u8]]) -> Self::Scalar {
        let mut h = Self::Hasher::new();
        for p in parts {
            h.update(p);
        }
        h.finish()
    }

    fn point_bytes(p: &Self::Point) -> Vec<u8> {
        p.to_bytes().as_ref().to_vec()
    }

    /// Second generator for the IA Pedersen commitments, discrete log unknown.
    fn pedersen_generator() -> Self::Point;

    fn challenge(vk: &Self::Point, r: &Self::Point, msg: &[u8; 32]) -> Self::Scalar;

    /// BIP-340 forces the verifying key to even y, negating the secret if needed.
    fn normalize_keygen(sk: Self::Scalar, vk: Self::Point) -> (Self::Scalar, Self::Point) {
        (sk, vk)
    }

    /// BIP-340 negates both when `R` has odd y, so the aggregate `R` stays even.
    fn normalize_share_r(r: Self::Point, nonce: Self::Scalar) -> (Self::Point, Self::Scalar) {
        (r, nonce)
    }

    fn accept_r(_r: &Self::Point) -> bool {
        true
    }
}
