//! Ed25519 ciphersuite (backed by `curve25519-dalek`).
//!
//! FaFROST operates entirely in the prime-order subgroup, so an aggregate
//! signature `(R, s)` produced under this ciphersuite is a valid RFC 8032
//! Ed25519 signature: it verifies under any compliant EdDSA verifier, including
//! `ed25519-dalek`'s strict `verify_strict`.
//!
//! Note that the threshold key and nonces are **not** the deterministic,
//! clamped values of a seed-derived RFC 8032 keypair (they cannot be, being
//! Shamir-shared / jointly random). Verification does not depend on that; it only
//! checks `[s]B = R + [k]A` with `k = SHA512(R‖A‖M) mod L`, which holds.
#![allow(non_snake_case)]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use group::Group;
use sha2::{Digest, Sha512};

use crate::ciphersuite::{Ciphersuite, ScalarHasher};
use crate::keygen::PublicKeyPackage;
use crate::sign::Signature;

/// `SHA-512` accumulator finalising to an edwards25519 scalar via the wide
/// (64-byte) reduction mod L.
#[derive(Clone)]
pub struct Sha512ScalarHasher(Sha512);

impl ScalarHasher for Sha512ScalarHasher {
    type Scalar = Scalar;

    fn new() -> Self {
        Self(Sha512::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> Scalar {
        let wide: [u8; 64] = self.0.finalize().into();
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

/// Nothing-up-my-sleeve Pedersen generator on edwards25519.
///
/// Try-and-increment over a decompressed y-coordinate, then multiply by the
/// cofactor (8) to land in the prime-order subgroup. The discrete log with
/// respect to the basepoint is unknown, as required for a binding commitment.
fn ed25519_pedersen_generator() -> EdwardsPoint {
    for ctr in 0u32.. {
        let mut h = Sha512::new();
        h.update(b"FaFROST/ed25519/SHA512/PedersenH");
        h.update(ctr.to_le_bytes());
        let digest = h.finalize();

        let mut y = [0u8; 32];
        y.copy_from_slice(&digest[..32]);

        if let Some(p) = CompressedEdwardsY(y).decompress() {
            let hp = p.mul_by_cofactor();
            if !bool::from(hp.is_identity()) {
                return hp;
            }
        }
    }
    unreachable!("hash-to-curve must terminate")
}

/// `k = SHA512(R‖A‖M) mod L` — the pure Ed25519 (empty `dom2`) challenge.
fn rfc8032_challenge(r_enc: &[u8; 32], a_enc: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r_enc);
    h.update(a_enc);
    h.update(msg);
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// RFC 8032 Ed25519.
#[derive(Copy, Clone, Debug)]
pub struct Ed25519;

impl Ciphersuite for Ed25519 {
    type Scalar = Scalar;
    type Point = EdwardsPoint;
    type Hasher = Sha512ScalarHasher;

    const CONTEXT: &'static str = "FaFROST/ed25519/SHA512";
    const SCHEME_ID: &'static str = "FaFROST-ed25519";

    fn pedersen_generator() -> EdwardsPoint {
        ed25519_pedersen_generator()
    }

    fn challenge(vk: &EdwardsPoint, r: &EdwardsPoint, msg: &[u8; 32]) -> Scalar {
        // Standard RFC 8032 encoding: compressed Edwards points, no context prefix.
        rfc8032_challenge(&r.compress().to_bytes(), &vk.compress().to_bytes(), msg)
    }
    // normalize_keygen / normalize_share_r / accept_r: identity (defaults). Any
    // subgroup R is fine; its sign bit is captured by the compressed encoding.
}

/// 32-byte Ed25519 public key `A = compress(vk)`, the "verifying key" a standard
/// Ed25519 verifier consumes.
pub fn verifying_key_bytes(pubkeys: &PublicKeyPackage<Ed25519>) -> [u8; 32] {
    pubkeys.verifying_key.compress().to_bytes()
}

/// Serialise an aggregate `Signature` to the 64-byte RFC 8032 wire format:
/// `compress(R) ‖ s` with `s` little-endian.
pub fn signature_to_bytes(sig: &Signature<Ed25519>) -> [u8; 64] {
    let r_enc = sig.R.compress().to_bytes();
    let s_enc = sig.z.to_bytes();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_enc);
    out[32..].copy_from_slice(&s_enc);
    out
}

/// Standalone RFC 8032 verification from raw bytes (cofactorless equation
/// `[s]B = R + [k]A`), the dependency-free counterpart to `bip340_verify_bytes`.
pub fn ed25519_verify_bytes(sig: &[u8; 64], msg: &[u8; 32], vk_bytes: &[u8; 32]) -> bool {
    let r_enc: [u8; 32] = sig[..32].try_into().unwrap();
    let s_enc: [u8; 32] = sig[32..].try_into().unwrap();

    let Some(A) = CompressedEdwardsY(*vk_bytes).decompress() else {
        return false;
    };
    let Some(R) = CompressedEdwardsY(r_enc).decompress() else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_enc)) else {
        return false;
    };

    let k = rfc8032_challenge(&r_enc, vk_bytes, msg);

    EdwardsPoint::generator() * s == R + A * k
}
