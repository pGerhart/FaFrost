//! BIP-340 primitives, used by the `Secp256k1Bip340` ciphersuite.
use k256::elliptic_curve::{
    PrimeField,
    ops::Reduce,
    sec1::{FromSec1Point, Sec1Point, ToSec1Point},
};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

use super::secp256k1::Secp256k1Bip340;
use crate::keygen::PublicKeyPackage;
use crate::sign::Signature;

pub fn has_odd_y(point: &ProjectivePoint) -> bool {
    let enc = point.to_affine().to_sec1_point(true);
    enc.as_bytes()[0] == 0x03
}

pub fn x_only_bytes(point: &ProjectivePoint) -> [u8; 32] {
    let enc = point.to_affine().to_sec1_point(false);
    let mut out = [0u8; 32];
    out.copy_from_slice(&enc.as_bytes()[1..33]);
    out
}

pub fn bip340_challenge_scalar(r_x: &[u8; 32], p_x: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(r_x);
    data[32..64].copy_from_slice(p_x);
    data[64..].copy_from_slice(msg);
    let hash = tagged_hash(b"BIP0340/challenge", &data);
    <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(hash))
}

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    h.finalize().into()
}

fn lift_x(x_bytes: &[u8; 32]) -> Option<ProjectivePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x_bytes);
    let ep = Sec1Point::<Secp256k1>::from_bytes(&compressed).ok()?;
    let affine: Option<AffinePoint> = AffinePoint::from_sec1_point(&ep).into();
    affine.map(ProjectivePoint::from)
}

/// 32-byte x-only public key for use in a `OP_1 <32-byte-key>` (P2TR) output.
pub fn xonly_pubkey(pubkeys: &PublicKeyPackage<Secp256k1Bip340>) -> [u8; 32] {
    x_only_bytes(&pubkeys.verifying_key)
}

/// 64-byte Bitcoin wire format `bytes(R_x) || bytes(s)`.
pub fn signature_to_bytes(sig: &Signature<Secp256k1Bip340>) -> [u8; 64] {
    assert!(!has_odd_y(&sig.R), "BIP340 signature R must have even y");

    let r_x = x_only_bytes(&sig.R);
    let s_bytes: [u8; 32] = sig.z.to_repr().into();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_x);
    out[32..].copy_from_slice(&s_bytes);
    out
}

/// Standalone verification from raw bytes.
pub fn bip340_verify_bytes(sig: &[u8; 64], msg: &[u8; 32], pubkey_x: &[u8; 32]) -> bool {
    let r_x: [u8; 32] = sig[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[32..].try_into().unwrap();

    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes))) else {
        return false;
    };
    let Some(p) = lift_x(pubkey_x) else {
        return false;
    };
    let c = bip340_challenge_scalar(&r_x, pubkey_x, msg);

    let r_computed = ProjectivePoint::GENERATOR * s + p * (-c);

    if r_computed == ProjectivePoint::IDENTITY || has_odd_y(&r_computed) {
        return false;
    }

    x_only_bytes(&r_computed) == r_x
}
