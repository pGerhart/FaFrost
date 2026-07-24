//! secp256k1 ciphersuites, backed by `k256`.
#![allow(non_snake_case)]

use k256::elliptic_curve::{group::CurveAffine, ops::Reduce};
use k256::hash2curve::GroupDigest;
use k256::{FieldBytes, ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

use crate::bip340;
use crate::ciphersuite::{Ciphersuite, ScalarHasher};

#[derive(Clone)]
pub struct Sha256ScalarHasher(Sha256);

impl ScalarHasher for Sha256ScalarHasher {
    type Scalar = Scalar;

    fn new() -> Self {
        Self(Sha256::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> Scalar {
        let bytes: [u8; 32] = self.0.finalize().into();
        <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(bytes))
    }
}

fn secp_pedersen_generator() -> ProjectivePoint {
    let h = Secp256k1::hash_from_bytes(
        &[b"FaFROST/secp256k1/SHA256/PedersenH"],
        &[b"FaFROST/secp256k1/SHA256"],
    )
    .expect("hash to curve failed");

    assert!(bool::from(!h.to_affine().is_identity()));

    h
}

#[derive(Copy, Clone, Debug)]
pub struct Secp256k1Plain;

impl Ciphersuite for Secp256k1Plain {
    type Scalar = Scalar;
    type Point = ProjectivePoint;
    type Hasher = Sha256ScalarHasher;

    const CONTEXT: &'static str = "FaFROST/secp256k1/SHA256";
    const SCHEME_ID: &'static str = "FaFROST-secp256k1-plain";

    fn pedersen_generator() -> ProjectivePoint {
        secp_pedersen_generator()
    }

    fn challenge(vk: &ProjectivePoint, r: &ProjectivePoint, msg: &[u8; 32]) -> Scalar {
        let vk_bytes = Self::point_bytes(vk);
        let r_bytes = Self::point_bytes(r);
        Self::hash_to_scalar(&[Self::CONTEXT.as_bytes(), b"/Hsig", &vk_bytes, &r_bytes, msg])
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Secp256k1Bip340;

impl Ciphersuite for Secp256k1Bip340 {
    type Scalar = Scalar;
    type Point = ProjectivePoint;
    type Hasher = Sha256ScalarHasher;

    // Internal hashes (binding factor, blinding, IA) share the secp256k1 context;
    // only the external `challenge` and the wire encoding follow BIP-340.
    const CONTEXT: &'static str = "FaFROST/secp256k1/SHA256";
    const SCHEME_ID: &'static str = "FaFROST-secp256k1-bip340";

    fn pedersen_generator() -> ProjectivePoint {
        secp_pedersen_generator()
    }

    fn challenge(vk: &ProjectivePoint, r: &ProjectivePoint, msg: &[u8; 32]) -> Scalar {
        let r_x = bip340::x_only_bytes(r);
        let p_x = bip340::x_only_bytes(vk);
        bip340::bip340_challenge_scalar(&r_x, &p_x, msg)
    }

    fn normalize_keygen(sk: Scalar, vk: ProjectivePoint) -> (Scalar, ProjectivePoint) {
        if bip340::has_odd_y(&vk) {
            (-sk, -vk)
        } else {
            (sk, vk)
        }
    }

    fn normalize_share_r(r: ProjectivePoint, nonce: Scalar) -> (ProjectivePoint, Scalar) {
        if bip340::has_odd_y(&r) {
            (-r, -nonce)
        } else {
            (r, nonce)
        }
    }

    fn accept_r(r: &ProjectivePoint) -> bool {
        !bip340::has_odd_y(r)
    }
}
