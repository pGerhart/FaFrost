use std::collections::BTreeMap;

use std::vec::Vec;

use k256::{
    FieldBytes, ProjectivePoint, Scalar, Secp256k1, U256,
    elliptic_curve::{
        Field,
        group::prime::PrimeCurveAffine,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
};

use rand_core::{CryptoRng, RngCore};

use sha2::{Digest, Sha256};

pub type Identifier = u16;

#[derive(Clone)]
pub struct KeyPackage {
    pub identifier: Identifier,
    pub signing_share: Scalar,
    pub signing_share_blinding: Scalar,
    pub pairwise_keys: BTreeMap<Identifier, [u8; 32]>,
}

#[derive(Clone)]
pub struct PartialVerificationKey {
    pub signing_share_commitment: ProjectivePoint,
    pub pairwise_key_commitments: BTreeMap<Identifier, [u8; 32]>,
}

#[derive(Clone)]
pub struct PublicKeyPackage {
    pub verifying_key: ProjectivePoint,
    pub max_signers: u16,
    pub min_signers: u16,
    pub pedersen_h: ProjectivePoint,
    pub partial_verification_keys: BTreeMap<Identifier, PartialVerificationKey>,
}

pub fn generate_with_dealer<R: RngCore + CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
    assert!(min_signers <= max_signers);

    let sk = Scalar::random(&mut *rng);
    let vk_raw = ProjectivePoint::GENERATOR * sk;

    // BIP-340: the verifying key must have even y — negate sk so g^sk has even y.
    // All shares are evaluations of a polynomial with sk as constant term, so
    // negating sk here automatically normalises every share and commitment.
    #[cfg(feature = "bip340")]
    let (sk, verifying_key) = if crate::bip340::has_odd_y(&vk_raw) {
        (-sk, -vk_raw)
    } else {
        (sk, vk_raw)
    };
    #[cfg(not(feature = "bip340"))]
    let verifying_key = vk_raw;

    let pedersen_h = pedersen_generator();
    let mut coeffs = Vec::new();
    coeffs.push(sk);

    for _ in 1..min_signers {
        coeffs.push(Scalar::random(&mut *rng));
    }

    let mut shares = BTreeMap::new();
    let mut partial_verification_keys = BTreeMap::new();

    for id in 1..=max_signers {
        let x = Scalar::from(id as u64);
        let mut y = Scalar::ZERO;
        let mut pow = Scalar::ONE;

        for a in &coeffs {
            y += *a * pow;
            pow *= x;
        }

        let omega_i = Scalar::random(&mut *rng);
        let vki = pedersen_commit(y, omega_i, pedersen_h);

        shares.insert(
            id,
            KeyPackage {
                identifier: id,
                signing_share: y,
                signing_share_blinding: omega_i,
                pairwise_keys: BTreeMap::new(),
            },
        );

        partial_verification_keys.insert(
            id,
            PartialVerificationKey {
                signing_share_commitment: vki,
                pairwise_key_commitments: BTreeMap::new(),
            },
        );
    }

    for i in 1..=max_signers {
        for j in (i + 1)..=max_signers {
            let mut k_ij = [0u8; 32];
            rng.fill_bytes(&mut k_ij);

            let K_ij = hash_pairwise_key_commitment(&k_ij);

            shares.get_mut(&i).unwrap().pairwise_keys.insert(j, k_ij);
            shares.get_mut(&j).unwrap().pairwise_keys.insert(i, k_ij);

            partial_verification_keys
                .get_mut(&i)
                .unwrap()
                .pairwise_key_commitments
                .insert(j, K_ij);

            partial_verification_keys
                .get_mut(&j)
                .unwrap()
                .pairwise_key_commitments
                .insert(i, K_ij);
        }
    }

    let pubkeys = PublicKeyPackage {
        verifying_key,
        max_signers,
        min_signers,
        pedersen_h,
        partial_verification_keys,
    };

    (shares, pubkeys)
}

pub fn pedersen_commit(value: Scalar, blinding: Scalar, h: ProjectivePoint) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * value + h * blinding
}

pub fn hash_pairwise_key_commitment(k_ij: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"FaFROST/secp256k1/SHA256/Hvk");
    h.update(k_ij);
    h.finalize().into()
}

pub fn scalar_from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(bytes))
}

pub fn point_bytes(point: &ProjectivePoint) -> [u8; 33] {
    let enc = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_bytes());
    out
}

pub fn pedersen_generator() -> ProjectivePoint {
    let h = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[b"FaFROST/secp256k1/SHA256/PedersenH"],
        &[b"FaFROST/secp256k1/SHA256"],
    )
    .expect("hash to curve failed");

    assert!(bool::from(!h.to_affine().is_identity()));

    h
}
