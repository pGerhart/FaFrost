use std::collections::BTreeMap;
use std::vec::Vec;

use k256::elliptic_curve::{Field, ops::Reduce, sec1::ToEncodedPoint};
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::keygen::{Identifier, KeyPackage, PartialVerificationKey, PublicKeyPackage};

#[derive(Clone)]
pub struct SigningNonces {
    pub d: Scalar,
    pub e: Scalar,
}

#[derive(Clone)]
pub struct SigningCommitments {
    pub D: ProjectivePoint,
    pub E: ProjectivePoint,
}

#[derive(Clone)]
pub struct SigningPackage {
    pub message: [u8; 32],
    pub signing_commitments: BTreeMap<Identifier, SigningCommitments>,
    pub partial_verification_keys: BTreeMap<Identifier, PartialVerificationKey>,
}

#[derive(Clone)]
pub struct SignatureShare {
    pub identifier: Identifier,
    pub R: ProjectivePoint,
    pub z: Scalar,
}

#[derive(Clone)]
pub struct Signature {
    pub R: ProjectivePoint,
    pub z: Scalar,
}

pub fn commit<R: RngCore + CryptoRng>(rng: &mut R) -> (SigningNonces, SigningCommitments) {
    let d = Scalar::random(&mut *rng);
    let e = Scalar::random(rng);

    let D = ProjectivePoint::GENERATOR * d;
    let E = ProjectivePoint::GENERATOR * e;

    (SigningNonces { d, e }, SigningCommitments { D, E })
}

pub fn sign(
    signing_package: &SigningPackage,
    signer_nonces: &SigningNonces,
    key_package: &KeyPackage,
    pubkeys: &PublicKeyPackage,
) -> SignatureShare {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    assert!(
        signing_package
            .signing_commitments
            .contains_key(&key_package.identifier)
    );

    assert!(
        signing_package
            .partial_verification_keys
            .contains_key(&key_package.identifier)
    );

    let commitments_bytes = encode_commitments(&signing_package.signing_commitments);

    let signer_commitment = signing_package
        .signing_commitments
        .get(&key_package.identifier)
        .unwrap();

    assert_eq!(
        signer_commitment.D,
        ProjectivePoint::GENERATOR * signer_nonces.d
    );
    assert_eq!(
        signer_commitment.E,
        ProjectivePoint::GENERATOR * signer_nonces.e
    );

    let mut D = ProjectivePoint::IDENTITY;
    let mut E = ProjectivePoint::IDENTITY;

    for c in signing_package.signing_commitments.values() {
        D += c.D;
        E += c.E;
    }

    let vk_bytes = point_bytes(&pubkeys.verifying_key);

    let b = scalar_from_hash(&[
        b"FaFROST/secp256k1/SHA256/Hnon",
        &vk_bytes,
        &encode_signer_set(&ids),
        &signing_package.message,
        &commitments_bytes,
    ]);

    let R = D + E * b;

    #[cfg(feature = "bip340")]
    let r_is_odd = crate::bip340::has_odd_y(&R);

    let c = {
        #[cfg(feature = "bip340")]
        {
            let r_x = crate::bip340::x_only_bytes(&R);
            let p_x = crate::bip340::x_only_bytes(&pubkeys.verifying_key);
            crate::bip340::bip340_challenge_scalar(&r_x, &p_x, &signing_package.message)
        }
        #[cfg(not(feature = "bip340"))]
        {
            let R_bytes = point_bytes(&R);
            scalar_from_hash(&[
                &vk_bytes,
                &R_bytes,
                &signing_package.message,
            ])
        }
    };

    let lambda_i = lagrange(key_package.identifier, &ids);

    // This is extra compared to non-adaptive Frost: Compute the blinding values
    let mut blind = Scalar::ZERO;

    for j in &ids {
        if *j == key_package.identifier {
            continue;
        }

        let k_ij = key_package
            .pairwise_keys
            .get(j)
            .expect("missing pairwise key");

        let B_ij = scalar_from_hash(&[
            b"FaFROST/secp256k1/SHA256/Hs",
            k_ij,
            &commitments_bytes,
            &signing_package.message,
            &encode_signer_set(&ids),
        ]);

        blind += B_ij * delta(key_package.identifier, *j);
    }

    #[cfg(feature = "bip340")]
    let nonce_contrib = if r_is_odd {
        -(signer_nonces.d + b * signer_nonces.e)
    } else {
        signer_nonces.d + b * signer_nonces.e
    };
    #[cfg(not(feature = "bip340"))]
    let nonce_contrib = signer_nonces.d + b * signer_nonces.e;

    let z = c * lambda_i * key_package.signing_share + nonce_contrib + blind;

    #[cfg(feature = "bip340")]
    let sig_r = if r_is_odd { -R } else { R };
    #[cfg(not(feature = "bip340"))]
    let sig_r = R;

    SignatureShare {
        identifier: key_package.identifier,
        R: sig_r,
        z,
    }
}

pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
) -> Signature {
    assert_eq!(
        signing_package.signing_commitments.len(),
        signature_shares.len()
    );

    let mut z = Scalar::ZERO;
    let mut R_opt = None;

    for share in signature_shares.values() {
        z += share.z;

        if let Some(R) = R_opt {
            assert_eq!(R, share.R);
        } else {
            R_opt = Some(share.R);
        }
    }

    Signature {
        R: R_opt.expect("missing signature shares"),
        z,
    }
}

pub(crate) fn lagrange(i: Identifier, signer_set: &[Identifier]) -> Scalar {
    let i_s = Scalar::from(i as u64);
    let mut out = Scalar::ONE;

    for j in signer_set {
        if *j == i {
            continue;
        }

        let j_s = Scalar::from(*j as u64);
        out *= j_s * (j_s - i_s).invert().unwrap();
    }

    out
}

pub(crate) fn delta(i: Identifier, j: Identifier) -> Scalar {
    if i > j { Scalar::ONE } else { -Scalar::ONE }
}

pub(crate) fn encode_signer_set(ids: &[Identifier]) -> Vec<u8> {
    let mut out = Vec::new();

    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }

    out
}

pub(crate) fn encode_commitments(
    commitments: &BTreeMap<Identifier, SigningCommitments>,
) -> Vec<u8> {
    let mut out = Vec::new();

    for (id, c) in commitments {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&point_bytes(&c.D));
        out.extend_from_slice(&point_bytes(&c.E));
    }

    out
}

pub(crate) fn scalar_from_hash(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha256::new();

    for p in parts {
        h.update(p);
    }

    let bytes: [u8; 32] = h.finalize().into();
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&bytes))
}

pub(crate) fn point_bytes(point: &ProjectivePoint) -> [u8; 33] {
    let enc = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_bytes());
    out
}
