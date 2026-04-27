#![allow(non_snake_case)]

use crate::utils::{
    encode_commitments, encode_signer_set, lagrange, point_bytes, scalar_from_hash, ScalarHasher,
};
use std::collections::BTreeMap;
use std::vec::Vec;

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};

use rand_core::{CryptoRng, RngCore};

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

impl SignatureShare {
    pub fn new(identifier: Identifier, R: ProjectivePoint, nonce: Scalar, z_rest: Scalar) -> Self {
        #[cfg(feature = "bip340")]
        let (R, nonce) = if crate::bip340::has_odd_y(&R) {
            (-R, -nonce)
        } else {
            (R, nonce)
        };
        Self {
            identifier,
            R,
            z: z_rest + nonce,
        }
    }
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

    let c = pubkeys.challenge_scalar(&R, &signing_package.message);

    let lambda_i = lagrange(key_package.identifier, &ids);

    let blind = key_package.blinding_scalar(&ids, &commitments_bytes, &signing_package.message);

    let nonce = signer_nonces.d + b * signer_nonces.e;
    let z_rest = c * lambda_i * key_package.signing_share + blind;
    SignatureShare::new(key_package.identifier, R, nonce, z_rest)
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

impl KeyPackage {
    pub fn blinding_scalar(
        &self,
        ids: &[Identifier],
        commitments_bytes: &[u8],
        msg: &[u8; 32],
    ) -> Scalar {
        let signer_set_bytes = encode_signer_set(ids);

        // Hash the constant prefix once; k_ij is appended last per peer.
        let mut base = ScalarHasher::new();
        base.update(b"FaFROST/secp256k1/SHA256/Hs");
        base.update(commitments_bytes);
        base.update(msg);
        base.update(&signer_set_bytes);

        let mut blind = Scalar::ZERO;

        for j in ids {
            if *j == self.identifier {
                continue;
            }

            let k_ij = self.pairwise_keys.get(j).expect("missing pairwise key");
            let B_ij = base.clone().finish_with(k_ij);

            if self.identifier > *j {
                blind += B_ij;
            } else {
                blind -= B_ij;
            }
        }

        blind
    }
}

impl PublicKeyPackage {
    pub fn challenge_scalar(&self, r: &ProjectivePoint, msg: &[u8; 32]) -> Scalar {
        #[cfg(feature = "bip340")]
        {
            let r_x = crate::bip340::x_only_bytes(r);
            let p_x = crate::bip340::x_only_bytes(&self.verifying_key);
            return crate::bip340::bip340_challenge_scalar(&r_x, &p_x, msg);
        }
        #[cfg(not(feature = "bip340"))]
        {
            let vk_bytes = point_bytes(&self.verifying_key);
            let r_bytes = point_bytes(r);
            scalar_from_hash(&[b"FaFROST/secp256k1/SHA256/Hsig", &vk_bytes, &r_bytes, msg])
        }
    }
}
