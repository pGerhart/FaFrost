#![allow(non_snake_case)]

use crate::ciphersuite::{Ciphersuite, ScalarHasher};
use crate::utils::{encode_commitments, encode_signer_set, lagrange};
use std::collections::BTreeMap;
use std::vec::Vec;

use ff::Field;
use group::Group;

use rand_core::CryptoRng;

use crate::keygen::{Identifier, KeyPackage, PartialVerificationKey, PublicKeyPackage};

#[derive(Clone)]
pub struct SigningNonces<C: Ciphersuite> {
    pub d: C::Scalar,
    pub e: C::Scalar,
}

#[derive(Clone)]
pub struct SigningCommitments<C: Ciphersuite> {
    pub D: C::Point,
    pub E: C::Point,
}

#[derive(Clone)]
pub struct SigningPackage<C: Ciphersuite> {
    pub message: [u8; 32],
    pub signing_commitments: BTreeMap<Identifier, SigningCommitments<C>>,
    pub partial_verification_keys: BTreeMap<Identifier, PartialVerificationKey<C>>,
}

#[derive(Clone)]
pub struct SignatureShare<C: Ciphersuite> {
    pub identifier: Identifier,
    pub R: C::Point,
    pub z: C::Scalar,
}

impl<C: Ciphersuite> SignatureShare<C> {
    pub fn new(identifier: Identifier, R: C::Point, nonce: C::Scalar, z_rest: C::Scalar) -> Self {
        let (R, nonce) = C::normalize_share_r(R, nonce);
        Self {
            identifier,
            R,
            z: z_rest + nonce,
        }
    }
}

#[derive(Clone)]
pub struct Signature<C: Ciphersuite> {
    pub R: C::Point,
    pub z: C::Scalar,
}

pub fn commit<C: Ciphersuite, R: CryptoRng>(
    rng: &mut R,
) -> (SigningNonces<C>, SigningCommitments<C>) {
    let d = C::Scalar::random(&mut *rng);
    let e = C::Scalar::random(rng);

    let D = C::Point::generator() * d;
    let E = C::Point::generator() * e;

    (SigningNonces { d, e }, SigningCommitments { D, E })
}

pub fn sign<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signer_nonces: &SigningNonces<C>,
    key_package: &KeyPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
) -> SignatureShare<C> {
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

    let commitments_bytes = encode_commitments::<C>(&signing_package.signing_commitments);

    let signer_commitment = signing_package
        .signing_commitments
        .get(&key_package.identifier)
        .unwrap();

    assert_eq!(signer_commitment.D, C::Point::generator() * signer_nonces.d);
    assert_eq!(signer_commitment.E, C::Point::generator() * signer_nonces.e);

    let mut D = C::Point::identity();
    let mut E = C::Point::identity();

    for c in signing_package.signing_commitments.values() {
        D += c.D;
        E += c.E;
    }

    let vk_bytes = C::point_bytes(&pubkeys.verifying_key);

    let b = C::hash_to_scalar(&[
        C::CONTEXT.as_bytes(),
        b"/Hnon",
        &vk_bytes,
        &encode_signer_set(&ids),
        &signing_package.message,
        &commitments_bytes,
    ]);

    let R = D + E * b;

    let c = C::challenge(&pubkeys.verifying_key, &R, &signing_package.message);

    let lambda_i = lagrange::<C>(key_package.identifier, &ids);

    let blind = key_package.blinding_scalar(&ids, &commitments_bytes, &signing_package.message);

    let nonce = signer_nonces.d + b * signer_nonces.e;
    let z_rest = c * lambda_i * key_package.signing_share + blind;
    SignatureShare::new(key_package.identifier, R, nonce, z_rest)
}

pub fn aggregate<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signature_shares: &BTreeMap<Identifier, SignatureShare<C>>,
) -> Signature<C> {
    assert_eq!(
        signing_package.signing_commitments.len(),
        signature_shares.len()
    );

    let mut z = C::Scalar::ZERO;
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

impl<C: Ciphersuite> KeyPackage<C> {
    pub fn blinding_scalar(
        &self,
        ids: &[Identifier],
        commitments_bytes: &[u8],
        msg: &[u8; 32],
    ) -> C::Scalar {
        let signer_set_bytes = encode_signer_set(ids);

        // Hash the constant prefix once; k_ij is appended last per peer.
        let mut base = C::Hasher::new();
        base.update(C::CONTEXT.as_bytes());
        base.update(b"/Hs");
        base.update(commitments_bytes);
        base.update(msg);
        base.update(&signer_set_bytes);

        let mut blind = C::Scalar::ZERO;

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
