#![allow(non_snake_case)]

use crate::ciphersuite::{Ciphersuite, ScalarHasher};
use crate::error::{Error, Result};
use crate::utils::{
    binding_factor, blinding_base, encode_commitments, encode_signer_set, lagrange,
};
use std::collections::BTreeMap;
use std::vec::Vec;

use ff::Field;
use group::Group;
use zeroize::Zeroize;

use rand_core::CryptoRng;

use crate::keygen::{Identifier, KeyPackage, PartialVerificationKey, PublicKeyPackage};

#[derive(Clone)]
pub struct SigningNonces<C: Ciphersuite> {
    pub d: C::Scalar,
    pub e: C::Scalar,
}

/// Zeroizes the one-time nonces on drop.
impl<C: Ciphersuite> Drop for SigningNonces<C> {
    fn drop(&mut self) {
        self.d.zeroize();
        self.e.zeroize();
    }
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

    let D = C::mul_generator(&d);
    let E = C::mul_generator(&e);

    (SigningNonces { d, e }, SigningCommitments { D, E })
}

pub fn sign<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signer_nonces: &SigningNonces<C>,
    key_package: &KeyPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
) -> Result<SignatureShare<C>> {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = key_package.identifier;

    let commitments_bytes = encode_commitments::<C>(&signing_package.signing_commitments);

    let signer_commitment = signing_package
        .signing_commitments
        .get(&i)
        .ok_or(Error::UnknownSigner(i))?;

    // The coordinator must have published this signer's own commitment `(D_i, E_i)`
    // for exactly the nonce it holds; a mismatch means a wrong or tampered session.
    if signer_commitment.D != C::mul_generator(&signer_nonces.d)
        || signer_commitment.E != C::mul_generator(&signer_nonces.e)
    {
        return Err(Error::NonceCommitmentMismatch(i));
    }

    let mut D = C::Point::identity();
    let mut E = C::Point::identity();

    for c in signing_package.signing_commitments.values() {
        D += c.D;
        E += c.E;
    }

    let b = binding_factor::<C>(
        &pubkeys.verifying_key,
        &encode_signer_set(&ids),
        &signing_package.message,
        &commitments_bytes,
    );

    let R = D + E * b;

    let c = C::challenge(&pubkeys.verifying_key, &R, &signing_package.message);

    let lambda_i = lagrange::<C>(i, &ids);

    let blind = key_package.blinding_scalar(&ids, &commitments_bytes, &signing_package.message)?;

    let nonce = signer_nonces.d + b * signer_nonces.e;
    let z_rest = c * lambda_i * key_package.signing_share + blind;
    Ok(SignatureShare::new(i, R, nonce, z_rest))
}

pub fn aggregate<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signature_shares: &BTreeMap<Identifier, SignatureShare<C>>,
) -> Result<Signature<C>> {
    let expected = signing_package.signing_commitments.len();
    let got = signature_shares.len();
    if expected != got {
        return Err(Error::ShareCountMismatch { expected, got });
    }

    let mut z = C::Scalar::ZERO;
    let mut R_opt = None;

    for share in signature_shares.values() {
        z += share.z;

        match R_opt {
            // Every share must carry the same aggregate nonce R; a disagreement
            // is an adversarial or malformed share, not a reason to crash.
            Some(R) if R != share.R => return Err(Error::InconsistentAggregateNonce),
            Some(_) => {}
            None => R_opt = Some(share.R),
        }
    }

    let R = R_opt.ok_or(Error::NoSignatureShares)?;
    Ok(Signature { R, z })
}

impl<C: Ciphersuite> KeyPackage<C> {
    pub fn blinding_scalar(
        &self,
        ids: &[Identifier],
        commitments_bytes: &[u8],
        msg: &[u8; 32],
    ) -> Result<C::Scalar> {
        let signer_set_bytes = encode_signer_set(ids);

        // Shared prefix hashed once; k_ij is appended last per peer.
        let base = blinding_base::<C>(commitments_bytes, msg, &signer_set_bytes);

        let mut blind = C::Scalar::ZERO;

        for j in ids {
            if *j == self.identifier {
                continue;
            }

            let k_ij = self
                .pairwise_keys
                .get(j)
                .ok_or(Error::MissingPairwiseKey(*j))?;
            let B_ij = base.clone().finish_with(k_ij);

            if self.identifier > *j {
                blind += B_ij;
            } else {
                blind -= B_ij;
            }
        }

        Ok(blind)
    }
}
