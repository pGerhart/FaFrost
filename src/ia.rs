//! Identifiable-abort protocol: the two IA rounds and the `decide` algorithm.
#![allow(non_snake_case)]

use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

use ff::{Field, FromUniformBytes};
use group::Group;
use merlin::Transcript;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::ciphersuite::{Ciphersuite, ScalarHasher};
use crate::error::{Error, Result};
use crate::keygen::{Identifier, KeyPackage, PublicKeyPackage};
use crate::sign::{SignatureShare, SigningPackage};
use crate::utils::{
    binding_factor, blinding_base, blinding_randomizer, delta, encode_signer_set,
    hash_pairwise_key_commitment, lagrange, pedersen_commit,
};
use crate::wire::{encode_commitments, scalar_bytes};

#[derive(Clone)]
pub struct IA1Message<C: Ciphersuite> {
    pub identifier: Identifier,
    pub blinding_commitments: BTreeMap<Identifier, C::Point>,
    pub proof: WellformedProof<C>,
}

#[derive(Clone)]
pub struct IA2Decision {
    pub identifier: Identifier,
    pub opened_pairwise_keys: BTreeMap<Identifier, [u8; 32]>,
}

#[derive(Clone)]
pub struct WellformedProof<C: Ciphersuite> {
    pub t_sig: C::Point,
    pub t_key: C::Point,
    pub t_blind: BTreeMap<Identifier, C::Point>,

    pub z_sk: C::Scalar,
    pub z_sk_blinding: C::Scalar,
    pub z_blind: BTreeMap<Identifier, C::Scalar>,
    pub z_blind_blinding: BTreeMap<Identifier, C::Scalar>,
}

pub fn ia1<C: Ciphersuite, R: CryptoRng>(
    signing_package: &SigningPackage<C>,
    signature_share: &SignatureShare<C>,
    key_package: &KeyPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
    all_signature_shares: &BTreeMap<Identifier, SignatureShare<C>>,
    rng: &mut R,
) -> Result<IA1Message<C>> {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = key_package.identifier;

    if signature_share.identifier != i || !ids.contains(&i) {
        return Err(Error::UnknownSigner(i));
    }

    let commitments_bytes = encode_commitments::<C>(&signing_package.signing_commitments);

    let signer_set_bytes = encode_signer_set(&ids);
    let view_bytes = ia_view_bytes::<C>(signing_package, all_signature_shares);

    let b_base = blinding_base::<C>(
        &commitments_bytes,
        &signing_package.message,
        &signer_set_bytes,
    );

    let mut blinding_values = BTreeMap::new();
    let mut blinding_randomizers = BTreeMap::new();
    let mut blinding_commitments = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        let k_ij = key_package
            .pairwise_keys
            .get(j)
            .ok_or(Error::MissingPairwiseKey(*j))?;

        let B_ij = b_base.clone().finish_with(k_ij);
        let omega_ij = blinding_randomizer::<C>(k_ij, &view_bytes);

        let C_ij = pedersen_commit::<C>(B_ij, omega_ij, pubkeys.pedersen_h);

        blinding_values.insert(*j, B_ij);
        blinding_randomizers.insert(*j, omega_ij);
        blinding_commitments.insert(*j, C_ij);
    }

    let proof = prove_wellformed::<C, R>(
        signing_package,
        signature_share,
        key_package,
        pubkeys,
        &blinding_values,
        &blinding_randomizers,
        &blinding_commitments,
        rng,
    );

    Ok(IA1Message {
        identifier: i,
        blinding_commitments,
        proof,
    })
}

pub fn ia2<C: Ciphersuite>(
    key_package: &KeyPackage<C>,
    signing_package: &SigningPackage<C>,
    ia1_messages: &BTreeMap<Identifier, IA1Message<C>>,
) -> Result<IA2Decision> {
    let i = key_package.identifier;

    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let own = ia1_messages.get(&i).ok_or(Error::MissingIa1Message(i))?;

    let mut opened_pairwise_keys = BTreeMap::new();

    for j in ids {
        if j == i {
            continue;
        }

        let C_ij = own
            .blinding_commitments
            .get(&j)
            .ok_or(Error::MissingBlindingCommitment { from: i, about: j })?;

        let C_ji = ia1_messages
            .get(&j)
            .ok_or(Error::MissingIa1Message(j))?
            .blinding_commitments
            .get(&i)
            .ok_or(Error::MissingBlindingCommitment { from: j, about: i })?;

        if C_ij != C_ji {
            let k_ij = key_package
                .pairwise_keys
                .get(&j)
                .ok_or(Error::MissingPairwiseKey(j))?;

            opened_pairwise_keys.insert(j, *k_ij);
        }
    }

    Ok(IA2Decision {
        identifier: i,
        opened_pairwise_keys,
    })
}

pub fn decide<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
    signature_shares: &BTreeMap<Identifier, SignatureShare<C>>,
    ia1_messages: &BTreeMap<Identifier, IA1Message<C>>,
    ia2_decisions: &BTreeMap<Identifier, IA2Decision>,
) -> BTreeSet<Identifier> {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let mut malicious = BTreeSet::new();

    for id in &ids {
        let Some(share) = signature_shares.get(id) else {
            malicious.insert(*id);
            continue;
        };

        let Some(msg) = ia1_messages.get(id) else {
            malicious.insert(*id);
            continue;
        };

        if !verify_wellformed_proof::<C>(signing_package, share, msg, pubkeys) {
            malicious.insert(*id);
        }
    }

    let commitments_bytes = encode_commitments::<C>(&signing_package.signing_commitments);

    let signer_set_bytes = encode_signer_set(&ids);
    let view_bytes = ia_view_bytes::<C>(signing_package, signature_shares);
    let b_base = blinding_base::<C>(
        &commitments_bytes,
        &signing_package.message,
        &signer_set_bytes,
    );

    for (accuser, decision) in ia2_decisions {
        for (peer, opened_key) in &decision.opened_pairwise_keys {
            let Some(vk_accuser) = pubkeys.partial_verification_keys.get(accuser) else {
                malicious.insert(*accuser);
                continue;
            };

            let Some(expected_key_commitment) = vk_accuser.pairwise_key_commitments.get(peer)
            else {
                malicious.insert(*accuser);
                continue;
            };

            if hash_pairwise_key_commitment::<C>(opened_key) != *expected_key_commitment {
                malicious.insert(*accuser);
                continue;
            }

            let B = b_base.clone().finish_with(opened_key);
            let omega = blinding_randomizer::<C>(opened_key, &view_bytes);

            let expected_commitment = pedersen_commit::<C>(B, omega, pubkeys.pedersen_h);

            let Some(peer_msg) = ia1_messages.get(peer) else {
                malicious.insert(*peer);
                continue;
            };

            let Some(peer_commitment) = peer_msg.blinding_commitments.get(accuser) else {
                malicious.insert(*peer);
                continue;
            };

            if *peer_commitment != expected_commitment {
                malicious.insert(*peer);
            }
        }
    }

    for i in &ids {
        for j in &ids {
            if i >= j {
                continue;
            }

            let Some(msg_i) = ia1_messages.get(i) else {
                malicious.insert(*i);
                continue;
            };

            let Some(msg_j) = ia1_messages.get(j) else {
                malicious.insert(*j);
                continue;
            };

            let Some(C_ij) = msg_i.blinding_commitments.get(j) else {
                malicious.insert(*i);
                continue;
            };

            let Some(C_ji) = msg_j.blinding_commitments.get(i) else {
                malicious.insert(*j);
                continue;
            };

            if C_ij != C_ji {
                let i_opened_j = ia2_decisions
                    .get(i)
                    .map(|d| d.opened_pairwise_keys.contains_key(j))
                    .unwrap_or(false);

                let j_opened_i = ia2_decisions
                    .get(j)
                    .map(|d| d.opened_pairwise_keys.contains_key(i))
                    .unwrap_or(false);

                if !i_opened_j {
                    malicious.insert(*i);
                }

                if !j_opened_i {
                    malicious.insert(*j);
                }
            }
        }
    }

    malicious
}

// Sigma-protocol inputs, kept explicit rather than bundled.
#[allow(clippy::too_many_arguments)]
fn prove_wellformed<C: Ciphersuite, R: CryptoRng>(
    signing_package: &SigningPackage<C>,
    signature_share: &SignatureShare<C>,
    key_package: &KeyPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
    blinding_values: &BTreeMap<Identifier, C::Scalar>,
    blinding_randomizers: &BTreeMap<Identifier, C::Scalar>,
    blinding_commitments: &BTreeMap<Identifier, C::Point>,
    rng: &mut R,
) -> WellformedProof<C> {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = key_package.identifier;

    let b = nonce_challenge::<C>(signing_package, pubkeys);
    let c = sig_challenge::<C>(signing_package, pubkeys);
    let lambda_i = lagrange::<C>(i, &ids);

    let mut r_sk = C::Scalar::random(&mut *rng);
    let mut r_sk_blinding = C::Scalar::random(&mut *rng);

    let mut r_blind = BTreeMap::new();
    let mut r_blind_blinding = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        r_blind.insert(*j, C::Scalar::random(&mut *rng));
        r_blind_blinding.insert(*j, C::Scalar::random(&mut *rng));
    }

    let mut t_sig = C::Point::generator() * (lambda_i * c * r_sk);

    for j in &ids {
        if *j == i {
            continue;
        }

        t_sig += C::Point::generator() * (*r_blind.get(j).unwrap() * delta::<C>(i, *j));
    }

    let t_key = C::Point::generator() * r_sk + pubkeys.pedersen_h * r_sk_blinding;

    let mut t_blind = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        let t = C::Point::generator() * *r_blind.get(j).unwrap()
            + pubkeys.pedersen_h * *r_blind_blinding.get(j).unwrap();

        t_blind.insert(*j, t);
    }

    let challenge = proof_challenge::<C>(
        signing_package,
        signature_share,
        pubkeys,
        blinding_commitments,
        &t_sig,
        &t_key,
        &t_blind,
        b,
        c,
    );

    let mut z_blind = BTreeMap::new();
    let mut z_blind_blinding = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        z_blind.insert(
            *j,
            *r_blind.get(j).unwrap() + challenge * *blinding_values.get(j).unwrap(),
        );

        z_blind_blinding.insert(
            *j,
            *r_blind_blinding.get(j).unwrap() + challenge * *blinding_randomizers.get(j).unwrap(),
        );
    }

    let proof = WellformedProof {
        t_sig,
        t_key,
        t_blind,
        z_sk: r_sk + challenge * key_package.signing_share,
        z_sk_blinding: r_sk_blinding + challenge * key_package.signing_share_blinding,
        z_blind,
        z_blind_blinding,
    };

    // Wipe the secret commitment randomness once the responses are formed.
    r_sk.zeroize();
    r_sk_blinding.zeroize();
    for r in r_blind.values_mut() {
        r.zeroize();
    }
    for r in r_blind_blinding.values_mut() {
        r.zeroize();
    }

    proof
}

fn verify_wellformed_proof<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signature_share: &SignatureShare<C>,
    ia1_message: &IA1Message<C>,
    pubkeys: &PublicKeyPackage<C>,
) -> bool {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = signature_share.identifier;

    if ia1_message.identifier != i {
        return false;
    }

    let Some(vki) = pubkeys.partial_verification_keys.get(&i) else {
        return false;
    };

    let Some(commitment_i) = signing_package.signing_commitments.get(&i) else {
        return false;
    };

    let b = nonce_challenge::<C>(signing_package, pubkeys);
    let c = sig_challenge::<C>(signing_package, pubkeys);
    let lambda_i = lagrange::<C>(i, &ids);

    // A = G*z - sign*(D_i + b*E_i)  (= G*(c*lambda_i*sk_i + B_i^s) after nonces cancel).
    // `sign` is +1 if the share kept its nonce and -1 if the ciphersuite negated
    // it during normalisation (BIP-340 odd-y aggregate R); a probe of ONE through
    // `normalize_share_r` recovers that sign without curve-specific branches.
    let A = {
        let base = C::Point::generator() * signature_share.z;

        let mut agg_d = C::Point::identity();
        let mut agg_e = C::Point::identity();
        for comm in signing_package.signing_commitments.values() {
            agg_d += comm.D;
            agg_e += comm.E;
        }
        let R_raw = agg_d + agg_e * b;
        let (_, sign) = C::normalize_share_r(R_raw, C::Scalar::ONE);

        base - (commitment_i.D + commitment_i.E * b) * sign
    };

    let challenge = proof_challenge::<C>(
        signing_package,
        signature_share,
        pubkeys,
        &ia1_message.blinding_commitments,
        &ia1_message.proof.t_sig,
        &ia1_message.proof.t_key,
        &ia1_message.proof.t_blind,
        b,
        c,
    );

    let mut rhs_sig = C::Point::generator() * (lambda_i * c * ia1_message.proof.z_sk);

    for j in &ids {
        if *j == i {
            continue;
        }

        let Some(z_B) = ia1_message.proof.z_blind.get(j) else {
            return false;
        };

        rhs_sig += C::Point::generator() * (*z_B * delta::<C>(i, *j));
    }

    rhs_sig += A * (-challenge);

    if rhs_sig != ia1_message.proof.t_sig {
        return false;
    }

    let rhs_key = C::Point::generator() * ia1_message.proof.z_sk
        + pubkeys.pedersen_h * ia1_message.proof.z_sk_blinding
        + vki.signing_share_commitment * (-challenge);

    if rhs_key != ia1_message.proof.t_key {
        return false;
    }

    for j in &ids {
        if *j == i {
            continue;
        }

        let Some(C_ij) = ia1_message.blinding_commitments.get(j) else {
            return false;
        };

        let Some(t_j) = ia1_message.proof.t_blind.get(j) else {
            return false;
        };

        let Some(z_B) = ia1_message.proof.z_blind.get(j) else {
            return false;
        };

        let Some(z_omega) = ia1_message.proof.z_blind_blinding.get(j) else {
            return false;
        };

        let rhs =
            C::Point::generator() * *z_B + pubkeys.pedersen_h * *z_omega + *C_ij * (-challenge);

        if rhs != *t_j {
            return false;
        }
    }

    true
}

fn nonce_challenge<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
) -> C::Scalar {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let commitments_bytes = encode_commitments::<C>(&signing_package.signing_commitments);

    binding_factor::<C>(
        &pubkeys.verifying_key,
        &encode_signer_set(&ids),
        &signing_package.message,
        &commitments_bytes,
    )
}

fn sig_challenge<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    pubkeys: &PublicKeyPackage<C>,
) -> C::Scalar {
    let b = nonce_challenge::<C>(signing_package, pubkeys);

    let mut D = C::Point::identity();
    let mut E = C::Point::identity();

    for c in signing_package.signing_commitments.values() {
        D += c.D;
        E += c.E;
    }

    let R = D + E * b;

    C::challenge(&pubkeys.verifying_key, &R, &signing_package.message)
}

// Arguments mirror the Fiat-Shamir transcript contents, kept flat.
#[allow(clippy::too_many_arguments)]
fn proof_challenge<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signature_share: &SignatureShare<C>,
    pubkeys: &PublicKeyPackage<C>,
    blinding_commitments: &BTreeMap<Identifier, C::Point>,
    t_sig: &C::Point,
    t_key: &C::Point,
    t_blind: &BTreeMap<Identifier, C::Point>,
    b: C::Scalar,
    c: C::Scalar,
) -> C::Scalar {
    let mut transcript = Transcript::new(b"FaFrost/IAProof");
    transcript.append_message(b"ctx", C::CONTEXT.as_bytes());

    transcript.append_message(b"signer", &signature_share.identifier.to_be_bytes());
    transcript.append_message(b"msg", &signing_package.message);
    transcript.append_message(b"b", &scalar_bytes::<C>(&b));
    transcript.append_message(b"c", &scalar_bytes::<C>(&c));
    transcript.append_message(b"z", &scalar_bytes::<C>(&signature_share.z));
    transcript.append_message(b"R", &C::point_bytes(&signature_share.R));
    transcript.append_message(b"vk", &C::point_bytes(&pubkeys.verifying_key));

    transcript.append_message(
        b"commitments",
        &encode_commitments::<C>(&signing_package.signing_commitments),
    );

    for (id, C_pt) in blinding_commitments {
        transcript.append_message(b"blind-id", &id.to_be_bytes());
        transcript.append_message(b"blind-commit", &C::point_bytes(C_pt));
    }

    transcript.append_message(b"t_sig", &C::point_bytes(t_sig));
    transcript.append_message(b"t_key", &C::point_bytes(t_key));

    for (id, T) in t_blind {
        transcript.append_message(b"t_blind-id", &id.to_be_bytes());
        transcript.append_message(b"t_blind", &C::point_bytes(T));
    }

    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
    C::Scalar::from_uniform_bytes(&challenge_bytes)
}

fn ia_view_bytes<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signature_shares: &BTreeMap<Identifier, SignatureShare<C>>,
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&encode_commitments::<C>(
        &signing_package.signing_commitments,
    ));

    for (id, share) in signature_shares {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&C::point_bytes(&share.R));
        out.extend_from_slice(&scalar_bytes::<C>(&share.z));
    }

    out
}
