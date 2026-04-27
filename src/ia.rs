#![allow(non_snake_case)]

use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::keygen::{Identifier, KeyPackage, PublicKeyPackage};
use crate::sign::{SignatureShare, SigningPackage};
use crate::utils::{
    delta, encode_commitments, encode_signer_set, hash_pairwise_key_commitment, lagrange,
    pedersen_commit, point_bytes, scalar_bytes, scalar_from_hash,
};

#[derive(Clone)]
pub struct IA1Message {
    pub identifier: Identifier,
    pub blinding_commitments: BTreeMap<Identifier, ProjectivePoint>,
    pub proof: WellformedProof,
}

#[derive(Clone)]
pub struct IA2Decision {
    pub identifier: Identifier,
    pub opened_pairwise_keys: BTreeMap<Identifier, [u8; 32]>,
}

#[derive(Clone)]
pub struct WellformedProof {
    pub t_sig: ProjectivePoint,
    pub t_key: ProjectivePoint,
    pub t_blind: BTreeMap<Identifier, ProjectivePoint>,

    pub z_sk: Scalar,
    pub z_sk_blinding: Scalar,
    pub z_blind: BTreeMap<Identifier, Scalar>,
    pub z_blind_blinding: BTreeMap<Identifier, Scalar>,
}

pub fn ia1<R: RngCore + CryptoRng>(
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
    key_package: &KeyPackage,
    pubkeys: &PublicKeyPackage,
    all_signature_shares: &BTreeMap<Identifier, SignatureShare>,
    rng: &mut R,
) -> IA1Message {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = key_package.identifier;

    assert_eq!(signature_share.identifier, i);
    assert!(ids.contains(&i));

    let commitments_bytes = encode_commitments(&signing_package.signing_commitments);

    let signer_set_bytes = encode_signer_set(&ids);
    let view_bytes = ia_view_bytes(signing_package, all_signature_shares);

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
            .expect("missing pairwise key");

        let B_ij = scalar_from_hash(&[
            b"FaFROST/secp256k1/SHA256/Hs",
            k_ij,
            &commitments_bytes,
            &signing_package.message,
            &signer_set_bytes,
        ]);

        let omega_ij = scalar_from_hash(&[b"FaFROST/secp256k1/SHA256/HIA", k_ij, &view_bytes]);

        let C_ij = pedersen_commit(B_ij, omega_ij, pubkeys.pedersen_h);

        blinding_values.insert(*j, B_ij);
        blinding_randomizers.insert(*j, omega_ij);
        blinding_commitments.insert(*j, C_ij);
    }

    let proof = prove_wellformed(
        signing_package,
        signature_share,
        key_package,
        pubkeys,
        &blinding_values,
        &blinding_randomizers,
        &blinding_commitments,
        rng,
    );

    IA1Message {
        identifier: i,
        blinding_commitments,
        proof,
    }
}

pub fn ia2(
    key_package: &KeyPackage,
    signing_package: &SigningPackage,
    ia1_messages: &BTreeMap<Identifier, IA1Message>,
) -> IA2Decision {
    let i = key_package.identifier;

    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let own = ia1_messages.get(&i).expect("missing own IA1 message");

    let mut opened_pairwise_keys = BTreeMap::new();

    for j in ids {
        if j == i {
            continue;
        }

        let C_ij = own
            .blinding_commitments
            .get(&j)
            .expect("missing own blinding commitment");

        let C_ji = ia1_messages
            .get(&j)
            .expect("missing peer IA1 message")
            .blinding_commitments
            .get(&i)
            .expect("missing peer blinding commitment");

        if C_ij != C_ji {
            let k_ij = key_package
                .pairwise_keys
                .get(&j)
                .expect("missing pairwise key");

            opened_pairwise_keys.insert(j, *k_ij);
        }
    }

    IA2Decision {
        identifier: i,
        opened_pairwise_keys,
    }
}

pub fn decide(
    signing_package: &SigningPackage,
    pubkeys: &PublicKeyPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    ia1_messages: &BTreeMap<Identifier, IA1Message>,
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

        if !verify_wellformed_proof(signing_package, share, msg, pubkeys) {
            malicious.insert(*id);
        }
    }

    let commitments_bytes = encode_commitments(&signing_package.signing_commitments);

    let signer_set_bytes = encode_signer_set(&ids);
    let view_bytes = ia_view_bytes(signing_package, signature_shares);

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

            if hash_pairwise_key_commitment(opened_key) != *expected_key_commitment {
                malicious.insert(*accuser);
                continue;
            }

            let B = scalar_from_hash(&[
                b"FaFROST/secp256k1/SHA256/Hs",
                opened_key,
                &commitments_bytes,
                &signing_package.message,
                &signer_set_bytes,
            ]);

            let omega =
                scalar_from_hash(&[b"FaFROST/secp256k1/SHA256/HIA", opened_key, &view_bytes]);

            let expected_commitment = pedersen_commit(B, omega, pubkeys.pedersen_h);

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

fn prove_wellformed<R: RngCore + CryptoRng>(
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
    key_package: &KeyPackage,
    pubkeys: &PublicKeyPackage,
    blinding_values: &BTreeMap<Identifier, Scalar>,
    blinding_randomizers: &BTreeMap<Identifier, Scalar>,
    blinding_commitments: &BTreeMap<Identifier, ProjectivePoint>,
    rng: &mut R,
) -> WellformedProof {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let i = key_package.identifier;

    let b = nonce_challenge(signing_package, pubkeys);
    let c = sig_challenge(signing_package, pubkeys);
    let lambda_i = lagrange(i, &ids);

    let r_sk = Scalar::random(&mut *rng);
    let r_sk_blinding = Scalar::random(&mut *rng);

    let mut r_blind = BTreeMap::new();
    let mut r_blind_blinding = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        r_blind.insert(*j, Scalar::random(&mut *rng));
        r_blind_blinding.insert(*j, Scalar::random(&mut *rng));
    }

    let mut t_sig = ProjectivePoint::GENERATOR * (lambda_i * c * r_sk);

    for j in &ids {
        if *j == i {
            continue;
        }

        t_sig += ProjectivePoint::GENERATOR * (*r_blind.get(j).unwrap() * delta(i, *j));
    }

    let t_key = ProjectivePoint::GENERATOR * r_sk + pubkeys.pedersen_h * r_sk_blinding;

    let mut t_blind = BTreeMap::new();

    for j in &ids {
        if *j == i {
            continue;
        }

        let t = ProjectivePoint::GENERATOR * *r_blind.get(j).unwrap()
            + pubkeys.pedersen_h * *r_blind_blinding.get(j).unwrap();

        t_blind.insert(*j, t);
    }

    let challenge = proof_challenge(
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

    WellformedProof {
        t_sig,
        t_key,
        t_blind,
        z_sk: r_sk + challenge * key_package.signing_share,
        z_sk_blinding: r_sk_blinding + challenge * key_package.signing_share_blinding,
        z_blind,
        z_blind_blinding,
    }
}

fn verify_wellformed_proof(
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
    ia1_message: &IA1Message,
    pubkeys: &PublicKeyPackage,
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

    let b = nonce_challenge(signing_package, pubkeys);
    let c = sig_challenge(signing_package, pubkeys);
    let lambda_i = lagrange(i, &ids);

    // A = G*z - D_i - b*E_i  (= G*(c·λi·sk_i + B_i^s) after nonces cancel).
    // With bip340 and odd R the nonces in z were negated, so the signs flip.
    let A = {
        let base = ProjectivePoint::GENERATOR * signature_share.z;
        #[cfg(feature = "bip340")]
        {
            let mut agg_d = ProjectivePoint::IDENTITY;
            let mut agg_e = ProjectivePoint::IDENTITY;
            for comm in signing_package.signing_commitments.values() {
                agg_d += comm.D;
                agg_e += comm.E;
            }
            let R_raw = agg_d + agg_e * b;
            if crate::bip340::has_odd_y(&R_raw) {
                base + commitment_i.D + commitment_i.E * b
            } else {
                base + commitment_i.D * (-Scalar::ONE) + commitment_i.E * (-b)
            }
        }
        #[cfg(not(feature = "bip340"))]
        {
            base + commitment_i.D * (-Scalar::ONE) + commitment_i.E * (-b)
        }
    };

    let challenge = proof_challenge(
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

    let mut rhs_sig = ProjectivePoint::GENERATOR * (lambda_i * c * ia1_message.proof.z_sk);

    for j in &ids {
        if *j == i {
            continue;
        }

        let Some(z_B) = ia1_message.proof.z_blind.get(j) else {
            return false;
        };

        rhs_sig += ProjectivePoint::GENERATOR * (*z_B * delta(i, *j));
    }

    rhs_sig += A * (-challenge);

    if rhs_sig != ia1_message.proof.t_sig {
        return false;
    }

    let rhs_key = ProjectivePoint::GENERATOR * ia1_message.proof.z_sk
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

        let rhs = ProjectivePoint::GENERATOR * *z_B
            + pubkeys.pedersen_h * *z_omega
            + *C_ij * (-challenge);

        if rhs != *t_j {
            return false;
        }
    }

    true
}

fn nonce_challenge(signing_package: &SigningPackage, pubkeys: &PublicKeyPackage) -> Scalar {
    let ids: Vec<Identifier> = signing_package
        .signing_commitments
        .keys()
        .copied()
        .collect();

    let commitments_bytes = encode_commitments(&signing_package.signing_commitments);

    let vk_bytes = point_bytes(&pubkeys.verifying_key);

    scalar_from_hash(&[
        b"FaFROST/secp256k1/SHA256/Hnon",
        &vk_bytes,
        &encode_signer_set(&ids),
        &signing_package.message,
        &commitments_bytes,
    ])
}

fn sig_challenge(signing_package: &SigningPackage, pubkeys: &PublicKeyPackage) -> Scalar {
    let b = nonce_challenge(signing_package, pubkeys);

    let mut D = ProjectivePoint::IDENTITY;
    let mut E = ProjectivePoint::IDENTITY;

    for c in signing_package.signing_commitments.values() {
        D += c.D;
        E += c.E;
    }

    let R = D + E * b;

    {
        #[cfg(feature = "bip340")]
        {
            let r_x = crate::bip340::x_only_bytes(&R);
            let p_x = crate::bip340::x_only_bytes(&pubkeys.verifying_key);
            crate::bip340::bip340_challenge_scalar(&r_x, &p_x, &signing_package.message)
        }
        #[cfg(not(feature = "bip340"))]
        {
            let vk_bytes = point_bytes(&pubkeys.verifying_key);
            let R_bytes = point_bytes(&R);
            scalar_from_hash(&[
                b"FaFROST/secp256k1/SHA256/Hsig",
                &vk_bytes,
                &R_bytes,
                &signing_package.message,
            ])
        }
    }
}

fn proof_challenge(
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
    pubkeys: &PublicKeyPackage,
    blinding_commitments: &BTreeMap<Identifier, ProjectivePoint>,
    t_sig: &ProjectivePoint,
    t_key: &ProjectivePoint,
    t_blind: &BTreeMap<Identifier, ProjectivePoint>,
    b: Scalar,
    c: Scalar,
) -> Scalar {
    let mut transcript = Vec::new();

    transcript.extend_from_slice(b"FaFROST/secp256k1/SHA256/IAProof");

    transcript.extend_from_slice(&signature_share.identifier.to_be_bytes());
    transcript.extend_from_slice(&signing_package.message);
    transcript.extend_from_slice(&scalar_bytes(&b));
    transcript.extend_from_slice(&scalar_bytes(&c));
    transcript.extend_from_slice(&scalar_bytes(&signature_share.z));
    transcript.extend_from_slice(&point_bytes(&signature_share.R));
    transcript.extend_from_slice(&point_bytes(&pubkeys.verifying_key));

    transcript.extend_from_slice(&encode_commitments(&signing_package.signing_commitments));

    for (id, C) in blinding_commitments {
        transcript.extend_from_slice(&id.to_be_bytes());
        transcript.extend_from_slice(&point_bytes(C));
    }

    transcript.extend_from_slice(&point_bytes(t_sig));
    transcript.extend_from_slice(&point_bytes(t_key));

    for (id, T) in t_blind {
        transcript.extend_from_slice(&id.to_be_bytes());
        transcript.extend_from_slice(&point_bytes(T));
    }

    scalar_from_hash(&[&transcript])
}

fn ia_view_bytes(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&encode_commitments(&signing_package.signing_commitments));

    for (id, share) in signature_shares {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&point_bytes(&share.R));
        out.extend_from_slice(&scalar_bytes(&share.z));
    }

    out
}

#[test]
fn identifiable_abort_finds_tampered_share() {
    use std::collections::{BTreeMap, BTreeSet};

    use rand_core::OsRng;

    use crate::ia::{decide, ia1, ia2};
    use crate::keygen::generate_with_dealer;
    use crate::sign::{SigningPackage, aggregate, commit, sign};
    use crate::verify::verify;

    let mut rng = OsRng;

    let (shares, pubkeys) = generate_with_dealer(3, 2, &mut rng);

    let signer_ids = [1u16, 2u16];
    let message = [99u8; 32];

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for id in signer_ids {
        let (nonce, commitment) = commit(&mut rng);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let signing_package = SigningPackage {
        message,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();

    for id in signer_ids {
        let share = sign(
            &signing_package,
            nonces.get(&id).unwrap(),
            shares.get(&id).unwrap(),
            &pubkeys,
        );

        signature_shares.insert(id, share);
    }

    signature_shares.get_mut(&1).unwrap().z += k256::Scalar::ONE;

    let bad_sig = aggregate(&signing_package, &signature_shares);
    assert!(!verify(&bad_sig, &message, &pubkeys));

    let mut ia1_messages = BTreeMap::new();

    for id in signer_ids {
        let msg = ia1(
            &signing_package,
            signature_shares.get(&id).unwrap(),
            shares.get(&id).unwrap(),
            &pubkeys,
            &signature_shares,
            &mut rng,
        );

        ia1_messages.insert(id, msg);
    }

    let mut ia2_decisions = BTreeMap::new();

    for id in signer_ids {
        let decision = ia2(shares.get(&id).unwrap(), &signing_package, &ia1_messages);

        ia2_decisions.insert(id, decision);
    }

    let malicious = decide(
        &signing_package,
        &pubkeys,
        &signature_shares,
        &ia1_messages,
        &ia2_decisions,
    );

    let mut expected = BTreeSet::new();
    expected.insert(1u16);

    assert_eq!(malicious, expected);
}
