use std::collections::BTreeMap;
use std::vec::Vec;

use ff::{Field, PrimeField};

use crate::ciphersuite::{Ciphersuite, ScalarHasher};
use crate::keygen::Identifier;
use crate::sign::SigningCommitments;

pub(crate) fn lagrange<C: Ciphersuite>(i: Identifier, signer_set: &[Identifier]) -> C::Scalar {
    let i_s = C::Scalar::from(i as u64);
    let mut num = C::Scalar::ONE;
    let mut den = C::Scalar::ONE;

    // Accumulate numerator and denominator separately so the whole product
    // needs a single field inversion instead of one per term.
    for j in signer_set {
        if *j == i {
            continue;
        }

        let j_s = C::Scalar::from(*j as u64);
        num *= j_s;
        den *= j_s - i_s;
    }

    num * den.invert().unwrap()
}

pub(crate) fn delta<C: Ciphersuite>(i: Identifier, j: Identifier) -> C::Scalar {
    if i > j {
        C::Scalar::ONE
    } else {
        -C::Scalar::ONE
    }
}

/// Binding factor `b = H_non(vk, S, m, {D_j, E_j})`.
///
/// The single source of truth for the FROST binding factor: both `sign` and the
/// identifiable-abort path derive `b` here, so the two can never drift apart.
pub(crate) fn binding_factor<C: Ciphersuite>(
    verifying_key: &C::Point,
    signer_set_bytes: &[u8],
    message: &[u8; 32],
    commitments_bytes: &[u8],
) -> C::Scalar {
    C::hash_to_scalar(&[
        C::CONTEXT.as_bytes(),
        b"/Hnon",
        &C::point_bytes(verifying_key),
        signer_set_bytes,
        message,
        commitments_bytes,
    ])
}

/// Hasher pre-loaded with the shared prefix of the blinding value
/// `B_{i,j} = H_s(k_{i,j}, {D_\ell, E_\ell}, m, S)`. Clone it and `finish_with`
/// the peer key `k_{i,j}` to obtain `B_{i,j}`.
///
/// Signing, IA round 1, and the decision phase all derive their blinding values
/// through this one prefix, which keeps the honest pairwise commitments equal.
pub(crate) fn blinding_base<C: Ciphersuite>(
    commitments_bytes: &[u8],
    message: &[u8; 32],
    signer_set_bytes: &[u8],
) -> C::Hasher {
    let mut base = C::Hasher::new();
    base.update(C::CONTEXT.as_bytes());
    base.update(b"/Hs");
    base.update(commitments_bytes);
    base.update(message);
    base.update(signer_set_bytes);
    base
}

/// Commitment randomness `omega_{i,j} = H_IA(k_{i,j}, view)` for the IA Pedersen
/// commitments, derived identically in IA round 1 and the decision phase.
pub(crate) fn blinding_randomizer<C: Ciphersuite>(k_ij: &[u8; 32], view_bytes: &[u8]) -> C::Scalar {
    C::hash_to_scalar(&[C::CONTEXT.as_bytes(), b"/HIA", k_ij, view_bytes])
}

pub(crate) fn encode_signer_set(ids: &[Identifier]) -> Vec<u8> {
    let mut out = Vec::new();

    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }

    out
}

pub fn encode_commitments<C: Ciphersuite>(
    commitments: &BTreeMap<Identifier, SigningCommitments<C>>,
) -> Vec<u8> {
    let mut out = Vec::new();

    for (id, c) in commitments {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&C::point_bytes(&c.D));
        out.extend_from_slice(&C::point_bytes(&c.E));
    }

    out
}

pub fn pedersen_commit<C: Ciphersuite>(
    value: C::Scalar,
    blinding: C::Scalar,
    h: C::Point,
) -> C::Point {
    C::mul_generator(&value) + h * blinding
}

/// Commitment `K_{i,j} = H_pk(k_{i,j})` to a 32-byte pairwise key, derived
/// through the ciphersuite's own hash family (no hardcoded hash).
pub fn hash_pairwise_key_commitment<C: Ciphersuite>(k_ij: &[u8; 32]) -> [u8; 32] {
    C::hash_commitment(&[C::CONTEXT.as_bytes(), b"/Hvk", k_ij])
}

pub fn scalar_bytes<C: Ciphersuite>(scalar: &C::Scalar) -> Vec<u8> {
    scalar.to_repr().as_ref().to_vec()
}

pub fn scalar_to_hex<C: Ciphersuite>(scalar: &C::Scalar) -> String {
    hex::encode(scalar.to_repr().as_ref())
}

pub fn scalar_from_hex<C: Ciphersuite>(
    hex_string: &str,
) -> Result<C::Scalar, Box<dyn std::error::Error>> {
    let bytes_vec = hex::decode(hex_string)?;

    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    if bytes_vec.len() != repr.as_ref().len() {
        return Err("scalar hex has wrong length for this ciphersuite".into());
    }
    repr.as_mut().copy_from_slice(&bytes_vec);

    Option::<C::Scalar>::from(C::Scalar::from_repr(repr))
        .ok_or_else(|| "scalar is not canonical modulo the group order".into())
}
