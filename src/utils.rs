use std::collections::BTreeMap;
use std::vec::Vec;

use ff::{Field, PrimeField};
use group::Group;

use crate::ciphersuite::Ciphersuite;
use crate::keygen::Identifier;
use crate::sign::SigningCommitments;

pub(crate) fn lagrange<C: Ciphersuite>(i: Identifier, signer_set: &[Identifier]) -> C::Scalar {
    let i_s = C::Scalar::from(i as u64);
    let mut out = C::Scalar::ONE;

    for j in signer_set {
        if *j == i {
            continue;
        }

        let j_s = C::Scalar::from(*j as u64);
        out *= j_s * (j_s - i_s).invert().unwrap();
    }

    out
}

pub(crate) fn delta<C: Ciphersuite>(i: Identifier, j: Identifier) -> C::Scalar {
    if i > j {
        C::Scalar::ONE
    } else {
        -C::Scalar::ONE
    }
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
    C::Point::generator() * value + h * blinding
}

/// Domain-separated `SHA-256` commitment to a 32-byte pairwise key. This is a
/// scheme-internal binding commitment (independent of the signature challenge),
/// so it uses `SHA-256` for every ciphersuite, keyed by the suite context.
pub fn hash_pairwise_key_commitment<C: Ciphersuite>(k_ij: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(C::CONTEXT.as_bytes());
    h.update(b"/Hvk");
    h.update(k_ij);
    h.finalize().into()
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
