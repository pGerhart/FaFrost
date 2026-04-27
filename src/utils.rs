use std::collections::BTreeMap;
use std::vec::Vec;

use k256::{
    FieldBytes, ProjectivePoint, Scalar, Secp256k1, U256,
    elliptic_curve::{
        PrimeField,
        group::prime::PrimeCurveAffine,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
};
use sha2::{Digest, Sha256};

use crate::keygen::Identifier;
use crate::sign::SigningCommitments;

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

pub fn encode_commitments(
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

pub fn pedersen_commit(value: Scalar, blinding: Scalar, h: ProjectivePoint) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * value + h * blinding
}

pub fn hash_pairwise_key_commitment(k_ij: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"FaFROST/secp256k1/SHA256/Hvk");
    h.update(k_ij);
    h.finalize().into()
}

pub fn scalar_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_repr().into()
}

pub fn scalar_to_hex(scalar: &Scalar) -> String {
    let bytes: [u8; 32] = scalar.to_repr().into();
    hex::encode(bytes)
}

pub fn scalar_from_hex(hex_string: &str) -> Result<Scalar, Box<dyn std::error::Error>> {
    let bytes_vec = hex::decode(hex_string)?;
    if bytes_vec.len() != 32 {
        return Err("scalar hex must decode to exactly 32 bytes".into());
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&bytes_vec);

    let maybe_scalar = Scalar::from_repr(FieldBytes::from(bytes));
    Option::<Scalar>::from(maybe_scalar)
        .ok_or_else(|| "scalar is not canonical modulo secp256k1 order".into())
}

pub fn scalar_from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(bytes))
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
