use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::vec::Vec;

use k256::{
    FieldBytes, ProjectivePoint, Scalar, Secp256k1, U256,
    elliptic_curve::{
        Field, PrimeField,
        group::prime::PrimeCurveAffine,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
};

use rand_core::{CryptoRng, RngCore};

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

pub type Identifier = u16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub scheme: String,
    pub max_signers: u16,
    pub min_signers: u16,
    pub secret_key_hex: String,
    pub verifying_key_hex: String,
    pub bip340: bool,
}

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
    let sk = Scalar::random(&mut *rng);
    generate_with_dealer_from_secret(sk, max_signers, min_signers, rng)
}

pub fn generate_with_dealer_from_secret<R: RngCore + CryptoRng>(
    secret_key: Scalar,
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
    assert!(min_signers <= max_signers);

    let sk = secret_key;
    let vk_raw = ProjectivePoint::GENERATOR * sk;

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

pub fn write_key_yaml<P: AsRef<Path>>(
    path: P,
    secret_key: Scalar,
    max_signers: u16,
    min_signers: u16,
) -> Result<StoredKey, Box<dyn std::error::Error>> {
    assert!(min_signers <= max_signers);

    let vk_raw = ProjectivePoint::GENERATOR * secret_key;

    #[cfg(feature = "bip340")]
    let (secret_key, verifying_key) = if crate::bip340::has_odd_y(&vk_raw) {
        (-secret_key, -vk_raw)
    } else {
        (secret_key, vk_raw)
    };
    #[cfg(not(feature = "bip340"))]
    let verifying_key = vk_raw;

    let stored_key = StoredKey {
        scheme: "FaFROST-secp256k1-SHA256".to_string(),
        max_signers,
        min_signers,
        secret_key_hex: scalar_to_hex(&secret_key),
        verifying_key_hex: hex::encode(point_bytes(&verifying_key)),
        bip340: cfg!(feature = "bip340"),
    };

    let yaml = serde_yaml::to_string(&stored_key)?;
    fs::write(path, yaml)?;
    Ok(stored_key)
}

pub fn read_key_yaml<P: AsRef<Path>>(path: P) -> Result<StoredKey, Box<dyn std::error::Error>> {
    let yaml = fs::read_to_string(path)?;
    let stored_key: StoredKey = serde_yaml::from_str(&yaml)?;
    validate_stored_key(&stored_key)?;
    Ok(stored_key)
}

pub fn generate_with_dealer_from_key_yaml<P: AsRef<Path>, R: RngCore + CryptoRng>(
    path: P,
    rng: &mut R,
) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), Box<dyn std::error::Error>> {
    let stored_key = read_key_yaml(path)?;
    validate_stored_key(&stored_key)?;
    let secret_key = scalar_from_hex(&stored_key.secret_key_hex)?;

    let (shares, pubkeys) = generate_with_dealer_from_secret(
        secret_key,
        stored_key.max_signers,
        stored_key.min_signers,
        rng,
    );

    let regenerated_vk_hex = hex::encode(point_bytes(&pubkeys.verifying_key));
    if regenerated_vk_hex != stored_key.verifying_key_hex {
        return Err(
            "stored key YAML is inconsistent: verifying_key_hex does not match secret_key_hex"
                .into(),
        );
    }

    Ok((shares, pubkeys))
}

pub fn validate_stored_key(stored_key: &StoredKey) -> Result<(), Box<dyn std::error::Error>> {
    if stored_key.scheme != "FaFROST-secp256k1-SHA256" {
        return Err("unsupported stored key scheme".into());
    }

    if stored_key.min_signers == 0 {
        return Err("stored key YAML is invalid: min_signers must be at least 1".into());
    }

    if stored_key.max_signers == 0 {
        return Err("stored key YAML is invalid: max_signers must be at least 1".into());
    }

    if stored_key.min_signers > stored_key.max_signers {
        return Err("stored key YAML is invalid: min_signers exceeds max_signers".into());
    }

    if stored_key.bip340 != cfg!(feature = "bip340") {
        return Err("stored key YAML was created with a different bip340 feature setting".into());
    }

    let secret_key = scalar_from_hex(&stored_key.secret_key_hex)?;
    let vk_raw = ProjectivePoint::GENERATOR * secret_key;

    #[cfg(feature = "bip340")]
    let verifying_key = if crate::bip340::has_odd_y(&vk_raw) {
        -vk_raw
    } else {
        vk_raw
    };
    #[cfg(not(feature = "bip340"))]
    let verifying_key = vk_raw;

    let regenerated_vk_hex = hex::encode(point_bytes(&verifying_key));
    if regenerated_vk_hex != stored_key.verifying_key_hex {
        return Err(
            "stored key YAML is inconsistent: verifying_key_hex does not match secret_key_hex"
                .into(),
        );
    }

    Ok(())
}

pub fn generate_with_dealer_and_write_key_yaml<P: AsRef<Path>, R: RngCore + CryptoRng>(
    path: P,
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> Result<
    (
        BTreeMap<Identifier, KeyPackage>,
        PublicKeyPackage,
        StoredKey,
    ),
    Box<dyn std::error::Error>,
> {
    let secret_key = Scalar::random(&mut *rng);
    let stored_key = write_key_yaml(path, secret_key, max_signers, min_signers)?;
    let normalized_secret_key = scalar_from_hex(&stored_key.secret_key_hex)?;
    let (shares, pubkeys) =
        generate_with_dealer_from_secret(normalized_secret_key, max_signers, min_signers, rng);

    Ok((shares, pubkeys, stored_key))
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
