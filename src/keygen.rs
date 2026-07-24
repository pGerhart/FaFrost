//! Idealized dealer-based key generation.
#![allow(non_snake_case)]

use crate::ciphersuite::Ciphersuite;
use crate::utils::{hash_pairwise_key_commitment, pedersen_commit};
use crate::wire::{scalar_from_hex, scalar_to_hex};
use ff::Field;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::vec::Vec;
use zeroize::Zeroize;

pub type Identifier = u16;

/// Per-signer secret key packages produced by the dealer, keyed by identifier.
pub type KeyShares<C> = BTreeMap<Identifier, KeyPackage<C>>;

/// Dealer output paired with the serialisable key file it was generated from.
pub type KeySharesWithStored<C> = (KeyShares<C>, PublicKeyPackage<C>, StoredKey);

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub scheme: String,
    pub max_signers: u16,
    pub min_signers: u16,
    pub secret_key_hex: String,
    pub verifying_key_hex: String,
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.secret_key_hex.zeroize();
    }
}

#[derive(Clone)]
pub struct KeyPackage<C: Ciphersuite> {
    pub identifier: Identifier,
    pub signing_share: C::Scalar,
    pub signing_share_blinding: C::Scalar,
    pub pairwise_keys: BTreeMap<Identifier, [u8; 32]>,
}

/// Zeroizes the secret key share, its blinding, and every pairwise key on drop.
impl<C: Ciphersuite> Drop for KeyPackage<C> {
    fn drop(&mut self) {
        self.signing_share.zeroize();
        self.signing_share_blinding.zeroize();
        for key in self.pairwise_keys.values_mut() {
            key.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct PartialVerificationKey<C: Ciphersuite> {
    pub signing_share_commitment: C::Point,
    pub pairwise_key_commitments: BTreeMap<Identifier, [u8; 32]>,
}

#[derive(Clone)]
pub struct PublicKeyPackage<C: Ciphersuite> {
    pub verifying_key: C::Point,
    pub max_signers: u16,
    pub min_signers: u16,
    pub pedersen_h: C::Point,
    pub partial_verification_keys: BTreeMap<Identifier, PartialVerificationKey<C>>,
}

pub fn generate_with_dealer<C: Ciphersuite, R: CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> (KeyShares<C>, PublicKeyPackage<C>) {
    let sk = C::Scalar::random(&mut *rng);
    generate_with_dealer_from_secret::<C, R>(sk, max_signers, min_signers, rng)
}

pub fn generate_with_dealer_from_secret<C: Ciphersuite, R: CryptoRng>(
    secret_key: C::Scalar,
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> (KeyShares<C>, PublicKeyPackage<C>) {
    assert!(min_signers <= max_signers);

    let vk_raw = C::mul_generator(&secret_key);
    let (sk, verifying_key) = C::normalize_keygen(secret_key, vk_raw);

    let pedersen_h = C::pedersen_generator();
    let mut coeffs = Vec::new();
    coeffs.push(sk);

    for _ in 1..min_signers {
        coeffs.push(C::Scalar::random(&mut *rng));
    }

    let mut shares = BTreeMap::new();
    let mut partial_verification_keys = BTreeMap::new();

    for id in 1..=max_signers {
        let x = C::Scalar::from(id as u64);
        let mut y = C::Scalar::ZERO;
        let mut pow = C::Scalar::ONE;

        for a in &coeffs {
            y += *a * pow;
            pow *= x;
        }

        let omega_i = C::Scalar::random(&mut *rng);
        let vki = pedersen_commit::<C>(y, omega_i, pedersen_h);

        shares.insert(
            id,
            KeyPackage::<C> {
                identifier: id,
                signing_share: y,
                signing_share_blinding: omega_i,
                pairwise_keys: BTreeMap::new(),
            },
        );

        partial_verification_keys.insert(
            id,
            PartialVerificationKey::<C> {
                signing_share_commitment: vki,
                pairwise_key_commitments: BTreeMap::new(),
            },
        );
    }

    // Wipe the polynomial; its constant term is the master secret.
    coeffs.zeroize();

    for i in 1..=max_signers {
        for j in (i + 1)..=max_signers {
            let mut k_ij = [0u8; 32];
            rng.fill_bytes(&mut k_ij);

            let K_ij = hash_pairwise_key_commitment::<C>(&k_ij);

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

    let pubkeys = PublicKeyPackage::<C> {
        verifying_key,
        max_signers,
        min_signers,
        pedersen_h,
        partial_verification_keys,
    };

    (shares, pubkeys)
}

pub fn write_key_yaml<C: Ciphersuite, P: AsRef<Path>>(
    path: P,
    secret_key: C::Scalar,
    max_signers: u16,
    min_signers: u16,
) -> Result<StoredKey, Box<dyn std::error::Error>> {
    assert!(min_signers <= max_signers);

    let vk_raw = C::mul_generator(&secret_key);
    let (secret_key, verifying_key) = C::normalize_keygen(secret_key, vk_raw);

    let stored_key = StoredKey {
        scheme: C::SCHEME_ID.to_string(),
        max_signers,
        min_signers,
        secret_key_hex: scalar_to_hex::<C>(&secret_key),
        verifying_key_hex: hex::encode(C::point_bytes(&verifying_key)),
    };

    let yaml = serde_yaml_ng::to_string(&stored_key)?;
    fs::write(path, yaml)?;
    Ok(stored_key)
}

pub fn read_key_yaml<C: Ciphersuite, P: AsRef<Path>>(
    path: P,
) -> Result<StoredKey, Box<dyn std::error::Error>> {
    let yaml = fs::read_to_string(path)?;
    let stored_key: StoredKey = serde_yaml_ng::from_str(&yaml)?;
    validate_stored_key::<C>(&stored_key)?;
    Ok(stored_key)
}

pub fn generate_with_dealer_from_key_yaml<C: Ciphersuite, P: AsRef<Path>, R: CryptoRng>(
    path: P,
    rng: &mut R,
) -> Result<(KeyShares<C>, PublicKeyPackage<C>), Box<dyn std::error::Error>> {
    let stored_key = read_key_yaml::<C, _>(path)?;
    let secret_key = scalar_from_hex::<C>(&stored_key.secret_key_hex)?;

    let (shares, pubkeys) = generate_with_dealer_from_secret::<C, R>(
        secret_key,
        stored_key.max_signers,
        stored_key.min_signers,
        rng,
    );

    let regenerated_vk_hex = hex::encode(C::point_bytes(&pubkeys.verifying_key));
    if regenerated_vk_hex != stored_key.verifying_key_hex {
        return Err(
            "stored key YAML is inconsistent: verifying_key_hex does not match secret_key_hex"
                .into(),
        );
    }

    Ok((shares, pubkeys))
}

pub fn validate_stored_key<C: Ciphersuite>(
    stored_key: &StoredKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if stored_key.scheme != C::SCHEME_ID {
        return Err(format!(
            "unsupported stored key scheme: expected {}, found {}",
            C::SCHEME_ID,
            stored_key.scheme
        )
        .into());
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

    let secret_key = scalar_from_hex::<C>(&stored_key.secret_key_hex)?;
    let vk_raw = C::mul_generator(&secret_key);
    let (_, verifying_key) = C::normalize_keygen(secret_key, vk_raw);

    let regenerated_vk_hex = hex::encode(C::point_bytes(&verifying_key));
    if regenerated_vk_hex != stored_key.verifying_key_hex {
        return Err(
            "stored key YAML is inconsistent: verifying_key_hex does not match secret_key_hex"
                .into(),
        );
    }

    Ok(())
}

pub fn generate_with_dealer_and_write_key_yaml<C: Ciphersuite, P: AsRef<Path>, R: CryptoRng>(
    path: P,
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> Result<KeySharesWithStored<C>, Box<dyn std::error::Error>> {
    let secret_key = C::Scalar::random(&mut *rng);
    let stored_key = write_key_yaml::<C, P>(path, secret_key, max_signers, min_signers)?;
    let normalized_secret_key = scalar_from_hex::<C>(&stored_key.secret_key_hex)?;
    let (shares, pubkeys) = generate_with_dealer_from_secret::<C, R>(
        normalized_secret_key,
        max_signers,
        min_signers,
        rng,
    );

    Ok((shares, pubkeys, stored_key))
}
