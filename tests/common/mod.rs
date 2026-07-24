//! Shared test harness: runs a full dealer keygen and two-round signing session
//! over the public API, returning the intermediates the tests reach into.
#![allow(dead_code)]

use std::collections::BTreeMap;

use fafrost::Ciphersuite;
use fafrost::keygen::{KeyPackage, PublicKeyPackage, generate_with_dealer};
use fafrost::sign::{SignatureShare, SigningPackage, commit, sign};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

pub struct Session<C: Ciphersuite> {
    pub shares: BTreeMap<u16, KeyPackage<C>>,
    pub pubkeys: PublicKeyPackage<C>,
    pub signing_package: SigningPackage<C>,
    pub signature_shares: BTreeMap<u16, SignatureShare<C>>,
}

pub fn run<C: Ciphersuite>(
    max: u16,
    min: u16,
    signer_ids: &[u16],
    message: [u8; 32],
) -> Session<C> {
    let mut rng = UnwrapErr(SysRng);

    let (shares, pubkeys) = generate_with_dealer::<C, _>(max, min, &mut rng);

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in signer_ids {
        let (nonce, commitment) = commit::<C, _>(&mut rng);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let signing_package = SigningPackage::<C> {
        message,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();
    for &id in signer_ids {
        let share = sign(
            &signing_package,
            nonces.get(&id).unwrap(),
            shares.get(&id).unwrap(),
            &pubkeys,
        )
        .unwrap();
        signature_shares.insert(id, share);
    }

    Session {
        shares,
        pubkeys,
        signing_package,
        signature_shares,
    }
}
