//! Negative-path tests: every [`Error`] variant is returned on the matching
//! malformed or adversarial input, and no such input causes a panic.

mod common;

use std::collections::BTreeMap;

use common::{Session, run};
use fafrost::Ed25519;
use fafrost::error::Error;
use fafrost::ia::{IA1Message, ia1, ia2};
use fafrost::keygen::generate_with_dealer;
use fafrost::sign::{Signature, SigningPackage, aggregate, commit, sign};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

const MSG: [u8; 32] = [0x11; 32];

#[test]
fn aggregate_share_count_mismatch() {
    let s = run::<Ed25519>(3, 2, &[1, 2], MSG);
    let mut incomplete = BTreeMap::new();
    incomplete.insert(1u16, s.signature_shares.get(&1).unwrap().clone());

    assert!(matches!(
        aggregate(&s.signing_package, &incomplete),
        Err(Error::ShareCountMismatch {
            expected: 2,
            got: 1
        })
    ));
}

#[test]
fn aggregate_inconsistent_nonce() {
    let mut s = run::<Ed25519>(3, 2, &[1, 2], MSG);
    // Every honest share carries the same aggregate nonce R; break that.
    let r = s.signature_shares.get(&1).unwrap().R;
    s.signature_shares.get_mut(&2).unwrap().R = -r;

    assert!(matches!(
        aggregate(&s.signing_package, &s.signature_shares),
        Err(Error::InconsistentAggregateNonce)
    ));
}

#[test]
fn aggregate_no_shares() {
    let empty = SigningPackage::<Ed25519> {
        message: MSG,
        signing_commitments: BTreeMap::new(),
        partial_verification_keys: BTreeMap::new(),
    };
    assert!(matches!(
        aggregate(&empty, &BTreeMap::new()),
        Err(Error::NoSignatureShares)
    ));
}

#[test]
fn sign_unknown_signer() {
    let mut rng = UnwrapErr(SysRng);
    // The signing package covers {1,2}, but signer 3 also holds a key package.
    let s = run::<Ed25519>(3, 2, &[1, 2], MSG);
    let (nonce, _) = commit::<Ed25519, _>(&mut rng);

    assert!(matches!(
        sign(
            &s.signing_package,
            &nonce,
            s.shares.get(&3).unwrap(),
            &s.pubkeys
        ),
        Err(Error::UnknownSigner(3))
    ));
}

#[test]
fn sign_nonce_commitment_mismatch() {
    let mut rng = UnwrapErr(SysRng);
    let s = run::<Ed25519>(3, 2, &[1, 2], MSG);
    // A fresh nonce whose commitment does not match the one in the package.
    let (wrong, _) = commit::<Ed25519, _>(&mut rng);

    assert!(matches!(
        sign(
            &s.signing_package,
            &wrong,
            s.shares.get(&1).unwrap(),
            &s.pubkeys
        ),
        Err(Error::NonceCommitmentMismatch(1))
    ));
}

#[test]
fn blinding_scalar_missing_pairwise_key() {
    let mut rng = UnwrapErr(SysRng);
    let (shares, _) = generate_with_dealer::<Ed25519, _>(3, 2, &mut rng);
    // Signer 1 holds pairwise keys for {2,3}; a signer set naming peer 99 has none.
    assert!(matches!(
        shares[&1].blinding_scalar(&[1, 99], &[], &MSG),
        Err(Error::MissingPairwiseKey(99))
    ));
}

/// Produce the IA round-1 messages for a tampered `(3,2)` session over `{1,2}`.
fn ia1_messages() -> (BTreeMap<u16, IA1Message<Ed25519>>, Session<Ed25519>) {
    let mut rng = UnwrapErr(SysRng);
    let s = run::<Ed25519>(3, 2, &[1, 2], MSG);
    let mut msgs = BTreeMap::new();
    for id in [1u16, 2u16] {
        let m = ia1(
            &s.signing_package,
            s.signature_shares.get(&id).unwrap(),
            s.shares.get(&id).unwrap(),
            &s.pubkeys,
            &s.signature_shares,
            &mut rng,
        )
        .unwrap();
        msgs.insert(id, m);
    }
    (msgs, s)
}

#[test]
fn ia2_missing_peer_message() {
    let (mut msgs, s) = ia1_messages();
    msgs.remove(&2); // signer 2's IA1 message is absent

    assert!(matches!(
        ia2(s.shares.get(&1).unwrap(), &s.signing_package, &msgs),
        Err(Error::MissingIa1Message(2))
    ));
}

#[test]
fn ia2_missing_blinding_commitment() {
    let (mut msgs, s) = ia1_messages();
    // Drop signer 1's own blinding commitment for peer 2.
    msgs.get_mut(&1).unwrap().blinding_commitments.remove(&2);

    assert!(matches!(
        ia2(s.shares.get(&1).unwrap(), &s.signing_package, &msgs),
        Err(Error::MissingBlindingCommitment { from: 1, about: 2 })
    ));
}

#[test]
fn wire_rejects_malformed() {
    assert!(matches!(
        Signature::<Ed25519>::from_bytes(&[]),
        Err(Error::MalformedEncoding)
    ));
    assert!(matches!(
        Signature::<Ed25519>::from_bytes(&[0u8; 10]),
        Err(Error::MalformedEncoding)
    ));
}
