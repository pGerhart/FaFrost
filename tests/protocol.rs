//! End-to-end protocol tests over the three ciphersuites: signing and
//! verification, tamper rejection, identifiable abort, and RFC 8032 interop.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::run;
use ff::Field;

use fafrost::ia::{IA1Message, decide, ia1, ia2};
use fafrost::sign::{Signature, aggregate};
use fafrost::verify::verify;
use fafrost::{Ciphersuite, Ed25519, Secp256k1Bip340, Secp256k1Plain};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

fn signs_and_verifies<C: Ciphersuite>(max: u16, min: u16, ids: &[u16]) {
    let message = [42u8; 32];
    let s = run::<C>(max, min, ids, message);
    let sig = aggregate(&s.signing_package, &s.signature_shares).unwrap();
    assert!(verify(&sig, &message, &s.pubkeys));
    assert!(!verify(&sig, &[7u8; 32], &s.pubkeys));
}

fn tampered_share_fails<C: Ciphersuite>() {
    let message = [9u8; 32];
    let mut s = run::<C>(3, 2, &[1, 2], message);
    s.signature_shares.get_mut(&1).unwrap().z += C::Scalar::ONE;
    let sig = aggregate(&s.signing_package, &s.signature_shares).unwrap();
    assert!(!verify(&sig, &message, &s.pubkeys));
}

fn ia_identifies_tampered_share<C: Ciphersuite>() {
    let mut rng = UnwrapErr(SysRng);
    let message = [99u8; 32];
    let mut s = run::<C>(3, 2, &[1, 2], message);

    s.signature_shares.get_mut(&1).unwrap().z += C::Scalar::ONE;
    let bad = aggregate(&s.signing_package, &s.signature_shares).unwrap();
    assert!(!verify(&bad, &message, &s.pubkeys));

    let mut ia1_messages: BTreeMap<u16, IA1Message<C>> = BTreeMap::new();
    for id in [1u16, 2u16] {
        let msg = ia1(
            &s.signing_package,
            s.signature_shares.get(&id).unwrap(),
            s.shares.get(&id).unwrap(),
            &s.pubkeys,
            &s.signature_shares,
            &mut rng,
        )
        .unwrap();
        ia1_messages.insert(id, msg);
    }

    let mut ia2_decisions = BTreeMap::new();
    for id in [1u16, 2u16] {
        let decision = ia2(
            s.shares.get(&id).unwrap(),
            &s.signing_package,
            &ia1_messages,
        )
        .unwrap();
        ia2_decisions.insert(id, decision);
    }

    let malicious = decide(
        &s.signing_package,
        &s.pubkeys,
        &s.signature_shares,
        &ia1_messages,
        &ia2_decisions,
    );

    let mut expected = BTreeSet::new();
    expected.insert(1u16);
    assert_eq!(malicious, expected);
}

#[test]
fn plain_two_of_three() {
    signs_and_verifies::<Secp256k1Plain>(3, 2, &[1, 3]);
}
#[test]
fn plain_three_of_five() {
    signs_and_verifies::<Secp256k1Plain>(5, 3, &[1, 2, 5]);
}
#[test]
fn plain_tamper() {
    tampered_share_fails::<Secp256k1Plain>();
}
#[test]
fn plain_ia() {
    ia_identifies_tampered_share::<Secp256k1Plain>();
}

#[test]
fn bip340_two_of_three() {
    signs_and_verifies::<Secp256k1Bip340>(3, 2, &[1, 3]);
}
#[test]
fn bip340_three_of_five() {
    signs_and_verifies::<Secp256k1Bip340>(5, 3, &[1, 2, 5]);
}
#[test]
fn bip340_tamper() {
    tampered_share_fails::<Secp256k1Bip340>();
}
#[test]
fn bip340_ia() {
    ia_identifies_tampered_share::<Secp256k1Bip340>();
}

#[test]
fn ed25519_two_of_three() {
    signs_and_verifies::<Ed25519>(3, 2, &[1, 3]);
}
#[test]
fn ed25519_three_of_five() {
    signs_and_verifies::<Ed25519>(5, 3, &[1, 2, 5]);
}
#[test]
fn ed25519_tamper() {
    tampered_share_fails::<Ed25519>();
}
#[test]
fn ed25519_ia() {
    ia_identifies_tampered_share::<Ed25519>();
}

/// An Ed25519-ciphersuite threshold signature must be accepted by the
/// independent `ed25519-dalek` verifier, `verify_strict` included.
#[test]
fn ed25519_interop_with_dalek() {
    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};

    let message = [0x24u8; 32];
    let s = run::<Ed25519>(3, 2, &[1, 2], message);
    let sig: Signature<Ed25519> = aggregate(&s.signing_package, &s.signature_shares).unwrap();

    assert!(verify(&sig, &message, &s.pubkeys));

    let vk_bytes = fafrost::ed25519::verifying_key_bytes(&s.pubkeys);
    let sig_bytes = fafrost::ed25519::signature_to_bytes(&sig);

    assert!(fafrost::ed25519::ed25519_verify_bytes(
        &sig_bytes, &message, &vk_bytes
    ));

    let vk = VerifyingKey::from_bytes(&vk_bytes).expect("valid Ed25519 public key");
    let dalek_sig = DalekSig::from_bytes(&sig_bytes);
    assert!(
        vk.verify_strict(&message, &dalek_sig).is_ok(),
        "ed25519-dalek verify_strict must accept the FaFROST signature"
    );
    assert!(vk.verify(&message, &dalek_sig).is_ok());
}
