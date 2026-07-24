//! Known-answer test vectors and wire round-trip checks.
//!
//! Each vector fixes a ChaCha20 seed and message, runs a full dealer keygen and
//! two-round `(3,2)` signing session with signers `{1,2}`, and pins the aggregate
//! signature bytes. A conforming reimplementation that consumes randomness in the
//! same order must reproduce these values, so they double as interoperability
//! anchors and as a regression guard for the serialization format.

use std::collections::BTreeMap;

use fafrost::keygen::generate_with_dealer;
use fafrost::sign::{
    Signature, SignatureShare, SigningCommitments, SigningPackage, aggregate, commit, sign,
};
use fafrost::verify::verify;
use fafrost::{Ciphersuite, Ed25519, Secp256k1Bip340, Secp256k1Plain};
use rand::rngs::ChaCha20Rng;
use rand_core::SeedableRng;

const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const MESSAGE: [u8; 32] = [0x42; 32];

/// Runs a deterministic `(3,2)` signing session over signers `{1,2}` and returns
/// the verified aggregate signature together with its wire encoding.
fn deterministic_signature<C: Ciphersuite>() -> (Signature<C>, fafrost::keygen::PublicKeyPackage<C>)
{
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let (shares, pubkeys) = generate_with_dealer::<C, _>(3, 2, &mut rng);

    let signer_ids = [1u16, 2u16];
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in &signer_ids {
        let (nonce, commitment) = commit::<C, _>(&mut rng);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let signing_package = SigningPackage::<C> {
        message: MESSAGE,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();
    for &id in &signer_ids {
        let share = sign(&signing_package, &nonces[&id], &shares[&id], &pubkeys).unwrap();
        signature_shares.insert(id, share);
    }

    let sig = aggregate(&signing_package, &signature_shares).unwrap();
    assert!(verify(&sig, &MESSAGE, &pubkeys), "own verifier must accept");
    (sig, pubkeys)
}

fn check_vector<C: Ciphersuite>(scheme: &str, expected_hex: &str) {
    let (sig, pubkeys) = deterministic_signature::<C>();
    let got = hex::encode(sig.to_bytes());

    // Uncomment to (re)generate the pinned vectors:
    // println!("{scheme}: {got}");

    assert_eq!(got, expected_hex, "KAT signature mismatch for {scheme}");

    // Wire round-trip: from_bytes(to_bytes(x)) == x and still verifies.
    let reparsed = Signature::<C>::from_bytes(&sig.to_bytes()).expect("round-trip");
    assert!(
        verify(&reparsed, &MESSAGE, &pubkeys),
        "round-tripped signature must verify for {scheme}"
    );
    assert_eq!(hex::encode(reparsed.to_bytes()), expected_hex);
}

#[test]
fn kat_ed25519() {
    check_vector::<Ed25519>("ed25519", ED25519_SIG);
}

#[test]
fn kat_secp256k1_plain() {
    check_vector::<Secp256k1Plain>("secp256k1-plain", SECP_PLAIN_SIG);
}

#[test]
fn kat_secp256k1_bip340() {
    check_vector::<Secp256k1Bip340>("secp256k1-bip340", SECP_BIP340_SIG);
}

/// Serialization is a bijection on well-formed messages, and malformed inputs
/// are rejected rather than accepted or panicking.
#[test]
fn wire_round_trip_and_rejection() {
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let (nonce, commitment) = commit::<Ed25519, _>(&mut rng);
    let _ = nonce;

    let bytes = commitment.to_bytes();
    let reparsed = SigningCommitments::<Ed25519>::from_bytes(&bytes).unwrap();
    assert_eq!(reparsed.to_bytes(), bytes);

    // Truncated and over-long encodings are rejected.
    assert!(SigningCommitments::<Ed25519>::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut too_long = bytes.clone();
    too_long.push(0);
    assert!(SigningCommitments::<Ed25519>::from_bytes(&too_long).is_err());

    // A share round-trips through its wire form.
    let (sig, _) = deterministic_signature::<Ed25519>();
    let share = SignatureShare::<Ed25519> {
        identifier: 7,
        R: sig.R,
        z: sig.z,
    };
    let rt = SignatureShare::<Ed25519>::from_bytes(&share.to_bytes()).unwrap();
    assert_eq!(rt.identifier, 7);
    assert_eq!(rt.to_bytes(), share.to_bytes());
}

// Pinned known-answer vectors (aggregate signature `R \Vert z`, hex).
// ed25519 is 64 bytes (32-byte compressed R, 32-byte scalar); the secp256k1
// suites are 65 bytes (33-byte compressed SEC1 point, 32-byte scalar).
const ED25519_SIG: &str = "dd6feea52b298960e0bf148a602c646a5dd7caceee0415ed68c247540a4c1b40e3c72c80b05b216973b4562e5b1e92024dbfe9d2ec84820f90fcf1d2b73f4e0a";
const SECP_PLAIN_SIG: &str = "02acccb1a41ae207d306b276abbf93b620e217899a4e392413ec58b694fd928d31264f660182135ce654d19860bb1e7ccf318b397166d56d1a142f74f369187ef9";
const SECP_BIP340_SIG: &str = "0237a6c328a9b2848da83ed9c74cdd029cc6d52170e553e4117566d9df21a51088bf1d13b6d728cfa3804f0012d86bed1ac41c27ab93b811e3c92fc459e233c48d";
