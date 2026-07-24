//! # FaFrost — fully adaptive Frost threshold Schnorr signatures
//!
//! A curve-agnostic reference implementation of FaFrost, a two-round threshold
//! Schnorr signature scheme with fully adaptive security under AOMDL and an
//! identifiable-abort extension. The protocol logic is generic over a
//! [`Ciphersuite`]; three are provided:
//!
//! - [`Secp256k1Plain`] — generic Schnorr over secp256k1.
//! - [`Secp256k1Bip340`] — Bitcoin/BIP-340 Taproot key-spend signatures.
//! - [`Ed25519`] — RFC 8032 Ed25519; aggregate signatures verify under any
//!   compliant EdDSA verifier.
//!
//! ## Entry points
//!
//! [`keygen`] (idealized dealer), [`sign::commit`] / [`sign::sign`] /
//! [`sign::aggregate`] for the two signing rounds, [`verify()`], and the
//! identifiable-abort rounds in [`ia`]. Message wire formats live in [`wire`].
//! Functions that consume data from a coordinator or from other (possibly
//! malicious) signers return [`Result`] on malformed input; see [`error`].
//!
//! ## Example
//!
//! A full 2-of-3 signing session over the Ed25519 ciphersuite:
//!
//! ```
//! use std::collections::BTreeMap;
//!
//! use fafrost::keygen::generate_with_dealer;
//! use fafrost::sign::{SigningPackage, aggregate, commit, sign};
//! use fafrost::verify::verify;
//! use fafrost::Ed25519;
//! use rand::rngs::SysRng;
//! use rand_core::UnwrapErr;
//!
//! let mut rng = UnwrapErr(SysRng);
//! let message = [0x24u8; 32];
//!
//! // Dealer produces 2-of-3 key shares.
//! let (shares, pubkeys) = generate_with_dealer::<Ed25519, _>(3, 2, &mut rng);
//!
//! // Round 1: signers {1, 2} each publish a nonce commitment.
//! let signers = [1u16, 2u16];
//! let mut nonces = BTreeMap::new();
//! let mut commitments = BTreeMap::new();
//! for &id in &signers {
//!     let (nonce, commitment) = commit::<Ed25519, _>(&mut rng);
//!     nonces.insert(id, nonce);
//!     commitments.insert(id, commitment);
//! }
//!
//! let package = SigningPackage {
//!     message,
//!     signing_commitments: commitments,
//!     partial_verification_keys: pubkeys.partial_verification_keys.clone(),
//! };
//!
//! // Round 2: each signer produces a signature share.
//! let mut signature_shares = BTreeMap::new();
//! for &id in &signers {
//!     let share = sign(&package, &nonces[&id], &shares[&id], &pubkeys).unwrap();
//!     signature_shares.insert(id, share);
//! }
//!
//! // The coordinator aggregates; the signature verifies under the group key.
//! let signature = aggregate(&package, &signature_shares).unwrap();
//! assert!(verify(&signature, &message, &pubkeys));
//! ```
//!
//! ## Side channels
//!
//! Secret-dependent arithmetic runs through the constant-time field and group
//! operations of `k256` and `curve25519-dalek`. Every value the code branches on
//! or indexes with (signer identifiers, the signing set `S`, message lengths) is
//! public protocol data, so control flow does not depend on secret key
//! material or nonces. Secret-holding types ([`keygen::KeyPackage`],
//! [`sign::SigningNonces`], [`keygen::StoredKey`]) zeroize on drop. The
//! `decide` adjudicator and the wire parsers are the only places that branch on
//! attacker-supplied data, and they do so only over public commitments and
//! encodings.

#![forbid(unsafe_code)]

pub mod ciphersuite;
pub mod error;
pub mod ia;
pub mod keygen;
pub mod sign;
pub mod verify;
pub mod wire;

mod utils;

pub use ciphersuite::ed25519::Ed25519;
pub use ciphersuite::secp256k1::{Secp256k1Bip340, Secp256k1Plain};
pub use ciphersuite::{Ciphersuite, ScalarHasher};
pub use error::{Error, Result};

// Re-exported at the crate root so the ciphersuite modules keep their existing
// public paths (`fafrost::bip340`, `fafrost::ed25519`, `fafrost::secp256k1`).
pub use ciphersuite::{bip340, ed25519, secp256k1};

pub use ia::*;
pub use keygen::*;
pub use sign::*;
pub use verify::verify;

// `utils` holds internal protocol helpers; its one public item (`encode_commitments`,
// used by the benches) stays reachable at `fafrost::utils::` rather than the root.

// The serialisers stay unexported at the crate root: both `bip340` and `ed25519`
// define a `signature_to_bytes`, so they are reached through their module path.
