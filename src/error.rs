//! Error type for operations that consume data from other parties.
//!
//! Signing, aggregation, and the identifiable-abort rounds process messages
//! assembled by a coordinator or broadcast by potentially malicious signers.

use core::fmt;

use crate::keygen::Identifier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The signer is not part of the signing package.
    UnknownSigner(Identifier),
    /// A signer's published nonce commitment does not match its stored nonce.
    NonceCommitmentMismatch(Identifier),
    /// The signature shares disagree on the aggregate nonce `R`.
    InconsistentAggregateNonce,
    /// The number of signature shares does not match the number of signers.
    ShareCountMismatch { expected: usize, got: usize },
    /// Aggregation was called without any signature shares.
    NoSignatureShares,
    /// An expected IA round-1 message from a signer is missing.
    MissingIa1Message(Identifier),
    /// A signer's IA message lacks a blinding commitment for the given peer.
    MissingBlindingCommitment { from: Identifier, about: Identifier },
    /// The key package lacks the pairwise key shared with the given peer.
    MissingPairwiseKey(Identifier),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownSigner(id) => {
                write!(f, "signer {id} is not part of the signing package")
            }
            Error::NonceCommitmentMismatch(id) => {
                write!(
                    f,
                    "published nonce commitment for signer {id} does not match its nonce"
                )
            }
            Error::InconsistentAggregateNonce => {
                write!(f, "signature shares disagree on the aggregate nonce R")
            }
            Error::ShareCountMismatch { expected, got } => {
                write!(f, "expected {expected} signature shares, got {got}")
            }
            Error::NoSignatureShares => write!(f, "no signature shares were supplied"),
            Error::MissingIa1Message(id) => {
                write!(f, "missing IA round-1 message from signer {id}")
            }
            Error::MissingBlindingCommitment { from, about } => {
                write!(
                    f,
                    "signer {from} did not commit to a blinding value for peer {about}"
                )
            }
            Error::MissingPairwiseKey(id) => {
                write!(f, "no pairwise key for peer {id} in the key package")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
