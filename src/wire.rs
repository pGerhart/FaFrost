//! Canonical byte encodings for the protocol wire messages.
//!
//! Each `to_bytes` is a fixed-length concatenation of compressed group elements
//! and scalars in the ciphersuite's canonical encoding; each `from_bytes` rejects
//! wrong-length or non-canonical inputs with [`Error::MalformedEncoding`].
//! Scheme-specific signature formats (RFC 8032, BIP-340) are produced by the
//! per-ciphersuite serialisers in the `ed25519` / `bip340` modules; the
//! [`Signature`] encoding here is the curve-agnostic `R \Vert z`.
#![allow(non_snake_case)]

use core::fmt;
use std::collections::BTreeMap;
use std::vec::Vec;

use ff::PrimeField;
use group::GroupEncoding;

use crate::ciphersuite::Ciphersuite;
use crate::error::{Error, Result};
use crate::keygen::Identifier;
use crate::sign::{Signature, SignatureShare, SigningCommitments};

/// Canonical byte encoding of the round-1 commitment map, `id \Vert D \Vert E`
/// per signer in identifier order. Used as a hashing input for the binding
/// factor and IA transcripts, and by the benchmarks.
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

/// Canonical serialized length of a group element for this ciphersuite.
pub fn point_len<C: Ciphersuite>() -> usize {
    <C::Point as GroupEncoding>::Repr::default().as_ref().len()
}

/// Canonical serialized length of a scalar for this ciphersuite.
pub fn scalar_len<C: Ciphersuite>() -> usize {
    <C::Scalar as PrimeField>::Repr::default().as_ref().len()
}

/// Canonical little/big-endian scalar bytes.
pub fn scalar_bytes<C: Ciphersuite>(scalar: &C::Scalar) -> Vec<u8> {
    scalar.to_repr().as_ref().to_vec()
}

/// Deserialize a group element from its canonical encoding, rejecting
/// wrong-length or non-canonical (e.g. off-curve) inputs.
pub fn point_from_bytes<C: Ciphersuite>(bytes: &[u8]) -> Option<C::Point> {
    let mut repr = <C::Point as GroupEncoding>::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return None;
    }
    repr.as_mut().copy_from_slice(bytes);
    Option::from(C::Point::from_bytes(&repr))
}

/// Deserialize a scalar from its canonical encoding, rejecting wrong-length or
/// non-canonical (>= group order) inputs.
pub fn scalar_from_bytes<C: Ciphersuite>(bytes: &[u8]) -> Option<C::Scalar> {
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return None;
    }
    repr.as_mut().copy_from_slice(bytes);
    Option::from(C::Scalar::from_repr(repr))
}

/// Hex encoding of a scalar (used for the serialized key files).
pub fn scalar_to_hex<C: Ciphersuite>(scalar: &C::Scalar) -> String {
    hex::encode(scalar.to_repr().as_ref())
}

/// Parse a scalar from hex, rejecting wrong-length or non-canonical inputs.
pub fn scalar_from_hex<C: Ciphersuite>(
    hex_string: &str,
) -> core::result::Result<C::Scalar, Box<dyn std::error::Error>> {
    let bytes_vec = hex::decode(hex_string)?;
    scalar_from_bytes::<C>(&bytes_vec)
        .ok_or_else(|| "scalar hex has wrong length or is non-canonical".into())
}

impl<C: Ciphersuite> SigningCommitments<C> {
    /// Canonical wire encoding `D \Vert E` (two compressed group elements).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = C::point_bytes(&self.D);
        out.extend_from_slice(&C::point_bytes(&self.E));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let plen = point_len::<C>();
        if bytes.len() != 2 * plen {
            return Err(Error::MalformedEncoding);
        }
        let D = point_from_bytes::<C>(&bytes[..plen]).ok_or(Error::MalformedEncoding)?;
        let E = point_from_bytes::<C>(&bytes[plen..]).ok_or(Error::MalformedEncoding)?;
        Ok(Self { D, E })
    }
}

impl<C: Ciphersuite> SignatureShare<C> {
    /// Canonical wire encoding `\mathrm{id} \Vert R \Vert z` (2-byte identifier,
    /// one compressed group element, one scalar).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.identifier.to_be_bytes().to_vec();
        out.extend_from_slice(&C::point_bytes(&self.R));
        out.extend_from_slice(&scalar_bytes::<C>(&self.z));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (plen, slen) = (point_len::<C>(), scalar_len::<C>());
        if bytes.len() != 2 + plen + slen {
            return Err(Error::MalformedEncoding);
        }
        let identifier = Identifier::from_be_bytes([bytes[0], bytes[1]]);
        let R = point_from_bytes::<C>(&bytes[2..2 + plen]).ok_or(Error::MalformedEncoding)?;
        let z = scalar_from_bytes::<C>(&bytes[2 + plen..]).ok_or(Error::MalformedEncoding)?;
        Ok(Self { identifier, R, z })
    }
}

impl<C: Ciphersuite> Signature<C> {
    /// Curve-agnostic wire encoding `R \Vert z`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = C::point_bytes(&self.R);
        out.extend_from_slice(&scalar_bytes::<C>(&self.z));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (plen, slen) = (point_len::<C>(), scalar_len::<C>());
        if bytes.len() != plen + slen {
            return Err(Error::MalformedEncoding);
        }
        let R = point_from_bytes::<C>(&bytes[..plen]).ok_or(Error::MalformedEncoding)?;
        let z = scalar_from_bytes::<C>(&bytes[plen..]).ok_or(Error::MalformedEncoding)?;
        Ok(Self { R, z })
    }
}

// `Debug` prints the hex of the wire encoding. These values are public protocol
// data, not secrets.
impl<C: Ciphersuite> fmt::Debug for SigningCommitments<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningCommitments({})", hex::encode(self.to_bytes()))
    }
}

impl<C: Ciphersuite> fmt::Debug for SignatureShare<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureShare({})", hex::encode(self.to_bytes()))
    }
}

impl<C: Ciphersuite> fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.to_bytes()))
    }
}
