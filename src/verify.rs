use k256::ProjectivePoint;

use crate::keygen::PublicKeyPackage;
use crate::sign::{Signature, point_bytes, scalar_from_hash};

pub fn verify(signature: &Signature, message: &[u8; 32], pubkeys: &PublicKeyPackage) -> bool {
    let vk_bytes = point_bytes(&pubkeys.verifying_key);
    let R_bytes = point_bytes(&signature.R);

    let c = scalar_from_hash(&[
        b"FaFROST/secp256k1/SHA256/Hsig",
        &vk_bytes,
        &R_bytes,
        message,
    ]);

    ProjectivePoint::GENERATOR * signature.z == signature.R + pubkeys.verifying_key * c
}
