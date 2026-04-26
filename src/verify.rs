use k256::ProjectivePoint;

use crate::keygen::PublicKeyPackage;
use crate::sign::Signature;

#[cfg(not(feature = "bip340"))]
use crate::sign::{point_bytes, scalar_from_hash};

pub fn verify(signature: &Signature, message: &[u8; 32], pubkeys: &PublicKeyPackage) -> bool {
    #[cfg(feature = "bip340")]
    if crate::bip340::has_odd_y(&signature.R) {
        return false;
    }

    let c = {
        #[cfg(feature = "bip340")]
        {
            let r_x = crate::bip340::x_only_bytes(&signature.R);
            let p_x = crate::bip340::x_only_bytes(&pubkeys.verifying_key);
            crate::bip340::bip340_challenge_scalar(&r_x, &p_x, message)
        }
        #[cfg(not(feature = "bip340"))]
        {
            let vk_bytes = point_bytes(&pubkeys.verifying_key);
            let R_bytes = point_bytes(&signature.R);
            scalar_from_hash(&[
                b"FaFROST/secp256k1/SHA256/Hsig",
                &vk_bytes,
                &R_bytes,
                message,
            ])
        }
    };

    ProjectivePoint::GENERATOR * signature.z == signature.R + pubkeys.verifying_key * c
}
