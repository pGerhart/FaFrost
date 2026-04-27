use k256::ProjectivePoint;

use crate::keygen::PublicKeyPackage;
use crate::sign::Signature;

pub fn verify(signature: &Signature, message: &[u8; 32], pubkeys: &PublicKeyPackage) -> bool {
    #[cfg(feature = "bip340")]
    if crate::bip340::has_odd_y(&signature.R) {
        return false;
    }

    let c = pubkeys.challenge_scalar(&signature.R, message);

    ProjectivePoint::GENERATOR * signature.z == signature.R + pubkeys.verifying_key * c
}
