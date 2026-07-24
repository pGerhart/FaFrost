use crate::ciphersuite::Ciphersuite;
use crate::keygen::PublicKeyPackage;
use crate::sign::Signature;

pub fn verify<C: Ciphersuite>(
    signature: &Signature<C>,
    message: &[u8; 32],
    pubkeys: &PublicKeyPackage<C>,
) -> bool {
    if !C::accept_r(&signature.R) {
        return false;
    }

    let c = C::challenge(&pubkeys.verifying_key, &signature.R, message);

    C::mul_generator(&signature.z) == signature.R + pubkeys.verifying_key * c
}
