pub mod bip340;
pub mod ia;
pub mod keygen;
pub mod sign;
pub mod utils;
pub mod verify;

pub use bip340::*;
pub use ia::*;
pub use keygen::*;
pub use sign::*;
pub use utils::*;
pub use verify::*;

#[cfg(test)]
mod tests {
    extern crate alloc;
    use std::collections::BTreeMap;

    use rand_core::OsRng;

    use crate::keygen::generate_with_dealer;
    use crate::sign::{SignatureShare, SigningPackage, aggregate, commit, sign};
    use crate::verify::verify;

    #[test]
    fn two_of_three_signature_verifies() {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer(3, 2, &mut rng);

        let signer_ids = [1u16, 3u16];
        let message = [42u8; 32];

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for id in signer_ids {
            let (nonce, commitment) = commit(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares = BTreeMap::new();

        for id in signer_ids {
            let share = sign(
                &signing_package,
                nonces.get(&id).unwrap(),
                shares.get(&id).unwrap(),
                &pubkeys,
            );

            signature_shares.insert(id, share);
        }

        let sig = aggregate(&signing_package, &signature_shares);

        assert!(verify(&sig, &message, &pubkeys));
    }

    #[test]
    fn three_of_five_signature_verifies() {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer(5, 3, &mut rng);

        let signer_ids = [1u16, 2u16, 5u16];
        let message = [7u8; 32];

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for id in signer_ids {
            let (nonce, commitment) = commit(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares = BTreeMap::new();

        for id in signer_ids {
            let share = sign(
                &signing_package,
                nonces.get(&id).unwrap(),
                shares.get(&id).unwrap(),
                &pubkeys,
            );

            signature_shares.insert(id, share);
        }

        let sig = aggregate(&signing_package, &signature_shares);

        assert!(verify(&sig, &message, &pubkeys));
    }

    #[test]
    fn signature_fails_for_wrong_message() {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer(3, 2, &mut rng);

        let signer_ids = [1u16, 2u16];
        let message = [1u8; 32];
        let wrong_message = [2u8; 32];

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for id in signer_ids {
            let (nonce, commitment) = commit(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares = BTreeMap::new();

        for id in signer_ids {
            let share = sign(
                &signing_package,
                nonces.get(&id).unwrap(),
                shares.get(&id).unwrap(),
                &pubkeys,
            );

            signature_shares.insert(id, share);
        }

        let sig = aggregate(&signing_package, &signature_shares);

        assert!(!verify(&sig, &wrong_message, &pubkeys));
    }

    #[test]
    fn tampered_signature_share_fails() {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer(3, 2, &mut rng);

        let signer_ids = [1u16, 2u16];
        let message = [9u8; 32];

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for id in signer_ids {
            let (nonce, commitment) = commit(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares: BTreeMap<u16, SignatureShare> = BTreeMap::new();

        for id in signer_ids {
            let share = sign(
                &signing_package,
                nonces.get(&id).unwrap(),
                shares.get(&id).unwrap(),
                &pubkeys,
            );

            signature_shares.insert(id, share);
        }

        signature_shares.get_mut(&1).unwrap().z += k256::Scalar::ONE;

        let sig = aggregate(&signing_package, &signature_shares);

        assert!(!verify(&sig, &message, &pubkeys));
    }

    #[test]
    fn aggregate_rejects_missing_share() {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer(3, 2, &mut rng);

        let signer_ids = [1u16, 2u16];
        let message = [11u8; 32];

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for id in signer_ids {
            let (nonce, commitment) = commit(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares = BTreeMap::new();

        let id = 1u16;
        let share = sign(
            &signing_package,
            nonces.get(&id).unwrap(),
            shares.get(&id).unwrap(),
            &pubkeys,
        );

        signature_shares.insert(id, share);

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(|| aggregate(&signing_package, &signature_shares));
        std::panic::set_hook(prev_hook);
        assert!(
            result.is_err(),
            "aggregate must reject incomplete signature shares"
        );
    }
}
