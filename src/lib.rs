pub mod bip340;
pub mod ciphersuite;
pub mod ed25519;
pub mod ia;
pub mod keygen;
pub mod secp256k1;
pub mod sign;
pub mod utils;
pub mod verify;

pub use ciphersuite::{Ciphersuite, ScalarHasher};
pub use ed25519::Ed25519;
pub use secp256k1::{Secp256k1Bip340, Secp256k1Plain};

pub use ia::*;
pub use keygen::*;
pub use sign::*;
pub use utils::*;
pub use verify::*;

// Backend-specific serialisers/verifiers live in their modules to avoid name
// clashes (both `bip340` and `ed25519` expose a `signature_to_bytes`):
//   fafrost::bip340::{signature_to_bytes, bip340_verify_bytes, xonly_pubkey, ..}
//   fafrost::ed25519::{signature_to_bytes, ed25519_verify_bytes, verifying_key_bytes}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ff::Field;
    use rand_core::OsRng;

    use crate::ciphersuite::Ciphersuite;
    use crate::ed25519::Ed25519;
    use crate::ia::{decide, ia1, ia2, IA1Message};
    use crate::keygen::{generate_with_dealer, KeyPackage, PublicKeyPackage};
    use crate::secp256k1::{Secp256k1Bip340, Secp256k1Plain};
    use crate::sign::{aggregate, commit, sign, SignatureShare, SigningPackage, Signature};
    use crate::verify::verify;

    /// One full signing session, retaining every intermediate needed by the
    /// signing, tampering and identifiable-abort tests.
    struct Session<C: Ciphersuite> {
        shares: BTreeMap<u16, KeyPackage<C>>,
        pubkeys: PublicKeyPackage<C>,
        signing_package: SigningPackage<C>,
        signature_shares: BTreeMap<u16, SignatureShare<C>>,
    }

    fn run<C: Ciphersuite>(max: u16, min: u16, signer_ids: &[u16], message: [u8; 32]) -> Session<C> {
        let mut rng = OsRng;

        let (shares, pubkeys) = generate_with_dealer::<C, _>(max, min, &mut rng);

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for &id in signer_ids {
            let (nonce, commitment) = commit::<C, _>(&mut rng);
            nonces.insert(id, nonce);
            commitments.insert(id, commitment);
        }

        let signing_package = SigningPackage::<C> {
            message,
            signing_commitments: commitments,
            partial_verification_keys: pubkeys.partial_verification_keys.clone(),
        };

        let mut signature_shares = BTreeMap::new();

        for &id in signer_ids {
            let share = sign(
                &signing_package,
                nonces.get(&id).unwrap(),
                shares.get(&id).unwrap(),
                &pubkeys,
            );
            signature_shares.insert(id, share);
        }

        Session {
            shares,
            pubkeys,
            signing_package,
            signature_shares,
        }
    }

    fn signs_and_verifies<C: Ciphersuite>(max: u16, min: u16, ids: &[u16]) {
        let message = [42u8; 32];
        let s = run::<C>(max, min, ids, message);
        let sig = aggregate(&s.signing_package, &s.signature_shares);
        assert!(verify(&sig, &message, &s.pubkeys));
        assert!(!verify(&sig, &[7u8; 32], &s.pubkeys));
    }

    fn tampered_share_fails<C: Ciphersuite>() {
        let message = [9u8; 32];
        let mut s = run::<C>(3, 2, &[1, 2], message);
        s.signature_shares.get_mut(&1).unwrap().z += C::Scalar::ONE;
        let sig = aggregate(&s.signing_package, &s.signature_shares);
        assert!(!verify(&sig, &message, &s.pubkeys));
    }

    fn ia_identifies_tampered_share<C: Ciphersuite>() {
        use std::collections::BTreeSet;

        let mut rng = OsRng;
        let message = [99u8; 32];
        let mut s = run::<C>(3, 2, &[1, 2], message);

        s.signature_shares.get_mut(&1).unwrap().z += C::Scalar::ONE;
        let bad = aggregate(&s.signing_package, &s.signature_shares);
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
            );
            ia1_messages.insert(id, msg);
        }

        let mut ia2_decisions = BTreeMap::new();
        for id in [1u16, 2u16] {
            let decision = ia2(s.shares.get(&id).unwrap(), &s.signing_package, &ia1_messages);
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

    // --- generic Schnorr over secp256k1 -------------------------------------
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

    // --- Bitcoin / BIP-340 --------------------------------------------------
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

    // --- Ed25519 ------------------------------------------------------------
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

    /// The convincing artifact: a FaFROST threshold signature under the Ed25519
    /// ciphersuite is accepted by the independent `ed25519-dalek` verifier,
    /// including the strict RFC 8032 path (`verify_strict`).
    #[test]
    fn ed25519_interop_with_dalek() {
        use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};

        let message = [0x24u8; 32];
        let s = run::<Ed25519>(3, 2, &[1, 2], message);
        let sig: Signature<Ed25519> = aggregate(&s.signing_package, &s.signature_shares);

        // internal verifier
        assert!(verify(&sig, &message, &s.pubkeys));

        let vk_bytes = crate::ed25519::verifying_key_bytes(&s.pubkeys);
        let sig_bytes = crate::ed25519::signature_to_bytes(&sig);

        // our own standalone RFC 8032 verifier
        assert!(crate::ed25519::ed25519_verify_bytes(
            &sig_bytes, &message, &vk_bytes
        ));

        // independent implementation: ed25519-dalek, strict and non-strict
        let vk = VerifyingKey::from_bytes(&vk_bytes).expect("valid Ed25519 public key");
        let dalek_sig = DalekSig::from_bytes(&sig_bytes);
        assert!(
            vk.verify_strict(&message, &dalek_sig).is_ok(),
            "ed25519-dalek verify_strict must accept the FaFROST signature"
        );
        assert!(vk.verify(&message, &dalek_sig).is_ok());
    }

    /// `aggregate` must reject an incomplete set of signature shares.
    #[test]
    fn aggregate_rejects_missing_share() {
        let message = [11u8; 32];
        let s = run::<Secp256k1Plain>(3, 2, &[1, 2], message);

        let mut incomplete = BTreeMap::new();
        incomplete.insert(1u16, s.signature_shares.get(&1).unwrap().clone());

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(|| aggregate(&s.signing_package, &incomplete));
        std::panic::set_hook(prev_hook);
        assert!(
            result.is_err(),
            "aggregate must reject incomplete signature shares"
        );
    }
}
