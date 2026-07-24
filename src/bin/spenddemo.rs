use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
    absolute::LockTime,
    consensus::encode::serialize,
    opcodes,
    script::Builder,
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use bitcoin_hashes::Hash;
use fafrost::{
    Secp256k1Bip340,
    bip340::{
        bip340_challenge_scalar, bip340_verify_bytes, has_odd_y, signature_to_bytes, x_only_bytes,
    },
    keygen::generate_with_dealer_from_key_yaml,
    sign::{SigningPackage, aggregate, commit, sign},
};
use std::collections::BTreeMap;
use std::str::FromStr;

use k256::elliptic_curve::ops::Reduce;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_file = arg(1, "fafrost-key.yaml");

    let txid = Txid::from_str(&arg(
        2,
        "19649d146d80356696246d527956787fc0eb6d6099a62249d1440344cbf83326",
    ))?;

    let vout = arg(3, "0").parse::<u32>()?;
    let amount_sat = arg(4, "143208").parse::<u64>()?;
    let fee_sat = arg(5, "800").parse::<u64>()?;

    let network = Network::Testnet;
    let mut rng = UnwrapErr(SysRng);

    let (shares, pubkeys) =
        generate_with_dealer_from_key_yaml::<Secp256k1Bip340, _, _>(&key_file, &mut rng)?;

    let internal_xonly = x_only_bytes(&pubkeys.verifying_key);
    let internal = XOnlyPublicKey::from_slice(&internal_xonly)?;

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();

    let funded_address = Address::p2tr(&secp, internal, None, network);

    let prev_txout = TxOut {
        value: Amount::from_sat(amount_sat),
        script_pubkey: funded_address.script_pubkey(),
    };

    let marker = Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_slice(b"FaFROST demo")
        .into_script();

    let send_value = amount_sat
        .checked_sub(fee_sat)
        .ok_or("fee exceeds input amount")?;

    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(send_value),
                script_pubkey: funded_address.script_pubkey(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: marker,
            },
        ],
    };

    let sighash = {
        let mut cache = SighashCache::new(&tx);
        cache.taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[prev_txout]),
            TapSighashType::Default,
        )?
    };

    let msg: [u8; 32] = sighash.to_byte_array();

    let (tweak, tweaked_key) = taproot_tweak(&pubkeys.verifying_key);

    let mut signing_pubkeys = pubkeys.clone();
    signing_pubkeys.verifying_key = tweaked_key;

    let mut signing_shares = shares.clone();

    let q_raw = pubkeys.verifying_key + ProjectivePoint::GENERATOR * tweak;

    let tweak_eff = if has_odd_y(&q_raw) {
        for share in signing_shares.values_mut() {
            share.signing_share = -share.signing_share;
        }
        -tweak
    } else {
        tweak
    };

    let signer_ids = [1u16, 2u16];

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for id in signer_ids {
        let (nonce, commitment) = commit::<Secp256k1Bip340, _>(&mut rng);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let signing_package = SigningPackage {
        message: msg,
        signing_commitments: commitments,
        partial_verification_keys: signing_pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();

    for id in signer_ids {
        let share = sign(
            &signing_package,
            nonces.get(&id).unwrap(),
            signing_shares.get(&id).unwrap(),
            &signing_pubkeys,
        );

        signature_shares.insert(id, share);
    }

    let mut sig = aggregate(&signing_package, &signature_shares);

    let c = bip340_challenge_scalar(
        &x_only_bytes(&sig.R),
        &x_only_bytes(&signing_pubkeys.verifying_key),
        &msg,
    );

    sig.z += c * tweak_eff;

    let sig_bytes = signature_to_bytes(&sig);

    assert!(bip340_verify_bytes(
        &sig_bytes,
        &msg,
        &x_only_bytes(&signing_pubkeys.verifying_key),
    ));

    tx.input[0].witness.push(sig_bytes.to_vec());

    let raw_tx = hex::encode(serialize(&tx));

    println!("funded address: {}", funded_address);
    println!("input txid: {}", txid);
    println!("input vout: {}", vout);
    println!("input amount: {} sats", amount_sat);
    println!("fee: {} sats", fee_sat);
    println!("raw tx:");
    println!("{}", raw_tx);

    Ok(())
}

fn arg(n: usize, default: &str) -> String {
    std::env::args()
        .nth(n)
        .unwrap_or_else(|| default.to_string())
}

fn taproot_tweak(internal_key: &ProjectivePoint) -> (Scalar, ProjectivePoint) {
    let x = x_only_bytes(internal_key);
    let tweak_hash = tagged_hash(b"TapTweak", &x);
    let tweak = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(tweak_hash));

    let q_raw = *internal_key + ProjectivePoint::GENERATOR * tweak;
    let q_even = if has_odd_y(&q_raw) { -q_raw } else { q_raw };

    (tweak, q_even)
}

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);

    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);

    h.finalize().into()
}
