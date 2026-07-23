use bitcoin::{Address, Network, XOnlyPublicKey};
use fafrost::Secp256k1Bip340;
use fafrost::keygen::{generate_with_dealer_from_key_yaml, read_key_yaml};
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fafrost-key.yaml".to_string());

    let network = match std::env::args().nth(2).as_deref() {
        Some("testnet4") => Network::Testnet4,
        Some("signet") => Network::Signet,
        Some("regtest") => Network::Regtest,
        _ => Network::Testnet,
    };

    // read_key_yaml validates the scheme matches the Secp256k1Bip340 ciphersuite.
    let stored_key = read_key_yaml::<Secp256k1Bip340, _>(&path)?;

    let mut rng = OsRng;
    let (_shares, pubkeys) =
        generate_with_dealer_from_key_yaml::<Secp256k1Bip340, _, _>(&path, &mut rng)?;

    let xonly_bytes = fafrost::bip340::x_only_bytes(&pubkeys.verifying_key);
    let xonly = XOnlyPublicKey::from_slice(&xonly_bytes)?;

    let address = Address::p2tr(
        &bitcoin::secp256k1::Secp256k1::verification_only(),
        xonly,
        None,
        network,
    );

    println!("compressed verifying key: {}", stored_key.verifying_key_hex);
    println!("x-only public key: {}", hex::encode(xonly_bytes));
    println!("taproot address: {}", address);

    Ok(())
}
