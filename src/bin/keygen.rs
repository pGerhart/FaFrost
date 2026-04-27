use fafrost::keygen::generate_with_dealer_and_write_key_yaml;
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fafrost-key.yaml".to_string());

    let max_signers = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "3".to_string())
        .parse::<u16>()?;

    let min_signers = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "2".to_string())
        .parse::<u16>()?;

    let (_shares, _pubkeys, stored_key) =
        generate_with_dealer_and_write_key_yaml(&path, max_signers, min_signers, &mut rng)?;

    println!("wrote key file: {}", path);
    println!("scheme: {}", stored_key.scheme);
    println!("threshold: {} of {}", min_signers, max_signers);
    println!("verifying key: {}", stored_key.verifying_key_hex);

    #[cfg(feature = "bip340")]
    {
        println!(
            "x-only pubkey: {}",
            hex::encode(fafrost::bip340::x_only_bytes(&pubkeys.verifying_key))
        );
    }

    Ok(())
}
