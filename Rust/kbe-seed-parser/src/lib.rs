use kaspa_addresses::{Address, Version};
use kaspa_bip32::secp256k1::{self, Secp256k1};
use kaspa_bip32::{ExtendedPrivateKey, Language, Mnemonic};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};

pub fn derive_keys(
    mnemonic_phrase: &str,
) -> Result<(secp256k1::XOnlyPublicKey, secp256k1::SecretKey), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mnemonic = Mnemonic::new(mnemonic_phrase, Language::English)?;
    let seed = mnemonic.to_seed("");
    let xprv = ExtendedPrivateKey::<kaspa_bip32::SecretKey>::new(seed)?;

    let path = "m/44'/111111'/0'/0".parse()?;
    let account_key = xprv.derive_path(&path)?;
    let private_key = account_key.derive_child(0.into())?;

    let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let x_only_pubkey = public_key.x_only_public_key().0;

    Ok((x_only_pubkey, secret_key))
}

pub fn load_account()
-> Result<(Address, secp256k1::SecretKey, NetworkId), Box<dyn std::error::Error>> {
    kbe_utils::load_users_env_file();
    let mnemonic = std::env::var("MNEMONIC")?;

    let network_id = NetworkId::new(NetworkType::Mainnet);
    let (x_public_key, private_key) = derive_keys(&mnemonic)?;
    let derived_address = Address::new(
        network_id.into(),
        Version::PubKey,
        &x_public_key.serialize(),
    );
    println!("\nDerived address: {}", derived_address.to_string());
    Ok((derived_address, private_key, network_id))
}

pub fn load_account2()
-> Result<(Address, secp256k1::SecretKey, NetworkId), Box<dyn std::error::Error>> {
    kbe_utils::load_users_env_file();
    let mnemonic = std::env::var("MNEMONIC2")?;

    let network_id = NetworkId::new(NetworkType::Mainnet);
    let (x_public_key, private_key) = derive_keys(&mnemonic)?;
    let derived_address = Address::new(
        network_id.into(),
        Version::PubKey,
        &x_public_key.serialize(),
    );
    println!("\nDerived address: {}", derived_address.to_string());
    Ok((derived_address, private_key, network_id))
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_derive_keys() {
        let mnemonic = "autumn sure upset hole result toe buddy paddle shiver inside raccoon wrong crop situate cabbage rural sample glory argue hurdle gym latin discover kid";
        let (xpub, sk) = derive_keys(mnemonic).expect("Key derivation failed");
        assert_eq!(
            hex::encode(xpub.serialize()),
            "45c28ef03ccc06022c282b79ca729f817bceef199db0bd487132c5d938ff3618"
        );
        assert_eq!(
            hex::encode(sk.secret_bytes()),
            "75c7cba2f40513e24127ac59552e694191da98c0a896338d80fb25dc69c3fbfb"
        );
    }

    #[test]
    fn derive_users_keys() {
        kbe_utils::load_users_env_file();
        let mnemonic = std::env::var("MNEMONIC").expect("MNEMONIC not set in .env file");
        let (xpub, _sk) = derive_keys(&mnemonic).expect("Key derivation failed");
        println!("Derived Public Key: {}", hex::encode(xpub.serialize()));
    }
}
