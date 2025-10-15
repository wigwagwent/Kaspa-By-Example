use dotenv::dotenv;
use kaspa_addresses::{Address, Version};
use kaspa_bip32::secp256k1::{self, Secp256k1};
use kaspa_bip32::{ExtendedPrivateKey, Language, Mnemonic};
use kaspa_wallet_core::tx::{Fees, Generator, GeneratorSettings, PaymentDestination};
use kaspa_wallet_core::utxo::UtxoEntryReference;
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding, prelude::*};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Kaspa WebSocket node...");

    dotenv().ok();
    let mnemonic = std::env::var("MNEMONIC")?;

    // Connect to the Kaspa node
    let client = Arc::new(KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("wss://wrpc.kasia.fyi/"),
        None,
        None,
        None,
    )?);

    client.connect(None).await?;
    println!("Connected successfully!");

    send_transaction_with_payload(&client, &mnemonic, b"Hello World".to_vec()).await
}

fn derive_keys(
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

async fn send_transaction_with_payload(
    client: &Arc<KaspaRpcClient>,
    mnemonic: &str,
    payload: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let network_id = NetworkId::new(NetworkType::Mainnet);

    let (x_public_key, private_key) = derive_keys(&mnemonic)?;
    let derived_address = Address::new(
        network_id.into(),
        Version::PubKey,
        &x_public_key.serialize(),
    );

    println!("Derived address: {}", derived_address);

    let utxos = client
        .get_utxos_by_addresses(vec![derived_address.clone()])
        .await?;

    let utxos = utxos
        .into_iter()
        .map(UtxoEntryReference::from)
        .collect::<Vec<_>>();

    let settings = GeneratorSettings::try_new_with_iterator(
        network_id,
        Box::new(utxos.into_iter()),
        None,
        derived_address.clone(),
        1,
        1,
        PaymentDestination::Change, // PaymentOutputs(outputs),
        Some(1.1),
        Fees::None, // SenderPays(0),
        Some(payload),
        None,
    )?;

    let generator = Generator::try_new(settings, None, None)?;
    println!("Generator created successfully");

    let pending = generator
        .generate_transaction()?
        .ok_or("No transaction generated")?;

    pending.try_sign_with_keys(&[private_key.secret_bytes()], None)?;
    let id = pending.try_submit(&client.rpc_api()).await?;
    println!("Transaction submitted with ID: {}", id);

    Ok(())
}
