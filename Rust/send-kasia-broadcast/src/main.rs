use kaspa_addresses::{Address, Version};
use kaspa_wallet_core::tx::{Fees, Generator, GeneratorSettings, PaymentDestination};
use kaspa_wallet_core::utxo::UtxoEntryReference;
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding, prelude::*};
use std::sync::Arc;
use std::thread::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    connect_and_send().await
}

// Exists to call from tests
async fn connect_and_send() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Kaspa WebSocket node...");

    kbe_utils::load_users_env_file();
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

    // Send transaction with a custom payload
    send_transaction_with_payload(
        &client,
        &mnemonic,
        b"Hello World. Welcome from Kaspa By Example".to_vec(),
    )
    .await?;

    sleep(tokio::time::Duration::from_secs(2)); // To avoid sending the utxo too quickly in succession

    // Send transaction with a Kasia broadcast message
    let message =
        kasia_interface::KaspaMessage::new_broadcast("Kaspa_By_Example_Demo_Code", "Hello World");

    send_transaction_with_payload(&client, &mnemonic, message.to_payload().unwrap()).await
}

async fn send_transaction_with_payload(
    client: &Arc<KaspaRpcClient>,
    mnemonic: &str,
    payload: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let network_id = NetworkId::new(NetworkType::Mainnet);

    let (x_public_key, private_key) = kbe_seed_parser::derive_keys(&mnemonic)?;
    let derived_address = Address::new(
        network_id.into(),
        Version::PubKey,
        &x_public_key.serialize(),
    );

    println!("\nDerived address: {}", derived_address);

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
        PaymentDestination::PayloadOnly,
        Some(1.0),
        Fees::None,
        Some(payload),
        None,
    )?;

    let generator = Generator::try_new(settings, None, None)?;

    let pending = generator
        .generate_transaction()?
        .ok_or("No transaction generated")?;

    pending.try_sign_with_keys(&[private_key.secret_bytes()], None)?;
    let id = pending.try_submit(&client.rpc_api()).await?;
    println!("\nTransaction submitted - Link to view on explorer below");
    println!("https://explorer.kaspa.org/txs/{}", id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_main_transaction_succeeds() {
        let result = connect_and_send().await;
        assert!(
            result.is_ok(),
            "Transaction failed with error: {:?}",
            result.err()
        );
    }
}
