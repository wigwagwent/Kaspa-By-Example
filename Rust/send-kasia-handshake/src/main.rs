use kaspa_wallet_core::{tx::PaymentOutput, utils::kaspa_to_sompi};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, _network) = kbe_seed_parser::load_account()?;
    let (address2, _secret2, network) = kbe_seed_parser::load_account2()?;
    let client = kbe_kas_client::connect_kaspa_client(None).await?;

    let (processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    // let mut rng = rand::rng();
    // let bytes: [u8; 6] = rng.random();
    // let alias = hex::encode(bytes);
    let alias = "a1f3c5d9e8b2".to_string(); // Example fixed alias

    let handshake = kasia_interface::KaspaMessage::new_handshake_request(alias);
    let payload = handshake.encrypt(&address2.to_string())?.to_payload()?;

    let payment = PaymentOutput {
        address: address2.clone(),
        amount: kaspa_to_sompi(0.2),
    };

    let _tx_id1 = kbe_transactions::send_kaspa_transaction(
        client.clone(),
        &context,
        &address,
        vec![payment],
        Some(payload),
        &secret,
    )
    .await?;

    kbe_transactions::stop_processor(processor).await?;

    Ok(())
}
