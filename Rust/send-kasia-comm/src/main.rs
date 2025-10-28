#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, network) = kbe_seed_parser::load_account()?;
    let (address2, _secret, _network) = kbe_seed_parser::load_account2()?;
    let client = kbe_kas_client::connect_kaspa_client(None).await?;

    let (processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    let alias = "12fa45bc78de".to_string(); // Example fixed alias would be stored from prior handshake

    let message =
        kasia_interface::KaspaMessage::new_communication(alias, "Super Secret Message".to_string());

    let enc = message.encrypt(&address2.to_string())?;

    let _tx_id = kbe_transactions::send_payload_transaction(
        client.clone(),
        &context,
        &address,
        Some(enc.to_payload()?),
        &secret,
    )
    .await?;

    kbe_transactions::stop_processor(processor).await?;

    Ok(())
}
