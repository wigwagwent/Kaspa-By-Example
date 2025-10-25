use rand::Rng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, _network) = kbe_seed_parser::load_account()?;
    let (address2, _secret2, network) = kbe_seed_parser::load_account2()?;
    let client = kbe_kas_client::connect_kaspa_client(None).await?;

    let (processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    let mut rng = rand::rng();
    let bytes: [u8; 6] = rng.random();
    let alias = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let handshake = kasia_interface::KaspaMessage::new_handshake_request(alias);
    let payload = handshake.encrypt(&address2.to_string())?.to_payload()?;

    let _tx_id = kbe_transactions::send_payload_transaction(
        client.clone(),
        &context,
        &address,
        Some(payload),
        &secret,
    )
    .await?;

    kbe_transactions::stop_processor(processor).await?;

    Ok(())
}
