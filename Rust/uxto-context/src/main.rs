#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, network) = kbe_seed_parser::load_account()?;
    let client = kbe_kas_client::connect_kaspa_client(None, false, false, false).await?;

    let (processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    let _tx_id1 = kbe_transactions::send_payload_transaction(
        client.clone(),
        &context,
        &address,
        Some("ABC".as_bytes().to_vec()),
        &secret,
    )
    .await?;

    let _tx_id2 = kbe_transactions::send_payload_transaction(
        client.clone(),
        &context,
        &address,
        Some("123".as_bytes().to_vec()),
        &secret,
    )
    .await?;

    kbe_transactions::stop_processor(processor).await?;

    Ok(())
}
