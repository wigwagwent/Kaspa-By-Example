#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, network) = kbe_seed_parser::load_account()?;
    let client = kbe_kas_client::connect_kaspa_client(None).await?;

    let (processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    // Send transaction with a Kasia broadcast message
    let message =
        kasia_interface::KaspaMessage::new_broadcast("Kaspa_By_Example_Demo_Code", "Hello World")
            .to_payload()?;

    let _tx_id = kbe_transactions::send_payload_transaction(
        client.clone(),
        &context,
        &address,
        Some(message),
        &secret,
    )
    .await?;

    kbe_transactions::stop_processor(processor).await?;

    Ok(())
}
