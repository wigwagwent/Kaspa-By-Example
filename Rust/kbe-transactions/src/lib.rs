use std::{sync::Arc, vec};

use kaspa_addresses::Address;
use kaspa_bip32::secp256k1;
use kaspa_consensus_core::Hash;
use kaspa_wallet_core::{
    rpc::{DynRpcApi, Rpc},
    tx::{Fees, Generator, GeneratorSettings, PaymentDestination, PaymentOutput, PaymentOutputs},
    utxo::{UtxoContext, UtxoContextBinding, UtxoProcessor},
};
use kaspa_wrpc_client::{KaspaRpcClient, prelude::NetworkId};

pub async fn send_payload_transaction(
    client: Arc<KaspaRpcClient>,
    context: &UtxoContext,
    address: &Address,
    payload: Option<Vec<u8>>,
    secret: &secp256k1::SecretKey,
) -> Result<Hash, Box<dyn std::error::Error>> {
    let outputs = PaymentOutputs {
        outputs: Vec::new(),
    };
    let settings = GeneratorSettings::try_new_with_context(
        context.clone(),
        None,
        address.clone(),
        1,
        1,
        PaymentDestination::PaymentOutputs(outputs),
        None,
        kaspa_wallet_core::tx::Fees::SenderPays(0),
        payload,
        None,
    )?;

    let generator = Generator::try_new(settings, None, None)?;

    let pending = generator
        .generate_transaction()?
        .ok_or("No transaction generated")?;

    pending.try_sign_with_keys(&[secret.secret_bytes()], None)?;
    let id = pending.try_submit(&client.rpc_api()).await?;
    println!("\nTransaction submitted - Link to view on explorer below");
    println!("https://explorer.kaspa.org/txs/{}", id);

    Ok(id)
}

pub async fn send_kaspa_transaction(
    client: Arc<KaspaRpcClient>,
    context: &UtxoContext,
    address: &Address,
    output: vec::Vec<PaymentOutput>,
    payload: Option<Vec<u8>>,
    secret: &secp256k1::SecretKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let outputs = PaymentOutputs { outputs: output };

    let settings = GeneratorSettings::try_new_with_context(
        context.clone(),
        None,
        address.clone(),
        1,
        1,
        PaymentDestination::PaymentOutputs(outputs),
        None, //Some(1.0),
        Fees::SenderPays(0),
        payload,
        None,
    )?;

    let generator = Generator::try_new(settings, None, None)?;

    let pending = generator
        .generate_transaction()?
        .ok_or("No transaction generated")?;

    pending.try_sign_with_keys(&[secret.secret_bytes()], None)?;
    let id = pending.try_submit(&client.rpc_api()).await?;
    println!("\nTransaction submitted - Link to view on explorer below");
    println!("https://explorer.kaspa.org/txs/{}", id);

    Ok(id.to_string())
}

pub async fn get_utxo_context(
    client: Arc<KaspaRpcClient>,
    network_id: NetworkId,
    address: &Address,
) -> Result<(UtxoProcessor, UtxoContext), Box<dyn std::error::Error>> {
    let rpc_ctl = client.ctl().clone();
    let rpc_api: Arc<DynRpcApi> = client.clone();
    let rpc = Rpc::new(rpc_api, rpc_ctl);

    let processor = UtxoProcessor::new(Some(rpc), Some(network_id), None, None);

    processor.start().await?;

    let utxo_context = UtxoContext::new(&processor, UtxoContextBinding::default());
    utxo_context
        .scan_and_register_addresses(vec![address.clone()], None)
        .await?;

    if utxo_context.balance().unwrap_or_default().is_empty() {
        println!(
            "Warning: The address {} has a balance of 0 KASPA.",
            address.to_string()
        );
    }

    Ok((processor, utxo_context))
}

pub async fn stop_processor(processor: UtxoProcessor) -> Result<(), Box<dyn std::error::Error>> {
    processor.stop().await?;
    Ok(())
}
