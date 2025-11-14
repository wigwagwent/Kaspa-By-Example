use kaspa_addresses::Address;
use kaspa_bip32::secp256k1;
use kaspa_wallet_core::tx::{
    Fees, Generator, GeneratorSettings, PaymentDestination, PaymentOutput, PaymentOutputs,
};
use kaspa_wallet_core::utils::kaspa_to_sompi;
use kaspa_wallet_core::utxo::UtxoEntryReference;
use kaspa_wrpc_client::{KaspaRpcClient, prelude::*};
use std::sync::Arc;
use tokio::time::{Duration, sleep};

const SPLIT_ITERATIONS: usize = 20;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, network) = kbe_seed_parser::load_account()?;
    let client = kbe_kas_client::connect_kaspa_client(None, false, false, false).await?;

    println!("Will perform {} split iterations", SPLIT_ITERATIONS);

    for iteration in 1..SPLIT_ITERATIONS {
        println!(
            "\n=== Split Iteration {}/{} ===",
            iteration, SPLIT_ITERATIONS
        );

        // Get current UTXOs
        let utxos = client.get_utxos_by_addresses(vec![address.clone()]).await?;

        let utxo_count = utxos.len();
        println!("Current UTXO count: {}", utxo_count);
        println!("Splitting all {} UTXOs...", utxo_count);

        let utxo_refs: Vec<UtxoEntryReference> =
            utxos.into_iter().map(UtxoEntryReference::from).collect();

        // Split each UTXO
        for (i, utxo) in utxo_refs.into_iter().enumerate() {
            let utxo_amount = utxo.amount();
            let half_amount = utxo_amount / 2;
            if half_amount <= kaspa_to_sompi(0.25) {
                println!(
                    "  Skipping UTXO {}/{} with amount {} sompi (too small to split)",
                    i + 1,
                    utxo_count,
                    utxo_amount
                );
                continue;
            }
            println!("\n  Splitting UTXO {}/{}", i + 1, utxo_count);

            let tx_id = split_one_utxo(&client, &address, &secret, network, utxo).await?;

            println!("  Transaction: https://explorer.kaspa.org/txs/{}", tx_id);
        }

        // Wait for transactions to confirm before next iteration
        if iteration < SPLIT_ITERATIONS {
            println!("\nWaiting for transactions to confirm before next iteration...");
            sleep(Duration::from_secs(5)).await;
        }
    }

    // Final count
    let final_utxos = client.get_utxos_by_addresses(vec![address.clone()]).await?;

    println!("\n✓ Splitting complete!");
    println!("Final UTXO count: {}", final_utxos.len());
    println!("Expected: {} UTXOs", 2_usize.pow(SPLIT_ITERATIONS as u32));

    Ok(())
}

async fn split_one_utxo(
    client: &Arc<KaspaRpcClient>,
    address: &Address,
    private_key: &secp256k1::SecretKey,
    network_id: NetworkId,
    utxo: UtxoEntryReference,
) -> Result<String, Box<dyn std::error::Error>> {
    let utxo_amount = utxo.amount();
    let half_amount = utxo_amount / 2;

    println!(
        "    Input: {} sompi → Output: {} sompi (+ change)",
        utxo_amount, half_amount
    );

    // Create only 1 output with half the amount
    // The other half becomes change automatically
    let outputs = PaymentOutputs {
        outputs: vec![PaymentOutput {
            address: address.clone(),
            amount: half_amount,
        }],
    };

    let settings = GeneratorSettings::try_new_with_iterator(
        network_id,
        Box::new(vec![utxo].into_iter()),
        None,
        address.clone(),
        1,
        1,
        PaymentDestination::PaymentOutputs(outputs),
        Some(1.0),
        Fees::SenderPays(0),
        None,
        None,
    )?;

    let generator = Generator::try_new(settings, None, None)?;
    let pending = generator
        .generate_transaction()?
        .ok_or("No transaction generated")?;

    pending.try_sign_with_keys(&[private_key.secret_bytes()], None)?;
    let id = pending.try_submit(&client.rpc_api()).await?;

    Ok(id.to_string())
}
