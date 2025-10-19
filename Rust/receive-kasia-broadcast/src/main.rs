use kasia_interface::{CIPH_MSG_PREFIX, KaspaMessage};
use kaspa_addresses::{Address, Version};
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding, prelude::*};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    connect_and_listen().await
}

// Exists to call from tests
async fn connect_and_listen() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Kaspa WebSocket node...");

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

    let (notification_sender, receiver) = async_channel::unbounded::<Notification>();

    // Register listener
    let listener_id =
        client
            .rpc_api()
            .register_new_listener(kaspa_notify::connection::ChannelConnection::new(
                "transaction-processor",
                notification_sender,
                kaspa_notify::connection::ChannelType::Persistent,
            ));

    // Subscribe to block added notifications only
    client
        .rpc_api()
        .start_notify(listener_id, Scope::BlockAdded(BlockAddedScope {}))
        .await
        .expect("Could not add notification to client listener");

    println!("Subscribed to block notifications. Waiting for transactions...");

    loop {
        let notification = receiver.recv().await?;
        match notification {
            Notification::BlockAdded(msg) => {
                for tx in msg.block.transactions.iter() {
                    if !tx.payload.starts_with(CIPH_MSG_PREFIX) {
                        continue;
                    }

                    let tx_id = tx
                        .verbose_data
                        .as_ref()
                        .map(|vd| vd.transaction_id.to_string());

                    // Just add this inside your transaction loop:
                    println!("\n=== Transaction {:?} ===", tx_id);
                    println!("Addresses involved:");

                    for (idx, output) in tx.outputs.iter().enumerate() {
                        let address = extract_address_from_script(&output.script_public_key);
                        println!(
                            "  Address {}: {} ({} KAS)",
                            idx,
                            address,
                            output.value as f64 / 100_000_000.0 // Convert sompi to KAS
                        );
                    }

                    match KaspaMessage::try_from(&tx.payload) {
                        Ok(kaspa_message) => {
                            if let KaspaMessage::Broadcast {
                                group: gp,
                                message: ms,
                            } = kaspa_message
                            {
                                println!(
                                    "Received broadcast message group {} in transaction {:?} with message: {}",
                                    gp, tx_id, ms
                                );
                            }
                        }
                        Err(_e) => {}
                    }
                }
            }
            _ => {
                println!("Received unexpected notification: {:?}", notification);
            }
        }
    }
}

fn extract_address_from_script(
    script_public_key: &kaspa_consensus_core::tx::ScriptPublicKey,
) -> String {
    let derived_address = Address::new(
        NetworkId::new(NetworkType::Mainnet).into(),
        Version::PubKey,
        &script_public_key.script()[1..33],
    );
    derived_address.to_string()
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_main_transaction_succeeds() {
//         let result = connect_and_listen().await;
//         assert!(
//             result.is_ok(),
//             "Transaction failed with error: {:?}",
//             result.err()
//         );
//     }
// }
