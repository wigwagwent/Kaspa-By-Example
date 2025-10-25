use std::{sync::Arc, time::Duration};

use async_channel::Sender;
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{BlockAddedScope, NetworkId, NetworkType, Notification, Scope},
};

pub async fn connect_kaspa_client(
    block_updates: Option<Sender<Notification>>,
) -> Result<Arc<KaspaRpcClient>, Box<dyn std::error::Error>> {
    println!("Connecting to Kaspa WebSocket node...");

    let network_id = NetworkId::new(NetworkType::Mainnet);

    // Connect to the Kaspa node
    let client = Arc::new(KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("wss://wrpc.kasia.fyi/"),
        None,
        Some(network_id),
        None,
    )?);

    let connect_options = ConnectOptions {
        block_async_connect: true,
        strategy: ConnectStrategy::Retry,
        url: None,
        connect_timeout: Some(Duration::from_secs(5)),
        retry_interval: Some(Duration::from_secs(3)),
    };

    client.connect(Some(connect_options)).await?;
    println!("Connected successfully!");

    match block_updates {
        Some(sender) => {
            // Register listener
            let listener_id = client.rpc_api().register_new_listener(
                kaspa_notify::connection::ChannelConnection::new(
                    "transaction-processor",
                    sender,
                    kaspa_notify::connection::ChannelType::Persistent,
                ),
            );

            // Subscribe to block added notifications only
            client
                .rpc_api()
                .start_notify(listener_id, Scope::BlockAdded(BlockAddedScope {}))
                .await
                .expect("Could not add notification to client listener");

            println!("Subscribed to block notifications. Waiting for transactions...");
        }
        None => (),
    }

    Ok(client)
}
