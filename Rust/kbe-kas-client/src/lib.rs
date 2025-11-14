use std::{sync::Arc, time::Duration};

use async_channel::Sender;
use kaspa_notify::scope::{BlockAddedScope, VirtualChainChangedScope, VirtualDaaScoreChangedScope};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType, Notification, Scope},
};

pub async fn connect_kaspa_client(
    block_updates: Option<Sender<Notification>>,
    virtual_chain: bool,
    block_added: bool,
    virtual_daa: bool,
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
            if !virtual_chain && !block_added && !virtual_daa {
                panic!(
                    "At least one of virtual_chain, block_added, or virtual_daa must be true to subscribe to notifications."
                );
            }

            let listener_id = client.rpc_api().register_new_listener(
                kaspa_notify::connection::ChannelConnection::new(
                    "transaction-processor",
                    sender,
                    kaspa_notify::connection::ChannelType::Persistent,
                ),
            );

            // Subscribe to block added notifications only
            if virtual_chain {
                client
                    .rpc_api()
                    .start_notify(
                        listener_id,
                        Scope::VirtualChainChanged(VirtualChainChangedScope {
                            include_accepted_transaction_ids: true,
                        }),
                    )
                    .await
                    .expect("Could not add virtual chain notification to client listener");
            }

            if block_added {
                client
                    .rpc_api()
                    .start_notify(listener_id, Scope::BlockAdded(BlockAddedScope {}))
                    .await
                    .expect("Could not add block added notification to client listener");
            }

            if virtual_daa {
                client
                    .rpc_api()
                    .start_notify(
                        listener_id,
                        Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {}),
                    )
                    .await
                    .expect("Could not add virtual daa notification to client listener");
            }

            println!("Subscribed to block notifications. Waiting for transactions...");
        }
        None => println!("Waiting for transactions..."),
    }

    Ok(client)
}
