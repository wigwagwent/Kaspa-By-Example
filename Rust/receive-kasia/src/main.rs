use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    vec,
};

use kasia_interface::{CIPH_MSG_PREFIX, KaspaMessage};
use kaspa_addresses::{Address, Version};
use kaspa_bip32::secp256k1;
use kaspa_consensus_core::Hash;
use kaspa_wallet_core::{tx::PaymentOutput, utils::kaspa_to_sompi, utxo::UtxoContext};
use kaspa_wrpc_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    connect_and_listen().await
}

// Exists to call from tests
async fn connect_and_listen() -> Result<(), Box<dyn std::error::Error>> {
    let (address, secret, network) = kbe_seed_parser::load_account2()?;
    let (notification_sender, receiver) = async_channel::unbounded::<Notification>();
    let client = kbe_kas_client::connect_kaspa_client(Some(notification_sender)).await?;
    let (_processor, context) =
        kbe_transactions::get_utxo_context(client.clone(), network, &address).await?;

    let mut receive_alias: Option<String> = None;
    let mut send_alias: Option<String> = None;

    let mut seen_tx = HashSet::new();

    let mut need_sender: HashMap<Hash, KaspaMessage> = HashMap::new();

    loop {
        let notification = receiver.recv().await?;
        match notification {
            // These are unaccepted blocks at the current state so responding to them would mean that it is very fast processing,
            // but it also means that the original message might be "unsent" when not accepted.
            Notification::BlockAdded(msg) => {
                for tx in msg.block.transactions.iter() {
                    if !tx.payload.starts_with(CIPH_MSG_PREFIX) {
                        continue;
                    }

                    let tx_id = match tx.verbose_data.as_ref().map(|vd| vd.transaction_id) {
                        // If seen than this is a reog and we don't undo on that happening
                        Some(ref id) if seen_tx.contains(id) => continue,
                        Some(id) => {
                            seen_tx.insert(id.clone());
                            id
                        }
                        None => continue,
                    };

                    match KaspaMessage::try_from(&tx.payload) {
                        Ok(kaspa_message) => match kaspa_message {
                            KaspaMessage::Broadcast { group, message } => {
                                println!("\n⬇️  RX: Broadcast Message [{}]", tx_id);
                                println!("    Group: {}", group);
                                println!("    Message: {}", message);
                            }
                            KaspaMessage::EncryptCommunication { ref alias, .. } => {
                                println!("\n⬇️  RX: Encrypted Communication [{}]", tx_id);
                                println!("    Alias: {}", alias);

                                if Some(alias.clone()) != receive_alias {
                                    println!("    ⚠️  Alias mismatch - ignoring");
                                    continue;
                                }

                                let message = kaspa_message.decrypt(&secret)?;
                                let msg_data = message.get_message();
                                println!("    Decrypted: {}", msg_data);

                                let msg_data = format!("Echo: {}", msg_data);
                                if let Some(ref alias) = send_alias {
                                    let sendback = KaspaMessage::new_communication(alias, msg_data);
                                    need_sender.insert(tx_id, sendback);
                                }
                            }
                            KaspaMessage::EncryptHandshake { .. } => {
                                println!("\n⬇️  RX: Handshake Request [{}]", tx_id);

                                let recv_address =
                                    extract_address_from_script(&tx.outputs[0].script_public_key);

                                if recv_address != address {
                                    println!("    ⚠️  Not addressed to us - ignoring");
                                    continue;
                                }

                                let message = kaspa_message.decrypt(&secret)?;
                                let msg_data = message.get_message();
                                println!("    Decrypted: {}", msg_data);
                                need_sender.insert(tx_id, message);
                            }
                            _ => {
                                println!("\n⬇️  RX: Unsupported message type [{}]", tx_id);
                            }
                        },
                        Err(_e) => {}
                    }
                }
            }
            Notification::VirtualChainChanged(msg) => {
                // if need_sender.len() == 0 {
                //     continue;
                // }
                for accepted_tx in msg.accepted_transaction_ids.iter() {
                    let block_hash = accepted_tx.accepting_block_hash;
                    let block = client.rpc_api().get_block(block_hash, true).await?;
                    if let Some(verbose_data) = &block.verbose_data {
                        if !verbose_data.is_chain_block {
                            continue;
                        }
                    }
                    let daa = block.header.daa_score;

                    for tx_id in accepted_tx.accepted_transaction_ids.iter() {
                        // find message in needs sender
                        let kas_msg = need_sender.remove(tx_id);

                        let kas_msg = match kas_msg {
                            Some(msg) => msg,
                            None => continue,
                        };

                        let sender = client
                            .rpc_api()
                            .get_utxo_return_address(*tx_id, daa)
                            .await?;

                        match kas_msg {
                            KaspaMessage::DecryptCommunication { .. } => {
                                println!("\n⬆️  TX: Encrypted Reply [{}]", tx_id);
                                println!("    Recipient: {}", sender.address_to_string());

                                let sendback = kas_msg.encrypt(&sender.to_string())?;
                                if let Err(e) = kbe_transactions::send_payload_transaction(
                                    client.clone(),
                                    &context,
                                    &address,
                                    Some(sendback.to_payload()?),
                                    &secret,
                                )
                                .await
                                {
                                    eprintln!("⚠️  Transaction error: {}", e);
                                }
                            }
                            KaspaMessage::DecryptHandshake { decrypted_msg } => {
                                println!("\n⬆️  TX: Handshake Response [{}]", tx_id);
                                println!("    Recipient: {}", sender.address_to_string());

                                (send_alias, receive_alias) = respond_to_handshake(
                                    client.clone(),
                                    &context,
                                    &address,
                                    &secret,
                                    decrypted_msg,
                                    &sender,
                                )
                                .await?;

                                println!("    Alias sent: {:?}", send_alias);
                                println!("    Alias received: {:?}", receive_alias);
                            }
                            _ => {
                                println!("\n⬆️  TX: Unsupported response type [{}]", tx_id);
                            }
                        }
                    }
                }
            }
            _ => {
                println!("⚠️  Unexpected notification: {:?}", notification);
            }
        }
    }
}

fn extract_address_from_script(
    script_public_key: &kaspa_consensus_core::tx::ScriptPublicKey,
) -> Address {
    let derived_address = Address::new(
        NetworkId::new(NetworkType::Mainnet).into(),
        Version::PubKey,
        &script_public_key.script()[1..33],
    );
    derived_address
}

async fn respond_to_handshake(
    client: Arc<KaspaRpcClient>,
    context: &UtxoContext,
    address: &Address,
    secret: &secp256k1::SecretKey,
    decrypted_msg: kasia_interface::HandshakeMessage,
    handshake_address: &Address,
) -> Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let send_alias = decrypted_msg.alias;

    // let receive_alias = {
    //     let mut rng = rand::rng();
    //     let bytes: [u8; 6] = rng.random();
    //     hex::encode(bytes)
    // };

    let receive_alias = "12fa45bc78de".to_string();

    let response_message = kasia_interface::KaspaMessage::new_handshake_response(
        send_alias.clone(),
        receive_alias.clone(),
    );
    let response = response_message.encrypt(&handshake_address.to_string())?;

    let payment = PaymentOutput {
        address: handshake_address.clone(),
        amount: kaspa_to_sompi(0.2),
    };

    if let Err(e) = kbe_transactions::send_kaspa_transaction(
        client,
        context,
        address,
        vec![payment],
        Some(response.to_payload()?),
        secret,
    )
    .await
    {
        eprintln!("⚠️  Transaction error: {}", e);
    }

    Ok((Some(send_alias), Some(receive_alias)))
}
