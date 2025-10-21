use kasia_interface::KaspaMessage;

/// Given a list of raw payloads (hex strings from block exploere), decode and decrypt them if necessary,
/// using the mnemonics stored in the environment variables MNEMONIC and MNEMONIC2.
/// MNEMONIC is used to derive the private key for user A, and MNEMONIC2 for user b.
/// If only one mnemonic needs to be provided if only decrypting messages sent to a single user.
/// Print the decoded messages to the console.
fn main() {
    let raw = vec![
        (
            "Broadcast A -> Bot", // What this payload represents (used for output only)
            "636970685f6d73673a313a62636173743a6b6173626f743a48656c6c6f20776f726c64", // Hex from the block explorer
        ),
        (
            "Broadcast Bot -> A",
            "636970685f6d73673a313a62636173743a6b6173626f743a48657921204e69636520746f2073656520746865206368617420616c6976652e20486f7727732065766572796f6e6520646f696e673f",
        ),
    ];

    kbe_utils::load_users_env_file();
    let mnemonic = std::env::var("MNEMONIC").unwrap_or("".to_string());
    let mnemonic2 = std::env::var("MNEMONIC2").unwrap_or(mnemonic.clone());

    if mnemonic.is_empty() {
        println!("Warning: MNEMONIC is not set, decryption will fail for encrypted messages.");
    } else if mnemonic == mnemonic2 {
        println!(
            "Warning: MNEMONIC and MNEMONIC2 are the same! Both messages sides not supported."
        );
    }

    for (action, raw) in raw {
        let bytes = hex::decode(raw).unwrap();
        let mut message = KaspaMessage::try_from(&bytes).unwrap();
        assert!(!message.is_invalid());

        if message.is_encrypted() {
            let (_pub, sec) = kbe_seed_parser::derive_keys(&mnemonic).unwrap();

            let (_pubb, secb) = kbe_seed_parser::derive_keys(&mnemonic2).unwrap();

            message = message
                .decrypt(&sec)
                .unwrap_or_else(|_| message.decrypt(&secb).unwrap());
        }

        println!("{}: {:?}", action, message);
    }
}
