# Kaspa By Example (KBE)

Learn how to interact with the Kaspa ecosystem through practical examples.

## Prerequisites

Before you begin, ensure you have:
- Two funded Kaspa wallets (1 KAS in each should be sufficient)
- A 12 or 24 word seed phrase for your primary wallet

## Setup

1. Copy `sample.env` to `.env` in the project root
2. Add your seed phrase to the `.env` file:

```env
# Seed phrase (12 or 24 words)
MNEMONIC="your seed phrase here"

# Optional: Second wallet for encrypted communication examples
#MNEMONIC2="your second seed phrase here"
```

**⚠️ Important:** Never commit your `.env` file or share your actual seed phrase. The example seed phrase shown above is fake and for demonstration purposes only.

**💲 Note:** Instructions marked with 💲 will send transactions on the Kaspa network, costing a minimal amount of KAS.

---

## Rust Examples

These examples demonstrate various Kasia protocol features for on-chain messaging and encrypted communication on the Kaspa network. Ensure you have Rust installed

### 1. Setup: Start the Receiver

First, you'll set up a listener that monitors the Kaspa network for Kasia messages.

1. Open a terminal in the `Rust` folder
2. 💲 Run the receiver with: `cargo run -p receive-kasia`

You should see:
```
Connecting to Kaspa WebSocket node...
Connected successfully!
Subscribed to block notifications. Waiting for transactions...
```

**Note:** This receiver only responds to encrypted transactions and handshake requests. It will only print out broadcast messages without responding to them.

**Keep this terminal running** while you proceed with the following examples.

---

### 2. Broadcast Messages

Broadcast messages are public messages sent to a group that anyone monitoring can read.

1. Open a **new terminal** in the `Rust` folder
2. 💲 Run: `cargo run -p send-kasia-broadcast`

This sends the message "Hello World" to the group "Kaspa_By_Example_Demo_Code".

**Expected output** in the `receive-kasia` terminal:
```
⬇️  RX: Broadcast Message [########]
    Group: kaspa_by_example_demo_code
    Message: Hello World
```

**Note:** When the receiver responds, it will reprocess the message it sent. In production, you would typically filter out your own sent transactions:
```
⬇️  RX: Handshake Request [########]
    ⚠️  Not addressed to us - ignoring
```

---

### 3. Handshake Protocol

The handshake establishes a secure communication channel between two wallets by exchanging aliases and public keys.

1. 💲 Run: `cargo run -p send-kasia-handshake`

This initiates a handshake from wallet 1 to wallet 2 (the receiver).

**What happens:**
- Wallet 1 sends a handshake request with 0.2 KAS
- Wallet 2 (receive-kasia) automatically accepts and responds
- The 0.2 KAS is returned when wallet 2 sends its handshake response
- Both wallets exchange aliases for future encrypted communication

**Expected output** in the `receive-kasia` terminal:
```
⬇️  RX: Handshake Request [########]
    Decrypted: {"type":"handshake","alias":"a1f3c5d9e8b2","theirAlias":"","timestamp":1761672081,"version":1,"isResponse":false}

⬆️  TX: Handshake Response [########]
    Recipient: kaspa:########

Transaction submitted - Link to view on explorer below
https://explorer.kaspa.org/txs/########
    Alias sent: Some("a1f3c5d9e8b2")
    Alias received: Some("12fa45bc78de")
```

**Note:** The aliases in this example are hardcoded to allow the next example to work. In production, these should be randomly generated (see commented code in the example).

---

### 4. Encrypted Communication

Once a handshake is complete, wallets can send encrypted messages using the exchanged aliases.

1. 💲 Run: `cargo run -p send-kasia-comm`

This sends an encrypted message from wallet 1 to wallet 2. Wallet 2 will decrypt the message and send an encrypted reply.

**Expected output** in the `receive-kasia` terminal:
```
⬇️  RX: Encrypted Communication [########]
    Alias: 12fa45bc78de
    Decrypted: Super Secret Message

⬆️  TX: Encrypted Reply [########]
    Recipient: kaspa:########

Transaction submitted - Link to view on explorer below
https://explorer.kaspa.org/txs/########
```

**Why this matters:** Unlike broadcast messages, these encrypted communications can only be read by the intended recipient, enabling private messaging on a public blockchain.

---

## Understanding the Workflow

1. **Receiver listens** → Monitors blockchain for Kasia protocol transactions
2. **Broadcast** → Public messages anyone can read (no handshake required)
3. **Handshake** → Establishes secure channel between two wallets
4. **Encrypted Communication** → Private messages only readable by recipient (requires completed handshake)

Each example builds on the previous one, demonstrating progressively more advanced features of the Kasia protocol.

---

## Additional Projects

### Library Crates

These reusable libraries power the examples above:

#### `kasia-interface`
Handles encryption/decryption and converts between the payload field and Kasia message format.

#### `kbe-kas-client`
Subscribes to the Kaspa network and creates a client for interaction. Simple startup with no complex configuration.

#### `kbe-seed-parser`
- Derives wallets from seed phrases
- Loads wallet configurations from `.env` file

#### `kbe-utils`
Loads the `.env` file. Used by `kbe-seed-parser` and other components.

#### `kbe-transactions`
Sends different types of transactions. Used throughout the examples to deduplicate transaction code.

---

### Utility Tools

These standalone tools help with debugging and specialized tasks:

#### `payload-decoder`
Decodes and decrypts (if needed) a vector of description strings and payloads using the two wallets provided. Great for debugging Kasia messages.

**Usage:** Input payload data in hex format (how it is found in explorer.kaspa.org) to see decrypted contents.

#### `send-coins`
Sends Kaspa payments to other users.

**TODO:** Upgrade to support Kasia payments.

#### `utxo-splitter`
Splits UTXOs for better transaction management. Probably not very efficient, but gets the job done.

**Note:** You most likely won't need to run this unless you're doing advanced UTXO management.

#### `utxo-context`
Demonstrates the power of UTXO context by sending two transactions back-to-back.

**Requirements:** Needs 2+ UTXOs to function properly. Running the handshake with the reciever running will get you 2 UTXOs.
