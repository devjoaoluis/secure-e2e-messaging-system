# Multi-Client E2E Secure Messaging System

An end-to-end (E2E) encrypted multi-client messaging system implemented in Python (using the `cryptography` library and `asyncio`).

In this architecture, the central server acts strictly as an unauthenticated/authenticated relay and rendezvous point without any ability to decrypt user communication. Each client performs an authenticated handshake with the server, receives ephemeral public keys of active peers, derives directional symmetric session keys, and exchanges authenticated encrypted frames.

## 🔒 Security Guarantees & Cryptographic Primitives

| Property | Mechanism / Primitive | Specification | 
| ----- | ----- | ----- | 
| **Confidentiality** | AES-128-GCM | Authenticated Encryption with Associated Data (AEAD) | 
| **Integrity & Authenticity** | AES-GCM Tag (16B) | Verified against payload and Associated Data (AAD) | 
| **Server Authentication** | RSA-PSS with SHA-256 | Self-signed pinned X.509 certificate ($\ge 2048$ bits) | 
| **Forward Secrecy (PFS)** | ECDHE (X25519) | Ephemeral 32-byte keys generated per session | 
| **Key Derivation** | HKDF-SHA256 | `HKDF-Extract` using server salt + `HKDF-Expand` with labels | 
| **Anti-Replay Protection** | Monotonic Counter (`seq_no`) | Strict 64-bit sequence counters per communication direction | 

## 📐 Protocol Architecture & Data Flow

```
   Client A                           Server                            Client B
      |                                  |                                 |
      |--- 1) client_id_A + pk_C_A ----->|                                 |
      |<-- 2) pk_S + cert + sig + salt --|                                 |
      |                                  |<--- 3) client_id_B + pk_C_B ----|
      |                                  |---- 4) Register B --------------|
      |<-- 5) Forward pk_C_B ------------|                                 |
      |                                  |---- 6) Forward pk_C_A --------->|
      |                                  |                                 |
      |== 7) Compute Z_AB & derive keys =|== Compute Z_AB & derive keys ===|
      |                                  |                                 |
      |--- 8) Encrypted E2E Frame ------>|                                 |
      |                                  |--- 9) Relay Raw Bytes --------->|
      |                                  |                                 [Decrypt & Verify Tag]
      |                                  |<-- 11) Encrypted E2E Frame -----|
      |                                  |<-- 12) Relay Raw Bytes ---------|
      [Decrypt & Verify Tag]             |                                 |

```

### 1. Handshake & Registration

1. **Client Registration:** Client sends its binary `client_id` (16 bytes, UUIDv4) along with its raw ephemeral public key `pk_client` (32 bytes, X25519).

2. **Server Proof:** The server signs the concatenated parameters with RSA-PSS:
   

   $$
   H = \text{SHA256}(pk\_server \parallel pk\_client \parallel client\_id \parallel salt)
   $$

   
   The client validates the pinned certificate (`server.crt`) and verifies the signature over $H$.

3. **Key Exchange Broadcast:** When a new client joins, the server distributes its public key to all existing peers and broadcasts all active peers' public keys to the newcomer.

### 2. E2E Key Derivation (HKDF-SHA256)

Clients calculate the shared secret directly with their peers:

$$
Z_{AB} = \text{ECDH}(sk_A, pk_B)
$$

Keys are derived using the server-provided 16-byte random salt (`salt_srv`):

$$
\text{PRK} = \text{HKDF-Extract}(salt\_srv, Z_{AB})
$$

$$
\text{Key}_{A \to B} = \text{HKDF-Expand}(\text{PRK}, info=\text{"A2B"}, L=16)
$$

$$
\text{Key}_{B \to A} = \text{HKDF-Expand}(\text{PRK}, info=\text{"B2A"}, L=16)
$$

*Note: The shared secret* $Z_{AB}$ *is zeroized/discarded immediately after key derivation.*

## 📦 Packet & Frame Structures

### TCP Framing

All packets transmitted over TCP use a 4-byte big-endian length prefix to prevent stream delimitation issues:

```
+--------------------------+-------------------------------------+
| Length Prefix (4 bytes)  | Message Payload / Raw Frame (N B)   |
+--------------------------+-------------------------------------+

```

### E2E Encrypted Application Frame

The E2E frame format carries the encrypted payload and associated authentication metadata:

```
+-------------+----------------+------------------+--------------+-------------------+---------------+
| Nonce (12B) | sender_id (16B)| recipient_id(16B)| seq_no (8B)  | Ciphertext (var)  | Tag (16B)     |
+-------------+----------------+------------------+--------------+-------------------+---------------+
|<----------------------------- AAD ---------------------------->|

```

* **Nonce Construction (12 bytes):** `IV_base (4B) || seq_no (8B, big-endian)`.

* **Associated Data (AAD):** `sender_id (16B) || recipient_id (16B) || seq_no (8B)`.

* **Payload Bound:** Maximum plaintext size per message is 4096 bytes.

## 📂 Project Structure

```
.
├── certs/
│   ├── server.crt          # Self-signed X.509 RSA certificate (pinned by clients)
│   └── server.key          # Server RSA private key (kept secret)
├── client/
│   ├── client.py           # Client application & interactive CLI
│   └── session_manager.py  # Peer session storage, IV tracking, HKDF derivation
├── server/
│   ├── server.py           # Multi-client TCP async relay server
│   └── session_store.py    # Active client sessions & routing tables
├── common/
│   ├── crypto.py           # Cryptographic primitives (X25519, HKDF, AES-GCM, RSA-PSS)
│   └── protocol.py         # Frame serialization, headers, and pack/unpack utilities
├── tests/
│   ├── test_bitflip.py     # Tampering validation (tag mismatch verification)
│   ├── test_replay.py      # Sequence counter anti-replay attack simulation
│   └── test_framing.py     # Malformed length-prefix handling tests
├── requirements.txt
└── README.md

```

## 🚀 Setup & Execution

### Prerequisites

* Python 3.10+

* `cryptography` library

```
pip install -r requirements.txt

```

### 1. Generate Server Certificates (RSA-2048+)

```
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=SecureRelayServer"

```

### 2. Start the Server

```
python server/server.py --host 127.0.0.1 --port 9000

```

### 3. Launch Clients

In separate terminal tabs:

```
# Terminal 1 - Start Alice
python client/client.py --server 127.0.0.1 --port 9000 --cert certs/server.crt

# Terminal 2 - Start Bob
python client/client.py --server 127.0.0.1 --port 9000 --cert certs/server.crt

```

## 🧪 Security Validation & Defense Scenarios

The suite includes dedicated tests to demonstrate defense mechanisms against active attacks:

1. **Tampering / Bitflip Test:**

   * Modify one bit in the ciphertext during transmission.

   * **Result:** AES-GCM authentication fails; receiver immediately discards frame (`InvalidTag`).

2. **Replay Attack Simulation:**

   * Resend a previously captured frame containing an identical or decreased `seq_no`.

   * **Result:** Receiver checks monotonic `seq_recv`; rejects duplicate frame.

3. **Framing & Malformed Packets:**

   * Send frame with payload mismatch relative to 4-byte prefix.

   * **Result:** Parser catches framing violation and safely terminates connection.

4. **Zero-Knowledge Relay Assurance:**

   * Server logs verify that only routing headers (`recipient_id`) are inspected, while payload remains opaque ciphertext. No raw keys or secrets are logged.

## 🛡️ Logging & Operational Constraints

* **Strict Log Sanitization:** Private keys (`sk`), shared secrets ($Z$), symmetric keys (`Key_A2B`), nonces, and raw plaintexts are never logged.

* **Transient Memory Model:** Disconnection clears all peer and session data from memory. Reconnecting under the same client identity enforces a full re-handshake and key renegotiation.