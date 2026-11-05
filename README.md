# Multi-Client E2E Secure Messaging System

An end-to-end (E2E) encrypted multi-client messaging system implemented in Python using `cryptography` and `asyncio`.

The central relay server acts strictly as a zero-knowledge rendezvous and routing point without any capability to decrypt user communication. Each client performs an RSA-PSS authenticated handshake with the server, exchanges ephemeral X25519 public keys with active peers, derives directional AES-128-GCM session keys via HKDF-SHA256, and exchanges authenticated frames protected against tampering and replay attacks.

## 🔒 Security Primitives

| Property | Primitive | Specification |
| --- | --- | --- |
| **Confidentiality** | AES-128-GCM | Authenticated Encryption with Associated Data (AEAD) |
| **Integrity & Authenticity** | AES-GCM Tag (16B) | Verified against payload and AAD (`sender_id \|\| recipient_id \|\| seq_no`) |
| **Server Authentication** | RSA-PSS with SHA-256 | Self-signed pinned X.509 certificate ($\ge 2048$ bits) |
| **Forward Secrecy (PFS)** | ECDHE (X25519) | Ephemeral 32-byte keypairs generated per session |
| **Key Derivation** | HKDF-SHA256 | `HKDF-Extract` with 16B server salt + `HKDF-Expand` (`"A2B"`, `"B2A"`) |
| **Anti-Replay Protection** | Monotonic Counter (`seq_no`) | Strict 64-bit sequence counters per communication direction |

## 🚀 Setup & Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Relay Server
*(Automatically loads `certs/server.crt` and `certs/server.key`, or generates a 2048-bit RSA self-signed pair if missing)*
```bash
python server/server.py --host 127.0.0.1 --port 9000
```

### 3. Launch Interactive Clients
In separate terminals:
```bash
# Terminal 1 - Alice
python client/client.py --server 127.0.0.1 --port 9000 --cert certs/server.crt

# Terminal 2 - Bob
python client/client.py --server 127.0.0.1 --port 9000 --cert certs/server.crt
```

### 4. Run the Security & Unit Test Suite
```bash
pytest -v
```
