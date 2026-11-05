"""Client-side peer session management, HKDF key derivation, IV tracking, and anti-replay state.

Maintains the `peers` dictionary mapping each peer's 16-byte `client_id` to its
cryptographic session state:
- Directional AES-128-GCM keys (`key_send`, `key_recv`)
- Directional 4-byte IV bases (`iv_base_send`, `iv_base_recv`)
- Monotonic 64-bit sequence counters (`seq_send`, `seq_recv`)

Enforces:
- Strict monotonic sequence numbers (`seq_no > seq_recv`) to prevent replay attacks
- Tag verification before committing state updates (`seq_recv`) to prevent DoS via forged packets
- Transient memory model: zeroizes and wipes all peer keys upon disconnection
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import x25519

from common.crypto import (
    CLIENT_ID_SIZE,
    MAX_SEQ_NO,
    SALT_SIZE,
    X25519_KEY_SIZE,
    derive_e2e_session_keys,
    generate_client_id,
    generate_x25519_keypair,
    zeroize,
)
from common.protocol import (
    E2EFrame,
    FramingError,
    create_encrypted_frame,
    decrypt_e2e_frame,
)


class SessionError(Exception):
    """Base exception for client session management errors."""


class UnknownPeerError(SessionError):
    """Raised when attempting to communicate with an unregistered peer."""


class ReplayAttackError(SessionError):
    """Raised when an incoming E2E frame has a duplicate or non-monotonic sequence number."""


class RecipientMismatchError(SessionError):
    """Raised when an incoming E2E frame is not addressed to the local client_id."""


@dataclass
class PeerSession:
    """Holds directional keys, IV bases, and monotonic counters for a single peer."""

    peer_id: bytes
    pk_peer: bytes
    salt: bytes
    key_send: bytearray
    key_recv: bytearray
    iv_base_send: bytearray
    iv_base_recv: bytearray
    seq_send: int = 0
    seq_recv: int = -1

    def next_send_seq(self) -> int:
        """Return and increment the 64-bit monotonic send sequence number (starts at 1)."""
        if self.seq_send >= MAX_SEQ_NO:
            raise SessionError("Outgoing sequence counter exhausted; session rekey required.")
        self.seq_send += 1
        return self.seq_send

    def verify_monotonic_seq(self, incoming_seq_no: int) -> None:
        """Ensure incoming_seq_no is strictly greater than the highest accepted seq_recv."""
        if incoming_seq_no <= self.seq_recv:
            raise ReplayAttackError(
                f"Replay detected from peer {self.peer_id.hex()[:8]}: "
                f"incoming seq_no={incoming_seq_no} <= last_accepted={self.seq_recv}."
            )

    def clear_secrets(self) -> None:
        """Zeroize sensitive key and IV material in memory."""
        zeroize(self.key_send)
        zeroize(self.key_recv)
        zeroize(self.iv_base_send)
        zeroize(self.iv_base_recv)
        self.seq_send = 0
        self.seq_recv = -1

    def __repr__(self) -> str:
        """Sanitized representation that never exposes keys, IVs, or secrets."""
        return (
            f"PeerSession(peer_id={self.peer_id.hex()[:12]}..., "
            f"seq_send={self.seq_send}, seq_recv={self.seq_recv})"
        )


class SessionManager:
    """Manages the local client's ephemeral identity and active E2E peer sessions."""

    def __init__(self, client_id: bytes | None = None) -> None:
        if client_id is not None:
            if len(client_id) != CLIENT_ID_SIZE:
                raise ValueError(f"client_id must be {CLIENT_ID_SIZE} bytes.")
            self.client_id: bytes = bytes(client_id)
        else:
            self.client_id = generate_client_id()

        self._sk_client: x25519.X25519PrivateKey
        self.pk_client: bytes
        self._sk_client, self.pk_client = generate_x25519_keypair()

        self.server_salt: bytes | None = None
        self.pk_server: bytes | None = None
        self.peers: Dict[bytes, PeerSession] = {}

    def set_server_handshake_context(self, pk_server: bytes, salt_srv: bytes) -> None:
        """Record verified server ephemeral public key and 16-byte session salt."""
        if len(pk_server) != X25519_KEY_SIZE:
            raise ValueError(f"pk_server must be {X25519_KEY_SIZE} bytes.")
        if len(salt_srv) != SALT_SIZE:
            raise ValueError(f"salt_srv must be {SALT_SIZE} bytes.")
        self.pk_server = bytes(pk_server)
        self.server_salt = bytes(salt_srv)

    def register_peer(
        self,
        peer_id: bytes,
        pk_peer: bytes,
        salt: bytes | None = None,
    ) -> PeerSession:
        """Compute Z_AB = ECDH(sk_client, pk_peer), derive directional keys with HKDF-SHA256,
        zeroize Z_AB, and store the peer state in `self.peers`.
        """
        if len(peer_id) != CLIENT_ID_SIZE:
            raise ValueError(f"peer_id must be {CLIENT_ID_SIZE} bytes.")
        if peer_id == self.client_id:
            raise ValueError("Cannot register local client_id as a remote peer.")
        if len(pk_peer) != X25519_KEY_SIZE:
            raise ValueError(f"pk_peer must be {X25519_KEY_SIZE} bytes.")

        effective_salt = salt if salt is not None else self.server_salt
        if effective_salt is None:
            raise SessionError("Cannot derive peer keys without a 16-byte server salt.")

        # If replacing an existing peer session, zeroize old keys first
        if peer_id in self.peers:
            self.peers[peer_id].clear_secrets()

        derived = derive_e2e_session_keys(
            sk_local=self._sk_client,
            pk_peer=pk_peer,
            salt=effective_salt,
            local_id=self.client_id,
            peer_id=peer_id,
        )

        session = PeerSession(
            peer_id=bytes(peer_id),
            pk_peer=bytes(pk_peer),
            salt=bytes(effective_salt),
            key_send=bytearray(derived.key_send),
            key_recv=bytearray(derived.key_recv),
            iv_base_send=bytearray(derived.iv_base_send),
            iv_base_recv=bytearray(derived.iv_base_recv),
            seq_send=0,
            seq_recv=-1,
        )
        self.peers[bytes(peer_id)] = session
        return session

    def remove_peer(self, peer_id: bytes) -> None:
        """Zeroize and remove a single peer's session state."""
        session = self.peers.pop(bytes(peer_id), None)
        if session is not None:
            session.clear_secrets()

    def get_peer(self, peer_id: bytes) -> PeerSession:
        """Retrieve an active PeerSession or raise UnknownPeerError."""
        session = self.peers.get(bytes(peer_id))
        if session is None:
            raise UnknownPeerError(f"Peer {peer_id.hex()[:8]} is not registered.")
        return session

    def encrypt_message(self, recipient_id: bytes, plaintext: bytes) -> E2EFrame:
        """Encrypt a plaintext message for `recipient_id` using its directional send key
        and next monotonic `seq_no`.
        """
        peer = self.get_peer(recipient_id)
        seq_no = peer.next_send_seq()
        return create_encrypted_frame(
            key=bytes(peer.key_send),
            iv_base=bytes(peer.iv_base_send),
            sender_id=self.client_id,
            recipient_id=peer.peer_id,
            seq_no=seq_no,
            plaintext=plaintext,
        )

    def decrypt_frame(self, frame: E2EFrame | bytes) -> tuple[bytes, bytes]:
        """Validate and decrypt an incoming E2EFrame (or raw frame bytes).

        Performs:
        1. Recipient verification (frame.recipient_id == self.client_id)
        2. Sender lookup in `self.peers`
        3. Anti-replay check (frame.seq_no > peer.seq_recv)
        4. Nonce IV_base & AES-128-GCM tag verification
        5. Monotonic counter update (`peer.seq_recv = frame.seq_no`) ONLY after tag passes

        Returns:
            A tuple of (sender_id, decrypted_plaintext).
        """
        parsed = E2EFrame.unpack(frame) if isinstance(frame, (bytes, bytearray, memoryview)) else frame
        if not isinstance(parsed, E2EFrame):
            raise FramingError("Expected E2EFrame or raw bytes.")

        if parsed.recipient_id != self.client_id:
            raise RecipientMismatchError(
                f"Frame recipient_id ({parsed.recipient_id.hex()[:8]}) does not match local client_id."
            )

        peer = self.get_peer(parsed.sender_id)

        # Step 1: Reject replay or out-of-order sequence numbers before decryption
        peer.verify_monotonic_seq(parsed.seq_no)

        # Step 2: Verify nonce structure and AES-GCM authentication tag
        plaintext = decrypt_e2e_frame(
            frame=parsed,
            key=bytes(peer.key_recv),
            expected_iv_base=bytes(peer.iv_base_recv),
        )

        # Step 3: Commit new monotonic sequence number only after authentic decryption
        peer.seq_recv = parsed.seq_no
        return parsed.sender_id, plaintext

    def clear(self, rotate_ephemeral_keys: bool = True) -> None:
        """Transient Memory Model: zeroize all peer keys and wipe session state on disconnect.
        Optionally rotates the ephemeral X25519 keypair to enforce a full re-handshake.
        """
        for session in self.peers.values():
            session.clear_secrets()
        self.peers.clear()
        self.server_salt = None
        self.pk_server = None
        if rotate_ephemeral_keys:
            self._sk_client, self.pk_client = generate_x25519_keypair()

    def __repr__(self) -> str:
        """Sanitized representation that never exposes private keys or session secrets."""
        return (
            f"SessionManager(client_id={self.client_id.hex()[:12]}..., "
            f"active_peers={len(self.peers)})"
        )
