"""Server-side active client session storage and routing table (server/session_store.py).

Maintains the `sessions` dictionary mapping each active `client_id` (16B) to its
`ClientSession` metadata:
- `client_id` (16B UUIDv4)
- `pk_client` (32B ephemeral X25519 public key)
- `salt_srv` (16B random server salt)
- Routing counters (`frames_sent`, `frames_received`) and sequence counters (`seq_counters`)
- Associated `asyncio.StreamWriter`

Enforces the Transient Memory Model:
- Disconnection clears all session state for the client from memory.
- Reconnecting under an existing `client_id` evicts the prior session and enforces
  a full re-handshake and key renegotiation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import os
from typing import Dict

from common.crypto import (
    CLIENT_ID_SIZE,
    SALT_SIZE,
    X25519_KEY_SIZE,
    load_x25519_public_key,
)


class ServerSessionError(Exception):
    """Base exception for server session store errors."""


class ServerReplayOrSequenceError(ServerSessionError):
    """Raised when the relay detects a non-monotonic sequence number for a (sender, recipient) pair."""


@dataclass
class ClientSession:
    """Represents an active client registered with the relay server."""

    client_id: bytes
    pk_client: bytes
    salt_srv: bytes
    writer: asyncio.StreamWriter | None = None
    peername: tuple[str, int] | None = None
    frames_sent: int = 0
    frames_received: int = 0
    seq_counters: Dict[bytes, int] = field(default_factory=dict)

    def clear(self) -> None:
        """Clear transient counters and references on disconnect."""
        self.seq_counters.clear()
        self.frames_sent = 0
        self.frames_received = 0
        self.writer = None

    def __repr__(self) -> str:
        """Sanitized representation that never logs raw keys or secrets."""
        return (
            f"ClientSession(client_id={self.client_id.hex()[:12]}..., "
            f"frames_sent={self.frames_sent}, frames_received={self.frames_received})"
        )


class SessionStore:
    """In-memory store for active client sessions and E2E frame routing tables."""

    def __init__(self, salt_srv: bytes | None = None) -> None:
        if salt_srv is not None:
            if len(salt_srv) != SALT_SIZE:
                raise ValueError(f"salt_srv must be {SALT_SIZE} bytes.")
            self.salt_srv: bytes = bytes(salt_srv)
        else:
            self.salt_srv = os.urandom(SALT_SIZE)

        self.sessions: Dict[bytes, ClientSession] = {}

    def register_session(
        self,
        client_id: bytes,
        pk_client: bytes,
        writer: asyncio.StreamWriter | None = None,
        peername: tuple[str, int] | None = None,
        salt_srv: bytes | None = None,
    ) -> tuple[ClientSession, ClientSession | None]:
        """Register or replace a client session in `self.sessions`.

        Returns:
            A tuple of (new_session, evicted_previous_session_or_None).
        """
        if len(client_id) != CLIENT_ID_SIZE:
            raise ValueError(f"client_id must be {CLIENT_ID_SIZE} bytes.")
        if len(pk_client) != X25519_KEY_SIZE:
            raise ValueError(f"pk_client must be {X25519_KEY_SIZE} bytes.")
        # Validate that pk_client is a well-formed X25519 public key
        load_x25519_public_key(pk_client)

        effective_salt = bytes(salt_srv) if salt_srv is not None else self.salt_srv
        if len(effective_salt) != SALT_SIZE:
            raise ValueError(f"salt_srv must be {SALT_SIZE} bytes.")

        evicted = self.sessions.pop(bytes(client_id), None)
        if evicted is not None:
            evicted.clear()
            # Also reset directional seq_counters referencing the reconnected client in other sessions
            for other in self.sessions.values():
                other.seq_counters.pop(bytes(client_id), None)

        session = ClientSession(
            client_id=bytes(client_id),
            pk_client=bytes(pk_client),
            salt_srv=effective_salt,
            writer=writer,
            peername=peername,
        )
        self.sessions[bytes(client_id)] = session
        return session, evicted

    def get_session(self, client_id: bytes) -> ClientSession | None:
        """Look up an active session by its 16-byte client_id."""
        return self.sessions.get(bytes(client_id))

    def get_other_sessions(self, exclude_client_id: bytes) -> list[ClientSession]:
        """Return all active sessions except `exclude_client_id`."""
        target = bytes(exclude_client_id)
        return [s for cid, s in self.sessions.items() if cid != target]

    def remove_session(
        self,
        client_id: bytes,
        expected_session: ClientSession | None = None,
    ) -> ClientSession | None:
        """Remove a client session from memory and wipe its transient counters.

        If `expected_session` is provided, only removes the entry if it still points
        to that exact `ClientSession` instance (prevents race conditions on reconnect).
        """
        cid = bytes(client_id)
        current = self.sessions.get(cid)
        if current is None:
            return None
        if expected_session is not None and current is not expected_session:
            return None

        removed = self.sessions.pop(cid)
        removed.clear()
        for other in self.sessions.values():
            other.seq_counters.pop(cid, None)
        return removed

    def record_relayed_frame(
        self,
        sender_id: bytes,
        recipient_id: bytes,
        seq_no: int,
        enforce_monotonic: bool = True,
    ) -> None:
        """Update routing counters and track directional sequence numbers."""
        sender = self.get_session(sender_id)
        recipient = self.get_session(recipient_id)
        if sender is None:
            raise ServerSessionError("Sender does not have an active session.")
        if recipient is None:
            raise ServerSessionError("Recipient does not have an active session.")

        last_seq = sender.seq_counters.get(bytes(recipient_id), -1)
        if enforce_monotonic and seq_no <= last_seq:
            raise ServerReplayOrSequenceError(
                f"Non-monotonic sequence number on relay ({seq_no} <= {last_seq})."
            )

        sender.seq_counters[bytes(recipient_id)] = seq_no
        sender.frames_sent += 1
        recipient.frames_received += 1

    def clear(self) -> None:
        """Clear all active sessions from memory."""
        for session in self.sessions.values():
            session.clear()
        self.sessions.clear()

    def __repr__(self) -> str:
        return f"SessionStore(active_sessions={len(self.sessions)})"
