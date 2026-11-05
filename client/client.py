"""Multi-Client E2E Secure Messaging Client & Interactive CLI (client/client.py).

Implements the client-side protocol flow defined in docs/context.md:
1. Ephemeral X25519 key generation at startup (`SessionManager`).
2. TCP connection & Client Registration (`client_id + pk_client`).
3. Server Proof verification: validates pinned `server.crt` and RSA-PSS signature over
   H = SHA256(pk_server || pk_client || client_id || salt).
4. Peer key exchange reception & HKDF-SHA256 session key derivation.
5. Asynchronous E2E AES-128-GCM frame encryption/decryption with monotonic anti-replay checks.
6. Strict log sanitization (no private keys, shared secrets, symmetric keys, nonces, or plaintexts logged)
   and transient memory cleanup on disconnect.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import sys
from typing import Callable, Optional
import uuid

# Ensure project root is on sys.path when invoked as `python client/client.py`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from cryptography.exceptions import InvalidTag

from client.session_manager import (
    RecipientMismatchError,
    ReplayAttackError,
    SessionError,
    SessionManager,
    UnknownPeerError,
)
from common.crypto import (
    CLIENT_ID_SIZE,
    SALT_SIZE,
    X25519_KEY_SIZE,
    CryptoError,
    verify_server_handshake,
)
from common.protocol import (
    ClientHello,
    E2EFrame,
    FramingError,
    PacketType,
    PeerKeyAnnouncement,
    ServerHello,
    read_tcp_frame,
    write_tcp_frame,
)

logger = logging.getLogger("e2e.client")


MessageCallback = Callable[[bytes, bytes], None]


class SecureMessagingClient:
    """Asynchronous E2E encrypted messaging client."""

    def __init__(
        self,
        server_host: str,
        server_port: int,
        pinned_cert_path: str | Path | None = None,
        pinned_cert_bytes: bytes | None = None,
        client_id: bytes | None = None,
        on_message: Optional[MessageCallback] = None,
        use_packet_type_prefix: bool = False,
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.use_packet_type_prefix = use_packet_type_prefix
        self.on_message = on_message

        if pinned_cert_bytes is not None:
            self.pinned_cert_bytes: bytes | None = bytes(pinned_cert_bytes)
        elif pinned_cert_path is not None:
            self.pinned_cert_bytes = Path(pinned_cert_path).read_bytes()
        else:
            self.pinned_cert_bytes = None

        self.session = SessionManager(client_id=client_id)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._recv_task: asyncio.Task[None] | None = None
        self._connected = False

    @property
    def client_id(self) -> bytes:
        return self.session.client_id

    @property
    def client_id_hex(self) -> str:
        return self.session.client_id.hex()

    async def connect_and_handshake(self) -> None:
        """Open TCP connection, send ClientHello, and verify ServerHello RSA-PSS proof."""
        self._reader, self._writer = await asyncio.open_connection(
            self.server_host, self.server_port
        )
        try:
            # 1) Client Registration: client_id (16B) + pk_client (32B)
            hello = ClientHello(
                client_id=self.session.client_id,
                pk_client=self.session.pk_client,
            )
            await write_tcp_frame(
                self._writer,
                hello.pack(include_type=self.use_packet_type_prefix),
            )
            logger.info(
                "Sent client registration (client_id=%s)",
                self.client_id_hex[:12],
            )

            # 2) Server Proof: pk_S + cert + sig + salt
            raw_server_hello = await read_tcp_frame(self._reader)
            server_hello = ServerHello.unpack(raw_server_hello)

            verify_server_handshake(
                server_cert_bytes=server_hello.cert_bytes,
                pinned_cert_bytes=self.pinned_cert_bytes,
                pk_server=server_hello.pk_server,
                pk_client=self.session.pk_client,
                client_id=self.session.client_id,
                salt=server_hello.salt,
                signature=server_hello.signature,
            )

            self.session.set_server_handshake_context(
                pk_server=server_hello.pk_server,
                salt_srv=server_hello.salt,
            )
            self._connected = True
            logger.info(
                "Server RSA-PSS handshake verified for client_id=%s",
                self.client_id_hex[:12],
            )
        except Exception:
            await self.close()
            raise

    def start_background_receiver(self) -> asyncio.Task[None]:
        """Start the background task that processes incoming peer keys and E2E frames."""
        if not self._connected or self._reader is None:
            raise RuntimeError("Client must complete handshake before starting receiver loop.")
        self._recv_task = asyncio.create_task(self._receive_loop())
        return self._recv_task

    async def _receive_loop(self) -> None:
        assert self._reader is not None
        try:
            while self._connected:
                raw_packet = await read_tcp_frame(self._reader)
                self._handle_incoming_packet(raw_packet)
        except EOFError:
            logger.info("Server closed connection.")
        except FramingError as exc:
            logger.error("Protocol framing violation on connection: %s", exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Unexpected error in receive loop: %s", exc)
        finally:
            await self.close()

    def _handle_incoming_packet(self, raw_packet: bytes) -> None:
        """Dispatch an incoming framed packet (peer key broadcast, disconnect, or E2E frame)."""
        if not raw_packet:
            return

        # Case 1: Explicit packet type prefix
        first_byte = raw_packet[0]
        peer_base_len = CLIENT_ID_SIZE + X25519_KEY_SIZE

        if first_byte == PacketType.PEER_KEY and len(raw_packet) in (
            1 + peer_base_len,
            1 + peer_base_len + SALT_SIZE,
        ):
            announcement = PeerKeyAnnouncement.unpack(raw_packet)
            self._register_announced_peer(announcement)
            return

        if first_byte == PacketType.PEER_DISCONNECT and len(raw_packet) == 1 + CLIENT_ID_SIZE:
            peer_id = raw_packet[1:]
            self.session.remove_peer(peer_id)
            logger.info("Peer disconnected and session wiped: peer_id=%s", peer_id.hex()[:12])
            return

        if first_byte == PacketType.E2E_DATA and len(raw_packet) > 1:
            self._process_e2e_bytes(raw_packet[1:])
            return

        # Case 2: Raw unprefixed PeerKeyAnnouncement (48B or 64B) vs E2EFrame (>= 68B)
        if len(raw_packet) in (peer_base_len, peer_base_len + SALT_SIZE):
            announcement = PeerKeyAnnouncement.unpack(raw_packet)
            self._register_announced_peer(announcement)
            return

        # Case 3: Raw E2EFrame
        self._process_e2e_bytes(raw_packet)

    def _register_announced_peer(self, announcement: PeerKeyAnnouncement) -> None:
        if announcement.peer_id == self.client_id:
            return
        self.session.register_peer(
            peer_id=announcement.peer_id,
            pk_peer=announcement.pk_peer,
            salt=announcement.salt,
        )
        logger.info(
            "Registered E2E session with peer_id=%s",
            announcement.peer_id.hex()[:12],
        )

    def _process_e2e_bytes(self, frame_bytes: bytes) -> None:
        try:
            sender_id, plaintext = self.session.decrypt_frame(frame_bytes)
            logger.info(
                "Verified and decrypted E2E frame from sender_id=%s (seq_no=%d, size=%dB)",
                sender_id.hex()[:12],
                self.session.get_peer(sender_id).seq_recv,
                len(plaintext),
            )
            if self.on_message is not None:
                self.on_message(sender_id, plaintext)
        except InvalidTag:
            logger.warning("Dropped E2E frame: AES-GCM authentication tag verification failed.")
        except ReplayAttackError as exc:
            logger.warning("Dropped E2E frame: %s", exc)
        except (FramingError, RecipientMismatchError, UnknownPeerError, SessionError) as exc:
            logger.warning("Dropped E2E frame: %s", exc)

    async def send_message(self, recipient_id: bytes, plaintext: bytes | str) -> E2EFrame:
        """Encrypt a message for `recipient_id` with AES-128-GCM and transmit over TCP."""
        if not self._connected or self._writer is None:
            raise RuntimeError("Client is not connected.")
        payload_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        frame = self.session.encrypt_message(recipient_id, payload_bytes)
        wire_data = frame.pack()
        if self.use_packet_type_prefix:
            wire_data = bytes([PacketType.E2E_DATA]) + wire_data
        await write_tcp_frame(self._writer, wire_data)
        logger.info(
            "Sent E2E frame to recipient_id=%s (seq_no=%d, ciphertext_len=%dB)",
            recipient_id.hex()[:12],
            frame.seq_no,
            len(frame.ciphertext),
        )
        return frame

    async def broadcast_message(self, plaintext: bytes | str) -> list[E2EFrame]:
        """Send an individually encrypted E2E frame to every active peer."""
        frames: list[E2EFrame] = []
        for peer_id in list(self.session.peers.keys()):
            frame = await self.send_message(peer_id, plaintext)
            frames.append(frame)
        return frames

    def resolve_peer_id(self, prefix_or_hex: str) -> bytes:
        """Resolve a full or prefix hex string to a registered 16-byte peer_id."""
        cleaned = prefix_or_hex.strip().lower().replace("-", "")
        matches = [pid for pid in self.session.peers if pid.hex().startswith(cleaned)]
        if not matches:
            raise UnknownPeerError(f"No active peer matching '{prefix_or_hex}'.")
        if len(matches) > 1:
            raise SessionError(f"Ambiguous peer prefix '{prefix_or_hex}'; matched {len(matches)} peers.")
        return matches[0]

    async def close(self) -> None:
        """Close the TCP connection and wipe all transient session keys from memory."""
        self._connected = False
        if self._recv_task is not None and not self._recv_task.done():
            if self._recv_task is not asyncio.current_task():
                self._recv_task.cancel()
                try:
                    await self._recv_task
                except asyncio.CancelledError:
                    pass
        self._recv_task = None

        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
        self._reader = None

        # Transient Memory Model: zeroize all keys and clear peer state
        self.session.clear(rotate_ephemeral_keys=True)


async def run_interactive_cli(
    server_host: str,
    server_port: int,
    cert_path: str,
) -> None:
    """Run the interactive command-line client."""

    def _print_incoming(sender_id: bytes, plaintext: bytes) -> None:
        text = plaintext.decode("utf-8", errors="replace")
        print(f"\n[{sender_id.hex()[:12]}] > {text}")
        print("e2e> ", end="", flush=True)

    client = SecureMessagingClient(
        server_host=server_host,
        server_port=server_port,
        pinned_cert_path=cert_path,
        on_message=_print_incoming,
    )

    await client.connect_and_handshake()
    recv_task = client.start_background_receiver()

    print(f"Connected to {server_host}:{server_port}")
    print(f"Local client_id : {uuid.UUID(bytes=client.client_id)} ({client.client_id_hex})")
    print("Commands: /peers | /msg <peer_hex_prefix> <text> | /all <text> | /id | /quit")

    loop = asyncio.get_running_loop()
    try:
        while client._connected and not recv_task.done():
            line = await loop.run_in_executor(None, lambda: input("e2e> "))
            cmd = line.strip()
            if not cmd:
                continue
            if cmd in ("/quit", "/exit"):
                break
            if cmd == "/id":
                print(f"client_id: {client.client_id_hex}")
                continue
            if cmd == "/peers":
                if not client.session.peers:
                    print("No peers connected yet.")
                else:
                    for pid, ps in client.session.peers.items():
                        print(
                            f" - {pid.hex()} (seq_send={ps.seq_send}, seq_recv={ps.seq_recv})"
                        )
                continue
            if cmd.startswith("/msg "):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: /msg <peer_hex_prefix> <message>")
                    continue
                _, peer_prefix, msg_text = parts
                try:
                    target_id = client.resolve_peer_id(peer_prefix)
                    await client.send_message(target_id, msg_text)
                except Exception as exc:
                    print(f"Error: {exc}")
                continue
            if cmd.startswith("/all "):
                msg_text = cmd[5:]
                await client.broadcast_message(msg_text)
                continue

            # Default: broadcast to all connected peers
            if not client.session.peers:
                print("No active peers to send message to.")
            else:
                await client.broadcast_message(cmd)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        await client.close()
        print("Disconnected and cleared session keys from memory.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="E2E Secure Messaging Client")
    parser.add_argument("--server", default="127.0.0.1", help="Relay server host/IP")
    parser.add_argument("--port", type=int, default=9000, help="Relay server TCP port")
    parser.add_argument(
        "--cert",
        required=True,
        help="Path to pinned server X.509 certificate (certs/server.crt)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args(argv)
    try:
        asyncio.run(run_interactive_cli(args.server, args.port, args.cert))
    except CryptoError as exc:
        logger.error("Cryptographic verification error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
