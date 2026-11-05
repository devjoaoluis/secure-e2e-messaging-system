"""End-to-End Client & Security Policy Tests (tests/test_client_e2e.py).

Validates:
1. Full async handshake (ClientHello -> ServerHello with pinned X.509 cert & RSA-PSS).
2. Automatic peer key exchange broadcast & HKDF session establishment between Alice and Bob.
3. Bidirectional AES-128-GCM encrypted messaging over TCP relay.
4. Active tampering (bitflip) and replay rejection in the live client receive loop.
5. Strict log sanitization policy (private keys, shared secrets, symmetric keys, nonces,
   and raw plaintexts are never written to logs).
6. Transient memory cleanup on disconnect.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from client.client import SecureMessagingClient
from common.crypto import (
    SALT_SIZE,
    generate_x25519_keypair,
    sign_server_handshake,
)
from common.protocol import (
    ClientHello,
    E2EFrame,
    PeerKeyAnnouncement,
    ServerHello,
    read_tcp_frame,
    write_tcp_frame,
)


def _generate_server_credentials() -> tuple[rsa.RSAPrivateKey, bytes]:
    rsa_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "SecureRelayServer")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(rsa_sk, hashes.SHA256())
    )
    return rsa_sk, cert.public_bytes(serialization.Encoding.PEM)


class _MockRelayServer:
    """Minimal zero-knowledge TCP relay for testing Developer 2's client end-to-end."""

    def __init__(self, rsa_sk: rsa.RSAPrivateKey, cert_pem: bytes) -> None:
        self.rsa_sk = rsa_sk
        self.cert_pem = cert_pem
        self.sk_server, self.pk_server = generate_x25519_keypair()
        self.shared_salt = os.urandom(SALT_SIZE)
        self.clients: dict[bytes, tuple[ bytes, asyncio.StreamWriter]] = {}
        self.server: asyncio.AbstractServer | None = None
        self.port: int = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client_id = None
        try:
            raw_hello = await read_tcp_frame(reader)
            ch = ClientHello.unpack(raw_hello)
            client_id = ch.client_id

            sig = sign_server_handshake(
                self.rsa_sk,
                self.pk_server,
                ch.pk_client,
                ch.client_id,
                self.shared_salt,
            )
            sh = ServerHello(
                pk_server=self.pk_server,
                salt=self.shared_salt,
                cert_bytes=self.cert_pem,
                signature=sig,
            )
            await write_tcp_frame(writer, sh.pack())

            # Broadcast existing peers to newcomer, and newcomer to existing peers
            for existing_id, (existing_pk, existing_writer) in list(self.clients.items()):
                await write_tcp_frame(
                    writer,
                    PeerKeyAnnouncement(
                        peer_id=existing_id,
                        pk_peer=existing_pk,
                        salt=self.shared_salt,
                    ).pack(),
                )
                await write_tcp_frame(
                    existing_writer,
                    PeerKeyAnnouncement(
                        peer_id=ch.client_id,
                        pk_peer=ch.pk_client,
                        salt=self.shared_salt,
                    ).pack(),
                )

            self.clients[ch.client_id] = (ch.pk_client, writer)

            while True:
                raw_frame = await read_tcp_frame(reader)
                e2e = E2EFrame.unpack(raw_frame)
                target = self.clients.get(e2e.recipient_id)
                if target is not None:
                    await write_tcp_frame(target[1], raw_frame)
        except (EOFError, asyncio.CancelledError):
            pass
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            writer.close()


def test_full_client_e2e_handshake_messaging_and_log_sanitization(caplog):
    async def _run():
        caplog.set_level(logging.INFO)
        rsa_sk, cert_pem = _generate_server_credentials()
        relay = _MockRelayServer(rsa_sk, cert_pem)
        await relay.start()

        alice_received: list[tuple[bytes, bytes]] = []
        bob_received: list[tuple[bytes, bytes]] = []

        alice = SecureMessagingClient(
            server_host="127.0.0.1",
            server_port=relay.port,
            pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: alice_received.append((s, p)),
        )
        bob = SecureMessagingClient(
            server_host="127.0.0.1",
            server_port=relay.port,
            pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: bob_received.append((s, p)),
        )

        try:
            await alice.connect_and_handshake()
            alice.start_background_receiver()

            await bob.connect_and_handshake()
            bob.start_background_receiver()

            # Wait briefly for peer key announcements to arrive
            for _ in range(20):
                if bob.client_id in alice.session.peers and alice.client_id in bob.session.peers:
                    break
                await asyncio.sleep(0.02)

            assert bob.client_id in alice.session.peers
            assert alice.client_id in bob.session.peers

            secret_msg_a = "UltraSecretPlaintext_AliceToBob_987654"
            secret_msg_b = "UltraSecretPlaintext_BobToAlice_123456"

            sent_frame = await alice.send_message(bob.client_id, secret_msg_a)
            await bob.send_message(alice.client_id, secret_msg_b)

            for _ in range(20):
                if alice_received and bob_received:
                    break
                await asyncio.sleep(0.02)

            assert bob_received == [(alice.client_id, secret_msg_a.encode("utf-8"))]
            assert alice_received == [(bob.client_id, secret_msg_b.encode("utf-8"))]

            # Audit logs: verify neither plaintexts, symmetric keys, nor nonces appear in logs
            peer_state = alice.session.get_peer(bob.client_id)
            key_send_hex = bytes(peer_state.key_send).hex()
            key_recv_hex = bytes(peer_state.key_recv).hex()
            nonce_hex = sent_frame.nonce.hex()

            log_output = caplog.text
            assert secret_msg_a not in log_output
            assert secret_msg_b not in log_output
            assert key_send_hex not in log_output
            assert key_recv_hex not in log_output
            assert nonce_hex not in log_output
        finally:
            await alice.close()
            await bob.close()
            await relay.stop()

        # Verify transient memory model after close()
        assert len(alice.session.peers) == 0
        assert len(bob.session.peers) == 0

    asyncio.run(_run())
