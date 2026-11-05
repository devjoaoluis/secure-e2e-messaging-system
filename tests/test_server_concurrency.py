"""Unit tests for Developer 1 Task 3: Concurrent Multi-Client TCP Server & Key Broadcast."""

import asyncio

from client.client import SecureMessagingClient
from common.crypto import generate_self_signed_rsa_cert
from server.server import RelayServer


def test_concurrent_multi_client_handshakes_and_key_broadcast():
    async def _run():
        rsa_sk, _, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
        server = RelayServer(
            host="127.0.0.1",
            port=0,
            rsa_private_key=rsa_sk,
            cert_bytes=cert_pem,
        )
        await server.start()

        clients = [
            SecureMessagingClient(
                server_host="127.0.0.1",
                server_port=server.port,
                pinned_cert_bytes=cert_pem,
            )
            for _ in range(4)
        ]

        try:
            # Connect all 4 clients concurrently
            await asyncio.gather(*(c.connect_and_handshake() for c in clients))
            for c in clients:
                c.start_background_receiver()

            # Wait for all 4 clients to receive each other's public keys (3 peers each)
            for _ in range(30):
                if all(len(c.session.peers) == 3 for c in clients):
                    break
                await asyncio.sleep(0.02)

            assert len(server.session_store.sessions) == 4
            for c in clients:
                assert len(c.session.peers) == 3
                other_ids = {o.client_id for o in clients if o.client_id != c.client_id}
                assert set(c.session.peers.keys()) == other_ids
        finally:
            await asyncio.gather(*(c.close() for c in clients))
            await server.stop()

    asyncio.run(_run())
