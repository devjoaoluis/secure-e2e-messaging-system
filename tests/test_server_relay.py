"""Testes unitários para a Tarefa 4 do Developer 1: Roteamento e Relay de Frames E2E Zero-Knowledge (tests/test_server_relay.py)."""

import asyncio
import logging

from client.client import SecureMessagingClient
from common.crypto import generate_client_id, generate_self_signed_rsa_cert
from common.protocol import E2EFrame, write_tcp_frame
from server.server import RelayServer


def test_zero_knowledge_multi_client_routing_and_log_audit(caplog):
    async def _run():
        caplog.set_level(logging.INFO)
        rsa_sk, _, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
        server = RelayServer(
            host="127.0.0.1",
            port=0,
            rsa_private_key=rsa_sk,
            cert_bytes=cert_pem,
        )
        await server.start()

        inbox_a: list[tuple[bytes, bytes]] = []
        inbox_b: list[tuple[bytes, bytes]] = []
        inbox_c: list[tuple[bytes, bytes]] = []

        alice = SecureMessagingClient(
            "127.0.0.1", server.port, pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: inbox_a.append((s, p)),
        )
        bob = SecureMessagingClient(
            "127.0.0.1", server.port, pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: inbox_b.append((s, p)),
        )
        charlie = SecureMessagingClient(
            "127.0.0.1", server.port, pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: inbox_c.append((s, p)),
        )

        try:
            for c in (alice, bob, charlie):
                await c.connect_and_handshake()
                c.start_background_receiver()

            for _ in range(30):
                if all(len(c.session.peers) == 2 for c in (alice, bob, charlie)):
                    break
                await asyncio.sleep(0.02)

            msg_ab = "ZeroKnowledgeSecret_AliceToBob"
            msg_bc = "ZeroKnowledgeSecret_BobToCharlie"

            await alice.send_message(bob.client_id, msg_ab)
            await bob.send_message(charlie.client_id, msg_bc)

            for _ in range(30):
                if inbox_b and inbox_c:
                    break
                await asyncio.sleep(0.02)

            # Verifica roteamento seletivo: Charlie nunca recebe a mensagem entre Alice e Bob
            assert inbox_b == [(alice.client_id, msg_ab.encode("utf-8"))]
            assert inbox_c == [(bob.client_id, msg_bc.encode("utf-8"))]
            assert inbox_a == []

            # Verifica contadores de roteamento do servidor
            assert server.session_store.get_session(alice.client_id).frames_sent == 1
            assert server.session_store.get_session(bob.client_id).frames_received == 1
            assert server.session_store.get_session(bob.client_id).frames_sent == 1
            assert server.session_store.get_session(charlie.client_id).frames_received == 1

            # Auditoria de Logs Zero-Knowledge: servidor loga apenas cabeçalhos de roteamento, nunca plaintexts ou chaves
            assert "Relayed opaque E2E frame" in caplog.text
            assert msg_ab not in caplog.text
            assert msg_bc not in caplog.text
        finally:
            await asyncio.gather(alice.close(), bob.close(), charlie.close())
            await server.stop()

    asyncio.run(_run())


def test_relay_drops_sender_spoofed_and_offline_recipient_frames():
    async def _run():
        rsa_sk, _, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
        server = RelayServer(
            host="127.0.0.1",
            port=0,
            rsa_private_key=rsa_sk,
            cert_bytes=cert_pem,
        )
        await server.start()

        inbox_b: list[tuple[bytes, bytes]] = []
        alice = SecureMessagingClient("127.0.0.1", server.port, pinned_cert_bytes=cert_pem)
        bob = SecureMessagingClient(
            "127.0.0.1", server.port, pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: inbox_b.append((s, p)),
        )

        try:
            await alice.connect_and_handshake()
            alice.start_background_receiver()
            await bob.connect_and_handshake()
            bob.start_background_receiver()

            for _ in range(20):
                if bob.client_id in alice.session.peers:
                    break
                await asyncio.sleep(0.02)

            # Forja um frame onde Alice tenta falsificar o sender_id com um ID falso aleatório
            legit_frame = alice.session.encrypt_message(bob.client_id, b"Spoof attempt")
            spoofed_frame = E2EFrame(
                nonce=legit_frame.nonce,
                sender_id=generate_client_id(),
                recipient_id=bob.client_id,
                seq_no=legit_frame.seq_no,
                ciphertext=legit_frame.ciphertext,
                tag=legit_frame.tag,
            )
            assert alice._writer is not None
            await write_tcp_frame(alice._writer, spoofed_frame.pack())

            # Envia também um frame endereçado a um destinatário inexistente/offline
            offline_frame = E2EFrame(
                nonce=legit_frame.nonce,
                sender_id=alice.client_id,
                recipient_id=generate_client_id(),
                seq_no=legit_frame.seq_no,
                ciphertext=legit_frame.ciphertext,
                tag=legit_frame.tag,
            )
            await write_tcp_frame(alice._writer, offline_frame.pack())
            await asyncio.sleep(0.05)

            assert inbox_b == []
            assert server.session_store.get_session(bob.client_id).frames_received == 0
        finally:
            await asyncio.gather(alice.close(), bob.close())
            await server.stop()

    asyncio.run(_run())
