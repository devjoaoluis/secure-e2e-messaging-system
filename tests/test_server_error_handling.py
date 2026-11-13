"""Testes para a Tarefa 5 do Developer 1: Tratamento de Erros no Servidor, Framing Malformado, Limpeza em Desconexões e CLI."""

import asyncio
import struct

from client.client import SecureMessagingClient
from common.crypto import generate_self_signed_rsa_cert
from server.server import RelayServer, parse_args


def test_server_terminates_malformed_framing_connection_without_affecting_healthy_clients():
    async def _run():
        rsa_sk, _, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
        server = RelayServer(
            host="127.0.0.1",
            port=0,
            rsa_private_key=rsa_sk,
            cert_bytes=cert_pem,
        )
        await server.start()

        bob_inbox: list[tuple[bytes, bytes]] = []
        alice = SecureMessagingClient("127.0.0.1", server.port, pinned_cert_bytes=cert_pem)
        bob = SecureMessagingClient(
            "127.0.0.1",
            server.port,
            pinned_cert_bytes=cert_pem,
            on_message=lambda s, p: bob_inbox.append((s, p)),
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

            # Cliente malicioso conecta e envia um prefixo de 4 bytes malformado (declara 500B, fecha após 5B)
            _, rogue_writer = await asyncio.open_connection("127.0.0.1", server.port)
            rogue_writer.write(struct.pack("!I", 500) + b"short")
            await rogue_writer.drain()
            rogue_writer.close()
            await rogue_writer.wait_closed()

            # Outro cliente malicioso envia um prefixo de 4 bytes superdimensionado (999999 bytes)
            _, rogue_writer2 = await asyncio.open_connection("127.0.0.1", server.port)
            rogue_writer2.write(struct.pack("!I", 999999) + b"bad")
            await rogue_writer2.drain()
            await asyncio.sleep(0.05)
            rogue_writer2.close()

            # Verifica se Alice e Bob ainda conseguem trocar mensagens cifradas normalmente
            await alice.send_message(bob.client_id, "Still alive after malformed framing attack")
            for _ in range(20):
                if bob_inbox:
                    break
                await asyncio.sleep(0.02)

            assert bob_inbox == [
                (alice.client_id, b"Still alive after malformed framing attack")
            ]
        finally:
            await asyncio.gather(alice.close(), bob.close())
            await server.stop()

    asyncio.run(_run())


def test_client_disconnect_clears_server_session_and_notifies_remaining_peers():
    async def _run():
        rsa_sk, _, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
        server = RelayServer(
            host="127.0.0.1",
            port=0,
            rsa_private_key=rsa_sk,
            cert_bytes=cert_pem,
        )
        await server.start()

        alice = SecureMessagingClient("127.0.0.1", server.port, pinned_cert_bytes=cert_pem)
        bob = SecureMessagingClient("127.0.0.1", server.port, pinned_cert_bytes=cert_pem)

        try:
            await alice.connect_and_handshake()
            alice.start_background_receiver()
            await bob.connect_and_handshake()
            bob.start_background_receiver()

            for _ in range(20):
                if bob.client_id in alice.session.peers and alice.client_id in bob.session.peers:
                    break
                await asyncio.sleep(0.02)

            bob_id = bob.client_id
            assert server.session_store.get_session(bob_id) is not None
            assert bob_id in alice.session.peers

            # Bob desconecta -> Servidor remove a sessão de Bob e notifica Alice
            await bob.close()

            for _ in range(25):
                if server.session_store.get_session(bob_id) is None and bob_id not in alice.session.peers:
                    break
                await asyncio.sleep(0.02)

            assert server.session_store.get_session(bob_id) is None
            assert bob_id not in alice.session.peers
        finally:
            await alice.close()
            await server.stop()

    asyncio.run(_run())


def test_server_cli_argument_parsing():
    args = parse_args(["--host", "0.0.0.0", "--port", "9100", "--cert", "c.crt", "--key", "k.key"])
    assert args.host == "0.0.0.0"
    assert args.port == 9100
    assert args.cert == "c.crt"
    assert args.key == "k.key"
