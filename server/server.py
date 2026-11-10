"""Servidor relay TCP assíncrono multi-cliente (server/server.py).

Implementa:
- Gerenciamento concorrente de sockets TCP multi-cliente usando `asyncio`
- Handshake autenticado via RSA-PSS (SHA-256) usando `certs/server.crt` e `certs/server.key`
- Broadcast de troca de chaves distribuindo chaves públicas efêmeras X25519 de peers ativos
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import sys

# Garante que a raiz do projeto esteja no sys.path quando executado como `python server/server.py`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from cryptography.hazmat.primitives.asymmetric import rsa

from common.crypto import (
    CryptoError,
    ensure_server_credentials,
    generate_x25519_keypair,
    sign_server_handshake,
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
from server.session_store import ClientSession, SessionStore

logger = logging.getLogger("e2e.server")


class RelayServer:
    """Servidor TCP assíncrono de encontro (rendezvous) e relay multi-cliente."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        cert_path: str | Path = "certs/server.crt",
        key_path: str | Path = "certs/server.key",
        rsa_private_key: rsa.RSAPrivateKey | None = None,
        cert_bytes: bytes | None = None,
        salt_srv: bytes | None = None,
    ) -> None:
        self.host = host
        self.port = port

        if rsa_private_key is not None and cert_bytes is not None:
            self.rsa_private_key = rsa_private_key
            self.cert_bytes = bytes(cert_bytes)
        else:
            self.rsa_private_key, self.cert_bytes = ensure_server_credentials(
                cert_path=cert_path,
                key_path=key_path,
                auto_generate=True,
            )

        self._sk_server, self.pk_server = generate_x25519_keypair()
        self.session_store = SessionStore(salt_srv=salt_srv)
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Inicia a escuta de conexões TCP simultâneas de clientes."""
        self._server = await asyncio.start_server(
            self._handle_client_connection,
            self.host,
            self.port,
        )
        sockets = self._server.sockets
        if sockets:
            self.port = sockets[0].getsockname()[1]
        logger.info("RelayServer listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Fecha todas as conexões ativas, limpa o armazenamento de sessões e para o servidor TCP."""
        for session in list(self.session_store.sessions.values()):
            if session.writer is not None:
                try:
                    session.writer.close()
                    await session.writer.wait_closed()
                except Exception:
                    pass
        self.session_store.clear()

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("RelayServer stopped and session store cleared.")

    async def _perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> ClientSession:
        """Executa os Passos 1 a 3 do protocolo:
        1. Recebe ClientHello (client_id + pk_client)
        2. Assina H = SHA256(pk_server || pk_client || client_id || salt) com RSA-PSS e envia ServerHello
        3. Registra a sessão do cliente e faz broadcast das chaves públicas efêmeras X25519 entre peers ativos
        """
        raw_hello = await read_tcp_frame(reader)
        client_hello = ClientHello.unpack(raw_hello)

        salt_srv = self.session_store.salt_srv
        signature = sign_server_handshake(
            rsa_private_key=self.rsa_private_key,
            pk_server=self.pk_server,
            pk_client=client_hello.pk_client,
            client_id=client_hello.client_id,
            salt=salt_srv,
        )

        server_hello = ServerHello(
            pk_server=self.pk_server,
            salt=salt_srv,
            cert_bytes=self.cert_bytes,
            signature=signature,
        )
        await write_tcp_frame(writer, server_hello.pack())

        peername = writer.get_extra_info("peername")
        existing_peers = self.session_store.get_other_sessions(client_hello.client_id)
        session, evicted = self.session_store.register_session(
            client_id=client_hello.client_id,
            pk_client=client_hello.pk_client,
            writer=writer,
            peername=peername,
            salt_srv=salt_srv,
        )
        if evicted is not None and evicted.writer is not None and evicted.writer is not writer:
            try:
                evicted.writer.close()
            except Exception:
                pass

        logger.info(
            "Registered client_id=%s (active_sessions=%d)",
            session.client_id.hex()[:12],
            len(self.session_store.sessions),
        )

        await self._broadcast_peer_keys(session, existing_peers)
        return session

    async def _broadcast_peer_keys(
        self,
        new_session: ClientSession,
        existing_peers: list[ClientSession],
    ) -> None:
        """Distribui as chaves públicas dos peers existentes ao recém-chegado e faz broadcast
        da chave pública do recém-chegado a todos os peers ativos existentes.
        """
        if new_session.writer is None:
            return

        newcomer_announcement = PeerKeyAnnouncement(
            peer_id=new_session.client_id,
            pk_peer=new_session.pk_client,
            salt=new_session.salt_srv,
        ).pack()

        for peer in existing_peers:
            # Envia a chave pública do peer existente para o recém-chegado
            peer_announcement = PeerKeyAnnouncement(
                peer_id=peer.client_id,
                pk_peer=peer.pk_client,
                salt=peer.salt_srv,
            ).pack()
            await write_tcp_frame(new_session.writer, peer_announcement)

            # Envia a chave pública do recém-chegado para o peer existente
            if peer.writer is not None and not peer.writer.is_closing():
                try:
                    await write_tcp_frame(peer.writer, newcomer_announcement)
                except Exception:
                    pass

    async def _broadcast_peer_disconnect(self, disconnected_client_id: bytes) -> None:
        """Notifica os peers ativos restantes que um cliente desconectou para que limpem sua sessão."""
        disconnect_packet = bytes([PacketType.PEER_DISCONNECT]) + bytes(disconnected_client_id)
        for peer in self.session_store.get_other_sessions(disconnected_client_id):
            if peer.writer is not None and not peer.writer.is_closing():
                try:
                    await write_tcp_frame(peer.writer, disconnect_packet)
                except Exception:
                    pass

    async def _handle_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session: ClientSession | None = None
        peername = writer.get_extra_info("peername")
        try:
            session = await self._perform_handshake(reader, writer)
            while True:
                raw_frame = await read_tcp_frame(reader)
                await self._handle_client_frame(session, raw_frame)
        except EOFError:
            logger.info(
                "Client disconnected cleanly (client_id=%s)",
                session.client_id.hex()[:12] if session else str(peername),
            )
        except FramingError as exc:
            logger.warning(
                "Framing violation from client (%s); terminating connection: %s",
                session.client_id.hex()[:12] if session else str(peername),
                exc,
            )
        except (CryptoError, ValueError) as exc:
            logger.warning(
                "Handshake or cryptographic validation error from client (%s): %s",
                session.client_id.hex()[:12] if session else str(peername),
                exc,
            )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Unexpected client connection error: %s", exc)
        finally:
            if session is not None:
                removed = self.session_store.remove_session(
                    session.client_id,
                    expected_session=session,
                )
                if removed is not None:
                    logger.info(
                        "Removed client session from memory: client_id=%s",
                        session.client_id.hex()[:12],
                    )
                    await self._broadcast_peer_disconnect(session.client_id)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_client_frame(
        self,
        session: ClientSession,
        raw_frame: bytes,
    ) -> None:
        """Relay Zero-Knowledge: inspeciona apenas o cabeçalho de roteamento (`sender_id`, `recipient_id`, `seq_no`)
        e encaminha os bytes opacos do frame cifrado para o destinatário alvo sem decifrar.
        """
        frame_bytes = (
            raw_frame[1:]
            if (raw_frame and raw_frame[0] == PacketType.E2E_DATA and len(raw_frame) > 1)
            else raw_frame
        )
        e2e_frame = E2EFrame.unpack(frame_bytes)

        if e2e_frame.sender_id != session.client_id:
            logger.warning(
                "Dropped spoofed E2E frame: authenticated client_id=%s tried to send as sender_id=%s",
                session.client_id.hex()[:12],
                e2e_frame.sender_id.hex()[:12],
            )
            return

        target_session = self.session_store.get_session(e2e_frame.recipient_id)
        if target_session is None or target_session.writer is None or target_session.writer.is_closing():
            logger.warning(
                "Dropped E2E frame from sender_id=%s: recipient_id=%s is not connected",
                session.client_id.hex()[:12],
                e2e_frame.recipient_id.hex()[:12],
            )
            return

        self.session_store.record_relayed_frame(
            sender_id=session.client_id,
            recipient_id=e2e_frame.recipient_id,
            seq_no=e2e_frame.seq_no,
            enforce_monotonic=False,
        )
        await write_tcp_frame(target_session.writer, raw_frame)
        logger.info(
            "Relayed opaque E2E frame: sender_id=%s -> recipient_id=%s (seq_no=%d, ciphertext_len=%dB)",
            session.client_id.hex()[:12],
            e2e_frame.recipient_id.hex()[:12],
            e2e_frame.seq_no,
            len(e2e_frame.ciphertext),
        )


async def run_server(
    host: str,
    port: int,
    cert_path: str,
    key_path: str,
) -> None:
    """Inicia o servidor relay e executa até ser interrompido."""
    server = RelayServer(
        host=host,
        port=port,
        cert_path=cert_path,
        key_path=key_path,
    )
    await server.start()
    assert server._server is not None
    try:
        async with server._server:
            await server._server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multi-Client E2E Zero-Knowledge Relay Server")
    parser.add_argument("--host", default="127.0.0.1", help="Endereço de bind (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Porta TCP de escuta (padrão: 9000)")
    parser.add_argument(
        "--cert",
        default="certs/server.crt",
        help="Caminho para o certificado X.509 do servidor (padrão: certs/server.crt)",
    )
    parser.add_argument(
        "--key",
        default="certs/server.key",
        help="Caminho para a chave privada RSA do servidor (padrão: certs/server.key)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args(argv)
    try:
        asyncio.run(run_server(args.host, args.port, args.cert, args.key))
    except KeyboardInterrupt:
        logger.info("Server interrupted by user.")


if __name__ == "__main__":
    main()
