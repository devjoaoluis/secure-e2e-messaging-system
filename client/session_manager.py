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
    """Exceção base para erros de gerenciamento de sessão do cliente."""


class UnknownPeerError(SessionError):
    """Lançada ao tentar se comunicar com um peer não registrado."""


class ReplayAttackError(SessionError):
    """Lançada quando um frame E2E recebido possui um número de sequência duplicado ou não monotónico."""


class RecipientMismatchError(SessionError):
    """Lançada quando um frame E2E recebido não é endereçado ao client_id local."""


@dataclass
class PeerSession:
    """Contém chaves direcionais, bases de IV e contadores monotónicos para um único peer."""

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
        """Retorna e incrementa o número de sequência de envio monotónico de 64 bits (inicia em 1)."""
        if self.seq_send >= MAX_SEQ_NO:
            raise SessionError("Outgoing sequence counter exhausted; session rekey required.")
        self.seq_send += 1
        return self.seq_send

    def verify_monotonic_seq(self, incoming_seq_no: int) -> None:
        """Garante que incoming_seq_no seja estritamente maior que o maior seq_recv já aceito."""
        if incoming_seq_no <= self.seq_recv:
            raise ReplayAttackError(
                f"Replay detected from peer {self.peer_id.hex()[:8]}: "
                f"incoming seq_no={incoming_seq_no} <= last_accepted={self.seq_recv}."
            )

    def clear_secrets(self) -> None:
        """Zeroiza materiais sensíveis de chaves e IVs na memória."""
        zeroize(self.key_send)
        zeroize(self.key_recv)
        zeroize(self.iv_base_send)
        zeroize(self.iv_base_recv)
        self.seq_send = 0
        self.seq_recv = -1

    def __repr__(self) -> str:
        """Representação sanitizada que nunca expõe chaves, IVs ou segredos."""
        return (
            f"PeerSession(peer_id={self.peer_id.hex()[:12]}..., "
            f"seq_send={self.seq_send}, seq_recv={self.seq_recv})"
        )


class SessionManager:
    """Gerencia a identidade efêmera do cliente local e as sessões ativas com peers E2E."""

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
        """Registra a chave pública efêmera do servidor e o salt de 16 bytes verificados."""
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
        """Calcula Z_AB = ECDH(sk_client, pk_peer), deriva chaves direcionais com HKDF-SHA256,
        zeroiza Z_AB e armazena o estado do peer em `self.peers`.
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

        # Se substituir uma sessão de peer já existente, zeroiza as chaves antigas primeiro
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
        """Zeroiza e remove o estado de sessão de um único peer."""
        session = self.peers.pop(bytes(peer_id), None)
        if session is not None:
            session.clear_secrets()

    def get_peer(self, peer_id: bytes) -> PeerSession:
        """Recupera uma PeerSession ativa ou lança UnknownPeerError."""
        session = self.peers.get(bytes(peer_id))
        if session is None:
            raise UnknownPeerError(f"Peer {peer_id.hex()[:8]} is not registered.")
        return session

    def encrypt_message(self, recipient_id: bytes, plaintext: bytes) -> E2EFrame:
        """Cifra uma mensagem em texto claro para `recipient_id` usando sua chave direcional de envio
        e o próximo `seq_no` monotónico.
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
        """Valida e decifra um E2EFrame recebido (ou bytes brutos do frame).

        Executa:
        1. Verificação do destinatário (frame.recipient_id == self.client_id)
        2. Busca do remetente em `self.peers`
        3. Verificação anti-replay (frame.seq_no > peer.seq_recv)
        4. Verificação da base de IV do nonce e da tag de autenticação AES-128-GCM
        5. Atualização do contador monotónico (`peer.seq_recv = frame.seq_no`) SOMENTE após a tag ser validada

        Retorna:
            Uma tupla de (sender_id, decrypted_plaintext).
        """
        parsed = E2EFrame.unpack(frame) if isinstance(frame, (bytes, bytearray, memoryview)) else frame
        if not isinstance(parsed, E2EFrame):
            raise FramingError("Expected E2EFrame or raw bytes.")

        if parsed.recipient_id != self.client_id:
            raise RecipientMismatchError(
                f"Frame recipient_id ({parsed.recipient_id.hex()[:8]}) does not match local client_id."
            )

        peer = self.get_peer(parsed.sender_id)

        # Passo 1: Rejeita replay ou número de sequência fora de ordem antes da decifração
        peer.verify_monotonic_seq(parsed.seq_no)

        # Passo 2: Verifica a estrutura do nonce e a tag de autenticação AES-GCM
        plaintext = decrypt_e2e_frame(
            frame=parsed,
            key=bytes(peer.key_recv),
            expected_iv_base=bytes(peer.iv_base_recv),
        )

        # Passo 3: Comita o novo número de sequência monotónico somente após a decifração autêntica
        peer.seq_recv = parsed.seq_no
        return parsed.sender_id, plaintext

    def clear(self, rotate_ephemeral_keys: bool = True) -> None:
        """Modelo de Memória Transitória: zeroiza todas as chaves de peers e limpa o estado de sessão ao desconectar.
        Opcionalmente rotaciona o par efêmero X25519 para forçar um novo handshake completo.
        """
        for session in self.peers.values():
            session.clear_secrets()
        self.peers.clear()
        self.server_salt = None
        self.pk_server = None
        if rotate_ephemeral_keys:
            self._sk_client, self.pk_client = generate_x25519_keypair()

    def __repr__(self) -> str:
        """Representação sanitizada que nunca expõe chaves privadas ou segredos de sessão."""
        return (
            f"SessionManager(client_id={self.client_id.hex()[:12]}..., "
            f"active_peers={len(self.peers)})"
        )
