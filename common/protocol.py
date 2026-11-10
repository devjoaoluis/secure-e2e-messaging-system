from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import IntEnum
import struct

from common.crypto import (
    CLIENT_ID_SIZE,
    GCM_TAG_SIZE,
    IV_BASE_SIZE,
    MAX_PLAINTEXT_SIZE,
    MAX_SEQ_NO,
    NONCE_SIZE,
    SALT_SIZE,
    SEQ_NO_SIZE,
    X25519_KEY_SIZE,
    build_aad,
    build_nonce,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
)

TCP_LEN_PREFIX_SIZE = 4
E2E_HEADER_FORMAT = "!12s16s16sQ"  # Nonce(12B) + sender_id(16B) + recipient_id(16B) + seq_no(8B)
E2E_HEADER_SIZE = struct.calcsize(E2E_HEADER_FORMAT)  # 52 bytes
MIN_E2E_FRAME_SIZE = E2E_HEADER_SIZE + GCM_TAG_SIZE  # 68 bytes
MAX_E2E_FRAME_SIZE = E2E_HEADER_SIZE + MAX_PLAINTEXT_SIZE + GCM_TAG_SIZE  # 4164 bytes
MAX_TCP_FRAME_SIZE = 65536


class FramingError(Exception):
    """Lançada quando um frame TCP ou E2E viola restrições de tamanho ou estrutura."""


class PacketType(IntEnum):
    """Tipos de pacotes de controle e dados para a orquestração do protocolo cliente-servidor."""

    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    PEER_KEY = 0x03
    PEER_DISCONNECT = 0x04
    E2E_DATA = 0x05


@dataclass(frozen=True)
class E2EFrame:
    """Representa um Frame de Aplicação Cifrado E2E serializado."""

    nonce: bytes
    sender_id: bytes
    recipient_id: bytes
    seq_no: int
    ciphertext: bytes
    tag: bytes

    @property
    def aad(self) -> bytes:
        """Retorna os 40 bytes de Dados Associados: sender_id (16B) || recipient_id (16B) || seq_no (8B)."""
        return build_aad(self.sender_id, self.recipient_id, self.seq_no)

    @property
    def iv_base(self) -> bytes:
        """Extrai o prefixo IV_base de 4 bytes a partir do nonce de 12 bytes."""
        return self.nonce[:IV_BASE_SIZE]

    def validate(self) -> None:
        """Valida os tamanhos de todos os campos e limites estruturais."""
        if len(self.nonce) != NONCE_SIZE:
            raise FramingError(f"Invalid nonce length: {len(self.nonce)} (expected {NONCE_SIZE}).")
        if len(self.sender_id) != CLIENT_ID_SIZE:
            raise FramingError(
                f"Invalid sender_id length: {len(self.sender_id)} (expected {CLIENT_ID_SIZE})."
            )
        if len(self.recipient_id) != CLIENT_ID_SIZE:
            raise FramingError(
                f"Invalid recipient_id length: {len(self.recipient_id)} (expected {CLIENT_ID_SIZE})."
            )
        if not (0 <= self.seq_no <= MAX_SEQ_NO):
            raise FramingError(f"Invalid 64-bit seq_no: {self.seq_no}.")
        if len(self.tag) != GCM_TAG_SIZE:
            raise FramingError(f"Invalid GCM tag length: {len(self.tag)} (expected {GCM_TAG_SIZE}).")
        if len(self.ciphertext) > MAX_PLAINTEXT_SIZE:
            raise FramingError(
                f"Ciphertext length ({len(self.ciphertext)} B) exceeds maximum bound ({MAX_PLAINTEXT_SIZE} B)."
            )

    def pack(self) -> bytes:
        """Serializa o frame E2E nos bytes brutos da rede:
        Nonce (12B) || sender_id (16B) || recipient_id (16B) || seq_no (8B) || Ciphertext || Tag (16B).
        """
        self.validate()
        header = struct.pack(
            E2E_HEADER_FORMAT,
            self.nonce,
            self.sender_id,
            self.recipient_id,
            self.seq_no,
        )
        return header + self.ciphertext + self.tag

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> E2EFrame:
        """Desserializa bytes brutos da rede em uma instância de E2EFrame."""
        if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
            raise FramingError("E2E frame input must be bytes-like.")
        data = bytes(raw_bytes)
        if len(data) < MIN_E2E_FRAME_SIZE:
            raise FramingError(
                f"E2E frame too short: {len(data)} bytes (minimum {MIN_E2E_FRAME_SIZE} bytes)."
            )
        if len(data) > MAX_E2E_FRAME_SIZE:
            raise FramingError(
                f"E2E frame too large: {len(data)} bytes (maximum {MAX_E2E_FRAME_SIZE} bytes)."
            )

        nonce, sender_id, recipient_id, seq_no = struct.unpack(
            E2E_HEADER_FORMAT, data[:E2E_HEADER_SIZE]
        )
        ciphertext = data[E2E_HEADER_SIZE:-GCM_TAG_SIZE]
        tag = data[-GCM_TAG_SIZE:]

        frame = cls(
            nonce=nonce,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=seq_no,
            ciphertext=ciphertext,
            tag=tag,
        )
        frame.validate()
        return frame


def create_encrypted_frame(
    key: bytes,
    iv_base: bytes,
    sender_id: bytes,
    recipient_id: bytes,
    seq_no: int,
    plaintext: bytes,
) -> E2EFrame:
    """Constrói o nonce e AAD, cifra o plaintext com AES-128-GCM e retorna um E2EFrame."""
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise FramingError(
            f"Plaintext size ({len(plaintext)} B) exceeds maximum bound ({MAX_PLAINTEXT_SIZE} B)."
        )
    nonce = build_nonce(iv_base, seq_no)
    aad = build_aad(sender_id, recipient_id, seq_no)
    ciphertext, tag = encrypt_aes_gcm(key=key, nonce=nonce, plaintext=plaintext, aad=aad)
    return E2EFrame(
        nonce=nonce,
        sender_id=bytes(sender_id),
        recipient_id=bytes(recipient_id),
        seq_no=seq_no,
        ciphertext=ciphertext,
        tag=tag,
    )


def decrypt_e2e_frame(
    frame: E2EFrame,
    key: bytes,
    expected_iv_base: bytes | None = None,
) -> bytes:
    """Valida a estrutura do frame, a consistência do nonce e decifra com AES-128-GCM.

    Lança:
        FramingError: Se a estrutura do frame ou a construção do nonce estiverem malformadas.
        InvalidTag: Se o ciphertext, AAD ou tag de autenticação tiverem sido adulterados.
    """
    frame.validate()
    nonce_seq = struct.unpack("!Q", frame.nonce[IV_BASE_SIZE:])[0]
    if nonce_seq != frame.seq_no:
        raise FramingError(
            f"Nonce sequence number ({nonce_seq}) does not match frame header seq_no ({frame.seq_no})."
        )
    if expected_iv_base is not None and frame.iv_base != expected_iv_base:
        raise FramingError("Frame nonce IV_base does not match expected session IV_base.")

    return decrypt_aes_gcm(
        key=key,
        nonce=frame.nonce,
        ciphertext=frame.ciphertext,
        tag=frame.tag,
        aad=frame.aad,
    )


# ---------------------------------------------------------------------------
# Enquadramento TCP com Prefixo de Tamanho (4 bytes big-endian)
# ---------------------------------------------------------------------------


def pack_tcp_frame(payload: bytes, max_size: int = MAX_TCP_FRAME_SIZE) -> bytes:
    """Adiciona um prefixo de tamanho de 4 bytes big-endian a um payload bruto."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("Payload must be bytes-like.")
    raw = bytes(payload)
    length = len(raw)
    if length == 0:
        raise FramingError("Cannot pack empty TCP payload.")
    if length > max_size:
        raise FramingError(
            f"TCP payload length ({length} B) exceeds maximum allowed ({max_size} B)."
        )
    return struct.pack("!I", length) + raw


def unpack_tcp_frame(tcp_packet: bytes, max_size: int = MAX_TCP_FRAME_SIZE) -> bytes:
    """Desempacota e valida um único pacote TCP com prefixo de tamanho a partir de bytes brutos."""
    if not isinstance(tcp_packet, (bytes, bytearray, memoryview)):
        raise FramingError("TCP packet must be bytes-like.")
    data = bytes(tcp_packet)
    if len(data) < TCP_LEN_PREFIX_SIZE:
        raise FramingError(
            f"Malformed TCP packet: length {len(data)} is shorter than 4-byte header."
        )
    declared_len = struct.unpack("!I", data[:TCP_LEN_PREFIX_SIZE])[0]
    if declared_len == 0:
        raise FramingError("Malformed TCP packet: zero-length payload declared.")
    if declared_len > max_size:
        raise FramingError(
            f"Malformed TCP packet: declared length ({declared_len} B) exceeds maximum ({max_size} B)."
        )
    actual_len = len(data) - TCP_LEN_PREFIX_SIZE
    if actual_len != declared_len:
        raise FramingError(
            f"TCP framing mismatch: header declared {declared_len} bytes, but got {actual_len} bytes."
        )
    return data[TCP_LEN_PREFIX_SIZE:]


async def read_tcp_frame(
    reader: asyncio.StreamReader,
    max_size: int = MAX_TCP_FRAME_SIZE,
) -> bytes:
    """Lê um frame com prefixo de tamanho a partir de um asyncio StreamReader.

    Lança:
        EOFError: Se a conexão for fechada de forma limpa pelo peer antes de ler um frame.
        FramingError: Se o prefixo de tamanho for inválido ou a conexão for truncada durante a leitura.
    """
    try:
        prefix = await reader.readexactly(TCP_LEN_PREFIX_SIZE)
    except asyncio.IncompleteReadError as exc:
        if len(exc.partial) == 0:
            raise EOFError("Connection closed by remote peer.") from exc
        raise FramingError(
            f"Truncated 4-byte TCP length prefix: received {len(exc.partial)} bytes."
        ) from exc

    declared_len = struct.unpack("!I", prefix)[0]
    if declared_len == 0:
        raise FramingError("Invalid TCP frame with declared length 0.")
    if declared_len > max_size:
        raise FramingError(
            f"Declared TCP frame length ({declared_len} B) exceeds maximum ({max_size} B)."
        )

    try:
        payload = await reader.readexactly(declared_len)
    except asyncio.IncompleteReadError as exc:
        raise FramingError(
            f"Truncated TCP frame payload: expected {declared_len} bytes, received {len(exc.partial)} bytes."
        ) from exc

    return payload


async def write_tcp_frame(
    writer: asyncio.StreamWriter,
    payload: bytes,
    max_size: int = MAX_TCP_FRAME_SIZE,
) -> None:
    """Escreve um frame com prefixo de tamanho de 4 bytes em um asyncio StreamWriter."""
    framed = pack_tcp_frame(payload, max_size=max_size)
    writer.write(framed)
    await writer.drain()


# ---------------------------------------------------------------------------
# Serialização de Mensagens de Handshake e Controle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientHello:
    """Passo 1: Payload de registro do cliente (client_id + pk_client)."""

    client_id: bytes
    pk_client: bytes

    def pack(self, include_type: bool = False) -> bytes:
        if len(self.client_id) != CLIENT_ID_SIZE:
            raise FramingError(f"client_id must be {CLIENT_ID_SIZE} bytes.")
        if len(self.pk_client) != X25519_KEY_SIZE:
            raise FramingError(f"pk_client must be {X25519_KEY_SIZE} bytes.")
        body = self.client_id + self.pk_client
        return (bytes([PacketType.CLIENT_HELLO]) + body) if include_type else body

    @classmethod
    def unpack(cls, data: bytes) -> ClientHello:
        raw = bytes(data)
        if len(raw) == 1 + CLIENT_ID_SIZE + X25519_KEY_SIZE and raw[0] == PacketType.CLIENT_HELLO:
            raw = raw[1:]
        if len(raw) != CLIENT_ID_SIZE + X25519_KEY_SIZE:
            raise FramingError(
                f"Invalid ClientHello length: {len(raw)} (expected {CLIENT_ID_SIZE + X25519_KEY_SIZE})."
            )
        return cls(
            client_id=raw[:CLIENT_ID_SIZE],
            pk_client=raw[CLIENT_ID_SIZE:],
        )


@dataclass(frozen=True)
class ServerHello:
    """Passo 2: Prova de handshake do servidor (pk_server + cert + sig + salt)."""

    pk_server: bytes
    salt: bytes
    cert_bytes: bytes
    signature: bytes

    def pack(self, include_type: bool = False) -> bytes:
        if len(self.pk_server) != X25519_KEY_SIZE:
            raise FramingError(f"pk_server must be {X25519_KEY_SIZE} bytes.")
        if len(self.salt) != SALT_SIZE:
            raise FramingError(f"salt must be {SALT_SIZE} bytes.")
        if not self.cert_bytes or not self.signature:
            raise FramingError("cert_bytes and signature cannot be empty.")
        body = (
            self.pk_server
            + self.salt
            + struct.pack("!II", len(self.cert_bytes), len(self.signature))
            + self.cert_bytes
            + self.signature
        )
        return (bytes([PacketType.SERVER_HELLO]) + body) if include_type else body

    @classmethod
    def unpack(cls, data: bytes) -> ServerHello:
        raw = bytes(data)
        if raw and raw[0] == PacketType.SERVER_HELLO:
            # Verifica se o byte 0 é uma tag de tipo
            candidate = raw[1:]
            if len(candidate) >= X25519_KEY_SIZE + SALT_SIZE + 8:
                c_len, s_len = struct.unpack(
                    "!II",
                    candidate[X25519_KEY_SIZE + SALT_SIZE : X25519_KEY_SIZE + SALT_SIZE + 8],
                )
                if len(candidate) == X25519_KEY_SIZE + SALT_SIZE + 8 + c_len + s_len:
                    raw = candidate

        min_header = X25519_KEY_SIZE + SALT_SIZE + 8
        if len(raw) < min_header:
            raise FramingError(f"ServerHello too short ({len(raw)} bytes).")

        pk_server = raw[:X25519_KEY_SIZE]
        salt = raw[X25519_KEY_SIZE : X25519_KEY_SIZE + SALT_SIZE]
        cert_len, sig_len = struct.unpack("!II", raw[X25519_KEY_SIZE + SALT_SIZE : min_header])
        expected_total = min_header + cert_len + sig_len
        if len(raw) != expected_total:
            raise FramingError(
                f"Malformed ServerHello: expected {expected_total} bytes, got {len(raw)}."
            )
        cert_bytes = raw[min_header : min_header + cert_len]
        signature = raw[min_header + cert_len :]
        return cls(
            pk_server=pk_server,
            salt=salt,
            cert_bytes=cert_bytes,
            signature=signature,
        )


@dataclass(frozen=True)
class PeerKeyAnnouncement:
    """Passo 5/6: Servidor anuncia o client_id e a chave pública efêmera (pk_client) de um peer."""

    peer_id: bytes
    pk_peer: bytes
    salt: bytes | None = None

    def pack(self, include_type: bool = True) -> bytes:
        if len(self.peer_id) != CLIENT_ID_SIZE:
            raise FramingError(f"peer_id must be {CLIENT_ID_SIZE} bytes.")
        if len(self.pk_peer) != X25519_KEY_SIZE:
            raise FramingError(f"pk_peer must be {X25519_KEY_SIZE} bytes.")
        if self.salt is not None and len(self.salt) != SALT_SIZE:
            raise FramingError(f"salt must be {SALT_SIZE} bytes when provided.")
        body = self.peer_id + self.pk_peer + (self.salt if self.salt is not None else b"")
        return (bytes([PacketType.PEER_KEY]) + body) if include_type else body

    @classmethod
    def unpack(cls, data: bytes) -> PeerKeyAnnouncement:
        raw = bytes(data)
        base_len = CLIENT_ID_SIZE + X25519_KEY_SIZE
        if len(raw) in (1 + base_len, 1 + base_len + SALT_SIZE) and raw[0] == PacketType.PEER_KEY:
            raw = raw[1:]
        if len(raw) == base_len:
            return cls(
                peer_id=raw[:CLIENT_ID_SIZE],
                pk_peer=raw[CLIENT_ID_SIZE:],
                salt=None,
            )
        if len(raw) == base_len + SALT_SIZE:
            return cls(
                peer_id=raw[:CLIENT_ID_SIZE],
                pk_peer=raw[CLIENT_ID_SIZE:base_len],
                salt=raw[base_len:],
            )
        raise FramingError(f"Invalid PeerKeyAnnouncement length: {len(raw)} bytes.")
