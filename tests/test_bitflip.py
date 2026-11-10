"""Testes de Validação de Segurança contra Adulteração / Bitflip (tests/test_bitflip.py).

Valida que modificar mesmo um único bit no texto cifrado, Dados Associados (AAD),
nonce ou na tag de autenticação de 16 bytes faz a verificação AES-128-GCM falhar imediatamente
com InvalidTag (ou FramingError se a consistência de nonce/seq_no for violada).
"""

import os

from cryptography.exceptions import InvalidTag
import pytest

from common.crypto import AES_KEY_SIZE, IV_BASE_SIZE, generate_client_id
from common.protocol import (
    E2E_HEADER_SIZE,
    E2EFrame,
    FramingError,
    create_encrypted_frame,
    decrypt_e2e_frame,
)


def _flip_bit(data: bytes, byte_index: int, bit_mask: int = 0x01) -> bytes:
    mutable = bytearray(data)
    mutable[byte_index] ^= bit_mask
    return bytes(mutable)


def test_valid_e2e_frame_roundtrip():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender_id = generate_client_id()
    recipient_id = generate_client_id()
    seq_no = 1
    plaintext = b"Top secret E2E message payload"

    frame = create_encrypted_frame(
        key=key,
        iv_base=iv_base,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq_no=seq_no,
        plaintext=plaintext,
    )
    wire_bytes = frame.pack()
    unpacked = E2EFrame.unpack(wire_bytes)

    recovered = decrypt_e2e_frame(unpacked, key=key, expected_iv_base=iv_base)
    assert recovered == plaintext


def test_bitflip_in_ciphertext_raises_invalid_tag():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender_id = generate_client_id()
    recipient_id = generate_client_id()
    plaintext = b"Confidential financial transfer: $1000 to Alice"

    frame = create_encrypted_frame(
        key=key,
        iv_base=iv_base,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq_no=42,
        plaintext=plaintext,
    )
    raw = frame.pack()

    # Inverte 1 bit no meio do texto cifrado (após o cabeçalho de 52 bytes)
    tampered_raw = _flip_bit(raw, E2E_HEADER_SIZE + len(plaintext) // 2, 0x01)
    tampered_frame = E2EFrame.unpack(tampered_raw)

    with pytest.raises(InvalidTag):
        decrypt_e2e_frame(tampered_frame, key=key, expected_iv_base=iv_base)


def test_bitflip_in_gcm_tag_raises_invalid_tag():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender_id = generate_client_id()
    recipient_id = generate_client_id()

    frame = create_encrypted_frame(
        key=key,
        iv_base=iv_base,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq_no=7,
        plaintext=b"Verify GCM authentication tag integrity",
    )
    raw = frame.pack()

    # Inverte 1 bit no último byte da tag GCM de 16 bytes
    tampered_raw = _flip_bit(raw, len(raw) - 1, 0x80)
    tampered_frame = E2EFrame.unpack(tampered_raw)

    with pytest.raises(InvalidTag):
        decrypt_e2e_frame(tampered_frame, key=key, expected_iv_base=iv_base)


def test_bitflip_in_aad_sender_or_recipient_raises_invalid_tag():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender_id = generate_client_id()
    recipient_id = generate_client_id()

    frame = create_encrypted_frame(
        key=key,
        iv_base=iv_base,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq_no=10,
        plaintext=b"Authenticated header test",
    )
    raw = frame.pack()

    # O byte 15 está dentro de sender_id (bytes 12..28), que faz parte do AAD
    tampered_sender_raw = _flip_bit(raw, 15, 0x04)
    tampered_sender_frame = E2EFrame.unpack(tampered_sender_raw)
    with pytest.raises(InvalidTag):
        decrypt_e2e_frame(tampered_sender_frame, key=key, expected_iv_base=iv_base)

    # O byte 30 está dentro de recipient_id (bytes 28..44), que faz parte do AAD
    tampered_recipient_raw = _flip_bit(raw, 30, 0x02)
    tampered_recipient_frame = E2EFrame.unpack(tampered_recipient_raw)
    with pytest.raises(InvalidTag):
        decrypt_e2e_frame(tampered_recipient_frame, key=key, expected_iv_base=iv_base)


def test_bitflip_in_nonce_or_seq_no_rejected():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender_id = generate_client_id()
    recipient_id = generate_client_id()

    frame = create_encrypted_frame(
        key=key,
        iv_base=iv_base,
        sender_id=sender_id,
        recipient_id=recipient_id,
        seq_no=99,
        plaintext=b"Nonce tampering test",
    )
    raw = frame.pack()

    # Inverte bit na porção IV_base do nonce (byte 0) sem verificação de expected_iv_base -> InvalidTag
    tampered_nonce_raw = _flip_bit(raw, 0, 0x01)
    tampered_nonce_frame = E2EFrame.unpack(tampered_nonce_raw)
    with pytest.raises(InvalidTag):
        decrypt_e2e_frame(tampered_nonce_frame, key=key)

    # Com expected_iv_base informado -> detectado antes mesmo do AES-GCM como FramingError
    with pytest.raises(FramingError):
        decrypt_e2e_frame(tampered_nonce_frame, key=key, expected_iv_base=iv_base)
