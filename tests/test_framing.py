"""Framing & Malformed Packet Tests (tests/test_framing.py).

Validates 4-byte big-endian TCP framing, E2E frame structural bounds,
and safe rejection of truncated, oversized, or length-mismatched packets.
"""

import asyncio
import os
import struct

import pytest

from common.crypto import AES_KEY_SIZE, IV_BASE_SIZE, MAX_PLAINTEXT_SIZE, generate_client_id
from common.protocol import (
    E2EFrame,
    FramingError,
    create_encrypted_frame,
    pack_tcp_frame,
    read_tcp_frame,
    unpack_tcp_frame,
)


def test_tcp_frame_pack_and_unpack_success():
    payload = b"hello framed world"
    framed = pack_tcp_frame(payload)
    assert len(framed) == 4 + len(payload)
    assert struct.unpack("!I", framed[:4])[0] == len(payload)
    assert unpack_tcp_frame(framed) == payload


def test_tcp_frame_length_mismatch_rejected():
    payload = b"expected_16_byte"
    framed = pack_tcp_frame(payload)

    # Truncated payload (fewer bytes than 4-byte prefix declares)
    with pytest.raises(FramingError, match="TCP framing mismatch"):
        unpack_tcp_frame(framed[:-3])

    # Extra trailing bytes beyond 4-byte prefix declaration
    with pytest.raises(FramingError, match="TCP framing mismatch"):
        unpack_tcp_frame(framed + b"extra")


def test_tcp_frame_zero_or_oversized_prefix_rejected():
    with pytest.raises(FramingError, match="Cannot pack empty TCP payload"):
        pack_tcp_frame(b"")

    zero_prefix = struct.pack("!I", 0)
    with pytest.raises(FramingError, match="zero-length payload"):
        unpack_tcp_frame(zero_prefix)

    oversized_prefix = struct.pack("!I", 999999) + b"abc"
    with pytest.raises(FramingError, match="exceeds maximum"):
        unpack_tcp_frame(oversized_prefix)


def test_async_stream_reader_truncated_frame_raises_framing_error():
    async def _run():
        reader = asyncio.StreamReader()
        # Declare 50 bytes in 4-byte big-endian prefix, but only feed 10 bytes before EOF
        reader.feed_data(struct.pack("!I", 50) + b"0123456789")
        reader.feed_eof()

        with pytest.raises(FramingError, match="Truncated TCP frame payload"):
            await read_tcp_frame(reader)

    asyncio.run(_run())


def test_e2e_frame_payload_bound_4096_bytes_enforced():
    key = os.urandom(AES_KEY_SIZE)
    iv_base = os.urandom(IV_BASE_SIZE)
    sender = generate_client_id()
    recipient = generate_client_id()

    # Exact 4096-byte payload succeeds
    max_msg = b"A" * MAX_PLAINTEXT_SIZE
    frame = create_encrypted_frame(key, iv_base, sender, recipient, 1, max_msg)
    assert len(E2EFrame.unpack(frame.pack()).ciphertext) == MAX_PLAINTEXT_SIZE

    # 4097-byte payload is rejected
    oversized_msg = b"A" * (MAX_PLAINTEXT_SIZE + 1)
    with pytest.raises(FramingError, match="exceeds maximum bound"):
        create_encrypted_frame(key, iv_base, sender, recipient, 2, oversized_msg)


def test_truncated_e2e_frame_rejected():
    with pytest.raises(FramingError, match="E2E frame too short"):
        E2EFrame.unpack(b"short_frame")
