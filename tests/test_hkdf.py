"""Unit tests for Task 2: ECDH shared secret and HKDF-SHA256 key derivation."""

import os

import pytest

from common.crypto import (
    AES_KEY_SIZE,
    IV_BASE_SIZE,
    SALT_SIZE,
    X25519_KEY_SIZE,
    compute_shared_secret,
    derive_directional_keys,
    derive_e2e_session_keys,
    generate_client_id,
    generate_x25519_keypair,
    hkdf_expand,
    hkdf_extract,
    zeroize,
)


def test_ecdh_shared_secret_symmetry():
    sk_a, pk_a = generate_x25519_keypair()
    sk_b, pk_b = generate_x25519_keypair()

    z_ab = compute_shared_secret(sk_a, pk_b)
    z_ba = compute_shared_secret(sk_b, pk_a)

    assert len(z_ab) == X25519_KEY_SIZE
    assert z_ab == z_ba


def test_hkdf_extract_and_expand_labels_and_zeroization():
    sk_a, pk_a = generate_x25519_keypair()
    sk_b, pk_b = generate_x25519_keypair()
    salt = os.urandom(SALT_SIZE)

    z_ab = compute_shared_secret(sk_a, pk_b)
    z_copy = bytes(z_ab)

    key_a2b, key_b2a = derive_directional_keys(z_ab, salt)

    # Z_AB bytearray must be zeroized immediately after derivation
    assert z_ab == bytearray(X25519_KEY_SIZE)

    # Keys must be 16 bytes (AES-128) and distinct for A2B vs B2A
    assert len(key_a2b) == AES_KEY_SIZE
    assert len(key_b2a) == AES_KEY_SIZE
    assert key_a2b != key_b2a

    # Verify against explicit HKDF-Extract + HKDF-Expand steps
    prk = hkdf_extract(salt, z_copy)
    assert hkdf_expand(prk, b"A2B", 16) == key_a2b
    assert hkdf_expand(prk, b"B2A", 16) == key_b2a
    zeroize(prk)
    assert prk == bytearray(32)


def test_derive_e2e_session_keys_matching_directions():
    sk_a, pk_a = generate_x25519_keypair()
    sk_b, pk_b = generate_x25519_keypair()
    id_a = generate_client_id()
    id_b = generate_client_id()
    salt = os.urandom(SALT_SIZE)

    keys_a = derive_e2e_session_keys(sk_a, pk_b, salt, local_id=id_a, peer_id=id_b)
    keys_b = derive_e2e_session_keys(sk_b, pk_a, salt, local_id=id_b, peer_id=id_a)

    assert keys_a.key_a2b == keys_b.key_a2b
    assert keys_a.key_b2a == keys_b.key_b2a
    # Alice's send key must equal Bob's receive key and vice-versa
    assert keys_a.key_send == keys_b.key_recv
    assert keys_b.key_send == keys_a.key_recv
    assert keys_a.iv_base_send == keys_b.iv_base_recv
    assert keys_b.iv_base_send == keys_a.iv_base_recv
    assert len(keys_a.iv_base_send) == IV_BASE_SIZE


def test_hkdf_invalid_salt_rejected():
    sk_a, _ = generate_x25519_keypair()
    _, pk_b = generate_x25519_keypair()
    with pytest.raises(ValueError, match="Server salt must be 16 bytes"):
        derive_e2e_session_keys(sk_a, pk_b, b"short_salt")
