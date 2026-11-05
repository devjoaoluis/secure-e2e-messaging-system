"""Unit tests for Task 1: Ephemeral X25519 keys and RSA-PSS handshake verification."""

from datetime import datetime, timedelta, timezone
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import NameOID
import pytest

from common.crypto import (
    CLIENT_ID_SIZE,
    SALT_SIZE,
    X25519_KEY_SIZE,
    CryptoError,
    compute_handshake_hash,
    generate_client_id,
    generate_x25519_keypair,
    load_x25519_public_key,
    serialize_x25519_public_key,
    sign_server_handshake,
    verify_server_handshake,
)


def _create_self_signed_cert(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "SecureRelayServer")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert.public_bytes(serialization.Encoding.PEM)


def test_generate_x25519_ephemeral_keypair():
    sk1, pk1_bytes = generate_x25519_keypair()
    sk2, pk2_bytes = generate_x25519_keypair()

    assert isinstance(sk1, x25519.X25519PrivateKey)
    assert isinstance(pk1_bytes, bytes)
    assert len(pk1_bytes) == X25519_KEY_SIZE
    assert len(pk2_bytes) == X25519_KEY_SIZE
    # Ephemeral keys must be distinct per generation
    assert pk1_bytes != pk2_bytes

    loaded_pk = load_x25519_public_key(pk1_bytes)
    assert serialize_x25519_public_key(loaded_pk) == pk1_bytes


def test_load_x25519_invalid_length_rejected():
    with pytest.raises(ValueError, match="Invalid X25519 public key length"):
        load_x25519_public_key(b"too_short")


def test_generate_client_id():
    cid1 = generate_client_id()
    cid2 = generate_client_id()
    assert len(cid1) == CLIENT_ID_SIZE
    assert cid1 != cid2


def test_server_handshake_rsa_pss_verification_success():
    rsa_sk, cert_pem = _create_self_signed_cert(2048)
    _, pk_server = generate_x25519_keypair()
    _, pk_client = generate_x25519_keypair()
    client_id = generate_client_id()
    salt = os.urandom(SALT_SIZE)

    sig = sign_server_handshake(rsa_sk, pk_server, pk_client, client_id, salt)

    assert verify_server_handshake(
        server_cert_bytes=cert_pem,
        pinned_cert_bytes=cert_pem,
        pk_server=pk_server,
        pk_client=pk_client,
        client_id=client_id,
        salt=salt,
        signature=sig,
    )


def test_server_handshake_detects_tampered_parameters_and_wrong_pinned_cert():
    rsa_sk, cert_pem = _create_self_signed_cert(2048)
    _, other_cert_pem = _create_self_signed_cert(2048)
    _, pk_server = generate_x25519_keypair()
    _, pk_client = generate_x25519_keypair()
    client_id = generate_client_id()
    salt = os.urandom(SALT_SIZE)

    sig = sign_server_handshake(rsa_sk, pk_server, pk_client, client_id, salt)

    # Pinned cert mismatch
    with pytest.raises(CryptoError, match="does not match pinned certificate"):
        verify_server_handshake(
            server_cert_bytes=cert_pem,
            pinned_cert_bytes=other_cert_pem,
            pk_server=pk_server,
            pk_client=pk_client,
            client_id=client_id,
            salt=salt,
            signature=sig,
        )

    # Tampered salt
    tampered_salt = bytes([salt[0] ^ 0xFF]) + salt[1:]
    with pytest.raises(CryptoError, match="RSA-PSS handshake signature verification failed"):
        verify_server_handshake(
            server_cert_bytes=cert_pem,
            pinned_cert_bytes=cert_pem,
            pk_server=pk_server,
            pk_client=pk_client,
            client_id=client_id,
            salt=tampered_salt,
            signature=sig,
        )

    # Hash check
    h = compute_handshake_hash(pk_server, pk_client, client_id, salt)
    assert len(h) == 32
