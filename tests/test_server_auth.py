"""Testes unitários para a Tarefa 1 do Developer 1: Autenticação RSA do Servidor e Gestão de Certificados."""

import os
from pathlib import Path

import pytest

from common.crypto import (
    SALT_SIZE,
    CryptoError,
    ensure_server_credentials,
    generate_client_id,
    generate_self_signed_rsa_cert,
    generate_x25519_keypair,
    load_rsa_private_key,
    load_x509_certificate,
    sign_server_handshake,
    verify_server_handshake,
)


def test_generate_and_load_self_signed_rsa_cert():
    rsa_sk, key_pem, cert_pem = generate_self_signed_rsa_cert(key_size=2048)
    assert rsa_sk.key_size == 2048

    loaded_sk = load_rsa_private_key(key_pem)
    loaded_cert = load_x509_certificate(cert_pem)

    assert loaded_sk.key_size == 2048
    assert loaded_cert.public_key().public_numbers() == loaded_sk.public_key().public_numbers()


def test_reject_rsa_key_below_2048_bits():
    with pytest.raises(CryptoError, match="at least 2048 bits"):
        generate_self_signed_rsa_cert(key_size=1024)


def test_ensure_server_credentials_auto_generates_and_reloads(tmp_path: Path):
    cert_file = tmp_path / "certs" / "server.crt"
    key_file = tmp_path / "certs" / "server.key"

    sk1, cert1 = ensure_server_credentials(cert_file, key_file, auto_generate=True)
    assert cert_file.exists()
    assert key_file.exists()

    sk2, cert2 = ensure_server_credentials(cert_file, key_file, auto_generate=False)
    assert cert1 == cert2
    assert sk1.private_numbers() == sk2.private_numbers()


def test_ensure_server_credentials_detects_mismatched_key_and_cert(tmp_path: Path):
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"

    _, key_pem_1, _ = generate_self_signed_rsa_cert(key_size=2048)
    _, _, cert_pem_2 = generate_self_signed_rsa_cert(key_size=2048)

    key_file.write_bytes(key_pem_1)
    cert_file.write_bytes(cert_pem_2)

    with pytest.raises(CryptoError, match="does not match server RSA private key"):
        ensure_server_credentials(cert_file, key_file, auto_generate=False)


def test_server_rsa_pss_handshake_signing_with_generated_certs(tmp_path: Path):
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"
    rsa_sk, cert_pem = ensure_server_credentials(cert_file, key_file)

    _, pk_server = generate_x25519_keypair()
    _, pk_client = generate_x25519_keypair()
    client_id = generate_client_id()
    salt_srv = os.urandom(SALT_SIZE)

    signature = sign_server_handshake(rsa_sk, pk_server, pk_client, client_id, salt_srv)
    assert verify_server_handshake(
        server_cert_bytes=cert_pem,
        pinned_cert_bytes=cert_pem,
        pk_server=pk_server,
        pk_client=pk_client,
        client_id=client_id,
        salt=salt_srv,
        signature=signature,
    )
