"""Cryptographic primitives for the Multi-Client E2E Secure Messaging System.

Implements:
- Ephemeral X25519 key generation and serialization (Forward Secrecy / PFS)
- Server authentication via pinned X.509 certificate and RSA-PSS (SHA-256)
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, x25519

X25519_KEY_SIZE = 32
CLIENT_ID_SIZE = 16
SALT_SIZE = 16
MIN_RSA_KEY_BITS = 2048


class CryptoError(Exception):
    """Base exception for cryptographic validation and operation errors."""


def generate_client_id() -> bytes:
    """Generate a random 16-byte binary client_id (UUIDv4)."""
    return uuid.uuid4().bytes


def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    """Generate a fresh ephemeral X25519 keypair (sk_client, pk_client_bytes).

    Returns:
        A tuple of (X25519PrivateKey object, 32-byte raw public key bytes).
    """
    sk_client = x25519.X25519PrivateKey.generate()
    pk_client_bytes = serialize_x25519_public_key(sk_client.public_key())
    return sk_client, pk_client_bytes


def serialize_x25519_public_key(public_key: x25519.X25519PublicKey) -> bytes:
    """Serialize an X25519PublicKey into its 32-byte raw representation."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_x25519_public_key(pk_bytes: bytes) -> x25519.X25519PublicKey:
    """Deserialize and validate a 32-byte raw X25519 public key."""
    if not isinstance(pk_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("X25519 public key must be bytes-like.")
    raw = bytes(pk_bytes)
    if len(raw) != X25519_KEY_SIZE:
        raise ValueError(
            f"Invalid X25519 public key length: expected {X25519_KEY_SIZE} bytes, got {len(raw)}."
        )
    return x25519.X25519PublicKey.from_public_bytes(raw)


def compute_handshake_transcript(
    pk_server: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt: bytes,
) -> bytes:
    """Build the concatenated handshake data: pk_server || pk_client || client_id || salt."""
    if len(pk_client) != X25519_KEY_SIZE:
        raise ValueError(f"pk_client must be {X25519_KEY_SIZE} bytes.")
    if len(client_id) != CLIENT_ID_SIZE:
        raise ValueError(f"client_id must be {CLIENT_ID_SIZE} bytes.")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes.")
    if not pk_server:
        raise ValueError("pk_server must not be empty.")
    return bytes(pk_server) + bytes(pk_client) + bytes(client_id) + bytes(salt)


def compute_handshake_hash(
    pk_server: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt: bytes,
) -> bytes:
    """Compute H = SHA256(pk_server || pk_client || client_id || salt)."""
    transcript = compute_handshake_transcript(pk_server, pk_client, client_id, salt)
    return hashlib.sha256(transcript).digest()


def load_x509_certificate(cert_data: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER bytes and enforce RSA >= 2048 bits."""
    if not cert_data:
        raise CryptoError("Certificate data cannot be empty.")
    try:
        if b"-----BEGIN CERTIFICATE-----" in cert_data:
            cert = x509.load_pem_x509_certificate(cert_data)
        else:
            cert = x509.load_der_x509_certificate(cert_data)
    except Exception as exc:
        raise CryptoError(f"Failed to parse X.509 certificate: {exc}") from exc

    pub_key = cert.public_key()
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise CryptoError("Server certificate must contain an RSA public key.")
    if pub_key.key_size < MIN_RSA_KEY_BITS:
        raise CryptoError(
            f"Server RSA key size ({pub_key.key_size} bits) is below minimum {MIN_RSA_KEY_BITS} bits."
        )
    return cert


def sign_server_handshake(
    rsa_private_key: rsa.RSAPrivateKey,
    pk_server: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt: bytes,
) -> bytes:
    """Sign handshake parameters using RSA-PSS with SHA-256:
    H = SHA256(pk_server || pk_client || client_id || salt).
    """
    if rsa_private_key.key_size < MIN_RSA_KEY_BITS:
        raise CryptoError(f"RSA private key must be at least {MIN_RSA_KEY_BITS} bits.")
    digest = compute_handshake_hash(pk_server, pk_client, client_id, salt)
    return rsa_private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )


def verify_server_handshake(
    server_cert_bytes: bytes,
    pinned_cert_bytes: bytes | None,
    pk_server: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt: bytes,
    signature: bytes,
) -> bool:
    """Validate the server's pinned X.509 certificate and verify its RSA-PSS signature over H.

    Raises:
        CryptoError: If certificate pinning, validity, or signature verification fails.
    """
    server_cert = load_x509_certificate(server_cert_bytes)

    if pinned_cert_bytes is not None:
        pinned_cert = load_x509_certificate(pinned_cert_bytes)
        server_der = server_cert.public_bytes(serialization.Encoding.DER)
        pinned_der = pinned_cert.public_bytes(serialization.Encoding.DER)
        if server_der != pinned_der:
            raise CryptoError("Server certificate does not match pinned certificate.")

    now = datetime.now(timezone.utc)
    if now < server_cert.not_valid_before_utc or now > server_cert.not_valid_after_utc:
        raise CryptoError("Server certificate is expired or not yet valid.")

    rsa_pub_key = server_cert.public_key()
    assert isinstance(rsa_pub_key, rsa.RSAPublicKey)

    transcript = compute_handshake_transcript(pk_server, pk_client, client_id, salt)
    digest = hashlib.sha256(transcript).digest()

    # Support both Prehashed(SHA256) on H and standard SHA256 over transcript,
    # as well as PSS.MAX_LENGTH and PSS.AUTO salt lengths for interoperability.
    for salt_len in (padding.PSS.MAX_LENGTH, padding.PSS.AUTO):
        pss_pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=salt_len,
        )
        try:
            rsa_pub_key.verify(
                signature,
                digest,
                pss_pad,
                utils.Prehashed(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            pass

        try:
            rsa_pub_key.verify(
                signature,
                transcript,
                pss_pad,
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            pass

    raise CryptoError("RSA-PSS handshake signature verification failed.")
