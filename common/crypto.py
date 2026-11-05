"""Cryptographic primitives for the Multi-Client E2E Secure Messaging System.

Implements:
- Ephemeral X25519 key generation and serialization (Forward Secrecy / PFS)
- Server authentication via pinned X.509 certificate and RSA-PSS (SHA-256)
- ECDH shared secret computation (X25519) with immediate memory zeroization
- HKDF-SHA256 (HKDF-Extract + HKDF-Expand) directional key derivation (Key_A2B, Key_B2A)
- AES-128-GCM Authenticated Encryption with Associated Data (AEAD), Nonce & AAD construction
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import struct
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID

X25519_KEY_SIZE = 32
CLIENT_ID_SIZE = 16
SALT_SIZE = 16
AES_KEY_SIZE = 16
IV_BASE_SIZE = 4
SEQ_NO_SIZE = 8
NONCE_SIZE = 12
GCM_TAG_SIZE = 16
AAD_SIZE = 40
MAX_PLAINTEXT_SIZE = 4096
MAX_SEQ_NO = (1 << 64) - 1
MIN_RSA_KEY_BITS = 2048

HKDF_INFO_A2B = b"A2B"
HKDF_INFO_B2A = b"B2A"
HKDF_INFO_IV_A2B = b"IV_A2B"
HKDF_INFO_IV_B2A = b"IV_B2A"


class CryptoError(Exception):
    """Base exception for cryptographic validation and operation errors."""


@dataclass(frozen=True)
class DerivedSessionKeys:
    """Directional session keys and IV bases derived via ECDH + HKDF-SHA256."""

    key_a2b: bytes
    key_b2a: bytes
    key_send: bytes
    key_recv: bytes
    iv_base_send: bytes
    iv_base_recv: bytes


def zeroize(buffer: bytearray) -> None:
    """Overwrite a mutable bytearray in-place with zeros."""
    for i in range(len(buffer)):
        buffer[i] = 0


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


def load_rsa_private_key(
    key_data: bytes,
    password: bytes | None = None,
) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM or DER bytes and enforce >= 2048 bits."""
    if not key_data:
        raise CryptoError("RSA private key data cannot be empty.")
    try:
        if b"-----BEGIN" in key_data:
            private_key = serialization.load_pem_private_key(key_data, password=password)
        else:
            private_key = serialization.load_der_private_key(key_data, password=password)
    except Exception as exc:
        raise CryptoError(f"Failed to parse RSA private key: {exc}") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("Loaded private key is not an RSA private key.")
    if private_key.key_size < MIN_RSA_KEY_BITS:
        raise CryptoError(
            f"RSA private key size ({private_key.key_size} bits) is below minimum {MIN_RSA_KEY_BITS} bits."
        )
    return private_key


def generate_self_signed_rsa_cert(
    key_size: int = MIN_RSA_KEY_BITS,
    common_name: str = "SecureRelayServer",
    valid_days: int = 365,
) -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """Generate an RSA keypair (>= 2048 bits) and a self-signed X.509 certificate.

    Returns:
        A tuple of (RSAPrivateKey, private_key_pem_bytes, certificate_pem_bytes).
    """
    if key_size < MIN_RSA_KEY_BITS:
        raise CryptoError(
            f"RSA key size ({key_size} bits) must be at least {MIN_RSA_KEY_BITS} bits."
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return private_key, key_pem, cert_pem


def ensure_server_credentials(
    cert_path: str | Path,
    key_path: str | Path,
    key_size: int = MIN_RSA_KEY_BITS,
    auto_generate: bool = True,
) -> tuple[rsa.RSAPrivateKey, bytes]:
    """Load and validate server RSA private key and X.509 certificate from disk,
    or generate them if missing and `auto_generate` is True.

    Verifies that both key and certificate have >= 2048 bits and share the same modulus/exponent.
    """
    c_path = Path(cert_path)
    k_path = Path(key_path)

    if not c_path.exists() or not k_path.exists():
        if not auto_generate:
            raise CryptoError(
                f"Server credentials not found at {c_path} / {k_path}."
            )
        c_path.parent.mkdir(parents=True, exist_ok=True)
        k_path.parent.mkdir(parents=True, exist_ok=True)
        private_key, key_pem, cert_pem = generate_self_signed_rsa_cert(key_size=key_size)
        k_path.write_bytes(key_pem)
        c_path.write_bytes(cert_pem)
        return private_key, cert_pem

    cert_bytes = c_path.read_bytes()
    key_bytes = k_path.read_bytes()
    cert = load_x509_certificate(cert_bytes)
    private_key = load_rsa_private_key(key_bytes)

    cert_pub = cert.public_key()
    assert isinstance(cert_pub, rsa.RSAPublicKey)
    if cert_pub.public_numbers() != private_key.public_key().public_numbers():
        raise CryptoError("Server certificate public key does not match server RSA private key.")

    return private_key, cert_bytes


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


def compute_shared_secret(
    sk_local: x25519.X25519PrivateKey,
    pk_peer: bytes | x25519.X25519PublicKey,
) -> bytearray:
    """Compute the X25519 ECDH shared secret Z_AB = ECDH(sk_A, pk_B).

    Returns a mutable bytearray so the caller can zeroize it immediately afterHKDF.
    """
    if isinstance(pk_peer, (bytes, bytearray, memoryview)):
        peer_pub = load_x25519_public_key(bytes(pk_peer))
    elif isinstance(pk_peer, x25519.X25519PublicKey):
        peer_pub = pk_peer
    else:
        raise TypeError("pk_peer must be raw 32-byte public key bytes or X25519PublicKey.")

    raw_secret = sk_local.exchange(peer_pub)
    if len(raw_secret) != X25519_KEY_SIZE or raw_secret == b"\x00" * X25519_KEY_SIZE:
        raise CryptoError("Invalid or all-zero X25519 shared secret.")
    return bytearray(raw_secret)


def hkdf_extract(salt: bytes, ikm: bytes | bytearray) -> bytearray:
    """Perform RFC 5869 HKDF-Extract(salt, IKM) using HMAC-SHA256.

    PRK = HMAC-SHA256(salt, Z_AB)
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Server salt must be {SALT_SIZE} bytes, got {len(salt)}.")
    if not ikm:
        raise ValueError("Input keying material (IKM) cannot be empty.")
    prk = hmac.new(bytes(salt), bytes(ikm), hashlib.sha256).digest()
    return bytearray(prk)


def hkdf_expand(
    prk: bytes | bytearray,
    info: bytes,
    length: int = AES_KEY_SIZE,
) -> bytes:
    """Perform RFC 5869 HKDF-Expand(PRK, info, L) using SHA-256."""
    if not prk:
        raise ValueError("PRK cannot be empty.")
    kdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return kdf.derive(bytes(prk))


def derive_directional_keys(
    shared_secret: bytes | bytearray,
    salt: bytes,
) -> tuple[bytes, bytes]:
    """Derive directional AES-128 keys (Key_A2B, Key_B2A) from shared secret Z_AB and salt.

    Formula:
        PRK = HKDF-Extract(salt_srv, Z_AB)
        Key_A2B = HKDF-Expand(PRK, info="A2B", L=16)
        Key_B2A = HKDF-Expand(PRK, info="B2A", L=16)

    Automatically zeroizes PRK and shared_secret (if bytearray).
    """
    prk = bytearray()
    try:
        prk = hkdf_extract(salt, shared_secret)
        key_a2b = hkdf_expand(prk, info=HKDF_INFO_A2B, length=AES_KEY_SIZE)
        key_b2a = hkdf_expand(prk, info=HKDF_INFO_B2A, length=AES_KEY_SIZE)
        return key_a2b, key_b2a
    finally:
        if prk:
            zeroize(prk)
        if isinstance(shared_secret, bytearray):
            zeroize(shared_secret)


def derive_e2e_session_keys(
    sk_local: x25519.X25519PrivateKey,
    pk_peer: bytes | x25519.X25519PublicKey,
    salt: bytes,
    local_id: bytes | None = None,
    peer_id: bytes | None = None,
    is_role_a: bool | None = None,
) -> DerivedSessionKeys:
    """Compute Z_AB = ECDH(sk_local, pk_peer), derive directional keys and IV bases via HKDF-SHA256,
    and immediately zeroize Z_AB and PRK from memory.

    Direction resolution:
    - If `is_role_a` is explicitly passed, uses True -> A (send=A2B, recv=B2A), False -> B.
    - Else if `local_id` and `peer_id` are provided, orders deterministically by client_id
      (the smaller client_id is A, the larger is B).
    - Otherwise defaults to role A (send=A2B, recv=B2A).
    """
    shared_secret = bytearray()
    prk = bytearray()
    try:
        shared_secret = compute_shared_secret(sk_local, pk_peer)
        prk = hkdf_extract(salt, shared_secret)

        key_a2b = hkdf_expand(prk, info=HKDF_INFO_A2B, length=AES_KEY_SIZE)
        key_b2a = hkdf_expand(prk, info=HKDF_INFO_B2A, length=AES_KEY_SIZE)
        iv_a2b = hkdf_expand(prk, info=HKDF_INFO_IV_A2B, length=IV_BASE_SIZE)
        iv_b2a = hkdf_expand(prk, info=HKDF_INFO_IV_B2A, length=IV_BASE_SIZE)

        if is_role_a is None:
            if local_id is not None and peer_id is not None:
                if local_id == peer_id:
                    raise ValueError("local_id and peer_id must be distinct.")
                role_a = bytes(local_id) < bytes(peer_id)
            else:
                role_a = True
        else:
            role_a = is_role_a

        if role_a:
            return DerivedSessionKeys(
                key_a2b=key_a2b,
                key_b2a=key_b2a,
                key_send=key_a2b,
                key_recv=key_b2a,
                iv_base_send=iv_a2b,
                iv_base_recv=iv_b2a,
            )
        return DerivedSessionKeys(
            key_a2b=key_a2b,
            key_b2a=key_b2a,
            key_send=key_b2a,
            key_recv=key_a2b,
            iv_base_send=iv_b2a,
            iv_base_recv=iv_a2b,
        )
    finally:
        if shared_secret:
            zeroize(shared_secret)
        if prk:
            zeroize(prk)


def build_nonce(iv_base: bytes, seq_no: int) -> bytes:
    """Construct the 12-byte AES-GCM Nonce: IV_base (4B) || seq_no (8B, big-endian)."""
    if len(iv_base) != IV_BASE_SIZE:
        raise ValueError(f"iv_base must be {IV_BASE_SIZE} bytes, got {len(iv_base)}.")
    if not (0 <= seq_no <= MAX_SEQ_NO):
        raise ValueError("seq_no must be an unsigned 64-bit integer.")
    return bytes(iv_base) + struct.pack("!Q", seq_no)


def build_aad(sender_id: bytes, recipient_id: bytes, seq_no: int) -> bytes:
    """Construct the 40-byte Associated Data (AAD):
    sender_id (16B) || recipient_id (16B) || seq_no (8B, big-endian).
    """
    if len(sender_id) != CLIENT_ID_SIZE:
        raise ValueError(f"sender_id must be {CLIENT_ID_SIZE} bytes.")
    if len(recipient_id) != CLIENT_ID_SIZE:
        raise ValueError(f"recipient_id must be {CLIENT_ID_SIZE} bytes.")
    if not (0 <= seq_no <= MAX_SEQ_NO):
        raise ValueError("seq_no must be an unsigned 64-bit integer.")
    return bytes(sender_id) + bytes(recipient_id) + struct.pack("!Q", seq_no)


def encrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-128-GCM with AAD.

    Returns:
        A tuple of (ciphertext, tag) where tag is 16 bytes.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-128-GCM key must be {AES_KEY_SIZE} bytes, got {len(key)}.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}.")
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"Plaintext size ({len(plaintext)} B) exceeds maximum bound ({MAX_PLAINTEXT_SIZE} B)."
        )

    aesgcm = AESGCM(bytes(key))
    ct_with_tag = aesgcm.encrypt(bytes(nonce), bytes(plaintext), bytes(aad))
    ciphertext = ct_with_tag[:-GCM_TAG_SIZE]
    tag = ct_with_tag[-GCM_TAG_SIZE:]
    return ciphertext, tag


def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes:
    """Decrypt and verify an AES-128-GCM payload and 16-byte authentication tag.

    Raises:
        InvalidTag: If the ciphertext, AAD, nonce, or tag was tampered with.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-128-GCM key must be {AES_KEY_SIZE} bytes, got {len(key)}.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}.")
    if len(tag) != GCM_TAG_SIZE:
        raise ValueError(f"GCM tag must be {GCM_TAG_SIZE} bytes, got {len(tag)}.")
    if len(ciphertext) > MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"Ciphertext size ({len(ciphertext)} B) exceeds maximum bound ({MAX_PLAINTEXT_SIZE} B)."
        )

    aesgcm = AESGCM(bytes(key))
    # InvalidTag is raised directly if verification fails
    return aesgcm.decrypt(bytes(nonce), bytes(ciphertext) + bytes(tag), bytes(aad))


