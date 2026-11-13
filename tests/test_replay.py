"""Testes de Simulação de Ataque de Repetição (Anti-Replay) e Estado de Sessão (tests/test_replay.py).

Valida:
1. Progressão monotónica do contador de sequência entre peers.
2. Rejeição imediata de frames repetidos (seq_no idêntico).
3. Rejeição imediata de números de sequência atrasados/menores (seq_no < seq_recv).
4. Proteção contra dessincronização de seq_recv não autenticada (um frame forjado com seq_no alto
   não avança seq_recv).
5. Zeroização de memória transitória ao desconectar.
"""

import os

from cryptography.exceptions import InvalidTag
import pytest

from client.session_manager import (
    RecipientMismatchError,
    ReplayAttackError,
    SessionManager,
    UnknownPeerError,
)
from common.crypto import SALT_SIZE
from common.protocol import E2EFrame


def _setup_alice_and_bob() -> tuple[SessionManager, SessionManager]:
    salt_srv = os.urandom(SALT_SIZE)
    alice = SessionManager()
    bob = SessionManager()

    alice.register_peer(bob.client_id, bob.pk_client, salt=salt_srv)
    bob.register_peer(alice.client_id, alice.pk_client, salt=salt_srv)
    return alice, bob


def test_bidirectional_e2e_session_and_monotonic_counters():
    alice, bob = _setup_alice_and_bob()

    f1 = alice.encrypt_message(bob.client_id, b"Message 1 from Alice")
    f2 = alice.encrypt_message(bob.client_id, b"Message 2 from Alice")
    assert f1.seq_no == 1
    assert f2.seq_no == 2

    sender1, pt1 = bob.decrypt_frame(f1.pack())
    sender2, pt2 = bob.decrypt_frame(f2.pack())
    assert sender1 == alice.client_id
    assert sender2 == alice.client_id
    assert pt1 == b"Message 1 from Alice"
    assert pt2 == b"Message 2 from Alice"
    assert bob.get_peer(alice.client_id).seq_recv == 2

    # Bob responde para Alice (contador direcional independente)
    reply = bob.encrypt_message(alice.client_id, b"Reply 1 from Bob")
    assert reply.seq_no == 1
    sender_b, pt_b = alice.decrypt_frame(reply.pack())
    assert sender_b == bob.client_id
    assert pt_b == b"Reply 1 from Bob"


def test_duplicate_frame_replay_attack_rejected():
    alice, bob = _setup_alice_and_bob()

    captured_frame = alice.encrypt_message(bob.client_id, b"Transfer $500").pack()

    # Primeira entrega é bem-sucedida
    _, plaintext = bob.decrypt_frame(captured_frame)
    assert plaintext == b"Transfer $500"

    # Atacante reproduz o exato mesmo frame capturado -> rejeitado com ReplayAttackError
    with pytest.raises(ReplayAttackError, match="Replay detected"):
        bob.decrypt_frame(captured_frame)


def test_decreased_sequence_number_replay_rejected():
    alice, bob = _setup_alice_and_bob()

    frame_seq_1 = alice.encrypt_message(bob.client_id, b"First packet").pack()
    frame_seq_2 = alice.encrypt_message(bob.client_id, b"Second packet").pack()
    frame_seq_3 = alice.encrypt_message(bob.client_id, b"Third packet").pack()

    # Bob recebe seq_no=1 e seq_no=3
    bob.decrypt_frame(frame_seq_1)
    bob.decrypt_frame(frame_seq_3)
    assert bob.get_peer(alice.client_id).seq_recv == 3

    # Atacante injeta frame capturado mais antigo com seq_no=2 -> rejeitado!
    with pytest.raises(ReplayAttackError, match="Replay detected"):
        bob.decrypt_frame(frame_seq_2)


def test_forged_high_seq_frame_does_not_advance_seq_recv():
    alice, bob = _setup_alice_and_bob()

    valid_1 = alice.encrypt_message(bob.client_id, b"Hello 1")
    bob.decrypt_frame(valid_1)
    assert bob.get_peer(alice.client_id).seq_recv == 1

    # Atacante forja um frame com seq_no=500 mas tag inválida
    valid_2 = alice.encrypt_message(bob.client_id, b"Hello 2")
    forged_nonce = valid_2.iv_base + (500).to_bytes(8, "big")
    forged_frame = E2EFrame(
        nonce=forged_nonce,
        sender_id=alice.client_id,
        recipient_id=bob.client_id,
        seq_no=500,
        ciphertext=valid_2.ciphertext,
        tag=valid_2.tag,
    )

    with pytest.raises(InvalidTag):
        bob.decrypt_frame(forged_frame)

    # O seq_recv de Bob deve permanecer em 1 para que valid_2 (seq_no=2) ainda seja aceito!
    assert bob.get_peer(alice.client_id).seq_recv == 1
    _, pt2 = bob.decrypt_frame(valid_2)
    assert pt2 == b"Hello 2"
    assert bob.get_peer(alice.client_id).seq_recv == 2


def test_recipient_mismatch_and_transient_memory_clear():
    alice, bob = _setup_alice_and_bob()
    charlie = SessionManager()

    frame_for_bob = alice.encrypt_message(bob.client_id, b"Only for Bob")
    with pytest.raises(RecipientMismatchError):
        charlie.decrypt_frame(frame_for_bob)

    # Verifica a limpeza de memória transitória ao desconectar
    bob_peer_ref = alice.get_peer(bob.client_id)
    old_pk = alice.pk_client
    alice.clear(rotate_ephemeral_keys=True)

    assert len(alice.peers) == 0
    assert bob_peer_ref.key_send == bytearray(16)
    assert bob_peer_ref.key_recv == bytearray(16)
    assert alice.pk_client != old_pk

    with pytest.raises(UnknownPeerError):
        alice.get_peer(bob.client_id)
