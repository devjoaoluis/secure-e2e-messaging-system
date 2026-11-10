"""Testes unitários para a Tarefa 2 do Developer 1: SessionStore e Tabela de Roteamento no Servidor (tests/test_session_store.py)."""

import pytest

from common.crypto import SALT_SIZE, generate_client_id, generate_x25519_keypair
from server.session_store import (
    ServerReplayOrSequenceError,
    SessionStore,
)


def test_register_and_lookup_sessions():
    store = SessionStore()
    assert len(store.salt_srv) == SALT_SIZE

    id_a = generate_client_id()
    _, pk_a = generate_x25519_keypair()
    id_b = generate_client_id()
    _, pk_b = generate_x25519_keypair()

    sess_a, evicted_a = store.register_session(id_a, pk_a)
    sess_b, evicted_b = store.register_session(id_b, pk_b)

    assert evicted_a is None
    assert evicted_b is None
    assert store.get_session(id_a) is sess_a
    assert store.get_session(id_b) is sess_b
    assert store.get_other_sessions(id_a) == [sess_b]


def test_reconnect_same_client_id_evicts_previous_session_and_resets_counters():
    store = SessionStore()
    id_a = generate_client_id()
    _, pk_a1 = generate_x25519_keypair()
    _, pk_a2 = generate_x25519_keypair()
    id_b = generate_client_id()
    _, pk_b = generate_x25519_keypair()

    sess_a1, _ = store.register_session(id_a, pk_a1)
    store.register_session(id_b, pk_b)
    store.record_relayed_frame(id_a, id_b, seq_no=1)
    store.record_relayed_frame(id_b, id_a, seq_no=5)

    # Reconecta com o mesmo id_a e uma nova chave efêmera pk_a2
    sess_a2, evicted = store.register_session(id_a, pk_a2)
    assert evicted is sess_a1
    assert sess_a2.pk_client == pk_a2
    assert sess_a2.frames_sent == 0
    # O contador direcional de B -> A também deve ser redefinido para a nova sessão
    assert id_a not in store.get_session(id_b).seq_counters


def test_record_relayed_frame_and_monotonic_sequence_tracking():
    store = SessionStore()
    id_a = generate_client_id()
    _, pk_a = generate_x25519_keypair()
    id_b = generate_client_id()
    _, pk_b = generate_x25519_keypair()

    sess_a, _ = store.register_session(id_a, pk_a)
    sess_b, _ = store.register_session(id_b, pk_b)

    store.record_relayed_frame(id_a, id_b, seq_no=1)
    store.record_relayed_frame(id_a, id_b, seq_no=2)

    assert sess_a.frames_sent == 2
    assert sess_b.frames_received == 2

    with pytest.raises(ServerReplayOrSequenceError):
        store.record_relayed_frame(id_a, id_b, seq_no=2)


def test_remove_session_clears_transient_memory():
    store = SessionStore()
    id_a = generate_client_id()
    _, pk_a = generate_x25519_keypair()

    sess_a, _ = store.register_session(id_a, pk_a)
    removed = store.remove_session(id_a, expected_session=sess_a)
    assert removed is sess_a
    assert store.get_session(id_a) is None
