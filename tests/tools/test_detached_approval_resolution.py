"""Session-wide /approve with detached children waiting, and where decision evidence is written."""
import queue
import threading
import time

import pytest

from tools import approval as A
from tools import approval_audit
from tools.approval_gateway_wait import _await_gateway_decision
from tools.approval_relay import capture_relay, run_with_relay

KEY = 'fixture-resolution'


@pytest.fixture
def waits(monkeypatch, tmp_path):
    monkeypatch.setattr('tools.approval_context._get_approval_timeout', lambda: 10)
    monkeypatch.setattr('hermes_constants.get_hermes_home', lambda: tmp_path)
    notices = queue.Queue()
    A.register_gateway_notify(KEY, notices.put)
    threads = []

    def start(delegation_id=None):
        """Block one request in a worker: a detached child when *delegation_id* is given, else the turn."""
        relay = capture_relay(KEY, delegation_id) if delegation_id else None
        results = []

        def wait():
            return _await_gateway_decision(KEY, A._gateway_notify_cb(KEY),
                                           {'command': delegation_id or 'turn', 'pattern_keys': ['fixture']})
        t = threading.Thread(target=lambda: results.append(run_with_relay(relay, wait) if relay else wait()))
        t.start()
        threads.append(t)
        return relay, notices.get(timeout=5), results, t

    yield start
    for data in A.list_gateway_approvals(KEY):
        A.resolve_gateway_approval(KEY, 'deny', request_id=data['request_id'])
    for t in threads:
        t.join(5)
    A.clear_session(KEY)


@pytest.mark.parametrize('resolve_all', [False, True])
def test_session_approve_reaches_turn_request_but_not_waiting_child(waits, resolve_all):
    _, child_notice, child_results, _ = waits('deleg_child')
    _, _, turn_results, turn = waits()
    assert A.resolve_gateway_approval(KEY, 'once', resolve_all=resolve_all) == 1
    turn.join(5)
    assert turn_results[0]['choice'] == 'once'
    assert not child_results
    assert [d['request_id'] for d in A.list_gateway_approvals(KEY)] == [child_notice['request_id']]


def test_unwritable_decision_evidence_denies_and_is_not_acknowledged(waits, monkeypatch):
    _, notice, results, t = waits('deleg_child')

    def unwritable(*args, **kwargs):
        raise OSError('fixture: audit storage unavailable')
    monkeypatch.setattr(approval_audit, 'record', unwritable)
    assert A.resolve_gateway_approval(KEY, 'once', request_id=notice['request_id']) == 0
    t.join(5)
    assert results[0]['choice'] == 'deny'


def test_detached_evidence_is_written_outside_the_approval_lock(waits, monkeypatch):
    real, held = approval_audit.record, []

    def spy(relay, event, **fields):
        if event in ('decision', 'relay_closed'):
            held.append((event, A._lock.locked()))
        return real(relay, event, **fields)
    monkeypatch.setattr(approval_audit, 'record', spy)
    _, notice, _, t = waits('deleg_answered')
    closing, _, _, _ = waits('deleg_closed')
    assert A.resolve_gateway_approval(KEY, 'once', request_id=notice['request_id']) == 1
    closing.close()
    revoked, _, _, _ = waits('deleg_revoked')
    A.clear_session(KEY)
    deadline = time.monotonic() + 5
    while len(held) < 4 and time.monotonic() < deadline:
        time.sleep(0.01)
    # clear_session revokes the answered and the still-waiting relay alike.
    assert sorted(event for event, _ in held) == ['decision'] + ['relay_closed'] * 3
    assert not any(locked for _, locked in held)
    assert revoked.closed
