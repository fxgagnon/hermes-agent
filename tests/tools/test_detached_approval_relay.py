"""Real worker/queue integration; no model, shell command or network transport."""
import queue
import threading
import pytest

from tools import approval as A
from tools import async_delegation as D
from tools.approval_gateway_wait import _await_gateway_decision


@pytest.fixture
def relay_wait(monkeypatch):
    """Create an actual blocking queue entry in a context-propagated worker."""
    from tools.approval_relay import capture_relay, run_with_relay
    monkeypatch.setattr('tools.approval_context._get_approval_timeout', lambda: 2)
    workers = []

    def start(key='fixture-session', delegation_id='deleg_fixture'):
        notices = queue.Queue()
        A.register_gateway_notify(key, notices.put)
        relay = capture_relay(key, delegation_id)
        results = []
        t = threading.Thread(target=lambda: results.append(run_with_relay(relay, lambda:
            _await_gateway_decision(key, A._gateway_notify_cb(key),
                                    {'command': delegation_id, 'pattern_keys': ['fixture']}))))
        t.start()
        notice = notices.get(timeout=1)
        workers.append((key, t))
        return relay, notice, results, t

    yield start
    for key, t in workers:
        for data in A.list_gateway_approvals(key):
            A.resolve_gateway_approval(key, 'deny', request_id=data['request_id'])
        t.join(3)
        A.unregister_gateway_notify(key)


@pytest.mark.parametrize('all_requests', [False, True])
def test_detached_approval_never_falls_back_to_fifo(relay_wait, all_requests):
    relay, notice, results, t = relay_wait()
    assert A.resolve_gateway_approval(relay.session_key, 'once', resolve_all=all_requests) == 0
    assert not results


def test_cancel_revokes_only_its_delegation_and_cannot_rearm(relay_wait):
    from tools.approval_relay import run_with_relay
    a, na, ra, ta = relay_wait(delegation_id='deleg_a')
    b, nb, rb, tb = relay_wait(delegation_id='deleg_b')
    assert hasattr(a, 'close'), 'Relay needs terminal revocation'
    a.close()
    assert A.resolve_gateway_approval(a.session_key, 'once', request_id=na['request_id']) == 0
    assert A.resolve_gateway_approval(b.session_key, 'once', request_id=nb['request_id']) == 1
    ta.join(1)
    tb.join(1)
    assert ra[0]['choice'] == 'deny'
    assert rb[0]['choice'] == 'once'
    again = run_with_relay(a, lambda: _await_gateway_decision(a.session_key, a, {'command': 'late'}))
    assert again['choice'] == 'deny'
    assert not A.list_gateway_approvals(a.session_key)


def test_reset_revokes_relay_even_before_next_request(relay_wait):
    from tools.approval_relay import run_with_relay
    relay, notice, results, t = relay_wait()
    A.clear_session(relay.session_key)
    t.join(1)
    assert relay.closed
    again = run_with_relay(relay, lambda: _await_gateway_decision(relay.session_key, relay, {'command': 'late'}))
    assert again['choice'] == 'deny'


def test_expired_detached_request_cannot_win_before_waiter_cleans_up(relay_wait):
    import time
    relay, notice, results, worker = relay_wait()
    with A._lock:
        entry = A._gateway_queues[relay.session_key][0]
        entry.deadline = time.monotonic() - 1
    assert A.resolve_gateway_approval(relay.session_key, 'once', request_id=notice['request_id']) == 0
    relay.close()
    worker.join(3)
    assert results[0]['choice'] != 'once'


def test_disallowed_scope_cannot_be_submitted_to_exact_core_request(relay_wait):
    relay, notice, results, worker = relay_wait()
    with A._lock:
        A._gateway_queues[relay.session_key][0].data['allow_session'] = False
    assert A.resolve_gateway_approval(relay.session_key, 'session', request_id=notice['request_id']) == 0
    assert A.resolve_gateway_approval('unrelated-session', 'once', request_id=notice['request_id']) == 0
    assert A.resolve_gateway_approval(relay.session_key, 'once', request_id=notice['request_id']) == 1
    worker.join(3)
    assert results[0]['choice'] == 'once'


def test_answer_committed_before_deadline_is_not_lost_to_poll_race(monkeypatch):
    from tools.approval_relay import capture_relay, run_with_relay
    key = 'fixture-race'
    A.register_gateway_notify(key, lambda notice: None)
    relay = capture_relay(key, 'deleg_fixture')
    def poll(*args, **kwargs):
        request = A.list_gateway_approvals(key)[0]
        assert A.resolve_gateway_approval(key, 'once', request_id=request['request_id']) == 1
        return 'timeout'  # deadline check happened before the resolver acquired the lock
    monkeypatch.setattr('tools.approval_gateway_wait._poll_event', poll)
    try:
        result = run_with_relay(relay, lambda: _await_gateway_decision(key, relay, {'command': 'fixture'}))
        assert result['resolved'] and result['choice'] == 'once'
    finally:
        relay.close()
        A.unregister_gateway_notify(key)


def test_interruption_cannot_be_overridden_by_a_racing_answer(monkeypatch):
    from tools.approval_relay import capture_relay, run_with_relay
    key = 'fixture-interrupt-race'
    A.register_gateway_notify(key, lambda notice: None)
    relay = capture_relay(key, 'deleg_fixture')

    def poll(event, *args, **kwargs):
        request = A.list_gateway_approvals(key)[0]
        original_set = event.set

        def racing_answer():
            # Schedule a real resolver after interruption is observed, before cleanup.
            event.set = original_set
            assert A.resolve_gateway_approval(key, 'once', request_id=request['request_id']) == 1
            original_set()

        event.set = racing_answer
        return 'interrupted'

    monkeypatch.setattr('tools.approval_gateway_wait._poll_event', poll)
    try:
        result = run_with_relay(relay, lambda: _await_gateway_decision(key, relay, {'command': 'fixture'}))
        assert result['resolved'] and result['choice'] == 'deny'
    finally:
        relay.close()
        A.unregister_gateway_notify(key)


def test_old_turn_cleanup_does_not_remove_new_turn_notifier():
    key = 'fixture-turns'
    old, new = lambda data: None, lambda data: None
    A.register_gateway_notify(key, old)
    A.register_gateway_notify(key, new)
    try:
        import inspect
        assert 'expected_cb' in inspect.signature(A.unregister_gateway_notify).parameters
        A.unregister_gateway_notify(key, expected_cb=old)
        assert A._gateway_notify_cb(key) is new
    finally:
        A.unregister_gateway_notify(key)


@pytest.mark.parametrize('ending', ['stop', 'complete', 'crash', 'base_crash'])
def test_real_dispatch_lifecycle_revokes_relay(ending):
    from tools.approval_relay import current_relay
    D._reset_for_tests()
    key = 'fixture-lifecycle'
    captured = queue.Queue()
    release = threading.Event()
    A.register_gateway_notify(key, lambda data: None)

    def runner():
        captured.put(current_relay(key))
        assert release.wait(2)
        if ending == 'crash':
            raise RuntimeError('fixture failure')
        if ending == 'base_crash':
            raise SystemExit('fixture worker exit')
        return {'status': 'completed'}

    handle = D.dispatch_async_delegation(goal='fixture', context=None, toolsets=[], role='leaf',
        model=None, session_key=key, runner=runner)
    try:
        assert handle['status'] == 'dispatched'
        relay = captured.get(timeout=1)
        if ending == 'stop':
            D.interrupt_for_session(session_key=key)
            assert relay.closed, 'Stop must revoke approvals before a cooperative worker returns'
        release.set()
        D._executor.shutdown(wait=True)
        assert relay.closed, 'Worker termination leaked a notifier'
    finally:
        release.set()
        if D._executor is not None:
            D._executor.shutdown(wait=True)
        D._reset_for_tests()
        A.unregister_gateway_notify(key)


def test_parent_cleanup_does_not_cancel_waiting_detached_child(relay_wait):
    relay, notice, results, t = relay_wait()
    A.unregister_gateway_notify(relay.session_key)
    assert A.resolve_gateway_approval(relay.session_key, 'once', request_id=notice['request_id']) == 1
    t.join(1)
    assert results[0]['choice'] == 'once'


def test_detached_worker_notifies_after_parent_turn_returns(monkeypatch):
    monkeypatch.setattr('tools.approval_context._get_approval_timeout', lambda: 2)
    D._reset_for_tests()
    ready, done = threading.Event(), threading.Event()
    notices = queue.Queue()
    decisions = []
    key = 'fixture-session'
    A.register_gateway_notify(key, notices.put)

    def worker():
        assert ready.wait(2)
        cb = A._gateway_notify_cb(key)
        decisions.append(None if cb is None else _await_gateway_decision(
            key, cb, {'command': 'fixture operation', 'pattern_keys': ['fixture']}))
        done.set()
        return {'status': 'completed'}

    handle = D.dispatch_async_delegation(goal='fixture', context=None, toolsets=[], role='leaf',
        model=None, session_key=key, runner=worker)
    try:
        assert handle['status'] == 'dispatched'
        A.unregister_gateway_notify(key)
        ready.set()
        try:
            notice = notices.get(timeout=1)
        except queue.Empty:
            notice = None
        assert notice is not None, 'Detached worker lost its notifier when the parent returned'
        assert notice['delegation_id'] == handle['delegation_id']
        assert A.resolve_gateway_approval(key, 'once', request_id=notice['request_id']) == 1
        assert done.wait(2)
        assert decisions[0]['choice'] == 'once'
    finally:
        ready.set()
        D.interrupt_for_session(session_key=key)
        done.wait(2)
        if D._executor is not None:
            D._executor.shutdown(wait=True)
        D._reset_for_tests()
        A.unregister_gateway_notify(key)
