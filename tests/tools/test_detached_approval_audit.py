"""Private evidence follows the dispatching profile, not the reader's environment."""
import json
import queue
import threading
import pytest

from tools import approval as A
from tools.approval_gateway_wait import _await_gateway_decision
from tools.approval_relay import capture_relay, run_with_relay


def test_real_dispatch_evidence_is_private_and_not_execution_permission(tmp_path, monkeypatch):
    from gateway.run import _profile_runtime_scope as hermes_home_override
    from model_tools import handle_function_call, registry
    from tools import approval_audit

    notices = queue.Queue()
    key = 'fixture-audit'
    A.register_gateway_notify(key, notices.put)
    homes = [tmp_path / 'a', tmp_path / 'b']
    relays = []
    for home in homes:
        home.mkdir()
        with hermes_home_override(home):
            relays.append(capture_relay(key, 'deleg_fixture'))
    A.unregister_gateway_notify(key)
    monkeypatch.setattr('tools.approval_context._get_approval_timeout', lambda: 3)

    def handler(args, **kwargs):
        decision = _await_gateway_decision(key, A._gateway_notify_cb(key),
            {'command': 'SECRET-COMMAND', 'description': 'SECRET-DESCRIPTION'})
        return json.dumps({'success': decision['choice'] == 'once', 'output': 'SECRET-OUTPUT'})

    registry.register(name='audit_fixture', toolset='fixture', schema={'name': 'audit_fixture'}, handler=handler)
    try:
        for relay in (relays[0], relays[1], relays[0]):
            worker = threading.Thread(target=lambda: run_with_relay(relay, lambda:
                handle_function_call('audit_fixture', {}, tool_call_id='fixture-call')))
            worker.start()
            notice = notices.get(timeout=3)
            assert A.resolve_gateway_approval(key, 'once', request_id=notice['request_id'], issuer='SECRET-SENDER') == 1
            worker.join(3)
            assert not worker.is_alive()
        for home, count in zip(homes, (2, 1)):
            path = home / 'logs' / 'approval-audit' / 'events.jsonl'
            text = path.read_text()
            rows = [json.loads(line) for line in text.splitlines()]
            assert 'SECRET-' not in text
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
            assert sum(r['event'] == 'request' for r in rows) == count
            assert sum(r['event'] == 'decision' for r in rows) == count
            assert sum(r['event'] == 'tool_dispatch' for r in rows) == count
            assert sum(r['event'] == 'tool_result' for r in rows) == count
            assert all(r['tool_name'] == 'audit_fixture' for r in rows if r['event'] == 'tool_dispatch')
            assert all(r.get('execution_effect') == 'unknown' for r in rows if r['event'] == 'tool_result')
        # Closing a detached owner forbids new dispatch, not only pending approvals.
        relays[1].close()
        called = []
        registry.register(name='audit_closed_fixture', toolset='fixture', schema={'name': 'audit_closed_fixture'},
                          handler=lambda args, **kw: called.append(True) or '{}')
        run_with_relay(relays[1], lambda: handle_function_call('audit_closed_fixture', {}))
        assert not called
        monkeypatch.setattr(approval_audit, 'MAX_BYTES', 600)
        for _ in range(50):
            approval_audit.record(relays[0], 'request', request_id='fixture')
        paths = list((homes[0] / 'logs' / 'approval-audit').iterdir())
        assert len(paths) <= 2
        assert all(p.stat().st_size < 1200 for p in paths)
    finally:
        for relay in relays:
            relay.close()
        A.clear_session(key)


@pytest.mark.linux_only
def test_audit_rejects_symlink_without_creating_files_outside_home(tmp_path):
    from types import SimpleNamespace
    from tools.approval_audit import record
    home, outside = tmp_path / 'home', tmp_path / 'outside'
    home.mkdir()
    outside.mkdir()
    (home / 'logs').symlink_to(outside, target_is_directory=True)
    relay = SimpleNamespace(audit_home=home, delegation_id='fixture', session_key='fixture')
    with pytest.raises(OSError):
        record(relay, 'request')
    assert not list(outside.iterdir())
