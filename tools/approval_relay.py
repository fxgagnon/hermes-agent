"""Process-local, delegation-owned approval notifier; never a credential transport.

Only dispatch captures an existing gateway notifier. Children cannot supply a
room, requester or callback. Persistence of evidence is separate from permission:
no lease or decision is restored after process exit.
"""
from contextvars import ContextVar
from weakref import WeakSet

_current = ContextVar('detached_approval_relay', default=None)
_relays = WeakSet()  # guarded by tools.approval._lock


class ApprovalRelay:
    def __init__(self, session_key, delegation_id, notify):
        from hermes_constants import get_hermes_home
        self.audit_home = get_hermes_home()
        self.session_key = session_key
        self.delegation_id = delegation_id
        self.notify = notify
        self.closed = False

    def __call__(self, data):
        if self.closed:
            raise RuntimeError('Delegation approval relay is closed')
        self.notify({**data, 'delegation_id': self.delegation_id})

    def close(self):
        from tools import approval as a
        with a._lock:
            closed_now = self._close_locked()
        if closed_now:
            self.audit_closed()

    def _close_locked(self):
        """Deny this relay's pending waits; True when this call closed it. Caller holds the lock
        and writes the evidence with ``audit_closed`` after releasing it (fsync)."""
        from tools import approval as a
        if self.closed:
            return False
        self.closed = True
        self.notify = None
        queue = a._gateway_queues.get(self.session_key, [])
        for entry in list(queue):
            if entry.relay is self:
                queue.remove(entry)
                entry.result = 'deny'
                entry.event.set()
        if not queue:
            a._gateway_queues.pop(self.session_key, None)
        _relays.discard(self)
        return True

    def audit_closed(self):
        from tools.approval_audit import best_effort
        best_effort(self, 'relay_closed', status='closed')


def current_relay(session_key):
    relay = _current.get()
    return relay if relay is not None and relay.session_key == session_key else None


def capture_relay(session_key, delegation_id):
    from tools import approval as a
    with a._lock:
        parent = current_relay(session_key)
        cb = parent.notify if parent is not None else a._gateway_notify_cbs.get(session_key)
        if cb is None:
            return None
        relay = ApprovalRelay(session_key, delegation_id, cb)
        _relays.add(relay)
        return relay


def revoke_session_locked(session_key):
    """Close the session's relays under ``tools.approval._lock``; returns them for ``audit_closed``."""
    return [relay for relay in list(_relays) if relay.session_key == session_key and relay._close_locked()]


def run_with_relay(relay, runner):
    token = _current.set(relay)
    try:
        return runner()
    finally:
        _current.reset(token)
