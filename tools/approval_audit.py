"""Bounded local evidence, never a permission/replay store.

Only fixed event/status values and hashed identifiers are persisted. No command,
arguments, output, denial reason, room ID or credentials enter this schema.
A single gateway owns writes; retention is two 1 MiB segments per profile.
"""
import hashlib
import inspect
import json
import logging
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar

MAX_BYTES = 1024 * 1024
_lock = threading.Lock()
_tool_call = ContextVar('approval_audit_tool_call', default='')
_tool_name = ContextVar('approval_audit_tool_name', default='')
logger = logging.getLogger(__name__)
_EVENTS = {'request', 'decision', 'settled', 'tool_dispatch', 'tool_result', 'relay_closed'}
_STATUSES = {'once', 'session', 'always', 'deny', 'timeout', 'interrupted', 'set',
             'notify_failed', 'closed', 'returned', 'raised', 'unknown'}


def _digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest() if value else None


def record(relay, event, *, request_id='', choice='', issuer='', status=''):
    if relay is None:
        return
    if event not in _EVENTS or (choice and choice not in _STATUSES) or (status and status not in _STATUSES):
        raise ValueError('Invalid audit event')
    row = {'version': 1, 'at': time.time(), 'event': event,
           'delegation': _digest(relay.delegation_id), 'session': _digest(relay.session_key),
           'request': _digest(request_id), 'tool_call': _digest(_tool_call.get()),
           'tool_name': _tool_name.get() or None,
           'issuer': _digest(issuer), 'choice': choice or None, 'status': status or None}
    if event == 'tool_result':
        # A returned handler (even a successful one) is not verification of an external effect.
        row['execution_effect'] = 'unknown'
    data = (json.dumps(row, separators=(',', ':')) + '\n').encode()
    with _lock:
        if inspect.unwrap(os.open) not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW'):
            raise OSError('Secure audit storage requires descriptor-relative file operations')
        dfd = os.open(relay.audit_home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in ('logs', 'approval-audit'):
                try:
                    os.mkdir(component, 0o700, dir_fd=dfd)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                os.close(dfd)
                dfd = child
            os.fchmod(dfd, 0o700)
            flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open('events.jsonl', flags, 0o600, dir_fd=dfd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise OSError('Audit target must be a private regular file')
                os.fchmod(fd, 0o600)
                if info.st_size + len(data) > MAX_BYTES:
                    os.close(fd)
                    fd = -1
                    os.replace('events.jsonl', 'events.previous.jsonl', src_dir_fd=dfd, dst_dir_fd=dfd)
                    fd = os.open('events.jsonl', flags | os.O_EXCL, 0o600, dir_fd=dfd)
                with os.fdopen(fd, 'ab', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(fd)
            finally:
                if fd != -1:
                    os.close(fd)
        finally:
            os.close(dfd)


def best_effort(relay, event, **fields):
    try:
        record(relay, event, **fields)
    except OSError:
        # Do not log paths, exceptions or payloads; after execution a failed audit cannot undo effects.
        logger.error('Detached approval audit write failed; evidence is incomplete')


@contextmanager
def observe_dispatch(tool_call_id, tool_name):
    from tools.approval_relay import _current
    relay = _current.get()
    if relay is not None and relay.closed:
        raise RuntimeError('Detached delegation has ended; new tool dispatch is refused')
    token = _tool_call.set(tool_call_id or '')
    name_token = _tool_name.set(tool_name if re.fullmatch(r'[a-zA-Z0-9_]{1,64}', tool_name) else 'other')
    try:
        record(relay, 'tool_dispatch')
        try:
            yield
        except BaseException:
            best_effort(relay, 'tool_result', status='raised')
            raise
        else:
            best_effort(relay, 'tool_result', status='returned')
    finally:
        _tool_call.reset(token)
        _tool_name.reset(name_token)
