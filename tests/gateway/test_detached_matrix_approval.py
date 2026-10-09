"""Real gateway notifier → Matrix card → exact core request; transport only is fake."""
import asyncio
from types import SimpleNamespace

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import SendResult
from gateway.run_turn_runner import TurnRunner
from plugins.platforms.matrix.adapter import MatrixAdapter
from tools import approval as A
from tools.approval_gateway_wait import _await_gateway_decision
from tools.approval_relay import capture_relay, run_with_relay


@pytest.mark.asyncio
async def test_parallel_cards_resolve_exact_child_and_keep_source(monkeypatch):
    monkeypatch.setenv('MATRIX_ALLOWED_USERS', '@owner:example.org,@other:example.org')
    monkeypatch.setattr('tools.approval_context._get_approval_timeout', lambda: 30)
    adapter = MatrixAdapter(PlatformConfig(enabled=True, token='fixture', extra={'homeserver': 'https://example.org'}))
    adapter._client = object()
    adapter._approval_require_sender = False
    adapter._user_id = '@bot:example.org'
    sent, posted = asyncio.Queue(), []

    async def send(chat_id, text, **kwargs):
        event = f'$fixture-{len(posted)}'
        posted.append((event, chat_id, kwargs.get('metadata')))
        sent.put_nowait(event)
        return SendResult(success=True, message_id=event)

    async def reaction(*args, **kwargs):
        return None

    adapter.send = send
    adapter._send_reaction = reaction
    adapter._redact_bot_approval_reactions = reaction
    runner = object.__new__(TurnRunner)
    key = 'matrix-fixture-thread'
    runner._ctx = SimpleNamespace(_status_adapter=adapter, _status_chat_id='!source:example.org',
        _status_thread_metadata={'thread_id': '$thread', 'requester_user_id': '@owner:example.org'},
        session_key=key, source=SimpleNamespace(user_id='@owner:example.org', chat_id='!source:example.org'))
    runner._close_native_stream_boundary = lambda reason: None
    loop = asyncio.get_running_loop()
    runner._schedule = lambda coro, label: asyncio.run_coroutine_threadsafe(coro, loop)
    A.register_gateway_notify(key, runner._approval_notify_sync)
    relays, workers, notices = [], [], []
    try:
        for i in range(3):
            relay = capture_relay(key, f'deleg_fixture{i}')
            relays.append(relay)
            def work(r=relay):
                return run_with_relay(r, lambda: _await_gateway_decision(key, r,
                    {'command': 'fixture', 'pattern_keys': ['fixture'], 'allow_session': False,
                     'allow_permanent': False}))
            workers.append(asyncio.create_task(asyncio.to_thread(work)))
            notices.append(await asyncio.wait_for(sent.get(), 10))
        A.unregister_gateway_notify(key, expected_cb=runner._approval_notify_sync)
        assert all(e in adapter._approval_prompts_by_event for e in notices)
        for _, room, metadata in posted:
            assert room == '!source:example.org'
            assert metadata['thread_id'] == '$thread'
            assert metadata['requester_user_id'] == '@owner:example.org'
            assert metadata.get('approval_request_id')

        async def react(event, sender='@owner:example.org', room='!source:example.org', emoji='✅'):
            await adapter._handle_approval_reaction(room, event, emoji, sender)
        await react(notices[1], room='!wrong:example.org')
        await react(notices[1], sender='@other:example.org')
        await react(notices[1], emoji='♾️')
        assert len(A.list_gateway_approvals(key)) == 3
        await react(notices[1])
        assert (await asyncio.wait_for(workers[1], 10))['choice'] == 'once'
        await react(notices[1])
        assert len(A.list_gateway_approvals(key)) == 2
        await react(notices[0], emoji='❌')
        assert (await asyncio.wait_for(workers[0], 10))['choice'] == 'deny'
        relays[2].close()
        assert (await asyncio.wait_for(workers[2], 10))['choice'] == 'deny'
        # The originating turn is gone; cleanup must still withdraw the exact card. Withdrawal is
        # posted to the loop from the worker thread, so let it drain instead of a single tick.
        for _ in range(200):
            if not adapter._approval_prompts_by_event:
                break
            await asyncio.sleep(0.01)
        assert not adapter._approval_prompts_by_event
        assert not adapter._approval_prompt_by_session
    finally:
        for relay in relays:
            relay.close()
        await asyncio.gather(*workers)
        A.unregister_gateway_notify(key)


def test_detached_notifier_refuses_uncorrelated_adapter():
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(_status_adapter=SimpleNamespace(), _status_chat_id='fixture')
    with pytest.raises(RuntimeError, match='correlated'):
        runner._approval_notify_sync({'delegation_id': 'fixture', 'request_id': 'fixture'})
