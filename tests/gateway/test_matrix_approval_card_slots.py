"""A turn's newest Matrix approval card supersedes its previous one; detached cards keep their own slot."""
import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import ExecApprovalPrompt, SendResult
from plugins.platforms.matrix.adapter import MatrixAdapter

KEY = 'matrix-fixture-slots'


def _prompt(request_id, delegation_id=None):
    metadata = {'approval_request_id': request_id}
    if delegation_id:
        metadata['approval_delegation_id'] = delegation_id
    return ExecApprovalPrompt(chat_id='!room:example.org', session_key=KEY, text='fixture',
                              actions=[('Approve', 'once', 'primary'), ('Deny', 'deny', 'danger')],
                              command='fixture', description='fixture', smart_denied=False, metadata=metadata)


@pytest.fixture
def adapter(monkeypatch):
    adapter = MatrixAdapter(PlatformConfig(enabled=True, token='fixture', extra={'homeserver': 'https://example.org'}))
    adapter._client = object()
    events = iter(f'$card-{i}' for i in range(10))

    async def send_reaction_prompt(chat_id, text, metadata, make, store, reactions, label):
        event = next(events)
        store[event] = make(event, '@owner:example.org', None)
        return SendResult(success=True, message_id=event)
    adapter._send_reaction_prompt = send_reaction_prompt
    # Detached cards attach a settle hook to a live core request; none exists in this fixture.
    monkeypatch.setattr('tools.approval.register_gateway_settle', lambda *args: True)
    return adapter


@pytest.mark.asyncio
async def test_turn_card_supersedes_previous_turn_card_only(adapter):
    first = await adapter._send_exec_approval_prompt(_prompt('turn-1'))
    child = await adapter._send_exec_approval_prompt(_prompt('child-1', delegation_id='deleg_fixture'))
    second = await adapter._send_exec_approval_prompt(_prompt('turn-2'))
    assert set(adapter._approval_prompts_by_event) == {child.message_id, second.message_id}
    assert adapter._approval_prompt_by_session == {KEY: second.message_id}
    assert first.message_id not in adapter._approval_prompts_by_event
