"""Matrix reaction-driven exec approvals: prompt delivery, reaction resolution and withdrawal."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from agent.i18n import t
from gateway.platforms.base import ExecApprovalPrompt, SendResult

logger = logging.getLogger("plugins.platforms.matrix.adapter")


class MatrixApprovalMixin:
    """Exec-approval half of ``MatrixAdapter``; state lives on the adapter instance."""

    _EA_REACTIONS = {"once": "✅", "session": "🌀", "always": "♾️", "deny": "❌"}
    _EA_LEGEND_KEYS = {"once": "platform.matrix.approval.legend_once", "session": "platform.matrix.approval.legend_session",
                       "always": "platform.matrix.approval.legend_always", "deny": "platform.matrix.approval.legend_deny"}
    # Whole sentences per offered tier (the highest tier wins) so translations never splice fragments.
    _EA_TYPED_HINT_KEYS = {"once": "platform.matrix.approval.typed_hint_once",
                           "session": "platform.matrix.approval.typed_hint_session",
                           "always": "platform.matrix.approval.typed_hint_always"}

    async def _send_exec_approval_prompt(self, prompt: ExecApprovalPrompt) -> SendResult:
        """Reaction-driven approval: the bot seeds one reaction per offered choice."""
        if not self._client:
            return SendResult(success=False, error="Not connected")
        choices = prompt.choices
        tier = "once"
        if not prompt.smart_denied:
            tier = "always" if "always" in choices else ("session" if "session" in choices else "once")
        text = (
            f"{prompt.text}\n\n"
            f"{t(self._EA_TYPED_HINT_KEYS[tier])}\n\n"
            f"{t('platform.matrix.approval.legend_intro')}\n" + "\n".join(t(self._EA_LEGEND_KEYS[c]) for c in choices))
        reactions = tuple(self._EA_REACTIONS[c] for c in choices)
        session_key, chat_id = prompt.session_key, prompt.chat_id
        detached = bool((prompt.metadata or {}).get("approval_delegation_id"))

        def _make(message_id, requester, expires_at):
            # The turn's newest card supersedes its previous one; detached cards are withdrawn
            # by their own settle hook and never take or evict the turn's slot.
            if not detached:
                old_event = self._approval_prompt_by_session.get(session_key)
                if old_event:
                    self._approval_prompts_by_event.pop(old_event, None)
                self._approval_prompt_by_session[session_key] = message_id
            from plugins.platforms.matrix.adapter import _MatrixApprovalPrompt
            return _MatrixApprovalPrompt(
                session_key=session_key, chat_id=chat_id, message_id=message_id, requester_user_id=requester,
                request_id=(prompt.metadata or {}).get("approval_request_id"),
                detached=detached,
                allowed_choices=tuple(choices),
                expires_at=expires_at)
        result = await self._send_reaction_prompt(
            chat_id, text, prompt.metadata, _make, self._approval_prompts_by_event, reactions, "approval")
        if detached and result.success and result.message_id:
            from tools.approval import register_gateway_settle
            loop = asyncio.get_running_loop()
            def settle(reason):
                loop.call_soon_threadsafe(self._withdraw_detached_approval, result.message_id)
            if not register_gateway_settle(session_key, prompt.metadata["approval_request_id"], settle):
                self._withdraw_detached_approval(result.message_id)
        return result

    def _withdraw_detached_approval(self, message_id):
        """Run on the adapter loop, even after the originating turn has returned."""
        prompt = self._approval_prompts_by_event.pop(message_id, None)
        if prompt is None:
            return
        prompt.resolved = True
        if self._approval_prompt_by_session.get(prompt.session_key) == message_id:
            self._approval_prompt_by_session.pop(prompt.session_key, None)
        task = asyncio.create_task(self._redact_bot_approval_reactions(prompt.chat_id, prompt))
        self._reaction_redaction_tasks.add(task)
        task.add_done_callback(self._reaction_redaction_tasks.discard)

    async def _handle_approval_reaction(self, room_id: str, reacts_to: str, key: str, sender: str) -> bool:
        """Resolve a pending exec-approval prompt from a reaction. True if it was the target."""
        candidate = self._approval_prompts_by_event.get(reacts_to)
        if candidate and candidate.detached and (not candidate.requester_user_id or sender != candidate.requester_user_id):
            return True
        handled, prompt, choice = await self._claim_reaction_prompt(
            self._approval_prompts_by_event, room_id, reacts_to, key, sender, "approval",
            t("platform.matrix.approval.invalid_reaction"), self._expire_matrix_approval_prompt,
            choices=self._approval_reaction_map)
        if choice is None:
            return handled
        if not prompt.request_id or choice not in prompt.allowed_choices:
            return True  # Never resolve a different operation through a session FIFO.
        try:
            from tools.approval import resolve_gateway_approval
            count = resolve_gateway_approval(prompt.session_key, choice, request_id=prompt.request_id,
                                             issuer=sender)
            if count:
                prompt.resolved = True
                self._approval_prompts_by_event.pop(reacts_to, None)
                if self._approval_prompt_by_session.get(prompt.session_key) == reacts_to:
                    self._approval_prompt_by_session.pop(prompt.session_key, None)
                logger.info(
                    "Matrix reaction resolved %d approval(s) for session %s (choice=%s, user=%s)",
                    count, prompt.session_key, choice, sender)
                await self._redact_bot_approval_reactions(room_id, prompt)
        except Exception as exc:
            logger.error("Failed to resolve gateway approval from Matrix reaction: %s", exc, exc_info=True)
        return True

    async def _expire_matrix_approval_prompt(self, room_id: str, target_event_id: str, prompt: Any) -> None:
        prompt.resolved = True
        self._approval_prompts_by_event.pop(target_event_id, None)
        self._approval_prompt_by_session.pop(prompt.session_key, None)
        await self._redact_bot_approval_reactions(room_id, prompt)
        await self._send_invalid_reaction_feedback(
            room_id, target_event_id,
            t("platform.matrix.approval.expired"))

    async def _redact_bot_approval_reactions(self, room_id: str, prompt: Any) -> None:
        """Redact the bot's seeded approval reactions (delayed), leaving only the user's reaction."""
        for emoji, evt_id in prompt.bot_reaction_events.items():
            self._schedule_reaction_redaction(room_id, evt_id, "approval resolved")
            logger.debug("Matrix: scheduled bot reaction redaction %s (%s)", emoji, evt_id)
