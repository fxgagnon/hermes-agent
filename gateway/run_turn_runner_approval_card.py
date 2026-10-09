"""Exec-approval card routing for ``TurnRunner._approval_notify_sync``.

Decides whether an adapter renders native approval buttons and builds the card metadata. A
detached (async-delegation) approval is only ever delivered as a correlated, requester-bound card:
the requester comes from the gateway turn, never from child-provided routing data.
"""

from __future__ import annotations

from gateway.platforms.base import BasePlatformAdapter


class _ExecApprovalDeclined(RuntimeError):
    """The connector refused the approval card's destination.

    Raised (not returned) so it propagates out of `_approval_notify_sync` to
    `_await_gateway_decision`, whose notify-failure path drops the central
    approval queue entry and unblocks the waiting tool. A plain return
    suppressed the text fallback but left that entry pending.
    """


def _renders_exec_approval_buttons(adapter_cls: type) -> bool:
    """True when the adapter class renders native approval buttons. BasePlatformAdapter subclasses
    say so through ``supports_exec_approval_buttons``; anything else (test doubles, relay-style
    duck types) counts when it defines ``send_exec_approval`` itself."""
    probe = getattr(adapter_cls, "supports_exec_approval_buttons", None)
    if callable(probe) and issubclass(adapter_cls, BasePlatformAdapter):
        return bool(probe())
    return getattr(adapter_cls, "send_exec_approval", None) is not None


def approval_card_metadata(ctx, adapter, approval_data: dict) -> dict:
    """Card metadata for one approval request; raises when a detached request cannot be bound.

    Raising is the refusal path: ``_await_gateway_decision`` treats a failing notify as
    ``notify_failed`` and the child's command does not run.
    """
    delegation_id = approval_data.get("delegation_id")
    if delegation_id and not getattr(type(adapter), "supports_correlated_exec_approval", False):
        raise RuntimeError("Detached approvals require a correlated, requester-bound adapter")
    metadata = {**(ctx._status_thread_metadata or {}), "approval_request_id": approval_data.get("request_id")}
    if not delegation_id:
        return metadata
    requester = getattr(ctx.source, "user_id", None)
    if not requester:
        raise RuntimeError("Detached approval has no trusted requester")
    return {**metadata, "requester_user_id": requester, "approval_delegation_id": delegation_id}
