# Detached gateway approval relay

## Scope and lifetime

This contribution is prepared against `eaef52371fb803e4a73eb42f9615c63bac9b54e2`.
An asynchronous delegation captures the gateway's existing notifier at dispatch.
The relay remains available after its parent turn returns **within the same
process**. It does not restore callbacks or approvals after a process restart.
There is no credential transport, new model tool, or additional approval mode.

The gateway captures the source room/thread and requester; a child cannot choose
another approval destination. Detached delivery requires an adapter declaring
correlated, requester-bound execution approvals. Matrix supplies that path.
Unsupported adapters and missing requesters fail closed; detached prompts never
fall back to an uncorrelated text approval.

Each detached queue entry has a request ID and a monotonic deadline. Matrix
reactions resolve that exact entry, not the session FIFO. The adapter checks the
room, requester, authorized-user gate and displayed choices; the queue additionally
checks session, request, deadline, relay lifetime and allowed permission scopes.
Session-wide FIFO/all approvals are refused while detached requests are pending.
These checks do not change the meaning of an explicitly offered session or
permanent choice. The internal resolver trusts its callers; `issuer` is evidence,
not an authentication mechanism or a standalone public API.

Parent turn cleanup releases only its own notifier and foreground waits. Relay
closure denies its remaining waits. Delegation cancellation, stop, normal return,
worker failure and session teardown revoke relays. Settled detached Matrix cards
are withdrawn through the adapter's event loop independently of the parent turn.
An interrupted waiter always returns deny even if a resolver races with cleanup.
Cancellation is cooperative: an already-dispatched handler or external effect
cannot be rolled back by closing a relay.

## Local evidence and privacy

`tools/approval_audit.py` writes to the dispatching profile's
`logs/approval-audit/`. The schema records request, decision, settlement, dispatch,
handler return/exception and relay closure, using fixed event/status values and
SHA-256 digests of identifiers. Commands, arguments, tool output, denial text,
room identifiers and credentials are not part of this schema. Tool names and
timestamps remain visible. Digests are **pseudonyms, not anonymization**: known or
low-entropy identifiers can be guessed and matching values correlated.

The directory is restricted to mode 0700 and files to 0600. Descriptor-relative
opens reject symlink components; event files must be regular single-link files.
Retention is one current and one previous segment, each targeted at 1 MiB.
Rotation assumes a single gateway writer per profile, with an in-process lock;
it is not a multiprocess journal, tamper-proof ledger or permission store.
The profile home and its ancestors must be trusted. Secure storage requires
POSIX descriptor-relative operations and `O_NOFOLLOW`; unsupported storage (for
example Windows) fails closed for approvals: a detached child's dangerous command
is never approved there. Disk latency can delay approval operations.

Request evidence failure prevents the approval prompt (`notify_failed`); decision
write failure produces deny. Dispatch, post-execution and closure evidence is
best effort: it never blocks a tool that needs no approval, and a failed write
reports incomplete evidence without recording payloads. A handler
return is recorded with `execution_effect: unknown`: neither a return nor an
approval proves that an external operation succeeded. Existing gateway logs,
transcripts and Matrix message content have separate privacy/retention policies;
these guarantees apply only to the new audit stream.

## Contribution boundaries

Relay and audit changes form one functional code unit in this version:
`approval_relay` imports `approval_audit`, and the closed-owner dispatch check is
inside `observe_dispatch`, called by `model_tools`. Splitting only by file would
produce a broken intermediate tree. Submit code plus regression tests together;
this documentation may follow as a second commit. No deployment is implied.

The targeted suite exercises real worker/queue/registry paths with temporary
profile homes (including A → B → A evidence routing). Matrix transport is fake.
It is not a live homeserver test, full-suite run, restart-recovery test or proof of
all nested/batch/context-hop paths. Storage outage and all race interleavings are
not exhaustively tested.

Upstream integration must be resolved and retested before submission. The
separately inspected upstream revision is
`25a71a744cb9ef06950a91638e6229b4f808d461`, not this tested baseline.
`2afb405337c3e4820ee9b605c2ec64a5481a6f5c` already moves choice commitment
under the queue lock and adds withdrawal handling;
`f9d178f78ed878d89391f59a0db2f6b5b5393391` already handles late choices
and preserves interruption denial. Those hunks overlap this patch. Preserve
upstream cancellation causes, prepared approval handling and settlement reason
contracts when adapting it; do not blindly apply or cherry-pick overlapping fixes.
No compatibility with that upstream tree is claimed by baseline test results.
