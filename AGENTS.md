# Switchyard — Shared Coding-Agent Rules (AGENTS.md template)

> This is a proposed repository governance file; review and commit it through the normal task process. It is not a substitute for the architecture specification or individual task contract.

## Priority
1. Approved architecture v1.2 is normative for behavior, security and accounting.
2. Accepted ADRs explicitly signed off by the project owner can refine the architecture.
3. Current atomic-task contract defines the authorized work scope.
4. Existing code and tests describe implementation state but do not override a stated invariant.

If these conflict, **stop, identify the conflict, and ask for an architect decision**. Do not silently choose a new design.

## Agent boundaries
- Implement exactly one authorized task ID at a time, on a dedicated worktree/branch if provided.
- Inspect actual code and repository status before editing.
- Never introduce providers, dependencies, infrastructure, schema changes or behavioral deviations outside the task without asking.
- Do not overwrite unrelated work, delete data, force-push, merge or deploy without authorization.
- No claim of successful testing without running the named command.
- Never emit production credentials or raw prompts/response payloads in tool reports or logs.
- For code review, include diff/commit reference, actual test outputs, failures, and open questions.

## Non-negotiable v1 constraints
- One active Gateway; standalone Redis; PostgreSQL canonical ledger; modular monolith.
- Provider attempts: SQL `reserved` row before upstream dispatch and independent reservation for fallback.
- Money: integer microdollars, TypeScript bigint, Redis Lua bounded below 2^53 and preflight validation.
- Accounting: idempotent ACK/settlement, expired hold never silently released, generation fence and fail-closed uncertainty.
- Security: FORCE RLS, composite tenant FKs, limited SECURITY DEFINER, session/virtual-key principal separation, CSRF, secrets redacted.
- Transport: bounded parser, downstream backpressure, abort propagation, no failover after first downstream content token.
- Mock deterministic and private; public provider endpoints fixed HTTPS allowlisted; no provider secrets in workers.
- All core invariants must be proven with real PostgreSQL and Redis integration tests; mock upstream for reproducible network faults.

## End-of-task report
Task ID · files changed · behavior summary · tests/commands and exit codes · known limitations · security implications · requested deviations · diff/commit.

**Implementation completed ≠ accepted.** The principal architect reviews actual evidence; the project owner approves merges.
