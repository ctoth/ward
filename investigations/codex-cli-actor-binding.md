# Investigation: Codex CLI actor binding

## Facts (verified)

- `ward allow <signal> --session S --agent A` stores the signal in actor `A`.
- `ward set <phase> --session S --agent A` updates actor `A`.
- A Codex CLI PreToolUse payload can omit `agent_id`.
- `stateKeyFromHook` resolves a missing payload actor from `WARD_ACTOR_ID`, then falls back to `main`.
- Actor identity supplied through `--agent` is not persisted for later hook processes.
- Therefore a signal granted to actor `A` is invisible to a later hook that has the same session but no `agent_id` or inherited `WARD_ACTOR_ID`.
- The field failure reproduced this exactly: the signal receipt named actor `A`, while the following Git hook evaluated `main` and denied the operation.

## Theories

1. The signal rule is wrong. Prediction: the hook would still deny when it loads the same actor state containing `dirty-tree-switch`.
2. One-time signal consumption is wrong. Prediction: the actual hook would load actor `A` but find the signal already absent without any prior evaluation.
3. Actor binding is incomplete for CLI-launched workers. Prediction: command state resolves actor `A`, while a later actor-less hook in the same session resolves `main`.

## Tests Run

| Test | Hypothesis | Result | Rules Out | Supports |
|---|---|---|---|---|
| Inspect `cmdAllow`, `stateKeyFromCommandArgs`, and `stateKeyFromHook` | 1-3 | Commands honor `--agent`; hooks cannot see that choice later | Signal-rule-only explanation | 3 |
| Inspect the live promotion receipts | 2-3 | Manual evaluation consumed the first signal; the second attempt skipped manual evaluation and was still denied | Consumption as the sole cause | 3 |
| Inspect actor precedence tests | 3 | Tests cover payload/env actor identity but not persistent CLI command-to-hook binding | Existing coverage completeness | 3 |

## Current Best Theory

Theory 3 explains every receipt. Ward exposes actor-scoped CLI commands but does not durably bind their selected actor to later hook processes when the host omits `agent_id`. Requiring callers to set `WARD_ACTOR_ID` before starting Codex is a workaround, not a complete CLI actor surface.

## Required Fix

Persist the actor selected by Ward's state-mutating CLI commands as the active actor for that session. For hook events without `agent_id` or `WARD_ACTOR_ID`, resolve that session binding before falling back to `main`. Payload and environment actor identities must retain precedence, and native subagent isolation must remain unchanged.

## Exit Criteria

- A red test reproduces `--agent A` followed by an actor-less hook in session `S` resolving `main`.
- The fix makes that hook resolve `A`.
- Explicit payload actors and `WARD_ACTOR_ID` still win.
- Selecting `main` restores main-actor resolution.
- Actor/session lifecycle tests and the full Go suite pass.
- The installed Ward binary is rebuilt and the original dirty-tree promotion succeeds with one signal and no manual `ward eval` preflight.
