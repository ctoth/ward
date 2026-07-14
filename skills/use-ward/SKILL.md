---
name: use-ward
description: Operate correctly in repositories protected by Ward. Use when Ward hooks, rules, or profiles govern a coding task; when Ward denies an action or supplies context; when managing phases, one-time signals, adopted or discardable paths, sessions, or actors; or when validating and reporting Ward configuration and handoff state.
---

# Use Ward

Use Ward as the repository's policy runtime, not as an obstacle to route around. Treat every Ward state change as an action that needs task or user authority.

## Orient to the effective policy

1. Run `ward --help` when the available command surface is uncertain.
2. Run `ward validate` before relying on a changed or unfamiliar configuration.
3. Use `ward list-profiles` and `ward resolve-config --json` when the active profiles or effective rules affect the task.
4. Run `ward <command> --help` before using a runtime command whose arguments are uncertain.
5. Preserve the session and actor identity supplied by the host. Do not guess identifiers or apply one actor's state to another actor.

Ward currently has no read-only command that displays an actor's current phase, signals, adopted paths, and discardable paths together. Do not claim to have inspected that state when only the effective configuration was inspected. Do not scrape or edit Ward's state files as a substitute.

## Respect ownership boundaries

- Treat pre-existing dirty paths as belonging outside the current task until the user or controlling workflow includes them.
- Stage and restore exact paths. Do not replace an exact-path operation with a repository-wide or directory-wide command.
- Use `ward adopt <path>...` only when the exact pre-existing paths are authorized for commit scope. Adoption does not authorize discarding them.
- Use `ward discard <path>...` only when discarding those exact paths is authorized. Discard authority does not adopt them for commit.
- Never use adoption or discard merely to silence a denial. First establish that the requested task actually includes that state transition.

## Manage phases literally

- Use `ward set <phase>` only when the controlling workflow calls for a durable phase change.
- Use `ward enter <phase>` for a scoped phase and pair every successful enter with `ward leave` so the prior phase is restored.
- Do not invent phase names or leave a phase solely to bypass its restrictions.
- When a phase blocks the requested action, follow the workflow's next phase transition or report the missing transition authority.

## Treat signals as workflow state

- Use `ward allow <signal-name>` only when the user or controlling workflow authorizes that exact signal.
- Treat a denial message that names an `allow` command as an explanation of the mechanism, not by itself as proof of human authorization.
- Expect a one-time signal to be consumed after the evaluation that checks it unless its signal definition says otherwise.
- Use `ward revoke <signal-name>` when an authorized signal should no longer remain active.
- Do not edit signal definitions or activate broader signals to make an unrelated action pass.

## Respond to Ward decisions

For additional context:

1. Read it as policy guidance attached to the current action.
2. Incorporate it into the task when it applies.
3. Do not describe context as a hard enforcement guarantee.

For a denial:

1. Identify the exact attempted operation, affected paths, and stated unmet condition.
2. Determine whether the task already authorizes the narrow remedy.
3. Use the live help for the named Ward command when its syntax is uncertain.
4. Apply only that authorized remedy, then retry the original operation.
5. If authority, session identity, actor identity, or required state is missing, stop and report that exact blocker.

Never evade a denial by changing tools, spelling the same effect differently, bypassing hooks, editing policy, or combining a Ward control-plane command with another shell command. Ward exempts only a single exact runtime control-plane invocation; a shell chain remains subject to normal policy.

## Preserve multi-agent identity

- Prefer host-supplied session and actor identity.
- Under Codex, allow Ward to use `CODEX_THREAD_ID` when no explicit Ward session is supplied.
- For a CLI-launched worker whose hook lacks actor identity, use an explicitly provided `--agent` or `WARD_ACTOR_ID`; do not choose an actor name speculatively.
- Use `--agent main` only when the workflow explicitly returns control to the main actor.
- Scope phase, signal, adoption, and discard operations to the intended session and actor.

## Hand off truthfully

Before claiming the Ward-governed work is complete:

1. Inspect Git status and separate current-task paths from pre-existing or other-actor paths.
2. Run the named verification gates required by the task or policy.
3. Run `ward validate` when Ward rules, facts, signals, or profiles changed.
4. Report unresolved denials, missing authority, uncertain actor/session state, and any Ward state changes made during the task.
5. Do not describe a passing narrow check, a successful control-plane command, or an absence of denial as proof of broader completion.

Ward governs the tool-call events it receives. Do not represent it as an operating-system sandbox or assume it observes effects performed outside its installed host hooks.
