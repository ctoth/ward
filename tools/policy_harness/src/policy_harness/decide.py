from __future__ import annotations

from dataclasses import dataclass

from policy_harness.actions import (
    Action,
    AddAll,
    Adopt,
    Commit,
    Create,
    Edit,
    GrantDiscard,
    Push,
    ReadOnlyGit,
    ResetHard,
    RestoreDir,
    RestoreFile,
    Stage,
    Stash,
    SwitchBranch,
)
from policy_harness.model import PolicyState


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


def decide(state: PolicyState, action: Action) -> Decision:
    if isinstance(action, ReadOnlyGit):
        return Decision(True, "read-only git is always allowed")

    if isinstance(action, (Edit, Create, Adopt, GrantDiscard)):
        return Decision(True, "session-local state update")

    if isinstance(action, AddAll):
        return Decision(False, "bulk stage is forbidden")

    if isinstance(action, ResetHard):
        return Decision(False, "reset --hard is forbidden")

    if isinstance(action, Stash):
        return Decision(False, "stash is forbidden")

    if isinstance(action, Push):
        if action.force:
            return Decision(False, "force push is forbidden")
        return Decision(True, "non-force push allowed")

    if isinstance(action, SwitchBranch):
        return Decision(state.clean, "branch switching requires a clean tree")

    if isinstance(action, RestoreDir):
        return Decision(False, "directory-wide restore is forbidden")

    if isinstance(action, RestoreFile):
        if action.path in state.discardable_paths:
            return Decision(True, "explicit discard grant")
        if action.path in state.session_owned_paths:
            return Decision(True, "owned-file restore")
        return Decision(False, "restore requires owned or discardable path")

    if isinstance(action, Stage):
        if action.path in state.baseline_dirty_paths and action.path not in state.adopted_paths:
            return Decision(False, "baseline-dirty path must be explicitly adopted")
        if action.path not in state.touched_files and action.path not in state.adopted_paths:
            return Decision(False, "path must be touched or adopted before staging")
        return Decision(True, "explicit owned/adopted path")

    if isinstance(action, Commit):
        staged = state.current_staged_paths
        if staged and not staged.issubset(state.commit_eligible_paths):
            return Decision(False, "staged set contains unowned paths")
        return Decision(True, "commit scope is acceptable")

    raise TypeError(f"unsupported action: {action!r}")


def apply_action(state: PolicyState, action: Action) -> PolicyState:
    decision = decide(state, action)
    if not decision.allow:
        return state

    if isinstance(action, Edit):
        current_untracked = set(state.current_untracked_paths)
        current_unstaged = set(state.current_unstaged_paths)
        if action.path not in current_untracked:
            current_unstaged.add(action.path)
        return state.with_updates(
            touched_files=state.touched_files | frozenset({action.path}),
            touched_since_commit=state.touched_since_commit | frozenset({action.path}),
            current_unstaged_paths=frozenset(current_unstaged),
        )

    if isinstance(action, Create):
        return state.with_updates(
            touched_files=state.touched_files | frozenset({action.path}),
            touched_since_commit=state.touched_since_commit | frozenset({action.path}),
            current_untracked_paths=state.current_untracked_paths | frozenset({action.path}),
        )

    if isinstance(action, Adopt):
        return state.with_updates(adopted_paths=state.adopted_paths | frozenset({action.path}))

    if isinstance(action, GrantDiscard):
        return state.with_updates(
            discardable_paths=state.discardable_paths | frozenset({action.path})
        )

    if isinstance(action, Stage):
        staged = set(state.current_staged_paths)
        unstaged = set(state.current_unstaged_paths)
        untracked = set(state.current_untracked_paths)
        staged.add(action.path)
        unstaged.discard(action.path)
        untracked.discard(action.path)
        return state.with_updates(
            current_staged_paths=frozenset(staged),
            current_unstaged_paths=frozenset(unstaged),
            current_untracked_paths=frozenset(untracked),
        )

    if isinstance(action, Commit):
        return state.with_updates(
            current_staged_paths=frozenset(),
            touched_since_commit=frozenset(),
        )

    if isinstance(action, RestoreFile):
        return state.with_updates(
            current_staged_paths=state.current_staged_paths - frozenset({action.path}),
            current_unstaged_paths=state.current_unstaged_paths - frozenset({action.path}),
            current_untracked_paths=state.current_untracked_paths - frozenset({action.path}),
        )

    return state


def has_progress_path(state: PolicyState) -> bool:
    candidates: list[Action] = []
    for path in sorted(state.current_unstaged_paths | state.current_untracked_paths):
        candidates.append(Stage(path))
    for path in sorted(state.current_dirty_paths):
        candidates.append(RestoreFile(path))
    candidates.append(Commit())
    return any(decide(state, action).allow for action in candidates)
