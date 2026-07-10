from __future__ import annotations

from policy_harness.actions import Commit, GrantDiscard, RestoreFile, Stage, SwitchBranch
from policy_harness.decide import apply_action, decide
from policy_harness.model import PolicyState


def test_dirty_tree_branch_switch_is_denied() -> None:
    state = PolicyState(current_unstaged_paths=frozenset({"src/app.py"}))
    decision = decide(state, SwitchBranch())
    assert not decision.allow


def test_dirty_tree_branch_switch_override_is_allowed() -> None:
    state = PolicyState(
        current_unstaged_paths=frozenset({"src/app.py"}),
        signals=frozenset({"dirty-tree-switch"}),
    )
    decision = decide(state, SwitchBranch())
    assert decision.allow


def test_baseline_dirty_file_requires_adoption_for_staging() -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        touched_files=frozenset({"src/app.py"}),
    )
    decision = decide(state, Stage("src/app.py"))
    assert not decision.allow


def test_adoption_allows_commit_scope_but_not_restore() -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        adopted_paths=frozenset({"src/app.py"}),
    )
    assert decide(state, Stage("src/app.py")).allow
    staged = apply_action(state, Stage("src/app.py"))
    assert decide(staged, Commit()).allow
    assert not decide(staged, RestoreFile("src/app.py")).allow


def test_discard_grant_is_separate_from_adoption() -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        adopted_paths=frozenset({"src/app.py"}),
    )
    granted = apply_action(state, GrantDiscard("src/app.py"))
    assert decide(granted, RestoreFile("src/app.py")).allow
