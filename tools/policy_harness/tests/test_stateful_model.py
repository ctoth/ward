from __future__ import annotations

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from policy_harness.actions import (
    Adopt,
    Commit,
    Create,
    Edit,
    GrantDiscard,
    RestoreFile,
    Stage,
    SwitchBranch,
)
from policy_harness.decide import apply_action, decide, has_progress_path
from policy_harness.model import PolicyState
from policy_harness.strategies import PATH_POOL, UNTRACKED_POOL

ALL_PATHS = PATH_POOL + UNTRACKED_POOL


class PolicyStateMachine(RuleBasedStateMachine):
    @initialize()
    def init_model(self) -> None:
        self.state = PolicyState()

    @rule(path=st.sampled_from(ALL_PATHS))
    def edit(self, path: str) -> None:
        self.state = apply_action(self.state, Edit(path))

    @rule(path=st.sampled_from(ALL_PATHS))
    def create(self, path: str) -> None:
        self.state = apply_action(self.state, Create(path))

    @rule(path=st.sampled_from(ALL_PATHS))
    def adopt(self, path: str) -> None:
        self.state = apply_action(self.state, Adopt(path))

    @rule(path=st.sampled_from(ALL_PATHS))
    def grant_discard(self, path: str) -> None:
        self.state = apply_action(self.state, GrantDiscard(path))

    @rule(path=st.sampled_from(ALL_PATHS))
    def stage(self, path: str) -> None:
        self.state = apply_action(self.state, Stage(path))

    @rule(path=st.sampled_from(ALL_PATHS))
    def restore(self, path: str) -> None:
        self.state = apply_action(self.state, RestoreFile(path))

    @rule()
    def commit(self) -> None:
        self.state = apply_action(self.state, Commit())

    @rule()
    def switch_branch(self) -> None:
        self.state = apply_action(self.state, SwitchBranch())

    @invariant()
    def commits_only_contain_eligible_paths(self) -> None:
        assert self.state.current_staged_paths.issubset(self.state.commit_eligible_paths)

    @invariant()
    def adoption_does_not_imply_discard(self) -> None:
        for path in self.state.adopted_paths - self.state.discardable_paths:
            if path in self.state.baseline_dirty_paths:
                assert not decide(self.state, RestoreFile(path)).allow

    @invariant()
    def owned_dirty_work_has_an_escape_hatch(self) -> None:
        owned_dirty = self.state.current_dirty_paths & self.state.session_owned_paths
        if owned_dirty:
            assert has_progress_path(self.state)


TestPolicyStateMachine = PolicyStateMachine.TestCase
