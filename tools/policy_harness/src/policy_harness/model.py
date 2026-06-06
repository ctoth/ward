from __future__ import annotations

from dataclasses import dataclass, replace
from typing import FrozenSet


BranchClass = str


@dataclass(frozen=True)
class PolicyState:
    branch_class: BranchClass = "feature"
    baseline_dirty_paths: FrozenSet[str] = frozenset()
    baseline_staged_paths: FrozenSet[str] = frozenset()
    current_unstaged_paths: FrozenSet[str] = frozenset()
    current_staged_paths: FrozenSet[str] = frozenset()
    current_untracked_paths: FrozenSet[str] = frozenset()
    touched_files: FrozenSet[str] = frozenset()
    touched_since_commit: FrozenSet[str] = frozenset()
    adopted_paths: FrozenSet[str] = frozenset()
    discardable_paths: FrozenSet[str] = frozenset()
    phase: str = "implementing"
    signals: FrozenSet[str] = frozenset()

    @property
    def current_dirty_paths(self) -> FrozenSet[str]:
        return (
            self.current_unstaged_paths
            | self.current_staged_paths
            | self.current_untracked_paths
        )

    @property
    def session_owned_paths(self) -> FrozenSet[str]:
        return self.touched_files - self.baseline_dirty_paths

    @property
    def commit_eligible_paths(self) -> FrozenSet[str]:
        return self.session_owned_paths | self.adopted_paths

    @property
    def clean(self) -> bool:
        return not self.current_dirty_paths

    def with_updates(self, **kwargs: object) -> "PolicyState":
        return replace(self, **kwargs)
