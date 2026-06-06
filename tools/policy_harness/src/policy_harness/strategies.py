from __future__ import annotations

from hypothesis import strategies as st

from policy_harness.actions import (
    AddAll,
    Commit,
    Push,
    ReadOnlyGit,
    ResetHard,
    RestoreFile,
    Stage,
    Stash,
    SwitchBranch,
)
from policy_harness.model import PolicyState


PATH_POOL = [
    "src/app.py",
    "src/menu.py",
    "docs/spec.md",
    "notes/todo.txt",
]

UNTRACKED_POOL = [
    "scratch/new.txt",
    "scratch/draft.md",
]


@st.composite
def policy_states(draw: st.DrawFn) -> PolicyState:
    paths = set(PATH_POOL) | set(UNTRACKED_POOL)
    baseline_dirty = draw(st.sets(st.sampled_from(PATH_POOL), max_size=3))
    baseline_staged = draw(optional_subset(sorted(baseline_dirty)))
    touched = draw(st.sets(st.sampled_from(sorted(paths)), max_size=4))
    touched_since_commit = draw(optional_subset(sorted(touched)))
    adopted = draw(optional_subset(sorted(baseline_dirty)))
    discardable = draw(optional_subset(sorted(paths), max_size=2))
    current_staged = draw(optional_subset(sorted(paths), max_size=3))
    remaining_tracked = [path for path in PATH_POOL if path not in current_staged]
    current_unstaged = draw(optional_subset(remaining_tracked, max_size=3))
    remaining_untracked = [path for path in UNTRACKED_POOL if path not in current_staged]
    current_untracked = draw(optional_subset(remaining_untracked, max_size=2))
    branch_class = draw(st.sampled_from(["feature", "main_master"]))
    return PolicyState(
        branch_class=branch_class,
        baseline_dirty_paths=frozenset(baseline_dirty),
        baseline_staged_paths=frozenset(baseline_staged),
        current_unstaged_paths=frozenset(current_unstaged),
        current_staged_paths=frozenset(current_staged),
        current_untracked_paths=frozenset(current_untracked),
        touched_files=frozenset(touched),
        touched_since_commit=frozenset(touched_since_commit),
        adopted_paths=frozenset(adopted),
        discardable_paths=frozenset(discardable),
    )


@st.composite
def git_actions(draw: st.DrawFn):
    path = draw(st.sampled_from(PATH_POOL + UNTRACKED_POOL))
    return draw(
        st.one_of(
            st.just(Stage(path)),
            st.just(Commit()),
            st.just(SwitchBranch()),
            st.just(RestoreFile(path)),
            st.just(ResetHard()),
            st.just(Stash()),
            st.just(Push(force=True)),
            st.just(Push(force=False)),
            st.just(ReadOnlyGit("status")),
            st.just(ReadOnlyGit("diff")),
            st.just(AddAll()),
        )
    )


def optional_subset(items: list[str], max_size: int | None = None):
    if not items:
        return st.just(set())
    return st.sets(
        st.sampled_from(items),
        max_size=min(len(items), max_size if max_size is not None else len(items)),
    )
