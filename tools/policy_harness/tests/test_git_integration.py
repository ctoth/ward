from __future__ import annotations

import json
from uuid import uuid4

from policy_harness.actions import RestoreFile, Stage
from policy_harness.event_builders import action_to_event
from policy_harness.git_repo_state import materialize_policy_state
from policy_harness.model import PolicyState
from policy_harness.ward_runner import run_eval, run_grant, state_file, write_state


def test_adopt_allows_staging_baseline_dirty_file(
    ward_binary,
    git_repo,
    fake_home,
    rules_dir,
) -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        touched_files=frozenset({"src/app.py"}),
    )
    materialize_policy_state(git_repo, state)
    session_id = f"adopt-{uuid4().hex}"
    write_state(session_id, state, git_repo)

    denied = run_eval(
        ward_binary,
        action_to_event(Stage("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert denied != ""

    run_grant(
        ward_binary,
        "adopt",
        cwd=git_repo,
        home=fake_home,
        session_id=session_id,
        paths=["src/app.py"],
    )
    allowed = run_eval(
        ward_binary,
        action_to_event(Stage("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert allowed == ""


def test_adopt_does_not_grant_restore(
    ward_binary,
    git_repo,
    fake_home,
    rules_dir,
) -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        adopted_paths=frozenset({"src/app.py"}),
    )
    materialize_policy_state(git_repo, state)
    session_id = f"restore-{uuid4().hex}"
    write_state(session_id, state, git_repo)

    denied = run_eval(
        ward_binary,
        action_to_event(RestoreFile("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert denied != ""


def test_discard_grant_allows_exact_restore(
    ward_binary,
    git_repo,
    fake_home,
    rules_dir,
) -> None:
    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
    )
    materialize_policy_state(git_repo, state)
    session_id = f"discard-{uuid4().hex}"
    write_state(session_id, state, git_repo)

    run_grant(
        ward_binary,
        "discard",
        cwd=git_repo,
        home=fake_home,
        session_id=session_id,
        paths=["src/app.py"],
    )
    allowed = run_eval(
        ward_binary,
        action_to_event(RestoreFile("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert allowed == ""


def test_directory_restore_is_denied(
    ward_binary,
    git_repo,
    fake_home,
    rules_dir,
) -> None:
    state = PolicyState(
        current_unstaged_paths=frozenset({"src/app.py", "src/menu.py"}),
        touched_files=frozenset({"src/app.py", "src/menu.py"}),
    )
    materialize_policy_state(git_repo, state)
    session_id = f"dirrestore-{uuid4().hex}"
    write_state(session_id, state, git_repo)

    denied = run_eval(
        ward_binary,
        action_to_event(RestoreFile("src")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert denied != ""
