from __future__ import annotations

from uuid import uuid4

import pytest

from policy_harness.actions import RestoreFile, Stage
from policy_harness.event_builders import action_to_event, shell_event
from policy_harness.git_repo_state import materialize_policy_state
from policy_harness.model import PolicyState
from policy_harness.ward_runner import run_cli, run_eval, write_state


def test_installed_builtin_profiles_drive_runtime_policy(
    ward_binary,
    git_repo,
    fake_home,
) -> None:
    run_cli(
        ward_binary,
        ["install-defaults", "--profile", "core-safety,git-discipline"],
        cwd=git_repo,
        home=fake_home,
    )

    state = PolicyState(
        baseline_dirty_paths=frozenset({"src/app.py"}),
        current_unstaged_paths=frozenset({"src/app.py"}),
        touched_files=frozenset({"src/app.py"}),
    )
    materialize_policy_state(git_repo, state)
    session_id = f"profiles-{uuid4().hex}"
    write_state(session_id, state, git_repo)

    denied = run_eval(
        ward_binary,
        action_to_event(Stage("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=None,
    )
    assert denied != ""

    run_cli(
        ward_binary,
        ["adopt", "src/app.py"],
        cwd=git_repo,
        home=fake_home,
        session_id=session_id,
    )
    allowed = run_eval(
        ward_binary,
        action_to_event(Stage("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=None,
    )
    assert allowed == ""

    restore_denied = run_eval(
        ward_binary,
        action_to_event(RestoreFile("src/app.py")),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=None,
    )
    assert restore_denied != ""


# Regression: the reset-hard rule must key off the parsed git subcommand/args,
# not a "^git reset --hard" string match on the raw command. The string form
# was bypassable by global options (git -C . / git -c k=v) and by git's
# unambiguous option abbreviations (git reset --har). See no-git-reset-hard.yaml.
RESET_HARD_BLOCKED = [
    "git reset --hard",
    "git reset --hard HEAD~3",
    "git -C . reset --hard",
    "git -c core.editor=vim reset --hard",
    "git --no-pager reset --hard",
    "git reset --har",
    "git reset --ha",
    # command-wrapper / path bypasses, closed by the parser normalization
    "/usr/bin/git reset --hard",
    "command git reset --hard",
    "sudo git reset --hard",
    "env GIT_PAGER=cat git reset --hard",
]

RESET_HARD_ALLOWED = [
    "git reset --soft HEAD~1",
    "git reset HEAD~1",
    "git reset",
    "git reset --mixed",
    "git reset --keep HEAD",
    "git status --short",
]


@pytest.mark.parametrize("command", RESET_HARD_BLOCKED)
def test_reset_hard_variants_are_denied(
    ward_binary, rules_dir, fake_home, tmp_path, command
) -> None:
    decision = run_eval(
        ward_binary,
        shell_event(command),
        agent="claude",
        session_id="reset-hard-deny",
        cwd=tmp_path,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert decision != "", f"expected DENY but was allowed: {command!r}"


@pytest.mark.parametrize("command", RESET_HARD_ALLOWED)
def test_non_hard_reset_is_allowed(
    ward_binary, rules_dir, fake_home, tmp_path, command
) -> None:
    decision = run_eval(
        ward_binary,
        shell_event(command),
        agent="claude",
        session_id="reset-hard-allow",
        cwd=tmp_path,
        home=fake_home,
        rules_dir=rules_dir,
    )
    assert decision == "", f"expected ALLOW but was denied: {command!r}"


# Regression: the force-tag rule must key off the parsed git tag subcommand and
# its flags (covering bundled short flags like -af and global-option smuggling),
# not a "^git tag .*-f" string match. See core-safety/rules/no-force-tag.yaml.
FORCE_TAG_BLOCKED = [
    "git tag -f v1",
    "git tag --force v1",
    "git -C . tag -f v1",
    "git tag -af v1",
    "command git tag -f v1",
]

FORCE_TAG_ALLOWED = [
    "git tag v1",
    "git tag -l",
    "git tag -a v1 -m msg",
    "git tag -d v1",
]


@pytest.fixture(scope="session")
def builtin_core_safety_rules(repo_root):
    return repo_root / "builtin_profiles" / "core-safety" / "rules"


@pytest.mark.parametrize("command", FORCE_TAG_BLOCKED)
def test_force_tag_variants_are_denied(
    ward_binary, builtin_core_safety_rules, fake_home, tmp_path, command
) -> None:
    decision = run_eval(
        ward_binary,
        shell_event(command),
        agent="claude",
        session_id="force-tag-deny",
        cwd=tmp_path,
        home=fake_home,
        rules_dir=builtin_core_safety_rules,
    )
    assert decision != "", f"expected DENY but was allowed: {command!r}"


@pytest.mark.parametrize("command", FORCE_TAG_ALLOWED)
def test_non_force_tag_is_allowed(
    ward_binary, builtin_core_safety_rules, fake_home, tmp_path, command
) -> None:
    decision = run_eval(
        ward_binary,
        shell_event(command),
        agent="claude",
        session_id="force-tag-allow",
        cwd=tmp_path,
        home=fake_home,
        rules_dir=builtin_core_safety_rules,
    )
    assert decision == "", f"expected ALLOW but was denied: {command!r}"
