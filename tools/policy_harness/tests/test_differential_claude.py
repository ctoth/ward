from __future__ import annotations

from uuid import uuid4

from hypothesis import HealthCheck, given, settings

from policy_harness.decide import decide
from policy_harness.event_builders import action_to_event
from policy_harness.git_repo_state import materialize_policy_state
from policy_harness.strategies import git_actions, policy_states
from policy_harness.ward_runner import run_eval, write_state


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(state=policy_states(), action=git_actions())
def test_claude_policy_matches_oracle(
    state,
    action,
    ward_binary,
    git_repo,
    fake_home,
    rules_dir,
) -> None:
    materialize_policy_state(git_repo, state)
    session_id = f"claude-{uuid4().hex}"
    write_state(session_id, state, git_repo)
    stdout = run_eval(
        ward_binary,
        action_to_event(action),
        agent="claude",
        session_id=session_id,
        cwd=git_repo,
        home=fake_home,
        rules_dir=rules_dir,
    )
    actual_allow = stdout == ""
    expected_allow = decide(state, action).allow
    assert actual_allow == expected_allow
