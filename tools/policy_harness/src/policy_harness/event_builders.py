from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from policy_harness.actions import (
    Action,
    AddAll,
    Commit,
    Push,
    ReadOnlyGit,
    ResetHard,
    RestoreDir,
    RestoreFile,
    Stage,
    Stash,
    SwitchBranch,
)


@dataclass(frozen=True)
class HookEvent:
    tool_name: str
    tool_input: dict[str, object]

    def as_claude(self, session_id: str, cwd: Path) -> dict[str, object]:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "session_id": session_id,
            "cwd": str(cwd),
        }

    def as_gemini(self, session_id: str, cwd: Path) -> dict[str, object]:
        return {
            "hook_event_name": "BeforeTool",
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "session_id": session_id,
            "cwd": str(cwd),
        }


def shell_event(command: str) -> HookEvent:
    return HookEvent(tool_name="Bash", tool_input={"command": command})


def edit_event(path: str) -> HookEvent:
    return HookEvent(tool_name="Edit", tool_input={"file_path": path})


def action_to_event(action: Action) -> HookEvent:
    if isinstance(action, Stage):
        return shell_event(f"git add {action.path}")
    if isinstance(action, Commit):
        return shell_event("git commit -m checkpoint")
    if isinstance(action, SwitchBranch):
        return shell_event("git switch topic")
    if isinstance(action, RestoreFile):
        return shell_event(f"git checkout -- {action.path}")
    if isinstance(action, RestoreDir):
        return shell_event(f"git checkout -- {action.path}")
    if isinstance(action, ResetHard):
        return shell_event("git reset --hard")
    if isinstance(action, Stash):
        return shell_event("git stash")
    if isinstance(action, Push):
        return shell_event("git push --force" if action.force else "git push")
    if isinstance(action, ReadOnlyGit):
        if action.name == "status":
            return shell_event("git status --short")
        if action.name == "diff":
            return shell_event("git diff --stat")
        return shell_event(f"git {action.name}")
    if isinstance(action, AddAll):
        return shell_event("git add -A")
    raise TypeError(f"unsupported action for hook event: {action!r}")
