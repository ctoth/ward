from __future__ import annotations

import subprocess
from pathlib import Path

from policy_harness.model import PolicyState
from policy_harness.strategies import PATH_POOL, UNTRACKED_POOL


def materialize_policy_state(repo: Path, state: PolicyState) -> None:
    subprocess.run(
        ["git", "reset", "--hard", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "clean", "-fd"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    for path in PATH_POOL:
        file_path = repo / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(base_content(path), encoding="utf-8")

    dirty_tracked = state.current_unstaged_paths | {
        path for path in state.current_staged_paths if path in PATH_POOL
    }
    for path in sorted(dirty_tracked):
        file_path = repo / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(base_content(path) + f"# dirty {path}\n", encoding="utf-8")

    for path in sorted(state.current_untracked_paths):
        file_path = repo / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(f"new file {path}\n", encoding="utf-8")

    for path in sorted(path for path in state.current_staged_paths if path in UNTRACKED_POOL):
        file_path = repo / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if not file_path.exists():
            file_path.write_text(f"staged new file {path}\n", encoding="utf-8")

    for path in sorted(state.current_staged_paths):
        subprocess.run(
            ["git", "add", path],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )


def base_content(path: str) -> str:
    if path == "src/app.py":
        return "print('app')\n"
    if path == "src/menu.py":
        return "print('menu')\n"
    if path == "docs/spec.md":
        return "# spec\n"
    if path == "notes/todo.txt":
        return "todo\n"
    return f"{path}\n"
