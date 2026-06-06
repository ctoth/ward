from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from policy_harness.event_builders import HookEvent
from policy_harness.model import PolicyState


AgentName = Literal["claude", "gemini"]


def state_file(session_id: str) -> Path:
    return Path(tempfile.gettempdir()) / "ward" / f"{session_id}.json"


def write_state(session_id: str, state: PolicyState, repo_root: Path) -> None:
    path = state_file(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "phase": state.phase,
        "history": [],
        "signals": {},
        "started_at": "2026-04-05T00:00:00Z",
        "repo_root": repo_root.as_posix(),
        "baseline_dirty_paths": sorted(state.baseline_dirty_paths),
        "touched_files": sorted(state.touched_files),
        "touched_since_commit": sorted(state.touched_since_commit),
        "adopted_paths": sorted(state.adopted_paths),
        "discardable_paths": sorted(state.discardable_paths),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def run_eval(
    ward_binary: Path,
    event: HookEvent,
    *,
    agent: AgentName,
    session_id: str,
    cwd: Path,
    home: Path,
    rules_dir: Path | None = None,
) -> str:
    if agent == "claude":
        payload = event.as_claude(session_id=session_id, cwd=cwd)
    elif agent == "gemini":
        payload = event.as_gemini(session_id=session_id, cwd=cwd)
    else:
        raise ValueError(agent)

    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    if rules_dir is not None:
        env["WARD_RULES_PATH"] = str(rules_dir)
    else:
        env.pop("WARD_RULES_PATH", None)
    env.pop("WARD_FACTS_PATH", None)
    env.pop("WARD_SIGNALS_PATH", None)

    proc = subprocess.run(
        [str(ward_binary), "eval"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=cwd,
        env=env,
        check=True,
    )
    return proc.stdout.strip()


def run_grant(
    ward_binary: Path,
    kind: Literal["adopt", "discard"],
    *,
    cwd: Path,
    home: Path,
    session_id: str,
    paths: list[str],
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["WARD_SESSION"] = session_id
    return subprocess.run(
        [str(ward_binary), kind, *paths],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def run_cli(
    ward_binary: Path,
    args: list[str],
    *,
    cwd: Path,
    home: Path,
    session_id: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    if session_id is not None:
        env["WARD_SESSION"] = session_id
    return subprocess.run(
        [str(ward_binary), *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
