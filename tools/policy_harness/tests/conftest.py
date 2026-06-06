from __future__ import annotations

import subprocess
import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def rules_dir(repo_root: Path) -> Path:
    return repo_root / "tools" / "policy_harness" / "ward_rules"


@pytest.fixture(scope="session")
def ward_binary(tmp_path_factory: pytest.TempPathFactory, repo_root: Path) -> Path:
    out_dir = tmp_path_factory.mktemp("ward-bin")
    binary = out_dir / ("ward-harness.exe" if os.name == "nt" else "ward-harness")
    subprocess.run(
        ["go", "build", "-o", str(binary), "."],
        cwd=repo_root,
        check=True,
    )
    return binary


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "config", "user.name", "Ward Harness"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "ward@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    for relative, content in {
        "src/app.py": "print('app')\n",
        "src/menu.py": "print('menu')\n",
        "docs/spec.md": "# spec\n",
        "notes/todo.txt": "todo\n",
    }.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return repo
