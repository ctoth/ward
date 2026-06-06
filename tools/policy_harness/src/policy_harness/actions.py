from __future__ import annotations

from dataclasses import dataclass


class Action:
    pass


@dataclass(frozen=True)
class Edit(Action):
    path: str


@dataclass(frozen=True)
class Create(Action):
    path: str


@dataclass(frozen=True)
class Stage(Action):
    path: str


@dataclass(frozen=True)
class Adopt(Action):
    path: str


@dataclass(frozen=True)
class GrantDiscard(Action):
    path: str


class Commit(Action):
    pass


@dataclass(frozen=True)
class RestoreFile(Action):
    path: str


@dataclass(frozen=True)
class RestoreDir(Action):
    path: str


class SwitchBranch(Action):
    pass


class ResetHard(Action):
    pass


class Stash(Action):
    pass


@dataclass(frozen=True)
class Push(Action):
    force: bool = False


@dataclass(frozen=True)
class ReadOnlyGit(Action):
    name: str = "status"


class AddAll(Action):
    pass
