# Ward

Session-aware guard for AI coding agents. Ward evaluates CEL rules against tool calls from Claude Code, Gemini CLI, and Codex CLI, enforcing project-specific policies like "no `python -c`" or "commit before editing more files." Rules are per-file YAML, deny is a veto, and context messages accumulate.

Ward parses shell commands into an AST using [mvdan.cc/sh](https://pkg.go.dev/mvdan.cc/sh/v3), so rules match against actual commands — not raw text. This means `git commit -m "python -c blah"` won't trigger a no-python-c rule, because the only actual command is `git`. Pipes, `&&` chains, and semicolons are all decomposed into individual commands.

## Install

```
go install github.com/ctoth/ward@latest
```

## Facts

Facts are shell commands evaluated on demand when referenced by rules. Each fact is one YAML file:

| Path | Scope |
|---|---|
| `~/.ward/facts/*.yaml` | Global (all projects) |
| `.ward/facts/*.yaml` | Project-specific (override global on name conflict) |

The filename (minus extension) becomes the fact name:

```yaml
# ~/.ward/facts/git_branch.yaml
command: "git branch --show-current"
```

```yaml
# ~/.ward/facts/has_pyproject.yaml
command: "test -f pyproject.toml && echo true || echo false"
type: bool
```

| Field | Required | Description |
|---|---|---|
| `command` | yes | Shell command to execute (via `bash -c`) |
| `type` | no | `string` (default) or `bool` (`"true"`/`"1"` → true) |

The default session phase is always "planning" (hardcoded, no config needed).

## Rules

Rules live in two directories, one file per rule:

| Path | Scope |
|---|---|
| `~/.ward/rules/*.yaml` | Global (all projects) |
| `.ward/rules/*.yaml` | Project-specific |

Each file is one rule:

```yaml
when: 'tool == "Bash" && input.command.matches("python[3]?\\s+-c")'
action: deny
message: "Write a .py file, then run it."
```

### Rule format

| Field | Required | Description |
|---|---|---|
| `when` | yes | CEL expression that returns bool |
| `action` | yes | `deny`, `allow`, or `context` |
| `message` | yes | Human-readable explanation |
| `scope` | no | Glob pattern restricting rule to matching file paths |

### Actions and conflict resolution

All matching rules from all sources are collected. Then:

- **Any rule says `deny`** -- denied (first deny's message used)
- **No denies, some say `context`** -- all context messages joined and injected
- **Nothing matches** -- allowed

No ordering, no priority. Deny is a veto. Context accumulates.

### Scope

Optional `scope` restricts a rule to file paths matching a glob:

```yaml
scope: "output/**"
when: 'tool in ["Edit", "Write"]'
action: deny
message: "Fix upstream, not generated files."
```

### CEL context

Rules have access to these variables:

| Variable | Type | Description |
|---|---|---|
| `tool` | string | Tool name: "Bash", "Edit", "Write", "Read", etc. |
| `input` | map | Tool-specific input (e.g., `input.command`, `input.file_path`). For Bash tools, also includes `input.commands` — a list of parsed command maps (see below). |
| `session.phase` | string | Current phase ("planning", "implementing", etc.) |
| `session.history` | list(string) | Tool names in call order (capped at 100). Includes synthetic `_commit` marker when a Bash call contains "git commit". |
| `session.tool_count` | int | Total tool calls this session (derived from history length) |
| `facts.*` | any | Computed facts from config (shell commands, evaluated on demand) |

### Parsed commands (`input.commands`)

For Bash tool calls, ward parses the shell command into an AST and adds `input.commands` — a list of maps, one per command in the pipeline/chain. Each map has:

| Field | Type | Description |
|---|---|---|
| `name` | string | The command name (first word, e.g., `git`, `python`) |
| `full` | string | The full command reconstructed from the AST (`name arg1 arg2 ...`), excluding heredoc bodies and command substitution contents |

This means rules can match against actual commands rather than raw text:

```yaml
# Old (matches "python -c" anywhere in the raw string, including commit messages):
when: 'tool == "Bash" && input.command.matches("python[3]?\\s+-c")'

# New (matches only if an actual command is python with -c flag):
when: 'tool == "Bash" && input.commands.exists(c, c.full.matches("^python[3]?\\s+-c"))'
```

If shell parsing fails (invalid syntax), ward falls back to treating the raw string as a single command, so rules still work.

### Custom CEL functions

| Function | Signature | Description |
|---|---|---|
| `last` | `last(list, n) -> list` | Returns the last N elements. If the list has fewer than N elements, returns the whole list. |
| `since` | `since(list, marker) -> list` | Returns all elements after the last occurrence of `marker`. If `marker` never appears, returns the whole list. |

All paths are normalized to forward slashes internally, including on Windows.

## Commands

### `ward eval`

Reads a tool call event from stdin (JSON), evaluates rules, outputs response JSON (or nothing if allowed).

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git stash"},"session_id":"abc","cwd":"/tmp"}' | ward eval
```

### `ward set <phase>`

Sets the session phase.

```bash
ward set implementing --session abc
```

### `ward validate`

Scans all rule files, compiles CEL, reports errors.

```bash
ward validate
```

## Multi-agent support

Ward auto-detects the calling agent from the JSON format:

- **Claude Code**: `hook_event_name` is `PreToolUse`/`PostToolUse`
- **Gemini CLI**: `hook_event_name` is `BeforeTool`/`AfterTool`
- **Codex CLI**: nested `hook_event.event_type`

Each agent gets responses in its native format.

## Example rules

### Safety: block dangerous commands

**No python -c oneliners:**
```yaml
# ~/.ward/rules/no-python-c.yaml
when: 'tool == "Bash" && input.command.matches("python[3]?\\s+-c")'
action: deny
message: "Write a .py file, then run it."
```

**Use uv, not bare python:**
```yaml
# ~/.ward/rules/uv-not-python.yaml
when: 'tool == "Bash" && input.command.matches("^python[3]?\\s") && facts.has_pyproject'
action: deny
message: "Use `uv run python` instead of bare python."
```

**No git stash:**
```yaml
# ~/.ward/rules/no-git-stash.yaml
when: 'tool == "Bash" && input.command.matches("git\\s+stash")'
action: deny
message: "Commit or branch first. git stash destroys uncommitted work."
```

**No git add . or git add -A:**
```yaml
# ~/.ward/rules/no-git-add-all.yaml
when: 'tool == "Bash" && input.command.matches("git\\s+add\\s+(\\.|--all|-A)")'
action: deny
message: "Add specific files by name."
```

**No git reset --hard:**
```yaml
# ~/.ward/rules/no-git-reset-hard.yaml
when: 'tool == "Bash" && input.command.matches("git\\s+reset\\s+--hard")'
action: deny
message: "git reset --hard requires explicit permission."
```

**No force push:**
```yaml
# ~/.ward/rules/no-force-push.yaml
when: 'tool == "Bash" && input.command.matches("git\\s+push\\s+.*--force")'
action: deny
message: "Force-push requires explicit permission."
```

### Git discipline: branch before editing, commit frequently

**No editing on main/master:**
```yaml
# ~/.ward/rules/branch-before-edit.yaml
when: 'tool in ["Edit", "Write"] && facts.git_branch in ["main", "master"]'
action: deny
message: "Create a feature branch before editing files."
```

**Nudge to commit after multiple edits:**
```yaml
# ~/.ward/rules/commit-after-edits.yaml
when: 'since(session.history, "_commit").filter(t, t in ["Edit", "Write"]).size() >= 2'
action: context
message: "You have edited 2+ files without committing. Commit your work — uncommitted work does not exist."
```

### Phase enforcement

**No editing during planning:**
```yaml
# .ward/rules/no-edit-in-planning.yaml
when: 'session.phase == "planning" && tool in ["Edit", "Write"]'
action: deny
message: "Planning phase. Present your plan first."
```

**No editing during investigation:**
```yaml
# .ward/rules/no-edit-in-investigating.yaml
when: 'session.phase == "investigating" && tool in ["Edit", "Write"]'
action: deny
message: "Investigating phase. Diagnose only — report findings first."
```

### Behavioral nudges

**Possible flailing — too many reads without running anything:**
```yaml
# ~/.ward/rules/flailing-reads.yaml
when: 'size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])'
action: context
message: "You have read 5+ files without running anything. State your theory about what is wrong before reading more."
```

### File scope: protect generated output

**No editing generated files:**
```yaml
# .ward/rules/no-edit-generated.yaml
scope: "output/**"
when: 'tool in ["Edit", "Write"]'
action: deny
message: "Fix upstream (templates, schema, annotations) — generated files are read-only."
```
