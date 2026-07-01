package main

import (
	"testing"
)

func TestParseSimpleCommand(t *testing.T) {
	cmds := ParseCommands(`python -c "print(1)"`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Name != "python" {
		t.Errorf("expected name python, got %q", cmds[0].Name)
	}
	if cmds[0].Full != `python -c print(1)` {
		t.Errorf("unexpected full: %q", cmds[0].Full)
	}
}

func TestParsePipe(t *testing.T) {
	cmds := ParseCommands(`cat foo | grep bar`)
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if cmds[0].Name != "cat" {
		t.Errorf("expected cat, got %q", cmds[0].Name)
	}
	if cmds[1].Name != "grep" {
		t.Errorf("expected grep, got %q", cmds[1].Name)
	}
}

func TestParseChain(t *testing.T) {
	cmds := ParseCommands(`git add foo && git commit -m "msg"`)
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if cmds[0].Name != "git" {
		t.Errorf("expected git, got %q", cmds[0].Name)
	}
	if cmds[1].Name != "git" {
		t.Errorf("expected git, got %q", cmds[1].Name)
	}
}

func TestParseHeredocDoesNotExtractContent(t *testing.T) {
	// The heredoc body contains "python -c blah" but we should only see git
	cmd := "git commit -m \"$(cat <<'EOF'\npython -c blah\nEOF\n)\""
	cmds := ParseCommands(cmd)

	for _, c := range cmds {
		if c.Name == "python" {
			t.Errorf("heredoc content should not produce a python command, got: %+v", cmds)
		}
	}
	// Should have git as a command
	found := false
	for _, c := range cmds {
		if c.Name == "git" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected git command, got: %+v", cmds)
	}
}

func TestParsePipeWithPythonC(t *testing.T) {
	cmds := ParseCommands(`echo foo | python -c "import sys"`)
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.Name
	}
	// Should have both echo and python
	foundPython := false
	for _, c := range cmds {
		if c.Name == "python" {
			foundPython = true
			// Check that -c is in the full string
			if c.Full != "python -c import sys" {
				t.Errorf("unexpected full for python: %q", c.Full)
			}
		}
	}
	if !foundPython {
		t.Errorf("expected python in pipe, got: %v", names)
	}
}

func TestParseChainWithPythonC(t *testing.T) {
	cmds := ParseCommands(`cd /tmp && python -c "print(1)"`)
	foundPython := false
	for _, c := range cmds {
		if c.Name == "python" {
			foundPython = true
		}
	}
	if !foundPython {
		t.Fatalf("expected python in chain, got %+v", cmds)
	}
}

func TestParseSafeCommandWithDangerousArgs(t *testing.T) {
	// echo "git stash is bad" should only produce echo, not git
	cmds := ParseCommands(`echo "git stash is bad"`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d: %+v", len(cmds), cmds)
	}
	if cmds[0].Name != "echo" {
		t.Errorf("expected echo, got %q", cmds[0].Name)
	}
}

func TestParseGitCommitWithPythonInMessage(t *testing.T) {
	// git commit message containing "python -c" should NOT produce python command
	cmds := ParseCommands(`git commit -m "python -c is forbidden"`)
	for _, c := range cmds {
		if c.Name == "python" {
			t.Errorf("should not extract python from git commit message, got: %+v", cmds)
		}
	}
	if len(cmds) != 1 || cmds[0].Name != "git" {
		t.Errorf("expected single git command, got: %+v", cmds)
	}
}

func TestParseInvalidSyntaxFallback(t *testing.T) {
	// Invalid shell syntax should fall back to raw string
	cmds := ParseCommands(`this is ((( not valid shell`)
	if len(cmds) == 0 {
		t.Fatal("expected fallback command, got none")
	}
	// Should have something, not crash
	if cmds[0].Name == "" {
		t.Error("expected non-empty name in fallback")
	}
}

func TestParseEmptyString(t *testing.T) {
	cmds := ParseCommands("")
	if len(cmds) != 0 {
		t.Errorf("expected 0 commands for empty string, got %d", len(cmds))
	}
}

func TestParseSemicolonChain(t *testing.T) {
	cmds := ParseCommands(`ls; echo done`)
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if cmds[0].Name != "ls" {
		t.Errorf("expected ls, got %q", cmds[0].Name)
	}
	if cmds[1].Name != "echo" {
		t.Errorf("expected echo, got %q", cmds[1].Name)
	}
}

func TestParseSubshell(t *testing.T) {
	cmds := ParseCommands(`(cd /tmp && ls)`)
	// Should handle gracefully — get cd and ls from inside subshell
	if len(cmds) < 1 {
		t.Fatal("expected at least 1 command from subshell")
	}
}

func TestParseCommandSubstitution(t *testing.T) {
	// The inner command (date) is inside a command substitution — it's an argument to echo
	cmds := ParseCommands(`echo "today is $(date)"`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d: %+v", len(cmds), cmds)
	}
	if cmds[0].Name != "echo" {
		t.Errorf("expected echo, got %q", cmds[0].Name)
	}
}

func TestParseTeeRedirect(t *testing.T) {
	cmds := ParseCommands(`go test ./... 2>&1 | tee build.log`)
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d: %+v", len(cmds), cmds)
	}
	if cmds[0].Name != "go" {
		t.Errorf("expected go, got %q", cmds[0].Name)
	}
	if cmds[1].Name != "tee" {
		t.Errorf("expected tee, got %q", cmds[1].Name)
	}
}

func TestParseGitSwitchMetadata(t *testing.T) {
	cmds := ParseCommands(`git checkout feature/test-branch`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].GitSubcommand != "checkout" {
		t.Fatalf("expected git subcommand checkout, got %q", cmds[0].GitSubcommand)
	}
	if cmds[0].GitCategory != "switch" {
		t.Fatalf("expected git category switch, got %q", cmds[0].GitCategory)
	}
}

func TestParseGitRestoreMetadata(t *testing.T) {
	cmds := ParseCommands(`git checkout -- src/main.go`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].GitCategory != "restore" {
		t.Fatalf("expected git category restore, got %q", cmds[0].GitCategory)
	}
	if len(cmds[0].GitArgs) == 0 || cmds[0].GitArgs[0] != "--" {
		t.Fatalf("expected git args to retain path-restore separator, got %#v", cmds[0].GitArgs)
	}
	if len(cmds[0].GitPaths) != 1 || cmds[0].GitPaths[0] != "src/main.go" {
		t.Fatalf("expected git path operand src/main.go, got %#v", cmds[0].GitPaths)
	}
}

func TestParseGitGlobalOptionsMetadata(t *testing.T) {
	cmds := ParseCommands(`git -C repo status --short`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].GitSubcommand != "status" {
		t.Fatalf("expected git subcommand status, got %q", cmds[0].GitSubcommand)
	}
	if cmds[0].GitCategory != "query" {
		t.Fatalf("expected git category query, got %q", cmds[0].GitCategory)
	}
}

func TestParseGitAddPathspecs(t *testing.T) {
	cmds := ParseCommands(`git add src/app.py docs/spec.md`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if got := cmds[0].GitPaths; len(got) != 2 || got[0] != "docs/spec.md" || got[1] != "src/app.py" {
		t.Fatalf("unexpected add pathspecs: %#v", got)
	}
}

// TestParseNormalizesInvocation locks in the bypass-closing behavior: a command
// reached via a directory path, an executable suffix, or a wrapper program must
// still resolve to the real command name (and have its git metadata parsed) so
// that rules keying on c.name / c.git_subcommand fire.
func TestParseNormalizesInvocation(t *testing.T) {
	cases := []struct {
		cmd            string
		wantName       string
		wantSubcommand string
		wantFullPrefix string
	}{
		{`/usr/bin/git reset --hard`, "git", "reset", "git reset --hard"},
		{`/usr/local/bin/git.exe reset --hard`, "git", "reset", "git reset --hard"},
		{`command git reset --hard`, "git", "reset", "git reset --hard"},
		{`exec git reset --hard`, "git", "reset", "git reset --hard"},
		{`builtin git reset --hard`, "git", "reset", "git reset --hard"},
		{`sudo git reset --hard`, "git", "reset", "git reset --hard"},
		{`nohup git reset --hard`, "git", "reset", "git reset --hard"},
		{`env GIT_PAGER=cat git reset --hard`, "git", "reset", "git reset --hard"},
		{`env -i FOO=bar git reset --hard`, "git", "reset", "git reset --hard"},
		{`sudo VAR=v git reset --hard`, "git", "reset", "git reset --hard"},
		{`command env git reset --hard`, "git", "reset", "git reset --hard"},
	}
	for _, tc := range cases {
		cmds := ParseCommands(tc.cmd)
		if len(cmds) != 1 {
			t.Fatalf("%q: expected 1 command, got %d: %+v", tc.cmd, len(cmds), cmds)
		}
		got := cmds[0]
		if got.Name != tc.wantName {
			t.Errorf("%q: name = %q, want %q", tc.cmd, got.Name, tc.wantName)
		}
		if got.GitSubcommand != tc.wantSubcommand {
			t.Errorf("%q: subcommand = %q, want %q", tc.cmd, got.GitSubcommand, tc.wantSubcommand)
		}
		if got.Full != tc.wantFullPrefix {
			t.Errorf("%q: full = %q, want %q", tc.cmd, got.Full, tc.wantFullPrefix)
		}
	}
}

// TestParseUnwrapsRunWrappers locks in that Python/JS run-wrappers are unwrapped
// so the INNER command is what rules see. Otherwise an agent can evade a
// name-based rule (e.g. no-python-c) simply by prefixing "uv run".
//
// Two families:
//   - "<wrapper> run <cmd> ...": uv, poetry, pdm, rye, pipenv — unwrap ONLY when
//     the first non-flag argument is the "run" subcommand.
//   - direct-exec "<wrapper> <cmd> ...": uvx, npx — the first non-flag argument
//     IS the command.
func TestParseUnwrapsRunWrappers(t *testing.T) {
	cases := []struct {
		cmd            string
		wantName       string
		wantFullPrefix string
	}{
		{`uv run python -c 'print(1)'`, "python", "python -c print(1)"},
		{`uvx ruff check`, "ruff", "ruff check"},
		{`poetry run python script.py`, "python", "python script.py"},
		{`pdm run pytest -q`, "pytest", "pytest -q"},
		{`rye run python app.py`, "python", "python app.py"},
		{`pipenv run flask run`, "flask", "flask run"},
		{`npx tsc --noEmit`, "tsc", "tsc --noEmit"},
		// Boolean options before the inner command are skipped.
		{`uv run --no-project python -c 'print(1)'`, "python", "python -c print(1)"},
		{`npx --yes tsc --noEmit`, "tsc", "tsc --noEmit"},
		// Nested wrapper + run-wrapper still resolves to the inner command.
		{`sudo uv run python -c 'print(1)'`, "python", "python -c print(1)"},
	}
	for _, tc := range cases {
		cmds := ParseCommands(tc.cmd)
		if len(cmds) != 1 {
			t.Fatalf("%q: expected 1 command, got %d: %+v", tc.cmd, len(cmds), cmds)
		}
		got := cmds[0]
		if got.Name != tc.wantName {
			t.Errorf("%q: name = %q, want %q", tc.cmd, got.Name, tc.wantName)
		}
		if got.Full != tc.wantFullPrefix {
			t.Errorf("%q: full = %q, want %q", tc.cmd, got.Full, tc.wantFullPrefix)
		}
	}
}

// TestParseUnwrapsRunWrappersWithValueFlags locks in that value-taking option
// flags in the space-separated "--flag value" form placed BEFORE the inner
// command are advanced past correctly, so the flag's VALUE is not mistaken for
// the inner command name. Without a per-wrapper value-flag table, "uv run
// --python 3.11 python -c ..." would resolve name=3.11 and evade no-python-c.
func TestParseUnwrapsRunWrappersWithValueFlags(t *testing.T) {
	cases := []struct {
		cmd            string
		wantName       string
		wantFullPrefix string
	}{
		// Space-separated value flags before the inner command.
		{`uv run --python 3.11 python -c 'print(1)'`, "python", "python -c print(1)"},
		{`uvx --from build pyproject-build`, "pyproject-build", "pyproject-build"},
		{`poetry run --directory foo python app.py`, "python", "python app.py"},
		// Multiple value flags in a row still resolve to the inner command.
		{`uv run --python 3.11 --with rich python -c 'x'`, "python", "python -c x"},
		// Short-form value flag (-p == --python for uv).
		{`uv run -p 3.11 python -c 'x'`, "python", "python -c x"},
		// Regression guard: the "--flag=value" form already worked and must keep working.
		{`uv run --python=3.11 python -c 'x'`, "python", "python -c x"},
		// Regression guard: boolean flag interleaved with a value flag.
		{`uv run --no-project --python 3.11 python -c 'x'`, "python", "python -c x"},
	}
	for _, tc := range cases {
		cmds := ParseCommands(tc.cmd)
		if len(cmds) != 1 {
			t.Fatalf("%q: expected 1 command, got %d: %+v", tc.cmd, len(cmds), cmds)
		}
		got := cmds[0]
		if got.Name != tc.wantName {
			t.Errorf("%q: name = %q, want %q", tc.cmd, got.Name, tc.wantName)
		}
		if got.Full != tc.wantFullPrefix {
			t.Errorf("%q: full = %q, want %q", tc.cmd, got.Full, tc.wantFullPrefix)
		}
	}
}

// TestParseValueFlagSealNegativesUnchanged confirms the value-flag seal did not
// alter non-run subcommands: uv pip / uv venv keep the wrapper as the name.
func TestParseValueFlagSealNegativesUnchanged(t *testing.T) {
	cases := []struct {
		cmd      string
		wantName string
	}{
		{`uv pip install foo`, "uv"},
		{`uv venv`, "uv"},
	}
	for _, tc := range cases {
		cmds := ParseCommands(tc.cmd)
		if len(cmds) != 1 {
			t.Fatalf("%q: expected 1 command, got %d: %+v", tc.cmd, len(cmds), cmds)
		}
		if cmds[0].Name != tc.wantName {
			t.Errorf("%q: name = %q, want %q", tc.cmd, cmds[0].Name, tc.wantName)
		}
	}
}

// TestParseRunWrappersDoNotUnwrapNonRunSubcommands ensures the run-wrapper
// unwrapping is conservative: only the "run" subcommand triggers it. Other
// subcommands (uv pip, uv venv, poetry add, ...) must keep the wrapper as the
// command name so those invocations are not misattributed.
func TestParseRunWrappersDoNotUnwrapNonRunSubcommands(t *testing.T) {
	cases := []struct {
		cmd      string
		wantName string
	}{
		{`uv pip install foo`, "uv"},
		{`uv venv`, "uv"},
		{`poetry add requests`, "poetry"},
		{`pdm install`, "pdm"},
		{`rye sync`, "rye"},
		{`pipenv install`, "pipenv"},
	}
	for _, tc := range cases {
		cmds := ParseCommands(tc.cmd)
		if len(cmds) != 1 {
			t.Fatalf("%q: expected 1 command, got %d: %+v", tc.cmd, len(cmds), cmds)
		}
		if cmds[0].Name != tc.wantName {
			t.Errorf("%q: name = %q, want %q", tc.cmd, cmds[0].Name, tc.wantName)
		}
	}
}

// TestParseDoesNotUnwrapNonWrappers ensures a bare command and a non-wrapper
// leading token are left intact (no false unwrapping).
func TestParseDoesNotUnwrapNonWrappers(t *testing.T) {
	cmds := ParseCommands(`mygit reset --hard`)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Name != "mygit" {
		t.Errorf("expected name mygit, got %q", cmds[0].Name)
	}
	if cmds[0].GitSubcommand != "" {
		t.Errorf("non-git command should have no git subcommand, got %q", cmds[0].GitSubcommand)
	}
}
