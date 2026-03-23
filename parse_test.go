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
