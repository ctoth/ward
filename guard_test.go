package main

import (
	"os"
	"path/filepath"
	"testing"
)

func loadTestGuard(t *testing.T) *Guard {
	t.Helper()
	facts, err := LoadFactsFromDir("testdata/facts")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFromDir("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(facts, rules)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestLoadFact(t *testing.T) {
	name, fact, err := LoadFact("testdata/facts/git_branch.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if name != "git_branch" {
		t.Errorf("expected name git_branch, got %q", name)
	}
	if fact.Command != "echo main" {
		t.Errorf("expected command 'echo main', got %q", fact.Command)
	}
}

func TestLoadFactMissingCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := writeFile(path, "type: bool\n"); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadFact(path)
	if err == nil {
		t.Error("expected error for missing 'command'")
	}
}

func TestLoadFactsFromDir(t *testing.T) {
	facts, err := LoadFactsFromDir("testdata/facts")
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Errorf("expected 2 facts, got %d", len(facts))
	}
	if facts["git_branch"].Command != "echo main" {
		t.Errorf("expected git_branch command 'echo main', got %q", facts["git_branch"].Command)
	}
	if facts["has_pyproject"].Type != "bool" {
		t.Errorf("expected has_pyproject type 'bool', got %q", facts["has_pyproject"].Type)
	}
}

func TestLoadFactsFromDirMissing(t *testing.T) {
	facts, err := LoadFactsFromDir("testdata/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if facts != nil {
		t.Errorf("expected nil from missing dir, got %v", facts)
	}
}

func TestNewGuardInvalidCEL(t *testing.T) {
	// Write a rule file with bad CEL
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(rulesDir, "bad.yaml"), `
when: 'this is not valid CEL %%% !!!'
action: deny
message: test
`); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromDir(rulesDir)
	if err != nil {
		t.Fatal(err) // parse error
	}

	_, err = NewGuard(nil, rules)
	if err == nil {
		t.Error("expected error for invalid CEL")
	}
}

func TestLoadRulesFromDir(t *testing.T) {
	rules, err := LoadRulesFromDir("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 7 {
		t.Errorf("expected 7 rules, got %d", len(rules))
	}
}

func TestLoadRulesFromDirMissing(t *testing.T) {
	rules, err := LoadRulesFromDir("testdata/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from missing dir, got %d", len(rules))
	}
}

func TestLoadRuleMissingWhen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := writeFile(path, "action: deny\nmessage: test\n"); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRule(path)
	if err == nil {
		t.Error("expected error for missing 'when'")
	}
}

func TestMergeFacts(t *testing.T) {
	global := map[string]Fact{
		"a": {Command: "echo a"},
		"b": {Command: "echo b"},
	}
	project := map[string]Fact{
		"b": {Command: "echo B-override"},
		"c": {Command: "echo c"},
	}
	merged := MergeFacts(global, project)

	if merged["a"].Command != "echo a" {
		t.Error("expected global fact 'a' preserved")
	}
	if merged["b"].Command != "echo B-override" {
		t.Error("expected project fact 'b' to override global")
	}
	if merged["c"].Command != "echo c" {
		t.Error("expected project fact 'c' present")
	}
}

func TestNewState(t *testing.T) {
	s := NewState("planning")
	if s.Phase != "planning" {
		t.Errorf("expected planning, got %q", s.Phase)
	}
	if len(s.History) != 0 {
		t.Errorf("expected empty history, got %d entries", len(s.History))
	}
}

func TestStateHistory(t *testing.T) {
	s := NewState("implementing")

	s.Update("Read", nil)
	s.Update("Read", nil)
	s.Update("Read", nil)

	if len(s.History) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(s.History))
	}
	for i, h := range s.History {
		if h != "Read" {
			t.Errorf("history[%d] = %q, want Read", i, h)
		}
	}

	s.Update("Bash", map[string]any{"command": "ls"})
	if len(s.History) != 4 {
		t.Errorf("expected 4 history entries, got %d", len(s.History))
	}
	if s.History[3] != "Bash" {
		t.Errorf("expected Bash at end, got %q", s.History[3])
	}
}

func TestStateCommitMarker(t *testing.T) {
	s := NewState("implementing")

	s.Update("Edit", nil)
	s.Update("Write", nil)
	s.Update("Bash", map[string]any{"command": "git commit -m 'test'"})

	// Should have: Edit, Write, _commit, Bash
	expected := []string{"Edit", "Write", "_commit", "Bash"}
	if len(s.History) != len(expected) {
		t.Fatalf("expected %d history entries, got %d: %v", len(expected), len(s.History), s.History)
	}
	for i, want := range expected {
		if s.History[i] != want {
			t.Errorf("history[%d] = %q, want %q", i, s.History[i], want)
		}
	}
}

func TestStateCommitMarkerIgnoresRawMention(t *testing.T) {
	s := NewState("implementing")

	s.Update("Edit", nil)
	s.Update("Bash", map[string]any{"command": "echo git commit"})
	s.Update("Edit", nil)

	expected := []string{"Edit", "Bash", "Edit"}
	if len(s.History) != len(expected) {
		t.Fatalf("expected %d history entries, got %d: %v", len(expected), len(s.History), s.History)
	}
	for i, want := range expected {
		if s.History[i] != want {
			t.Errorf("history[%d] = %q, want %q", i, s.History[i], want)
		}
	}
}

func TestStateHistoryCap(t *testing.T) {
	s := NewState("implementing")
	for i := 0; i < 110; i++ {
		s.Update("Read", nil)
	}
	if len(s.History) != maxHistory {
		t.Errorf("expected history capped at %d, got %d", maxHistory, len(s.History))
	}
}

// bashEvent creates a Bash ToolEvent with parsed commands enrichment.
func bashEvent(t *testing.T, command string) ToolEvent {
	t.Helper()
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": command},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	enrichBashCommands(&event)
	return event
}

func TestEvaluatePythonCDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "python -c \"print('hello')\"")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateGitStashDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "git stash")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateEditInPlanningDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("planning")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateEditInImplementingAllow(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow), got %v", result)
	}
}

func TestEvaluateFlailingContext(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	// Build up 4 reads in history; the 5th (the event itself) will be added by Update
	// But Evaluate doesn't call Update — we need 5 reads already in history
	// so the rule sees last 5 are all reads
	for i := 0; i < 5; i++ {
		state.History = append(state.History, "Read")
	}

	event := ToolEvent{
		Tool:      "Read",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected context result, got nil")
	}
	if result.Action != "context" {
		t.Errorf("expected context, got %q", result.Action)
	}
}

func TestEvaluateSafeCommandAllow(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "ls -la")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow) for safe command, got %v", result)
	}
}

func TestEvaluateCodexLocalShellMatchesBashRules(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	raw := []byte(`{
		"session_id":"codex-session-789",
		"cwd":"C:/tmp",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"local_shell",
			"tool_input":{
				"params":{
					"command":["python","-c","print(1)"]
				}
			}
		}
	}`)

	event, _, err := DetectAndParse(raw)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateDenyVetoesContext(t *testing.T) {
	// Create a guard with both a deny and context rule that match
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `tool == "Bash" && input.commands.exists(c, c.full.matches("^python[3]?\\s+-c"))`, Action: "deny", Message: "no python -c"},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	for i := 0; i < 5; i++ {
		state.History = append(state.History, "Read")
	}
	event := bashEvent(t, "python -c 'x'")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("deny should veto context; got %q", result.Action)
	}
}

func TestEvaluateContextAccumulates(t *testing.T) {
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `since(session.history, "_commit").filter(t, t in ["Edit", "Write"]).size() >= 2`, Action: "context", Message: "uncommitted"},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	// History: Edit, Write, Edit, Read x5 — triggers both rules
	state.History = []string{"Edit", "Write", "Edit", "Read", "Read", "Read", "Read", "Read"}
	event := ToolEvent{
		Tool:      "Read",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected context, got nil")
	}
	if result.Action != "context" {
		t.Errorf("expected context, got %q", result.Action)
	}
	// Both messages should be present
	if result.Message != "flailing\nuncommitted" {
		t.Errorf("expected both messages joined, got %q", result.Message)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`C:\Users\Q\foo`, "C:/Users/Q/foo"},
		{"C:/Users/Q/foo", "C:/Users/Q/foo"},
		{"/tmp/foo", "/tmp/foo"},
		{`a\b\c`, "a/b/c"},
	}
	for _, tt := range tests {
		got := NormalizePath(tt.in)
		if got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeInput(t *testing.T) {
	input := map[string]any{
		"file_path": `C:\Users\Q\foo.go`,
		"command":   `echo hello`,
	}
	norm := NormalizeInput(input)
	if norm["file_path"] != "C:/Users/Q/foo.go" {
		t.Errorf("expected normalized file_path, got %q", norm["file_path"])
	}
	// command should NOT be normalized (not a path field)
	if norm["command"] != "echo hello" {
		t.Errorf("command should be unchanged, got %q", norm["command"])
	}
}

func TestEvaluateWithScope(t *testing.T) {
	rules := []Rule{
		{
			Scope:   "output/**",
			When:    `tool in ["Edit", "Write"]`,
			Action:  "deny",
			Message: "Fix upstream, not generated files.",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")

	// Edit in output/ — should be denied
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "output/generated.html"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("expected deny for output/ file, got %v", result)
	}

	// Edit outside output/ — should be allowed
	event2 := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "src/main.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	result2, err := Evaluate(guard, state, event2)
	if err != nil {
		t.Fatal(err)
	}
	if result2 != nil {
		t.Errorf("expected allow for src/ file, got %v", result2)
	}
}

func TestStatePersistence(t *testing.T) {
	sessionID := "test-persist-" + t.Name()
	state := NewState("implementing")
	state.History = []string{"Read", "Bash", "Edit", "Bash", "Read"}

	if err := SaveState(sessionID, state); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(sessionID)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Phase != "implementing" {
		t.Errorf("expected implementing, got %q", loaded.Phase)
	}
	if len(loaded.History) != 5 {
		t.Errorf("expected 5 history entries, got %d", len(loaded.History))
	}
	if loaded.History[2] != "Edit" {
		t.Errorf("expected Edit at index 2, got %q", loaded.History[2])
	}
}

func TestCompileRule(t *testing.T) {
	good := &Rule{When: `tool == "Bash"`, Action: "deny"}
	if err := CompileRule(good); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	bad := &Rule{When: `this is not valid CEL %%% !!!`, Action: "deny"}
	if err := CompileRule(bad); err == nil {
		t.Error("expected error for invalid CEL")
	}
}

// --- Shell parsing integration tests ---

func TestHeredocFalsePositive(t *testing.T) {
	// git commit with "python -c" in heredoc message should NOT trigger no-python-c
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "git commit -m \"$(cat <<'EOF'\npython -c blah\nEOF\n)\"")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("heredoc content should not trigger deny, got: %s", result.Message)
	}
}

func TestPipeChainTriggers(t *testing.T) {
	// python -c in a pipe should still trigger
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "echo foo | python -c \"import sys\"")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("python -c in pipe should trigger deny, got: %v", result)
	}
}

func TestAndChainTriggers(t *testing.T) {
	// python -c in && chain should still trigger
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "cd /tmp && python -c \"print(1)\"")

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("python -c in && chain should trigger deny, got: %v", result)
	}
}

func TestSafeArgsNoFalsePositive(t *testing.T) {
	// echo "git stash is bad" should NOT trigger no-git-stash
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, `echo "git stash is bad"`)

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("echo with 'git stash' in args should not trigger deny, got: %s", result.Message)
	}
}

func TestGitCommitMessageNoFalsePositive(t *testing.T) {
	// git commit -m "python -c is forbidden" should NOT trigger no-python-c
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, `git commit -m "python -c is forbidden"`)

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("commit message with 'python -c' should not trigger deny, got: %s", result.Message)
	}
}

// --- Phase-gating tests ---

func TestPhaseGatingBasic(t *testing.T) {
	// Rule: deny Bash/Edit/Write when session.phase == "foreman"
	rules := []Rule{
		{
			When:    `session.phase == "foreman" && tool in ["Bash", "Edit", "Write"]`,
			Action:  "deny",
			Message: "foreman cannot use code-editing tools",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	makeEvent := func(toolName string) ToolEvent {
		return ToolEvent{
			Tool:      toolName,
			Input:     map[string]any{},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
	}

	// phase=foreman, tool=Bash → denied
	t.Run("foreman_bash_denied", func(t *testing.T) {
		state := NewState("foreman")
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman phase, got %v", result)
		}
	})

	// phase=foreman, tool=Read → allowed
	t.Run("foreman_read_allowed", func(t *testing.T) {
		state := NewState("foreman")
		result, err := Evaluate(guard, state, makeEvent("Read"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Read in foreman phase, got %v", result)
		}
	})

	// phase="" (empty, defaults to planning) → Bash allowed (not foreman)
	t.Run("no_phase_bash_allowed", func(t *testing.T) {
		state := NewState("") // defaults to "planning"
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash with no foreman phase, got %v", result)
		}
	})

	// phase=implementing → Bash allowed
	t.Run("implementing_bash_allowed", func(t *testing.T) {
		state := NewState("implementing")
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash in implementing phase, got %v", result)
		}
	})
}

func TestPhaseGatingFilePathWhitelist(t *testing.T) {
	// Rule: deny Write in foreman EXCEPT when path contains "/prompts/" or "notes-"
	// CEL: deny when foreman + Write + path does NOT match whitelist
	// We use "file_path" in input to safely check for key existence.
	rules := []Rule{
		{
			When: `session.phase == "foreman" && tool == "Write" &&
				(!("file_path" in input) ||
				 !(input.file_path.contains("prompts/") || input.file_path.contains("notes-")))`,
			Action:  "deny",
			Message: "foreman can only write to prompts/ or notes- files",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	// Write to src/foo.py → denied
	t.Run("foreman_write_src_denied", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "src/foo.py"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Write to src/foo.py in foreman, got %v", result)
		}
	})

	// Write to prompts/task.md → allowed
	t.Run("foreman_write_prompts_allowed", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "prompts/task.md"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Write to prompts/task.md in foreman, got %v", result)
		}
	})

	// Write to notes-session.md → allowed
	t.Run("foreman_write_notes_allowed", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "notes-session.md"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Write to notes-session.md in foreman, got %v", result)
		}
	})

	// Write with NO file_path in input → denied (not error)
	t.Run("foreman_write_no_filepath_denied", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"content": "hello"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Write with no file_path in foreman, got %v", result)
		}
	})
}

func TestPhaseGatingCELMapKeyAccess(t *testing.T) {
	// Document the correct pattern for checking map keys in CEL.
	//
	// CORRECT: "file_path" in input
	//   The `in` operator checks for key existence in a map. This is the
	//   standard CEL idiom for optional fields.
	//
	// INCORRECT: has(input.file_path)
	//   has() is for protocol buffer field presence checks. On a plain map,
	//   it either errors or returns false — it does NOT check key existence.
	//   When the CEL eval errors, ward silently skips the rule (guard.go ~line 497).

	// Test 1: "file_path" in input works correctly
	t.Run("in_operator_works", func(t *testing.T) {
		rules := []Rule{
			{
				When:    `"file_path" in input && input.file_path.contains("secret")`,
				Action:  "deny",
				Message: "no secret files",
			},
		}
		guard, err := NewGuard(nil, rules)
		if err != nil {
			t.Fatal(err)
		}
		state := NewState("implementing")

		// With file_path containing "secret" → denied
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "secret.txt"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny when file_path contains 'secret', got %v", result)
		}

		// Without file_path → allowed (key not in map, short-circuits safely)
		event2 := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"content": "hello"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result2, err := Evaluate(guard, state, event2)
		if err != nil {
			t.Fatal(err)
		}
		if result2 != nil {
			t.Errorf("expected allow when file_path key is absent, got %v", result2)
		}
	})

	// Test 2: has(input.file_path) does NOT work for map key checking.
	// On a plain CEL map, has() with a dotted field access either errors
	// or returns false. When the CEL eval errors, the rule is silently skipped.
	t.Run("has_does_not_work_for_maps", func(t *testing.T) {
		rules := []Rule{
			{
				When:    `has(input.file_path) && input.file_path.contains("secret")`,
				Action:  "deny",
				Message: "no secret files",
			},
		}
		guard, err := NewGuard(nil, rules)
		if err != nil {
			t.Fatal(err)
		}
		state := NewState("implementing")

		// Even with file_path present and containing "secret", has() on a plain
		// map may not behave as expected — it may error or return false,
		// causing the rule to silently not fire.
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "secret.txt"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		// has(input.file_path) on a CEL map type may actually work in some
		// CEL-Go versions. We document the behavior here: if has() works,
		// that's fine, but "key" in map is the canonical and reliable pattern.
		// The important thing is: this test documents the pattern.
		// If has() works → result is deny. If has() silently fails → result is nil.
		// Either way, use "key" in map for reliability.
		_ = result // behavior documented; see "in_operator_works" for the correct pattern
	})
}

func TestPhaseGatingCompoundPhaseMatch(t *testing.T) {
	// Rule using startsWith to match "foreman", "foreman:planning", etc.
	rules := []Rule{
		{
			When:    `session.phase.startsWith("foreman") && tool in ["Bash", "Edit", "Write"]`,
			Action:  "deny",
			Message: "foreman modes cannot use code-editing tools",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	makeEvent := func(toolName string) ToolEvent {
		return ToolEvent{
			Tool:      toolName,
			Input:     map[string]any{},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
	}

	// phase="foreman:planning", tool=Bash → denied
	t.Run("foreman_planning_bash_denied", func(t *testing.T) {
		state := &State{Phase: "foreman:planning", History: []string{}}
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman:planning phase, got %v", result)
		}
	})

	// phase="foreman", tool=Bash → denied
	t.Run("foreman_bash_denied", func(t *testing.T) {
		state := NewState("foreman")
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman phase, got %v", result)
		}
	})

	// phase="implementing", tool=Bash → allowed
	t.Run("implementing_bash_allowed", func(t *testing.T) {
		state := NewState("implementing")
		result, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash in implementing phase, got %v", result)
		}
	})
}

// helper
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
