package main

import (
	"os"
	"path/filepath"
	"testing"
)

func loadTestGuard(t *testing.T) *Guard {
	t.Helper()
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFromDir("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.DefaultPhase != "planning" {
		t.Errorf("expected default_phase planning, got %q", cfg.DefaultPhase)
	}
	if len(cfg.Facts) != 2 {
		t.Errorf("expected 2 facts, got %d", len(cfg.Facts))
	}
}

func TestLoadConfigMissing(t *testing.T) {
	cfg, err := LoadConfig("testdata/nonexistent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultPhase != "planning" {
		t.Errorf("expected default planning, got %q", cfg.DefaultPhase)
	}
}

func TestLoadConfigInvalidCEL(t *testing.T) {
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

	cfg := &Config{DefaultPhase: "planning"}
	_, err = NewGuard(cfg, rules)
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

func TestMergeConfigs(t *testing.T) {
	global := &Config{
		DefaultPhase: "planning",
		Facts: map[string]Fact{
			"a": {Command: "echo a"},
			"b": {Command: "echo b"},
		},
	}
	project := &Config{
		DefaultPhase: "implementing",
		Facts: map[string]Fact{
			"b": {Command: "echo B-override"},
			"c": {Command: "echo c"},
		},
	}
	merged := MergeConfigs(global, project)

	if merged.DefaultPhase != "implementing" {
		t.Errorf("expected implementing, got %q", merged.DefaultPhase)
	}
	if merged.Facts["a"].Command != "echo a" {
		t.Error("expected global fact 'a' preserved")
	}
	if merged.Facts["b"].Command != "echo B-override" {
		t.Error("expected project fact 'b' to override global")
	}
	if merged.Facts["c"].Command != "echo c" {
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

func TestStateHistoryCap(t *testing.T) {
	s := NewState("implementing")
	for i := 0; i < 110; i++ {
		s.Update("Read", nil)
	}
	if len(s.History) != maxHistory {
		t.Errorf("expected history capped at %d, got %d", maxHistory, len(s.History))
	}
}

func TestEvaluatePythonCDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "python -c \"print('hello')\""},
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

func TestEvaluateGitStashDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "git stash"},
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
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "ls -la"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow) for safe command, got %v", result)
	}
}

func TestEvaluateDenyVetoesContext(t *testing.T) {
	// Create a guard with both a deny and context rule that match
	cfg := &Config{DefaultPhase: "planning"}
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `tool == "Bash" && input.command.matches("python[3]?\\s+-c")`, Action: "deny", Message: "no python -c"},
	}
	guard, err := NewGuard(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	for i := 0; i < 5; i++ {
		state.History = append(state.History, "Read")
	}
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "python -c 'x'"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

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
	cfg := &Config{DefaultPhase: "planning"}
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `since(session.history, "_commit").filter(t, t in ["Edit", "Write"]).size() >= 2`, Action: "context", Message: "uncommitted"},
	}
	guard, err := NewGuard(cfg, rules)
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
	cfg := &Config{DefaultPhase: "implementing"}
	rules := []Rule{
		{
			Scope:   "output/**",
			When:    `tool in ["Edit", "Write"]`,
			Action:  "deny",
			Message: "Fix upstream, not generated files.",
		},
	}
	guard, err := NewGuard(cfg, rules)
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

// helper
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
