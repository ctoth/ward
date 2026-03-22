package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.DefaultPhase != "planning" {
		t.Errorf("expected default_phase planning, got %q", cfg.DefaultPhase)
	}
	if len(cfg.Rules) != 7 {
		t.Errorf("expected 7 rules, got %d", len(cfg.Rules))
	}
	if len(cfg.Facts) != 2 {
		t.Errorf("expected 2 facts, got %d", len(cfg.Facts))
	}
	if len(cfg.programs) != 7 {
		t.Errorf("expected 7 compiled programs, got %d", len(cfg.programs))
	}
}

func TestLoadConfigInvalidCEL(t *testing.T) {
	// Write a temp config with bad CEL
	cfg := `
default_phase: planning
rules:
  - when: 'this is not valid CEL %%% !!!'
    action: deny
    message: test
`
	tmpFile := t.TempDir() + "/bad.yaml"
	if err := writeFile(tmpFile, cfg); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("expected error for invalid CEL")
	}
}

func TestNewState(t *testing.T) {
	s := NewState("planning")
	if s.Phase != "planning" {
		t.Errorf("expected planning, got %q", s.Phase)
	}
	if s.ToolCount != 0 {
		t.Errorf("expected 0 tool_count, got %d", s.ToolCount)
	}
}

func TestStateUpdateCounters(t *testing.T) {
	s := NewState("implementing")

	s.Update("Read", nil)
	s.Update("Read", nil)
	s.Update("Read", nil)

	if s.ToolCount != 3 {
		t.Errorf("expected 3 tool_count, got %d", s.ToolCount)
	}
	if s.ReadsSinceBash != 3 {
		t.Errorf("expected 3 reads_since_bash, got %d", s.ReadsSinceBash)
	}
	if s.ToolCounts["Read"] != 3 {
		t.Errorf("expected Read count 3, got %d", s.ToolCounts["Read"])
	}

	// Bash resets reads_since_bash
	s.Update("Bash", map[string]any{"command": "ls"})
	if s.ReadsSinceBash != 0 {
		t.Errorf("expected 0 reads_since_bash after Bash, got %d", s.ReadsSinceBash)
	}
}

func TestStateUpdateEditsSinceCommit(t *testing.T) {
	s := NewState("implementing")

	s.Update("Edit", nil)
	s.Update("Write", nil)
	if s.EditsSinceCommit != 2 {
		t.Errorf("expected 2 edits_since_commit, got %d", s.EditsSinceCommit)
	}

	// git commit resets
	s.Update("Bash", map[string]any{"command": "git commit -m 'test'"})
	if s.EditsSinceCommit != 0 {
		t.Errorf("expected 0 edits_since_commit after git commit, got %d", s.EditsSinceCommit)
	}
}

func TestEvaluatePythonCDeny(t *testing.T) {
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "python -c \"print('hello')\""},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
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
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "git stash"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
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
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("planning")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
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
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
	if err != nil {
		t.Fatal(err)
	}
	// No rule should match — allowed
	if result != nil {
		t.Errorf("expected nil (allow), got %v", result)
	}
}

func TestEvaluateFlailingContext(t *testing.T) {
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	// Simulate 3 reads without a Bash call
	state.ReadsSinceBash = 3

	event := ToolEvent{
		Tool:      "Read",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
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
	cfg, err := LoadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": "ls -la"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, err := Evaluate(cfg, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow) for safe command, got %v", result)
	}
}

func TestStatePersistence(t *testing.T) {
	sessionID := "test-persist-" + t.Name()
	state := NewState("implementing")
	state.ToolCount = 5
	state.ToolCounts["Bash"] = 3

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
	if loaded.ToolCount != 5 {
		t.Errorf("expected 5, got %d", loaded.ToolCount)
	}
	if loaded.ToolCounts["Bash"] != 3 {
		t.Errorf("expected 3, got %d", loaded.ToolCounts["Bash"])
	}
}

// helper
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
